//! Draws a cook progress bar on the console, so a long `-Processes=N` cook says
//! how far through it is instead of only scrolling package names.
//!
//! # Where the numbers come from
//!
//! Both halves are read from state the engine already maintains, so nothing has
//! to be counted twice or inferred from log text.
//!
//! **Total.** `UCookPackagesCommandlet::CookPackages` counts the packages it is
//! about to hand out and passes that count straight to `StartChildren`
//! (`UnrealEd/Src/UnContentCookers.cpp`):
//!
//! ```c
//! INT NumJobs = 0;
//! for( INT PackageIndex=Max<INT>(0,LastStartupIndex); PackageIndex < PackageList.Num() ; PackageIndex++ )
//! {
//!     if( ... ) { NumJobs++; }
//! }
//! if (!StartChildren(NumJobs)) { bIsMTMaster = FALSE; }
//! ```
//!
//! so hooking `StartChildren` yields the denominator directly, and its return
//! value says whether the cook is running multithreaded at all - it refuses on
//! too few jobs, too few cores or too little RAM, and the master silently
//! demotes itself to a single-process cook.
//!
//! **Completed.** Each child's finished-job count is kept by the master in
//! `FChildProcess::JobsCompleted`, incremented in `ChildIsIdle` as each job comes
//! back:
//!
//! ```c
//! UBOOL bIdle = !ChildProcesses(ProcessIndex).CommandFile.NonLockingFileExists();
//! if (bIdle && ChildProcesses(ProcessIndex).StartTime > 0.0)
//! {
//!     warnf(NAME_Log,TEXT("Job[%d] %s done in %5.1fs"), ...);
//!     ChildProcesses(ProcessIndex).StartTime = 0.0;
//!     ChildProcesses(ProcessIndex).JobsCompleted++;
//! }
//! ```
//!
//! Summing that field over the array is the numerator. It is the engine's own
//! bookkeeping, so a relaunched or stalled child cannot desynchronise it.
//!
//! # Structure layout
//!
//! `ChildProcesses` is a `TArray<FChildProcess>` at `this+0x2AD4`, read straight
//! out of `ChildIsIdle`:
//!
//! ```asm
//! MOV  EAX, dword [RCX+0x2ADC]   ; ChildProcesses.ArrayNum
//! MOV  RAX, qword [RDI+0x2AD4]   ; ChildProcesses.Data
//! IMUL RSI, RSI, 0x68            ; sizeof(FChildProcess)
//! LEA  RCX, [RSI+RAX+0x20]       ; &Element.CommandFile
//! ```
//!
//! The `0x68` stride and the `CommandFile` at `+0x20` reconcile field-for-field
//! with the declared struct once UE3's `pack(4)` is applied, which is also why
//! the array does not sit on an 8-byte boundary:
//!
//! ```text
//! 0x00 Directory      0x10 LogFilename   0x20 CommandFile   0x30 LastCommand
//! 0x40 StartTime      0x48 JobsCompleted 0x4C bStopped      0x50 bMergedResults
//! 0x54 LastTFCTexture 0x5C ProcessHandle 0x64 ProcessId     = 0x68
//! ```
//!
//! Every read is bounds-checked against a sane element count and a non-null data
//! pointer, and any failure just skips that repaint - the bar is cosmetic and
//! must never be able to take a cook down.
//!
//! # Scope
//!
//! Only the multithreaded **master** draws. A child would fight the master for
//! the same console, and a single-process cook never calls `StartChildren`, so
//! neither draws anything. Covering single-process cooks needs a per-package tick
//! from `CollectGarbageAndVerify`, whose entry point is not yet confirmed - see
//! the note in `init`.
//!
//! # Provenance
//!
//! RVAs read from `RenXSDK/UDK.exe`, whose `.text` hash is pinned in `dll.rs`.
//! `StartChildren` (`0x11BC6E0`) is the function [`crate::udk_mt_cook_processes`]
//! already patches. The completion tick is driven from the `ChildIsIdle` detour
//! that [`crate::udk_cook_pcd_checkpoint`] owns, rather than a second detour on
//! the same address.

#![cfg(target_arch = "x86_64")]

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::Context;
use retour::static_detour;

use crate::dll::get_udk_ptr;
use crate::patch_utils::{debug_log, find_signature_offset};

/// `UCookPackagesCommandlet::StartChildren` in the 12791 (UDK-2015-01) x64 build.
const START_CHILDREN_OFFSET: usize = 0x0011_BC6E0;

/// Prologue of `StartChildren`, up to the stack cookie load:
///
/// ```asm
/// MOV    RAX, RSP
/// PUSH   RBP ; RSI ; RDI ; R12 ; R13 ; R14 ; R15
/// LEA    RBP, [RAX-0x338]
/// SUB    RSP, 0x400
/// MOV    qword [RBP+0xA0], -2        ; EH state
/// MOV    qword [RAX+0x18], RBX
/// MOVAPS xmmword [RAX-0x48], XMM6
/// ```
///
/// Deliberately stops before `MOV dword [RSP+0x40], 5` at `+0x45`, which
/// [`crate::udk_mt_cook_processes`] rewrites to 4 - so this still matches
/// whichever order the two modules install in. Contains no rip-relative
/// displacement, so it is a plain byte match.
const START_CHILDREN_SIG: [u8; 47] = [
    0x48, 0x8B, 0xC4, // MOV RAX,RSP
    0x55, // PUSH RBP
    0x56, // PUSH RSI
    0x57, // PUSH RDI
    0x41, 0x54, // PUSH R12
    0x41, 0x55, // PUSH R13
    0x41, 0x56, // PUSH R14
    0x41, 0x57, // PUSH R15
    0x48, 0x8D, 0xA8, 0xC8, 0xFC, 0xFF, 0xFF, // LEA RBP,[RAX-0x338]
    0x48, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00, // SUB RSP,0x400
    0x48, 0xC7, 0x85, 0xA0, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, // MOV [RBP+0xA0],-2
    0x48, 0x89, 0x58, 0x18, // MOV [RAX+0x18],RBX
    0x0F, 0x29, 0x70, 0xB8, // MOVAPS [RAX-0x48],XMM6
];

/// `UCookPackagesCommandlet::ChildProcesses`, a `TArray<FChildProcess>`.
const CHILD_PROCESSES_DATA: usize = 0x2AD4;
const CHILD_PROCESSES_NUM: usize = 0x2ADC;

/// `sizeof(FChildProcess)` and the offset of `JobsCompleted` within it.
const CHILD_PROCESS_STRIDE: usize = 0x68;
const CHILD_PROCESS_JOBS_COMPLETED: usize = 0x48;

/// `StartChildren` itself clamps to 48 children; anything beyond this means the
/// pointer being read is not really the array.
const MAX_PLAUSIBLE_CHILDREN: i32 = 64;

/// Cells in the drawn bar.
const BAR_WIDTH: usize = 32;

/// Repaint at most this often, so the spin loop that calls `ChildIsIdle`
/// thousands of times a second cannot flood the console.
const REPAINT_INTERVAL_MILLIS: u128 = 250;

static_detour! {
    static StartChildrenHook: extern "C" fn(*mut core::ffi::c_void, i32) -> i32;
}

static TOTAL_JOBS: AtomicI32 = AtomicI32::new(0);
static LAST_COMPLETED: AtomicI32 = AtomicI32::new(-1);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PAINTING: AtomicBool = AtomicBool::new(false);
static LAST_PAINT_MILLIS: AtomicU64 = AtomicU64::new(0);
static EPOCH: OnceLock<Instant> = OnceLock::new();

fn elapsed_millis() -> u128 {
    EPOCH
        .get()
        .map(|epoch| epoch.elapsed().as_millis())
        .unwrap_or(0)
}

fn format_duration(seconds: u64) -> String {
    let (hours, minutes, secs) = (seconds / 3600, (seconds / 60) % 60, seconds % 60);
    format!("{hours:02}:{minutes:02}:{secs:02}")
}

/// Sums `JobsCompleted` across the master's child array.
///
/// Returns `None` rather than a partial count if anything about the array looks
/// wrong, so a bad read can only cost a repaint.
unsafe fn completed_jobs(commandlet: *mut core::ffi::c_void) -> Option<i32> {
    if commandlet.is_null() {
        return None;
    }
    let base = commandlet as usize;

    let count = (base + CHILD_PROCESSES_NUM) as *const i32;
    let data = (base + CHILD_PROCESSES_DATA) as *const usize;
    let count = count.read_unaligned();
    let data = data.read_unaligned();

    if count <= 0 || count > MAX_PLAUSIBLE_CHILDREN || data == 0 {
        return None;
    }

    let mut total = 0i32;
    for index in 0..count as usize {
        let element = data + index * CHILD_PROCESS_STRIDE;
        let jobs = ((element + CHILD_PROCESS_JOBS_COMPLETED) as *const i32).read_unaligned();
        if !(0..=i32::MAX / 2).contains(&jobs) {
            return None;
        }
        total = total.saturating_add(jobs);
    }
    Some(total)
}

fn paint(completed: i32, total: i32) {
    let fraction = if total > 0 {
        (completed as f64 / total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let filled = (fraction * BAR_WIDTH as f64).round() as usize;
    let bar: String = (0..BAR_WIDTH)
        .map(|cell| if cell < filled { '#' } else { '.' })
        .collect();

    let elapsed = (elapsed_millis() / 1000) as u64;
    // Estimate from throughput so far; meaningless until a job has finished.
    let eta = if completed > 0 && completed < total {
        let per_job = elapsed as f64 / completed as f64;
        format!(
            " ETA {}",
            format_duration((per_job * (total - completed) as f64) as u64)
        )
    } else {
        String::new()
    };

    let line = format!(
        "\r[cook] [{bar}] {:>3}%  {completed}/{total} pkgs  {}{eta}   ",
        (fraction * 100.0) as u32,
        format_duration(elapsed),
    );

    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(line.as_bytes());
    let _ = stdout.flush();
}

/// Called from the `ChildIsIdle` detour once per poll. Cheap and throttled: it
/// only walks the child array when the repaint interval has elapsed.
pub fn tick(commandlet: *mut core::ffi::c_void) {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }

    let total = TOTAL_JOBS.load(Ordering::Relaxed);
    if total <= 0 {
        return;
    }

    let now = elapsed_millis();
    let last = LAST_PAINT_MILLIS.load(Ordering::Relaxed) as u128;
    if now.saturating_sub(last) < REPAINT_INTERVAL_MILLIS {
        return;
    }

    if PAINTING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    if let Some(completed) = unsafe { completed_jobs(commandlet) } {
        // Repaint on a timer even when the count has not moved, so the elapsed
        // clock keeps running and the bar survives being scrolled off by log
        // output.
        LAST_COMPLETED.store(completed, Ordering::Relaxed);
        LAST_PAINT_MILLIS.store(now as u64, Ordering::Relaxed);
        paint(completed, total);

        // Every job is back, so close the bar off on its own line rather than
        // leaving the cook's remaining output to overwrite it. Needs no
        // end-of-cook hook: the counter reaching the total is the signal.
        if completed >= total {
            ACTIVE.store(false, Ordering::SeqCst);
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(b"\n");
            let _ = stdout.flush();
        }
    }

    PAINTING.store(false, Ordering::SeqCst);
}

/// Hook for `UCookPackagesCommandlet::StartChildren`.
///
/// Its argument is the job total and its return value says whether the cook is
/// actually going multithreaded, so both are taken from the one call.
fn start_children_hook(commandlet: *mut core::ffi::c_void, num_files: i32) -> i32 {
    let started = StartChildrenHook.call(commandlet, num_files);

    if started != 0 && num_files > 0 {
        TOTAL_JOBS.store(num_files, Ordering::Relaxed);
        ACTIVE.store(true, Ordering::SeqCst);
        debug_log!("udk_cook_progress: tracking {num_files} packages");
    } else {
        debug_log!(
            "udk_cook_progress: StartChildren declined ({num_files} jobs); \
             single-process cooks are not tracked"
        );
    }

    started
}

/// Only the MT master: `cookpackages` with `-Processes=` and without `-MTCHILD`.
fn is_mt_cook_master() -> bool {
    let mut is_cook = false;
    let mut has_processes = false;
    let mut is_child = false;

    for argument in std::env::args_os() {
        let text = argument.to_string_lossy();
        let trimmed = text.trim_start_matches(['-', '/']);
        let key = trimmed.split_once('=').map(|(k, _)| k).unwrap_or(trimmed);
        if key.eq_ignore_ascii_case("cookpackages") {
            is_cook = true;
        } else if key.eq_ignore_ascii_case("Processes") {
            has_processes = true;
        } else if key.eq_ignore_ascii_case("MTCHILD") {
            is_child = true;
        }
    }

    is_cook && has_processes && !is_child
}

pub fn init() -> anyhow::Result<()> {
    if !is_mt_cook_master() {
        return Ok(());
    }
    if std::env::args_os().any(|argument| {
        argument
            .to_string_lossy()
            .trim_start_matches(['-', '/'])
            .eq_ignore_ascii_case("NOCOOKPROGRESS")
    }) {
        return Ok(());
    }

    debug_log!("udk_cook_progress::init start");

    let (offset, matches) =
        find_signature_offset(&START_CHILDREN_SIG, START_CHILDREN_OFFSET, 0);
    debug_log!("udk_cook_progress: StartChildren signature matches: {matches}");

    let Some(offset) = offset else {
        debug_log!("udk_cook_progress: refusing to install - StartChildren not found");
        return Ok(());
    };

    let _ = EPOCH.set(Instant::now());

    unsafe {
        let udk = get_udk_ptr();
        StartChildrenHook
            .initialize(std::mem::transmute(udk.add(offset)), start_children_hook)
            .context("Failed to setup StartChildren hook")?;
        StartChildrenHook.enable()?;
    }

    debug_log!("udk_cook_progress: installed");
    Ok(())
}
