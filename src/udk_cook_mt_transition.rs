//! Lets a cook that started single-threaded go multithreaded when it reaches the
//! maps, instead of grinding through the entire map phase on one core.
//!
//! # The problem
//!
//! `-Processes=N` is decided once, in `UCookPackagesCommandlet::Init`, and a full
//! recook refuses it: the material shaders are out of date, so the master demotes
//! itself to a single-process cook and stays that way for the whole run. That is
//! the right call for the first two thirds of the work - the non-map packages are
//! what warm the shader cache, and letting N children each rebuild it
//! independently is the redundancy the refusal exists to prevent.
//!
//! It is the wrong call for the last third. Measured over a complete 741-job
//! PCServer cook:
//!
//! ```text
//! 676 non-map packages   mean  0.44s   max   9.1s    5% of the work
//!  65 map packages       mean 85.60s   max 577.9s   95% of the work
//! ```
//!
//! By the time the first map is reached the shader cache is warm, which is
//! precisely the condition the refusal was waiting for - and 95% of the cook is
//! still ahead, running on one core.
//!
//! # What this does
//!
//! It performs by hand the steps `CookPackages` would have taken at the top of
//! the pass had it gone multithreaded, but **split across two moments**:
//!
//! - at the first `.udk` load: neutralise the `bWasMTMaster` restore (see below)
//!   and set `bIsMTMaster`,
//! - at the master's first `StartChildJob`: call `StartChildren(NumJobs)`, which
//!   flushes the PCD and the local shader caches to disk and then launches the
//!   child processes.
//!
//! The next iteration of the package loop then takes the dispatch branch, and
//! every remaining map is handed to a child. Everything downstream - the job
//! spin, `ChildIsIdle`, `StopChildren`, `MergeChildProducts`, `MergeLogs` - is
//! stock code following the flag.
//!
//! # Why the launch is deferred, and not done with the flag
//!
//! Doing both at once does not work, and fails in the worst way: a cook that
//! reports success having silently killed itself. A child that is started but
//! given nothing to do gives up:
//!
//! ```text
//! appError called: Waited more that 60 seconds for another job,
//!                  assume parent is dead, killing myself.
//! ```
//!
//! and `CheckForCrashedChildren` then terminates every sibling and `appErrorf`s
//! the whole cook behind `Child process crashed:`.
//!
//! Setting the flag does not make the master dispatch anything - the branch that
//! calls `StartChildJob` is at the *top* of the loop body, above every point this
//! module can hook, so the package that triggered the transition is still cooked
//! by the master and only the iteration *after* it dispatches. That package is a
//! map. Measured 2026-08-04: children launched at t=809s and the first
//! `StartChildJob` came at t=918s, so all three sat idle for 109s against a 60s
//! timer and took the cook down with them.
//!
//! Hooking `StartChildJob` moves the launch to the exact moment the master has
//! work in hand. A freshly launched child is idle by definition - `ChildIsIdle`
//! tests for the absence of its command file - so the first job is assigned
//! immediately and the timer never starts. It also puts the `BulletProofPCDSave`
//! and `SaveLocalShaderCaches` that `StartChildren` performs after the master's
//! last serial package rather than before it, which is where they belong.
//!
//! Nothing is re-cooked. The packages already finished are behind the loop
//! cursor, and the children inherit the master's warm shader cache because
//! `StartChildren` writes it out before it launches them:
//!
//! ```c
//! BulletProofPCDSave(PersistentCookerData,*(CookedDir * GetBulkDataContainerFilename()));
//! SaveLocalShaderCaches(); // children will load this, and maybe we did some work here.
//! ```
//!
//! # The trap: `bWasMTMaster` silently undoes a mid-loop flip
//!
//! Each pass of the outer `ProcessingPass` loop saves and restores the flag
//! (`UnrealEd/Src/UnContentCookers.cpp`):
//!
//! ```c
//! for (INT ProcessingPass = 0; ProcessingPass < 2; ProcessingPass++)
//! {
//!     UBOOL bWasMTMaster = bIsMTMaster;
//!     if (ProcessingPass == 0) { bIsMTMaster = FALSE; }   // deliberate
//!     else { if (bIsMTMaster) { ... if (!StartChildren(NumJobs)) bIsMTMaster = FALSE; } }
//!     ... package loop ...
//!     bIsMTMaster = bWasMTMaster;                          // the restore
//! }
//!
//! if (bIsMTMaster)
//! {
//!     StopChildren();
//! }
//! ```
//!
//! Setting the flag inside the loop is not enough, because the restore runs
//! *after* the loop and *before* the `StopChildren` decision. Children would be
//! started and given jobs, and then never stopped, waited on, or merged - the
//! cooked data would be left scattered across `CookedDir/Process_<pid>/`
//! directories and the run would report success. Strictly worse than staying
//! serial.
//!
//! So the restore is removed rather than fought:
//!
//! ```asm
//! 0x1411FC06D  MOV EAX, dword [RBP+0x70]           ; bWasMTMaster
//! 0x1411FC070  MOV dword [R13+0x2AB8], EAX         ; bIsMTMaster = bWasMTMaster
//! ```
//!
//! The 7 bytes at `0x1411FC070` become a 7-byte `NOP`, leaving the dead load in
//! place. This is exact rather than a workaround: the restore exists to undo
//! pass 0's deliberate `bIsMTMaster = FALSE`, that undo has already happened by
//! the time any map is reached, and the only thing left for it to revert is the
//! flip this module just made. A scan of all 4096 instructions of `CookPackages`
//! confirms `0x1411FC070` is its only write of `bIsMTMaster` from a saved copy;
//! the other write site, `0x1411F740B`, is the shared `= FALSE` store, which the
//! serial path has already executed and cannot reach again.
//!
//! # Where the transition fires, and why there
//!
//! `LoadPackageForCooking` is hooked, and the transition happens on entry - so
//! the map that triggered it is still cooked by the master, and dispatch begins
//! with the next one. One map cooked serially is the price of the trigger being
//! exact rather than predicted from an index.
//!
//! That entry is also the low-water mark for memory. The package loop runs
//! `CollectGarbageAndVerify()` a few statements earlier and nothing substantial
//! is loaded in between:
//!
//! ```c
//! CollectGarbageAndVerify();
//! ...
//! warnf( NAME_Log, TEXT("Cooking%s%s %s"), ... );
//! Package = LoadPackageForCooking(*SrcFilename);
//! ```
//!
//! Forking N children each wanting ~2 GB is exactly the thing to do immediately
//! after a garbage collection and immediately before the master's own working set
//! grows again.
//!
//! # Known cost: the master keeps one map resident
//!
//! `CollectGarbageAndVerify()` sits *below* the dispatch branch in the loop body,
//! so once the flag is set the master stops reaching it - and the map it cooked
//! in the triggering iteration is never collected. The master therefore carries
//! roughly one map's working set for the rest of the run, on top of whatever the
//! children take.
//!
//! This is the same shape as a stock multithreaded cook, where the master carries
//! everything pass 0 loaded into pass 1 for the same reason, but a map is a good
//! deal larger than the startup packages. Leave headroom in `-Processes=N`
//! accordingly: what fits as a from-the-start MT cook may not fit as a
//! transitioned one.
//!
//! # Why the job count handed to `StartChildren` is the *remaining* maps
//!
//! `StartChildren` caps the child count with `Min(NumChildProcesses,NumFiles)`,
//! and that cap is the only thing standing between this and the starvation
//! failure above: a child with no job to receive kills the cook after 60s. Stock
//! passes the exact number of packages it is about to dispatch, so children can
//! never outnumber jobs.
//!
//! The triggering map is cooked by the master and never dispatched, so the count
//! here is `map jobs - maps already loaded`, which at the transition is one less
//! than `GeneratePackageList` reported. Maps are the tail of the list, so nothing
//! but maps remains and the figure is exact - unless a remaining map carries
//! `bShouldOnlyLoad`, which would leave the last child idle. Erring low is safe
//! and erring high is fatal, which is why this subtracts rather than rounds up,
//! and why the transition is refused outright below three map jobs.
//!
//! # Why the `.udk` test is safe
//!
//! `LoadPackageForCooking` has seven call sites and only one of them is the
//! package loop, so the extension alone is not enough. Two guards narrow it:
//!
//! - **Armed only once `GeneratePackageList` has returned.** That call is the
//!   first thing `CookPackages` does, which excludes the three call sites in
//!   `Init` - including `LoadPackageForCooking(*PackageFilename)` on a `-DLCName`
//!   run, which really does load `.udk` files. The arming comes from
//!   [`crate::udk_cook_progress`], which already hooks `GeneratePackageList` for
//!   the map count this module also needs.
//! - **Pass 0 cannot reach a map.** It breaks out at
//!   `PackageIndex > LastStartupIndex`, and `GeneratePackageList` appends the maps
//!   after everything else, so `FirstMapIndex > LastStartupIndex` always holds.
//!   Without this, a transition during pass 0 would survive into pass 1 (the
//!   restore having been removed) and the stock `if (bIsMTMaster) StartChildren`
//!   would launch a second full set of children.
//!
//! The remaining in-loop call sites load `.upk` startup and per-map packages, and
//! `bIsMTMaster` is re-checked before the flip, so a cook that is already
//! multithreaded is left alone.
//!
//! # Opt-in
//!
//! `-MTTRANSITION`, alongside `-Processes=N`, and never in a child
//! (`StartChildren` appends `-MTCHILD` to the inherited command line, so every
//! child would otherwise inherit the flag too). Without the switch this module
//! installs nothing at all.
//!
//! Nothing else is needed. This only ever fires on a cook that is already running
//! serially, which is the case it exists for: a full recook, where
//! `bMaterialShadersOutdated` makes `Init` refuse `-Processes=N` outright. On an
//! incremental cook with current shaders `Init` goes multithreaded from the
//! start, the master never cooks a map itself, and this module correctly does
//! nothing.
//!
//! # `-SINGLETHREAD` is a test lever, not a recommendation
//!
//! `Init` tests it *before* `bMaterialShadersOutdated`:
//!
//! ```c
//! if (Switches.FindItemIndex(TEXT("SINGLETHREAD")) == INDEX_NONE )
//! {
//!     if ( bMaterialShadersOutdated && !GIsBuildMachine) { warnf(...); }
//!     ...
//!     else { bIsMTMaster = TRUE; }
//! }
//! ```
//!
//! so it forces the serial half on *any* cook, which is the only way to exercise
//! this module on a cheap incremental run instead of a two-hour `-FULL` one. That
//! is what it is for here.
//!
//! Using it on a real cook is a **separate, unmeasured bet**: that cooking the
//! content serially and only the maps in parallel beats a from-the-start
//! multithreaded cook, because N children otherwise each compile overlapping
//! shaders independently - the redundancy Epic's gate exists to prevent - whereas
//! a serial content phase compiles them once and the children inherit a fully
//! warm cache. Plausible on a shader-heavy `-platform=PC` cook, near-certainly a
//! loss on `PCServer` where there are no shaders to warm and the serial phase is
//! pure cost. Nobody has A/B'd it. Do not pair the switches on the strength of
//! this paragraph.

#![cfg(target_arch = "x86_64")]

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use anyhow::{bail, Context};
use retour::static_detour;
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache, Threading::GetCurrentProcess,
};

use crate::dll::{get_udk_ptr, UDK_RANGE};
use crate::patch_utils::{debug_log, find_signature_offset};

/// `UCookPackagesCommandlet::LoadPackageForCooking` in the 12791 (UDK-2015-01)
/// x64 build.
const LOAD_PACKAGE_OFFSET: usize = 0x0011_EDEA0;

/// Prologue, through the first two argument moves:
///
/// ```asm
/// PUSH RBP ; RBX ; RSI ; RDI ; R12 ; R13 ; R14 ; R15
/// MOV  RBP, RSP
/// SUB  RSP, 0x78
/// MOV  qword [RBP-0x58], -2      ; EH state
/// MOV  RSI, RDX                  ; Filename
/// MOV  R14, RCX                  ; this
/// XOR  EBX, EBX
/// MOV  dword [RBP+0x48], EBX
/// ```
///
/// The last two moves are what confirm the argument mapping this hook assumes:
/// `this` in RCX and `const TCHAR* Filename` in RDX. No rip-relative
/// displacement, so this is a plain byte match.
const LOAD_PACKAGE_SIG: [u8; 39] = [
    0x40, 0x55, // PUSH RBP
    0x53, // PUSH RBX
    0x56, // PUSH RSI
    0x57, // PUSH RDI
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, // PUSH R12 ; R13 ; R14 ; R15
    0x48, 0x8B, 0xEC, // MOV RBP,RSP
    0x48, 0x83, 0xEC, 0x78, // SUB RSP,0x78
    0x48, 0xC7, 0x45, 0xA8, 0xFE, 0xFF, 0xFF, 0xFF, // MOV [RBP-0x58],-2
    0x48, 0x8B, 0xF2, // MOV RSI,RDX
    0x4C, 0x8B, 0xF1, // MOV R14,RCX
    0x33, 0xDB, // XOR EBX,EBX
    0x89, 0x5D, 0x48, // MOV [RBP+0x48],EBX
];

/// `MOV dword [R13+0x2AB8], EAX` - the `bIsMTMaster = bWasMTMaster` restore at
/// the end of each `ProcessingPass`.
const RESTORE_RVA: usize = 0x0011_FC070;
const RESTORE_ORIGINAL: [u8; 7] = [0x41, 0x89, 0x85, 0xB8, 0x2A, 0x00, 0x00];
/// `NOP dword ptr [RAX]` in its 7-byte encoding, so the instruction boundary and
/// everything the unwind data says about this frame stay exactly as they were.
const RESTORE_NOP: [u8; 7] = [0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00];

/// `UCookPackagesCommandlet::bIsMTMaster` and `bIsMTChild`.
const B_IS_MT_MASTER: usize = 0x2AB8;
const B_IS_MT_CHILD: usize = 0x2ABC;

/// UDK's `DefaultMapExt`. Content packages are `.upk`, maps are `.udk`, and the
/// cook's own list is built by appending `MapFilenamePairs` last - so this is the
/// same partition the weighting in [`crate::udk_cook_progress`] uses, just read
/// off the filename instead of the index.
const MAP_SUFFIX: [u16; 4] = [b'.' as u16, b'u' as u16, b'd' as u16, b'k' as u16];

/// `UCookPackagesCommandlet::StartChildJob` in the 12791 (UDK-2015-01) x64 build.
const START_CHILD_JOB_OFFSET: usize = 0x0011_E89B0;

/// Prologue, through the register moves that name the arguments:
///
/// ```asm
/// MOV  qword [RSP+0x08], RBX
/// MOV  qword [RSP+0x10], RBP
/// MOV  qword [RSP+0x18], RSI
/// MOV  qword [RSP+0x20], RDI
/// PUSH R12 ; R13 ; R14
/// SUB  RSP, 0x20
/// MOV  R13, RDX          ; const FFilename& Job
/// MOV  RDI, RCX          ; this
/// MOV  R14D, 1
/// ```
///
/// `MOV R13,RDX` / `MOV RDI,RCX` are what confirm the two arguments this hook
/// forwards. No rip-relative displacement, so this is a plain byte match.
const START_CHILD_JOB_SIG: [u8; 42] = [
    0x48, 0x89, 0x5C, 0x24, 0x08, // MOV [RSP+0x08],RBX
    0x48, 0x89, 0x6C, 0x24, 0x10, // MOV [RSP+0x10],RBP
    0x48, 0x89, 0x74, 0x24, 0x18, // MOV [RSP+0x18],RSI
    0x48, 0x89, 0x7C, 0x24, 0x20, // MOV [RSP+0x20],RDI
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, // PUSH R12 ; R13 ; R14
    0x48, 0x83, 0xEC, 0x20, // SUB RSP,0x20
    0x4C, 0x8B, 0xEA, // MOV R13,RDX
    0x48, 0x8B, 0xF9, // MOV RDI,RCX
    0x41, 0xBE, 0x01, 0x00, 0x00, 0x00, // MOV R14D,1
];

static_detour! {
    static LoadPackageForCookingHook: extern "C" fn(*mut core::ffi::c_void, *const u16) -> *mut core::ffi::c_void;
}

static_detour! {
    static StartChildJobHook: extern "C" fn(*mut core::ffi::c_void, *mut core::ffi::c_void);
}

/// Set once `GeneratePackageList` has returned, which is what proves any `.udk`
/// seen afterwards belongs to the package loop rather than to `Init`.
static ARMED: AtomicBool = AtomicBool::new(false);
/// Maps in the list, used as `StartChildren`'s `NumFiles`. -1 means unknown, in
/// which case no transition is attempted.
static MAP_JOBS: AtomicI32 = AtomicI32::new(-1);
/// One transition per process, whether it succeeded or not.
static DONE: AtomicBool = AtomicBool::new(false);
/// Maps the master has loaded itself. Only the triggering one is ever counted in
/// practice, since every iteration after the flip dispatches instead of loading.
static MAPS_LOADED: AtomicI32 = AtomicI32::new(0);
/// Set once the flag is flipped, cleared by the `StartChildJob` that launches the
/// children. That call is the first moment the master has a job in hand, which is
/// the only moment it is safe to start them - see the module header.
static LAUNCH_PENDING: AtomicBool = AtomicBool::new(false);

/// Called from [`crate::udk_cook_progress`]'s `GeneratePackageList` hook.
///
/// Both halves of what this module needs come out of that one call: the fact
/// that `CookPackages` has started, and how many of its jobs are maps.
pub fn arm(map_jobs: Option<i32>) {
    if let Some(maps) = map_jobs {
        MAP_JOBS.store(maps, Ordering::Relaxed);
    }
    ARMED.store(true, Ordering::SeqCst);
}

fn image_address(rva: usize, length: usize) -> anyhow::Result<*mut u8> {
    let range = UDK_RANGE.get().context("UDK_RANGE not set")?;
    let address = range.start.checked_add(rva).context("address overflow")?;
    let end = address.checked_add(length).context("end overflow")?;
    if end > range.end {
        bail!("RVA 0x{rva:X} lies outside UDK.exe");
    }
    Ok(address as *mut u8)
}

/// Reads the restore site without writing, so a binary that does not match this
/// module's expectations can be rejected before anything irreversible happens.
fn restore_site_matches(expected: &[u8; 7]) -> bool {
    match image_address(RESTORE_RVA, RESTORE_ORIGINAL.len()) {
        Ok(address) => {
            unsafe { std::slice::from_raw_parts(address, RESTORE_ORIGINAL.len()) == expected }
        }
        Err(_) => false,
    }
}

fn write_restore_site(bytes: &[u8; 7]) -> anyhow::Result<()> {
    let address = image_address(RESTORE_RVA, bytes.len())?;
    unsafe {
        let _guard =
            region::protect_with_handle(address, bytes.len(), region::Protection::READ_WRITE_EXECUTE)
                .context("failed to make the bIsMTMaster restore writable")?;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), address, bytes.len());
        FlushInstructionCache(GetCurrentProcess(), Some(address.cast()), bytes.len())
            .context("failed to flush the bIsMTMaster restore")?;
    }
    Ok(())
}

unsafe fn read_flag(commandlet: *mut core::ffi::c_void, offset: usize) -> i32 {
    (commandlet as usize as *const u8).add(offset).cast::<i32>().read_unaligned()
}

unsafe fn write_flag(commandlet: *mut core::ffi::c_void, offset: usize, value: i32) {
    (commandlet as usize as *mut u8)
        .add(offset)
        .cast::<i32>()
        .write_unaligned(value);
}

/// `-Processes=N`, which is what `StartChildren` will parse for itself.
///
/// Checked before the flag is flipped rather than relied on afterwards: once the
/// loop is dispatching, a `StartChildren` that returns FALSE would leave
/// `StartChildJob` spinning forever on an empty child array. `StartChildren`'s
/// other refusals - too few cores, too little RAM - are skipped when
/// `-Processes=` is present, and the job count is checked separately, so
/// establishing `N >= 2` here means the deferred call cannot decline.
fn requested_processes() -> Option<i32> {
    for argument in std::env::args_os() {
        let text = argument.to_string_lossy();
        let trimmed = text.trim_start_matches(['-', '/']);
        if let Some((key, value)) = trimmed.split_once('=') {
            if key.eq_ignore_ascii_case("Processes") {
                return value.trim().parse::<i32>().ok();
            }
        }
    }
    None
}

/// Jobs left for the children: the maps, less the ones the master loaded itself.
fn remaining_jobs() -> i32 {
    MAP_JOBS.load(Ordering::Relaxed) - MAPS_LOADED.load(Ordering::Relaxed)
}

/// Flips the cook into multithreaded mode without starting anything.
///
/// The restore is neutralised first, because it is the step that can still be
/// undone: if anything below fails, the original bytes go back and the cook
/// carries on serially exactly as it would have. Children are deliberately not
/// launched here - see the module header for the 60-second timer that makes that
/// fatal.
fn begin_transition(commandlet: *mut core::ffi::c_void, filename: &str) {
    if crate::udk_cook_progress::start_children_address().is_none() {
        crate::udk_log::log(
            crate::udk_log::LogType::Warning,
            "cook MT transition: StartChildren was never resolved (udk_cook_progress is not \
             installed), staying single-threaded",
        );
        return;
    }

    let jobs = remaining_jobs();
    if jobs < 2 {
        crate::udk_log::log(
            crate::udk_log::LogType::Init,
            &format!(
                "cook MT transition: only {jobs} map jobs would be left for children, staying \
                 single-threaded"
            ),
        );
        return;
    }

    match requested_processes() {
        Some(processes) if processes >= 2 => {}
        other => {
            crate::udk_log::log(
                crate::udk_log::LogType::Warning,
                &format!(
                    "cook MT transition: -Processes={} cannot start children, staying \
                     single-threaded",
                    other.map_or("?".to_string(), |value| value.to_string())
                ),
            );
            return;
        }
    }

    if !restore_site_matches(&RESTORE_ORIGINAL) {
        crate::udk_log::log(
            crate::udk_log::LogType::Warning,
            "cook MT transition: the bIsMTMaster restore is not the expected instruction, \
             refusing to transition",
        );
        return;
    }

    if let Err(error) = write_restore_site(&RESTORE_NOP) {
        crate::udk_log::log(
            crate::udk_log::LogType::Warning,
            &format!("cook MT transition: could not neutralise the restore: {error:#}"),
        );
        return;
    }

    unsafe { write_flag(commandlet, B_IS_MT_MASTER, 1) };
    LAUNCH_PENDING.store(true, Ordering::SeqCst);

    crate::udk_log::log(
        crate::udk_log::LogType::Init,
        &format!(
            "cook MT transition: reached the first map ({filename}); the master finishes this \
             one, then {jobs} map jobs go to children"
        ),
    );
}

/// Launches the children, at the first moment the master has a job to hand out.
///
/// Returns whether the cook is still going multithreaded. A refusal here is
/// recoverable only because it happens before the original `StartChildJob` runs:
/// the flag goes back to FALSE and the restore is put back, so the package the
/// master was about to dispatch is cooked by the master instead.
fn launch_children(commandlet: *mut core::ffi::c_void) {
    if !LAUNCH_PENDING.swap(false, Ordering::SeqCst) {
        return;
    }

    let Some(start_children) = crate::udk_cook_progress::start_children_address() else {
        return;
    };
    let jobs = remaining_jobs().max(2);

    // Deliberately called through its address rather than around it, so
    // udk_cook_progress's StartChildren detour sees the call and arms the
    // progress bar with this job count.
    let started = unsafe {
        let entry: extern "C" fn(*mut core::ffi::c_void, i32) -> i32 =
            std::mem::transmute(start_children);
        entry(commandlet, jobs)
    };

    if started == 0 {
        unsafe { write_flag(commandlet, B_IS_MT_MASTER, 0) };
        let _ = write_restore_site(&RESTORE_ORIGINAL);
        crate::udk_log::log(
            crate::udk_log::LogType::Warning,
            "cook MT transition: StartChildren declined after all; reverting to single-threaded",
        );
        return;
    }

    crate::udk_log::log(
        crate::udk_log::LogType::Init,
        "cook MT transition: children are up and the first job goes out now",
    );
}

fn start_child_job_hook(commandlet: *mut core::ffi::c_void, job: *mut core::ffi::c_void) {
    if LAUNCH_PENDING.load(Ordering::Relaxed) && !commandlet.is_null() {
        launch_children(commandlet);
    }

    // If the launch was refused, bIsMTMaster is FALSE again - but this call is
    // already in flight and its package would be lost if it simply returned, so
    // the original still runs. With no children it would spin, which is why
    // `begin_transition` establishes up front that StartChildren cannot decline.
    StartChildJobHook.call(commandlet, job);
}

/// Longest path this will read out of the engine before giving up on it.
const MAX_PATH_CHARS: usize = 4096;

/// Length of a NUL-terminated wide string, capped.
unsafe fn wide_len(text: *const u16) -> Option<usize> {
    let mut len = 0usize;
    while len < MAX_PATH_CHARS {
        if text.add(len).read() == 0 {
            return Some(len);
        }
        len += 1;
    }
    None
}

/// Tested against the wide string in place, because this runs for every package
/// the cook loads and only ever matches one of them - building a `String` first
/// would put an allocation on the path of all the others for nothing.
fn ends_with_map_extension(text: &[u16]) -> bool {
    let Some(tail) = text
        .len()
        .checked_sub(MAP_SUFFIX.len())
        .map(|start| &text[start..])
    else {
        return false;
    };
    tail.iter()
        .zip(MAP_SUFFIX.iter())
        .all(|(&actual, &expected)| {
            actual < 0x80 && (actual as u8).eq_ignore_ascii_case(&(expected as u8))
        })
}

fn load_package_hook(
    commandlet: *mut core::ffi::c_void,
    filename: *const u16,
) -> *mut core::ffi::c_void {
    // Cheapest tests first, in the order that rejects the most for the least: two
    // relaxed atomics, then two null checks, then the flags, and only then the
    // string.
    if ARMED.load(Ordering::Relaxed)
        && !DONE.load(Ordering::Relaxed)
        && !commandlet.is_null()
        && !filename.is_null()
        && unsafe { read_flag(commandlet, B_IS_MT_MASTER) } == 0
        && unsafe { read_flag(commandlet, B_IS_MT_CHILD) } == 0
    {
        if let Some(len) = unsafe { wide_len(filename) } {
            let path = unsafe { std::slice::from_raw_parts(filename, len) };
            if ends_with_map_extension(path) && !DONE.swap(true, Ordering::SeqCst) {
                // Counted before the decision, because this map is the one the
                // master keeps: it must not be included in the children's share.
                MAPS_LOADED.fetch_add(1, Ordering::Relaxed);
                begin_transition(commandlet, &String::from_utf16_lossy(path));
            }
        }
    }

    LoadPackageForCookingHook.call(commandlet, filename)
}

/// `cookpackages -Processes=N -MTTRANSITION`, and never a child.
///
/// `-Processes=` is required even though `StartChildren` would default to a
/// child count without it, because it is also what makes
/// [`crate::udk_cook_progress`] install - and this module's arming signal, map
/// count and `StartChildren` address all come from there. Requiring it here
/// keeps the two modules' conditions identical rather than merely usually equal.
fn wanted() -> bool {
    let mut is_cook = false;
    let mut opted_in = false;
    let mut has_processes = false;
    let mut is_child = false;

    for argument in std::env::args_os() {
        let text = argument.to_string_lossy();
        let trimmed = text.trim_start_matches(['-', '/']);
        let key = trimmed.split_once('=').map(|(k, _)| k).unwrap_or(trimmed);
        if key.eq_ignore_ascii_case("cookpackages") {
            is_cook = true;
        } else if key.eq_ignore_ascii_case("MTTRANSITION") {
            opted_in = true;
        } else if key.eq_ignore_ascii_case("Processes") {
            has_processes = true;
        } else if key.eq_ignore_ascii_case("MTCHILD") {
            is_child = true;
        }
    }

    is_cook && opted_in && has_processes && !is_child
}

pub fn init() -> anyhow::Result<()> {
    if !wanted() {
        return Ok(());
    }

    debug_log!("udk_cook_mt_transition::init start");

    // Everything is verified before a single hook goes in, so a binary this
    // module does not recognise ends up completely untouched rather than half
    // armed.
    if !restore_site_matches(&RESTORE_ORIGINAL) {
        debug_log!(
            "udk_cook_mt_transition: refusing to install - the bIsMTMaster restore at \
             0x{RESTORE_RVA:X} is not the expected instruction"
        );
        return Ok(());
    }

    let (load_package, matches) = find_signature_offset(&LOAD_PACKAGE_SIG, LOAD_PACKAGE_OFFSET, 0);
    debug_log!("udk_cook_mt_transition: LoadPackageForCooking signature matches: {matches}");

    let Some(load_package) = load_package else {
        debug_log!("udk_cook_mt_transition: refusing to install - LoadPackageForCooking not found");
        return Ok(());
    };

    let (start_child_job, matches) =
        find_signature_offset(&START_CHILD_JOB_SIG, START_CHILD_JOB_OFFSET, 0);
    debug_log!("udk_cook_mt_transition: StartChildJob signature matches: {matches}");

    // Both hooks or neither: the flag hook without the launch hook would flip a
    // cook into dispatching to children that are never started, which spins
    // forever instead of failing.
    let Some(start_child_job) = start_child_job else {
        debug_log!("udk_cook_mt_transition: refusing to install - StartChildJob not found");
        return Ok(());
    };

    unsafe {
        let udk = get_udk_ptr();
        LoadPackageForCookingHook
            .initialize(
                std::mem::transmute(udk.add(load_package)),
                load_package_hook,
            )
            .context("Failed to setup LoadPackageForCooking hook")?;
        StartChildJobHook
            .initialize(
                std::mem::transmute(udk.add(start_child_job)),
                start_child_job_hook,
            )
            .context("Failed to setup StartChildJob hook")?;
        LoadPackageForCookingHook.enable()?;
        StartChildJobHook.enable()?;
    }

    debug_log!("udk_cook_mt_transition: installed");
    Ok(())
}
