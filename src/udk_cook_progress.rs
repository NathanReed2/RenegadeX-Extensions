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
//! # Why the bar is weighted rather than counting packages
//!
//! Cook jobs are violently bimodal, so a count-based bar and the ETA derived from
//! it are not merely imprecise - they are wrong by orders of magnitude. Measured
//! over a complete 741-job PCServer cook:
//!
//! ```text
//! 676 non-map packages   mean  0.44s   max   9.1s    5% of the work
//!  65 map packages       mean 85.60s   max 577.9s   95% of the work
//! ```
//!
//! Maps are 9% of the count and 95% of the cost, a 195x per-job ratio, and the
//! engine dispatches them **last** (`GeneratePackageList` appends `MapFilenamePairs`
//! after everything else). So a counting bar reached 90% at t=91s and then took a
//! further 715s to finish, and its ETA at that moment predicted 11s against 715s
//! actual. Weighting by cost instead put the same moment at 21% against 23% of the
//! wall clock actually elapsed.
//!
//! The split is not guessed. `UCookPackagesCommandlet::GeneratePackageList` hands
//! back the assembled list and reports where the maps begin:
//!
//! ```c
//! TArray<FPackageCookerInfo> UCookPackagesCommandlet::GeneratePackageList(
//!     INT& FirstStartupIndex, INT& FirstScriptIndex,
//!     INT& FirstGameScriptIndex, INT& FirstMapIndex )
//! ...
//!     if( MapFilenamePairs.Num() )
//!     {
//!         FirstMapIndex = SortedFilenamePairs.Num();   // maps are the tail
//!         SortedFilenamePairs += MapFilenamePairs;
//!     }
//! ```
//!
//! so `Num() - FirstMapIndex` is the map count, known before the first job is
//! dispatched - which is what makes the bar right from t=0 on a first run rather
//! than only after the phase change becomes observable.
//!
//! Per-job costs are then measured live (a child's `JobsCompleted` stepping tells
//! us how long its last job took) and persisted to `CookProgress.stats` beside the
//! cooked data, so a repeat cook starts with the previous run's costs instead of
//! the built-in priors.
//!
//! # There is deliberately no ETA
//!
//! One was built, measured, and removed. The tail of a cook is not a throughput
//! problem: a job cannot be split across children, so the finish time is set by
//! the single longest map rather than by how much work is left. On a measured
//! 875s cook the last job ran alone for its final nine minutes, and the bar sat at
//! 98% throughout - an ETA over that stretch has nothing to estimate *from*. The
//! version that floored the estimate by the longest running job simply drifted
//! upward as that job continued (1:23 -> 2:23 while stuck at 98%), which is worse
//! than no number at all: it looked authoritative and was steadily wrong.
//!
//! Elapsed time is shown instead. It is always true.
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

/// Where the signature above resolved to, published for
/// [`crate::udk_cook_mt_transition`] - which calls `StartChildren` by hand and
/// must not re-run the signature search, because by then the detour below has
/// replaced the prologue it would be matching against.
static START_CHILDREN_ADDRESS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The address `StartChildren` was found at, once [`init`] has run.
pub(crate) fn start_children_address() -> Option<usize> {
    match START_CHILDREN_ADDRESS.load(Ordering::Relaxed) {
        0 => None,
        address => Some(address),
    }
}

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

/// `UCookPackagesCommandlet::GeneratePackageList` in the 12791 (UDK-2015-01) x64
/// build.
///
/// Identified by diffing against the symbol-bearing 2013 build (which is compiled
/// from `D:\Firestorm SDK\UE3 2013 Base`, so its names are the source's): 2268
/// instructions on both sides, 1999 equal and exactly one changed - a `LEA
/// RDI,[RCX+0x7d8]` that became `[RCX+0x1258]` as the commandlet grew. It also
/// sits immediately before `CookPackages`, its only caller, in both images.
const GENERATE_PACKAGE_LIST_OFFSET: usize = 0x0011_F4710;

/// Prologue of `GeneratePackageList`, through the EH state store:
///
/// ```asm
/// MOV  RAX, RSP
/// MOV  qword [RAX+0x20], R9      ; home FirstScriptIndex
/// MOV  qword [RAX+0x18], R8      ; home FirstStartupIndex
/// MOV  qword [RAX+0x10], RDX     ; home this
/// MOV  qword [RAX+0x08], RCX     ; home the hidden return pointer
/// PUSH RBP ; RBX ; RSI ; RDI ; R12 ; R13 ; R14 ; R15
/// LEA  RBP, [RAX-0x358]
/// SUB  RSP, 0x418
/// MOV  qword [RBP+0x2D0], -2
/// ```
///
/// The four homing stores are what confirm the argument mapping used by
/// [`generate_package_list_hook`]: MSVC passes the hidden struct-return pointer
/// ahead of `this`, so the four `INT&` out-parameters land in R8, R9 and the two
/// stack slots. No rip-relative displacement, so this is a plain byte match.
const GENERATE_PACKAGE_LIST_SIG: [u8; 56] = [
    0x48, 0x8B, 0xC4, // MOV RAX,RSP
    0x4C, 0x89, 0x48, 0x20, // MOV [RAX+0x20],R9
    0x4C, 0x89, 0x40, 0x18, // MOV [RAX+0x18],R8
    0x48, 0x89, 0x50, 0x10, // MOV [RAX+0x10],RDX
    0x48, 0x89, 0x48, 0x08, // MOV [RAX+0x08],RCX
    0x55, 0x53, 0x56, 0x57, // PUSH RBP ; RBX ; RSI ; RDI
    0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, // PUSH R12 ; R13 ; R14 ; R15
    0x48, 0x8D, 0xA8, 0xA8, 0xFC, 0xFF, 0xFF, // LEA RBP,[RAX-0x358]
    0x48, 0x81, 0xEC, 0x18, 0x04, 0x00, 0x00, // SUB RSP,0x418
    0x48, 0xC7, 0x85, 0xD0, 0x02, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, // MOV [RBP+0x2D0],-2
];

/// `TArray::ArrayNum`, which is all this module reads out of the returned list.
const TARRAY_NUM: usize = 0x8;

/// Costs assumed before anything has been measured and with no stats file to
/// load. Only used for the first minutes of a first-ever cook.
const DEFAULT_FAST_MILLIS: u64 = 500;
const DEFAULT_MAP_MILLIS: u64 = 60_000;

/// Samples needed before a measured mean displaces the prior.
const MIN_SAMPLES: u32 = 3;

/// `StartChildren` itself clamps to 48 children; anything beyond this means the
/// pointer being read is not really the array.
const MAX_PLAUSIBLE_CHILDREN: i32 = 64;

/// Cells in the drawn bar.
const BAR_WIDTH: usize = 32;

/// Repaint at most this often, so the spin loop that calls `ChildIsIdle`
/// thousands of times a second cannot flood the console.
const REPAINT_INTERVAL_MILLIS: u128 = 250;

/// How often the background ticker repaints so the elapsed clock keeps moving.
///
/// `tick` only runs when the engine calls `ChildIsIdle`, and the master stops
/// doing that for long stretches - an 18s `BulletProofPCDSave` is the worst case,
/// during which log lines keep scrolling past a bar whose clock has frozen. This
/// repaints on its own so the seconds always advance while output is moving.
const CLOCK_INTERVAL_MILLIS: u64 = 250;

/// How often the same figures also go to the log.
///
/// The bar itself is drawn to the console and leaves no trace, so without this
/// there is no record of what it predicted - which makes an ETA impossible to
/// hold to account after the fact, and leaves an unattended cook with no progress
/// history at all.
const PROGRESS_LOG_INTERVAL_MILLIS: u64 = 60_000;

static_detour! {
    static StartChildrenHook: extern "C" fn(*mut core::ffi::c_void, i32) -> i32;
}

// Its own block, and with no trailing comma after the last argument: both of
// those send `static_detour!` into unbounded recursion rather than a parse error,
// so the compiler reports "recursion limit reached" and suggests a bigger limit
// that never helps - it just asks for double again on the next build.
//
// `MOV [RAX+0x08],RCX` in the prologue homes the hidden struct-return pointer,
// so it arrives *before* `this` - hence six slots for a function the source
// declares with four arguments. On Windows x64 `extern "C"` is the Microsoft
// ABI, which places them in RCX, RDX, R8, R9 and then `[RSP+0x20]`, `[RSP+0x28]`.
static_detour! {
    static GeneratePackageListHook: extern "C" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut i32,
        *mut i32,
        *mut i32,
        *mut i32
    ) -> *mut core::ffi::c_void;
}

static TOTAL_JOBS: AtomicI32 = AtomicI32::new(0);
static LAST_COMPLETED: AtomicI32 = AtomicI32::new(-1);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PAINTING: AtomicBool = AtomicBool::new(false);
/// Set once the first tick has reported what it could and could not do.
static DIAGNOSED: AtomicBool = AtomicBool::new(false);
static LAST_PAINT_MILLIS: AtomicU64 = AtomicU64::new(0);
static LAST_LOG_MILLIS: AtomicU64 = AtomicU64::new(0);
static EPOCH: OnceLock<Instant> = OnceLock::new();

/// How many of the trailing jobs are maps, or -1 while unknown. Unknown means
/// the bar falls back to weighting every package the same, which is what it did
/// before this was available.
static MAP_JOBS: AtomicI32 = AtomicI32::new(-1);

/// Running cost model, rebuilt each cook and seeded from the previous one.
///
/// Guarded by a mutex rather than split into atomics because the samples have to
/// move together to stay consistent, and `tick` is throttled to 4 Hz so the lock
/// is never contended.
static MODEL: std::sync::Mutex<Model> = std::sync::Mutex::new(Model::new());

#[derive(Default)]
struct Model {
    /// Last `JobsCompleted` seen per child, or -1 for a child not yet observed.
    child_last_count: Vec<i32>,
    /// When each child most recently started a job, as `elapsed_millis`.
    child_job_start: Vec<u64>,

    /// Completions folded into the model so far, which is what decides whether
    /// the next one belongs to the fast span or the map tail.
    jobs_seen: u32,

    fast_samples: u32,
    fast_total_millis: u64,
    map_samples: u32,
    map_total_millis: u64,
    map_max_millis: u64,

    /// Costs carried over from the last completed cook, if there was one.
    prior_fast_millis: Option<u64>,
    prior_map_millis: Option<u64>,
}

impl Model {
    const fn new() -> Self {
        Self {
            child_last_count: Vec::new(),
            child_job_start: Vec::new(),
            jobs_seen: 0,
            fast_samples: 0,
            fast_total_millis: 0,
            map_samples: 0,
            map_total_millis: 0,
            map_max_millis: 0,
            prior_fast_millis: None,
            prior_map_millis: None,
        }
    }

    /// Mean cost of a non-map package: measured if there is enough evidence,
    /// otherwise the previous cook's figure, otherwise the built-in prior.
    fn fast_millis(&self) -> u64 {
        if self.fast_samples >= MIN_SAMPLES {
            return (self.fast_total_millis / self.fast_samples as u64).max(1);
        }
        self.prior_fast_millis.unwrap_or(DEFAULT_FAST_MILLIS).max(1)
    }

    fn map_millis(&self) -> u64 {
        if self.map_samples >= MIN_SAMPLES {
            return (self.map_total_millis / self.map_samples as u64).max(1);
        }
        self.prior_map_millis.unwrap_or(DEFAULT_MAP_MILLIS).max(1)
    }

    /// Folds one finished job into the bucket its **position** puts it in.
    ///
    /// Position, not duration, because these two means are multiplied back by the
    /// positional job counts to get the total work - so they have to measure the
    /// same populations those counts describe. Classifying by duration instead
    /// sounds more precise and is actually wrong: this content has ~15 expensive
    /// non-map packages (`RX_BU_Prefabs`, `EngineMeshes`, ~143s each) sitting
    /// inside the 691-package "fast" span, and filing them under maps leaves their
    /// 2145s of work counted in neither bucket - a 22% underestimate of the cook.
    ///
    /// Jobs finish out of order, but never more than one child's worth out of
    /// dispatch order, so the nth completion is the nth dispatch to within the
    /// number of children.
    fn record(&mut self, millis: u64, fast_jobs: i32) {
        self.jobs_seen += 1;
        if self.jobs_seen as i64 > fast_jobs as i64 {
            self.map_samples += 1;
            self.map_total_millis += millis;
        } else {
            self.fast_samples += 1;
            self.fast_total_millis += millis;
        }
        // Tracked across both buckets purely to size the tail estimate.
        self.map_max_millis = self.map_max_millis.max(millis);
    }

    /// Takes a fresh reading of every child's finished-job count and turns the
    /// increments into job durations.
    ///
    /// A child's job started when its previous one finished - measured across a
    /// full cook, the gap between the two is at most 0.07s, so the difference is
    /// the job's duration to well within what the bar needs.
    fn observe(&mut self, now: u64, per_child: &[i32], fast_jobs: i32) {
        if self.child_last_count.len() != per_child.len() {
            self.child_last_count = vec![-1; per_child.len()];
            self.child_job_start = vec![0; per_child.len()];
        }

        for (index, &count) in per_child.iter().enumerate() {
            let previous = self.child_last_count[index];
            if count <= previous {
                continue;
            }

            // The first sighting of a child only establishes a start time; there
            // is no earlier completion to measure from, and timing its first job
            // from the arming instant would charge child startup to that job and
            // misfile a 0.4s package as a map.
            let start = self.child_job_start[index];
            if previous >= 0 && start > 0 {
                // A single tick can span more than one completion, so split the
                // window evenly rather than crediting it all to one job.
                let jobs = (count - previous) as u64;
                let each = now.saturating_sub(start) / jobs.max(1);
                for _ in 0..jobs {
                    self.record(each, fast_jobs);
                }
            }

            self.child_job_start[index] = now;
            self.child_last_count[index] = count;
        }
    }

}

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

/// `JobsCompleted` for every child, and their sum.
///
/// A fixed array rather than a `Vec` because this is now read on *every*
/// `ChildIsIdle` call - thousands a second - rather than only when the repaint
/// throttle allows. Sixteen unaligned loads are nothing; an allocation per call
/// would not be.
struct Census {
    completed: i32,
    per_child: [i32; MAX_PLAUSIBLE_CHILDREN as usize],
    children: usize,
}

impl Census {
    fn counts(&self) -> &[i32] {
        &self.per_child[..self.children]
    }
}

/// Sums `JobsCompleted` across the master's child array.
///
/// Returns `None` rather than a partial count if anything about the array looks
/// wrong, so a bad read can only cost a repaint.
unsafe fn completed_jobs(commandlet: *mut core::ffi::c_void) -> Option<Census> {
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
    let mut per_child = [0i32; MAX_PLAUSIBLE_CHILDREN as usize];
    for index in 0..count as usize {
        let element = data + index * CHILD_PROCESS_STRIDE;
        let jobs = ((element + CHILD_PROCESS_JOBS_COMPLETED) as *const i32).read_unaligned();
        if !(0..=i32::MAX / 2).contains(&jobs) {
            return None;
        }
        total = total.saturating_add(jobs);
        per_child[index] = jobs;
    }
    Some(Census {
        completed: total,
        per_child,
        children: count as usize,
    })
}

/// Writes a line to the console as UTF-16.
///
/// UDK writes its log wide, which leaves the console stream in UTF-16 mode, so
/// narrow bytes written through `std::io::stdout` are re-read as UTF-16: the
/// text comes out as CJK filler and - worse - the `\r` is swallowed into a wide
/// character instead of returning the carriage, so every repaint appends rather
/// than overwriting. `WriteConsoleW` on the console handle sidesteps the CRT
/// stream mode entirely.
///
/// `UDK.com` is a console stub that launches `UDK.exe` and relays its output, so
/// inside this process stdout is a **pipe, not a console** - measured, via the
/// `console writable false` diagnostic on a live cook. There is therefore no
/// console handle to write to in the normal case, and the bar has to go down the
/// pipe in the encoding the relay expects.
///
/// That encoding is UTF-16: UDK writes its log wide, and the first attempt at
/// this bar (narrow UTF-8 through `std::io::stdout`) came out the other end as
/// CJK filler with the `\r` absorbed into a wide character, which is precisely
/// what UTF-8 bytes look like when re-read as UTF-16.
///
/// Both paths are kept, because running `UDK.exe` directly does give a real
/// console, and `WriteConsoleW` is correct there regardless of stream mode.
/// Direct handle to the console screen buffer, or 0 if there is no console.
static CONSOLE: OnceLock<isize> = OnceLock::new();
/// Window height the scroll region is currently reserved for, or 0 when no
/// region is reserved. Kept as the height rather than a flag so a resize is
/// detectable - see [`pin`].
static PINNED_ROWS: AtomicI32 = AtomicI32::new(0);

/// Opens the console screen buffer directly and turns on VT sequence handling.
///
/// `GetStdHandle(STD_OUTPUT_HANDLE)` is useless here: `UDK.com` launches
/// `UDK.exe` with stdout redirected into a pipe it relays, so there is no console
/// handle on stdout (measured - the `console writable false` diagnostic). The
/// process is still *attached* to that console though, so `CONOUT$` opens the
/// screen buffer itself and bypasses the pipe entirely.
fn console() -> Option<windows::Win32::Foundation::HANDLE> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        AttachConsole, GetConsoleMode, SetConsoleMode, ATTACH_PARENT_PROCESS, CONSOLE_MODE,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    };

    let raw = *CONSOLE.get_or_init(|| unsafe {
        let name: Vec<u16> = "CONOUT$\0".encode_utf16().collect();
        let open = || {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                0x8000_0000 | 0x4000_0000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )
        };

        // UDK.exe is a GUI-subsystem binary, so it starts with no console of its
        // own and CONOUT$ cannot be opened - measured, which is what forced the
        // inline fallback. Its parent UDK.com does own the console that launched
        // it, and ATTACH_PARENT_PROCESS adopts that one. After this CONOUT$
        // resolves to the real screen buffer and scroll margins become usable.
        //
        // Harmless if it fails (already attached, or launched without a console):
        // the open below is retried either way and the inline path still covers us.
        let handle = match open() {
            Ok(handle) if !handle.is_invalid() => Ok(handle),
            _ => {
                let _ = AttachConsole(ATTACH_PARENT_PROCESS);
                open()
            }
        };

        match handle {
            Ok(handle) if !handle.is_invalid() => {
                // Scroll margins are a VT feature, so the terminal has to be in VT
                // mode before DECSTBM will do anything.
                let mut mode = CONSOLE_MODE::default();
                if GetConsoleMode(handle, &mut mode).is_ok() {
                    let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
                handle.0
            }
            _ => 0,
        }
    });

    (raw != 0).then_some(HANDLE(raw))
}

/// Raw write of a UTF-16 string to the console screen buffer.
fn emit(text: &str) -> bool {
    use windows::Win32::System::Console::WriteConsoleW;

    let Some(handle) = console() else {
        return false;
    };
    let wide: Vec<u16> = text.encode_utf16().collect();

    unsafe {
        // windows-0.52 types WriteConsoleW's buffer as `&[u8]` but forwards `len()`
        // as nNumberOfCharsToWrite, which the API counts in *characters*. Passing
        // the UTF-16 bytes directly would ask for twice as many characters as exist
        // and read off the end. This slice keeps the wide pointer but carries the
        // character count, so it spans half the allocation and stays in bounds.
        let buffer = std::slice::from_raw_parts(wide.as_ptr().cast::<u8>(), wide.len());
        let mut written = 0u32;
        WriteConsoleW(handle, buffer, Some(&mut written), None).is_ok()
    }
}

/// Number of rows in the console window.
fn console_rows() -> Option<i16> {
    use windows::Win32::System::Console::{
        GetConsoleScreenBufferInfo, CONSOLE_SCREEN_BUFFER_INFO,
    };

    let handle = console()?;
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    unsafe { GetConsoleScreenBufferInfo(handle, &mut info).ok()? };
    Some(info.srWindow.Bottom - info.srWindow.Top + 1)
}

/// Reserves the last row by confining the scrolling region to everything above
/// it, so UDK's log output can no longer scroll over the bar.
///
/// Re-run whenever the window height changes. A scroll region reserved once and
/// left alone breaks the moment the user resizes: shrinking the window leaves the
/// old region extending past the new bottom row, so the bar is then drawn *inside*
/// the scrolling area and every subsequent log line shunts a copy of it upward -
/// one fossil per repaint, interleaved with the cook's output.
fn pin(rows: i16) {
    let wanted = if rows >= 3 { rows as i32 } else { 0 };
    let previous = PINNED_ROWS.swap(wanted, Ordering::Relaxed);
    if previous == wanted {
        return;
    }

    if previous != 0 {
        // Hand the old region back before reserving a different one, and wipe the
        // row the bar used to occupy so the resize does not strand a copy of it.
        // Only when that row still exists - after a shrink the terminal clamps the
        // address, and clearing it would eat a line of the cook's own output.
        emit("\x1b[r");
        if previous <= rows as i32 {
            emit(&format!("\x1b[{previous};1H\x1b[2K"));
        }
    }

    if wanted != 0 {
        // DECSTBM: margins are 1-based and inclusive.
        emit(&format!("\x1b[1;{}r", rows - 1));
    }
}

/// Releases the reserved row and leaves the cursor below the bar.
fn unpin() {
    let rows = PINNED_ROWS.swap(0, Ordering::SeqCst);
    if rows == 0 {
        return;
    }
    let rows = console_rows().map_or(rows, |current| current as i32);
    emit("\x1b[r"); // reset margins to the full window
    emit(&format!("\x1b[{rows};1H\r\n"));
}

/// Draws `text` on the reserved bottom row without disturbing the cursor the
/// engine's own logging is writing at.
fn write_console(text: &str) -> bool {
    if console().is_some() {
        if let Some(rows) = console_rows() {
            // Measured fresh every paint rather than cached, because this is the
            // only thing that notices a resize.
            pin(rows);
            // DECSC/DECRC (save/restore cursor) rather than CSI s/u, which
            // conflicts with the horizontal-margin sequence on some terminals.
            return emit(&format!("\x1b7\x1b[{rows};1H\x1b[2K{text}\x1b8"));
        }
    }

    // No reachable console screen buffer. Fall back to the pipe UDK.com relays -
    // inline and scrolled away by each log line, but visible, which beats a bar
    // that silently does not exist. Making CONOUT$ a hard requirement is exactly
    // how this regressed to nothing being drawn at all.
    write_pipe(text)
}

/// Inline fallback: UTF-16LE down stdout, which is the pipe `UDK.com` relays.
///
/// The trailing spaces cover the tail of a previous, longer line, since `\r` only
/// returns the cursor and does not clear.
fn write_pipe(text: &str) -> bool {
    let line = format!("\r{text}    ");
    let wide: Vec<u16> = line.encode_utf16().collect();

    let mut bytes = Vec::with_capacity(wide.len() * 2);
    for unit in &wide {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    let mut stdout = std::io::stdout();
    stdout.write_all(&bytes).is_ok() && stdout.flush().is_ok()
}

/// What the bar reports for one reading.
struct Estimate {
    fraction: f64,
    maps_left: i32,
}

/// Turns a job count into a share of the *work*, which is not the same thing.
///
/// See the module header for why counting packages does not work, and why this
/// deliberately stops at a fraction rather than going on to predict a finish time.
fn estimate(completed: i32, total: i32, model: &Model) -> Estimate {
    let completed = completed.clamp(0, total);
    let map_jobs = MAP_JOBS.load(Ordering::Relaxed).clamp(0, total);
    let fast_jobs = total - map_jobs;

    let fast_cost = model.fast_millis() as f64;
    let map_cost = model.map_millis();

    // Maps are the tail of the list and are dispatched last, so the split of what
    // has finished follows from the count alone - no need to identify individual
    // jobs. At the boundary this is off by however many are in flight, which is
    // at most one job per child and self-corrects on the next tick.
    let completed_fast = completed.min(fast_jobs);
    let completed_maps = (completed - fast_jobs).max(0);

    let done = completed_fast as f64 * fast_cost + completed_maps as f64 * map_cost as f64;
    let remaining = (fast_jobs - completed_fast) as f64 * fast_cost
        + (map_jobs - completed_maps) as f64 * map_cost as f64;
    let work = done + remaining;

    let fraction = if work > 0.0 {
        (done / work).clamp(0.0, 1.0)
    } else {
        0.0
    };

    Estimate {
        fraction,
        maps_left: map_jobs - completed_maps,
    }
}

fn paint(completed: i32, total: i32, model: &Model) {
    let now = elapsed_millis() as u64;
    let estimate = estimate(completed, total, model);

    let filled = (estimate.fraction * BAR_WIDTH as f64).round() as usize;
    let bar: String = (0..BAR_WIDTH)
        .map(|cell| if cell < filled { '#' } else { '.' })
        .collect();

    // The count still gets shown - it is what the engine's own log lines report,
    // so the two have to be reconcilable - but the bar and the percentage track
    // work rather than count.
    let maps = if estimate.maps_left > 0 {
        format!(" ({} maps left)", estimate.maps_left)
    } else {
        String::new()
    };
    let line = format!(
        "[cook] [{bar}] {:>3}%  {completed}/{total} pkgs{maps}  {}",
        (estimate.fraction * 100.0) as u32,
        format_duration(now / 1000),
    );

    write_console(&line);
}

/// Redraws the bar from the last counts read, advancing only the clock.
///
/// Deliberately does not touch the commandlet: this runs on its own thread, and
/// walking engine structures from off the game thread to move a clock forward
/// would be trading a real risk for a cosmetic gain. The job counts it shows are
/// whatever [`tick`] last observed.
fn repaint_clock() {
    let total = TOTAL_JOBS.load(Ordering::Relaxed);
    let completed = LAST_COMPLETED.load(Ordering::Relaxed);
    if total <= 0 || completed < 0 {
        return;
    }

    if PAINTING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    if let Ok(model) = MODEL.lock() {
        LAST_PAINT_MILLIS.store(elapsed_millis() as u64, Ordering::Relaxed);
        paint(completed, total, &model);
    }
    PAINTING.store(false, Ordering::SeqCst);
}

/// Starts the clock ticker, once, when the bar arms.
///
/// Only for the pinned route. The inline fallback cannot repaint in place - `\r`
/// returns the cursor but the next log line appends and scrolls it away - so
/// ticking it on a timer would produce a fossil every 250ms instead of one line
/// per completed job. There the clock advancing is not worth ~1600 junk lines.
///
/// Started here rather than from `init`, which runs under the Windows loader lock
/// where spawning a thread is not safe.
fn start_clock() {
    if console().is_none() {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("cook-progress-clock".to_string())
        .spawn(|| {
            while ACTIVE.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(CLOCK_INTERVAL_MILLIS));
                if ACTIVE.load(Ordering::Relaxed) {
                    repaint_clock();
                }
            }
        });
}

/// Called from the `ChildIsIdle` detour once per poll.
///
/// The child array is read on **every** call, and only the painting is throttled.
/// Throttling the read instead loses the last job: `ChildIsIdle` is what
/// increments `JobsCompleted`, and the master stops polling the moment the queue
/// drains, so the call that carries the final increment is also the last one there
/// will ever be. If the 250ms throttle happens to swallow it, nothing else comes
/// along to correct the count - which is why a finished cook sat at "99% 154/155"
/// under the "Cook finished OK" prompt, with the reserved row never handed back,
/// and why the persisted stats recorded 49 of 50 maps.
pub fn tick(commandlet: *mut core::ffi::c_void) {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }

    let total = TOTAL_JOBS.load(Ordering::Relaxed);
    if total <= 0 {
        return;
    }

    if PAINTING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let now = elapsed_millis();
    let read = unsafe { completed_jobs(commandlet) };

    // One-shot diagnosis of the two things that can silently kill the bar: an
    // unreadable ChildProcesses array, or stdout not being a console.
    if !DIAGNOSED.swap(true, Ordering::SeqCst) {
        // Report which output path is actually in use. The previous version of
        // this line said "console writable true" on the pipe fallback too, which
        // was measuring whether a write succeeded rather than where it went.
        let route = if console().is_some() {
            "pinned bottom row via CONOUT$"
        } else {
            "inline via UDK.com pipe (no console screen buffer reachable)"
        };
        crate::udk_log::log(
            crate::udk_log::LogType::Init,
            &format!(
                "cook progress: first tick - ChildProcesses read {}, output route: {route}, \
                 total {total}, maps {}",
                match &read {
                    Some(census) => format!("OK ({} jobs done)", census.completed),
                    None => "FAILED (layout mismatch)".to_string(),
                },
                match MAP_JOBS.load(Ordering::Relaxed) {
                    -1 => "unknown (weighting every package equally)".to_string(),
                    maps => format!("{maps}"),
                },
            ),
        );
    }

    if let Some(census) = read {
        let completed = census.completed;

        let moved = LAST_COMPLETED.swap(completed, Ordering::Relaxed) != completed;
        let finished = completed >= total;
        // Repaint on a timer even when the count has not moved, so the elapsed
        // clock keeps running and the bar survives being scrolled off by log
        // output.
        let due = now.saturating_sub(LAST_PAINT_MILLIS.load(Ordering::Relaxed) as u128)
            >= REPAINT_INTERVAL_MILLIS;

        // Nothing to do on the overwhelming majority of calls, which is what keeps
        // reading every time affordable.
        if !(moved || due || finished) {
            PAINTING.store(false, Ordering::SeqCst);
            return;
        }
        LAST_PAINT_MILLIS.store(now as u64, Ordering::Relaxed);

        let fast_jobs = total - MAP_JOBS.load(Ordering::Relaxed).clamp(0, total);
        if let Ok(mut model) = MODEL.lock() {
            model.observe(now as u64, census.counts(), fast_jobs);

            // A pinned bar can repaint in place, so it may tick on the timer to
            // keep the clock live. The inline fallback cannot - `\r` returns the
            // cursor but the next log line appends and scrolls it away, so every
            // repaint leaves a fossil. Measured: UDK.exe has no console (only a
            // pipe to UDK.com), so inline is the normal case, and at 4Hz it
            // produced ~1600 fossil lines per cook. Drawing only when the count
            // moves yields one line per completed job, which is the same cadence
            // as the engine's own "done in" lines.
            if moved || finished || console().is_some() {
                paint(completed, total, &model);
            }

            let due = LAST_LOG_MILLIS.load(Ordering::Relaxed);
            if now as u64 >= due.saturating_add(PROGRESS_LOG_INTERVAL_MILLIS) || finished {
                LAST_LOG_MILLIS.store(now as u64, Ordering::Relaxed);
                let estimate = estimate(completed, total, &model);
                crate::udk_log::log(
                    crate::udk_log::LogType::Init,
                    &format!(
                        "cook progress: {}% ({completed}/{total} pkgs, {} maps left) elapsed {} \
                         [costs: fast {}ms x{}, map {}ms x{}]",
                        (estimate.fraction * 100.0) as u32,
                        estimate.maps_left,
                        format_duration(now as u64 / 1000),
                        model.fast_millis(),
                        model.fast_samples,
                        model.map_millis(),
                        model.map_samples,
                    ),
                );

                // Persisted on the same cadence rather than only at the end. The
                // master stops polling ChildIsIdle once the queue drains, so the
                // tick that would see completed == total often never happens -
                // measured: a clean 155-job cook finished without one, and wrote
                // no stats at all. Saving as we go also means a cook that is
                // killed still teaches the next one something.
                save_stats(&model);
            }

        }

        // Every job is back, so close the bar off on its own line rather than
        // leaving the cook's remaining output to overwrite it. Needs no
        // end-of-cook hook: the counter reaching the total is the signal, which
        // only holds because the count above is read unthrottled.
        if finished {
            ACTIVE.store(false, Ordering::SeqCst);
            // Hand the reserved row back before the cook's closing output arrives,
            // otherwise the console keeps scrolling inside the shrunken region for
            // the rest of the session.
            unpin();
        }
    }

    PAINTING.store(false, Ordering::SeqCst);
}

/// Where the cost model is kept between cooks: beside the cooked data, so each
/// platform keeps its own and wiping a cooked tree wipes its statistics too.
///
/// Derived from `-platform=` exactly as `udk_cook_pcd_checkpoint` derives the
/// PCD path (`<exe>\..\..\UDKGame\Cooked<Platform>\`).
fn stats_path() -> Option<std::path::PathBuf> {
    let platform = std::env::args_os().find_map(|argument| {
        let text = argument.to_string_lossy();
        let (key, value) = text.trim_start_matches(['-', '/']).split_once('=')?;
        key.eq_ignore_ascii_case("platform")
            .then(|| value.trim().to_string())
    })?;

    let base = std::env::current_exe().ok().and_then(|exe| {
        exe.parent()
            .and_then(|dir| dir.parent())
            .and_then(|dir| dir.parent())
            .map(|dir| dir.to_path_buf())
    })?;

    Some(
        base.join("UDKGame")
            .join(format!("Cooked{platform}"))
            .join("CookProgress.stats"),
    )
}

/// Seeds the model with the last completed cook's costs.
///
/// Anything unparseable is ignored rather than repaired: a corrupt stats file
/// must never be able to stop a cook, and the built-in priors are a fine
/// fallback.
fn load_stats(model: &mut Model) {
    let Some(text) = stats_path().and_then(|path| std::fs::read_to_string(path).ok()) else {
        return;
    };

    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Ok(value) = value.trim().parse::<u64>() else {
            continue;
        };
        match key.trim() {
            "fast_millis" if value > 0 => model.prior_fast_millis = Some(value),
            "map_millis" if value > 0 => model.prior_map_millis = Some(value),
            _ => {}
        }
    }
}

/// Writes the costs this cook measured, for the next one to start from.
///
/// Only measured values are written; if a cook was too short to observe either
/// cluster, the previous file is left alone rather than overwritten with priors.
fn save_stats(model: &Model) {
    if model.fast_samples < MIN_SAMPLES && model.map_samples < MIN_SAMPLES {
        return;
    }
    let Some(path) = stats_path() else {
        return;
    };

    let text = format!(
        "# Cook job costs measured by TotemArts Extensions; delete to reset.\n\
         version=1\n\
         fast_millis={}\n\
         map_millis={}\n\
         map_max_millis={}\n\
         fast_samples={}\n\
         map_samples={}\n",
        model.fast_millis(),
        model.map_millis(),
        model.map_max_millis,
        model.fast_samples,
        model.map_samples,
    );
    let _ = std::fs::write(path, text);
}

/// Hook for `UCookPackagesCommandlet::GeneratePackageList`.
///
/// Runs once per cook, before `StartChildren`, and exists only to learn how much
/// of the job list is maps - see the module header for why that dominates.
///
/// Nothing is altered: the original builds the list, and this reads two numbers
/// out of the result afterwards. A reading that fails validation leaves
/// `MAP_JOBS` at -1, which degrades the bar to equal weighting rather than
/// producing a confidently wrong estimate.
fn generate_package_list_hook(
    result: *mut core::ffi::c_void,
    commandlet: *mut core::ffi::c_void,
    first_startup: *mut i32,
    first_script: *mut i32,
    first_game_script: *mut i32,
    first_map: *mut i32,
) -> *mut core::ffi::c_void {
    let returned = GeneratePackageListHook.call(
        result,
        commandlet,
        first_startup,
        first_script,
        first_game_script,
        first_map,
    );

    let read = |pointer: *mut i32| -> Option<i32> {
        (!pointer.is_null()).then(|| unsafe { pointer.read_unaligned() })
    };

    let packages = (!returned.is_null())
        .then(|| unsafe { ((returned as usize + TARRAY_NUM) as *const i32).read_unaligned() });
    let map_index = read(first_map);

    // INDEX_NONE means the cook has no maps at all, which is the -nomaps pass the
    // user runs first; equal weighting is then exactly right.
    let maps = match (packages, map_index) {
        (Some(packages), Some(index)) if index > 0 && index < packages => {
            MAP_JOBS.store(packages - index, Ordering::Relaxed);
            Some(packages - index)
        }
        _ => None,
    };

    // This return is also the point that separates `Init` from `CookPackages`,
    // which is the guard the serial->MT transition needs before it can trust a
    // `.udk` load to belong to the package loop. It gets the map count from the
    // same reading.
    crate::udk_cook_mt_transition::arm(maps);

    // Logged rather than trusted silently: the four out-parameters are positional
    // and only their order in the source distinguishes them, so this line is what
    // confirms the mapping on a real cook. FirstScriptIndex <= FirstStartupIndex
    // <= FirstMapIndex < Num is the invariant the assembled list guarantees.
    crate::udk_log::log(
        crate::udk_log::LogType::Init,
        &format!(
            "cook progress: package list has {} entries (startup {}, script {}, game script {}, \
             first map {}) -> {}",
            packages.map_or("?".to_string(), |value| value.to_string()),
            read(first_startup).map_or("?".to_string(), |value| value.to_string()),
            read(first_script).map_or("?".to_string(), |value| value.to_string()),
            read(first_game_script).map_or("?".to_string(), |value| value.to_string()),
            map_index.map_or("?".to_string(), |value| value.to_string()),
            match maps {
                Some(maps) => format!("{maps} map jobs, weighting enabled"),
                None => "no map split, weighting every package equally".to_string(),
            },
        ),
    );

    returned
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
        start_clock();
    }

    // Install confirmation is deferred to here rather than done in init(), which
    // runs from DllMain under the loader lock where udk_log would deadlock. This
    // is the first point that proves the detour is live.
    crate::udk_log::log(
        crate::udk_log::LogType::Init,
        &format!(
            "cook progress: StartChildren returned {started} for {num_files} jobs; \
             bar {}",
            if started != 0 && num_files > 0 { "ARMED" } else { "inactive" }
        ),
    );

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

    // Reading the stats file here is safe - it is plain file IO with no engine
    // calls - whereas logging from init() would deadlock under the loader lock.
    if let Ok(mut model) = MODEL.lock() {
        load_stats(&mut model);
    }

    unsafe {
        let udk = get_udk_ptr();
        START_CHILDREN_ADDRESS.store(udk.add(offset) as usize, Ordering::Relaxed);
        StartChildrenHook
            .initialize(std::mem::transmute(udk.add(offset)), start_children_hook)
            .context("Failed to setup StartChildren hook")?;
        StartChildrenHook.enable()?;
    }

    // The map split is a refinement, not a prerequisite: if this second hook
    // cannot be placed the bar still draws, just with every package weighted the
    // same. So a failure here is logged and swallowed rather than propagated.
    let (offset, matches) = find_signature_offset(
        &GENERATE_PACKAGE_LIST_SIG,
        GENERATE_PACKAGE_LIST_OFFSET,
        0,
    );
    debug_log!("udk_cook_progress: GeneratePackageList signature matches: {matches}");

    if let Some(offset) = offset {
        unsafe {
            let udk = get_udk_ptr();
            let installed = GeneratePackageListHook
                .initialize(
                    std::mem::transmute(udk.add(offset)),
                    generate_package_list_hook,
                )
                .and_then(|hook| hook.enable());
            if installed.is_err() {
                debug_log!("udk_cook_progress: GeneratePackageList hook failed to install");
            }
        }
    } else {
        debug_log!("udk_cook_progress: GeneratePackageList not found - equal weighting");
    }

    debug_log!("udk_cook_progress: installed");
    Ok(())
}
