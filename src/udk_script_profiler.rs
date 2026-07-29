//! Per-function UnrealScript profiler, written as a detour on the bytecode
//! interpreter entry point.
//!
//! # Why this rather than `PROFILEGAME`
//!
//! The shipping `UDK.exe` does carry Epic's gameplay profiler -
//! `USE_GAMEPLAY_PROFILER` is compiled in, `"GameplayProfiler STARTING
//! capture."` is in `.rdata`, and `PROFILEGAME START` works. But it emits a
//! token stream that only the standalone `GameplayProfiler` tool from the UDK
//! `Tools` folder can read, which is a poor fit for answering one question
//! quickly: which script functions actually cost anything.
//!
//! This writes a CSV instead, and costs nothing when it is switched off,
//! because without the switch no detour is installed at all.
//!
//! # What it measures
//!
//! `UObject::ProcessInternal` is the interpreter: every script function body in
//! the game runs inside one call to it, reached either from
//! `UObject::CallFunction` (script calling script) or through
//! `UFunction::Func` from `UObject::ProcessEvent` (C++ calling script). So one
//! detour sees every script invocation exactly once.
//!
//! Each call is timed and attributed to `Stack.Node`, the `UFunction` being
//! interpreted. A shadow stack subtracts the time spent inside nested calls, so
//! the report carries both figures:
//!
//! - **inclusive** - wall time in this function and everything it called.
//! - **exclusive** - wall time in this function's own bytecode.
//!
//! Sort by exclusive to find what to optimise; read inclusive to find what to
//! stop calling.
//!
//! # Names
//!
//! A `UFunction` is turned into a readable path the first time it is seen, by
//! calling the engine's own `UObject::GetPathName`, and the string is kept
//! afterwards. Resolving on first sight rather than at dump time means this
//! module never dereferences a `UFunction` pointer that a later garbage
//! collection could have freed - after the first sighting the pointer is only
//! ever a map key. The residual wart is that a reaped-then-reallocated
//! `UFunction` landing on the same address would merge two functions' totals,
//! which is a reporting inaccuracy in a development tool and not a crash.
//!
//! # Overhead
//!
//! Two `Instant::now()` reads and a `HashMap` update per script call, so
//! roughly 50-100ns of measurement on top of a call that the interpreter
//! itself runs in a few hundred. Cheap functions therefore look relatively
//! more expensive than they are - trust the ranking and the ratios between
//! runs, not the absolute microseconds.
//!
//! # Use
//!
//! Launch with `-SCRIPTPROF`. Every 30 seconds, and only at a moment when no
//! script is on the stack, `scriptprof.csv` is written next to `UDK.exe`,
//! sorted by exclusive time. Its header line also carries the
//! [`crate::udk_script_func_cache`] hit rate, which is the quickest way to see
//! whether that cache is doing anything.
//!
//! RVAs were mapped in Ghidra from the symbol-bearing 2013
//! `UDK Source Build with symbols/UDK.exe` to `RenXSDK/UDK.exe`.
//! `ProcessInternal` was located through the sole xref to its "Infinite script
//! recursion" literal; `GetPathName` and `appFree` matched by unique prologue
//! searches, and `appFree` diffs 13 of 13 instructions equal against its
//! symbol-bearing twin.

#![cfg(target_arch = "x86_64")]

use anyhow::{bail, Context};
use retour::static_detour;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::Write;
use std::ptr::null_mut;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

/// `FFrame::Node`, the `UStruct` being interpreted - a `UFunction` for every
/// frame `ProcessInternal` runs. UE3 packs its structs to 4 bytes, which is why
/// this is not 8-aligned.
const FFRAME_NODE: usize = 0x14;

/// Command line switch that installs this module.
const ENABLE_SWITCH: &str = "SCRIPTPROF";

/// How often the report is rewritten, checked only when the script stack is
/// empty so a dump can never land mid-call.
const DUMP_INTERVAL: Duration = Duration::from_secs(30);

/// Guards against a desynchronised shadow stack, which an engine-level script
/// error unwinding past the detour epilogue could otherwise leave behind. The
/// interpreter's own `RECURSE_LIMIT` is 250, so anything past this is not a
/// real call depth.
const MAX_TRACKED_DEPTH: usize = 512;

/// A function whose prologue is verified before it is detoured or called.
struct HookTarget {
    name: &'static str,
    rva: usize,
    prologue: &'static [u8],
}

const PROCESS_INTERNAL: HookTarget = HookTarget {
    name: "UObject::ProcessInternal",
    rva: 0x0020_C120,
    prologue: &[
        0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00,
    ],
};

const GET_PATH_NAME: HookTarget = HookTarget {
    name: "UObject::GetPathName",
    rva: 0x0026_AD90,
    prologue: &[
        0x48, 0x89, 0x54, 0x24, 0x10, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x20,
        0xFE, 0xFF, 0xFF, 0xFF,
    ],
};

const APP_FREE: HookTarget = HookTarget {
    name: "appFree",
    rva: 0x001C_AFE0,
    prologue: &[0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x0D],
};

/// `TArray<TCHAR>`. `Num` counts the null terminator; an empty string has a
/// null `data`.
#[repr(C)]
struct FString {
    data: *mut u16,
    num: i32,
    max: i32,
}

/// `void UObject::ProcessInternal( FFrame& Stack, RESULT_DECL )`.
type ProcessInternal = extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
/// `FString UObject::GetPathName( UObject* StopOuter ) const`.
///
/// This returns a struct by value from a member function, so MSVC keeps `this`
/// in RCX and passes the caller's result slot in **RDX**, pushing `StopOuter`
/// out to R8 - not the sret-first order a free function would use. Confirmed
/// against the disassembly, which moves RDX into RBX, zeroes `[RBX]` and
/// `[RBX+8]`, then forwards RBX as the third argument to the real worker.
/// Getting this backwards makes the callee read the result slot as `this`.
type GetPathName = extern "C" fn(*mut c_void, *mut FString, *mut c_void) -> *mut FString;
/// `void appFree( void* Original )`.
type AppFree = extern "C" fn(*mut c_void);

static_detour! {
    static ProcessInternalHook: extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
}

static ENGINE_GET_PATH_NAME: OnceLock<GetPathName> = OnceLock::new();
static ENGINE_APP_FREE: OnceLock<AppFree> = OnceLock::new();

/// One entry per `UFunction` ever interpreted.
struct Stat {
    name: String,
    calls: u64,
    inclusive_ns: u64,
    exclusive_ns: u64,
}

/// One live `ProcessInternal` call. The start time lives in the detour's own
/// frame rather than here, so an unwind that skips the epilogue cannot leave a
/// half-formed sample behind.
struct Frame {
    function: usize,
    /// Time attributed to nested calls, subtracted to get exclusive time.
    child_ns: u64,
}

struct Profiler {
    stack: Vec<Frame>,
    stats: HashMap<usize, Stat>,
    last_dump: Instant,
    total_ns: u64,
}

thread_local! {
    static PROFILER: UnsafeCell<Option<Profiler>> = const { UnsafeCell::new(None) };
}

impl HookTarget {
    /// Validates the prologue and returns the address to detour or call.
    fn resolve(&self) -> anyhow::Result<*const ()> {
        let range = UDK_RANGE.get().context("UDK_RANGE not set")?;
        let address = range
            .start
            .checked_add(self.rva)
            .with_context(|| format!("{} address overflow", self.name))?;
        let end = address
            .checked_add(self.prologue.len())
            .with_context(|| format!("{} end overflow", self.name))?;
        if end > range.end {
            bail!("{} lies outside UDK.exe", self.name);
        }

        let actual =
            unsafe { std::slice::from_raw_parts(address as *const u8, self.prologue.len()) };
        if actual != self.prologue {
            bail!(
                "{} validation failed at RVA 0x{:X}: expected {:02X?}, found {:02X?}",
                self.name,
                self.rva,
                self.prologue,
                actual
            );
        }
        Ok(address as *const ())
    }
}

/// Asks the engine for an object's full path. Returns `None` rather than
/// guessing if anything is missing, so an unnamed row is visibly unnamed.
unsafe fn engine_path_name(object: *mut c_void) -> Option<String> {
    if object.is_null() {
        return None;
    }
    let get_path_name = ENGINE_GET_PATH_NAME.get()?;
    let app_free = ENGINE_APP_FREE.get()?;

    let mut result = FString {
        data: null_mut(),
        num: 0,
        max: 0,
    };
    // this, result slot, StopOuter - see the GetPathName type alias.
    get_path_name(object, &mut result, null_mut());

    if result.data.is_null() || result.num <= 1 {
        return None;
    }

    // Num counts the terminator that the engine wrote; the text is everything
    // before it.
    let units = std::slice::from_raw_parts(result.data, (result.num - 1) as usize);
    let text = String::from_utf16_lossy(units);
    app_free(result.data.cast());
    Some(text)
}

/// Borrows the calling thread's profiler, creating it on first use. Sound
/// because the state is thread-local and the closure never re-enters the
/// detour; the borrow is always released before the interpreter is called.
fn with_profiler<T>(body: impl FnOnce(&mut Profiler) -> T) -> T {
    PROFILER.with(|cell| {
        let slot = unsafe { &mut *cell.get() };
        let profiler = slot.get_or_insert_with(|| Profiler {
            stack: Vec::with_capacity(64),
            stats: HashMap::new(),
            last_dump: Instant::now(),
            total_ns: 0,
        });
        body(profiler)
    })
}

extern "C" fn process_internal_hook(object: *mut c_void, stack: *mut c_void, result: *mut c_void) {
    if stack.is_null() {
        ProcessInternalHook.call(object, stack, result);
        return;
    }

    let function = unsafe { (stack as *const u8).add(FFRAME_NODE).cast::<usize>().read() };

    let started = Instant::now();
    let unnamed = with_profiler(|profiler| {
        if profiler.stack.len() >= MAX_TRACKED_DEPTH {
            // Only reachable if a previous call left the stack behind. Drop it
            // rather than grow without bound; the totals stay usable.
            profiler.stack.clear();
        }
        profiler.stack.push(Frame {
            function,
            child_ns: 0,
        });
        !profiler.stats.contains_key(&function)
    });

    // Named on first sight, while the UFunction is certainly alive, so nothing
    // after this dereferences the pointer again. Deliberately outside the
    // borrow above: GetPathName runs engine code, and no engine call is allowed
    // to observe a live `&mut` into the thread-local state.
    if unnamed {
        let name = unsafe { engine_path_name(function as *mut c_void) }
            .unwrap_or_else(|| format!("<unnamed 0x{function:X}>"));
        with_profiler(|profiler| {
            profiler.stats.entry(function).or_insert(Stat {
                name,
                calls: 0,
                inclusive_ns: 0,
                exclusive_ns: 0,
            });
        });
    }

    ProcessInternalHook.call(object, stack, result);

    let elapsed_ns = started.elapsed().as_nanos() as u64;
    with_profiler(|profiler| {
        let Some(frame) = profiler.stack.pop() else {
            return;
        };
        // A cleared stack can hand back somebody else's frame; attribute the
        // sample to what we actually entered with.
        let child_ns = if frame.function == function {
            frame.child_ns
        } else {
            0
        };

        if let Some(stat) = profiler.stats.get_mut(&function) {
            stat.calls += 1;
            stat.inclusive_ns += elapsed_ns;
            stat.exclusive_ns += elapsed_ns.saturating_sub(child_ns);
        }

        match profiler.stack.last_mut() {
            Some(parent) => parent.child_ns += elapsed_ns,
            None => {
                // Back at the top of a script entry, so the whole of it counts
                // once towards the measured total and a dump cannot interleave
                // with a live call.
                profiler.total_ns += elapsed_ns;
                if profiler.last_dump.elapsed() >= DUMP_INTERVAL {
                    profiler.last_dump = Instant::now();
                    if let Err(error) = write_report(profiler) {
                        debug_log!("script profiler dump failed: {error}");
                    }
                }
            }
        }
    });
}

fn report_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("scriptprof.csv")))
}

fn write_report(profiler: &Profiler) -> anyhow::Result<()> {
    let path = report_path().context("could not locate UDK.exe's directory")?;

    let mut rows: Vec<&Stat> = profiler.stats.values().collect();
    rows.sort_by_key(|stat| std::cmp::Reverse(stat.exclusive_ns));

    let (hits, misses) = crate::udk_script_func_cache::stats();
    let lookups = hits + misses;
    let hit_rate = if lookups == 0 {
        0.0
    } else {
        100.0 * hits as f64 / lookups as f64
    };

    let mut out = String::with_capacity(rows.len() * 96 + 256);
    out.push_str(&format!(
        "# measured script time {:.3} ms over {} distinct functions\n\
         # FindFunction cache: {hits} hits, {misses} misses, {hit_rate:.1}% hit rate\n\
         function,calls,exclusive_ms,inclusive_ms,exclusive_us_per_call\n",
        profiler.total_ns as f64 / 1.0e6,
        rows.len(),
    ));

    for stat in rows {
        let per_call_us = if stat.calls == 0 {
            0.0
        } else {
            stat.exclusive_ns as f64 / stat.calls as f64 / 1.0e3
        };
        // Paths carry no commas or quotes, but a corrupt read might, so the
        // field is quoted and any quote doubled.
        out.push_str(&format!(
            "\"{}\",{},{:.3},{:.3},{:.3}\n",
            stat.name.replace('"', "\"\""),
            stat.calls,
            stat.exclusive_ns as f64 / 1.0e6,
            stat.inclusive_ns as f64 / 1.0e6,
            per_call_us,
        ));
    }

    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(out.as_bytes())
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

fn enabled() -> bool {
    std::env::args_os().any(|argument| {
        argument
            .to_string_lossy()
            .to_ascii_uppercase()
            .trim_start_matches(['-', '/'])
            == ENABLE_SWITCH
    })
}

pub fn init() -> anyhow::Result<()> {
    if !enabled() {
        return Ok(());
    }

    let process_internal_address = PROCESS_INTERNAL.resolve()?;
    let get_path_name_address = GET_PATH_NAME.resolve()?;
    let app_free_address = APP_FREE.resolve()?;

    unsafe {
        let _ = ENGINE_GET_PATH_NAME.set(std::mem::transmute::<*const (), GetPathName>(
            get_path_name_address,
        ));
        let _ = ENGINE_APP_FREE.set(std::mem::transmute::<*const (), AppFree>(app_free_address));

        let process_internal: ProcessInternal = std::mem::transmute(process_internal_address);
        ProcessInternalHook
            .initialize(process_internal, |object, stack, result| {
                process_internal_hook(object, stack, result)
            })
            .context("failed to set up UObject::ProcessInternal hook")?;
        ProcessInternalHook
            .enable()
            .context("failed to enable UObject::ProcessInternal hook")?;
    }

    debug_log!(
        "udk_script_profiler armed by -{}, writing every {}s",
        ENABLE_SWITCH,
        DUMP_INTERVAL.as_secs()
    );
    Ok(())
}
