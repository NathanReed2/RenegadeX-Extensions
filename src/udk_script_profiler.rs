//! Per-function UnrealScript profiler, written as detours on the two script
//! dispatch points.
//!
//! # Why this rather than `PROFILEGAME`
//!
//! The shipping `UDK.exe` does carry Epic's gameplay profiler -
//! `USE_GAMEPLAY_PROFILER` is compiled in, `"GameplayProfiler STARTING
//! capture."` is in `.rdata`, `GGameplayProfiler` is the global at
//! `0x143562588` that `CallFunction` tests on every call, and
//! `Binaries/GameplayProfiler.exe` ships alongside the game to read its output.
//! On a client it is the better tool and this module is not a replacement for
//! it.
//!
//! It cannot profile a **dedicated server**, which is the case that matters
//! here. `FGameplayProfiler::Exec` has exactly one caller - the console exec
//! chain in `UnObj.cpp` - and there is no `ParseParam` autostart anywhere in
//! the tree, so a capture can only begin by someone typing `PROFILEGAME START`
//! at a console a headless server does not have.
//!
//! This is driven by a command line switch and writes a CSV on a timer, so it
//! needs no console and no interaction. It costs nothing when switched off,
//! because without the switch no detour is installed at all.
//!
//! # What it measures
//!
//! Script reaches native code through two disjoint entry points, and this hooks
//! both - the same two Epic instruments:
//!
//! - `UObject::ProcessInternal` is the interpreter. Every script function
//!   *body* runs inside one call to it, whether reached from `CallFunction`
//!   (script calling script) or through `UFunction::Func` from `ProcessEvent`
//!   (C++ calling script). Attributed to `Stack.Node`.
//! - `UObject::CallFunction` additionally dispatches **natives and DLLBind
//!   imports**, which never reach the interpreter at all. Those are attributed
//!   to the `UFunction` it was handed.
//!
//! `CallFunction` deliberately skips script bodies, since `ProcessInternal`
//! already counts those - hooking both without that filter would double count
//! every script call. The classification mirrors `CallFunction`'s own branch
//! order: `iNative != 0`, else `FUNC_DLLImport`, else `FUNC_Native`, else a
//! script body.
//!
//! Measuring natives matters more than it sounds. `Rx_TCPLink:TickListening`
//! measured 118us per server tick with its whole body being one
//! `dllimport c_accept` - a `FUNC_DLLImport` call that goes through libffi and
//! never touches the interpreter. Without the `CallFunction` hook that cost can
//! only appear as unexplained exclusive time in its caller.
//!
//! A shared shadow stack subtracts time spent in nested calls, so the report
//! carries both figures:
//!
//! - **inclusive** - wall time in this function and everything it called.
//! - **exclusive** - wall time in this function's own body.
//!
//! Sort by exclusive to find what to optimise; read inclusive to find what to
//! stop calling. The `kind` column separates interpreted script from native and
//! dllimport work.
//!
//! # What it still cannot see
//!
//! Operator and math natives dispatched straight from bytecode through
//! `GNatives` (`VSize`, `+`, `==`) bypass `CallFunction` entirely, and a native
//! reached through `ProcessEvent` rather than `CallFunction` is missed as well.
//! Both blind spots apply equally to Epic's profiler, which instruments the
//! same two functions.
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
//! symbol-bearing twin. `CallFunction` was identified by its 1024-byte
//! `Buffer` local and its four-way dispatch, and the `UFunction` offsets below
//! were read straight out of that decompilation. Every prologue here was then
//! checked byte for byte against the shipping `Firestorm/Binaries/Win64/UDK.exe`
//! by parsing its PE section table, not just against Ghidra's copy.

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

/// `UFunction::FunctionFlags`, read by `CallFunction` at `+0xD0` to pick its
/// dispatch branch.
const UFUNCTION_FUNCTION_FLAGS: usize = 0x00D0;
/// `UFunction::iNative` - a WORD at `+0xD4`, tested first by `CallFunction`.
/// Non-zero means a hardcoded native invoked straight through `Func`.
const UFUNCTION_INATIVE: usize = 0x00D4;

/// `FUNC_Native`, bit 10 of `FunctionFlags`.
const FUNC_NATIVE: u32 = 0x0000_0400;
/// `FUNC_DLLImport`, bit 25 - a DLLBind import routed through libffi.
const FUNC_DLL_IMPORT: u32 = 0x0200_0000;

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

/// A single call at or above this wall time is recorded individually, not just
/// folded into an average. Averages cannot show a hitch; one 68ms call buried
/// under thousands of cheap ones vanishes into a small mean.
const SPIKE_THRESHOLD_NS: u64 = 1_000_000;

/// How many of the worst spikes to keep. Small enough that re-sorting on insert
/// is free, large enough to show a whole bad call chain rather than just its
/// root.
const MAX_SPIKES: usize = 64;

/// One unusually slow call, kept whole rather than averaged away.
struct Spike {
    function: usize,
    kind: Kind,
    /// What the frame actually stalled for.
    inclusive_ns: u64,
    /// How much of that was this function's own doing - the gap between the two
    /// is what separates "this is slow" from "this called something slow".
    exclusive_ns: u64,
    depth: usize,
    since_start: Duration,
}

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

const PROCESS_EVENT: HookTarget = HookTarget {
    name: "UObject::ProcessEvent",
    rva: 0x0021_6EC0,
    prologue: &[
        0x40, 0x55, 0x41, 0x55, 0x41, 0x56, 0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x8D,
        0x6C, 0x24, 0x20,
    ],
};

const CALL_FUNCTION: HookTarget = HookTarget {
    name: "UObject::CallFunction",
    rva: 0x0020_ED00,
    prologue: &[
        0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81,
        0xEC, 0xC8, 0x04, 0x00, 0x00,
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
/// `void UObject::CallFunction( FFrame& Stack, RESULT_DECL, UFunction* Function )`.
type CallFunction = extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
/// `void UObject::ProcessEvent( UFunction* Function, void* Parms, void* Result )`.
type ProcessEvent = extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
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

static_detour! {
    static CallFunctionHook: extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
}

static_detour! {
    static ProcessEventHook: extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void);
}

static ENGINE_GET_PATH_NAME: OnceLock<GetPathName> = OnceLock::new();
static ENGINE_APP_FREE: OnceLock<AppFree> = OnceLock::new();

/// How a `UFunction`'s time was reached, so the report can separate interpreted
/// bytecode from work that only crosses the VM boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Script,
    Native,
    DllImport,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Script => "script",
            Kind::Native => "native",
            Kind::DllImport => "dllimport",
        }
    }
}

/// One entry per `UFunction` ever called.
struct Stat {
    name: String,
    kind: Kind,
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
    started: Instant,
    total_ns: u64,
    /// Worst calls by inclusive time, descending. Bounded at [`MAX_SPIKES`].
    spikes: Vec<Spike>,
}

impl Profiler {
    /// Keeps `candidate` only if it beats the weakest spike held, so the list
    /// stays the worst N seen rather than the most recent N.
    fn record_spike(&mut self, candidate: Spike) {
        if self.spikes.len() < MAX_SPIKES {
            self.spikes.push(candidate);
        } else if let Some(weakest) = self.spikes.last_mut() {
            if candidate.inclusive_ns <= weakest.inclusive_ns {
                return;
            }
            *weakest = candidate;
        }
        self.spikes
            .sort_by_key(|spike| std::cmp::Reverse(spike.inclusive_ns));
    }
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
            started: Instant::now(),
            total_ns: 0,
            spikes: Vec::with_capacity(MAX_SPIKES),
        });
        body(profiler)
    })
}

/// Times `body`, attributing it to `function`, and keeps the shadow stack that
/// turns nested calls into exclusive time. Shared by both hooks so a native
/// dispatched out of a script body correctly discounts its caller.
fn profile_call(function: usize, kind: Kind, body: impl FnOnce()) {
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
                kind,
                calls: 0,
                inclusive_ns: 0,
                exclusive_ns: 0,
            });
        });
    }

    body();

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

        let exclusive_ns = elapsed_ns.saturating_sub(child_ns);
        if let Some(stat) = profiler.stats.get_mut(&function) {
            stat.calls += 1;
            stat.inclusive_ns += elapsed_ns;
            stat.exclusive_ns += exclusive_ns;
        }

        if elapsed_ns >= SPIKE_THRESHOLD_NS {
            let since_start = profiler.started.elapsed();
            profiler.record_spike(Spike {
                function,
                kind,
                inclusive_ns: elapsed_ns,
                exclusive_ns,
                depth: profiler.stack.len(),
                since_start,
            });
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
                    if let Err(error) = write_spikes(profiler) {
                        debug_log!("script profiler spike dump failed: {error}");
                    }
                }
            }
        }
    });
}

/// Mirrors `CallFunction`'s own branch order to decide who owns this call's
/// time. `None` means an interpreted body, which `ProcessInternal` already
/// counts and this hook must therefore leave alone.
unsafe fn native_kind(function: *mut c_void) -> Option<Kind> {
    let base = function as *const u8;
    // Tested first by CallFunction: a hardcoded native reached through Func.
    if base.add(UFUNCTION_INATIVE).cast::<u16>().read() != 0 {
        return Some(Kind::Native);
    }
    let flags = base.add(UFUNCTION_FUNCTION_FLAGS).cast::<u32>().read();
    if flags & FUNC_DLL_IMPORT != 0 {
        Some(Kind::DllImport)
    } else if flags & FUNC_NATIVE != 0 {
        Some(Kind::Native)
    } else {
        None
    }
}

extern "C" fn process_internal_hook(object: *mut c_void, stack: *mut c_void, result: *mut c_void) {
    if stack.is_null() {
        ProcessInternalHook.call(object, stack, result);
        return;
    }

    let function = unsafe { (stack as *const u8).add(FFRAME_NODE).cast::<usize>().read() };
    profile_call(function, Kind::Script, || {
        ProcessInternalHook.call(object, stack, result)
    });
}

extern "C" fn call_function_hook(
    object: *mut c_void,
    stack: *mut c_void,
    result: *mut c_void,
    function: *mut c_void,
) {
    // Script bodies are counted by the ProcessInternal hook; timing them here
    // as well would double count every script call in the game.
    let Some(kind) = (unsafe { function.as_ref().and_then(|_| native_kind(function)) }) else {
        CallFunctionHook.call(object, stack, result, function);
        return;
    };

    profile_call(function as usize, kind, || {
        CallFunctionHook.call(object, stack, result, function)
    });
}

extern "C" fn process_event_hook(
    object: *mut c_void,
    function: *mut c_void,
    parms: *mut c_void,
    result: *mut c_void,
) {
    // ProcessEvent dispatches through UFunction::Func, which is ProcessInternal
    // for a script body - already counted there. Only a dynamically bound
    // native reaches its own code from here, and that is the one path neither
    // of the other two hooks can see.
    let Some(kind) = (unsafe { function.as_ref().and_then(|_| native_kind(function)) }) else {
        ProcessEventHook.call(object, function, parms, result);
        return;
    };

    profile_call(function as usize, kind, || {
        ProcessEventHook.call(object, function, parms, result)
    });
}

fn report_path(file: &str) -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join(file)))
}

/// Writes the individually-captured slow calls. Kept in its own file rather
/// than appended to the main table so both stay loadable as plain CSV.
fn write_spikes(profiler: &Profiler) -> anyhow::Result<()> {
    let path = report_path("scriptprof-spikes.csv").context("could not locate UDK.exe")?;

    let mut out = String::with_capacity(profiler.spikes.len() * 96 + 256);
    out.push_str(&format!(
        "# individual calls over {:.1} ms, worst {} kept, newest run wins\n\
         # a large inclusive with a small exclusive means this function is not the culprit - read down the depth\n\
         function,kind,depth,inclusive_ms,exclusive_ms,at_seconds\n",
        SPIKE_THRESHOLD_NS as f64 / 1.0e6,
        MAX_SPIKES,
    ));

    for spike in &profiler.spikes {
        let name = profiler
            .stats
            .get(&spike.function)
            .map(|stat| stat.name.as_str())
            .unwrap_or("<unknown>");
        out.push_str(&format!(
            "\"{}\",{},{},{:.3},{:.3},{:.1}\n",
            name.replace('"', "\"\""),
            spike.kind.label(),
            spike.depth,
            spike.inclusive_ns as f64 / 1.0e6,
            spike.exclusive_ns as f64 / 1.0e6,
            spike.since_start.as_secs_f64(),
        ));
    }

    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(out.as_bytes())
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

fn write_report(profiler: &Profiler) -> anyhow::Result<()> {
    let path = report_path("scriptprof.csv").context("could not locate UDK.exe's directory")?;

    let mut rows: Vec<&Stat> = profiler.stats.values().collect();
    rows.sort_by_key(|stat| std::cmp::Reverse(stat.exclusive_ns));

    let (hits, misses) = crate::udk_script_func_cache::stats();
    let lookups = hits + misses;
    let hit_rate = if lookups == 0 {
        0.0
    } else {
        100.0 * hits as f64 / lookups as f64
    };

    // Split the headline figure, because "how much of this is even bytecode"
    // is the first question a report like this has to answer.
    let native_ns: u64 = profiler
        .stats
        .values()
        .filter(|stat| stat.kind != Kind::Script)
        .map(|stat| stat.exclusive_ns)
        .sum();

    let mut out = String::with_capacity(rows.len() * 112 + 320);
    out.push_str(&format!(
        "# measured script time {:.3} ms over {} distinct functions\n\
         # of which {:.3} ms ({:.1}%) is native/dllimport, not interpreted bytecode\n\
         # FindFunction cache: {hits} hits, {misses} misses, {hit_rate:.1}% hit rate\n\
         function,kind,calls,exclusive_ms,inclusive_ms,exclusive_us_per_call\n",
        profiler.total_ns as f64 / 1.0e6,
        rows.len(),
        native_ns as f64 / 1.0e6,
        if profiler.total_ns == 0 {
            0.0
        } else {
            100.0 * native_ns as f64 / profiler.total_ns as f64
        },
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
            "\"{}\",{},{},{:.3},{:.3},{:.3}\n",
            stat.name.replace('"', "\"\""),
            stat.kind.label(),
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
    let call_function_address = CALL_FUNCTION.resolve()?;
    let process_event_address = PROCESS_EVENT.resolve()?;
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

        let call_function: CallFunction = std::mem::transmute(call_function_address);
        CallFunctionHook
            .initialize(call_function, |object, stack, result, function| {
                call_function_hook(object, stack, result, function)
            })
            .context("failed to set up UObject::CallFunction hook")?;

        let process_event: ProcessEvent = std::mem::transmute(process_event_address);
        ProcessEventHook
            .initialize(process_event, |object, function, parms, result| {
                process_event_hook(object, function, parms, result)
            })
            .context("failed to set up UObject::ProcessEvent hook")?;

        ProcessInternalHook
            .enable()
            .context("failed to enable UObject::ProcessInternal hook")?;
        CallFunctionHook
            .enable()
            .context("failed to enable UObject::CallFunction hook")?;
        ProcessEventHook
            .enable()
            .context("failed to enable UObject::ProcessEvent hook")?;
    }

    debug_log!(
        "udk_script_profiler armed by -{}, writing every {}s",
        ENABLE_SWITCH,
        DUMP_INTERVAL.as_secs()
    );
    Ok(())
}
