//! Periodically reports the [`crate::udk_script_func_cache`] hit rate, for a
//! dedicated server console that has no way to drive that module's own
//! debug output.
//!
//! # Why this rather than reading it some other way
//!
//! A dedicated server is headless - there is no console to poll the cache's
//! counters from, and no `PROFILEGAME`-style capture command reaches a
//! detached process either. Writing a CSV on a timer needs no interaction.
//! It costs nothing when switched off, because without the switch no detour
//! is installed at all.
//!
//! # How it ticks
//!
//! It detours `UObject::ProcessInternal` - the interpreter entry every
//! script function body runs through - purely as a place to check a clock.
//! Nothing about the call itself is read or timed; the hook is a single
//! `Instant` comparison before forwarding to the original function, so it
//! costs nothing resembling a profiler's overhead.
//!
//! # Use
//!
//! Launch with `-SCRIPTPROF`. Every 30 seconds, `scriptprof.csv` is written
//! next to `UDK.exe` with the cache's hits, misses, and hit rate. The cache
//! is thread-local and script only ever runs on the game thread, so the
//! figures reflect the same table [`crate::udk_script_func_cache`] itself
//! consults.
//!
//! RVAs were mapped in Ghidra from the symbol-bearing 2013
//! `UDK Source Build with symbols/UDK.exe` to `RenXSDK/UDK.exe`.
//! `ProcessInternal` was located through the sole xref to its "Infinite
//! script recursion" literal, then checked byte for byte against the
//! shipping `Firestorm/Binaries/Win64/UDK.exe` by parsing its PE section
//! table, not just against Ghidra's copy.

#![cfg(target_arch = "x86_64")]

use anyhow::{bail, Context};
use retour::static_detour;
use std::cell::Cell;
use std::ffi::c_void;
use std::io::Write;
use std::time::{Duration, Instant};

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

/// Command line switch that installs this module.
const ENABLE_SWITCH: &str = "SCRIPTPROF";

/// How often the report is rewritten.
const DUMP_INTERVAL: Duration = Duration::from_secs(30);

/// A function whose prologue is verified before it is detoured.
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

/// `void UObject::ProcessInternal( FFrame& Stack, RESULT_DECL )`.
type ProcessInternal = extern "C" fn(*mut c_void, *mut c_void, *mut c_void);

static_detour! {
    static ProcessInternalHook: extern "C" fn(*mut c_void, *mut c_void, *mut c_void);
}

thread_local! {
    /// `None` until the first call on this thread, which dumps immediately
    /// rather than waiting out a full interval first.
    static LAST_DUMP: Cell<Option<Instant>> = const { Cell::new(None) };
}

impl HookTarget {
    /// Validates the prologue and returns the address to detour.
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

extern "C" fn process_internal_hook(object: *mut c_void, stack: *mut c_void, result: *mut c_void) {
    LAST_DUMP.with(|cell| {
        let due = cell.get().is_none_or(|last| last.elapsed() >= DUMP_INTERVAL);
        if due {
            cell.set(Some(Instant::now()));
            if let Err(error) = write_report() {
                debug_log!("script profiler dump failed: {error}");
            }
        }
    });

    ProcessInternalHook.call(object, stack, result)
}

fn write_report() -> anyhow::Result<()> {
    let path = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("scriptprof.csv")))
        .context("could not locate UDK.exe's directory")?;

    let (hits, misses) = crate::udk_script_func_cache::stats();
    let lookups = hits + misses;
    let hit_rate = if lookups == 0 {
        0.0
    } else {
        100.0 * hits as f64 / lookups as f64
    };

    let out =
        format!("# FindFunction cache: {hits} hits, {misses} misses, {hit_rate:.1}% hit rate\n");

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

    unsafe {
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
