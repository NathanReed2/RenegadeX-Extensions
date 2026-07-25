//! This module contains a hook for the low-level array/byte-buffer append
//! helper at udk.exe+0x1A2A00, which crashes with an assertion failure
//! (`i>=0 && (i<ArrayNum||(i==0 && ArrayNum==0))`, Array.h:575) when called
//! with a negative byte count.
//!
//! This has been observed to fire exactly once per cook, right at the very
//! end of a full `CookPackages` run, while
//! `UCookPackagesCommandlet::SaveCookedPackage` is finalizing the combined
//! "Startup" seekfree package (`Startup.upk`) — every other package
//! (all script `.u` files, `GuidCache.upk`, `GlobalPersistentCookerData.upk`,
//! `Startup_LOC_INT.upk`, etc.) is already fully written to disk by that
//! point, and this crash otherwise kills the process before it can finish
//! writing `Startup.upk` and exit cleanly.
use anyhow::Context;
use retour::static_detour;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;

use crate::dll::{get_udk_ptr, UDK_RANGE};

#[cfg(target_arch = "x86_64")]
const FUN_1401A2A00_OFFSET: usize = 0x001A_2A00;

#[cfg(target_arch = "x86_64")]
const FUN_1401A2A00_SIG: [u8; 52] = [
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20, 0x41,
    0x54, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x99, 0x8C, 0x00, 0x00, 0x00, 0x8B, 0x81, 0x88, 0x00,
    0x00, 0x00, 0x49, 0x63, 0xF0, 0x2B, 0x43, 0x08, 0x4C, 0x8B, 0xE2, 0x48, 0x8B, 0xF9, 0x03, 0xC6,
    0x85, 0xC0, 0x7E, 0x37,
];

static_detour! {
    static Fun1401a2a00Hook: extern "C" fn(i64, *mut c_void, i32);
}

/// Appends a line to `renxhook.log` next to the game executable. Used
/// throughout this module to trace when/where the hook is installed and
/// when it actually fires, since this crash is otherwise hard to reproduce
/// on demand (it depends on cook state/content).
fn debug_log(msg: &str) {
    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("renxhook.log")));

    if let Some(path) = path {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{msg}");
        }
    }
}

/// Scans the loaded `udk.exe` image for [`FUN_1401A2A00_SIG`] and returns
/// the best matching offset (closest to the known [`FUN_1401A2A00_OFFSET`]),
/// so the hook keeps working even if the game binary is a slightly
/// different build/patch level than the one the offset was captured from.
#[cfg(target_arch = "x86_64")]
fn find_fun_1401a2a00_offset() -> Option<usize> {
    let range = UDK_RANGE.get()?;
    let base = range.start as *const u8;
    let len = range.end.checked_sub(range.start)?;
    let sig = &FUN_1401A2A00_SIG;

    if len < sig.len() {
        return None;
    }

    let bytes = unsafe { std::slice::from_raw_parts(base, len) };

    let mut matches = Vec::new();
    for i in 0..=(bytes.len() - sig.len()) {
        if &bytes[i..(i + sig.len())] == sig {
            matches.push(i);
        }
    }

    debug_log(&format!(
        "FUN_1401a2a00 signature matches: {}",
        matches.len()
    ));

    if matches.is_empty() {
        return None;
    }

    let expected = FUN_1401A2A00_OFFSET;
    let best = matches
        .into_iter()
        .min_by_key(|m| m.abs_diff(expected))
        .unwrap_or(expected);

    Some(best)
}

/// Hook for the array/byte-buffer append helper at udk.exe+0x1A2A00.
///
/// Ghidra decompilation of the original function:
///
///   void FUN_1401a2a00(longlong param_1, void *param_2, int param_3)
///   {
///       // param_1 = buffer object (ArrayNum at +0x88, {Data,ArrayMax} ptr at +0x8c)
///       // param_2 = source bytes, param_3 = byte count to append
///       plVar2 = *(longlong **)(param_1 + 0x8c);
///       iVar3 = (*(int *)(param_1 + 0x88) - (int)plVar2[1]) + param_3; // growth needed
///       if (0 < iVar3) { /* grow ArrayMax; realloc */ }
///       if (param_3 != 0) {
///           iVar3 = *(int *)(param_1 + 0x88);         // i = current write offset (ArrayNum)
///           if ((iVar3 < 0) || (ArrayMax <= iVar3 && (iVar3 != 0 || ArrayMax != 0)))
///               FUN_140245eb0("i>=0 && (i<ArrayNum||(i==0 && ArrayNum==0))", ..., 0x23f, ...);
///           memcpy(base + iVar3, param_2, param_3);
///       }
///   }
///
/// A negative `param_3` makes the growth-needed calculation
/// `(ArrayNum - ArrayMax) + param_3` come out `<= 0` even when the buffer
/// is already full, so the realloc is skipped — then the bounds check
/// below it fails and the game asserts/crashes. A legitimate call should
/// never pass a negative byte count, so this hook treats that case as a
/// no-op (skips the append) instead of letting it crash.
fn fun_1401a2a00_hook(this: i64, src: *mut c_void, count: i32) {
    if count < 0 {
        debug_log(&format!(
            "FUN_1401a2a00 hook fired: count == {count} (negative), skipping append instead of crashing"
        ));
        return;
    }

    Fun1401a2a00Hook.call(this, src, count);
}

/// Locates `FUN_1401a2a00` (via signature scan, falling back to the known
/// static offset) and installs [`Fun1401a2a00Hook`] over it so the
/// negative-count case can no longer crash the game.
pub fn init() -> anyhow::Result<()> {
    let udk = get_udk_ptr();
    debug_log("udk_array_append::init start");

    if let Some(range) = UDK_RANGE.get() {
        debug_log(&format!(
            "UDK range: start=0x{:X} end=0x{:X} size=0x{:X}",
            range.start,
            range.end,
            range.end.saturating_sub(range.start)
        ));
    }

    #[cfg(target_arch = "x86_64")]
    let hook_offset = find_fun_1401a2a00_offset().unwrap_or(FUN_1401A2A00_OFFSET);

    #[cfg(target_arch = "x86_64")]
    debug_log(&format!(
        "FUN_1401a2a00 hook offset selected: 0x{hook_offset:X}"
    ));

    #[cfg(target_arch = "x86_64")]
    debug_log(&format!(
        "FUN_1401a2a00 hook absolute addr: 0x{:X}",
        (udk as usize).saturating_add(hook_offset)
    ));

    unsafe {
        Fun1401a2a00Hook
            .initialize(
                std::mem::transmute(udk.add(hook_offset)),
                fun_1401a2a00_hook,
            )
            .context("Failed to setup FUN_1401a2a00 hook")?;

        Fun1401a2a00Hook.enable()?;
    }

    debug_log("udk_array_append::init done");

    Ok(())
}
