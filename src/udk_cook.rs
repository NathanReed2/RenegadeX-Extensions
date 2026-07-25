//! This module contains a hook for the lookup accessor at udk.exe+0xA1F740,
//! which crashes when called with a NULL `this` pointer.
use crate::dll::{get_udk_ptr, UDK_RANGE};
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;
use retour::static_detour;

#[cfg(target_arch = "x86_64")]
const FUN_140A1F740_OFFSET: usize = 0x00A1_F740;

#[cfg(target_arch = "x86_64")]
const FUN_140A1F740_SIG: [u8; 18] = [
    0x48, 0x83, 0xEC, 0x28, 0x8B, 0x89, 0x8C, 0x00, 0x00, 0x00, 0xE8, 0x51, 0xFF, 0xFF, 0xFF, 0x48,
    0x85, 0xC0,
];

static_detour! {
    static Fun140a1f740Hook: extern "C" fn(i64) -> i64;
}

/// Appends a line to `renxhook.log` next to the game executable. Used
/// throughout this module to trace when/where the hook is installed and
/// when it actually fires, since this crash is otherwise hard to reproduce
/// on demand (it depends on game/cook state).
/// Scans the loaded `udk.exe` image for [`FUN_140A1F740_SIG`] and returns
/// the best matching offset (closest to the known [`FUN_140A1F740_OFFSET`]),
/// so the hook keeps working even if the game binary is a slightly
/// different build/patch level than the one the offset was captured from.
#[cfg(target_arch = "x86_64")]
fn find_fun_140a1f740_offset() -> Option<usize> {
    let (best, count) = find_signature_offset(&FUN_140A1F740_SIG, FUN_140A1F740_OFFSET, 0);
    debug_log!("FUN_140a1f740 signature matches: {count}");
    best
}

/// Hook for the lookup accessor at udk.exe+0xA1F740.
///
/// Ghidra decompilation of the original function:
///
///   undefined8 FUN_140a1f740(longlong param_1)
///   {
///       undefined8 *puVar1;
///       puVar1 = (undefined8 *)FUN_140a1f6a0(*(undefined4 *)(param_1 + 0x8c);
///       if (puVar1 != (undefined8 *)0x0) {
///           return *puVar1;
///       }
///       return 0;
///   }
///
/// The original function unconditionally dereferences `param_1 + 0x8C` with
/// no NULL check on `param_1` ("this"). Some call site passes a NULL object
/// pointer here, which crashes with an access violation reading address
/// 0x8C. This hook mirrors the function's own "not found" return path (0)
/// when `this` is NULL, instead of letting it crash.
fn fun_140a1f740_hook(this: i64) -> i64 {
    if this == 0 {
        debug_log!("FUN_140a1f740 hook fired: this == NULL, returning 0 instead of crashing");
        return 0;
    }

    Fun140a1f740Hook.call(this)
}

/// Locates `FUN_140a1f740` (via signature scan, falling back to the known
/// static offset) and installs [`Fun140a1f740Hook`] over it so the NULL
/// `this` case can no longer crash the game.
pub fn init() -> anyhow::Result<()> {
    let udk = get_udk_ptr();
    debug_log!("udk_null_lookup::init start");

    if let Some(range) = UDK_RANGE.get() {
        debug_log!(
            "UDK range: start=0x{:X} end=0x{:X} size=0x{:X}",
            range.start,
            range.end,
            range.end.saturating_sub(range.start)
        );
    }

    #[cfg(target_arch = "x86_64")]
    let hook_offset = find_fun_140a1f740_offset().unwrap_or(FUN_140A1F740_OFFSET);

    #[cfg(target_arch = "x86_64")]
    debug_log!("FUN_140a1f740 hook offset selected: 0x{hook_offset:X}");

    #[cfg(target_arch = "x86_64")]
    debug_log!(
        "FUN_140a1f740 hook absolute addr: 0x{:X}",
        (udk as usize).saturating_add(hook_offset)
    );

    unsafe {
        Fun140a1f740Hook
            .initialize(
                std::mem::transmute(udk.add(hook_offset)),
                fun_140a1f740_hook,
            )
            .context("Failed to setup FUN_140a1f740 hook")?;

        Fun140a1f740Hook.enable()?;
    }

    debug_log!("udk_null_lookup::init done");

    Ok(())
}
