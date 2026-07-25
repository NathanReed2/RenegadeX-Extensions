//! This module contains a hook for `FUN_1401491b0` at udk.exe+0x1491B0, a
//! generic `TBitArray`/`TSparseArray`-style const-set-bit-iterator
//! constructor. It crashes when handed a bad array reference: it
//! unconditionally dereferences `param_2 + 0x10` (`MOV RCX, [RDX+0x10]` at
//! udk.exe+0x1491F9) before checking anything. A NULL `param_2` would read
//! from address `0x10` and fault; observed in practice, `param_2` is
//! actually a non-NULL but dangling/invalid pointer (confirmed: a plain
//! `== 0` guard here still let the crash through to the original function),
//! so this hook validates the target memory is actually a readable mapped
//! region (via the `region` crate) rather than just checking for NULL.
//!
//! This was reached (indirectly) while loading a SubstanceAir texture with
//! no `ParentInstance` during `CookPackages`, but the function itself is
//! generic engine code used broadly, so the guard below is intentionally
//! generic too (not SubstanceAir-specific): if `param_2` isn't safely
//! readable, we skip the dereference and set up the iterator fields to look
//! like an already-exhausted/empty iterator (mirroring the original
//! function's own "ran out of bits" exit path, which sets `param_1[5]` to
//! the array's count and returns `param_1`), instead of calling into the
//! original crashing logic.
use crate::dll::{get_udk_ptr, UDK_RANGE};
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;
use retour::static_detour;

#[cfg(target_arch = "x86_64")]
const FUN_1401491B0_OFFSET: usize = 0x0014_91B0;

// Bytes captured starting 5 bytes into the function (at udk.exe+0x1491B5),
// ending right before the crashing dereference at udk.exe+0x1491F9. The
// signature scan below subtracts 5 from any match to land on the true
// function entry point.
#[cfg(target_arch = "x86_64")]
const FUN_1401491B0_SIG_SKEW: usize = 5;

#[cfg(target_arch = "x86_64")]
const FUN_1401491B0_SIG: [u8; 68] = [
    0x4C, 0x8B, 0xD9, 0x45, 0x8B, 0xD0, 0x41, 0x83, 0xC9, 0xFF, 0x45, 0x89, 0x43, 0x14, 0x41, 0xC1,
    0xFA, 0x05, 0x49, 0x89, 0x53, 0x08, 0x44, 0x89, 0x11, 0x41, 0x8B, 0xC8, 0x41, 0x83, 0xE0, 0xE0,
    0x45, 0x89, 0x43, 0x18, 0x45, 0x33, 0xC0, 0x83, 0xE1, 0x1F, 0x41, 0xD3, 0xE1, 0x44, 0x89, 0x44,
    0x24, 0x18, 0x48, 0x8B, 0xDA, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x45, 0x89, 0x4B, 0x10, 0xD3, 0xE0,
    0x41, 0x89, 0x43, 0x04,
];

static_detour! {
    static Fun1401491b0Hook: extern "C" fn(i64, i64, u32) -> i64;
}

/// Checks whether `len` bytes starting at `addr` fall within a single
/// currently-committed, readable memory region. Used to guard against
/// dereferencing dangling/invalid (but non-NULL) pointers, which a plain
/// NULL check would miss.
fn is_readable(addr: usize, len: usize) -> bool {
    if addr == 0 {
        return false;
    }

    match region::query(addr as *const u8) {
        Ok(region) => {
            region.protection().contains(region::Protection::READ)
                && addr.saturating_add(len) <= region.as_range().end
        }
        Err(_) => false,
    }
}

/// Appends a line to `renxhook.log` next to the game executable. Used to
/// confirm when the hook is installed and when it actually catches a bad
/// array reference (this only reproduces under specific cook/asset states,
/// e.g. a SubstanceAir texture missing its `ParentInstance`).
// A zeroed dummy "array" buffer. When the real array reference is bad, we
// point the iterator's stored array-reference field at this instead of at
// the bad pointer itself. Callers of the bit-array iterator constructor
// (confirmed via a debug-symbol decompile of the actual caller) go on to
// read an `ArrayNum`-like `int` at `array_ref + 0x18` directly, without
// going through the iterator again - storing the bad pointer back would just
// move the crash into that later read. Pointing at this zeroed buffer makes
// that read come back as `0`, which every observed caller treats as "empty".
static SAFE_EMPTY_ARRAY: [u8; 0x20] = [0u8; 0x20];

/// Scans the loaded `udk.exe` image for [`FUN_1401491B0_SIG`] and returns
/// the best matching function-entry offset (closest to the known
/// [`FUN_1401491B0_OFFSET`]), correcting for [`FUN_1401491B0_SIG_SKEW`]
/// since the signature itself starts a few bytes into the function.
#[cfg(target_arch = "x86_64")]
fn find_fun_1401491b0_offset() -> Option<usize> {
    let (best, count) = find_signature_offset(
        &FUN_1401491B0_SIG,
        FUN_1401491B0_OFFSET,
        FUN_1401491B0_SIG_SKEW,
    );
    debug_log!("FUN_1401491b0 signature matches: {count}");
    best
}

/// Hook for `FUN_1401491b0` at udk.exe+0x1491B0.
///
/// Ghidra decompilation of the original function:
///
///   int * FUN_1401491b0(int *param_1, ulonglong param_2, uint param_3)
///   {
///       ...
///       param_1[5] = param_3;
///       *(ulonglong *)(param_1 + 2) = param_2;
///       *param_1 = (int)param_3 >> 5;
///       param_1[6] = param_3 & 0xffffffe0;
///       ...
///       uVar3 = (... ) & param_2 | *(ulonglong *)(param_2 + 0x10);   // <-- crash: deref param_2+0x10
///       ...
///   }
///
/// `param_1` is the iterator being constructed (`this`), `param_2` is a
/// reference to the array/container being iterated, and `param_3` is the
/// starting bit index. The very first thing this function does with
/// `param_2` is dereference `param_2 + 0x10` unconditionally, with no NULL
/// check. When `param_2 == 0` this reads from address `0x10` and crashes.
///
/// This hook checks that `param_2 + 0x10` is safely readable before calling
/// through. If it isn't (NULL or a dangling/invalid pointer), it replicates
/// just the unconditional, safe field writes from the original function
/// (which don't touch `param_2`) and then sets the iterator up to look
/// immediately exhausted/empty (mirroring the original function's own "ran
/// out of bits" exit path: `param_1[5] = ArrayNum; return param_1;`, just
/// using `0` instead of reading `ArrayNum` from the bad array). This avoids
/// the crash while leaving the iterator in a valid "no bits" state for any
/// well-behaved caller. Calls with a genuinely valid `param_2` are
/// unaffected and go through to the original function untouched.
///
/// Crucially, the array-reference field (offset `0x08`) is set to point at
/// `SAFE_EMPTY_ARRAY`, not at the original bad `array_ref`: a confirmed
/// caller reads `*(int*)(array_reference_field + 0x18)` afterwards (an
/// `ArrayNum`-like count) without going back through this function, so
/// storing the bad pointer verbatim just relocates the crash a few
/// instructions later in the caller.
fn fun_1401491b0_hook(this: i64, array_ref: i64, start_index: u32) -> i64 {
    if !is_readable(array_ref as usize, 0x10 + 8) {
        debug_log!(
            "FUN_1401491b0 hook fired: array reference 0x{array_ref:X} is NULL/unreadable, returning empty iterator instead of crashing"
        );

        if this != 0 {
            unsafe {
                let base = this as *mut u8;
                let safe_ref = SAFE_EMPTY_ARRAY.as_ptr() as i64;
                *(base.offset(0x00) as *mut i32) = (start_index >> 5) as i32;
                *(base.offset(0x04) as *mut i32) = 0;
                *(base.offset(0x08) as *mut i64) = safe_ref;
                *(base.offset(0x10) as *mut i32) = 0;
                *(base.offset(0x14) as *mut i32) = 0;
                *(base.offset(0x18) as *mut i32) = (start_index & 0xffffffe0) as i32;
            }
        }

        return this;
    }

    Fun1401491b0Hook.call(this, array_ref, start_index)
}

/// Locates `FUN_1401491b0` (via signature scan, falling back to the known
/// static offset) and installs [`Fun1401491b0Hook`] over it so bad/dangling
/// array references can no longer crash the game during operations like
/// `CookPackages`.
pub fn init() -> anyhow::Result<()> {
    let udk = get_udk_ptr();
    debug_log!("udk_substance::init start");

    if let Some(range) = UDK_RANGE.get() {
        debug_log!(
            "UDK range: start=0x{:X} end=0x{:X} size=0x{:X}",
            range.start,
            range.end,
            range.end.saturating_sub(range.start)
        );
    }

    #[cfg(target_arch = "x86_64")]
    let hook_offset = find_fun_1401491b0_offset().unwrap_or(FUN_1401491B0_OFFSET);

    #[cfg(target_arch = "x86_64")]
    debug_log!("FUN_1401491b0 hook offset selected: 0x{hook_offset:X}");

    #[cfg(target_arch = "x86_64")]
    debug_log!(
        "FUN_1401491b0 hook absolute addr: 0x{:X}",
        (udk as usize).saturating_add(hook_offset)
    );

    unsafe {
        Fun1401491b0Hook
            .initialize(
                std::mem::transmute(udk.add(hook_offset)),
                fun_1401491b0_hook,
            )
            .context("Failed to setup FUN_1401491b0 hook")?;

        Fun1401491b0Hook.enable()?;
    }

    debug_log!("udk_substance::init done");

    Ok(())
}
