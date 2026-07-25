//! Raises (well - for now, *lowers*, see [`NEW_MAX_ACTIVE_EFFECTS`]) the compiled-in
//! `UDKEmitterPool` default for `MaxActiveEffects`
//! (`EmitterPool.uc` / `UDKEmitterPool.uc` `defaultproperties`), which caps how many
//! pooled particle-effect components (`AEmitterPool::ActiveComponents`) can be active
//! at once before the oldest one gets recycled (see `AEmitterPool::GetPooledComponent`,
//! `Engine/Src/UnScript.cpp`).
//!
//! Unlike `MAX_AUDIOCHANNELS` (a real compile-time constant baked into native code),
//! `MaxActiveEffects` is an UnrealScript `defaultproperties` value - it isn't baked
//! into `udk.exe` at all, it lives in the compiled `.u` script package's serialized
//! class-default-object (CDO) data, loaded into memory at runtime. So instead of
//! patching an instruction, this patches the live CDO's field directly, once the
//! engine has loaded far enough for it to exist.
//!
//! Reverse-engineered (via Ghidra, live MCP session) call/data chain:
//!
//!  1. `UDKBase`'s package-init routine (`FUN_1417d3ba0`) does the equivalent of:
//!     ```c
//!     if (DAT_1436d3828 == NULL) {
//!         DAT_1436d3828 = UDKEmitterPool::StaticClass(); // FUN_1417b50d0(L"UDKBase")
//!         FUN_141792a70(); // finalizes/links the class
//!     }
//!     ```
//!     `DAT_1436d3828` (udk.exe+0x36D3828) is a persistent global caching the
//!     `UClass*` for `UDKEmitterPool`, set once and never touched again.
//!
//!  2. `UClass::ClassDefaultObject` (declared in `Core/Inc/UnClass.h`) sits at
//!     offset `+0x1E4` within the `UClass` object. An initial hand-count from
//!     `UnClass.h`'s declared member order suggested `+0x1D4` (assuming
//!     `WITH_LIBFFI` wasn't compiled in), but live testing showed that offset
//!     always read `0` even well after a match had loaded. Ghidra's own
//!     `UClass::GetDefaultObject` decompile (real check-and-cache logic against
//!     the CDO field) confirmed the real field sits 16 bytes later - exactly
//!     the size of the `WITH_LIBFFI`-only `FName DLLBindName` + `void*
//!     DLLBindHandle` block, which turns out *is* compiled into this build.
//!
//!  3. `AEmitterPool::MaxActiveEffects` sits at offset `+0x264` within a
//!     `UDKEmitterPool` instance (i.e. the CDO) - confirmed by decompiling
//!     `AEmitterPool::GetPooledComponent` (found via its `RecycleEmittersBasedOnTemplate`
//!     console-variable string) and matching its field reads 1:1 against the
//!     declared member order in `Engine/Inc/EngineClasses.h`'s `AEmitterPool`:
//!     `PSCTemplate@0x23c -> PoolComponents@0x244 -> ActiveComponents@0x254 ->
//!     MaxActiveEffects@0x264 -> bLogPoolOverflow/bLogPoolOverflowList bits@0x268`.
//!
//! Because `DAT_1436d3828` and the CDO it eventually points to are only populated
//! once script packages have loaded (well after `DllMain`/`post_udk_init` runs),
//! this doesn't patch synchronously - it spawns a small background thread that
//! polls until both pointers are valid (or gives up after a timeout), then writes
//! the new value once.
use anyhow::Context;
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::time::Duration;

use crate::dll::UDK_RANGE;

/// New value for `AEmitterPool::MaxActiveEffects`.
///
/// Set deliberately *low* right now (instead of raising it) so it's easy to
/// verify in-game that this patch is actually taking effect: pooled effects
/// should start recycling/overflowing (and, if `bLogPoolOverflow` is on,
/// logging "Exceeded max active pooled emitters!") far sooner than the
/// default of 200. Once confirmed working, bump this up instead.
const NEW_MAX_ACTIVE_EFFECTS: i32 = 1;

/// Offset (from `udk.exe` module base) of the persistent global caching the
/// `UClass*` for `UDKEmitterPool`, set once during `UDKBase` package init.
const UDKEMITTERPOOL_CLASS_PTR_OFFSET: usize = 0x036D_3828;

/// Offset of `UClass::ClassDefaultObject` within a `UClass` instance.
///
/// Corrected from an initial hand-count of `0x1D4` (which assumed `WITH_LIBFFI`
/// wasn't compiled in): live testing showed the CDO pointer at `0x1D4` always
/// read `0` even after a match had fully loaded, while the cached `UClass*`
/// itself was confirmed valid. Cross-checking against `UClass::GetDefaultObject`'s
/// actual decompiled check-and-cache logic (`if (this->field == NULL) { ...
/// construct ...; this->field = result; } return this->field;`) showed the real
/// field sits 16 bytes later than a generic (non-`WITH_LIBFFI`) `UClass` layout
/// would predict - exactly the size of the `FName DLLBindName` + `void*
/// DLLBindHandle` block that `WITH_LIBFFI` inserts before `ClassDefaultObject`.
const CLASS_DEFAULT_OBJECT_OFFSET: usize = 0x1E4;

/// Offset of `AEmitterPool::MaxActiveEffects` within a `UDKEmitterPool` instance.
const MAX_ACTIVE_EFFECTS_OFFSET: usize = 0x264;

/// How long to keep polling for the class/CDO pointers to become valid before
/// giving up. Generous, since this may not resolve until well after a map
/// has actually loaded, not just at menu/process start.
const POLL_TIMEOUT: Duration = Duration::from_secs(300);

/// Delay between polling attempts.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How often (in poll attempts) to log a progress update, so a stuck poll
/// shows exactly which pointer (class vs CDO) never became valid instead of
/// only reporting pass/fail once at the very end.
const LOG_EVERY_N_ATTEMPTS: u32 = 25; // ~5s at 200ms/attempt

/// Appends a line to `renxhook.log` next to the game executable.
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

/// Attempts a single read of `UDKEmitterPool`'s `UClass*` and its `ClassDefaultObject`.
/// Returns `(class_ptr, cdo_ptr)` - either may be `0` if not populated yet.
fn try_get_cdo(class_ptr_addr: usize) -> (usize, usize) {
    let class_ptr = unsafe { *(class_ptr_addr as *const usize) };
    if class_ptr == 0 {
        return (0, 0);
    }

    let cdo_addr = class_ptr.saturating_add(CLASS_DEFAULT_OBJECT_OFFSET);
    let cdo_ptr = unsafe { *(cdo_addr as *const usize) };

    (class_ptr, cdo_ptr)
}

/// Polls (on a background thread) until `UDKEmitterPool`'s CDO exists, then
/// overwrites `MaxActiveEffects` in place.
fn patch_thread(class_ptr_addr: usize) {
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    let mut attempt: u32 = 0;
    let mut last_class_ptr = 0usize;

    let cdo_ptr = loop {
        attempt += 1;
        let (class_ptr, cdo_ptr) = try_get_cdo(class_ptr_addr);

        if class_ptr != 0 && cdo_ptr != 0 {
            break cdo_ptr;
        }

        // Log whenever the class pointer first appears, and periodically
        // afterward, so a stuck poll shows exactly what's still missing.
        if (class_ptr != 0 && last_class_ptr == 0) || attempt % LOG_EVERY_N_ATTEMPTS == 0 {
            debug_log(&format!(
                "udk_emitter_pool: poll attempt {attempt}: class_ptr=0x{class_ptr:X} cdo_ptr=0x{cdo_ptr:X}"
            ));
        }
        last_class_ptr = class_ptr;

        if std::time::Instant::now() >= deadline {
            debug_log(&format!(
                "udk_emitter_pool: timed out after {POLL_TIMEOUT:?} waiting for UDKEmitterPool CDO (class ptr addr 0x{class_ptr_addr:X}, last seen class_ptr=0x{last_class_ptr:X})"
            ));
            return;
        }

        thread::sleep(POLL_INTERVAL);
    };

    debug_log(&format!(
        "udk_emitter_pool: UDKEmitterPool CDO = 0x{cdo_ptr:X}"
    ));

    let max_active_effects_addr = cdo_ptr.saturating_add(MAX_ACTIVE_EFFECTS_OFFSET);

    let old_value = unsafe { *(max_active_effects_addr as *const i32) };
    debug_log(&format!(
        "udk_emitter_pool: MaxActiveEffects at 0x{max_active_effects_addr:X} current value = {old_value} (expected 200 pre-patch)"
    ));

    let result = (|| -> anyhow::Result<()> {
        unsafe {
            let addr = max_active_effects_addr as *mut u8;
            let _guard = region::protect_with_handle(
                addr,
                std::mem::size_of::<i32>(),
                region::Protection::READ_WRITE_EXECUTE,
            )
            .context("Failed to make MaxActiveEffects writable")?;

            std::ptr::write(max_active_effects_addr as *mut i32, NEW_MAX_ACTIVE_EFFECTS);
        }
        Ok(())
    })();

    match result {
        Ok(()) => debug_log(&format!(
            "udk_emitter_pool: patched MaxActiveEffects at 0x{max_active_effects_addr:X} from {old_value} to {NEW_MAX_ACTIVE_EFFECTS}"
        )),
        Err(err) => debug_log(&format!(
            "udk_emitter_pool: failed to patch MaxActiveEffects: {err}"
        )),
    }
}

/// Spawns the background thread that waits for `UDKEmitterPool`'s CDO to exist
/// and then patches `MaxActiveEffects`.
pub fn init() -> anyhow::Result<()> {
    debug_log("udk_emitter_pool::init start");

    let range = UDK_RANGE.get().context("UDK_RANGE not set")?;
    let class_ptr_addr = range.start.saturating_add(UDKEMITTERPOOL_CLASS_PTR_OFFSET);

    debug_log(&format!(
        "udk_emitter_pool: UDKEmitterPool UClass* cache slot at 0x{class_ptr_addr:X}, spawning poll thread"
    ));

    thread::spawn(move || patch_thread(class_ptr_addr));

    debug_log("udk_emitter_pool::init done (patch happens asynchronously)");

    Ok(())
}
