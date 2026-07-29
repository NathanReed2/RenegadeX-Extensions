//! Corrects two `D3DPRESENT_PARAMETERS` fields that UE3 hard-codes for every
//! D3D9 device it creates or resets.
//!
//! `FD3D9DynamicRHI::UpdateD3DDeviceFromViewports` (RenXSDK RVA `0x16BBE60`,
//! `D3D9Device.cpp`) fills one stack-local `D3DPRESENT_PARAMETERS` and hands the
//! same struct to both `IDirect3D9::CreateDevice` and `IDirect3DDevice9::Reset`:
//!
//! ```text
//! PresentParameters.BackBufferCount = 1;                                  // RVA 0x16BC0B8
//! PresentParameters.SwapEffect      = bIsFullscreen ? DISCARD : COPY;     // RVA 0x16BC0D0
//! PresentParameters.Flags           = D3DPRESENTFLAG_LOCKABLE_BACKBUFFER; // RVA 0x16BC0E2
//! ```
//!
//! Two of those are worth changing:
//!
//! * **`D3DPRESENTFLAG_LOCKABLE_BACKBUFFER` is set unconditionally.** A lockable
//!   back buffer has to be allocated linear and uncompressed, which costs fill
//!   rate on hardware that would otherwise tile it, and it is not needed here:
//!   `FD3D9DynamicRHI::ReadSurfaceData` copies the render target with
//!   `IDirect3DDevice9::GetRenderTargetData` into a fresh `D3DPOOL_SYSTEMMEM`
//!   texture and locks *that*, so nothing in the driver ever locks the back
//!   buffer itself.
//!
//! * **`BackBufferCount` is 1.** In exclusive fullscreen the swap effect is
//!   `D3DSWAPEFFECT_DISCARD`, so one back buffer means plain double buffering:
//!   with vsync enabled, a single missed frame drops presentation to half the
//!   refresh rate and keeps it there. A second back buffer restores the usual
//!   triple-buffered behaviour.
//!
//! The extra buffer is added *only* to a `D3DSWAPEFFECT_DISCARD` chain.
//! `D3DSWAPEFFECT_COPY` - which is what UE3 selects for every windowed viewport,
//! and therefore what [`crate::udk_borderless_fullscreen`] runs through once it
//! clears `bIsFullscreen` - is defined only for a single back buffer, and asking
//! for more is an outright invalid call.
//!
//! # Why this hooks Direct3D instead of patching UDK.exe
//!
//! Both fields are stack locals, so changing them in place would mean rewriting
//! instructions in the middle of the parameter block. That block is booby
//! trapped: the `SETZ AL` at RVA `0x16BC0EB` that produces `Windowed` reads the
//! zero flag set by the `TEST ECX,ECX` at `0x16BC0D9`, fifteen bytes earlier, so
//! any inserted instruction that touches flags silently inverts windowed mode.
//! Detouring `CreateDevice`/`Reset` and rewriting the struct in flight avoids
//! that entirely, needs no instruction validation, and covers device creation
//! and every later resolution change through the one pair of hooks.
//!
//! # Switches
//!
//! * `-NoD3D9PresentTweaks` - install nothing.
//! * `-NoD3D9TripleBuffer` - leave `BackBufferCount` alone.
//! * `-NoD3D9LockableFix` - leave `Flags` alone.
//!
//! If either `-D3D9EX` or `-D3D9FLIPEX` is present this module stands down:
//! [`crate::udk_d3d9_flipex`] owns the same `Direct3DCreate9` export and already
//! applies both corrections on its FlipEx path.

#![cfg(target_arch = "x86_64")]

use crate::patch_utils::debug_log;
use crate::udk_log::{log, LogType};
use anyhow::Context;
use retour::static_detour;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use windows::core::s;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type Ptr = *mut c_void;
type Hr = i32;

/// `D3D_SDK_VERSION`, the only value UE3 passes to `Direct3DCreate9`.
const SDK_VERSION: u32 = 32;
/// `IDirect3D9::CreateDevice`.
const CREATE_DEVICE_SLOT: usize = 16;
/// `IDirect3DDevice9::Reset`.
const RESET_SLOT: usize = 16;

const D3DSWAPEFFECT_DISCARD: u32 = 1;
const D3DPRESENTFLAG_LOCKABLE_BACKBUFFER: u32 = 0x0000_0001;
/// One extra back buffer. `D3DSWAPEFFECT_DISCARD` accepts up to three.
const TRIPLE_BUFFERED: u32 = 2;

const D3DERR_OUTOFVIDEOMEMORY: Hr = 0x8876_017Cu32 as i32;
const D3DERR_INVALIDCALL: Hr = 0x8876_086Cu32 as i32;

#[repr(C)]
#[derive(Clone, Copy)]
struct PresentParams {
    width: u32,
    height: u32,
    format: u32,
    count: u32,
    ms_type: u32,
    ms_quality: u32,
    effect: u32,
    window: Ptr,
    windowed: i32,
    auto_depth: i32,
    depth_format: u32,
    flags: u32,
    refresh: u32,
    interval: u32,
}

const _: [(); 64] = [(); std::mem::size_of::<PresentParams>()];

type Create9 = unsafe extern "system" fn(u32) -> Ptr;
type CreateDevice =
    unsafe extern "system" fn(Ptr, u32, u32, Ptr, u32, *mut PresentParams, *mut Ptr) -> Hr;
type Reset = unsafe extern "system" fn(Ptr, *mut PresentParams) -> Hr;

static_detour! {
    static Create9Hook: unsafe extern "system" fn(u32) -> Ptr;
    static CreateDeviceHook: unsafe extern "system" fn(Ptr, u32, u32, Ptr, u32, *mut PresentParams, *mut Ptr) -> Hr;
    static ResetHook: unsafe extern "system" fn(Ptr, *mut PresentParams) -> Hr;
}

#[derive(Clone, Copy)]
struct Config {
    triple_buffer: bool,
    clear_lockable: bool,
}

static CONFIG: OnceLock<Config> = OnceLock::new();
static FACTORY_HOOKED: AtomicBool = AtomicBool::new(false);
static DEVICE_HOOKED: AtomicBool = AtomicBool::new(false);
/// Latched once a tweak has been rolled back, so we stop fighting a driver that
/// has already refused the parameters.
static DISABLED: AtomicBool = AtomicBool::new(false);
static REPORTED: AtomicBool = AtomicBool::new(false);
static INSTALL: Mutex<()> = Mutex::new(());

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn disabled() -> bool {
    DISABLED.load(Ordering::Acquire)
}

unsafe fn vtable_entry(object: Ptr, slot: usize) -> Ptr {
    *(*(object as *const *const Ptr)).add(slot)
}

/// Reads the launch switches. Returns `None` when the module is switched off, or
/// when [`crate::udk_d3d9_flipex`] would be driving the same export.
fn parse_config() -> Option<Config> {
    let arguments: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().to_ascii_uppercase())
        .collect();
    let has = |name: &str| {
        arguments
            .iter()
            .any(|argument| argument.trim_start_matches(['-', '/']) == name)
    };

    if has("NOD3D9PRESENTTWEAKS") || has("D3D9EX") || has("D3D9FLIPEX") {
        return None;
    }

    let config = Config {
        triple_buffer: !has("NOD3D9TRIPLEBUFFER"),
        clear_lockable: !has("NOD3D9LOCKABLEFIX"),
    };
    (config.triple_buffer || config.clear_lockable).then_some(config)
}

/// Applies both corrections in place. Idempotent, because UE3 reuses the same
/// struct across the `Reset` retry loop in `UpdateD3DDeviceFromViewports`.
fn adjust(params: &mut PresentParams) -> bool {
    let Some(config) = CONFIG.get().copied() else {
        return false;
    };
    let mut changed = false;

    if config.clear_lockable && params.flags & D3DPRESENTFLAG_LOCKABLE_BACKBUFFER != 0 {
        params.flags &= !D3DPRESENTFLAG_LOCKABLE_BACKBUFFER;
        changed = true;
    }

    if config.triple_buffer
        && params.effect == D3DSWAPEFFECT_DISCARD
        && params.count < TRIPLE_BUFFERED
    {
        params.count = TRIPLE_BUFFERED;
        changed = true;
    }

    changed
}

fn report(before: &PresentParams, after: &PresentParams, when: &str) {
    let message = format!(
        "D3D9 present parameters adjusted at {when}: {}x{}, swap effect {}, windowed={}, back buffers {} -> {}, flags {:#x} -> {:#x}",
        after.width,
        after.height,
        after.effect,
        after.windowed,
        before.count,
        after.count,
        before.flags,
        after.flags
    );

    if REPORTED.swap(true, Ordering::AcqRel) {
        debug_log!("{message}");
    } else {
        log(LogType::Init, &message);
    }
}

/// Restores `params` and stands the module down for the rest of the process.
unsafe fn roll_back(params: *mut PresentParams, original: &PresentParams, hr: Hr, when: &str) {
    *params = *original;
    DISABLED.store(true, Ordering::Release);
    log(
        LogType::Warning,
        &format!(
            "D3D9 present parameters rejected at {when} ({hr:#010x}); retrying with stock values and leaving them alone from here on"
        ),
    );
}

unsafe fn hook_factory(factory: Ptr) -> anyhow::Result<()> {
    if FACTORY_HOOKED.load(Ordering::Acquire) {
        return Ok(());
    }
    let _guard = lock(&INSTALL);
    if FACTORY_HOOKED.load(Ordering::Relaxed) {
        return Ok(());
    }

    let target: CreateDevice = std::mem::transmute(vtable_entry(factory, CREATE_DEVICE_SLOT));
    CreateDeviceHook
        .initialize(
            target,
            |factory, adapter, device_type, focus, behavior, params, out| unsafe {
                create_device(factory, adapter, device_type, focus, behavior, params, out)
            },
        )
        .context("initializing IDirect3D9::CreateDevice hook")?;
    CreateDeviceHook
        .enable()
        .context("enabling IDirect3D9::CreateDevice hook")?;
    FACTORY_HOOKED.store(true, Ordering::Release);
    Ok(())
}

unsafe fn hook_device(device: Ptr) -> anyhow::Result<()> {
    if DEVICE_HOOKED.load(Ordering::Acquire) {
        return Ok(());
    }
    let _guard = lock(&INSTALL);
    if DEVICE_HOOKED.load(Ordering::Relaxed) {
        return Ok(());
    }

    let target: Reset = std::mem::transmute(vtable_entry(device, RESET_SLOT));
    ResetHook
        .initialize(target, |device, params| unsafe { reset(device, params) })
        .context("initializing IDirect3DDevice9::Reset hook")?;
    ResetHook
        .enable()
        .context("enabling IDirect3DDevice9::Reset hook")?;
    DEVICE_HOOKED.store(true, Ordering::Release);
    Ok(())
}

unsafe fn create9(sdk: u32) -> Ptr {
    let factory = Create9Hook.call(sdk);
    if sdk != SDK_VERSION || factory.is_null() {
        return factory;
    }
    if let Err(error) = hook_factory(factory) {
        // The factory itself is fine; only the tweaks are lost.
        DISABLED.store(true, Ordering::Release);
        debug_log!("D3D9 CreateDevice hook failed: {error:#}; present parameters left stock");
    }
    factory
}

unsafe fn create_device(
    factory: Ptr,
    adapter: u32,
    device_type: u32,
    focus: Ptr,
    behavior: u32,
    params: *mut PresentParams,
    out: *mut Ptr,
) -> Hr {
    let call = |params: *mut PresentParams| {
        CreateDeviceHook.call(factory, adapter, device_type, focus, behavior, params, out)
    };

    if params.is_null() || disabled() {
        return call(params);
    }

    let original = *params;
    let changed = adjust(&mut *params);
    let hr = call(params);

    if hr >= 0 {
        if changed {
            report(&original, &*params, "device creation");
        }
        // Hook Reset off the live device: every IDirect3DDevice9 from this
        // runtime shares one vtable, so this installs once for the process.
        if !out.is_null() && !(*out).is_null() {
            if let Err(error) = hook_device(*out) {
                debug_log!("D3D9 Reset hook failed: {error:#}; resolution changes stay stock");
            }
        }
        return hr;
    }

    if !changed {
        return hr;
    }

    // Never let a tweak be the reason the game cannot start.
    roll_back(params, &original, hr, "device creation");
    call(params)
}

unsafe fn reset(device: Ptr, params: *mut PresentParams) -> Hr {
    if params.is_null() || disabled() {
        return ResetHook.call(device, params);
    }

    let original = *params;
    let changed = adjust(&mut *params);
    let hr = ResetHook.call(device, params);

    if hr >= 0 {
        if changed {
            report(&original, &*params, "device reset");
        }
        return hr;
    }

    // A lost device is the ordinary reason a reset fails, and UE3 loops on it
    // in UpdateD3DDeviceFromViewports; only back out when the parameters
    // themselves were refused.
    if !changed || !matches!(hr, D3DERR_INVALIDCALL | D3DERR_OUTOFVIDEOMEMORY) {
        return hr;
    }

    roll_back(params, &original, hr, "device reset");
    ResetHook.call(device, params)
}

fn try_init() -> anyhow::Result<()> {
    let Some(config) = parse_config() else {
        return Ok(());
    };
    CONFIG
        .set(config)
        .map_err(|_| anyhow::anyhow!("D3D9 present configuration already initialized"))?;

    // UDK.exe imports Direct3DCreate9 statically, so d3d9.dll is already mapped
    // by the time our DllMain runs. Resolving the module rather than loading it
    // keeps this off the loader lock.
    let module = unsafe { GetModuleHandleA(s!("d3d9.dll")) }.context("d3d9.dll is not loaded")?;
    let entry = unsafe { GetProcAddress(module, s!("Direct3DCreate9")) }
        .context("d3d9.dll does not export Direct3DCreate9")?;
    let target: Create9 = unsafe { std::mem::transmute(entry) };

    unsafe {
        Create9Hook
            .initialize(target, |sdk| create9(sdk))
            .context("initializing Direct3DCreate9 hook")?;
        Create9Hook
            .enable()
            .context("enabling Direct3DCreate9 hook")?;
    }

    debug_log!(
        "D3D9 present parameter hooks installed (triple buffer={}, lockable fix={})",
        config.triple_buffer,
        config.clear_lockable
    );
    Ok(())
}

pub fn init() -> anyhow::Result<()> {
    // DllMain runs before UE3's GLog object exists, so setup problems go to the
    // dev log only - a call into FOutputDevice this early faults inside UDK.exe
    // and Windows reports 0xc0000142. The runtime hooks log normally, because
    // the RHI is not constructed until well after engine init.
    if let Err(error) = try_init() {
        debug_log!("udk_d3d9_present_params::init failed: {error:#}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        adjust, Config, PresentParams, CONFIG, D3DPRESENTFLAG_LOCKABLE_BACKBUFFER,
        D3DSWAPEFFECT_DISCARD,
    };

    /// `D3DSWAPEFFECT_COPY`, which UE3 uses for every windowed viewport.
    const COPY: u32 = 3;

    fn params(effect: u32, count: u32, flags: u32) -> PresentParams {
        PresentParams {
            width: 1920,
            height: 1080,
            format: 0x15,
            count,
            ms_type: 0,
            ms_quality: 0,
            effect,
            window: std::ptr::null_mut(),
            windowed: i32::from(effect == COPY),
            auto_depth: 0,
            depth_format: 0,
            flags,
            refresh: 0,
            interval: 0x8000_0000u32 as i32 as u32,
        }
    }

    fn configure() {
        let _ = CONFIG.set(Config {
            triple_buffer: true,
            clear_lockable: true,
        });
    }

    #[test]
    fn adds_a_back_buffer_only_to_a_discard_chain() {
        configure();

        // Exclusive fullscreen: UE3 asks for DISCARD with one back buffer.
        let mut fullscreen = params(D3DSWAPEFFECT_DISCARD, 1, 0);
        assert!(adjust(&mut fullscreen));
        assert_eq!(fullscreen.count, 2);

        // Windowed and borderless both run through COPY, which is defined only
        // for a single back buffer.
        let mut windowed = params(COPY, 1, 0);
        assert!(!adjust(&mut windowed));
        assert_eq!(windowed.count, 1);
    }

    #[test]
    fn clears_the_lockable_back_buffer_flag_in_either_mode() {
        configure();

        let mut windowed = params(COPY, 1, D3DPRESENTFLAG_LOCKABLE_BACKBUFFER);
        assert!(adjust(&mut windowed));
        assert_eq!(windowed.flags, 0);

        let mut fullscreen = params(
            D3DSWAPEFFECT_DISCARD,
            1,
            D3DPRESENTFLAG_LOCKABLE_BACKBUFFER,
        );
        assert!(adjust(&mut fullscreen));
        assert_eq!(fullscreen.flags, 0);
        assert_eq!(fullscreen.count, 2);
    }

    #[test]
    fn is_idempotent_across_the_reset_retry_loop() {
        configure();

        // UpdateD3DDeviceFromViewports reuses one struct while it spins on a
        // lost device, so a second pass has to be a no-op.
        let mut reused = params(
            D3DSWAPEFFECT_DISCARD,
            1,
            D3DPRESENTFLAG_LOCKABLE_BACKBUFFER,
        );
        assert!(adjust(&mut reused));
        let after_first = (reused.count, reused.flags);
        assert!(!adjust(&mut reused));
        assert_eq!((reused.count, reused.flags), after_first);
    }

    #[test]
    fn leaves_a_deeper_chain_alone() {
        configure();

        let mut deep = params(D3DSWAPEFFECT_DISCARD, 3, 0);
        assert!(!adjust(&mut deep));
        assert_eq!(deep.count, 3);
    }
}
