//! DXGI flip-model support for the 64-bit Renegade X UDK binary.
//!
//! The stock D3D11 RHI creates a one-buffer `DXGI_SWAP_EFFECT_DISCARD`
//! swap chain.  This module intercepts that creation and requests a two-buffer
//! flip swap chain, falling back to the stock descriptor if the runtime rejects
//! both flip effects.  It also repairs UE3's resize/fullscreen ordering: DXGI
//! requires `ResizeBuffers` after `SetFullscreenState` for flip-model chains.

#![cfg(target_arch = "x86_64")]

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Context};
use lazy_static::lazy_static;
use retour::{static_detour, RawDetour};
use windows::core::GUID;

use crate::dll::get_udk_ptr;
use crate::udk_log::{log, LogType};

const VIEWPORT_CTOR_RVA: usize = 0x016A_E720;
const VIEWPORT_DTOR_RVA: usize = 0x016A_0940;
const GET_SWAP_CHAIN_SURFACE_RVA: usize = 0x016A_0810;

const VIEWPORT_RHI_OFFSET: usize = 0x0C;
const VIEWPORT_SWAP_CHAIN_OFFSET: usize = 0x2C;
const VIEWPORT_BACK_BUFFER_OFFSET: usize = 0x34;
const RHI_DXGI_FACTORY_OFFSET: usize = 0x88;

const IDXGI_FACTORY_CREATE_SWAP_CHAIN_INDEX: usize = 10;
const IDXGI_FACTORY5_CHECK_FEATURE_SUPPORT_INDEX: usize = 28;
const IDXGI_SWAP_CHAIN_PRESENT_INDEX: usize = 8;
const IDXGI_SWAP_CHAIN_SET_FULLSCREEN_STATE_INDEX: usize = 10;
const IDXGI_SWAP_CHAIN_GET_DESC_INDEX: usize = 12;
const IDXGI_SWAP_CHAIN_RESIZE_BUFFERS_INDEX: usize = 13;

const DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL: i32 = 3;
const DXGI_SWAP_EFFECT_FLIP_DISCARD: i32 = 4;
const DXGI_FEATURE_PRESENT_ALLOW_TEARING: i32 = 0;
const DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING: u32 = 0x0800;
const DXGI_PRESENT_ALLOW_TEARING: u32 = 0x0200;

const IID_IDXGI_FACTORY5: GUID = GUID::from_u128(0x7632e1f5_ee65_4dca_87fd_84cd75f8838d);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DxgiRational {
    numerator: u32,
    denominator: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DxgiModeDesc {
    width: u32,
    height: u32,
    refresh_rate: DxgiRational,
    format: i32,
    scanline_ordering: i32,
    scaling: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DxgiSampleDesc {
    count: u32,
    quality: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DxgiSwapChainDesc {
    buffer_desc: DxgiModeDesc,
    sample_desc: DxgiSampleDesc,
    buffer_usage: u32,
    buffer_count: u32,
    output_window: *mut c_void,
    windowed: i32,
    swap_effect: i32,
    flags: u32,
}

type OpaquePtr = *mut c_void;
type SwapChainDescPtr = *mut DxgiSwapChainDesc;
type SwapChainDescOut = *mut *mut c_void;

type ViewportCtor =
    extern "C" fn(*mut c_void, *mut c_void, *mut c_void, u32, u32, u32) -> *mut c_void;
type CreateSwapChain =
    extern "system" fn(*mut c_void, *mut c_void, *mut DxgiSwapChainDesc, *mut *mut c_void) -> i32;
type QueryInterface = extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> i32;
type CheckFeatureSupport = extern "system" fn(*mut c_void, i32, *mut c_void, u32) -> i32;
type Present = extern "system" fn(*mut c_void, u32, u32) -> i32;
type SetFullscreenState = extern "system" fn(*mut c_void, i32, *mut c_void) -> i32;
type GetDesc = extern "system" fn(*mut c_void, *mut DxgiSwapChainDesc) -> i32;
type ResizeBuffers = extern "system" fn(*mut c_void, u32, u32, u32, i32, u32) -> i32;
type Release = extern "system" fn(*mut c_void) -> u32;
type GetSwapChainSurface = extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
type DeleteRefCountedObject = extern "C" fn(*mut c_void, u32);

static_detour! {
    static ViewportDtorHook: extern "C" fn(OpaquePtr, usize, usize, usize);
}

static_detour! {
    static CreateSwapChainHook: extern "system" fn(OpaquePtr, OpaquePtr, SwapChainDescPtr, SwapChainDescOut) -> i32;
}

static_detour! {
    static PresentHook: extern "system" fn(OpaquePtr, u32, u32) -> i32;
}

static_detour! {
    static SetFullscreenStateHook: extern "system" fn(OpaquePtr, i32, OpaquePtr) -> i32;
}

static_detour! {
    static ResizeBuffersHook: extern "system" fn(OpaquePtr, u32, u32, u32, i32, u32) -> i32;
}

static VIEWPORT_CTOR_HOOK: OnceLock<RawDetour> = OnceLock::new();

#[derive(Clone, Copy)]
struct FlipSwapChainState {
    viewport: Option<usize>,
    windowed: bool,
    allow_tearing: bool,
}

thread_local! {
    // CreateSwapChain is synchronous inside FD3D11Viewport's constructor.
    // Consume this marker once so unrelated factory clients remain untouched.
    static EXPECTED_VIEWPORT_SWAP_CHAIN: Cell<bool> = const { Cell::new(false) };
}

struct ExpectedViewportSwapChainGuard;

impl ExpectedViewportSwapChainGuard {
    fn new() -> Self {
        EXPECTED_VIEWPORT_SWAP_CHAIN.with(|expected| expected.set(true));
        Self
    }
}

impl Drop for ExpectedViewportSwapChainGuard {
    fn drop(&mut self) {
        EXPECTED_VIEWPORT_SWAP_CHAIN.with(|expected| expected.set(false));
    }
}

lazy_static! {
    static ref FLIP_SWAP_CHAINS: Mutex<HashMap<usize, FlipSwapChainState>> =
        Mutex::new(HashMap::new());
    static ref FACTORY_HOOK_LOCK: Mutex<bool> = Mutex::new(false);
    static ref SWAP_CHAIN_HOOK_LOCK: Mutex<bool> = Mutex::new(false);
}

#[inline]
fn succeeded(hr: i32) -> bool {
    hr >= 0
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

unsafe fn read_ptr(base: *mut c_void, offset: usize) -> *mut c_void {
    *((base as *mut u8).add(offset) as *const *mut c_void)
}

unsafe fn write_ptr(base: *mut c_void, offset: usize, value: *mut c_void) {
    *((base as *mut u8).add(offset) as *mut *mut c_void) = value;
}

unsafe fn vtable_entry(object: *mut c_void, index: usize) -> *mut c_void {
    let vtable = *(object as *const *const *mut c_void);
    *vtable.add(index)
}

unsafe fn release_com(object: *mut c_void) {
    if !object.is_null() {
        let release: Release = std::mem::transmute(vtable_entry(object, 2));
        release(object);
    }
}

unsafe fn release_back_buffer(viewport: *mut c_void) -> bool {
    let back_buffer = read_ptr(viewport, VIEWPORT_BACK_BUFFER_OFFSET);
    if back_buffer.is_null() {
        return false;
    }

    write_ptr(viewport, VIEWPORT_BACK_BUFFER_OFFSET, std::ptr::null_mut());
    let references = (back_buffer as *mut u8).add(8) as *mut i32;
    *references -= 1;
    if *references == 0 {
        let delete: DeleteRefCountedObject = std::mem::transmute(vtable_entry(back_buffer, 0));
        delete(back_buffer, 1);
    }
    true
}

unsafe fn restore_back_buffer(viewport: *mut c_void, swap_chain: *mut c_void) {
    let rhi = read_ptr(viewport, VIEWPORT_RHI_OFFSET);
    let helper: GetSwapChainSurface =
        std::mem::transmute(get_udk_ptr().add(GET_SWAP_CHAIN_SURFACE_RVA));
    let back_buffer = helper(rhi, swap_chain);
    write_ptr(viewport, VIEWPORT_BACK_BUFFER_OFFSET, back_buffer);
    if !back_buffer.is_null() {
        let references = (back_buffer as *mut u8).add(8) as *mut i32;
        *references += 1;
    }
}

fn flip_swap_chain_state(swap_chain: *mut c_void) -> Option<FlipSwapChainState> {
    lock_or_recover(&FLIP_SWAP_CHAINS)
        .get(&(swap_chain as usize))
        .copied()
}

fn is_flip_swap_chain(swap_chain: *mut c_void) -> bool {
    flip_swap_chain_state(swap_chain).is_some()
}

unsafe fn factory_supports_tearing(factory: *mut c_void) -> bool {
    let query_interface: QueryInterface = std::mem::transmute(vtable_entry(factory, 0));
    let mut factory5 = std::ptr::null_mut();
    if !succeeded(query_interface(factory, &IID_IDXGI_FACTORY5, &mut factory5))
        || factory5.is_null()
    {
        return false;
    }

    let check_feature_support: CheckFeatureSupport = std::mem::transmute(vtable_entry(
        factory5,
        IDXGI_FACTORY5_CHECK_FEATURE_SUPPORT_INDEX,
    ));
    let mut supported = 0u32;
    let hr = check_feature_support(
        factory5,
        DXGI_FEATURE_PRESENT_ALLOW_TEARING,
        &mut supported as *mut u32 as *mut c_void,
        std::mem::size_of_val(&supported) as u32,
    );
    release_com(factory5);
    succeeded(hr) && supported != 0
}

unsafe fn install_swap_chain_hooks(swap_chain: *mut c_void) -> Result<(), String> {
    let mut installed = lock_or_recover(&SWAP_CHAIN_HOOK_LOCK);
    if *installed {
        return Ok(());
    }

    let present: Present =
        std::mem::transmute(vtable_entry(swap_chain, IDXGI_SWAP_CHAIN_PRESENT_INDEX));
    let set_fullscreen: SetFullscreenState = std::mem::transmute(vtable_entry(
        swap_chain,
        IDXGI_SWAP_CHAIN_SET_FULLSCREEN_STATE_INDEX,
    ));
    let resize_buffers: ResizeBuffers = std::mem::transmute(vtable_entry(
        swap_chain,
        IDXGI_SWAP_CHAIN_RESIZE_BUFFERS_INDEX,
    ));

    PresentHook
        .initialize(present, present_hook)
        .map_err(|error| format!("failed to initialize Present hook: {error}"))?;
    SetFullscreenStateHook
        .initialize(set_fullscreen, set_fullscreen_state_hook)
        .map_err(|error| format!("failed to initialize SetFullscreenState hook: {error}"))?;
    ResizeBuffersHook
        .initialize(resize_buffers, resize_buffers_hook)
        .map_err(|error| format!("failed to initialize ResizeBuffers hook: {error}"))?;

    PresentHook
        .enable()
        .map_err(|error| format!("failed to enable Present hook: {error}"))?;
    if let Err(error) = SetFullscreenStateHook.enable() {
        let _ = PresentHook.disable();
        return Err(format!("failed to enable SetFullscreenState hook: {error}"));
    }
    if let Err(error) = ResizeBuffersHook.enable() {
        let _ = SetFullscreenStateHook.disable();
        let _ = PresentHook.disable();
        return Err(format!("failed to enable ResizeBuffers hook: {error}"));
    }

    *installed = true;
    Ok(())
}

unsafe fn create_with_flip_effect(
    factory: *mut c_void,
    device: *mut c_void,
    original: &DxgiSwapChainDesc,
    output: *mut *mut c_void,
    effect: i32,
) -> i32 {
    let mut desc = *original;
    desc.buffer_count = 2;
    desc.swap_effect = effect;
    desc.flags |= DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING;
    *output = std::ptr::null_mut();
    CreateSwapChainHook.call(factory, device, &mut desc, output)
}

fn create_swap_chain_hook(
    factory: *mut c_void,
    device: *mut c_void,
    desc: *mut DxgiSwapChainDesc,
    output: *mut *mut c_void,
) -> i32 {
    let expected_viewport = EXPECTED_VIEWPORT_SWAP_CHAIN.with(|expected| expected.replace(false));
    if !expected_viewport || desc.is_null() || output.is_null() {
        return CreateSwapChainHook.call(factory, device, desc, output);
    }

    let original = unsafe { *desc };
    let tearing_supported = unsafe { factory_supports_tearing(factory) };
    if !tearing_supported {
        log(
            LogType::Warning,
            "DXGI flip model disabled: windowed tearing is unsupported",
        );
        let mut fallback = original;
        return CreateSwapChainHook.call(factory, device, &mut fallback, output);
    }

    for effect in [
        DXGI_SWAP_EFFECT_FLIP_DISCARD,
        DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL,
    ] {
        let hr = unsafe { create_with_flip_effect(factory, device, &original, output, effect) };
        if succeeded(hr) && !unsafe { *output }.is_null() {
            let swap_chain = unsafe { *output };
            match unsafe { install_swap_chain_hooks(swap_chain) } {
                Ok(()) => {
                    lock_or_recover(&FLIP_SWAP_CHAINS).insert(
                        swap_chain as usize,
                        FlipSwapChainState {
                            viewport: None,
                            windowed: original.windowed != 0,
                            allow_tearing: true,
                        },
                    );
                    log(
                        LogType::Init,
                        if effect == DXGI_SWAP_EFFECT_FLIP_DISCARD {
                            "DXGI flip-discard swap chain enabled with tearing support"
                        } else {
                            "DXGI flip-sequential swap chain enabled with tearing support"
                        },
                    );
                    return hr;
                }
                Err(error) => {
                    log(
                        LogType::Warning,
                        &format!("{error}; using legacy swap effect"),
                    );
                    unsafe { release_com(swap_chain) };
                    unsafe { *output = std::ptr::null_mut() };
                    break;
                }
            }
        }
        if !unsafe { *output }.is_null() {
            unsafe { release_com(*output) };
            unsafe { *output = std::ptr::null_mut() };
        }
    }

    let mut fallback = original;
    CreateSwapChainHook.call(factory, device, &mut fallback, output)
}

fn present_hook(swap_chain: *mut c_void, sync_interval: u32, flags: u32) -> i32 {
    let flags = match flip_swap_chain_state(swap_chain) {
        Some(state) if sync_interval == 0 && state.windowed && state.allow_tearing => {
            flags | DXGI_PRESENT_ALLOW_TEARING
        }
        Some(_) => flags & !DXGI_PRESENT_ALLOW_TEARING,
        None => flags,
    };
    PresentHook.call(swap_chain, sync_interval, flags)
}

fn resize_buffers_hook(
    swap_chain: *mut c_void,
    buffer_count: u32,
    width: u32,
    height: u32,
    format: i32,
    flags: u32,
) -> i32 {
    let state = flip_swap_chain_state(swap_chain);
    let count = if state.is_some() && buffer_count == 1 {
        2
    } else {
        buffer_count
    };
    let flags = if state.map(|state| state.allow_tearing).unwrap_or(false) {
        flags | DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING
    } else {
        flags
    };
    ResizeBuffersHook.call(swap_chain, count, width, height, format, flags)
}

fn set_fullscreen_state_hook(swap_chain: *mut c_void, fullscreen: i32, target: *mut c_void) -> i32 {
    let hr = SetFullscreenStateHook.call(swap_chain, fullscreen, target);
    if !succeeded(hr) || !is_flip_swap_chain(swap_chain) {
        return hr;
    }

    let state = {
        let mut swap_chains = lock_or_recover(&FLIP_SWAP_CHAINS);
        let state = swap_chains
            .get_mut(&(swap_chain as usize))
            .expect("tracked flip swap chain disappeared");
        state.windowed = fullscreen == 0;
        *state
    };
    let viewport = state.viewport.map(|address| address as *mut c_void);
    let released_back_buffer = viewport
        .map(|viewport| unsafe { release_back_buffer(viewport) })
        .unwrap_or(false);

    let mut desc = DxgiSwapChainDesc::default();
    let get_desc: GetDesc =
        unsafe { std::mem::transmute(vtable_entry(swap_chain, IDXGI_SWAP_CHAIN_GET_DESC_INDEX)) };
    let desc_hr = get_desc(swap_chain, &mut desc);
    if succeeded(desc_hr) {
        let flags = if state.allow_tearing {
            desc.flags | DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING
        } else {
            desc.flags
        };
        let resize_hr = ResizeBuffersHook.call(
            swap_chain,
            2,
            desc.buffer_desc.width,
            desc.buffer_desc.height,
            desc.buffer_desc.format,
            flags,
        );
        if !succeeded(resize_hr) {
            log(
                LogType::Warning,
                &format!("post-fullscreen ResizeBuffers failed with {resize_hr:#010x}"),
            );
        }
    } else {
        log(
            LogType::Warning,
            &format!("IDXGISwapChain::GetDesc failed with {desc_hr:#010x}"),
        );
    }

    if released_back_buffer {
        if let Some(viewport) = viewport {
            unsafe { restore_back_buffer(viewport, swap_chain) };
        }
    }
    hr
}

unsafe fn install_factory_hook(factory: *mut c_void) -> anyhow::Result<()> {
    let mut installed = lock_or_recover(&FACTORY_HOOK_LOCK);
    if *installed {
        return Ok(());
    }
    if factory.is_null() {
        bail!("FD3D11DynamicRHI has a null IDXGIFactory");
    }

    let create_swap_chain: CreateSwapChain =
        std::mem::transmute(vtable_entry(factory, IDXGI_FACTORY_CREATE_SWAP_CHAIN_INDEX));
    CreateSwapChainHook
        .initialize(create_swap_chain, create_swap_chain_hook)
        .context("failed to initialize IDXGIFactory::CreateSwapChain hook")?;
    CreateSwapChainHook
        .enable()
        .context("failed to enable IDXGIFactory::CreateSwapChain hook")?;
    *installed = true;
    Ok(())
}

fn viewport_ctor_hook(
    viewport: *mut c_void,
    rhi: *mut c_void,
    window: *mut c_void,
    size_x: u32,
    size_y: u32,
    fullscreen: u32,
) -> *mut c_void {
    let factory = unsafe { read_ptr(rhi, RHI_DXGI_FACTORY_OFFSET) };
    let factory_hook_ready = match unsafe { install_factory_hook(factory) } {
        Ok(()) => true,
        Err(error) => {
            log(
                LogType::Warning,
                &format!("DXGI flip model disabled: {error:#}"),
            );
            false
        }
    };

    let original: ViewportCtor = unsafe {
        std::mem::transmute(
            VIEWPORT_CTOR_HOOK
                .get()
                .expect("viewport constructor hook is enabled without a trampoline")
                .trampoline() as *const (),
        )
    };
    let expected_swap_chain = factory_hook_ready.then(ExpectedViewportSwapChainGuard::new);
    let result = original(viewport, rhi, window, size_x, size_y, fullscreen);
    drop(expected_swap_chain);

    let swap_chain = unsafe { read_ptr(viewport, VIEWPORT_SWAP_CHAIN_OFFSET) };
    if !swap_chain.is_null() {
        if let Some(state) = lock_or_recover(&FLIP_SWAP_CHAINS).get_mut(&(swap_chain as usize)) {
            state.viewport = Some(viewport as usize);
        }
    }
    result
}

fn viewport_dtor_hook(viewport: *mut c_void, arg2: usize, arg3: usize, arg4: usize) {
    let swap_chain = unsafe { read_ptr(viewport, VIEWPORT_SWAP_CHAIN_OFFSET) };
    if !swap_chain.is_null() {
        lock_or_recover(&FLIP_SWAP_CHAINS).remove(&(swap_chain as usize));
    }
    ViewportDtorHook.call(viewport, arg2, arg3, arg4);
}

pub fn init() -> anyhow::Result<()> {
    // These bytes identify the Ghidra-matched constructor in the supported
    // RenXSDK UDK.exe. dll.rs additionally verifies the complete .text hash.
    const EXPECTED_PROLOGUE: [u8; 12] = [
        0x48, 0x8B, 0xC4, 0x55, 0x41, 0x54, 0x41, 0x55, 0x48, 0x8D, 0x68, 0xB1,
    ];

    let udk = get_udk_ptr();
    let actual = unsafe { std::slice::from_raw_parts(udk.add(VIEWPORT_CTOR_RVA), 12) };
    if actual != EXPECTED_PROLOGUE {
        bail!("FD3D11Viewport constructor signature does not match the supported binary");
    }

    unsafe {
        let constructor_hook = RawDetour::new(
            udk.add(VIEWPORT_CTOR_RVA) as *const (),
            viewport_ctor_hook as *const (),
        )
        .context("failed to initialize FD3D11Viewport constructor hook")?;
        VIEWPORT_CTOR_HOOK
            .set(constructor_hook)
            .map_err(|_| anyhow::anyhow!("viewport constructor hook was already initialized"))?;
        ViewportDtorHook
            .initialize(
                std::mem::transmute(udk.add(VIEWPORT_DTOR_RVA)),
                viewport_dtor_hook,
            )
            .context("failed to initialize FD3D11Viewport destructor hook")?;
        VIEWPORT_CTOR_HOOK
            .get()
            .expect("viewport constructor hook was just initialized")
            .enable()
            .context("failed to enable FD3D11Viewport constructor hook")?;
        if let Err(error) = ViewportDtorHook.enable() {
            if let Some(hook) = VIEWPORT_CTOR_HOOK.get() {
                let _ = hook.disable();
            }
            return Err(error).context("failed to enable FD3D11Viewport destructor hook");
        }
    }

    Ok(())
}
