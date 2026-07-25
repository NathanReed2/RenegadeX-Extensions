//! Opt-in D3D9Ex/FlipEx compatibility layer for the 64-bit RenXSDK binary.
//!
//! `-D3D9FLIPEX` enables Ex plus FlipEx when the initial presentation setup is
//! eligible. `-D3D9EX` enables only the Ex/resource-emulation path. Without
//! either switch this module installs no hooks and stock D3D9 is unchanged.

#![cfg(target_arch = "x86_64")]

use crate::udk_log::{log, LogType};
use anyhow::Context;
use lazy_static::lazy_static;
use libloading::Library;
use retour::static_detour;
use std::{
    cell::Cell,
    collections::HashMap,
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Mutex, OnceLock},
};

type Ptr = *mut c_void;
type Hr = i32;
const OK: Hr = 0;
const FAIL: Hr = 0x80004005u32 as i32;
const SDK: u32 = 32;
const DEFAULT: u32 = 0;
const MANAGED: u32 = 1;
const SYSTEMMEM: u32 = 2;
const DISCARD: u32 = 1;
const FLIPEX: u32 = 5;
const LOCKABLE: u32 = 1;
const LOCK_READONLY: u32 = 0x10;
const LOCK_DISCARD: u32 = 0x2000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}
#[repr(C)]
struct LockedRect {
    pitch: i32,
    bits: Ptr,
}
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
#[repr(C)]
struct DisplayModeEx {
    size: u32,
    width: u32,
    height: u32,
    refresh: u32,
    format: u32,
    scanline: u32,
}

type Create9 = unsafe extern "system" fn(u32) -> Ptr;
type Create9Ex = unsafe extern "system" fn(u32, *mut Ptr) -> Hr;
type CreateDevice =
    unsafe extern "system" fn(Ptr, u32, u32, Ptr, u32, *mut PresentParams, *mut Ptr) -> Hr;
type CreateDeviceEx = unsafe extern "system" fn(
    Ptr,
    u32,
    u32,
    Ptr,
    u32,
    *mut PresentParams,
    *mut DisplayModeEx,
    *mut Ptr,
) -> Hr;
type ResetEx = unsafe extern "system" fn(Ptr, *mut PresentParams, *mut DisplayModeEx) -> Hr;
type PresentEx = unsafe extern "system" fn(Ptr, *const Rect, *const Rect, Ptr, Ptr, u32) -> Hr;
type UpdateTexture = unsafe extern "system" fn(Ptr, Ptr, Ptr) -> Hr;
type AddDirtyRect2D = unsafe extern "system" fn(Ptr, *const Rect) -> Hr;
type AddDirtyRectCube = unsafe extern "system" fn(Ptr, u32, *const Rect) -> Hr;
type Release = unsafe extern "system" fn(Ptr) -> u32;

const _: [(); 64] = [(); std::mem::size_of::<PresentParams>()];
const _: [(); 24] = [(); std::mem::size_of::<DisplayModeEx>()];

static_detour! {
 static Create9Hook:unsafe extern "system" fn(u32)->Ptr;
 static CreateDeviceHook:unsafe extern "system" fn(Ptr,u32,u32,Ptr,u32,*mut PresentParams,*mut Ptr)->Hr;
 static ResetHook:unsafe extern "system" fn(Ptr,*mut PresentParams)->Hr;
 static PresentHook:unsafe extern "system" fn(Ptr,*const Rect,*const Rect,Ptr,Ptr)->Hr;
 static CreateTextureHook:unsafe extern "system" fn(Ptr,u32,u32,u32,u32,u32,u32,*mut Ptr,*mut Ptr)->Hr;
 static CreateCubeHook:unsafe extern "system" fn(Ptr,u32,u32,u32,u32,u32,*mut Ptr,*mut Ptr)->Hr;
 static CreateVBHook:unsafe extern "system" fn(Ptr,u32,u32,u32,u32,*mut Ptr,*mut Ptr)->Hr;
 static CreateIBHook:unsafe extern "system" fn(Ptr,u32,u32,u32,u32,*mut Ptr,*mut Ptr)->Hr;
 static Lock2DHook:unsafe extern "system" fn(Ptr,u32,*mut LockedRect,*const Rect,u32)->Hr;
 static Unlock2DHook:unsafe extern "system" fn(Ptr,u32)->Hr;
 static Release2DHook:unsafe extern "system" fn(Ptr)->u32;
 static LockCubeHook:unsafe extern "system" fn(Ptr,u32,u32,*mut LockedRect,*const Rect,u32)->Hr;
 static UnlockCubeHook:unsafe extern "system" fn(Ptr,u32,u32)->Hr;
 static ReleaseCubeHook:unsafe extern "system" fn(Ptr)->u32;
}

#[derive(Clone, Copy)]
struct Config {
    ex: bool,
    flip: bool,
    editor: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    level: u32,
    face: u32,
    rect: Option<Rect>,
    read_only: bool,
}
#[derive(Clone, Copy)]
struct Managed {
    staging: usize,
    device: usize,
    pending: Option<Pending>,
}
static CONFIG: OnceLock<Config> = OnceLock::new();
static CREATE9EX: OnceLock<Create9Ex> = OnceLock::new();
static DEVICE: AtomicUsize = AtomicUsize::new(0);
static FLIP: AtomicBool = AtomicBool::new(false);
static FACTORY_HOOKED: AtomicBool = AtomicBool::new(false);
static DEVICE_HOOKED: AtomicBool = AtomicBool::new(false);
static TEX_HOOKED: AtomicBool = AtomicBool::new(false);
static CUBE_HOOKED: AtomicBool = AtomicBool::new(false);
static RELEASE_TARGET: AtomicUsize = AtomicUsize::new(0);
static FIRST_MANAGED_TEXTURE_LOGGED: AtomicBool = AtomicBool::new(false);
static FIRST_MANAGED_TEXTURE_STAGED_LOGGED: AtomicBool = AtomicBool::new(false);
thread_local! { static LEGACY_CREATE: Cell<bool> = const { Cell::new(false) }; }
lazy_static! {
    static ref INSTALL: Mutex<()> = Mutex::new(());
    static ref TEX: Mutex<HashMap<usize, Managed>> = Mutex::new(HashMap::new());
    static ref CUBES: Mutex<HashMap<usize, Managed>> = Mutex::new(HashMap::new());
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
fn good(hr: Hr) -> bool {
    hr >= 0
}
unsafe fn vt(p: Ptr, n: usize) -> Ptr {
    *(*(p as *const *const Ptr)).add(n)
}
unsafe fn release(p: Ptr) {
    if !p.is_null() {
        let f: Release = std::mem::transmute(vt(p, 2));
        f(p);
    }
}
fn active(p: Ptr) -> bool {
    DEVICE.load(Ordering::Acquire) == p as usize
}
fn args() -> Config {
    let a: Vec<String> = std::env::args_os()
        .map(|x| x.to_string_lossy().to_ascii_uppercase())
        .collect();
    let has = |n: &str| a.iter().any(|x| x.trim_start_matches(['-', '/']) == n);
    let flip = has("D3D9FLIPEX") && !has("NOD3D9FLIPEX");
    Config {
        ex: has("D3D9EX") || flip,
        flip,
        editor: has("EDITOR") || has("MAKE"),
    }
}
fn configure(p: &mut PresentParams, focus: Ptr) -> bool {
    let c = *CONFIG.get().unwrap();
    let flip = c.flip
        && !c.editor
        && p.windowed != 0
        && p.ms_type == 0
        && !p.window.is_null()
        && p.window == focus;
    if flip {
        p.count = 2;
        p.effect = FLIPEX;
        p.flags &= !LOCKABLE;
    } else if p.effect == FLIPEX {
        p.effect = DISCARD;
        p.count = 1;
    }
    flip
}

unsafe fn hook_factory(p: Ptr) -> anyhow::Result<()> {
    if FACTORY_HOOKED.load(Ordering::Acquire) {
        return Ok(());
    }
    let _g = lock(&INSTALL);
    if FACTORY_HOOKED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let f: CreateDevice = std::mem::transmute(vt(p, 16));
    CreateDeviceHook.initialize(f, |a, b, c, d, e, f, g| unsafe {
        create_device(a, b, c, d, e, f, g)
    })?;
    CreateDeviceHook.enable()?;
    FACTORY_HOOKED.store(true, Ordering::Release);
    Ok(())
}
unsafe fn hook_device(p: Ptr) -> anyhow::Result<()> {
    if DEVICE_HOOKED.load(Ordering::Acquire) {
        return Ok(());
    }
    let _g = lock(&INSTALL);
    if DEVICE_HOOKED.load(Ordering::Relaxed) {
        return Ok(());
    }
    ResetHook.initialize(std::mem::transmute(vt(p, 16)), |a, b| unsafe {
        reset(a, b)
    })?;
    ResetHook.enable()?;
    PresentHook.initialize(std::mem::transmute(vt(p, 17)), |a, b, c, d, e| unsafe {
        present(a, b, c, d, e)
    })?;
    PresentHook.enable()?;
    CreateTextureHook.initialize(
        std::mem::transmute(vt(p, 23)),
        |a, b, c, d, e, f, g, h, i| unsafe { create_texture(a, b, c, d, e, f, g, h, i) },
    )?;
    CreateTextureHook.enable()?;
    CreateCubeHook.initialize(
        std::mem::transmute(vt(p, 25)),
        |a, b, c, d, e, f, g, h| unsafe { create_cube(a, b, c, d, e, f, g, h) },
    )?;
    CreateCubeHook.enable()?;
    CreateVBHook.initialize(
        std::mem::transmute(vt(p, 26)),
        |a, b, c, d, e, f, g| unsafe { create_vb(a, b, c, d, e, f, g) },
    )?;
    CreateVBHook.enable()?;
    CreateIBHook.initialize(
        std::mem::transmute(vt(p, 27)),
        |a, b, c, d, e, f, g| unsafe { create_ib(a, b, c, d, e, f, g) },
    )?;
    CreateIBHook.enable()?;
    DEVICE_HOOKED.store(true, Ordering::Release);
    Ok(())
}

unsafe fn create9(sdk: u32) -> Ptr {
    let c = *CONFIG.get().unwrap();
    if !c.ex || sdk != SDK {
        return Create9Hook.call(sdk);
    }
    let mut p = std::ptr::null_mut();
    let hr = CREATE9EX.get().unwrap()(sdk, &mut p);
    if !good(hr) || p.is_null() {
        log(
            LogType::Warning,
            &format!("D3D9Ex unavailable ({hr:#010x}); stock D3D9 active"),
        );
        return Create9Hook.call(sdk);
    }
    if let Err(e) = hook_factory(p) {
        log(
            LogType::Warning,
            &format!("D3D9Ex hook failed: {e:#}; stock D3D9 active"),
        );
        release(p);
        return Create9Hook.call(sdk);
    }
    log(LogType::Init, "D3D9Ex available; awaiting device creation");
    p
}
unsafe fn legacy(
    adapter: u32,
    kind: u32,
    focus: Ptr,
    flags: u32,
    pp: *mut PresentParams,
    out: *mut Ptr,
) -> Hr {
    let d = Create9Hook.call(SDK);
    if d.is_null() {
        return FAIL;
    }
    let f: CreateDevice = std::mem::transmute(vt(d, 16));
    LEGACY_CREATE.with(|legacy| legacy.set(true));
    let hr = f(d, adapter, kind, focus, flags, pp, out);
    LEGACY_CREATE.with(|legacy| legacy.set(false));
    release(d);
    hr
}
unsafe fn create_device(
    factory: Ptr,
    adapter: u32,
    kind: u32,
    focus: Ptr,
    flags: u32,
    pp: *mut PresentParams,
    out: *mut Ptr,
) -> Hr {
    if LEGACY_CREATE.with(|legacy| legacy.replace(false)) {
        return CreateDeviceHook.call(factory, adapter, kind, focus, flags, pp, out);
    }
    if pp.is_null() || out.is_null() {
        return CreateDeviceHook.call(factory, adapter, kind, focus, flags, pp, out);
    }
    let old = *pp;
    let flip = configure(&mut *pp, focus);
    let f: CreateDeviceEx = std::mem::transmute(vt(factory, 20));
    *out = std::ptr::null_mut();
    let hr = f(
        factory,
        adapter,
        kind,
        focus,
        flags,
        pp,
        std::ptr::null_mut(),
        out,
    );
    if good(hr) && !(*out).is_null() {
        if let Err(e) = hook_device(*out) {
            log(
                LogType::Warning,
                &format!("D3D9Ex device hooks failed: {e:#}; falling back"),
            );
            release(*out);
            *out = std::ptr::null_mut();
            *pp = old;
            return legacy(adapter, kind, focus, flags, pp, out);
        }
        DEVICE.store(*out as usize, Ordering::Release);
        FLIP.store(flip, Ordering::Release);
        log(LogType::Init,&format!("D3D9Ex active: FlipEx requested={}, active={}, {}x{}, buffers={}, interval={}, HWND={:#x}",CONFIG.get().unwrap().flip,flip,(*pp).width,(*pp).height,(*pp).count,(*pp).interval,(*pp).window as usize));
        log(LogType::Init,"D3D9Ex resources: DEFAULT GPU textures with SYSTEMMEM staging; static vertex/index buffers use DEFAULT");
        return hr;
    }
    log(
        LogType::Warning,
        &format!("CreateDeviceEx failed ({hr:#010x}); falling back to stock D3D9"),
    );
    *pp = old;
    legacy(adapter, kind, focus, flags, pp, out)
}

unsafe fn reset(dev: Ptr, pp: *mut PresentParams) -> Hr {
    if !active(dev) || pp.is_null() {
        return ResetHook.call(dev, pp);
    }
    let flip = configure(&mut *pp, (*pp).window);
    FLIP.store(flip, Ordering::Release);
    let f: ResetEx = std::mem::transmute(vt(dev, 132));
    let mut m = DisplayModeEx {
        size: std::mem::size_of::<DisplayModeEx>() as u32,
        width: (*pp).width,
        height: (*pp).height,
        refresh: (*pp).refresh,
        format: (*pp).format,
        scanline: 0,
    };
    let mp = if (*pp).windowed != 0 {
        std::ptr::null_mut()
    } else {
        &mut m
    };
    let hr = f(dev, pp, mp);
    if !good(hr) {
        log(LogType::Warning, &format!("ResetEx failed ({hr:#010x})"));
    }
    hr
}
unsafe fn present(dev: Ptr, s: *const Rect, d: *const Rect, w: Ptr, r: Ptr) -> Hr {
    if !active(dev) {
        return PresentHook.call(dev, s, d, w, r);
    }
    let f: PresentEx = std::mem::transmute(vt(dev, 121));
    let flip = FLIP.load(Ordering::Acquire);
    let hr = if flip {
        f(
            dev,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    } else {
        f(dev, s, d, w, r, 0)
    };
    if hr < 0 {
        log(LogType::Warning, &format!("PresentEx failed ({hr:#010x})"));
    }
    hr
}

unsafe fn hook_texture(p: Ptr) -> anyhow::Result<()> {
    if TEX_HOOKED.load(Ordering::Acquire) {
        return Ok(());
    }
    let _g = lock(&INSTALL);
    if TEX_HOOKED.load(Ordering::Relaxed) {
        return Ok(());
    }
    Lock2DHook.initialize(std::mem::transmute(vt(p, 19)), |a, b, c, d, e| unsafe {
        lock_2d(a, b, c, d, e)
    })?;
    Unlock2DHook.initialize(std::mem::transmute(vt(p, 20)), |a, b| unsafe {
        unlock_2d(a, b)
    })?;
    let rel = vt(p, 2);
    Release2DHook.initialize(std::mem::transmute(rel), |a| unsafe { release_2d(a) })?;
    Lock2DHook.enable()?;
    Unlock2DHook.enable()?;
    Release2DHook.enable()?;
    RELEASE_TARGET.store(rel as usize, Ordering::Release);
    TEX_HOOKED.store(true, Ordering::Release);
    Ok(())
}
unsafe fn hook_cube(p: Ptr) -> anyhow::Result<()> {
    if CUBE_HOOKED.load(Ordering::Acquire) {
        return Ok(());
    }
    let _g = lock(&INSTALL);
    if CUBE_HOOKED.load(Ordering::Relaxed) {
        return Ok(());
    }
    LockCubeHook.initialize(std::mem::transmute(vt(p, 19)), |a, b, c, d, e, f| unsafe {
        lock_cube(a, b, c, d, e, f)
    })?;
    UnlockCubeHook.initialize(std::mem::transmute(vt(p, 20)), |a, b, c| unsafe {
        unlock_cube(a, b, c)
    })?;
    let rel = vt(p, 2);
    let shared = RELEASE_TARGET.load(Ordering::Acquire) == rel as usize;
    if !shared {
        ReleaseCubeHook.initialize(std::mem::transmute(rel), |a| unsafe { release_cube(a) })?;
    }
    LockCubeHook.enable()?;
    UnlockCubeHook.enable()?;
    if !shared {
        ReleaseCubeHook.enable()?
    }
    CUBE_HOOKED.store(true, Ordering::Release);
    Ok(())
}

unsafe fn create_texture(
    dev: Ptr,
    w: u32,
    h: u32,
    levels: u32,
    usage: u32,
    format: u32,
    pool: u32,
    out: *mut Ptr,
    shared: *mut Ptr,
) -> Hr {
    if pool == MANAGED && !FIRST_MANAGED_TEXTURE_LOGGED.swap(true, Ordering::AcqRel) {
        log(LogType::Init,&format!("D3D9Ex first managed texture: device={:#x}, active_device={:#x}, active_match={}, {}x{}, levels={}, usage={:#x}, format={:#x}",dev as usize,DEVICE.load(Ordering::Acquire),active(dev),w,h,levels,usage,format));
    }
    if !active(dev) || pool != MANAGED || out.is_null() {
        return CreateTextureHook.call(dev, w, h, levels, usage, format, pool, out, shared);
    }
    if usage != 0 {
        log(
            LogType::Warning,
            &format!("managed texture usage {usage:#x} cannot be staged"),
        );
        return FAIL;
    }
    let mut gpu = std::ptr::null_mut();
    let hr = CreateTextureHook.call(dev, w, h, levels, 0, format, DEFAULT, &mut gpu, shared);
    if !good(hr) || gpu.is_null() {
        log(
            LogType::Warning,
            &format!(
                "D3D9Ex managed texture GPU allocation failed ({hr:#010x}), ptr={:#x}",
                gpu as usize
            ),
        );
        return hr;
    }
    let mut staging = std::ptr::null_mut();
    let shr = CreateTextureHook.call(
        dev,
        w,
        h,
        levels,
        0,
        format,
        SYSTEMMEM,
        &mut staging,
        std::ptr::null_mut(),
    );
    if !good(shr) || staging.is_null() {
        log(
            LogType::Warning,
            &format!(
                "D3D9Ex managed texture staging allocation failed ({shr:#010x}), ptr={:#x}",
                staging as usize
            ),
        );
        release(gpu);
        return shr;
    }
    if let Err(e) = hook_texture(gpu) {
        log(LogType::Warning, &format!("2D staging hook failed: {e:#}"));
        release(staging);
        release(gpu);
        return FAIL;
    }
    lock(&TEX).insert(
        gpu as usize,
        Managed {
            staging: staging as usize,
            device: dev as usize,
            pending: None,
        },
    );
    *out = gpu;
    if !FIRST_MANAGED_TEXTURE_STAGED_LOGGED.swap(true, Ordering::AcqRel) {
        log(
            LogType::Init,
            &format!(
                "D3D9Ex first managed texture staged successfully: GPU={:#x}, SYSTEMMEM={:#x}",
                gpu as usize, staging as usize
            ),
        );
    }
    OK
}
unsafe fn create_cube(
    dev: Ptr,
    edge: u32,
    levels: u32,
    usage: u32,
    format: u32,
    pool: u32,
    out: *mut Ptr,
    shared: *mut Ptr,
) -> Hr {
    if !active(dev) || pool != MANAGED || out.is_null() {
        return CreateCubeHook.call(dev, edge, levels, usage, format, pool, out, shared);
    }
    if usage != 0 {
        return FAIL;
    }
    let mut gpu = std::ptr::null_mut();
    let hr = CreateCubeHook.call(dev, edge, levels, 0, format, DEFAULT, &mut gpu, shared);
    if !good(hr) || gpu.is_null() {
        return hr;
    }
    let mut staging = std::ptr::null_mut();
    let shr = CreateCubeHook.call(
        dev,
        edge,
        levels,
        0,
        format,
        SYSTEMMEM,
        &mut staging,
        std::ptr::null_mut(),
    );
    if !good(shr) || staging.is_null() {
        release(gpu);
        return shr;
    }
    if let Err(e) = hook_cube(gpu) {
        log(
            LogType::Warning,
            &format!("cube staging hook failed: {e:#}"),
        );
        release(staging);
        release(gpu);
        return FAIL;
    }
    lock(&CUBES).insert(
        gpu as usize,
        Managed {
            staging: staging as usize,
            device: dev as usize,
            pending: None,
        },
    );
    *out = gpu;
    OK
}
unsafe fn create_vb(
    dev: Ptr,
    len: u32,
    usage: u32,
    fvf: u32,
    pool: u32,
    out: *mut Ptr,
    shared: *mut Ptr,
) -> Hr {
    let p = if active(dev) && pool == MANAGED {
        DEFAULT
    } else {
        pool
    };
    CreateVBHook.call(dev, len, usage, fvf, p, out, shared)
}
unsafe fn create_ib(
    dev: Ptr,
    len: u32,
    usage: u32,
    format: u32,
    pool: u32,
    out: *mut Ptr,
    shared: *mut Ptr,
) -> Hr {
    let p = if active(dev) && pool == MANAGED {
        DEFAULT
    } else {
        pool
    };
    CreateIBHook.call(dev, len, usage, format, p, out, shared)
}

unsafe fn lock_2d(tex: Ptr, level: u32, out: *mut LockedRect, rect: *const Rect, flags: u32) -> Hr {
    let Some(mut m) = lock(&TEX).get(&(tex as usize)).copied() else {
        return Lock2DHook.call(tex, level, out, rect, flags);
    };
    let hr = Lock2DHook.call(m.staging as Ptr, level, out, rect, flags & !LOCK_DISCARD);
    if good(hr) {
        m.pending = Some(Pending {
            level,
            face: 0,
            rect: rect.as_ref().copied(),
            read_only: flags & LOCK_READONLY != 0,
        });
        lock(&TEX).insert(tex as usize, m);
    }
    hr
}
unsafe fn copy_2d(tex: Ptr, m: Managed, p: Pending) -> Hr {
    if p.read_only {
        return OK;
    }
    // D3D9 only accumulates UpdateTexture dirty regions at level zero. UE3
    // writes individual mip levels, so explicitly dirty the full texture after
    // every written mip to ensure the updated sublevel is uploaded as well.
    let dirty: AddDirtyRect2D = std::mem::transmute(vt(m.staging as Ptr, 21));
    let hr = dirty(m.staging as Ptr, std::ptr::null());
    if !good(hr) {
        log(
            LogType::Warning,
            &format!("D3D9Ex AddDirtyRect failed ({hr:#010x}), mip={}", p.level),
        );
        return hr;
    }
    let update: UpdateTexture = std::mem::transmute(vt(m.device as Ptr, 31));
    let hr = update(m.device as Ptr, m.staging as Ptr, tex);
    if !good(hr) {
        log(
            LogType::Warning,
            &format!(
                "D3D9Ex UpdateTexture failed ({hr:#010x}), mip={}, rect={}",
                p.level,
                if p.rect.is_some() { "partial" } else { "full" }
            ),
        );
    }
    hr
}
unsafe fn unlock_2d(tex: Ptr, level: u32) -> Hr {
    let Some(m) = lock(&TEX).get(&(tex as usize)).copied() else {
        return Unlock2DHook.call(tex, level);
    };
    let hr = Unlock2DHook.call(m.staging as Ptr, level);
    if !good(hr) {
        return hr;
    }
    let p = m.pending.unwrap_or(Pending {
        level,
        face: 0,
        rect: None,
        read_only: false,
    });
    let hr = copy_2d(tex, m, p);
    if let Some(v) = lock(&TEX).get_mut(&(tex as usize)) {
        v.pending = None
    }
    hr
}

unsafe fn lock_cube(
    tex: Ptr,
    face: u32,
    level: u32,
    out: *mut LockedRect,
    rect: *const Rect,
    flags: u32,
) -> Hr {
    let Some(mut m) = lock(&CUBES).get(&(tex as usize)).copied() else {
        return LockCubeHook.call(tex, face, level, out, rect, flags);
    };
    let hr = LockCubeHook.call(
        m.staging as Ptr,
        face,
        level,
        out,
        rect,
        flags & !LOCK_DISCARD,
    );
    if good(hr) {
        m.pending = Some(Pending {
            level,
            face,
            rect: rect.as_ref().copied(),
            read_only: flags & LOCK_READONLY != 0,
        });
        lock(&CUBES).insert(tex as usize, m);
    }
    hr
}
unsafe fn copy_cube(tex: Ptr, m: Managed, p: Pending) -> Hr {
    if p.read_only {
        return OK;
    }
    let dirty: AddDirtyRectCube = std::mem::transmute(vt(m.staging as Ptr, 21));
    let hr = dirty(m.staging as Ptr, p.face, std::ptr::null());
    if !good(hr) {
        log(
            LogType::Warning,
            &format!(
                "D3D9Ex cube AddDirtyRect failed ({hr:#010x}), face={}, mip={}",
                p.face, p.level
            ),
        );
        return hr;
    }
    let update: UpdateTexture = std::mem::transmute(vt(m.device as Ptr, 31));
    let hr = update(m.device as Ptr, m.staging as Ptr, tex);
    if !good(hr) {
        log(
            LogType::Warning,
            &format!(
                "D3D9Ex cube UpdateTexture failed ({hr:#010x}), face={}, mip={}, rect={}",
                p.face,
                p.level,
                if p.rect.is_some() { "partial" } else { "full" }
            ),
        );
    }
    hr
}
unsafe fn unlock_cube(tex: Ptr, face: u32, level: u32) -> Hr {
    let Some(m) = lock(&CUBES).get(&(tex as usize)).copied() else {
        return UnlockCubeHook.call(tex, face, level);
    };
    let hr = UnlockCubeHook.call(m.staging as Ptr, face, level);
    if !good(hr) {
        return hr;
    }
    let p = m.pending.unwrap_or(Pending {
        level,
        face,
        rect: None,
        read_only: false,
    });
    let hr = copy_cube(tex, m, p);
    if let Some(v) = lock(&CUBES).get_mut(&(tex as usize)) {
        v.pending = None
    }
    hr
}

unsafe fn drop_managed(map: &Mutex<HashMap<usize, Managed>>, tex: Ptr) {
    // Drop the map guard before Release. Texture Release is detoured and can
    // re-enter this function for the staging texture.
    let staging = { lock(map).remove(&(tex as usize)).map(|m| m.staging) };
    if let Some(staging) = staging {
        release(staging as Ptr)
    }
}
unsafe fn release_2d(tex: Ptr) -> u32 {
    let n = Release2DHook.call(tex);
    if n == 0 {
        drop_managed(&TEX, tex);
        drop_managed(&CUBES, tex)
    }
    n
}
unsafe fn release_cube(tex: Ptr) -> u32 {
    let n = ReleaseCubeHook.call(tex);
    if n == 0 {
        drop_managed(&CUBES, tex)
    }
    n
}

fn try_init() -> anyhow::Result<()> {
    let c = args();
    CONFIG
        .set(c)
        .map_err(|_| anyhow::anyhow!("D3D9Ex config already initialized"))?;
    if !c.ex {
        return Ok(());
    }
    let lib = unsafe { Library::new("d3d9.dll") }.context("loading d3d9.dll")?;
    let create: Create9 = unsafe { *lib.get(b"Direct3DCreate9\0")? };
    let create_ex: Create9Ex = unsafe { *lib.get(b"Direct3DCreate9Ex\0")? };
    CREATE9EX
        .set(create_ex)
        .map_err(|_| anyhow::anyhow!("Direct3DCreate9Ex already initialized"))?;
    std::mem::forget(lib);
    unsafe {
        Create9Hook
            .initialize(create, |sdk| create9(sdk))
            .context("initializing Direct3DCreate9 hook")?;
        Create9Hook
            .enable()
            .context("enabling Direct3DCreate9 hook")?;
    }
    Ok(())
}

pub fn init() -> anyhow::Result<()> {
    // DllMain runs before UE3's GLog object is ready. Never route setup errors
    // through udk_log here; a call into FOutputDevice during loader startup
    // faults inside UDK.exe and Windows reports 0xc0000142. Runtime hooks log
    // normally once Direct3D initialization begins.
    let _ = try_init();
    Ok(())
}
