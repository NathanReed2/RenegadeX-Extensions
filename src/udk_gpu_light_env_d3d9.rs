//! The GPU half of [`crate::udk_gpu_light_env`]: resources, the SH gather
//! shader, and the readback ring.
//!
//! Raw D3D9 through vtable indices, matching how `udk_d3d9_flipex` and
//! `udk_d3d9_present_params` already talk to the runtime. The `windows` crate is
//! not built with `Win32_Graphics_Direct3D9` in this crate, and pulling it in for
//! a couple of dozen calls would be a large dependency for little gain.
//!
//! Declared from the parent with `#[path]` so it can reach the parent's statics
//! through `use super::*` while staying a separate file.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::bail;
use retour::static_detour;

use super::*;

pub(crate) type Ptr = *mut c_void;
type Hr = i32;

/// `IDirect3DDevice9` vtable slots.
mod dev {
    pub const PRESENT: usize = 17;
    pub const CREATE_TEXTURE: usize = 23;
    pub const GET_RENDER_TARGET_DATA: usize = 32;
    pub const CREATE_OFFSCREEN_PLAIN_SURFACE: usize = 36;
    pub const SET_RENDER_TARGET: usize = 37;
    pub const GET_RENDER_TARGET: usize = 38;
    pub const SET_DEPTH_STENCIL_SURFACE: usize = 39;
    pub const GET_DEPTH_STENCIL_SURFACE: usize = 40;
    pub const SET_VIEWPORT: usize = 47;
    pub const SET_RENDER_STATE: usize = 57;
    pub const CREATE_STATE_BLOCK: usize = 59;
    pub const SET_TEXTURE: usize = 65;
    pub const SET_SAMPLER_STATE: usize = 69;
    pub const DRAW_PRIMITIVE_UP: usize = 83;
    pub const SET_FVF: usize = 89;
    pub const SET_VERTEX_SHADER: usize = 92;
    pub const CREATE_PIXEL_SHADER: usize = 106;
    pub const SET_PIXEL_SHADER: usize = 107;
    pub const SET_PIXEL_SHADER_CONSTANT_F: usize = 109;
}

const RELEASE: usize = 2;
const STATE_BLOCK_CAPTURE: usize = 4;
const STATE_BLOCK_APPLY: usize = 5;
const TEXTURE_GET_SURFACE_LEVEL: usize = 18;
const TEXTURE_LOCK_RECT: usize = 19;
const TEXTURE_UNLOCK_RECT: usize = 20;
const SURFACE_LOCK_RECT: usize = 13;
const SURFACE_UNLOCK_RECT: usize = 14;
/// `ID3DBlob::GetBufferPointer` / `GetBufferSize`.
const BLOB_GET_POINTER: usize = 3;
const BLOB_GET_SIZE: usize = 4;

const FMT_A32B32G32R32F: u32 = 116;
/// `D3DFMT_L8` - one byte per texel, read back as `.r`.
const FMT_L8: u32 = 50;
const POOL_DEFAULT: u32 = 0;
const POOL_MANAGED: u32 = 1;
const POOL_SYSTEMMEM: u32 = 2;
const USAGE_RENDERTARGET: u32 = 1;
const USAGE_DYNAMIC: u32 = 0x200;
const LOCK_DISCARD: u32 = 0x2000;
const LOCK_READONLY: u32 = 0x10;
const FVF_XYZRHW_TEX1: u32 = 0x004 | 0x100;
const PT_TRIANGLESTRIP: u32 = 5;
const SBT_ALL: u32 = 1;

const RS_ZENABLE: u32 = 7;
const RS_ZWRITEENABLE: u32 = 14;
const RS_ALPHATESTENABLE: u32 = 15;
const RS_CULLMODE: u32 = 22;
const RS_ALPHABLENDENABLE: u32 = 27;
const RS_FOGENABLE: u32 = 28;
const RS_STENCILENABLE: u32 = 52;
const RS_COLORWRITEENABLE: u32 = 168;
const RS_SCISSORTESTENABLE: u32 = 174;
const RS_SRGBWRITEENABLE: u32 = 194;
const CULL_NONE: u32 = 1;

const SAMP_ADDRESSU: u32 = 1;
const SAMP_ADDRESSV: u32 = 2;
const SAMP_MAGFILTER: u32 = 5;
const SAMP_MINFILTER: u32 = 6;
const SAMP_MIPFILTER: u32 = 7;
const SAMP_SRGBTEXTURE: u32 = 11;
const TEXF_NONE: u32 = 0;
const TEXF_POINT: u32 = 1;
const TADDRESS_CLAMP: u32 = 3;

#[repr(C)]
struct LockedRect {
    pitch: i32,
    bits: Ptr,
}

/// A screen-space quad vertex.
///
/// Pre-transformed, so the pass needs no vertex shader and no vertex
/// declaration. Fixed-function vertex processing feeding a programmable pixel
/// shader is legal in D3D9 and is by far the least device state to disturb.
#[repr(C)]
#[derive(Clone, Copy)]
struct Vertex {
    x: f32,
    y: f32,
    z: f32,
    rhw: f32,
    u: f32,
    v: f32,
}

unsafe fn vt(object: Ptr, slot: usize) -> Ptr {
    let vtable = *(object as *const *const Ptr);
    *vtable.add(slot)
}

unsafe fn release(object: Ptr) {
    if !object.is_null() {
        let f: unsafe extern "system" fn(Ptr) -> u32 = std::mem::transmute(vt(object, RELEASE));
        f(object);
    }
}

// The SH gather shader lives in shaders/sh_gather.hlsl and is compiled to
// ps_3_0 bytecode at build time; see SH_GATHER_BYTECODE below.

/// Everything the pass owns. All `D3DPOOL_DEFAULT` except the readback
/// surfaces, so all of it has to be rebuilt after a device reset.
struct Gpu {
    device: Ptr,
    light_texture: Ptr,
    dle_texture: Ptr,
    atlas_texture: Ptr,
    atlas_surface: Ptr,
    /// 256x256 `AndLut[a][b] = (a & b) != 0`. Built once; it is what lets a
    /// `ps_3_0` shader do the lighting-channel bit test.
    and_lut: Ptr,
    readback: [Ptr; READBACK_RING],
    pixel_shader: Ptr,
    /// Captured and applied around the pass, created **once**.
    ///
    /// `CreateStateBlock(D3DSBT_ALL)` records the entire device state and is a
    /// heavyweight allocation; D3D9 wants it built at init and reused. Doing it
    /// per frame - which this module did at first - cost roughly two thirds of
    /// the frame rate on its own.
    state_block: Ptr,
    /// Passes completed, used to pick which readback surface is safe to lock.
    tick: u64,
}


// Only ever touched on the thread that owns the device, under GPU's lock.
unsafe impl Send for Gpu {}

static GPU: Mutex<Option<Gpu>> = Mutex::new(None);
static PRESENT_HOOKED: AtomicBool = AtomicBool::new(false);
static DEVICE: AtomicUsize = AtomicUsize::new(0);

/// Counters behind the periodic status line in [`crate::udk_gpu_light_env`].
///
/// Every diagnostic in this file is `debug_log!`, which is compiled out of a
/// release build, so a silent failure here is indistinguishable from success in
/// the shipping log: the module falls back to the stock CPU path and says
/// nothing. These are the counters that make the difference observable.
pub(crate) static PASS_COUNT: AtomicU32 = AtomicU32::new(0);
pub(crate) static READBACK_COUNT: AtomicU32 = AtomicU32::new(0);
/// 0 = not attempted, 1 = created, 2 = creation failed.
pub(crate) static RESOURCE_STATE: AtomicU32 = AtomicU32::new(0);
/// First resource-creation failure, kept for the status line.
pub(crate) static RESOURCE_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// Snapshot for the status line: `(present hooked, resource state, passes,
/// readbacks)`.
pub(crate) fn status() -> (bool, u32, u32, u32) {
    (
        PRESENT_HOOKED.load(Ordering::Relaxed),
        RESOURCE_STATE.load(Ordering::Relaxed),
        PASS_COUNT.load(Ordering::Relaxed),
        READBACK_COUNT.load(Ordering::Relaxed),
    )
}

static_detour! {
    static PresentHook: unsafe extern "system" fn(Ptr, Ptr, Ptr, Ptr, Ptr) -> Hr;
}

/// Receives the live device from the `CreateDevice` detour in
/// `udk_d3d9_present_params` and installs the `Present` hook that drives the
/// pass.
///
/// Taking the device from there rather than hooking `CreateDevice` again matters:
/// two modules already own that export, and a third detour on it would be a
/// needless ordering hazard. Every `IDirect3DDevice9` from one runtime shares a
/// vtable, so the `Present` hook installs once per process.
pub(crate) fn note_device(device: Ptr) {
    if !ENABLED.load(Ordering::Acquire) || device.is_null() {
        return;
    }
    DEVICE.store(device as usize, Ordering::Release);

    if PRESENT_HOOKED.swap(true, Ordering::AcqRel) {
        return;
    }
    unsafe {
        let target: unsafe extern "system" fn(Ptr, Ptr, Ptr, Ptr, Ptr) -> Hr =
            std::mem::transmute(vt(device, dev::PRESENT));
        let installed = PresentHook
            .initialize(target, |device, a, b, c, d| present(device, a, b, c, d))
            .and_then(|_| PresentHook.enable());
        if installed.is_err() {
            debug_log!("-GPULIGHTENV: Present hook failed; the GPU pass will not run");
            PRESENT_HOOKED.store(false, Ordering::Release);
        }
    }
}

/// Marks the resources dead after a device reset. Called from the `Reset` path;
/// the next `Present` rebuilds them, and every DLE takes the stock CPU path in
/// the meantime.
pub(crate) fn invalidate() {
    ATLAS_INVALID.store(true, Ordering::Release);
    if let Ok(mut guard) = GPU.lock() {
        *guard = None;
    }
}

/// Runs one pass per presented frame, on the thread that owns the device.
unsafe fn present(device: Ptr, a: Ptr, b: Ptr, c: Ptr, d: Ptr) -> Hr {
    // This crate builds with `panic = "abort"`, so an unexpected panic here
    // would take the process down rather than drop a frame. Nothing in the pass
    // is worth that.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_pass(device)));
    note_frame();
    PresentHook.call(device, a, b, c, d)
}

/// The SH gather, precompiled to `ps_3_0` by `fxc` and embedded.
///
/// Compiling at runtime was tried first and does not work here, for two
/// independent reasons - either one fatal:
///
/// 1. The inbox `d3dcompiler_47.dll` returns `E_NOTIMPL` (`0x80004001`) from
///    `D3DCompile`. Shipping a working copy alongside the DLL would fix that,
///    but it is a redistributable dependency for no benefit: this shader takes
///    no runtime specialisation.
/// 2. The source has to pass `fxc` anyway. `ps_3_0` has no bitwise operators
///    and no `asint`, and the first draft of this shader used both to unpack
///    the lighting-channel mask and the light flags. That failed silently as a
///    runtime compile - the pass simply never ran - and was only caught once
///    the shader was put through `fxc` at build time.
///
/// Rebuild with `shaders/build.ps1` after editing `shaders/sh_gather.hlsl`.
const SH_GATHER_BYTECODE: &[u8] = include_bytes!("../shaders/sh_gather.ps_3_0.cso");

unsafe fn create_pixel_shader(device: Ptr) -> anyhow::Result<Ptr> {
    if SH_GATHER_BYTECODE.len() % 4 != 0 || SH_GATHER_BYTECODE.is_empty() {
        bail!("embedded ps_3_0 bytecode is not a whole number of DWORDs");
    }
    // `include_bytes!` gives no alignment guarantee and D3D9 wants DWORDs.
    let tokens: Vec<u32> = SH_GATHER_BYTECODE
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    let create: unsafe extern "system" fn(Ptr, *const u32, *mut Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::CREATE_PIXEL_SHADER));
    let mut shader: Ptr = std::ptr::null_mut();
    let hr = create(device, tokens.as_ptr(), &mut shader);
    if hr < 0 || shader.is_null() {
        bail!("CreatePixelShader failed ({hr:#010x})");
    }
    Ok(shader)
}

unsafe fn create_resources(device: Ptr) -> anyhow::Result<Gpu> {
    let create_texture: unsafe extern "system" fn(
        Ptr,
        u32,
        u32,
        u32,
        u32,
        u32,
        u32,
        *mut Ptr,
        Ptr,
    ) -> Hr = std::mem::transmute(vt(device, dev::CREATE_TEXTURE));
    let create_offscreen: unsafe extern "system" fn(Ptr, u32, u32, u32, u32, *mut Ptr, Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::CREATE_OFFSCREEN_PLAIN_SURFACE));

    let mut gpu = Gpu {
        device,
        light_texture: std::ptr::null_mut(),
        dle_texture: std::ptr::null_mut(),
        atlas_texture: std::ptr::null_mut(),
        atlas_surface: std::ptr::null_mut(),
        and_lut: std::ptr::null_mut(),
        readback: [std::ptr::null_mut(); READBACK_RING],
        pixel_shader: std::ptr::null_mut(),
        state_block: std::ptr::null_mut(),
        tick: 0,
    };

    if create_texture(
        device,
        MAX_LIGHTS as u32,
        LIGHT_TEXELS as u32,
        1,
        USAGE_DYNAMIC,
        FMT_A32B32G32R32F,
        POOL_DEFAULT,
        &mut gpu.light_texture,
        std::ptr::null_mut(),
    ) < 0
    {
        bail!("CreateTexture(light table) failed");
    }

    if create_texture(
        device,
        MAX_SLOTS as u32,
        DLE_TEXELS as u32,
        1,
        USAGE_DYNAMIC,
        FMT_A32B32G32R32F,
        POOL_DEFAULT,
        &mut gpu.dle_texture,
        std::ptr::null_mut(),
    ) < 0
    {
        bail!("CreateTexture(DLE table) failed");
    }

    // A render-target *texture* rather than a bare render target, so its level-0
    // surface can be handed to GetRenderTargetData.
    if create_texture(
        device,
        MAX_SLOTS as u32,
        ATLAS_ROWS as u32,
        1,
        USAGE_RENDERTARGET,
        FMT_A32B32G32R32F,
        POOL_DEFAULT,
        &mut gpu.atlas_texture,
        std::ptr::null_mut(),
    ) < 0
    {
        bail!("CreateTexture(SH atlas) failed");
    }

    let get_surface: unsafe extern "system" fn(Ptr, u32, *mut Ptr) -> Hr =
        std::mem::transmute(vt(gpu.atlas_texture, TEXTURE_GET_SURFACE_LEVEL));
    if get_surface(gpu.atlas_texture, 0, &mut gpu.atlas_surface) < 0 {
        bail!("GetSurfaceLevel(SH atlas) failed");
    }

    // Three system-memory surfaces: the one being locked was filled two frames
    // ago, so its copy has certainly retired and the lock never stalls.
    for surface in gpu.readback.iter_mut() {
        if create_offscreen(
            device,
            MAX_SLOTS as u32,
            ATLAS_ROWS as u32,
            FMT_A32B32G32R32F,
            POOL_SYSTEMMEM,
            surface,
            std::ptr::null_mut(),
        ) < 0
        {
            bail!("CreateOffscreenPlainSurface(readback) failed");
        }
    }

    // The channel-test lookup: 256x256 of `(a & b) != 0`, 8 bits per texel.
    //
    // D3DPOOL_MANAGED, not DEFAULT: a DEFAULT-pool texture cannot be locked
    // unless it was created D3DUSAGE_DYNAMIC, so filling one in place fails with
    // `LockRect(AndLut) failed` and takes the whole pass down with it. This is
    // write-once static data, which is exactly what MANAGED is for - the driver
    // keeps the system copy and it survives a device reset for free.
    if create_texture(
        device,
        256,
        256,
        1,
        0,
        FMT_L8,
        POOL_MANAGED,
        &mut gpu.and_lut,
        std::ptr::null_mut(),
    ) < 0
    {
        bail!("CreateTexture(AndLut) failed");
    }
    {
        let lock: unsafe extern "system" fn(Ptr, u32, *mut LockedRect, Ptr, u32) -> Hr =
            std::mem::transmute(vt(gpu.and_lut, TEXTURE_LOCK_RECT));
        let unlock: unsafe extern "system" fn(Ptr, u32) -> Hr =
            std::mem::transmute(vt(gpu.and_lut, TEXTURE_UNLOCK_RECT));
        let mut rect = LockedRect {
            pitch: 0,
            bits: std::ptr::null_mut(),
        };
        if lock(gpu.and_lut, 0, &mut rect, std::ptr::null_mut(), 0) < 0 || rect.bits.is_null() {
            bail!("LockRect(AndLut) failed");
        }
        for a in 0..256usize {
            let row = (rect.bits as *mut u8).add(a * rect.pitch as usize);
            for b in 0..256usize {
                *row.add(b) = if a & b != 0 { 255 } else { 0 };
            }
        }
        unlock(gpu.and_lut, 0);
    }

    gpu.pixel_shader = create_pixel_shader(device)?;

    // Once, not per frame - see the field's documentation.
    let create_state_block: unsafe extern "system" fn(Ptr, u32, *mut Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::CREATE_STATE_BLOCK));
    if create_state_block(device, SBT_ALL, &mut gpu.state_block) < 0 || gpu.state_block.is_null() {
        bail!("CreateStateBlock(D3DSBT_ALL) failed");
    }

    Ok(gpu)
}

impl Drop for Gpu {
    fn drop(&mut self) {
        unsafe {
            release(self.state_block);
            release(self.pixel_shader);
            for surface in self.readback {
                release(surface);
            }
            release(self.and_lut);
            release(self.atlas_surface);
            release(self.atlas_texture);
            release(self.dle_texture);
            release(self.light_texture);
        }
    }
}

/// Uploads a row-major staging array into a dynamic texture.
unsafe fn upload(texture: Ptr, rows: usize, width: usize, source: &[f32]) -> bool {
    let lock: unsafe extern "system" fn(Ptr, u32, *mut LockedRect, Ptr, u32) -> Hr =
        std::mem::transmute(vt(texture, TEXTURE_LOCK_RECT));
    let unlock: unsafe extern "system" fn(Ptr, u32) -> Hr =
        std::mem::transmute(vt(texture, TEXTURE_UNLOCK_RECT));

    let mut rect = LockedRect {
        pitch: 0,
        bits: std::ptr::null_mut(),
    };
    if lock(texture, 0, &mut rect, std::ptr::null_mut(), LOCK_DISCARD) < 0 || rect.bits.is_null() {
        return false;
    }
    for row in 0..rows {
        let destination = (rect.bits as *mut u8).add(row * rect.pitch as usize) as *mut f32;
        let start = row * width * 4;
        let available = source.len().saturating_sub(start).min(width * 4);
        if available > 0 {
            std::ptr::copy_nonoverlapping(source.as_ptr().add(start), destination, available);
        }
    }
    unlock(texture, 0);
    true
}

/// Uploads the staged tables, runs the gather, and copies an earlier result
/// back.
///
/// Bracketed by a `D3DSBT_ALL` state block so UE3's cached RHI state stays true:
/// the device is handed back in exactly the condition the engine believes it
/// left it in. The render target and depth surface are not covered by a state
/// block, so those two are saved and restored by hand.
unsafe fn run_pass(device: Ptr) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }

    let Ok(mut gpu_guard) = GPU.lock() else { return };
    if gpu_guard.as_ref().is_some_and(|gpu| gpu.device != device) {
        *gpu_guard = None;
        ATLAS_INVALID.store(true, Ordering::Release);
    }
    if gpu_guard.is_none() {
        match create_resources(device) {
            Ok(gpu) => {
                *gpu_guard = Some(gpu);
                RESOURCE_STATE.store(1, Ordering::Relaxed);
            }
            Err(error) => {
                debug_log!("-GPULIGHTENV: resource creation failed: {error:#}");
                RESOURCE_STATE.store(2, Ordering::Relaxed);
                if let Ok(mut slot) = RESOURCE_ERROR.lock() {
                    slot.get_or_insert_with(|| format!("{error:#}"));
                }
                return;
            }
        }
    }
    let Some(gpu) = gpu_guard.as_mut() else { return };

    let Ok(mut tables_guard) = TABLES.lock() else { return };
    let Some(tables) = tables_guard.as_mut() else { return };

    // No trustworthy light table means nothing can consume the result, so the
    // pass - and its readback - would be pure cost. Skip it outright.
    if !tables.light_table_valid {
        return;
    }
    let light_count = tables.lights.len().min(MAX_LIGHTS);

    // Both staging arrays are POD laid out one record per row, but the textures
    // want one record per *column* so a whole row is one component of every
    // record. Transpose on the way in; it is a few thousand floats.
    let mut light_rows = vec![0.0f32; LIGHT_TEXELS * MAX_LIGHTS * 4];
    {
        let source = std::slice::from_raw_parts(
            tables.lights.as_ptr() as *const f32,
            tables.lights.len() * LIGHT_TEXELS * 4,
        );
        for light in 0..light_count {
            for texel in 0..LIGHT_TEXELS {
                for component in 0..4 {
                    light_rows[(texel * MAX_LIGHTS + light) * 4 + component] =
                        source[(light * LIGHT_TEXELS + texel) * 4 + component];
                }
            }
        }
    }

    let mut dle_rows = vec![0.0f32; DLE_TEXELS * MAX_SLOTS * 4];
    {
        let source = std::slice::from_raw_parts(
            tables.dles.as_ptr() as *const f32,
            MAX_SLOTS * DLE_TEXELS * 4,
        );
        for slot in 0..MAX_SLOTS {
            for texel in 0..DLE_TEXELS {
                for component in 0..4 {
                    dle_rows[(texel * MAX_SLOTS + slot) * 4 + component] =
                        source[(slot * DLE_TEXELS + texel) * 4 + component];
                }
            }
        }
    }

    if !upload(gpu.light_texture, LIGHT_TEXELS, MAX_LIGHTS, &light_rows)
        || !upload(gpu.dle_texture, DLE_TEXELS, MAX_SLOTS, &dle_rows)
    {
        return;
    }

    let block = gpu.state_block;
    let capture: unsafe extern "system" fn(Ptr) -> Hr =
        std::mem::transmute(vt(block, STATE_BLOCK_CAPTURE));
    let apply: unsafe extern "system" fn(Ptr) -> Hr =
        std::mem::transmute(vt(block, STATE_BLOCK_APPLY));
    capture(block);

    let get_rt: unsafe extern "system" fn(Ptr, u32, *mut Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::GET_RENDER_TARGET));
    let set_rt: unsafe extern "system" fn(Ptr, u32, Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::SET_RENDER_TARGET));
    let get_ds: unsafe extern "system" fn(Ptr, *mut Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::GET_DEPTH_STENCIL_SURFACE));
    let set_ds: unsafe extern "system" fn(Ptr, Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::SET_DEPTH_STENCIL_SURFACE));
    let set_render_state: unsafe extern "system" fn(Ptr, u32, u32) -> Hr =
        std::mem::transmute(vt(device, dev::SET_RENDER_STATE));
    let set_sampler: unsafe extern "system" fn(Ptr, u32, u32, u32) -> Hr =
        std::mem::transmute(vt(device, dev::SET_SAMPLER_STATE));
    let set_texture: unsafe extern "system" fn(Ptr, u32, Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::SET_TEXTURE));
    let set_vertex_shader: unsafe extern "system" fn(Ptr, Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::SET_VERTEX_SHADER));
    let set_pixel_shader: unsafe extern "system" fn(Ptr, Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::SET_PIXEL_SHADER));
    let set_ps_constant: unsafe extern "system" fn(Ptr, u32, *const f32, u32) -> Hr =
        std::mem::transmute(vt(device, dev::SET_PIXEL_SHADER_CONSTANT_F));
    let set_fvf: unsafe extern "system" fn(Ptr, u32) -> Hr =
        std::mem::transmute(vt(device, dev::SET_FVF));
    let set_viewport: unsafe extern "system" fn(Ptr, *const u32) -> Hr =
        std::mem::transmute(vt(device, dev::SET_VIEWPORT));
    let draw_up: unsafe extern "system" fn(Ptr, u32, u32, *const c_void, u32) -> Hr =
        std::mem::transmute(vt(device, dev::DRAW_PRIMITIVE_UP));

    let mut old_rt: Ptr = std::ptr::null_mut();
    let mut old_ds: Ptr = std::ptr::null_mut();
    get_rt(device, 0, &mut old_rt);
    get_ds(device, &mut old_ds);

    set_rt(device, 0, gpu.atlas_surface);
    set_ds(device, std::ptr::null_mut());

    // D3DVIEWPORT9: four DWORDs then MinZ/MaxZ as floats.
    let viewport: [u32; 6] = [
        0,
        0,
        MAX_SLOTS as u32,
        ATLAS_ROWS as u32,
        0.0f32.to_bits(),
        1.0f32.to_bits(),
    ];
    set_viewport(device, viewport.as_ptr());

    set_render_state(device, RS_ZENABLE, 0);
    set_render_state(device, RS_ZWRITEENABLE, 0);
    set_render_state(device, RS_ALPHATESTENABLE, 0);
    set_render_state(device, RS_ALPHABLENDENABLE, 0);
    set_render_state(device, RS_CULLMODE, CULL_NONE);
    set_render_state(device, RS_FOGENABLE, 0);
    set_render_state(device, RS_STENCILENABLE, 0);
    set_render_state(device, RS_SCISSORTESTENABLE, 0);
    set_render_state(device, RS_SRGBWRITEENABLE, 0);
    set_render_state(device, RS_COLORWRITEENABLE, 0xF);

    for sampler in 0..3u32 {
        set_sampler(device, sampler, SAMP_MINFILTER, TEXF_POINT);
        set_sampler(device, sampler, SAMP_MAGFILTER, TEXF_POINT);
        set_sampler(device, sampler, SAMP_MIPFILTER, TEXF_NONE);
        set_sampler(device, sampler, SAMP_ADDRESSU, TADDRESS_CLAMP);
        set_sampler(device, sampler, SAMP_ADDRESSV, TADDRESS_CLAMP);
        set_sampler(device, sampler, SAMP_SRGBTEXTURE, 0);
    }
    set_texture(device, 0, gpu.light_texture);
    set_texture(device, 1, gpu.dle_texture);
    set_texture(device, 2, gpu.and_lut);

    set_vertex_shader(device, std::ptr::null_mut());
    set_fvf(device, FVF_XYZRHW_TEX1);
    set_pixel_shader(device, gpu.pixel_shader);

    let params = [
        light_count as f32,
        MAX_SLOTS as f32,
        MAX_LIGHTS as f32,
        MAX_SLOTS as f32,
    ];
    set_ps_constant(device, 0, params.as_ptr(), 1);

    // The -0.5 offsets are D3D9's pixel-centre rule: they put sample points at
    // exact texel centres, so `floor(uv)` in the shader is the index.
    let width = MAX_SLOTS as f32;
    let height = ATLAS_ROWS as f32;
    let quad = [
        Vertex { x: -0.5, y: -0.5, z: 0.0, rhw: 1.0, u: 0.0, v: 0.0 },
        Vertex { x: width - 0.5, y: -0.5, z: 0.0, rhw: 1.0, u: width, v: 0.0 },
        Vertex { x: -0.5, y: height - 0.5, z: 0.0, rhw: 1.0, u: 0.0, v: height },
        Vertex { x: width - 0.5, y: height - 0.5, z: 0.0, rhw: 1.0, u: width, v: height },
    ];
    draw_up(
        device,
        PT_TRIANGLESTRIP,
        2,
        quad.as_ptr() as *const c_void,
        std::mem::size_of::<Vertex>() as u32,
    );

    let get_render_target_data: unsafe extern "system" fn(Ptr, Ptr, Ptr) -> Hr =
        std::mem::transmute(vt(device, dev::GET_RENDER_TARGET_DATA));
    let write_index = gpu.tick as usize % READBACK_RING;
    get_render_target_data(device, gpu.atlas_surface, gpu.readback[write_index]);

    // Lock the oldest surface in the ring, never the one just written.
    if gpu.tick as usize >= READBACK_RING - 1 {
        let read_index = (gpu.tick as usize + 1) % READBACK_RING;
        let surface = gpu.readback[read_index];
        let lock: unsafe extern "system" fn(Ptr, *mut LockedRect, Ptr, u32) -> Hr =
            std::mem::transmute(vt(surface, SURFACE_LOCK_RECT));
        let unlock: unsafe extern "system" fn(Ptr) -> Hr =
            std::mem::transmute(vt(surface, SURFACE_UNLOCK_RECT));

        let mut rect = LockedRect {
            pitch: 0,
            bits: std::ptr::null_mut(),
        };
        if lock(surface, &mut rect, std::ptr::null_mut(), LOCK_READONLY) >= 0
            && !rect.bits.is_null()
        {
            let destination = tables
                .readback
                .get_or_insert_with(|| vec![0.0f32; MAX_SLOTS * ATLAS_ROWS * 4]);
            for row in 0..ATLAS_ROWS {
                let source = (rect.bits as *const u8).add(row * rect.pitch as usize) as *const f32;
                std::ptr::copy_nonoverlapping(
                    source,
                    destination.as_mut_ptr().add(row * MAX_SLOTS * 4),
                    MAX_SLOTS * 4,
                );
            }
            unlock(surface);
            tables.readback_frame = FRAME_INDEX.load(Ordering::Acquire);
            ATLAS_INVALID.store(false, Ordering::Release);
            READBACK_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
    gpu.tick += 1;
    PASS_COUNT.fetch_add(1, Ordering::Relaxed);

    set_rt(device, 0, old_rt);
    set_ds(device, old_ds);
    release(old_rt);
    release(old_ds);
    apply(block);
}
