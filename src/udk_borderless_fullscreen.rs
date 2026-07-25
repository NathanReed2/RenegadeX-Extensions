//! Adds a true borderless-fullscreen mode to the target UDK build.
//!
//! `-BorderlessFullscreen` selects it at launch. At runtime UnrealScript can
//! use `ConsoleCommand("SETRES <width>x<height>b")`; the existing `f` and `w`
//! suffixes switch back to exclusive fullscreen and windowed mode.
//!
//! The byte patches keep the D3D device/swap chain windowed while UE3 performs
//! its ordinary fullscreen work. That alone is not enough once the requested
//! resolution is smaller than the desktop: `FWindowsViewport::Resize` sizes the
//! fullscreen popup to the *render* resolution
//!
//! ```text
//! if( NewFullscreen ) { WindowPosX = 0; WindowPosY = 0;
//!                       WindowWidth = NewSizeX; WindowHeight = NewSizeY; }
//! ```
//!
//! which is correct only because a real mode switch shrinks the display to
//! match. Borderless never switches modes, so a downscale produced a small
//! undecorated window instead of a stretched fullscreen image. The hooks below
//! restore the missing half of that logic: the window is grown back over the
//! whole monitor, the blit-model swap chain scales the smaller back buffer up to
//! fill it, and the mouse accessors map the larger client area back into
//! viewport space so the cursor and UI hit-testing stay aligned.
//!
//! RVAs were mapped in Ghidra from the symbol-bearing 2013
//! `UDK Build W Simplygon/UDK.exe` to `RenXSDK/UDK.exe`. The target's
//! `.text` hash is pinned in `dll.rs`, and every instruction is validated
//! before any code is changed.

use anyhow::{bail, Context};
#[cfg(target_arch = "x86_64")]
use retour::static_detour;
#[cfg(target_arch = "x86_64")]
use std::cell::Cell;
#[cfg(target_arch = "x86_64")]
use std::ffi::c_void;
#[cfg(target_arch = "x86_64")]
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
#[cfg(target_arch = "x86_64")]
use std::sync::Mutex;

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use windows::Win32::Foundation::{HWND, RECT};
#[cfg(target_arch = "x86_64")]
use windows::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
    MONITOR_DEFAULTTOPRIMARY,
};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache, Threading::GetCurrentProcess,
};
#[cfg(target_arch = "x86_64")]
use windows::Win32::UI::WindowsAndMessaging::{
    GetClientRect, GetWindowRect, SetWindowPos, SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOZORDER,
};

const LAUNCH_OPTION: &str = "-BorderlessFullscreen";

/// A function whose prologue is verified before a detour is written over it.
#[cfg(target_arch = "x86_64")]
struct HookTarget {
    name: &'static str,
    rva: usize,
    prologue: &'static [u8],
}

#[cfg(target_arch = "x86_64")]
const GAME_VIEWPORT_EXEC: HookTarget = HookTarget {
    name: "UGameViewportClient::Exec",
    rva: 0x0086_5080,
    prologue: &[
        0x48, 0x8B, 0xC4, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    ],
};

#[cfg(target_arch = "x86_64")]
const WINDOWS_VIEWPORT_RESIZE: HookTarget = HookTarget {
    name: "FWindowsViewport::Resize",
    rva: 0x0170_7260,
    prologue: &[
        0x40, 0x55, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D,
        0x6C, 0x24, 0xE8, 0x48, 0x81, 0xEC, 0x18, 0x01, 0x00,
    ],
};

#[cfg(target_arch = "x86_64")]
const UPDATE_RENDER_DEVICE: HookTarget = HookTarget {
    name: "FWindowsViewport::UpdateRenderDevice",
    rva: 0x0170_5AF0,
    prologue: &[
        0x40, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83,
        0xEC, 0x68,
    ],
};

#[cfg(target_arch = "x86_64")]
const GET_MOUSE_X: HookTarget = HookTarget {
    name: "FWindowsViewport::GetMouseX",
    rva: 0x0170_4530,
    // GetCursorPos, ScreenToClient(Window, &P), return P.x.
    prologue: &[
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xFF,
        0x15, 0x54, 0xA1, 0xDB, 0x00, 0x48, 0x8B, 0x8B, 0xB4, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x54,
        0x24, 0x30, 0xFF, 0x15, 0xB2, 0xA0, 0xDB, 0x00, 0x8B, 0x44, 0x24, 0x30,
    ],
};

#[cfg(target_arch = "x86_64")]
const GET_MOUSE_Y: HookTarget = HookTarget {
    name: "FWindowsViewport::GetMouseY",
    rva: 0x0170_4560,
    // Identical to GetMouseX except for the returned POINT member.
    prologue: &[
        0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xFF,
        0x15, 0x24, 0xA1, 0xDB, 0x00, 0x48, 0x8B, 0x8B, 0xB4, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x54,
        0x24, 0x30, 0xFF, 0x15, 0x82, 0xA0, 0xDB, 0x00, 0x8B, 0x44, 0x24, 0x34,
    ],
};

#[cfg(target_arch = "x86_64")]
const GET_MOUSE_POS: HookTarget = HookTarget {
    name: "FWindowsViewport::GetMousePos",
    rva: 0x0170_4590,
    prologue: &[
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8D,
        0x4C, 0x24, 0x30, 0x48, 0x8B, 0xFA, 0xFF, 0x15, 0xED, 0xA0, 0xDB, 0x00,
    ],
};

#[cfg(target_arch = "x86_64")]
const SET_MOUSE: HookTarget = HookTarget {
    name: "FWindowsViewport::SetMouse",
    rva: 0x0170_45E0,
    // Stores into PreCaptureMousePos before ClientToScreen/SetCursorPos.
    prologue: &[
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x91, 0x04, 0x05, 0x00,
        0x00, 0x48, 0x8B, 0xF9, 0x44, 0x89, 0x81, 0x08, 0x05, 0x00, 0x00,
    ],
};

#[cfg(target_arch = "x86_64")]
const GET_SUPPORTED_RESOLUTION: HookTarget = HookTarget {
    name: "FD3D11DynamicRHI::GetSupportedResolution",
    rva: 0x0169_A070,
    prologue: &[
        0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xAC,
        0x24, 0x30, 0xFF, 0xFF, 0xFF,
    ],
};

/// `FWindowsViewport` derives from `FViewportFrame` first, so a `Resize` `this`
/// points at the object base while the `FViewport` virtuals receive base + 8.
#[cfg(target_arch = "x86_64")]
const VIEWPORT_FRAME_TO_VIEWPORT: usize = 0x08;
/// `FWindowsViewport::Window`, relative to the object base.
#[cfg(target_arch = "x86_64")]
const VIEWPORT_WINDOW_OFFSET: usize = 0xBC;
/// `FWindowsViewport::ParentWindow`, relative to the object base.
#[cfg(target_arch = "x86_64")]
const VIEWPORT_PARENT_WINDOW_OFFSET: usize = 0xC4;
/// `FRenderTarget::GetSizeX`/`GetSizeY` slots in the `FViewport` vtable.
#[cfg(target_arch = "x86_64")]
const GET_SIZE_X_SLOT: usize = 2;
#[cfg(target_arch = "x86_64")]
const GET_SIZE_Y_SLOT: usize = 3;

#[cfg(target_arch = "x86_64")]
struct CodePatch {
    name: &'static str,
    rva: usize,
    expected: &'static [u8],
    replacement: &'static [u8],
}

#[cfg(target_arch = "x86_64")]
const STARTUP_FULLSCREEN_PATCH: CodePatch = CodePatch {
    name: "borderless launch fullscreen state",
    // UGameEngine::Init: fall through to bFullscreen = TRUE when the
    // ordinary -FULLSCREEN parameter is absent. -WINDOWED still wins.
    rva: 0x0069_AB50,
    expected: &[0x74, 0x13],
    replacement: &[0x90, 0x90],
};

#[cfg(target_arch = "x86_64")]
const BORDERLESS_PATCHES: &[CodePatch] = &[
    CodePatch {
        name: "D3D11 constructor fullscreen state",
        // Store FALSE in FD3D11Viewport::bIsFullscreen.
        rva: 0x016A_E781,
        expected: &[0x8B, 0x45, 0x7F],
        replacement: &[0x31, 0xC0, 0x90],
    },
    CodePatch {
        name: "D3D11 resize fullscreen state",
        // Save FALSE instead of the bInIsFullscreen argument.
        rva: 0x016A_0A30,
        expected: &[0x41, 0x8B, 0xE9],
        replacement: &[0x31, 0xED, 0x90],
    },
    CodePatch {
        name: "D3D9 NewDeviceFullscreen",
        // EAX is already zero; removing SETNZ keeps the device windowed.
        rva: 0x016B_BFB3,
        expected: &[0x0F, 0x95, 0xC0],
        replacement: &[0x90, 0x90, 0x90],
    },
    CodePatch {
        name: "fullscreen SetWindowPos",
        // Remove the NewFullscreen != FALSE early-out in UpdateWindow.
        rva: 0x0170_3E6F,
        expected: &[0x75, 0x46],
        replacement: &[0x90, 0x90],
    },
];

#[cfg(target_arch = "x86_64")]
type GameViewportExec = extern "C" fn(*mut c_void, *const u16, *mut c_void) -> i32;
#[cfg(target_arch = "x86_64")]
type WindowsViewportResize = extern "C" fn(*mut c_void, u32, u32, u32, i32, i32);
#[cfg(target_arch = "x86_64")]
type UpdateRenderDevice = extern "C" fn(*mut c_void, u32, u32, u32, u32);
#[cfg(target_arch = "x86_64")]
type GetMouseAxis = extern "C" fn(*mut c_void) -> i32;
#[cfg(target_arch = "x86_64")]
type GetMousePos = extern "C" fn(*mut c_void, *mut i32);
#[cfg(target_arch = "x86_64")]
type SetMouse = extern "C" fn(*mut c_void, i32, i32);
#[cfg(target_arch = "x86_64")]
type GetSupportedResolution = extern "C" fn(*mut c_void, *mut u32, *mut u32);
/// `FRenderTarget::GetSizeX`/`GetSizeY`.
#[cfg(target_arch = "x86_64")]
type GetViewportSize = extern "C" fn(*mut c_void) -> u32;

#[cfg(target_arch = "x86_64")]
static_detour! {
    static GameViewportExecHook: extern "C" fn(
        *mut c_void,
        *const u16,
        *mut c_void
    ) -> i32;
}

#[cfg(target_arch = "x86_64")]
static_detour! {
    static WindowsViewportResizeHook: extern "C" fn(*mut c_void, u32, u32, u32, i32, i32);
}

#[cfg(target_arch = "x86_64")]
static_detour! {
    static UpdateRenderDeviceHook: extern "C" fn(*mut c_void, u32, u32, u32, u32);
}

#[cfg(target_arch = "x86_64")]
static_detour! {
    static GetMouseXHook: extern "C" fn(*mut c_void) -> i32;
}

#[cfg(target_arch = "x86_64")]
static_detour! {
    static GetMouseYHook: extern "C" fn(*mut c_void) -> i32;
}

#[cfg(target_arch = "x86_64")]
static_detour! {
    static GetMousePosHook: extern "C" fn(*mut c_void, *mut i32);
}

#[cfg(target_arch = "x86_64")]
static_detour! {
    static SetMouseHook: extern "C" fn(*mut c_void, i32, i32);
}

#[cfg(target_arch = "x86_64")]
static_detour! {
    static GetSupportedResolutionHook: extern "C" fn(*mut c_void, *mut u32, *mut u32);
}

#[cfg(target_arch = "x86_64")]
static MODE_CHANGE_LOCK: Mutex<()> = Mutex::new(());

/// TRUE while [`BORDERLESS_PATCHES`] are applied.
#[cfg(target_arch = "x86_64")]
static BORDERLESS_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The window that is currently stretched over a monitor, or 0. Stored last on
/// the way in and cleared first on the way out so a reader that sees a window
/// also sees its matching back-buffer size.
#[cfg(target_arch = "x86_64")]
static STRETCHED_WINDOW: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static STRETCHED_RENDER_X: AtomicU32 = AtomicU32::new(0);
#[cfg(target_arch = "x86_64")]
static STRETCHED_RENDER_Y: AtomicU32 = AtomicU32::new(0);

#[cfg(target_arch = "x86_64")]
thread_local! {
    /// Monitor the viewport occupied when `Resize` was entered. `Resize` moves a
    /// fullscreen window to the virtual-screen origin before `UpdateRenderDevice`
    /// runs, so the nested hook cannot re-derive the user's monitor itself.
    static RESIZE_MONITOR: Cell<Option<RECT>> = const { Cell::new(None) };
}

fn launch_option_present() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|arg| arg.to_string_lossy().eq_ignore_ascii_case(LAUNCH_OPTION))
}

#[cfg(target_arch = "x86_64")]
fn image_address(rva: usize, length: usize, name: &str) -> anyhow::Result<usize> {
    let range = UDK_RANGE.get().context("UDK_RANGE not set")?;
    let address = range
        .start
        .checked_add(rva)
        .with_context(|| format!("{name} address overflow"))?;
    let end = address
        .checked_add(length)
        .with_context(|| format!("{name} end overflow"))?;
    if end > range.end {
        bail!("{name} lies outside UDK.exe");
    }
    Ok(address)
}

#[cfg(target_arch = "x86_64")]
impl HookTarget {
    /// Validates the prologue and returns the address to detour.
    fn resolve(&self) -> anyhow::Result<*const ()> {
        let address = image_address(self.rva, self.prologue.len(), self.name)?;
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

#[cfg(target_arch = "x86_64")]
fn patch_address(patch: &CodePatch) -> anyhow::Result<*mut u8> {
    if patch.expected.len() != patch.replacement.len() {
        bail!("{} changes instruction length", patch.name);
    }
    Ok(image_address(patch.rva, patch.expected.len(), patch.name)? as *mut u8)
}

#[cfg(target_arch = "x86_64")]
fn validate_patch(patch: &CodePatch) -> anyhow::Result<()> {
    let address = patch_address(patch)?;
    let actual = unsafe { std::slice::from_raw_parts(address, patch.expected.len()) };
    if actual != patch.expected && actual != patch.replacement {
        bail!(
            "{} validation failed at RVA 0x{:X}: expected {:02X?} or {:02X?}, found {:02X?}",
            patch.name,
            patch.rva,
            patch.expected,
            patch.replacement,
            actual
        );
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn write_patch(patch: &CodePatch, enabled: bool) -> anyhow::Result<()> {
    let address = patch_address(patch)?;
    let desired = if enabled {
        patch.replacement
    } else {
        patch.expected
    };
    let actual = unsafe { std::slice::from_raw_parts(address, desired.len()) };
    if actual == desired {
        return Ok(());
    }

    unsafe {
        let _guard = region::protect_with_handle(
            address,
            desired.len(),
            region::Protection::READ_WRITE_EXECUTE,
        )
        .with_context(|| format!("failed to make {} writable", patch.name))?;
        std::ptr::copy_nonoverlapping(desired.as_ptr(), address, desired.len());
        FlushInstructionCache(GetCurrentProcess(), Some(address.cast()), desired.len())
            .with_context(|| format!("failed to flush {} instructions", patch.name))?;
    }

    debug_log!(
        "{} {} at UDK.exe+0x{:X}",
        if enabled { "applied" } else { "restored" },
        patch.name,
        patch.rva
    );
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn set_borderless_patches(enabled: bool) -> anyhow::Result<()> {
    // Validate the complete transition before writing its first instruction.
    for patch in BORDERLESS_PATCHES {
        validate_patch(patch)?;
    }
    for patch in BORDERLESS_PATCHES {
        write_patch(patch, enabled)?;
    }

    BORDERLESS_ACTIVE.store(enabled, Ordering::Relaxed);
    if !enabled {
        // The engine owns the window geometry again from here on.
        forget_stretched_window();
    }
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn forget_stretched_window() {
    STRETCHED_WINDOW.store(0, Ordering::Relaxed);
    STRETCHED_RENDER_X.store(0, Ordering::Relaxed);
    STRETCHED_RENDER_Y.store(0, Ordering::Relaxed);
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_window(object: *mut c_void, offset: usize) -> HWND {
    if object.is_null() {
        return HWND(0);
    }
    HWND(*((object as *const u8).add(offset) as *const isize))
}

#[cfg(target_arch = "x86_64")]
unsafe fn call_viewport_size(viewport: *mut c_void, slot: usize) -> u32 {
    let vtable = *(viewport as *const *const *const ());
    let entry: GetViewportSize = std::mem::transmute(*vtable.add(slot));
    entry(viewport)
}

/// Reads `FViewport::SizeX`/`SizeY` back from the object so the recorded
/// back-buffer size reflects whatever the engine actually settled on.
#[cfg(target_arch = "x86_64")]
fn viewport_size(frame: *mut c_void) -> Option<(u32, u32)> {
    if frame.is_null() {
        return None;
    }
    let viewport = unsafe { (frame as *mut u8).add(VIEWPORT_FRAME_TO_VIEWPORT) } as *mut c_void;
    let size_x = unsafe { call_viewport_size(viewport, GET_SIZE_X_SLOT) };
    let size_y = unsafe { call_viewport_size(viewport, GET_SIZE_Y_SLOT) };
    (size_x != 0 && size_y != 0).then_some((size_x, size_y))
}

/// Bounds of the monitor `window` sits on, falling back to the primary monitor.
#[cfg(target_arch = "x86_64")]
fn monitor_bounds(window: HWND) -> Option<RECT> {
    let mut monitor = unsafe { MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST) };
    if monitor.is_invalid() {
        monitor = unsafe { MonitorFromWindow(window, MONITOR_DEFAULTTOPRIMARY) };
    }
    if monitor.is_invalid() {
        return None;
    }

    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    if !unsafe { GetMonitorInfoW(monitor, &mut info) }.as_bool() {
        return None;
    }
    let bounds = info.rcMonitor;
    (bounds.right > bounds.left && bounds.bottom > bounds.top).then_some(bounds)
}

/// `FViewport::ViewportRHI`, relative to the object base. Offsets confirmed from
/// `FViewport::UpdateViewportRHI`, which writes `SizeX` at +0xA4 and `SizeY` at
/// +0xA8 right after it.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
const VIEWPORT_RHI_OFFSET: usize = 0x9C;
/// `FD3D11Viewport` members, matching the layout `udk_flip_model` relies on.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
const D3D11_VIEWPORT_SIZE_X_OFFSET: usize = 0x1C;
#[cfg(all(target_arch = "x86_64", debug_assertions))]
const D3D11_VIEWPORT_SWAP_CHAIN_OFFSET: usize = 0x2C;
#[cfg(all(target_arch = "x86_64", debug_assertions))]
const IDXGI_SWAP_CHAIN_GET_DESC_INDEX: usize = 12;

/// Reports the RHI's own idea of the viewport size and, decisively, the size DXGI
/// thinks the back buffer is. If those disagree with the client area we know
/// whether `Present` is being asked to scale at all.
#[cfg(all(target_arch = "x86_64", debug_assertions))]
fn trace_swap_chain(frame: *mut c_void) {
    // Diagnostic-only pointer walk; compiled out of the release profile.
    #[repr(C)]
    #[derive(Default)]
    struct BufferDesc {
        width: u32,
        height: u32,
        refresh_numerator: u32,
        refresh_denominator: u32,
        format: i32,
        scanline_ordering: i32,
        scaling: i32,
    }
    type GetDesc = extern "system" fn(*mut c_void, *mut u8) -> i32;

    unsafe {
        if frame.is_null() {
            return;
        }
        let rhi_viewport =
            *((frame as *const u8).add(VIEWPORT_RHI_OFFSET) as *const *mut c_void);
        if rhi_viewport.is_null() {
            debug_log!("[borderless]   rhi: ViewportRHI is null");
            return;
        }
        let rhi_size_x =
            *((rhi_viewport as *const u8).add(D3D11_VIEWPORT_SIZE_X_OFFSET) as *const u32);
        let rhi_size_y =
            *((rhi_viewport as *const u8).add(D3D11_VIEWPORT_SIZE_X_OFFSET + 4) as *const u32);
        let swap_chain =
            *((rhi_viewport as *const u8).add(D3D11_VIEWPORT_SWAP_CHAIN_OFFSET)
                as *const *mut c_void);
        if swap_chain.is_null() {
            debug_log!("[borderless]   rhi: FD3D11Viewport={rhi_size_x}x{rhi_size_y} swapchain=null");
            return;
        }

        // DXGI_SWAP_CHAIN_DESC starts with DXGI_MODE_DESC.
        let mut desc = [0u8; 128];
        let vtable = *(swap_chain as *const *const *mut c_void);
        let get_desc: GetDesc = std::mem::transmute(*vtable.add(IDXGI_SWAP_CHAIN_GET_DESC_INDEX));
        let hr = get_desc(swap_chain, desc.as_mut_ptr());
        if hr < 0 {
            debug_log!(
                "[borderless]   rhi: FD3D11Viewport={rhi_size_x}x{rhi_size_y} GetDesc failed {hr:#010X}"
            );
            return;
        }
        let buffer = &*(desc.as_ptr() as *const BufferDesc);
        // Offsets after DXGI_MODE_DESC (28) + DXGI_SAMPLE_DESC (8) + usage/count (8).
        let windowed = *(desc.as_ptr().add(48) as *const i32);
        let swap_effect = *(desc.as_ptr().add(52) as *const i32);
        debug_log!(
            "[borderless]   rhi: FD3D11Viewport={rhi_size_x}x{rhi_size_y} backbuffer={}x{} scaling={} windowed={windowed} swap_effect={swap_effect}",
            buffer.width,
            buffer.height,
            buffer.scaling
        );
    }
}

#[cfg(all(target_arch = "x86_64", not(debug_assertions)))]
fn trace_swap_chain(_frame: *mut c_void) {}

/// Dumps the window/client/viewport geometry at a point of interest. The release
/// profile compiles `debug_log!` away entirely; build the dev profile to get a
/// `renxhook.log` next to UDK.exe.
#[cfg(target_arch = "x86_64")]
fn trace_geometry(tag: &str, frame: *mut c_void) {
    let window = unsafe { read_window(frame, VIEWPORT_WINDOW_OFFSET) };
    let mut window_rect = RECT::default();
    let mut client_rect = RECT::default();
    let has_window = window.0 != 0 && unsafe { GetWindowRect(window, &mut window_rect) }.is_ok();
    if has_window {
        let _ = unsafe { GetClientRect(window, &mut client_rect) };
    }
    let (view_x, view_y) = viewport_size(frame).unwrap_or((0, 0));
    debug_log!(
        "[borderless] {tag}: hwnd={:#X} window=({},{})-({},{}) client={}x{} FViewport={}x{} recorded={}x{} active={}",
        window.0,
        window_rect.left,
        window_rect.top,
        window_rect.right,
        window_rect.bottom,
        client_rect.right - client_rect.left,
        client_rect.bottom - client_rect.top,
        view_x,
        view_y,
        STRETCHED_RENDER_X.load(Ordering::Relaxed),
        STRETCHED_RENDER_Y.load(Ordering::Relaxed),
        BORDERLESS_ACTIVE.load(Ordering::Relaxed)
    );
    trace_swap_chain(frame);
}

/// Grows the borderless popup back over `bounds`. UE3 sized it to the render
/// resolution because a real fullscreen switch would have shrunk the display to
/// match; the swap chain stays at that resolution and DXGI's blit-model
/// `Present` scales it up to the client area.
#[cfg(target_arch = "x86_64")]
fn stretch_window(window: HWND, bounds: RECT) -> bool {
    let width = bounds.right - bounds.left;
    let height = bounds.bottom - bounds.top;

    let mut current = RECT::default();
    if unsafe { GetWindowRect(window, &mut current) }.is_ok()
        && current.left == bounds.left
        && current.top == bounds.top
        && current.right == bounds.right
        && current.bottom == bounds.bottom
    {
        return true;
    }

    // WM_SIZE lands in FWindowsViewport::HandlePossibleSizeChange, which bails
    // out while FViewport::bIsFullscreen is set - and it still is, because only
    // the RHI-level flag was patched to FALSE. So this cannot bounce back into
    // Resize with the enlarged client size.
    let result = unsafe {
        SetWindowPos(
            window,
            None,
            bounds.left,
            bounds.top,
            width,
            height,
            SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        )
    };
    if let Err(error) = result {
        debug_log!("failed to stretch borderless window: {error}");
        return false;
    }
    true
}

/// Client and back-buffer extents when `window` is the stretched borderless
/// window and the two differ, i.e. when coordinates need rescaling.
#[cfg(target_arch = "x86_64")]
fn stretch_extents(window: HWND) -> Option<(u32, u32, u32, u32)> {
    let stretched = STRETCHED_WINDOW.load(Ordering::Relaxed);
    if stretched == 0 || stretched != window.0 as usize {
        return None;
    }
    let render_x = STRETCHED_RENDER_X.load(Ordering::Relaxed);
    let render_y = STRETCHED_RENDER_Y.load(Ordering::Relaxed);
    if render_x == 0 || render_y == 0 {
        return None;
    }

    let mut client = RECT::default();
    if unsafe { GetClientRect(window, &mut client) }.is_err() {
        return None;
    }
    let client_x = u32::try_from(client.right - client.left).ok()?;
    let client_y = u32::try_from(client.bottom - client.top).ok()?;
    if client_x == 0 || client_y == 0 || (client_x == render_x && client_y == render_y) {
        return None;
    }
    Some((client_x, client_y, render_x, render_y))
}

/// Maps `value` from a `from`-wide span onto a `to`-wide one, rounding towards
/// negative infinity so coordinates outside the client area keep their sign.
/// UE3 treats a negative mouse position as "outside the viewport".
#[cfg(target_arch = "x86_64")]
fn scale_coordinate(value: i32, from: u32, to: u32) -> i32 {
    if from == 0 {
        return value;
    }
    let numerator = i64::from(value) * i64::from(to);
    let denominator = i64::from(from);
    let mut scaled = numerator / denominator;
    if numerator < 0 && numerator % denominator != 0 {
        scaled -= 1;
    }
    scaled.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_wide_command(command: *const u16) -> Option<Vec<u16>> {
    const MAX_COMMAND_UNITS: usize = 4096;
    if command.is_null() {
        return None;
    }

    let mut units = Vec::new();
    for index in 0..MAX_COMMAND_UNITS {
        let unit = command.add(index).read();
        if unit == 0 {
            return Some(units);
        }
        units.push(unit);
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn ascii_eq_ignore_case(unit: u16, ascii: u8) -> bool {
    unit <= u8::MAX as u16 && (unit as u8).eq_ignore_ascii_case(&ascii)
}

#[cfg(target_arch = "x86_64")]
fn is_ascii_whitespace(unit: u16) -> bool {
    unit == b' ' as u16 || unit == b'\t' as u16 || unit == b'\r' as u16 || unit == b'\n' as u16
}

#[cfg(target_arch = "x86_64")]
fn is_ascii_digit(unit: u16) -> bool {
    (b'0' as u16..=b'9' as u16).contains(&unit)
}

/// Returns the UTF-16 index and lower-case mode suffix for a SETRES command.
#[cfg(target_arch = "x86_64")]
fn setres_mode(command: &[u16]) -> Option<(usize, u8)> {
    const SETRES: &[u8] = b"SETRES";
    let mut index = command
        .iter()
        .position(|unit| !is_ascii_whitespace(*unit))?;

    for expected in SETRES {
        let unit = *command.get(index)?;
        if !ascii_eq_ignore_case(unit, *expected) {
            return None;
        }
        index += 1;
    }
    if !is_ascii_whitespace(*command.get(index)?) {
        return None;
    }
    while command
        .get(index)
        .is_some_and(|unit| is_ascii_whitespace(*unit))
    {
        index += 1;
    }

    let width_start = index;
    while command.get(index).is_some_and(|unit| is_ascii_digit(*unit)) {
        index += 1;
    }
    if index == width_start
        || !matches!(command.get(index), Some(unit) if *unit == b'x' as u16 || *unit == b'X' as u16)
    {
        return None;
    }
    index += 1;

    let height_start = index;
    while command.get(index).is_some_and(|unit| is_ascii_digit(*unit)) {
        index += 1;
    }
    if index == height_start {
        return None;
    }

    let mode_index = index;
    let mode = *command.get(index)?;
    let mode = if ascii_eq_ignore_case(mode, b'b') {
        b'b'
    } else if ascii_eq_ignore_case(mode, b'f') {
        b'f'
    } else if ascii_eq_ignore_case(mode, b'w') {
        b'w'
    } else {
        return None;
    };
    index += 1;
    if command[index..]
        .iter()
        .any(|unit| !is_ascii_whitespace(*unit))
    {
        return None;
    }
    Some((mode_index, mode))
}

#[cfg(target_arch = "x86_64")]
extern "C" fn game_viewport_exec_hook(
    viewport_client: *mut c_void,
    command: *const u16,
    output_device: *mut c_void,
) -> i32 {
    let Some(mut command_units) = (unsafe { read_wide_command(command) }) else {
        return GameViewportExecHook.call(viewport_client, command, output_device);
    };
    let Some((mode_index, mode)) = setres_mode(&command_units) else {
        return GameViewportExecHook.call(viewport_client, command, output_device);
    };

    let _mode_guard = MODE_CHANGE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let borderless = mode == b'b';
    if let Err(error) = set_borderless_patches(borderless) {
        debug_log!("failed to switch SETRES mode '{}': {error:#}", mode as char);
        return GameViewportExecHook.call(viewport_client, command, output_device);
    }

    debug_log!(
        "SETRES mode '{}' selected",
        if borderless { 'b' } else { mode as char }
    );

    if borderless {
        // UE3 already knows how to perform all logical fullscreen work. Feed
        // it `f`, while the active native patches keep the swap chain/device
        // windowed and `windows_viewport_resize_hook` covers the one piece of
        // fullscreen geometry that assumed a display mode switch.
        command_units[mode_index] = b'f' as u16;
        command_units.push(0);
        GameViewportExecHook.call(viewport_client, command_units.as_ptr(), output_device)
    } else {
        GameViewportExecHook.call(viewport_client, command, output_device)
    }
}

/// TRUE when this resize should end with a window covering a whole monitor.
/// A ParentWindow makes UE3 force NewFullscreen to FALSE (editor previews).
#[cfg(target_arch = "x86_64")]
fn wants_borderless_stretch(frame: *mut c_void, new_fullscreen: u32) -> bool {
    BORDERLESS_ACTIVE.load(Ordering::Relaxed)
        && new_fullscreen != 0
        && unsafe { read_window(frame, VIEWPORT_PARENT_WINDOW_OFFSET) }.0 == 0
}

/// Grows the viewport window over its monitor and records the back-buffer size
/// the enlarged client area now presents.
#[cfg(target_arch = "x86_64")]
fn apply_borderless_stretch(frame: *mut c_void, render_x: u32, render_y: u32) -> bool {
    let window = unsafe { read_window(frame, VIEWPORT_WINDOW_OFFSET) };
    if window.0 == 0 {
        return false;
    }
    let Some(bounds) = RESIZE_MONITOR
        .get()
        .or_else(|| monitor_bounds(window))
    else {
        debug_log!("borderless stretch skipped: no monitor bounds for the viewport window");
        return false;
    };
    if !stretch_window(window, bounds) {
        return false;
    }

    STRETCHED_RENDER_X.store(render_x, Ordering::Relaxed);
    STRETCHED_RENDER_Y.store(render_y, Ordering::Relaxed);
    STRETCHED_WINDOW.store(window.0 as usize, Ordering::Relaxed);
    debug_log!(
        "borderless window stretched to {}x{} at ({},{}) presenting a {}x{} back buffer",
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        bounds.left,
        bounds.top,
        render_x,
        render_y
    );
    true
}

/// Restores the half of UE3's fullscreen path that a borderless mode removes:
/// the window has to cover the monitor even when the render resolution is
/// smaller, because no display mode switch shrinks the desktop to match.
///
/// This is the outer bracket. It records which monitor the user was on before
/// the fullscreen path slams the window to the virtual-screen origin, and
/// re-asserts the geometry afterwards because the window-creation path finishes
/// with `appShowGameWindow`/`ShowWindow` calls that run after
/// `UpdateRenderDevice`. The stretch that actually matters happens inside
/// [`update_render_device_hook`].
#[cfg(target_arch = "x86_64")]
extern "C" fn windows_viewport_resize_hook(
    frame: *mut c_void,
    new_size_x: u32,
    new_size_y: u32,
    new_fullscreen: u32,
    position_x: i32,
    position_y: i32,
) {
    let borderless = wants_borderless_stretch(frame, new_fullscreen);
    debug_log!(
        "[borderless] Resize({new_size_x}x{new_size_y}, fullscreen={new_fullscreen}, pos=({position_x},{position_y})) borderless={borderless}"
    );
    trace_geometry("Resize enter", frame);

    let monitor = if borderless {
        let window = unsafe { read_window(frame, VIEWPORT_WINDOW_OFFSET) };
        (window.0 != 0).then(|| monitor_bounds(window)).flatten()
    } else {
        None
    };
    let previous_monitor = RESIZE_MONITOR.replace(monitor);

    // Whatever we recorded describes the geometry that is about to change, and
    // this is the only path back out of a stretched window (Alt-Enter resizes
    // without going through SETRES). Re-record it only on success below.
    forget_stretched_window();

    WindowsViewportResizeHook.call(
        frame,
        new_size_x,
        new_size_y,
        new_fullscreen,
        position_x,
        position_y,
    );

    trace_geometry("Resize after original", frame);
    if borderless {
        // Re-read the size: UpdateRenderDevice may have clamped it.
        let (render_x, render_y) = viewport_size(frame).unwrap_or((new_size_x, new_size_y));
        apply_borderless_stretch(frame, render_x, render_y);
        trace_geometry("Resize exit", frame);
    }
    RESIZE_MONITOR.set(previous_monitor);
}

/// Sizes the window before the swap chain is created or resized.
///
/// This ordering is the whole fix. `UpdateRenderDevice` is what ends up calling
/// `FD3D11Viewport`'s constructor or `Resize`, i.e. `CreateSwapChain` /
/// `ResizeBuffers`. DXGI establishes the blit-model scaling from the client area
/// as it stands at that moment, so enlarging the window afterwards left the back
/// buffer presenting 1:1 into the top-left corner instead of being scaled up.
/// Growing the window first means the swap chain is sized against a client area
/// that already covers the monitor, and `Present` stretches the smaller back
/// buffer to fill it - the same image a real fullscreen mode switch produces.
#[cfg(target_arch = "x86_64")]
extern "C" fn update_render_device_hook(
    frame: *mut c_void,
    new_size_x: u32,
    new_size_y: u32,
    new_fullscreen: u32,
    save_resolution_settings: u32,
) {
    let borderless = wants_borderless_stretch(frame, new_fullscreen);
    debug_log!(
        "[borderless] UpdateRenderDevice({new_size_x}x{new_size_y}, fullscreen={new_fullscreen}, save={save_resolution_settings}) borderless={borderless}"
    );
    if borderless {
        apply_borderless_stretch(frame, new_size_x, new_size_y);
        trace_geometry("UpdateRenderDevice after stretch", frame);
    }
    UpdateRenderDeviceHook.call(
        frame,
        new_size_x,
        new_size_y,
        new_fullscreen,
        save_resolution_settings,
    );
    trace_geometry("UpdateRenderDevice exit", frame);
}

/// `this` for the `FViewport` virtuals; the window lives before the vtable-owner
/// adjustment, so undo it to reach `FWindowsViewport::Window`.
#[cfg(target_arch = "x86_64")]
fn viewport_window(viewport: *mut c_void) -> HWND {
    unsafe {
        read_window(
            viewport,
            VIEWPORT_WINDOW_OFFSET - VIEWPORT_FRAME_TO_VIEWPORT,
        )
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn get_mouse_x_hook(viewport: *mut c_void) -> i32 {
    let value = GetMouseXHook.call(viewport);
    match stretch_extents(viewport_window(viewport)) {
        Some((client_x, _, render_x, _)) => scale_coordinate(value, client_x, render_x),
        None => value,
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn get_mouse_y_hook(viewport: *mut c_void) -> i32 {
    let value = GetMouseYHook.call(viewport);
    match stretch_extents(viewport_window(viewport)) {
        Some((_, client_y, _, render_y)) => scale_coordinate(value, client_y, render_y),
        None => value,
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn get_mouse_pos_hook(viewport: *mut c_void, position: *mut i32) {
    GetMousePosHook.call(viewport, position);
    if position.is_null() {
        return;
    }
    let Some((client_x, client_y, render_x, render_y)) =
        stretch_extents(viewport_window(viewport))
    else {
        return;
    };
    unsafe {
        // FIntPoint { INT X, Y }.
        position.write(scale_coordinate(position.read(), client_x, render_x));
        let y = position.add(1);
        y.write(scale_coordinate(y.read(), client_y, render_y));
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn set_mouse_hook(viewport: *mut c_void, x: i32, y: i32) {
    let (x, y) = match stretch_extents(viewport_window(viewport)) {
        // Callers warp the cursor in viewport space; ClientToScreen inside
        // SetMouse expects client space.
        Some((client_x, client_y, render_x, render_y)) => (
            scale_coordinate(x, render_x, client_x),
            scale_coordinate(y, render_y, client_y),
        ),
        None => (x, y),
    };
    SetMouseHook.call(viewport, x, y);
}

/// Borderless never switches display modes, so the requested size does not have
/// to be an enumerated one. Snapping it would silently turn a downscale such as
/// `SETRES 1600x900b` into whichever mode the adapter happens to advertise.
#[cfg(target_arch = "x86_64")]
extern "C" fn get_supported_resolution_hook(
    rhi: *mut c_void,
    width: *mut u32,
    height: *mut u32,
) {
    if BORDERLESS_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    GetSupportedResolutionHook.call(rhi, width, height);
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_borderless_fullscreen::init start");

    #[cfg(target_arch = "x86_64")]
    {
        // Validate every instruction this module touches before installing the
        // first detour, so an unexpected binary leaves the process untouched.
        let exec_address = GAME_VIEWPORT_EXEC.resolve()?;
        let resize_address = WINDOWS_VIEWPORT_RESIZE.resolve()?;
        let update_render_device_address = UPDATE_RENDER_DEVICE.resolve()?;
        let get_mouse_x_address = GET_MOUSE_X.resolve()?;
        let get_mouse_y_address = GET_MOUSE_Y.resolve()?;
        let get_mouse_pos_address = GET_MOUSE_POS.resolve()?;
        let set_mouse_address = SET_MOUSE.resolve()?;
        let supported_resolution_address = GET_SUPPORTED_RESOLUTION.resolve()?;
        validate_patch(&STARTUP_FULLSCREEN_PATCH)?;
        for patch in BORDERLESS_PATCHES {
            validate_patch(patch)?;
        }

        let launch_borderless = launch_option_present();

        unsafe {
            let exec: GameViewportExec = std::mem::transmute(exec_address);
            GameViewportExecHook
                .initialize(exec, |viewport_client, command, output_device| {
                    game_viewport_exec_hook(viewport_client, command, output_device)
                })
                .context("failed to set up UGameViewportClient::Exec hook")?;

            let resize: WindowsViewportResize = std::mem::transmute(resize_address);
            WindowsViewportResizeHook
                .initialize(
                    resize,
                    |frame, size_x, size_y, fullscreen, position_x, position_y| {
                        windows_viewport_resize_hook(
                            frame, size_x, size_y, fullscreen, position_x, position_y,
                        )
                    },
                )
                .context("failed to set up FWindowsViewport::Resize hook")?;

            let update_render_device: UpdateRenderDevice =
                std::mem::transmute(update_render_device_address);
            UpdateRenderDeviceHook
                .initialize(
                    update_render_device,
                    |frame, size_x, size_y, fullscreen, save_settings| {
                        update_render_device_hook(
                            frame,
                            size_x,
                            size_y,
                            fullscreen,
                            save_settings,
                        )
                    },
                )
                .context("failed to set up FWindowsViewport::UpdateRenderDevice hook")?;

            let get_mouse_x: GetMouseAxis = std::mem::transmute(get_mouse_x_address);
            GetMouseXHook
                .initialize(get_mouse_x, |viewport| get_mouse_x_hook(viewport))
                .context("failed to set up FWindowsViewport::GetMouseX hook")?;
            let get_mouse_y: GetMouseAxis = std::mem::transmute(get_mouse_y_address);
            GetMouseYHook
                .initialize(get_mouse_y, |viewport| get_mouse_y_hook(viewport))
                .context("failed to set up FWindowsViewport::GetMouseY hook")?;
            let get_mouse_pos: GetMousePos = std::mem::transmute(get_mouse_pos_address);
            GetMousePosHook
                .initialize(get_mouse_pos, |viewport, position| {
                    get_mouse_pos_hook(viewport, position)
                })
                .context("failed to set up FWindowsViewport::GetMousePos hook")?;
            let set_mouse: SetMouse = std::mem::transmute(set_mouse_address);
            SetMouseHook
                .initialize(set_mouse, |viewport, x, y| set_mouse_hook(viewport, x, y))
                .context("failed to set up FWindowsViewport::SetMouse hook")?;

            let supported_resolution: GetSupportedResolution =
                std::mem::transmute(supported_resolution_address);
            GetSupportedResolutionHook
                .initialize(supported_resolution, |rhi, width, height| {
                    get_supported_resolution_hook(rhi, width, height)
                })
                .context("failed to set up FD3D11DynamicRHI::GetSupportedResolution hook")?;

            GameViewportExecHook
                .enable()
                .context("failed to enable UGameViewportClient::Exec hook")?;
            WindowsViewportResizeHook
                .enable()
                .context("failed to enable FWindowsViewport::Resize hook")?;
            UpdateRenderDeviceHook
                .enable()
                .context("failed to enable FWindowsViewport::UpdateRenderDevice hook")?;
            GetMouseXHook
                .enable()
                .context("failed to enable FWindowsViewport::GetMouseX hook")?;
            GetMouseYHook
                .enable()
                .context("failed to enable FWindowsViewport::GetMouseY hook")?;
            GetMousePosHook
                .enable()
                .context("failed to enable FWindowsViewport::GetMousePos hook")?;
            SetMouseHook
                .enable()
                .context("failed to enable FWindowsViewport::SetMouse hook")?;
            GetSupportedResolutionHook
                .enable()
                .context("failed to enable FD3D11DynamicRHI::GetSupportedResolution hook")?;
        }
        debug_log!("borderless fullscreen hooks enabled");

        if launch_borderless {
            write_patch(&STARTUP_FULLSCREEN_PATCH, true)?;
            set_borderless_patches(true)?;
            debug_log!("borderless fullscreen selected at launch by {LAUNCH_OPTION}");
        } else {
            debug_log!("normal launch mode (use {LAUNCH_OPTION} or SETRES <width>x<height>b)");
        }
    }

    debug_log!("udk_borderless_fullscreen::init done");
    Ok(())
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{scale_coordinate, setres_mode};

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn parses_setres_modes() {
        assert_eq!(setres_mode(&wide("SETRES 1920x1080b")), Some((16, b'b')));
        assert_eq!(setres_mode(&wide(" setres\t1280X720F ")), Some((16, b'f')));
        assert_eq!(setres_mode(&wide("SETRES 800x600w")), Some((14, b'w')));
    }

    #[test]
    fn rejects_non_setres_and_malformed_modes() {
        assert_eq!(setres_mode(&wide("SOMETHING 1920x1080b")), None);
        assert_eq!(setres_mode(&wide("SETRES 1920x1080")), None);
        assert_eq!(setres_mode(&wide("SETRES 1920x1080b extra")), None);
    }

    #[test]
    fn maps_a_stretched_client_area_into_viewport_space() {
        // 1280x720 back buffer stretched over a 1920x1080 monitor.
        assert_eq!(scale_coordinate(0, 1920, 1280), 0);
        assert_eq!(scale_coordinate(1919, 1920, 1280), 1279);
        assert_eq!(scale_coordinate(960, 1920, 1280), 640);
        assert_eq!(scale_coordinate(1079, 1080, 720), 719);
        // And back again for cursor warps.
        assert_eq!(scale_coordinate(640, 1280, 1920), 960);
    }

    #[test]
    fn keeps_positions_outside_the_client_area_negative() {
        // UE3 reads a negative mouse position as "outside the viewport", so
        // truncation towards zero would report the cursor as inside.
        assert_eq!(scale_coordinate(-1, 1920, 1280), -1);
        assert_eq!(scale_coordinate(-3, 1920, 1280), -2);
        assert_eq!(scale_coordinate(-1920, 1920, 1280), -1280);
    }

    #[test]
    fn passes_coordinates_through_without_a_span() {
        assert_eq!(scale_coordinate(42, 0, 1280), 42);
    }
}
