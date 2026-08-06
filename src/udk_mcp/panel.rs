//! The in-editor control panel for the MCP bridge - its capability policy and
//! its server lifecycle - and the Tools menu that reaches it.
//!
//! # What is on the menu
//!
//! `Tools > RenX MCP` holds everything: the control panel, a status report, and
//! Start / Stop / Restart for the server. Start and Stop grey themselves out
//! according to what the server is actually doing, so the menu shows its state
//! before anything is clicked. The same three actions are on the panel, routed
//! through the same functions so the two surfaces cannot disagree.
//!
//! It hangs off Tools rather than sitting on the menu bar because the bar is the
//! editor's, and a tenth top-level menu next to Help reads as part of UnrealEd
//! rather than as something injected. Tools is found by label, never by index -
//! see [`find_tools_menu`].
//!
//! # Why this is a tool window and not a browser tab
//!
//! UnrealEd's docked tabs are wxWidgets, and the shipped binary owner-draws
//! them - `SysTabControl32` does not appear in UDK.exe at all, so there is no
//! native tab control to insert an item into. A real page means constructing a
//! `WxBrowser`-derived C++ object whose vtable, event table and RTTI match the
//! exact wxWidgets build and MSVC ABI that UDK.exe 12791 was compiled with. We
//! have the 2013 source, not the 2015 build configuration, and a mismatch there
//! is a crash rather than a cosmetic fault. That is not a safe thing to do from
//! an injected DLL.
//!
//! What *is* safe is the part of the editor's UI that is still plain Win32.
//! `wxMenuBar` on Windows is backed by a real `HMENU`, and every `wxWindow` owns
//! a real `HWND`, so:
//!
//! - the menu item is a genuine `AppendMenuW` on the editor's own menu bar, and
//! - the panel is an owned pop-up, so it floats above the editor, minimises with
//!   it, and never steals its taskbar entry.
//!
//! Neither touches a wx object, so neither can be broken by a wx version we did
//! not compile against.
//!
//! # Threading
//!
//! Everything here runs on the editor thread, driven from the
//! `UUnrealEdEngine::Tick` detour the bridge already owns. That matters twice
//! over: a window must be created on the thread whose message loop will pump it,
//! and the menu bar must not be edited underneath wx while it is drawing.
//!
//! # Self-healing
//!
//! wx rebuilds the menu bar on some editor transitions, which silently drops a
//! foreign item. Rather than hook every such path, [`tick`] re-checks cheaply
//! and re-adds the item when it has gone missing.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, Ordering};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, SIZE, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontIndirectW, DrawTextW, GetDC, GetStockObject, GetSysColor, GetSysColorBrush,
    GetTextExtentPoint32W, InvalidateRect, ReleaseDC, SelectObject, SetBkMode, SetTextColor,
    COLOR_WINDOW, COLOR_WINDOWTEXT, DEFAULT_GUI_FONT, DT_CALCRECT, DT_LEFT, DT_WORDBREAK, HDC,
    HFONT, HGDIOBJ, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetKeyState, VK_CONTROL, VK_MENU,
};
use windows::Win32::UI::WindowsAndMessaging::*;

use super::policy::{self, Capability, ALL, ALL_MODES};
use crate::patch_utils::debug_log;

/// Command ids for our menu items. wx allocates its own ids from a low range and
/// from negatives, so values up near the top of the `WM_COMMAND` menu space are
/// the least likely to collide with ones the editor already uses.
const MENU_PANEL_ID: usize = 0x7F31;
const MENU_STATUS_ID: usize = 0x7F32;
const MENU_START_ID: usize = 0x7F33;
const MENU_STOP_ID: usize = 0x7F34;
const MENU_RESTART_ID: usize = 0x7F35;

/// Child control ids. Modes occupy `[MODE_BASE, MODE_BASE + ALL_MODES.len())`
/// and capabilities `[CAP_BASE, CAP_BASE + ALL.len())`, so a `WM_COMMAND` maps
/// back to its subject by subtraction.
const MODE_BASE: usize = 0x1000;
const CAP_BASE: usize = 0x2000;
/// The server section's own controls, above both ranges.
const SERVER_STATUS_TEXT: usize = 0x3000;
const SERVER_START_BUTTON: usize = 0x3001;
const SERVER_STOP_BUTTON: usize = 0x3002;
const SERVER_RESTART_BUTTON: usize = 0x3003;
const SERVER_DETAILS_BUTTON: usize = 0x3004;

const MARGIN: i32 = 14;
const ROW_HEIGHT: i32 = 22;
const BUTTON_HEIGHT: i32 = 26;
const BUTTON_WIDTH: i32 = 104;
/// Rows other than the headings sit one step in from the edge.
const INDENT: i32 = 8;

/// The panel measures its own text rather than assuming a width. These bound the
/// result: below the minimum it looks broken, and past the maximum a single long
/// capability description would drag the window across the editor it floats over.
/// Anything that does not fit inside the maximum wraps onto a second line, which
/// is why no label can be clipped at any font size or DPI.
const MIN_CONTENT_WIDTH: i32 = 420;
const MAX_CONTENT_WIDTH: i32 = 680;

static PANEL_HWND: AtomicIsize = AtomicIsize::new(0);
static EDITOR_FRAME: AtomicIsize = AtomicIsize::new(0);
static ORIGINAL_WNDPROC: AtomicIsize = AtomicIsize::new(0);
static MESSAGE_HOOK: AtomicIsize = AtomicIsize::new(0);
/// Where the last row ended, recorded by [`build_children`] so the window can be
/// sized around content whose height is only known once it has been laid out.
static CONTENT_BOTTOM: AtomicI32 = AtomicI32::new(0);
static PANEL_FONT: AtomicIsize = AtomicIsize::new(0);
static CLASS_REGISTERED: AtomicBool = AtomicBool::new(false);
static MENU_ADDED: AtomicBool = AtomicBool::new(false);
/// Our popup under Tools, so `WM_INITMENUPOPUP` can tell it apart from the
/// editor's own menus before touching any item state.
static SUBMENU: AtomicIsize = AtomicIsize::new(0);

fn hinstance() -> HINSTANCE {
    unsafe { GetModuleHandleW(None) }
        .map(HINSTANCE::from)
        .unwrap_or_default()
}

/// Picks the editor's main frame out of this thread's top-level windows.
///
/// `GetActiveWindow` is unreliable here - during a tick the active window may be
/// a viewport, a floating browser, or nothing at all - so the frame is chosen as
/// the largest visible top-level window with no owner, which is what a main
/// frame is and what none of the tool windows are.
fn find_editor_frame() -> Option<HWND> {
    let cached = EDITOR_FRAME.load(Ordering::Relaxed);
    if cached != 0 {
        let hwnd = HWND(cached);
        if unsafe { IsWindow(hwnd) }.as_bool() {
            return Some(hwnd);
        }
        EDITOR_FRAME.store(0, Ordering::Relaxed);
    }

    struct Search {
        best: HWND,
        area: i64,
    }
    let mut search = Search {
        best: HWND(0),
        area: 0,
    };

    unsafe extern "system" fn visit(hwnd: HWND, param: LPARAM) -> windows::Win32::Foundation::BOOL {
        let search = &mut *(param.0 as *mut Search);
        if !IsWindowVisible(hwnd).as_bool() || GetWindow(hwnd, GW_OWNER).0 != 0 {
            return true.into();
        }
        let mut rect = RECT::default();
        if GetWindowRect(hwnd, &mut rect).is_err() {
            return true.into();
        }
        let area = (rect.right - rect.left) as i64 * (rect.bottom - rect.top) as i64;
        if area > search.area {
            search.area = area;
            search.best = hwnd;
        }
        true.into()
    }

    unsafe {
        let _ = EnumThreadWindows(
            windows::Win32::System::Threading::GetCurrentThreadId(),
            Some(visit),
            LPARAM(&mut search as *mut Search as isize),
        );
    }

    (search.best.0 != 0).then(|| {
        EDITOR_FRAME.store(search.best.0, Ordering::Relaxed);
        search.best
    })
}

/// Called every editor tick. Cheap when there is nothing to do.
pub fn tick() {
    if MENU_ADDED.load(Ordering::Relaxed) && menu_item_present() {
        return;
    }
    install_menu_item();
}

fn menu_item_present() -> bool {
    let Some(frame) = find_editor_frame() else {
        return false;
    };
    let menu = unsafe { GetMenu(frame) };
    if menu.0 == 0 {
        return false;
    }
    // `MF_BYCOMMAND` searches submenus as well as the bar, so this still finds
    // the item now that it lives under Tools rather than on the bar itself.
    unsafe { GetMenuState(menu, MENU_PANEL_ID as u32, MF_BYCOMMAND) != u32::MAX }
}

fn menu_item_text(menu: HMENU, position: i32) -> String {
    let mut buffer = [0u16; 128];
    let length =
        unsafe { GetMenuStringW(menu, position as u32, Some(&mut buffer), MF_BYPOSITION) };
    if length <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..length as usize])
}

/// Finds the editor's Tools menu so our commands sit where the rest of the
/// editor's tooling does.
///
/// Matched by label rather than by position, because the menu bar's layout is
/// the editor's business and an index would silently point at Preferences the
/// first time a menu is added. The `&` accelerator marker and any keyboard
/// shortcut after the tab are stripped before comparing.
fn find_tools_menu(bar: HMENU) -> Option<HMENU> {
    let count = unsafe { GetMenuItemCount(bar) };
    for position in 0..count {
        let label = menu_item_text(bar, position);
        let normalized = label
            .split('\t')
            .next()
            .unwrap_or_default()
            .replace('&', "")
            .trim()
            .to_ascii_lowercase();
        if normalized == "tools" {
            let submenu = unsafe { GetSubMenu(bar, position) };
            if submenu.0 != 0 {
                return Some(submenu);
            }
        }
    }
    None
}

/// Builds the "RenX MCP" popup and hangs it off Tools, then subclasses the frame
/// so its `WM_COMMAND` reaches us.
///
/// The subclass chains to wx's original procedure for everything else. Only our
/// own ids are consumed; wx never sees an id it did not allocate, and every other
/// message is passed through untouched.
fn install_menu_item() {
    let Some(frame) = find_editor_frame() else {
        return;
    };
    let bar = unsafe { GetMenu(frame) };
    if bar.0 == 0 {
        return;
    }

    let submenu = unsafe { CreatePopupMenu() }.unwrap_or_default();
    if submenu.0 == 0 {
        return;
    }
    unsafe {
        let _ = AppendMenuW(
            submenu,
            MF_STRING,
            MENU_PANEL_ID,
            w!("Control Panel...\tCtrl+Alt+M"),
        );
        let _ = AppendMenuW(submenu, MF_STRING, MENU_STATUS_ID, w!("Server Status..."));
        let _ = AppendMenuW(submenu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(submenu, MF_STRING, MENU_START_ID, w!("Start Server"));
        let _ = AppendMenuW(submenu, MF_STRING, MENU_STOP_ID, w!("Stop Server"));
        let _ = AppendMenuW(submenu, MF_STRING, MENU_RESTART_ID, w!("Restart Server"));
    }

    // Tools if we can find it, the bar itself if the editor's menus are not what
    // we expect - a top-level entry is worse placement but still reachable, and
    // silently having no menu at all would be the worst outcome.
    let (host, nested) = match find_tools_menu(bar) {
        Some(tools) => (tools, true),
        None => (bar, false),
    };
    if nested {
        unsafe {
            let _ = AppendMenuW(host, MF_SEPARATOR, 0, PCWSTR::null());
        }
    }
    if unsafe { AppendMenuW(host, MF_POPUP, submenu.0 as usize, w!("RenX MCP")) }.is_err() {
        unsafe {
            let _ = DestroyMenu(submenu);
        }
        return;
    }
    SUBMENU.store(submenu.0, Ordering::Relaxed);
    unsafe {
        let _ = DrawMenuBar(frame);
    }

    if ORIGINAL_WNDPROC.load(Ordering::Relaxed) == 0 {
        // Through a fn pointer rather than casting the fn item straight to an
        // integer, which is what the compiler asks for and what keeps the
        // signature checked at the cast.
        let replacement: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
            frame_subclass;
        let previous =
            unsafe { SetWindowLongPtrW(frame, GWLP_WNDPROC, replacement as usize as isize) };
        ORIGINAL_WNDPROC.store(previous, Ordering::Relaxed);
    }
    install_message_hook();

    MENU_ADDED.store(true, Ordering::Relaxed);
    debug_log!(
        "RenX MCP menu installed {}",
        if nested { "under Tools" } else { "on the menu bar" }
    );
}

/// Makes the shortcut the menu item advertises actually do something.
///
/// `\tCtrl+Alt+M` in a menu string is a caption, not a binding: Windows draws it
/// right-aligned and binds nothing at all. A real binding normally comes from an
/// accelerator table run through `TranslateAccelerator`, but the message loop
/// here is wx's and we do not own the call - so the only place left to see the
/// keystroke is the queue it is pumped out of.
///
/// Scoped to the editor's own thread rather than installed with `RegisterHotKey`
/// or a `WH_KEYBOARD_LL` hook, both of which are machine-wide: this one cannot
/// fire while another application has focus, and it takes Ctrl+Alt+M away from
/// nothing except this editor.
unsafe extern "system" fn message_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // Only on the pass that actually consumes the message. A peek reports the
    // same keystroke without removing it, and acting on both would open the
    // panel twice for one press.
    if code == HC_ACTION as i32 && wparam.0 as u32 == PM_REMOVE.0 {
        let message = &mut *(lparam.0 as *mut MSG);
        // Both forms. A keystroke held with Alt normally arrives as
        // WM_SYSKEYDOWN, and which of the two Windows picks for Ctrl+Alt
        // depends on whether it decides the pair is AltGr - so matching only
        // WM_KEYDOWN silently caught nothing.
        if (message.message == WM_KEYDOWN || message.message == WM_SYSKEYDOWN)
            && message.wParam.0 as u32 == u32::from(b'M')
            && GetKeyState(VK_CONTROL.0 as i32) < 0
            && GetKeyState(VK_MENU.0 as i32) < 0
        {
            // Posted to the frame rather than calling `open` from inside the
            // hook, so the shortcut travels the identical path as the menu item
            // and the two cannot drift apart. It also keeps this proc - which
            // runs for every message the editor pumps - down to a comparison.
            if let Some(frame) = find_editor_frame() {
                let _ = PostMessageW(frame, WM_COMMAND, WPARAM(MENU_PANEL_ID), LPARAM(0));
            }
            // Swallowed. The editor has no binding for this chord, but a
            // viewport that treats an unrecognised key as camera input would
            // otherwise act on it as well.
            message.message = WM_NULL;
        }
    }
    // Always chained, even when the message was consumed: for this hook type the
    // return value is ignored and skipping the chain would silently break any
    // other hook on this thread.
    CallNextHookEx(HHOOK(0), code, wparam, lparam)
}

fn install_message_hook() {
    if MESSAGE_HOOK.load(Ordering::Relaxed) != 0 {
        return;
    }
    // The editor thread, because that is the thread this runs on - the tick
    // detour that drives everything in this module.
    let thread = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
    match unsafe { SetWindowsHookExW(WH_GETMESSAGE, Some(message_hook), HINSTANCE(0), thread) } {
        Ok(hook) if hook.0 != 0 => {
            MESSAGE_HOOK.store(hook.0, Ordering::Relaxed);
            debug_log!("RenX MCP installed the Ctrl+Alt+M hook on thread {thread}");
        }
        _ => debug_log!("RenX MCP could not install the Ctrl+Alt+M hook"),
    }
}

/// Runs the requested server action and reports what happened.
///
/// Every one of these is a deliberate click, so every one gets an answer -
/// including the failures, which are the cases where saying nothing would leave
/// the user staring at an editor that looks exactly the same either way.
fn run_server_command(owner: HWND, id: usize) {
    let (outcome, verb) = match id {
        MENU_START_ID => (super::start_server(), "Start"),
        MENU_STOP_ID => (super::stop_server(), "Stop"),
        MENU_RESTART_ID => (super::restart_server(), "Restart"),
        _ => return,
    };
    let (text, icon) = match outcome {
        Ok(message) => (message, MB_ICONINFORMATION),
        Err(message) => (message, MB_ICONWARNING),
    };
    let title = wide(&format!("RenX MCP - {verb} Server"));
    let body = wide(&text);
    unsafe {
        MessageBoxW(
            owner,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | icon,
        );
    }
    refresh();
}

/// The full report, in a message box because Windows lets Ctrl+C copy one - so
/// the endpoint can be pasted straight into a client's configuration.
fn show_status(owner: HWND) {
    let body = wide(&super::status_report());
    unsafe {
        MessageBoxW(
            owner,
            PCWSTR(body.as_ptr()),
            w!("RenX MCP - Server Status"),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

/// Greys out whichever of Start/Stop cannot apply right now, so the menu shows
/// the server's state before anything is clicked.
fn update_menu_state(popup: HMENU) {
    let running = super::server_running();
    let enable = |id: usize, on: bool| unsafe {
        EnableMenuItem(
            popup,
            id as u32,
            MF_BYCOMMAND | if on { MF_ENABLED } else { MF_GRAYED },
        );
    };
    enable(MENU_START_ID, !running);
    enable(MENU_STOP_ID, running);
    enable(MENU_RESTART_ID, true);
}

unsafe extern "system" fn frame_subclass(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_COMMAND {
        match wparam.0 & 0xFFFF {
            MENU_PANEL_ID => {
                open();
                return LRESULT(0);
            }
            MENU_STATUS_ID => {
                show_status(hwnd);
                return LRESULT(0);
            }
            id @ (MENU_START_ID | MENU_STOP_ID | MENU_RESTART_ID) => {
                run_server_command(hwnd, id);
                return LRESULT(0);
            }
            _ => {}
        }
    }
    // Only ever for our own popup - wx owns every other menu in the frame and
    // must not have its item states rewritten underneath it.
    if message == WM_INITMENUPOPUP {
        let popup = SUBMENU.load(Ordering::Relaxed);
        if popup != 0 && wparam.0 as isize == popup {
            update_menu_state(HMENU(popup));
        }
    }
    // Unhook before the frame goes away. A subclass left installed on a dead
    // window is harmless, but one left installed while this DLL unloads points
    // Windows at freed code the next time anything posts a message.
    if message == WM_NCDESTROY {
        let original = ORIGINAL_WNDPROC.load(Ordering::Relaxed);
        shutdown();
        MENU_ADDED.store(false, Ordering::Relaxed);
        EDITOR_FRAME.store(0, Ordering::Relaxed);
        if original != 0 {
            return CallWindowProcW(
                Some(std::mem::transmute::<
                    isize,
                    unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT,
                >(original)),
                hwnd,
                message,
                wparam,
                lparam,
            );
        }
    }
    let original = ORIGINAL_WNDPROC.load(Ordering::Relaxed);
    if original == 0 {
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
    CallWindowProcW(
        Some(std::mem::transmute::<
            isize,
            unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT,
        >(original)),
        hwnd,
        message,
        wparam,
        lparam,
    )
}

/// Shows the panel, creating it the first time and reusing it afterwards so its
/// position survives being closed and reopened.
pub fn open() {
    let existing = PANEL_HWND.load(Ordering::Relaxed);
    if existing != 0 && unsafe { IsWindow(HWND(existing)) }.as_bool() {
        unsafe {
            let _ = ShowWindow(HWND(existing), SW_SHOW);
            let _ = SetForegroundWindow(HWND(existing));
        }
        refresh();
        return;
    }
    create();
}

fn register_class() {
    if CLASS_REGISTERED.swap(true, Ordering::SeqCst) {
        return;
    }
    let class = WNDCLASSW {
        lpfnWndProc: Some(panel_proc),
        hInstance: hinstance(),
        lpszClassName: w!("RenXMcpPolicyPanel"),
        hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default(),
        hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
        ..Default::default()
    };
    unsafe {
        RegisterClassW(&class);
    }
}

fn create() {
    register_class();
    let owner = find_editor_frame().unwrap_or(HWND(0));

    let style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
    let ex_style = WS_EX_TOOLWINDOW | WS_EX_DLGMODALFRAME;

    // Created hidden and sized afterwards. How tall the rows came out depends on
    // which of them had to wrap, and that is not known until they exist; sizing
    // before the window is shown means there is no visible reflow.
    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            w!("RenXMcpPolicyPanel"),
            w!("RenX MCP Policy"),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            content_width() + MARGIN * 2,
            ROW_HEIGHT * 8,
            owner,
            None,
            hinstance(),
            None,
        )
    };
    if hwnd.0 == 0 {
        debug_log!("RenX MCP policy panel failed to create");
        return;
    }
    PANEL_HWND.store(hwnd.0, Ordering::Relaxed);
    fit_to_content(hwnd, style, ex_style);
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
}

/// Sizes the window around the children that were built into it.
///
/// The old code passed a client-sized figure straight to `CreateWindowEx`, which
/// takes a *window* size - so the frame and caption ate into the area the rows
/// were placed in, and the panel was a little narrower and shorter than the
/// layout believed. `AdjustWindowRectEx` is the conversion that was missing.
fn fit_to_content(hwnd: HWND, style: WINDOW_STYLE, ex_style: WINDOW_EX_STYLE) {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: content_width() + MARGIN * 2,
        bottom: CONTENT_BOTTOM.load(Ordering::Relaxed) + MARGIN,
    };
    unsafe {
        let _ = AdjustWindowRectEx(&mut rect, style, false, ex_style);
    }
    let mut width = rect.right - rect.left;
    let mut height = rect.bottom - rect.top;

    // A last guard against a window taller than the screen it opens on. With
    // fifteen capabilities this is unreachable; if a future list ever does reach
    // it, the panel needs a scroll bar rather than a bigger clamp.
    let mut work_area = RECT::default();
    if unsafe {
        SystemParametersInfoW(
            SPI_GETWORKAREA,
            0,
            Some(&mut work_area as *mut RECT as *mut std::ffi::c_void),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    }
    .is_ok()
    {
        width = width.min(work_area.right - work_area.left);
        height = height.min(work_area.bottom - work_area.top);
    }

    unsafe {
        let _ = SetWindowPos(
            hwnd,
            HWND(0),
            0,
            0,
            width,
            height,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

const SERVER_HEADING: &str = "Server - the loopback bridge a model connects to:";
const MODE_HEADING: &str = "Mode - what the connected model may do to this editor:";
const ADVANCED_HEADING: &str =
    "Advanced - individual capabilities (editing these selects 'custom'):";
const FOOTER: &str = "Changes apply immediately and persist to RenXMcpPolicy.json.";

/// Built here rather than inline at the call site so the string that is measured
/// is by construction the same string that is shown. Measuring one and drawing
/// another is exactly how a label ends up a few pixels too narrow.
fn mode_label(mode: policy::Mode) -> String {
    format!("{}  -  {}", mode.id(), mode.describe())
}

fn capability_label(capability: Capability) -> String {
    if capability.is_destructive() {
        format!("{}  (!)  {}", capability.id(), capability.describe())
    } else {
        format!("{}  -  {}", capability.id(), capability.describe())
    }
}

/// The one font the panel both measures with and draws in.
///
/// This used to be `DEFAULT_GUI_FONT` on both sides, which sounds like it cannot
/// disagree with itself - but inside the editor the controls rendered in
/// something noticeably wider than that stock handle measured, so every row was
/// told it had about a fifth more room than it really did. Rows that needed to
/// wrap were judged to fit, and were clipped. Holding one `HFONT` and using it
/// for both removes the question rather than answering it.
///
/// The shell's own message font is what a native dialog uses, so the panel also
/// stops looking like a 1990s applet.
fn panel_font() -> HFONT {
    let cached = PANEL_FONT.load(Ordering::Relaxed);
    if cached != 0 {
        return HFONT(cached);
    }
    let mut metrics = NONCLIENTMETRICSW {
        cbSize: std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
        ..Default::default()
    };
    let font = unsafe {
        let read = SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            metrics.cbSize,
            Some(&mut metrics as *mut NONCLIENTMETRICSW as *mut std::ffi::c_void),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        );
        if read.is_ok() {
            CreateFontIndirectW(&metrics.lfMessageFont)
        } else {
            // Not correct, but the panel still draws. Only reachable if the
            // shell cannot report its own metrics.
            HFONT(GetStockObject(DEFAULT_GUI_FONT).0)
        }
    };
    // Kept for the life of the process on purpose: every control holds it, and
    // the panel is only hidden on close, never destroyed.
    PANEL_FONT.store(font.0, Ordering::Relaxed);
    font
}

/// Runs `body` against a device context carrying the font the controls use, so a
/// measurement taken here is the measurement the control will make.
fn with_gui_font<T>(body: impl FnOnce(HDC) -> T) -> T {
    unsafe {
        let dc = GetDC(HWND(0));
        let previous = SelectObject(dc, HGDIOBJ(panel_font().0));
        let result = body(dc);
        SelectObject(dc, previous);
        ReleaseDC(HWND(0), dc);
        result
    }
}

fn text_width(dc: HDC, text: &str) -> i32 {
    let text: Vec<u16> = text.encode_utf16().collect();
    let mut size = SIZE::default();
    unsafe {
        let _ = GetTextExtentPoint32W(dc, &text, &mut size);
    }
    size.cx
}

/// How tall a row has to be for `text` to fit across `width`, wrapping it if it
/// does not fit on one line.
fn text_height(dc: HDC, text: &str, width: i32) -> i32 {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: width.max(1),
        bottom: 0,
    };
    let mut text: Vec<u16> = text.encode_utf16().collect();
    unsafe {
        DrawTextW(
            dc,
            &mut text,
            &mut rect,
            DT_CALCRECT | DT_WORDBREAK | DT_LEFT,
        );
    }
    (rect.bottom - rect.top + 6).max(ROW_HEIGHT)
}

/// The width a checkbox or radio spends on its own glyph before the text starts.
///
/// Deliberately a little generous. Being wrong the other way costs a few pixels
/// of window; being wrong this way clips a word.
fn box_width() -> i32 {
    unsafe { GetSystemMetrics(SM_CXMENUCHECK) }.max(13) + INDENT + 6
}

/// The content width, measured from the strings that will actually be drawn.
///
/// This replaced a fixed 470px. That number was narrower than the longest
/// capability description at the shell font, so those descriptions were clipped
/// mid-word - and being a constant, it could only ever have been right for one
/// font at one scale.
fn content_width() -> i32 {
    let furniture = INDENT + box_width();
    let widest = with_gui_font(|dc| {
        let mut widest = 0;
        for heading in [SERVER_HEADING, MODE_HEADING, ADVANCED_HEADING, FOOTER] {
            widest = widest.max(text_width(dc, heading));
        }
        for mode in ALL_MODES {
            widest = widest.max(furniture + text_width(dc, &mode_label(mode)));
        }
        for capability in ALL {
            widest = widest.max(furniture + text_width(dc, &capability_label(capability)));
        }
        widest
    });
    // The button row is laid out from fixed widths, so it sets a floor of its own.
    let buttons = INDENT + 4 * (BUTTON_WIDTH + 6);
    widest
        .max(buttons)
        .clamp(MIN_CONTENT_WIDTH, MAX_CONTENT_WIDTH)
}

fn child(
    parent: HWND,
    class: PCWSTR,
    text: &str,
    style: WINDOW_STYLE,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    id: usize,
) -> HWND {
    let label = wide(text);
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            PCWSTR(label.as_ptr()),
            WS_CHILD | WS_VISIBLE | style,
            x,
            y,
            width,
            height,
            parent,
            HMENU(id as isize),
            hinstance(),
            None,
        )
    };
    // The same handle the layout measured with, not merely the same stock
    // constant - see [`panel_font`].
    if hwnd.0 != 0 {
        unsafe {
            SendMessageW(
                hwnd,
                WM_SETFONT,
                WPARAM(panel_font().0 as usize),
                LPARAM(1),
            );
        }
    }
    hwnd
}

fn build_children(hwnd: HWND) {
    let width = content_width();
    // Rows that sit one step in have that much less room for their text, which
    // is the arithmetic the old layout skipped: every indented row was given the
    // full width and so ran past the right edge by exactly its own indent.
    let indented = width - INDENT;
    let y = with_gui_font(|dc| build_rows(hwnd, dc, width, indented));
    CONTENT_BOTTOM.store(y, Ordering::Relaxed);
}

fn build_rows(hwnd: HWND, dc: HDC, width: i32, indented: i32) -> i32 {
    let mut y = MARGIN;

    let heading = |text: &str, y: &mut i32| {
        let height = text_height(dc, text, width);
        child(
            hwnd,
            w!("STATIC"),
            text,
            WINDOW_STYLE(0),
            MARGIN,
            *y,
            width,
            height,
            0,
        );
        *y += height;
    };

    heading(SERVER_HEADING, &mut y);
    child(
        hwnd,
        w!("STATIC"),
        &super::status_line(),
        WINDOW_STYLE(0),
        MARGIN + INDENT,
        y,
        indented,
        ROW_HEIGHT,
        SERVER_STATUS_TEXT,
    );
    y += ROW_HEIGHT;

    for (index, (label, id)) in [
        ("Start", SERVER_START_BUTTON),
        ("Stop", SERVER_STOP_BUTTON),
        ("Restart", SERVER_RESTART_BUTTON),
        ("Details...", SERVER_DETAILS_BUTTON),
    ]
    .iter()
    .enumerate()
    {
        child(
            hwnd,
            w!("BUTTON"),
            label,
            WINDOW_STYLE(BS_PUSHBUTTON as u32),
            MARGIN + INDENT + index as i32 * (BUTTON_WIDTH + 6),
            y,
            BUTTON_WIDTH,
            BUTTON_HEIGHT,
            *id,
        );
    }
    y += BUTTON_HEIGHT + MARGIN;

    heading(MODE_HEADING, &mut y);

    // Text inside a checkbox or radio starts after its glyph, so that is what is
    // left for the words. BS_MULTILINE is what lets the surplus wrap instead of
    // being cut off at the edge of the control.
    let text_room = indented - box_width();
    for (index, mode) in ALL_MODES.iter().enumerate() {
        // WS_GROUP on the first radio makes them behave as one exclusive set.
        let mut style = WINDOW_STYLE(BS_AUTORADIOBUTTON as u32) | WINDOW_STYLE(BS_MULTILINE as u32);
        if index == 0 {
            style |= WS_GROUP;
        }
        let label = mode_label(*mode);
        let height = text_height(dc, &label, text_room);
        child(
            hwnd,
            w!("BUTTON"),
            &label,
            style,
            MARGIN + INDENT,
            y,
            indented,
            height,
            MODE_BASE + index,
        );
        y += height;
    }

    y += MARGIN;
    heading(ADVANCED_HEADING, &mut y);

    for (index, capability) in ALL.iter().enumerate() {
        let label = capability_label(*capability);
        let height = text_height(dc, &label, text_room);
        child(
            hwnd,
            w!("BUTTON"),
            &label,
            WINDOW_STYLE(BS_AUTOCHECKBOX as u32) | WINDOW_STYLE(BS_MULTILINE as u32) | WS_GROUP,
            MARGIN + INDENT,
            y,
            indented,
            height,
            CAP_BASE + index,
        );
        y += height;
    }

    y += MARGIN;
    heading(FOOTER, &mut y);
    y
}

/// Pushes the live policy into the controls.
///
/// Always driven from the policy rather than from what was clicked, so a change
/// made over `/control/policy` while the panel is open is reflected here, and so
/// a capability toggle that moves the mode to `custom` updates the radio group
/// without the panel having to work out that rule for itself.
fn refresh() {
    let hwnd = HWND(PANEL_HWND.load(Ordering::Relaxed));
    if hwnd.0 == 0 || !unsafe { IsWindow(hwnd) }.as_bool() {
        return;
    }
    let running = super::server_running();
    let status = unsafe { GetDlgItem(hwnd, SERVER_STATUS_TEXT as i32) };
    if status.0 != 0 {
        let text = wide(&super::status_line());
        unsafe {
            let _ = SetWindowTextW(status, PCWSTR(text.as_ptr()));
        }
    }
    for (id, enabled) in [
        (SERVER_START_BUTTON, !running),
        (SERVER_STOP_BUTTON, running),
    ] {
        let button = unsafe { GetDlgItem(hwnd, id as i32) };
        if button.0 != 0 {
            unsafe {
                let _ = EnableWindow(button, enabled);
            }
        }
    }

    let mode = policy::current_mode();
    for (index, candidate) in ALL_MODES.iter().enumerate() {
        let button = unsafe { GetDlgItem(hwnd, (MODE_BASE + index) as i32) };
        if button.0 != 0 {
            unsafe {
                SendMessageW(
                    button,
                    BM_SETCHECK,
                    WPARAM(if *candidate == mode { 1 } else { 0 }),
                    LPARAM(0),
                );
            }
        }
    }
    for (index, capability) in ALL.iter().enumerate() {
        let button = unsafe { GetDlgItem(hwnd, (CAP_BASE + index) as i32) };
        if button.0 != 0 {
            unsafe {
                SendMessageW(
                    button,
                    BM_SETCHECK,
                    WPARAM(if policy::allows(*capability) { 1 } else { 0 }),
                    LPARAM(0),
                );
            }
        }
    }
    unsafe {
        let _ = InvalidateRect(hwnd, None, true);
    }
}

unsafe extern "system" fn panel_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_CREATE => {
            PANEL_HWND.store(hwnd.0, Ordering::Relaxed);
            build_children(hwnd);
            refresh();
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = wparam.0 & 0xFFFF;
            if id == SERVER_DETAILS_BUTTON {
                show_status(hwnd);
            } else if let Some(command) = match id {
                SERVER_START_BUTTON => Some(MENU_START_ID),
                SERVER_STOP_BUTTON => Some(MENU_STOP_ID),
                SERVER_RESTART_BUTTON => Some(MENU_RESTART_ID),
                _ => None,
            } {
                // Same path as the menu, so the two surfaces cannot drift in
                // what they do or in what they report.
                run_server_command(hwnd, command);
            } else if (MODE_BASE..MODE_BASE + ALL_MODES.len()).contains(&id) {
                let chosen = ALL_MODES[id - MODE_BASE];
                // The one mode that asks on the way in, because it is the mode
                // that stops anything asking afterwards. The `refresh` below
                // puts the radio back where it was if they decline.
                if chosen == policy::Mode::Dangerous && !policy::confirmations_suppressed() {
                    let body = wide(&policy::dangerous_warning());
                    let answer = MessageBoxW(
                        hwnd,
                        PCWSTR(body.as_ptr()),
                        w!("RenX MCP - Turn off every safeguard?"),
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
                    );
                    if answer == IDYES {
                        policy::apply_mode(chosen);
                    }
                } else {
                    policy::apply_mode(chosen);
                }
                refresh();
            } else if (CAP_BASE..CAP_BASE + ALL.len()).contains(&id) {
                let capability = ALL[id - CAP_BASE];
                let checked = SendMessageW(HWND(lparam.0), BM_GETCHECK, WPARAM(0), LPARAM(0)).0 == 1;
                confirm_or_apply(hwnd, capability, checked);
                refresh();
            }
            LRESULT(0)
        }
        // Static labels paint with the dialog background rather than white.
        WM_CTLCOLORSTATIC => {
            SetBkMode(HDC(wparam.0 as isize), TRANSPARENT);
            SetTextColor(
                HDC(wparam.0 as isize),
                COLORREF(GetSysColor(COLOR_WINDOWTEXT)),
            );
            LRESULT(GetSysColorBrush(COLOR_WINDOW).0)
        }
        // Closing hides: the policy keeps applying whether the panel is on
        // screen or not, and keeping the window means keeping its position.
        WM_CLOSE => {
            let _ = ShowWindow(hwnd, SW_HIDE);
            LRESULT(0)
        }
        WM_DESTROY => {
            PANEL_HWND.store(0, Ordering::Relaxed);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

/// Asks the user to approve something that arrived over the bridge - a policy
/// change, or an editor command that is not known to be read-only.
///
/// Owned by the editor frame rather than by the panel, because the panel is
/// usually closed and a prompt with no visible owner can end up behind the
/// editor window where nobody sees it. Defaults to No.
pub(crate) fn confirm_change(title: &str, summary: &str) -> bool {
    let owner = find_editor_frame().unwrap_or(HWND(0));
    let body = wide(summary);
    let caption = wide(title);
    let answer = unsafe {
        MessageBoxW(
            owner,
            PCWSTR(body.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND,
        )
    };
    let approved = answer == IDYES;
    refresh();
    approved
}

/// Turning a destructive capability *on* asks first; turning one off never does.
///
/// The prompt is the one place a human is unambiguously present, which is what
/// makes it worth interrupting them for - and it only guards granting, because
/// revoking a permission is never the dangerous direction.
fn confirm_or_apply(hwnd: HWND, capability: Capability, enabling: bool) {
    if enabling && capability.is_destructive() {
        let body = wide(&format!(
            "Allow the connected model to use '{}'?\n\n{}\n\nThis can destroy work in ways undo may \
             not recover.",
            capability.id(),
            capability.describe()
        ));
        let answer = unsafe {
            MessageBoxW(
                hwnd,
                PCWSTR(body.as_ptr()),
                w!("RenX MCP Policy"),
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
            )
        };
        if answer != IDYES {
            return;
        }
    }
    policy::apply_capability(capability, enabling);
}

/// Unhooks the frame subclass and the keyboard hook. The panel itself is owned
/// by the editor window and goes with it.
///
/// Both of these are function pointers into this image that Windows holds on our
/// behalf, so this has to run before the library unloads as well as when the
/// frame dies. The hook is the more urgent of the two: it is called for every
/// message the editor pumps, so one left dangling would fault within moments
/// rather than eventually.
pub fn shutdown() {
    let hook = MESSAGE_HOOK.swap(0, Ordering::Relaxed);
    if hook != 0 {
        unsafe {
            let _ = UnhookWindowsHookEx(HHOOK(hook));
        }
    }
    let original = ORIGINAL_WNDPROC.swap(0, Ordering::Relaxed);
    let frame = EDITOR_FRAME.load(Ordering::Relaxed);
    if original != 0 && frame != 0 && unsafe { IsWindow(HWND(frame)) }.as_bool() {
        unsafe {
            SetWindowLongPtrW(HWND(frame), GWLP_WNDPROC, original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_id_ranges_do_not_overlap() {
        assert!(MODE_BASE + ALL_MODES.len() <= CAP_BASE);
        assert!(CAP_BASE + ALL.len() <= SERVER_STATUS_TEXT);
        // A `WM_COMMAND` carries only an id, so a panel control sharing a number
        // with a menu command would fire the wrong action.
        assert!(SERVER_DETAILS_BUTTON < MENU_PANEL_ID);
    }

    #[test]
    fn menu_command_ids_are_distinct() {
        let ids = [
            MENU_PANEL_ID,
            MENU_STATUS_ID,
            MENU_START_ID,
            MENU_STOP_ID,
            MENU_RESTART_ID,
        ];
        for (index, left) in ids.iter().enumerate() {
            for right in ids.iter().skip(index + 1) {
                assert_ne!(left, right);
            }
        }
    }

    /// The panel used to be a fixed 470px wide, which was narrower than its own
    /// longest capability description - so those descriptions were cut off
    /// mid-word. Nothing about a constant could have caught that, so the
    /// replacement is measured and this is what holds it to its measurement.
    #[test]
    fn every_label_gets_the_room_its_text_needs() {
        let width = content_width();
        assert!(
            (MIN_CONTENT_WIDTH..=MAX_CONTENT_WIDTH).contains(&width),
            "content width {width} is outside its bounds"
        );
        assert!(
            width >= INDENT + 4 * (BUTTON_WIDTH + 6),
            "the server button row does not fit in {width}px"
        );

        let room = width - INDENT - box_width();
        with_gui_font(|dc| {
            for label in ALL
                .iter()
                .map(|capability| capability_label(*capability))
                .chain(ALL_MODES.iter().map(|mode| mode_label(*mode)))
            {
                let needed = text_width(dc, &label);
                let given = text_height(dc, &label, room);
                // Either it fits on one line, or it was given the extra lines it
                // needs. The old layout gave every row one line and neither.
                assert!(
                    needed <= room || given > ROW_HEIGHT,
                    "{label:?} needs {needed}px across {room}px but was given {given}px"
                );
            }
        });
    }

    /// If the measurement does not respond to width then wrapping is a no-op and
    /// every long label quietly clips again, which is the bug this replaced.
    #[test]
    fn a_narrow_column_makes_a_long_label_taller() {
        with_gui_font(|dc| {
            let long = Capability::ReadViewport.describe();
            assert!(text_height(dc, long, 120) > text_height(dc, long, 600));
            // And a short one is left at the single-row height either way.
            assert_eq!(text_height(dc, "Stop", 600), ROW_HEIGHT);
        });
    }
}
