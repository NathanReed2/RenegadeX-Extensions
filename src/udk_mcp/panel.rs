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

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetStockObject, GetSysColor, GetSysColorBrush, InvalidateRect, SetBkMode, SetTextColor,
    COLOR_WINDOW, COLOR_WINDOWTEXT, DEFAULT_GUI_FONT, HDC, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
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

const PANEL_WIDTH: i32 = 470;
const MARGIN: i32 = 14;
const ROW_HEIGHT: i32 = 22;
const BUTTON_HEIGHT: i32 = 26;
const BUTTON_WIDTH: i32 = 104;

static PANEL_HWND: AtomicIsize = AtomicIsize::new(0);
static EDITOR_FRAME: AtomicIsize = AtomicIsize::new(0);
static ORIGINAL_WNDPROC: AtomicIsize = AtomicIsize::new(0);
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

    MENU_ADDED.store(true, Ordering::Relaxed);
    debug_log!(
        "RenX MCP menu installed {}",
        if nested { "under Tools" } else { "on the menu bar" }
    );
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

    let height = panel_height();

    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_DLGMODALFRAME,
            w!("RenXMcpPolicyPanel"),
            w!("RenX MCP Policy"),
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            PANEL_WIDTH,
            height,
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
}

/// Derived from the row counts so adding a mode or a capability cannot silently
/// clip the last row off the bottom of the window.
fn panel_height() -> i32 {
    // Server heading, status line, button row, then the two labelled sections.
    let server = ROW_HEIGHT * 2 + BUTTON_HEIGHT + MARGIN;
    MARGIN * 4
        + server
        + ROW_HEIGHT * (ALL_MODES.len() as i32 + ALL.len() as i32 + 3)
        + 40
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
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
    // Inherit the shell font instead of the 1980s bitmap default.
    if hwnd.0 != 0 {
        unsafe {
            let font = GetStockObject(DEFAULT_GUI_FONT);
            SendMessageW(hwnd, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
        }
    }
    hwnd
}

fn build_children(hwnd: HWND) {
    let mut y = MARGIN;
    let width = PANEL_WIDTH - MARGIN * 3;

    child(
        hwnd,
        w!("STATIC"),
        "Server - the loopback bridge a model connects to:",
        WINDOW_STYLE(0),
        MARGIN,
        y,
        width,
        ROW_HEIGHT,
        0,
    );
    y += ROW_HEIGHT;
    child(
        hwnd,
        w!("STATIC"),
        &super::status_line(),
        WINDOW_STYLE(0),
        MARGIN + 8,
        y,
        width - 8,
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
            MARGIN + 8 + index as i32 * (BUTTON_WIDTH + 6),
            y,
            BUTTON_WIDTH,
            BUTTON_HEIGHT,
            *id,
        );
    }
    y += BUTTON_HEIGHT + MARGIN;

    child(
        hwnd,
        w!("STATIC"),
        "Mode - what the connected model may do to this editor:",
        WINDOW_STYLE(0),
        MARGIN,
        y,
        width,
        ROW_HEIGHT,
        0,
    );
    y += ROW_HEIGHT;

    for (index, mode) in ALL_MODES.iter().enumerate() {
        // WS_GROUP on the first radio makes the four behave as one exclusive set.
        let mut style = WINDOW_STYLE(BS_AUTORADIOBUTTON as u32);
        if index == 0 {
            style |= WS_GROUP;
        }
        child(
            hwnd,
            w!("BUTTON"),
            &format!("{}  -  {}", mode.id(), mode.describe()),
            style,
            MARGIN + 8,
            y,
            width,
            ROW_HEIGHT,
            MODE_BASE + index,
        );
        y += ROW_HEIGHT;
    }

    y += MARGIN;
    child(
        hwnd,
        w!("STATIC"),
        "Advanced - individual capabilities (editing these selects 'custom'):",
        WINDOW_STYLE(0),
        MARGIN,
        y,
        width,
        ROW_HEIGHT,
        0,
    );
    y += ROW_HEIGHT;

    for (index, capability) in ALL.iter().enumerate() {
        let label = if capability.is_destructive() {
            format!("{}  (!)  {}", capability.id(), capability.describe())
        } else {
            format!("{}  -  {}", capability.id(), capability.describe())
        };
        child(
            hwnd,
            w!("BUTTON"),
            &label,
            WINDOW_STYLE(BS_AUTOCHECKBOX as u32) | WS_GROUP,
            MARGIN + 8,
            y,
            width,
            ROW_HEIGHT,
            CAP_BASE + index,
        );
        y += ROW_HEIGHT;
    }

    y += MARGIN;
    child(
        hwnd,
        w!("STATIC"),
        "Changes apply immediately and persist to RenXMcpPolicy.json.",
        WINDOW_STYLE(0),
        MARGIN,
        y,
        width,
        ROW_HEIGHT,
        0,
    );
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
                policy::apply_mode(ALL_MODES[id - MODE_BASE]);
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

/// Unhooks the frame subclass. The panel itself is owned by the editor window
/// and goes with it.
pub fn shutdown() {
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

    #[test]
    fn panel_is_tall_enough_for_every_row_it_builds() {
        // The height is derived from the row counts, so a new mode or capability
        // must not be able to appear without the window growing to fit it.
        let rows = ALL_MODES.len() as i32 + ALL.len() as i32
            + 2  // the two section headings
            + 2  // server heading and status line
            + 1; // the persistence footnote
        let content = ROW_HEIGHT * rows + BUTTON_HEIGHT + MARGIN * 5;
        assert!(
            panel_height() >= content,
            "panel {} is shorter than its {content}px of content",
            panel_height()
        );
    }
}
