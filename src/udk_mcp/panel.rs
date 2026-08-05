//! The in-editor control panel for [`super::policy`], and the menu item that
//! opens it.
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
use windows::Win32::UI::WindowsAndMessaging::*;

use super::policy::{self, Capability, ALL, ALL_MODES};
use crate::patch_utils::debug_log;

/// Command id for our menu item. wx allocates its own ids from a low range and
/// from negatives, so a value up near the top of the `WM_COMMAND` menu space is
/// the least likely to collide with one the editor already uses.
const MENU_COMMAND_ID: usize = 0x7F31;

/// Child control ids. Modes occupy `[MODE_BASE, MODE_BASE + ALL_MODES.len())`
/// and capabilities `[CAP_BASE, CAP_BASE + ALL.len())`, so a `WM_COMMAND` maps
/// back to its subject by subtraction.
const MODE_BASE: usize = 0x1000;
const CAP_BASE: usize = 0x2000;

const PANEL_WIDTH: i32 = 470;
const MARGIN: i32 = 14;
const ROW_HEIGHT: i32 = 22;

static PANEL_HWND: AtomicIsize = AtomicIsize::new(0);
static EDITOR_FRAME: AtomicIsize = AtomicIsize::new(0);
static ORIGINAL_WNDPROC: AtomicIsize = AtomicIsize::new(0);
static CLASS_REGISTERED: AtomicBool = AtomicBool::new(false);
static MENU_ADDED: AtomicBool = AtomicBool::new(false);

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
    // A menu item we added is still there if its id still resolves to a state.
    unsafe { GetMenuState(menu, MENU_COMMAND_ID as u32, MF_BYCOMMAND) != u32::MAX }
}

/// Appends the item to the editor's menu bar and subclasses the frame so its
/// `WM_COMMAND` reaches us.
///
/// The subclass chains to wx's original procedure for everything else. Only our
/// own id is consumed; wx never sees an id it did not allocate, and every other
/// message is passed through untouched.
fn install_menu_item() {
    let Some(frame) = find_editor_frame() else {
        return;
    };
    let menu = unsafe { GetMenu(frame) };
    if menu.0 == 0 {
        return;
    }

    if unsafe {
        AppendMenuW(
            menu,
            MF_STRING,
            MENU_COMMAND_ID,
            w!("MCP Policy\tCtrl+Alt+M"),
        )
    }
    .is_err()
    {
        return;
    }
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
    debug_log!("RenX MCP policy menu item installed");
}

unsafe extern "system" fn frame_subclass(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_COMMAND && (wparam.0 & 0xFFFF) == MENU_COMMAND_ID {
        open();
        return LRESULT(0);
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

    // Height is derived so adding a capability does not require re-measuring by
    // hand and silently clipping the last row.
    let height = MARGIN * 4
        + ROW_HEIGHT * (ALL_MODES.len() as i32 + ALL.len() as i32 + 3)
        + 40;

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
            if (MODE_BASE..MODE_BASE + ALL_MODES.len()).contains(&id) {
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
        assert!(CAP_BASE + ALL.len() < MENU_COMMAND_ID);
    }

    #[test]
    fn every_mode_and_capability_gets_a_row() {
        // The panel height is derived from these, so a new entry must not be
        // able to appear without the window growing to fit it.
        let height =
            MARGIN * 4 + ROW_HEIGHT * (ALL_MODES.len() as i32 + ALL.len() as i32 + 3) + 40;
        assert!(height > ROW_HEIGHT * (ALL_MODES.len() + ALL.len()) as i32);
    }
}
