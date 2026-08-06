//! Loopback MCP bridge for the Win64 Renegade X editor.
//!
//! Function RVAs were mapped with the live Ghidra MCP instance by comparing
//! the symbolized UDK source build with the RenXSDK target. Unreal calls are
//! drained by `UUnrealEdEngine::Tick`, so they run on the editor thread.

use anyhow::{bail, Context};
use retour::static_detour;
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

pub mod audit;
pub mod guard;
pub mod panel;
pub mod policy;
mod assets;
mod changes;
mod dependencies;
pub(crate) mod events;
mod pie;
pub(crate) mod exceptions;
mod health;
mod mapped;
mod object;
mod scene;
mod spatial;
mod state;
mod viewport;

const DEFAULT_PORT: u16 = 8765;
const MAX_HTTP_BODY: usize = 1024 * 1024;
const MAX_HTTP_HEADERS: usize = 64 * 1024;
const MAX_QUEUED_REQUESTS: usize = 128;
const MAX_COMMAND_UNITS: usize = 4096;
const MAX_CAPTURE_UNITS: usize = 1024 * 1024;
const MAX_SELECTED_ACTORS: i32 = 16_384;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAP_HEALTH_TIMEOUT: Duration = Duration::from_secs(60);
const MAP_HEALTH_SLOW_TIMEOUT: Duration = Duration::from_secs(120);
const ASSET_USAGE_TIMEOUT: Duration = Duration::from_secs(60);
// Each inbound hop is a whole-heap scan, so the budget rather than the
// depth is what bounds this one.
const REFERENCE_GRAPH_TIMEOUT: Duration = Duration::from_secs(300);
// A full-map scan with component bounds is bounded work, but on a dense map
// it is more than a frame's worth of it.
const SPATIAL_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

const EDITOR_TICK_RVA: usize = 0x013C_6960;
const EDITOR_EXEC_RVA: usize = 0x013C_EA70;
// `UUnrealEdEngine::Exec` is emitted for the secondary FExec base. Ghidra
// shows that its parent call subtracts 0x60 before accessing UEditorEngine.
const EDITOR_EXEC_THIS_OFFSET: usize = 0x60;
const GET_SELECTED_ACTORS_RVA: usize = 0x0126_6530;
const GET_SELECTED_OBJECTS_RVA: usize = 0x0126_6540;
const SELECTION_NUM_RVA: usize = 0x0017_C3A0;
const UOBJECT_STATIC_EXEC_RVA: usize = 0x0027_BBA0;
const UOBJECT_STATIC_FIND_OBJECT_RVA: usize = 0x0027_0520;
const UOBJECT_GET_NAME_RVA: usize = 0x0005_7AA0;
const UOBJECT_GET_FULL_NAME_RVA: usize = 0x0026_8A30;
const APP_FREE_RVA: usize = 0x001C_AFE0;
const BEGIN_TRANSACTION_RVA: usize = 0x0128_8A90;
const END_TRANSACTION_RVA: usize = 0x0128_8AB0;

const UOBJECT_OUTER_OFFSET: usize = 0x40;
pub(super) const UOBJECT_CLASS_OFFSET: usize = 0x50;
pub(super) const USTRUCT_SUPER_STRUCT_OFFSET: usize = 0x78;
const USELECTION_OBJECTS_OFFSET: usize = 0x60;
const USELECTION_COUNT_OFFSET: usize = 0x68;
pub(super) const ACTOR_LOCATION_OFFSET: usize = 0x80;
const ACTOR_ROTATION_OFFSET: usize = 0x8C;
const ACTOR_DRAW_SCALE_OFFSET: usize = 0x98;
const ACTOR_DRAW_SCALE3D_OFFSET: usize = 0x9C;

const EDITOR_TICK_PROLOGUE: &[u8] = &[
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x0F, 0x29, 0x74, 0x24, 0x20, 0x48,
];
const UOBJECT_STATIC_FIND_OBJECT_PROLOGUE: &[u8] = &[
    0x44, 0x89, 0x4C, 0x24, 0x20, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57,
];

type EditorTickFn = extern "C" fn(*mut c_void, f32);
type EditorExecFn = unsafe extern "C" fn(*mut c_void, *const u16, *mut c_void) -> u32;
type GetSelectionFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SelectionNumFn = unsafe extern "C" fn(*mut c_void) -> i32;
type UObjectGetNameFn = unsafe extern "C" fn(*mut c_void, *mut UnrealString) -> *mut UnrealString;
type UObjectGetFullNameFn =
    unsafe extern "C" fn(*mut c_void, *mut UnrealString, *mut c_void) -> *mut UnrealString;
type AppFreeFn = unsafe extern "C" fn(*mut c_void);
type UObjectStaticExecFn = unsafe extern "C" fn(*const u16, *mut c_void) -> u32;
type UObjectStaticFindObjectFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *const u16, u32) -> *mut c_void;
type BeginTransactionFn = unsafe extern "C" fn(*mut c_void, *const u16) -> i32;
type EndTransactionFn = unsafe extern "C" fn(*mut c_void) -> i32;

static_detour! {
    static EditorTickHook: extern "C" fn(*mut c_void, f32);
}

static REQUEST_QUEUE: OnceLock<Mutex<VecDeque<EditorRequest>>> = OnceLock::new();
static SERVER_LISTENING: AtomicBool = AtomicBool::new(false);
static SERVER_PORT: AtomicU16 = AtomicU16::new(DEFAULT_PORT);
static EDITOR_THIS: AtomicUsize = AtomicUsize::new(0);
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Set once, the first time a tick reaches us. Autostart is deliberately a
/// one-shot rather than "start it whenever it is not running", so that stopping
/// the server from the menu keeps it stopped instead of having the next frame
/// put it straight back.
static SERVER_AUTOSTARTED: AtomicBool = AtomicBool::new(false);
/// Bumped per start. An accept loop whose generation is stale belongs to a
/// previous server and retires itself, which is what makes restart safe even if
/// a stop is slow to be noticed.
static SERVER_GENERATION: AtomicU32 = AtomicU32::new(0);
static SERVER_STOP: AtomicBool = AtomicBool::new(false);
static CONNECTIONS_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static TOOL_CALLS: AtomicU64 = AtomicU64::new(0);
static POLICY_REFUSALS: AtomicU64 = AtomicU64::new(0);
/// Mutations that actually reached the editor and succeeded. This is how many
/// undo steps the bridge is responsible for, which is the number a user needs
/// after something unexpected.
static MUTATIONS_APPLIED: AtomicU64 = AtomicU64::new(0);
/// Numbers the named transactions this bridge opens, so a run of them is
/// recognisable in the editor's Undo History.
static TRANSACTIONS_OPENED: AtomicU64 = AtomicU64::new(0);
/// Last bind or accept failure, kept so the status view can explain a server
/// that is not listening rather than just saying that it is not.
static LAST_SERVER_ERROR: Mutex<String> = Mutex::new(String::new());

enum EditorOperation {
    Exec(String),
    SelectionCounts,
    SelectedActors,
    ListActorProperties {
        actor_index: usize,
        pattern: String,
    },
    GetActorProperty {
        actor_index: usize,
        property: String,
    },
    GetObjectProperty {
        object_path: String,
        property: String,
    },
    SetActorProperty {
        actor_index: usize,
        property: String,
        value: String,
    },
    SetObjectProperty {
        object_path: String,
        property: String,
        value: String,
    },
    ActorAction {
        action: ActorAction,
    },
    MapInfo,
    PieStatus,
    PieStart,
    PieStop,
    MapHealth {
        include_slow_reference_checks: bool,
        categories: Vec<String>,
        limit: usize,
    },
    ViewportContext {
        grid_width: usize,
        grid_height: usize,
        max_actors: usize,
        adaptive: bool,
        max_samples: usize,
    },
    InspectViewportPoint {
        x: i32,
        y: i32,
    },
    FocusViewportActor {
        source: ViewportActorSource,
    },
    ViewportScreenshot {
        max_width: usize,
    },
    FindActors {
        class_name: String,
        query: String,
        level: String,
        offset: usize,
        limit: usize,
    },
    ChangeState {
        include_clean_packages: bool,
        package_query: String,
        history_limit: usize,
        package_limit: usize,
    },
    AssetUsage {
        object_path: String,
        scope: String,
        limit: usize,
    },
    SpatialQuery(Box<spatial::Query>),
    ReferenceGraph {
        object_path: String,
        direction: String,
        class_filter: String,
        max_depth: usize,
        max_nodes: usize,
        max_inbound_scans: usize,
    },
    CaptureEditorState,
    DiffEditorState {
        from_snapshot: String,
        to_snapshot: Option<String>,
    },
}

#[derive(Clone)]
enum ViewportActorSource {
    Selected(usize),
    ScreenPoint { x: i32, y: i32 },
    ObjectPath(String),
}

#[derive(Clone, Copy)]
enum ActorAction {
    Duplicate,
    Delete,
    ResetLocation,
    ResetRotation,
    ResetScale,
    SnapToFloor,
    MoveToGrid,
}

/// Per-call safety arguments, kept apart from the operation itself.
///
/// They travel with the request rather than living in each variant because they
/// apply to whole classes of operation, and because a new variant that forgets
/// to carry them would silently opt out of every limit.
#[derive(Default, Clone)]
struct Guards {
    /// The caller has told the user how many actors this touches and been told
    /// to go ahead. See [`guard::check_blast_radius`].
    confirm_large_change: bool,
    /// The selection the caller believes it is acting on.
    selection_token: Option<String>,
    /// Report what would happen; change nothing.
    dry_run: bool,
}

impl Guards {
    fn from_arguments(arguments: &str) -> Guards {
        Guards {
            confirm_large_change: json_field_bool(arguments, "confirmLargeChange") == Some(true),
            selection_token: json_field_string(arguments, "selectionToken"),
            dry_run: json_field_bool(arguments, "dryRun") == Some(true),
        }
    }
}

struct EditorRequest {
    operation: EditorOperation,
    guards: Guards,
    queued_at: Instant,
    /// Raised by the drain the instant before the work begins.
    ///
    /// The split below cannot describe a call that timed out, because nothing
    /// ever came back to describe it - and that is the case a user most needs
    /// explained. This flag answers the one question that separates the two
    /// remedies: an operation that never started means the editor thread is not
    /// reaching the bridge at all, and one that started and did not finish means
    /// the work itself is too big. Reading it is only valid after the wait has
    /// expired, which is the only place it is read.
    started: std::sync::Arc<AtomicBool>,
    /// Raised by a caller that has stopped waiting, so the drain can drop the
    /// request instead of applying it to an editor nobody is watching.
    ///
    /// Giving up waiting was not the same as cancelling: a timed-out mutation
    /// stayed queued and applied minutes later, which makes the obvious agent
    /// reflex - retry on timeout - able to delete twice. This is the flag that
    /// makes a retry safe, and it is paired with `started` rather than trusted
    /// alone, because work already underway cannot be recalled.
    cancelled: std::sync::Arc<AtomicBool>,
    response: SyncSender<(Result<EditorValue, String>, EditorTiming)>,
}

/// What a queued operation cost, split at the only boundary that matters.
///
/// A single wall-clock number cannot separate "the editor was busy and did not
/// reach the drain" from "the work itself was slow", and those two have nothing
/// in common: the first is answered by closing a modal dialog, the second by
/// asking for less. The split is measured where both facts are known - on the
/// editor thread, either side of the call - rather than inferred afterwards.
#[derive(Clone, Copy)]
struct EditorTiming {
    queue_wait: Duration,
    execution: Duration,
}

thread_local! {
    /// Filled in by [`submit_guarded`] and drained by [`tools_call`], both of
    /// which run on the connection thread that is serving this one call.
    ///
    /// A thread-local rather than a value threaded back through every handler:
    /// `submit_guarded` returns `Result<EditorValue, String>` to eighteen call
    /// sites, and widening all of them to carry a measurement none of them use
    /// would be a large diff in service of a small fact.
    static EDITOR_TIMING: Cell<Option<EditorTiming>> = const { Cell::new(None) };
}

/// Accumulates, because a tool is free to submit more than one operation and
/// the audit line describes the call rather than any one of them.
fn record_editor_timing(timing: EditorTiming) {
    EDITOR_TIMING.with(|slot| {
        let total = match slot.get() {
            Some(previous) => EditorTiming {
                queue_wait: previous.queue_wait.saturating_add(timing.queue_wait),
                execution: previous.execution.saturating_add(timing.execution),
            },
            None => timing,
        };
        slot.set(Some(total));
    });
}

fn take_editor_timing() -> Option<EditorTiming> {
    EDITOR_TIMING.with(|slot| slot.take())
}

enum EditorValue {
    ExecResult { handled: bool, output: String },
    SelectionCounts { actors: i32, objects: i32 },
    Json(String),
    Image {
        mime_type: &'static str,
        data: String,
        metadata: String,
    },
}

#[repr(C)]
struct UnrealString {
    data: *mut u16,
    len: i32,
    capacity: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Vector3 {
    x: f32,
    y: f32,
    z: f32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rotator {
    pitch: i32,
    yaw: i32,
    roll: i32,
}

#[repr(C)]
struct CaptureOutputDevice {
    vtable: *const usize,
    allow_suppression: i32,
    suppress_event_tag: i32,
    auto_emit_line_terminator: i32,
    output: String,
}

static CAPTURE_VTABLE: OnceLock<[usize; 4]> = OnceLock::new();

extern "C" fn capture_destructor(
    this: *mut CaptureOutputDevice,
    _flags: u32,
) -> *mut CaptureOutputDevice {
    this
}

extern "C" fn capture_serialize(this: *mut CaptureOutputDevice, text: *const u16, _event: u32) {
    if this.is_null() || text.is_null() {
        return;
    }
    let mut len = 0usize;
    unsafe {
        while len < MAX_CAPTURE_UNITS && *text.add(len) != 0 {
            len += 1;
        }
        let message = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        let output = &mut (*this).output;
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&message);
    }
}

extern "C" fn capture_flush(_this: *mut CaptureOutputDevice) {}
extern "C" fn capture_teardown(_this: *mut CaptureOutputDevice) {}

impl CaptureOutputDevice {
    fn new() -> Self {
        let vtable = CAPTURE_VTABLE.get_or_init(|| {
            [
                capture_destructor as *const () as usize,
                capture_serialize as *const () as usize,
                capture_flush as *const () as usize,
                capture_teardown as *const () as usize,
            ]
        });
        Self {
            vtable: vtable.as_ptr(),
            allow_suppression: 1,
            suppress_event_tag: 0,
            auto_emit_line_terminator: 0,
            output: String::new(),
        }
    }

    fn as_output_device(&mut self) -> *mut c_void {
        self as *mut Self as *mut c_void
    }
}

fn editor_launch() -> bool {
    std::env::args_os()
        .skip(1)
        .any(|arg| arg.to_string_lossy().eq_ignore_ascii_case("editor"))
}

pub(super) fn image_address(rva: usize, length: usize, name: &str) -> anyhow::Result<usize> {
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

fn validate_tick_hook() -> anyhow::Result<EditorTickFn> {
    let address = image_address(
        EDITOR_TICK_RVA,
        EDITOR_TICK_PROLOGUE.len(),
        "UUnrealEdEngine::Tick",
    )?;
    let actual =
        unsafe { std::slice::from_raw_parts(address as *const u8, EDITOR_TICK_PROLOGUE.len()) };
    if actual != EDITOR_TICK_PROLOGUE {
        bail!(
            "UUnrealEdEngine::Tick validation failed at RVA 0x{EDITOR_TICK_RVA:X}: expected {:02X?}, found {:02X?}",
            EDITOR_TICK_PROLOGUE,
            actual
        );
    }
    Ok(unsafe { std::mem::transmute::<usize, EditorTickFn>(address) })
}

extern "C" fn editor_tick_hook(editor: *mut c_void, delta_seconds: f32) {
    EditorTickHook.call(editor, delta_seconds);

    EDITOR_THIS.store(editor as usize, Ordering::Release);
    let ticks = TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    // Registered here rather than at DLL attach because `GLog` points at a
    // static that the executable's own initialisers have not constructed yet at
    // that point - its critical section does not exist until they run.
    events::attach();
    start_server_once();
    drain_editor_requests(editor);
    drain_confirmations();

    // The panel and its menu item have to be created and repaired on the thread
    // that pumps them, which is this one. Throttled because the check walks the
    // thread's windows and queries the menu, and the menu bar only ever changes
    // at human speed - this is a repair path, not a render path.
    if ticks % MENU_REPAIR_TICK_INTERVAL == 0 {
        panel::tick();
    }
}

/// Roughly two seconds at editor frame rates.
const MENU_REPAIR_TICK_INTERVAL: u64 = 120;

fn drain_editor_requests(editor: *mut c_void) {
    for _ in 0..MAX_QUEUED_REQUESTS {
        let request = {
            let mut queue = request_queue()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            queue.pop_front()
        };
        let Some(request) = request else {
            break;
        };
        // Read before the work starts and again after, on this thread, so
        // neither number includes the other and neither includes the time the
        // caller spent on its own side of the socket.
        let queue_wait = request.queued_at.elapsed();
        let started = Instant::now();
        // Claim the request, then look for a cancellation. The caller does the
        // mirror of this - raises `cancelled`, then reads `started` - and both
        // sides are SeqCst, so the two cannot miss each other. Whoever loses
        // the race errs towards "may have run", which is the safe direction to
        // be wrong in for a mutation.
        request.started.store(true, Ordering::SeqCst);
        if request.cancelled.load(Ordering::SeqCst) {
            // Nobody is listening. Dropping the request also drops the sender,
            // which is what the caller's `recv` already gave up on.
            continue;
        }
        let result = guard_and_execute(editor, request.operation, &request.guards);
        let timing = EditorTiming {
            queue_wait,
            execution: started.elapsed(),
        };
        let _ = request.response.send((result, timing));
    }
}

fn selected_actor_pointers(editor: *mut c_void) -> Result<Vec<*mut c_void>, String> {
    let get_actors: GetSelectionFn = unsafe {
        std::mem::transmute(
            image_address(GET_SELECTED_ACTORS_RVA, 1, "GetSelectedActors")
                .map_err(|error| error.to_string())?,
        )
    };
    let selection = unsafe { get_actors(editor) };
    if selection.is_null() {
        return Ok(Vec::new());
    }
    let count = unsafe { *((selection as *const u8).add(USELECTION_COUNT_OFFSET) as *const i32) };
    if !(0..=MAX_SELECTED_ACTORS).contains(&count) {
        return Err(format!("invalid selected actor count: {count}"));
    }
    let data = unsafe {
        *((selection as *const u8).add(USELECTION_OBJECTS_OFFSET) as *const *const *mut c_void)
    };
    if count == 0 {
        return Ok(Vec::new());
    }
    if data.is_null() {
        return Err("selected actor array is null".to_string());
    }
    Ok(unsafe { std::slice::from_raw_parts(data, count as usize) }
        .iter()
        .copied()
        .filter(|actor| !actor.is_null())
        .collect())
}

fn selected_actor(editor: *mut c_void, index: usize) -> Result<*mut c_void, String> {
    selected_actor_pointers(editor)?
        .get(index)
        .copied()
        .ok_or_else(|| format!("selected actor index {index} is out of range"))
}

pub(super) unsafe fn read_pointer(object: *mut c_void, offset: usize) -> *mut c_void {
    *((object as *const u8).add(offset) as *const *mut c_void)
}

pub(super) fn unreal_object_string(object: *mut c_void, full: bool) -> Result<String, String> {
    if object.is_null() {
        return Ok(String::new());
    }
    let mut value = UnrealString {
        data: std::ptr::null_mut(),
        len: 0,
        capacity: 0,
    };
    unsafe {
        if full {
            let function: UObjectGetFullNameFn = std::mem::transmute(
                image_address(UOBJECT_GET_FULL_NAME_RVA, 1, "UObject::GetFullName")
                    .map_err(|error| error.to_string())?,
            );
            function(object, &mut value, std::ptr::null_mut());
        } else {
            let function: UObjectGetNameFn = std::mem::transmute(
                image_address(UOBJECT_GET_NAME_RVA, 1, "UObject::GetName")
                    .map_err(|error| error.to_string())?,
            );
            function(object, &mut value);
        }
    }
    let result = if value.data.is_null() || value.len <= 0 {
        String::new()
    } else {
        let len = (value.len as usize).min(MAX_CAPTURE_UNITS);
        let units = unsafe { std::slice::from_raw_parts(value.data, len) };
        let content_len = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        String::from_utf16_lossy(&units[..content_len])
    };
    if !value.data.is_null() {
        let free: AppFreeFn = unsafe {
            std::mem::transmute(
                image_address(APP_FREE_RVA, 1, "appFree").map_err(|error| error.to_string())?,
            )
        };
        unsafe { free(value.data.cast()) };
    }
    Ok(result)
}

pub(super) fn object_path_from_full_name(full_name: &str) -> &str {
    full_name
        .split_once(' ')
        .map_or(full_name, |(_, path)| path)
}

pub(super) fn validate_identifier(value: &str, pattern: bool) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || character == '_'
                || (pattern && matches!(character, '*' | '?'))
        });
    if valid {
        Ok(())
    } else {
        Err(format!("invalid UE3 identifier: {value}"))
    }
}

pub(super) fn run_editor_exec(
    editor: *mut c_void,
    command: &str,
) -> Result<(bool, String), String> {
    let wide = widestring::U16CString::from_str(command)
        .map_err(|_| "command contains an embedded NUL".to_string())?;
    if wide.len() > MAX_COMMAND_UNITS {
        return Err(format!("command exceeds {MAX_COMMAND_UNITS} UTF-16 units"));
    }
    let exec: EditorExecFn = unsafe {
        std::mem::transmute(
            image_address(EDITOR_EXEC_RVA, 1, "UUnrealEdEngine::Exec")
                .map_err(|error| error.to_string())?,
        )
    };
    let exec_this = editor_exec_this(editor)?;
    let mut capture = CaptureOutputDevice::new();
    let handled = unsafe { exec(exec_this, wide.as_ptr(), capture.as_output_device()) != 0 };
    Ok((handled, capture.output))
}

pub(super) fn run_static_exec(command: &str) -> Result<(bool, String), String> {
    let wide = widestring::U16CString::from_str(command)
        .map_err(|_| "command contains an embedded NUL".to_string())?;
    if wide.len() > MAX_COMMAND_UNITS {
        return Err(format!("command exceeds {MAX_COMMAND_UNITS} UTF-16 units"));
    }
    let function: UObjectStaticExecFn = unsafe {
        std::mem::transmute(
            image_address(UOBJECT_STATIC_EXEC_RVA, 1, "UObject::StaticExec")
                .map_err(|error| error.to_string())?,
        )
    };
    let mut capture = CaptureOutputDevice::new();
    let handled = unsafe { function(wide.as_ptr(), capture.as_output_device()) != 0 };
    Ok((handled, capture.output))
}

pub(super) fn actor_identity(actor: *mut c_void) -> Result<(String, String, String), String> {
    let name = unreal_object_string(actor, false)?;
    let full_name = unreal_object_string(actor, true)?;
    let class = unsafe { read_pointer(actor, UOBJECT_CLASS_OFFSET) };
    let class_name = unreal_object_string(class, false)?;
    Ok((name, full_name, class_name))
}

fn actor_data_json(actor: *mut c_void) -> Result<String, String> {
    let (name, full_name, class_name) = actor_identity(actor)?;
    let outer = unsafe { read_pointer(actor, UOBJECT_OUTER_OFFSET) };
    let level = unreal_object_string(outer, true)?;
    let location = unsafe { *((actor as *const u8).add(ACTOR_LOCATION_OFFSET) as *const Vector3) };
    let rotation = unsafe { *((actor as *const u8).add(ACTOR_ROTATION_OFFSET) as *const Rotator) };
    let draw_scale = unsafe { *((actor as *const u8).add(ACTOR_DRAW_SCALE_OFFSET) as *const f32) };
    let draw_scale3d =
        unsafe { *((actor as *const u8).add(ACTOR_DRAW_SCALE3D_OFFSET) as *const Vector3) };
    Ok(format!(
        "{{\"name\":\"{}\",\"path\":\"{}\",\"fullName\":\"{}\",\"class\":\"{}\",\"level\":\"{}\",\"location\":{{\"x\":{},\"y\":{},\"z\":{}}},\"rotation\":{{\"pitch\":{},\"yaw\":{},\"roll\":{}}},\"scale\":{{\"uniform\":{},\"x\":{},\"y\":{},\"z\":{}}}}}",
        json_escape(&name),
        json_escape(object_path_from_full_name(&full_name)),
        json_escape(&full_name),
        json_escape(&class_name),
        json_escape(&level),
        location.x,
        location.y,
        location.z,
        rotation.pitch,
        rotation.yaw,
        rotation.roll,
        draw_scale,
        draw_scale3d.x,
        draw_scale3d.y,
        draw_scale3d.z
    ))
}

/// Resolves and verifies one exact loaded UObject path. StaticFindObject's
/// prologue is checked against the target build so an updated executable is
/// refused rather than called at a stale RVA.
pub(super) fn find_object_by_path(path: &str) -> Result<*mut c_void, String> {
    find_object_by_path_of_class(path, std::ptr::null_mut())
}

/// The class-constrained form is needed for top-level package names: UE3 can
/// legally have another object with the same short name, while `StaticFindObject`
/// with a null class returns the first match. The exact resolved path is still
/// verified after lookup.
pub(super) fn find_object_by_path_of_class(
    path: &str,
    required_class: *mut c_void,
) -> Result<*mut c_void, String> {
    if path.is_empty()
        || path.len() > MAX_COMMAND_UNITS
        || path
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err("objectPath is invalid or too long".to_string());
    }
    let address = image_address(
        UOBJECT_STATIC_FIND_OBJECT_RVA,
        UOBJECT_STATIC_FIND_OBJECT_PROLOGUE.len(),
        "UObject::StaticFindObject",
    )
    .map_err(|error| error.to_string())?;
    let actual = unsafe {
        std::slice::from_raw_parts(
            address as *const u8,
            UOBJECT_STATIC_FIND_OBJECT_PROLOGUE.len(),
        )
    };
    if actual != UOBJECT_STATIC_FIND_OBJECT_PROLOGUE {
        return Err(format!(
            "UObject::StaticFindObject does not match the verified RenXSDK build at RVA 0x{UOBJECT_STATIC_FIND_OBJECT_RVA:X}; object-path lookup was refused"
        ));
    }
    let name = widestring::U16CString::from_str(path)
        .map_err(|_| "objectPath contains an embedded null".to_string())?;
    let find: UObjectStaticFindObjectFn = unsafe { std::mem::transmute(address) };
    let object = unsafe {
        find(
            required_class,
            usize::MAX as *mut c_void,
            name.as_ptr(),
            0,
        )
    };
    if object.is_null() {
        return Err(format!("no loaded object has path '{path}'"));
    }
    let (_, full_name, _) = actor_identity(object)?;
    let resolved_path = object_path_from_full_name(&full_name);
    if !resolved_path.eq_ignore_ascii_case(path) {
        return Err(format!(
            "object lookup was ambiguous: requested '{path}', resolved '{resolved_path}'"
        ));
    }
    Ok(object)
}

fn find_actor_by_path(path: &str) -> Result<*mut c_void, String> {
    let object = find_object_by_path(path)?;
    // These are the UObject/UStruct class-chain fields verified against the
    // symbolized source build. Only this actor-only wrapper performs the walk.
    let mut class = unsafe { read_pointer(object, UOBJECT_CLASS_OFFSET) };
    for _ in 0..128 {
        if class.is_null() {
            break;
        }
        if unreal_object_string(class, false)?.eq_ignore_ascii_case("Actor") {
            return Ok(object);
        }
        class = unsafe { read_pointer(class, USTRUCT_SUPER_STRUCT_OFFSET) };
    }
    Err(format!("'{path}' is loaded, but it is not an Actor"))
}

fn actor_json(index: usize, actor: *mut c_void) -> Result<String, String> {
    let data = actor_data_json(actor)?;
    Ok(format!(
        "{{\"index\":{index},{}",
        data.strip_prefix('{').unwrap_or(&data)
    ))
}

/// The checks that can only be made on the editor thread, then the work.
///
/// Blast radius and selection staleness both depend on the live selection, and
/// the live selection is only knowable here. Doing them off-thread would mean
/// trusting a count the caller supplied, which is precisely the number that goes
/// stale between a read and the mutation that follows it.
fn guard_and_execute(
    editor: *mut c_void,
    operation: EditorOperation,
    guards: &Guards,
) -> Result<EditorValue, String> {
    let capability = required_capability(&operation);
    let touches_selection = operation_touches_selection(&operation);

    let mut selection_size = None;
    if touches_selection {
        let count = selected_actor_pointers(editor)?.len();
        selection_size = Some(count);
        guard::note_selection(count);
        guard::check_selection_token(guards.selection_token.as_deref(), count)?;

        // Before the blast-radius check, not after. A dry run changes nothing,
        // and finding out that this would touch 741 actors is exactly what the
        // blast-radius refusal tells the caller to go and do - refusing the dry
        // run too would leave it no safe way to answer the question it was just
        // asked.
        if guards.dry_run {
            let large = count as i32 > guard::BLAST_RADIUS;
            return Ok(EditorValue::Json(format!(
                "{{\"dryRun\":true,\"wouldRun\":\"{}\",\"selectedActors\":{count},\"applied\":false,\
                 \"needsConfirmLargeChange\":{large},\"note\":\"Nothing was changed.{}\"}}",
                json_escape(&operation_description(&operation)),
                if large {
                    format!(
                        " This would affect {count} actors, which is over the limit of {}. Tell \
                         the user the count and what you intend to do, and only pass \
                         confirmLargeChange after they agree.",
                        guard::BLAST_RADIUS
                    )
                } else {
                    " Repeat without dryRun to apply this.".to_string()
                }
            )));
        }

        if !capability.is_read_only() {
            guard::check_blast_radius(
                count as i32,
                operation_description(&operation).as_str(),
                guards.confirm_large_change || policy::confirmations_suppressed(),
            )?;
        }
    } else if guards.dry_run && !capability.is_read_only() {
        return Ok(EditorValue::Json(format!(
            "{{\"dryRun\":true,\"wouldRun\":\"{}\",\"applied\":false,\"note\":\"Nothing was \
             changed. Repeat without dryRun to apply this.\"}}",
            json_escape(&operation_description(&operation))
        )));
    }

    let mutating = is_mutation(&operation);
    let mut result = execute_editor_operation(editor, operation);

    // A read of the selection hands back the token naming what it saw, so the
    // caller has something to pass to the mutation that follows.
    if !mutating {
        if let (Ok(EditorValue::Json(structured)), Some(count)) = (&mut result, selection_size) {
            *structured = with_selection_token(structured, &guard::selection_token(count));
        }
    }

    if mutating && result.is_ok() {
        MUTATIONS_APPLIED.fetch_add(1, Ordering::Relaxed);
        // Duplicate and delete change the selection as a side effect, and a
        // property write can change what a name resolves to. Cheaper to retire
        // every outstanding token than to work out which ones survived.
        guard::invalidate_selection();
    }
    result
}

/// Names a transaction so the editor's Undo History says where it came from.
///
/// UE3 shows the transaction name in Edit > Undo History, so numbering them
/// turns "something changed my map" into a contiguous run of numbered entries
/// the user can undo back through and recognise on sight. That is as close to a
/// session checkpoint as this can safely get from outside the engine: UE3 has no
/// nested-transaction API reachable here, and holding one transaction open
/// across HTTP calls would leave the editor in an open transaction for as long
/// as a client stayed connected - or forever, if it went away mid-edit.
///
/// The actions in [`ActorAction`] are not covered: `ACTOR DELETE` and friends
/// open their own transactions inside the engine, named by the engine. The
/// undoable-edit count in the status report covers those instead.
fn transaction_label(what: &str) -> String {
    format!(
        "MCP #{}: {what}",
        TRANSACTIONS_OPENED.fetch_add(1, Ordering::Relaxed) + 1
    )
}

/// Adds `selectionToken` to a JSON object this module built.
///
/// Safe as string surgery only because every value here is constructed by this
/// module and is always an object; it is never applied to anything parsed from
/// the wire.
fn with_selection_token(structured: &str, token: &str) -> String {
    let trimmed = structured.trim_end();
    let Some(head) = trimmed.strip_suffix('}') else {
        return structured.to_string();
    };
    if head.trim_end().ends_with('{') {
        format!("{head}\"selectionToken\":\"{token}\"}}")
    } else {
        format!("{head},\"selectionToken\":\"{token}\"}}")
    }
}

/// Whether this operation actually changes the map, for accounting and for the
/// rate limit.
///
/// Not the same question as which capability it needs. `exec.command` is a write
/// capability because most editor commands write, but the ones on the read-only
/// allowlist genuinely do not - and charging `OBJ LIST` against the mutation
/// budget, or reporting it as an undoable edit, would make both numbers lie in
/// the direction that matters: it inflates how much the bridge appears to have
/// changed, which is the figure someone reads when deciding how far to undo.
fn is_mutation(operation: &EditorOperation) -> bool {
    match operation {
        EditorOperation::Exec(command) => !guard::exec_is_read_only(command),
        other => !required_capability(other).is_read_only(),
    }
}

/// Whether the operation reads or writes the editor's current selection, and so
/// whether the selection guards apply to it.
fn operation_touches_selection(operation: &EditorOperation) -> bool {
    match operation {
        EditorOperation::SelectedActors
        | EditorOperation::SelectionCounts
        | EditorOperation::ListActorProperties { .. }
        | EditorOperation::GetActorProperty { .. }
        | EditorOperation::SetActorProperty { .. }
        | EditorOperation::ActorAction { .. }
        | EditorOperation::ViewportContext { .. }
        | EditorOperation::InspectViewportPoint { .. }
        | EditorOperation::CaptureEditorState
        | EditorOperation::DiffEditorState { .. }
        | EditorOperation::FocusViewportActor {
            source: ViewportActorSource::Selected(_),
        } => true,
        EditorOperation::Exec(_)
        | EditorOperation::GetObjectProperty { .. }
        | EditorOperation::SetObjectProperty { .. }
        | EditorOperation::PieStatus
        | EditorOperation::PieStart
        | EditorOperation::PieStop
        | EditorOperation::MapInfo
        | EditorOperation::MapHealth { .. }
        | EditorOperation::FindActors { .. }
        | EditorOperation::ChangeState { .. }
        | EditorOperation::AssetUsage { .. }
        | EditorOperation::ReferenceGraph { .. }
        | EditorOperation::SpatialQuery(_)
        | EditorOperation::ViewportScreenshot { .. }
        | EditorOperation::FocusViewportActor {
            source: ViewportActorSource::ScreenPoint { .. },
        }
        | EditorOperation::FocusViewportActor {
            source: ViewportActorSource::ObjectPath(_),
        } => false,
    }
}

/// A one-line description, for prompts, dry runs and the audit log.
fn operation_description(operation: &EditorOperation) -> String {
    match operation {
        EditorOperation::Exec(command) => format!("exec {command}"),
        EditorOperation::SelectionCounts => "read selection counts".to_string(),
        EditorOperation::SelectedActors => "read selected actors".to_string(),
        EditorOperation::ListActorProperties { actor_index, .. } => {
            format!("list properties of actor {actor_index}")
        }
        EditorOperation::GetActorProperty {
            actor_index,
            property,
        } => format!("read {property} of actor {actor_index}"),
        EditorOperation::GetObjectProperty {
            object_path,
            property,
        } => format!("read {property} from exact object {object_path}"),
        EditorOperation::SetActorProperty {
            actor_index,
            property,
            value,
        } => format!("set {property} = {value} on actor {actor_index}"),
        EditorOperation::SetObjectProperty {
            object_path,
            property,
            value,
        } => format!("set {property} = {value} on {object_path}"),
        EditorOperation::ActorAction { action } => format!("{} on the selected actors", match action
        {
            ActorAction::Duplicate => "ACTOR DUPLICATE",
            ActorAction::Delete => "ACTOR DELETE",
            ActorAction::ResetLocation => "ACTOR RESET LOCATION",
            ActorAction::ResetRotation => "ACTOR RESET ROTATION",
            ActorAction::ResetScale => "ACTOR RESET SCALE",
            ActorAction::SnapToFloor => "ACTOR ALIGN SNAPTOFLOOR",
            ActorAction::MoveToGrid => "ACTOR ALIGN MOVETOGRID",
        }),
        EditorOperation::MapInfo => "read map info".to_string(),
        EditorOperation::PieStatus => "read play-in-editor status".to_string(),
        EditorOperation::PieStart => "start a play-in-editor session".to_string(),
        EditorOperation::PieStop => "stop the play-in-editor session".to_string(),
        EditorOperation::MapHealth { .. } => {
            "run UE3's bounded, read-only map validation".to_string()
        }
        EditorOperation::ViewportContext { .. } => {
            "inspect the active viewport camera and visible actors".to_string()
        }
        EditorOperation::InspectViewportPoint { x, y } => {
            format!("inspect viewport point ({x},{y})")
        }
        EditorOperation::FocusViewportActor { source } => match source {
            ViewportActorSource::Selected(index) => {
                format!("frame selected actor {index} in the active viewport")
            }
            ViewportActorSource::ScreenPoint { x, y } => {
                format!("frame the actor at viewport point ({x},{y})")
            }
            ViewportActorSource::ObjectPath(path) => {
                format!("frame actor '{path}' in the active viewport")
            }
        },
        EditorOperation::ViewportScreenshot { .. } => {
            "capture the active viewport as a downscaled screenshot".to_string()
        }
        EditorOperation::FindActors {
            class_name,
            query,
            level,
            ..
        } => format!(
            "search loaded {class_name} actors for query '{query}' in level '{level}'"
        ),
        EditorOperation::ChangeState { .. } => {
            "inspect native undo/redo history and loaded package dirtiness".to_string()
        }
        EditorOperation::AssetUsage { object_path, .. } => {
            format!("find loaded objects that reference exact object '{object_path}'")
        }
        EditorOperation::ReferenceGraph {
            object_path,
            direction,
            max_depth,
            ..
        } => format!(
            "walk {direction} references of exact object '{object_path}' to depth {max_depth}"
        ),
        EditorOperation::SpatialQuery(query) => {
            format!("find loaded actors by {} volume", query.shape.id())
        }
        EditorOperation::CaptureEditorState => "capture a bounded editor state snapshot".to_string(),
        EditorOperation::DiffEditorState {
            from_snapshot,
            to_snapshot,
        } => format!(
            "compare editor snapshots {from_snapshot} and {}",
            to_snapshot.as_deref().unwrap_or("the current state")
        ),
    }
}

fn execute_editor_operation(
    editor: *mut c_void,
    operation: EditorOperation,
) -> Result<EditorValue, String> {
    match operation {
        EditorOperation::Exec(command) => {
            let (handled, output) = run_editor_exec(editor, &command)?;
            Ok(EditorValue::ExecResult { handled, output })
        }
        EditorOperation::SelectionCounts => {
            let get_actors: GetSelectionFn = unsafe {
                std::mem::transmute(
                    image_address(GET_SELECTED_ACTORS_RVA, 1, "GetSelectedActors")
                        .map_err(|error| error.to_string())?,
                )
            };
            let get_objects: GetSelectionFn = unsafe {
                std::mem::transmute(
                    image_address(GET_SELECTED_OBJECTS_RVA, 1, "GetSelectedObjects")
                        .map_err(|error| error.to_string())?,
                )
            };
            let selection_num: SelectionNumFn = unsafe {
                std::mem::transmute(
                    image_address(SELECTION_NUM_RVA, 1, "USelection::Num")
                        .map_err(|error| error.to_string())?,
                )
            };
            let actor_selection = unsafe { get_actors(editor) };
            let object_selection = unsafe { get_objects(editor) };
            let actors = if actor_selection.is_null() {
                0
            } else {
                unsafe { selection_num(actor_selection) }
            };
            let objects = if object_selection.is_null() {
                0
            } else {
                unsafe { selection_num(object_selection) }
            };
            Ok(EditorValue::SelectionCounts { actors, objects })
        }
        EditorOperation::SelectedActors => {
            let actors = selected_actor_pointers(editor)?;
            let entries = actors
                .iter()
                .enumerate()
                .map(|(index, actor)| actor_json(index, *actor))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(EditorValue::Json(format!(
                "{{\"count\":{},\"actors\":[{}]}}",
                entries.len(),
                entries.join(",")
            )))
        }
        EditorOperation::ListActorProperties {
            actor_index,
            pattern,
        } => {
            validate_identifier(&pattern, true)?;
            let actor = selected_actor(editor, actor_index)?;
            let (_, _, class_name) = actor_identity(actor)?;
            validate_identifier(&class_name, false)?;
            let (handled, output) = run_static_exec(&format!("LISTPROPS {class_name} {pattern}"))?;
            Ok(EditorValue::Json(format!(
                "{{\"actorIndex\":{actor_index},\"class\":\"{}\",\"pattern\":\"{}\",\"handled\":{handled},\"output\":\"{}\"}}",
                json_escape(&class_name),
                json_escape(&pattern),
                json_escape(&output)
            )))
        }
        EditorOperation::GetActorProperty {
            actor_index,
            property,
        } => {
            validate_identifier(&property, false)?;
            let actor = selected_actor(editor, actor_index)?;
            let (name, _, class_name) = actor_identity(actor)?;
            validate_identifier(&name, false)?;
            validate_identifier(&class_name, false)?;
            let (handled, output) =
                run_static_exec(&format!("GETALL {class_name} {property} NAME={name}"))?;
            Ok(EditorValue::Json(format!(
                "{{\"actorIndex\":{actor_index},\"actor\":\"{}\",\"class\":\"{}\",\"property\":\"{}\",\"handled\":{handled},\"output\":\"{}\"}}",
                json_escape(&name),
                json_escape(&class_name),
                json_escape(&property),
                json_escape(&output)
            )))
        }
        EditorOperation::GetObjectProperty {
            object_path,
            property,
        } => Ok(EditorValue::Json(object::read_property(
            &object_path,
            &property,
        )?)),
        EditorOperation::SetActorProperty {
            actor_index,
            property,
            value,
        } => {
            validate_identifier(&property, false)?;
            if value.contains('\0') || value.len() > MAX_COMMAND_UNITS {
                return Err("property value is invalid or too long".to_string());
            }
            let actor = selected_actor(editor, actor_index)?;
            let (_, full_name, _) = actor_identity(actor)?;
            let object_path = object_path_from_full_name(&full_name);
            if object_path.chars().any(char::is_whitespace) {
                return Err("selected actor path contains whitespace".to_string());
            }
            let transaction_name =
                widestring::U16CString::from_str(transaction_label("Set Actor Property"))
                    .map_err(|_| "invalid transaction name".to_string())?;
            let begin: BeginTransactionFn = unsafe {
                std::mem::transmute(
                    image_address(BEGIN_TRANSACTION_RVA, 1, "UEditorEngine::BeginTransaction")
                        .map_err(|error| error.to_string())?,
                )
            };
            let end: EndTransactionFn = unsafe {
                std::mem::transmute(
                    image_address(END_TRANSACTION_RVA, 1, "UEditorEngine::EndTransaction")
                        .map_err(|error| error.to_string())?,
                )
            };
            unsafe { begin(editor, transaction_name.as_ptr()) };
            let result = run_static_exec(&format!("SET {object_path} {property} {value}"));
            unsafe { end(editor) };
            let (handled, output) = result?;
            Ok(EditorValue::Json(format!(
                "{{\"actorIndex\":{actor_index},\"actorPath\":\"{}\",\"property\":\"{}\",\"value\":\"{}\",\"handled\":{handled},\"output\":\"{}\"}}",
                json_escape(object_path),
                json_escape(&property),
                json_escape(&value),
                json_escape(&output)
            )))
        }
        EditorOperation::SetObjectProperty {
            object_path,
            property,
            value,
        } => {
            validate_identifier(&property, false)?;
            if object_path.is_empty()
                || object_path.len() > MAX_COMMAND_UNITS
                || object_path
                    .chars()
                    .any(|character| character.is_whitespace() || character == '\0')
            {
                return Err("object path is invalid or too long".to_string());
            }
            if value.contains(['\0', '\r', '\n']) || value.len() > MAX_COMMAND_UNITS {
                return Err("property value is invalid or too long".to_string());
            }
            let transaction_name =
                widestring::U16CString::from_str(transaction_label("Set Object Property"))
                    .map_err(|_| "invalid transaction name".to_string())?;
            let begin: BeginTransactionFn = unsafe {
                std::mem::transmute(
                    image_address(BEGIN_TRANSACTION_RVA, 1, "UEditorEngine::BeginTransaction")
                        .map_err(|error| error.to_string())?,
                )
            };
            let end: EndTransactionFn = unsafe {
                std::mem::transmute(
                    image_address(END_TRANSACTION_RVA, 1, "UEditorEngine::EndTransaction")
                        .map_err(|error| error.to_string())?,
                )
            };
            unsafe { begin(editor, transaction_name.as_ptr()) };
            let result = run_static_exec(&format!("SET {object_path} {property} {value}"));
            unsafe { end(editor) };
            let (handled, output) = result?;
            Ok(EditorValue::Json(format!(
                "{{\"objectPath\":\"{}\",\"property\":\"{}\",\"value\":\"{}\",\"handled\":{handled},\"output\":\"{}\"}}",
                json_escape(&object_path),
                json_escape(&property),
                json_escape(&value),
                json_escape(&output)
            )))
        }
        EditorOperation::ActorAction { action } => {
            if selected_actor_pointers(editor)?.is_empty() {
                return Err("no actors are selected".to_string());
            }
            let command = match action {
                ActorAction::Duplicate => "ACTOR DUPLICATE",
                ActorAction::Delete => "ACTOR DELETE",
                ActorAction::ResetLocation => "ACTOR RESET LOCATION",
                ActorAction::ResetRotation => "ACTOR RESET ROTATION",
                ActorAction::ResetScale => "ACTOR RESET SCALE",
                ActorAction::SnapToFloor => "ACTOR ALIGN SNAPTOFLOOR",
                ActorAction::MoveToGrid => "ACTOR ALIGN MOVETOGRID",
            };
            let (handled, output) = run_editor_exec(editor, command)?;
            Ok(EditorValue::Json(format!(
                "{{\"command\":\"{command}\",\"handled\":{handled},\"output\":\"{}\"}}",
                json_escape(&output)
            )))
        }
        EditorOperation::PieStatus => Ok(EditorValue::Json(pie::status(editor)?)),
        EditorOperation::PieStart => Ok(EditorValue::Json(pie::start(editor)?)),
        EditorOperation::PieStop => Ok(EditorValue::Json(pie::stop(editor)?)),
        EditorOperation::MapInfo => {
            let actors = selected_actor_pointers(editor)?;
            let mut levels = Vec::new();
            let mut map = String::new();
            for actor in actors {
                let outer = unsafe { read_pointer(actor, UOBJECT_OUTER_OFFSET) };
                let level = unreal_object_string(outer, true)?;
                if !level.is_empty() && !levels.contains(&level) {
                    levels.push(level);
                }
                if map.is_empty() {
                    let (_, full_name, _) = actor_identity(actor)?;
                    let path = object_path_from_full_name(&full_name);
                    map = path.split('.').next().unwrap_or_default().to_string();
                }
            }
            let (handled, output) = run_editor_exec(editor, "OBJ LIST CLASS=WorldInfo")?;
            if map.is_empty() {
                map = output
                    .lines()
                    .filter_map(|line| line.trim().strip_prefix("WorldInfo "))
                    .filter_map(|path| path.split_whitespace().next())
                    .filter_map(|path| path.split_once(".TheWorld").map(|(package, _)| package))
                    .next()
                    .unwrap_or_default()
                    .to_string();
            }
            Ok(EditorValue::Json(format!(
                "{{\"map\":\"{}\",\"selectedLevels\":[{}],\"worldInfoHandled\":{handled},\"worldInfoOutput\":\"{}\"}}",
                json_escape(&map),
                levels
                    .iter()
                    .map(|level| format!("\"{}\"", json_escape(level)))
                    .collect::<Vec<_>>()
                    .join(","),
                json_escape(&output)
            )))
        }
        EditorOperation::MapHealth {
            include_slow_reference_checks,
            categories,
            limit,
        } => Ok(EditorValue::Json(health::report(
            editor,
            include_slow_reference_checks,
            &categories,
            limit,
        )?)),
        EditorOperation::ViewportContext {
            grid_width,
            grid_height,
            max_actors,
            adaptive,
            max_samples,
        } => {
            let selected = selected_actor_pointers(editor)?;
            Ok(EditorValue::Json(viewport::semantic_context(
                editor,
                &selected,
                grid_width,
                grid_height,
                max_actors,
                adaptive,
                max_samples,
            )?))
        }
        EditorOperation::InspectViewportPoint { x, y } => {
            let selected = selected_actor_pointers(editor)?;
            Ok(EditorValue::Json(viewport::inspect_point(
                editor, &selected, x, y,
            )?))
        }
        EditorOperation::FocusViewportActor { source } => {
            let selected = match source {
                ViewportActorSource::Selected(_) => selected_actor_pointers(editor)?,
                ViewportActorSource::ScreenPoint { .. }
                | ViewportActorSource::ObjectPath(_) => Vec::new(),
            };
            Ok(EditorValue::Json(viewport::focus_actor(
                editor, &selected, source,
            )?))
        }
        EditorOperation::ViewportScreenshot { max_width } => {
            let (data, metadata) = viewport::screenshot(editor, max_width)?;
            Ok(EditorValue::Image {
                mime_type: "image/bmp",
                data,
                metadata,
            })
        }
        EditorOperation::FindActors {
            class_name,
            query,
            level,
            offset,
            limit,
        } => Ok(EditorValue::Json(scene::find_actors(
            &class_name,
            &query,
            &level,
            offset,
            limit,
        )?)),
        EditorOperation::ChangeState {
            include_clean_packages,
            package_query,
            history_limit,
            package_limit,
        } => Ok(EditorValue::Json(changes::inspect(
            editor,
            include_clean_packages,
            &package_query,
            history_limit,
            package_limit,
        )?)),
        EditorOperation::AssetUsage {
            object_path,
            scope,
            limit,
        } => Ok(EditorValue::Json(assets::usage(
            &object_path,
            &scope,
            limit,
        )?)),
        EditorOperation::SpatialQuery(query) => {
            Ok(EditorValue::Json(spatial::query(editor, &query)?))
        }
        EditorOperation::ReferenceGraph {
            object_path,
            direction,
            class_filter,
            max_depth,
            max_nodes,
            max_inbound_scans,
        } => Ok(EditorValue::Json(dependencies::graph(
            &object_path,
            &direction,
            &class_filter,
            max_depth,
            max_nodes,
            max_inbound_scans,
        )?)),
        EditorOperation::CaptureEditorState => {
            let selected = selected_actor_pointers(editor)?;
            Ok(EditorValue::Json(state::capture(editor, &selected)?))
        }
        EditorOperation::DiffEditorState {
            from_snapshot,
            to_snapshot,
        } => {
            let selected = selected_actor_pointers(editor)?;
            Ok(EditorValue::Json(state::diff(
                editor,
                &selected,
                &from_snapshot,
                to_snapshot.as_deref(),
            )?))
        }
    }
}

fn editor_exec_this(editor: *mut c_void) -> Result<*mut c_void, String> {
    (editor as usize)
        .checked_add(EDITOR_EXEC_THIS_OFFSET)
        .map(|address| address as *mut c_void)
        .ok_or_else(|| "UUnrealEdEngine::Exec receiver address overflow".to_string())
}

fn request_queue() -> &'static Mutex<VecDeque<EditorRequest>> {
    REQUEST_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// The capability an operation needs.
///
/// Classified from the decoded operation rather than from the tool name, so the
/// check cannot be skipped by a tool that builds an operation some other way,
/// and so a new `ActorAction` variant has to be placed in a bucket before it
/// will compile.
fn required_capability(operation: &EditorOperation) -> policy::Capability {
    match operation {
        EditorOperation::Exec(_) => policy::Capability::Exec,
        EditorOperation::SelectionCounts | EditorOperation::SelectedActors => {
            policy::Capability::ReadSelection
        }
        EditorOperation::ListActorProperties { .. }
        | EditorOperation::GetActorProperty { .. }
        | EditorOperation::GetObjectProperty { .. } => policy::Capability::ReadProperties,
        EditorOperation::SetActorProperty { .. } => policy::Capability::WriteActorProperty,
        EditorOperation::SetObjectProperty { .. } => policy::Capability::WriteObjectProperty,
        EditorOperation::MapInfo | EditorOperation::MapHealth { .. } => policy::Capability::ReadMap,
        EditorOperation::PieStatus => policy::Capability::ReadPie,
        // Both directions, deliberately. A model that could stop a session it
        // was not allowed to start could still take the editor out from under
        // whoever was using it.
        EditorOperation::PieStart | EditorOperation::PieStop => policy::Capability::ControlPie,
        EditorOperation::ViewportContext { .. }
        | EditorOperation::InspectViewportPoint { .. }
        | EditorOperation::ViewportScreenshot { .. } => policy::Capability::ReadViewport,
        EditorOperation::FocusViewportActor { .. } => policy::Capability::ControlViewport,
        EditorOperation::FindActors { .. } => policy::Capability::ReadScene,
        EditorOperation::AssetUsage { .. }
        | EditorOperation::ReferenceGraph { .. }
        | EditorOperation::SpatialQuery(_) => policy::Capability::ReadScene,
        EditorOperation::ChangeState { .. }
        | EditorOperation::CaptureEditorState
        | EditorOperation::DiffEditorState { .. } => {
            policy::Capability::ReadState
        }
        EditorOperation::ActorAction { action } => match action {
            ActorAction::Delete => policy::Capability::WriteDelete,
            ActorAction::Duplicate => policy::Capability::WriteDuplicate,
            ActorAction::ResetLocation
            | ActorAction::ResetRotation
            | ActorAction::ResetScale
            | ActorAction::SnapToFloor
            | ActorAction::MoveToGrid => policy::Capability::WriteTransform,
        },
    }
}

fn submit_editor_operation(operation: EditorOperation) -> Result<EditorValue, String> {
    submit_guarded(operation, Guards::default())
}

/// A timeout means one of two unrelated things, and the fix for one is the
/// opposite of the fix for the other.
///
/// The old wording described only the first: it told every caller to go and
/// look for an open dialog, including the caller whose real problem was that it
/// had asked for a whole-heap scan. Both branches also say what happened to the
/// request, because giving up waiting is not the same as cancelling - nothing
/// here can recall an operation once it is queued, and a caller that assumes
/// otherwise will retry a mutation that is about to apply anyway.
fn timeout_message(started: bool, timeout: Duration) -> String {
    let seconds = timeout.as_secs();
    if started {
        format!(
            "The editor started this operation but had not finished it after {seconds} seconds, \
             so the bridge stopped waiting. This is not a policy refusal and not a bridge fault: \
             the work itself is larger than the budget for it. The editor is still running it and \
             will finish it - do not retry the same request, and expect the editor to be \
             unresponsive until it is done. Ask for less instead: a smaller volume, a lower \
             limit, or the version of the check that skips the slow passes."
        )
    } else {
        // Measured on CNC-Field, 2026-08-06: an open menu bar took an
        // ordinarily 16ms map query to 4.2s and a dropped-down menu to 7.0s,
        // both of which completed. So a menu defers this work by seconds rather
        // than stopping it, and something that has held the loop for a whole
        // timeout is more likely a modal dialog or a long build than a menu -
        // which is the order they are listed in.
        format!(
            "The editor never started this operation within {seconds} seconds. This is not a \
             policy refusal and not a bridge fault: the editor runs bridge work between frames, \
             so anything holding its main loop defers it. A modal dialog or a long operation such \
             as a build, import or light bake stops it outright; an open menu merely slows it, by \
             seconds. Ask the user to close any dialog or menu in the editor. The request has \
             been cancelled and will NOT run later, so nothing was changed and retrying is safe."
        )
    }
}

fn submit_guarded(operation: EditorOperation, guards: Guards) -> Result<EditorValue, String> {
    // Before the readiness check and before anything is queued: a denied
    // operation must never reach the editor thread, and must not be able to
    // distinguish "forbidden" from "editor busy" by the error it gets back.
    let capability = required_capability(&operation);
    if !policy::allows(capability) {
        POLICY_REFUSALS.fetch_add(1, Ordering::Relaxed);
        return Err(policy::deny_message(capability));
    }

    // A dry run changes nothing, so it is not spent against the mutation budget
    // and does not need a command approved - otherwise "show me what this would
    // do" would cost the same as doing it.
    let unguarded = policy::confirmations_suppressed();

    if is_mutation(&operation) && !guards.dry_run && !unguarded {
        guard::check_rate()?;
    }

    // `exec.command` is the one capability that subsumes all the others: with it
    // granted, every limit above can be reached round the side by typing the
    // equivalent console command. So a command that is not known to be read-only
    // is confirmed individually, which turns a single broad grant into a series
    // of specific ones.
    if let EditorOperation::Exec(command) = &operation {
        if unguarded && !guard::exec_is_read_only(command) {
            // Recorded even though nothing asked, because this is exactly the
            // command that would have been shown to a human in any other mode.
            audit::record(
                audit::Entry::new("exec", "renx_exec", audit::Outcome::Ok)
                    .detail(command)
                    .note("ran unprompted: dangerous mode"),
            );
        } else if !guards.dry_run && !guard::exec_is_read_only(command) {
            let approved = request_confirmation(
                "RenX MCP - Allow this editor command?",
                guard::exec_confirmation(command),
                "The user did not answer the approval prompt in the editor within two minutes, so \
                 the command was not run and nothing changed.",
            )?;
            if !approved {
                POLICY_REFUSALS.fetch_add(1, Ordering::Relaxed);
                audit::record(
                    audit::Entry::new("exec", "renx_exec", audit::Outcome::Blocked)
                        .detail(command)
                        .note("declined by the user"),
                );
                return Err(guard::EXEC_DECLINED.to_string());
            }
            audit::record(
                audit::Entry::new("exec", "renx_exec", audit::Outcome::Ok)
                    .detail(command)
                    .note("approved by the user"),
            );
        }
    }
    if EDITOR_THIS.load(Ordering::Acquire) == 0 {
        return Err("The editor is still starting up and has not run a frame yet. This is not a \
                    policy refusal - retry in a few seconds."
            .to_string());
    }
    let timeout = match &operation {
        EditorOperation::MapHealth {
            include_slow_reference_checks: true,
            ..
        } => MAP_HEALTH_SLOW_TIMEOUT,
        EditorOperation::MapHealth { .. } => MAP_HEALTH_TIMEOUT,
        EditorOperation::AssetUsage { .. } => ASSET_USAGE_TIMEOUT,
        EditorOperation::ReferenceGraph { .. } => REFERENCE_GRAPH_TIMEOUT,
        EditorOperation::SpatialQuery(_) => SPATIAL_QUERY_TIMEOUT,
        _ => REQUEST_TIMEOUT,
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let started = std::sync::Arc::new(AtomicBool::new(false));
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    {
        let mut queue = request_queue()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if queue.len() >= MAX_QUEUED_REQUESTS {
            return Err("the editor request queue is full".to_string());
        }
        queue.push_back(EditorRequest {
            operation,
            guards,
            queued_at: Instant::now(),
            started: started.clone(),
            cancelled: cancelled.clone(),
            response: sender,
        });
    }
    // Work is done on the editor's own thread, which only runs it between
    // frames. Anything that suspends the editor's loop - an open menu, a modal
    // dialog, a long import or build - stops that thread from getting here, and
    // the symptom is this timeout. Saying so matters because the alternative
    // reading is "the bridge is broken", which it is not.
    let (result, timing) = receiver.recv_timeout(timeout).map_err(|_| {
        // Cancel first, then ask whether it had already begun - the drain does
        // the mirror of this, so between them the outcome is never ambiguous in
        // the unsafe direction.
        cancelled.store(true, Ordering::SeqCst);
        timeout_message(started.load(Ordering::SeqCst), timeout)
    })?;
    // A timeout leaves this unrecorded on purpose. The request is still in the
    // queue and may run minutes later against a receiver nobody holds, so there
    // is no honest split to report for the call that gave up - only the total,
    // which is the timeout itself. What the split would have said is in the
    // message instead, which lands in the audit note for that line.
    record_editor_timing(timing);
    result
}

fn configured_port() -> u16 {
    std::env::var("RENX_MCP_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(DEFAULT_PORT)
}

fn start_server_once() {
    if SERVER_AUTOSTARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Err(error) = start_server() {
        debug_log!("RenX MCP autostart failed: {error}");
    }
}

fn record_server_error(message: &str) {
    if let Ok(mut slot) = LAST_SERVER_ERROR.lock() {
        slot.clear();
        slot.push_str(message);
    }
}

fn last_server_error() -> String {
    LAST_SERVER_ERROR
        .lock()
        .map(|slot| slot.clone())
        .unwrap_or_default()
}

/// Binds and serves, reporting the outcome of the bind back to the caller.
///
/// Starting is worth waiting for: the menu says "Start Server" and the user is
/// entitled to be told the port was busy rather than to watch nothing happen.
pub(crate) fn start_server() -> Result<String, String> {
    if SERVER_LISTENING.load(Ordering::Acquire) {
        return Err(format!(
            "The MCP server is already listening on 127.0.0.1:{}.",
            SERVER_PORT.load(Ordering::Relaxed)
        ));
    }
    SERVER_STOP.store(false, Ordering::Release);
    let port = configured_port();
    SERVER_PORT.store(port, Ordering::Relaxed);
    let generation = SERVER_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;

    let (ready, bound) = mpsc::sync_channel::<Result<(), String>>(1);
    std::thread::Builder::new()
        .name("renx-mcp".to_string())
        .spawn(move || server_main(port, generation, ready))
        .map_err(|error| format!("Could not spawn the MCP server thread: {error}"))?;

    match bound.recv_timeout(SERVER_START_TIMEOUT) {
        Ok(Ok(())) => Ok(format!(
            "MCP server started.\n\nListening on http://127.0.0.1:{port}/mcp"
        )),
        Ok(Err(message)) => Err(message),
        Err(_) => Err("The MCP server thread did not report back in time.".to_string()),
    }
}

/// Stops the accept loop and releases the port.
///
/// This blocks the caller for as long as it takes the loop to notice, which is
/// normally microseconds. It is called from a menu click on the editor thread,
/// so the wait is bounded and short rather than unbounded: a server that will
/// not stop is a bug to report, not a reason to freeze the editor.
pub(crate) fn stop_server() -> Result<String, String> {
    if !SERVER_LISTENING.load(Ordering::Acquire) {
        return Err("The MCP server is not running.".to_string());
    }
    SERVER_STOP.store(true, Ordering::Release);
    let port = SERVER_PORT.load(Ordering::Relaxed);

    // `accept` cannot be interrupted by setting a flag - the thread is parked
    // inside it. One throwaway loopback connection wakes it so it can see the
    // flag and leave. It is refused rather than served, because the loop checks
    // the flag before it looks at the connection.
    let _ = TcpStream::connect(("127.0.0.1", port));

    for _ in 0..SERVER_STOP_POLLS {
        if !SERVER_LISTENING.load(Ordering::Acquire) {
            return Ok(format!(
                "MCP server stopped.\n\n127.0.0.1:{port} has been released. Nothing can reach the \
                 editor over the bridge until it is started again."
            ));
        }
        std::thread::sleep(SERVER_STOP_POLL_INTERVAL);
    }
    Err("The MCP server did not stop in time; it may still be holding the port.".to_string())
}

pub(crate) fn restart_server() -> Result<String, String> {
    if SERVER_LISTENING.load(Ordering::Acquire) {
        stop_server()?;
    }
    start_server().map(|message| message.replacen("started", "restarted", 1))
}

const SERVER_START_TIMEOUT: Duration = Duration::from_secs(3);
const SERVER_STOP_POLLS: u32 = 60;
const SERVER_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);

fn server_main(port: u16, generation: u32, ready: mpsc::SyncSender<Result<(), String>>) {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(listener) => listener,
        Err(error) => {
            let message = format!(
                "Could not bind 127.0.0.1:{port}: {error}\n\nAnother process is probably using \
                 that port. Set RENX_MCP_PORT to choose a different one."
            );
            debug_log!("RenX MCP failed to bind 127.0.0.1:{port}: {error}");
            record_server_error(&message);
            let _ = ready.send(Err(message));
            return;
        }
    };
    SERVER_LISTENING.store(true, Ordering::Release);
    record_server_error("");
    let _ = ready.send(Ok(()));
    debug_log!("RenX MCP listening at http://127.0.0.1:{port}/mcp");

    for connection in listener.incoming() {
        // After the accept, not before: a stop wakes this loop *with* a
        // connection, so the flag has to be read once that connection is in hand
        // or the wake-up would be served as a request and the loop would park
        // again.
        if SERVER_STOP.load(Ordering::Acquire)
            || SERVER_GENERATION.load(Ordering::Acquire) != generation
        {
            break;
        }
        match connection {
            Ok(stream) => {
                CONNECTIONS_ACCEPTED.fetch_add(1, Ordering::Relaxed);
                if let Err(error) = handle_connection(stream) {
                    debug_log!("RenX MCP connection error: {error}");
                }
            }
            Err(error) => {
                record_server_error(&format!("accept failed: {error}"));
                debug_log!("RenX MCP accept error: {error}");
            }
        }
    }
    SERVER_LISTENING.store(false, Ordering::Release);
    debug_log!("RenX MCP server on port {port} stopped");
}

/// The human-readable report behind "Server Status".
///
/// It answers the two questions someone actually opens it for - "is it up" and
/// "what do I point the client at" - before any of the diagnostics, and it names
/// the policy mode because a bridge that is up but read-only looks identical to
/// a broken one from the client's side.
pub(crate) fn status_report() -> String {
    let port = SERVER_PORT.load(Ordering::Relaxed);
    let listening = SERVER_LISTENING.load(Ordering::Acquire);
    let editor_ready = EDITOR_THIS.load(Ordering::Acquire) != 0;
    let error = last_server_error();

    let mut report = String::new();
    if policy::confirmations_suppressed() {
        report.push_str(
            "*** DANGEROUS MODE ***\nNothing will ask you before it runs. No prompts, no size \
             limit, no rate limit.\nEverything is still recorded in the audit log below.\n\n",
        );
    }
    report.push_str(if listening {
        "Server:  RUNNING\n"
    } else {
        "Server:  STOPPED\n"
    });
    report.push_str(&format!("Policy:  {} mode\n", policy::current_mode().id()));
    report.push_str(&format!(
        "Editor:  {}\n",
        if editor_ready {
            "ready - the bridge has reached UUnrealEdEngine::Tick"
        } else {
            "not ready - no editor tick seen yet"
        }
    ));

    report.push_str("\nConnection points\n");
    if listening {
        report.push_str(&format!("  MCP endpoint     http://127.0.0.1:{port}/mcp\n"));
        report.push_str(&format!(
            "  Policy control   http://127.0.0.1:{port}/control/policy  (GET, POST)\n"
        ));
    } else {
        report.push_str("  none - the server is not listening\n");
    }
    report.push_str("  Bind address     127.0.0.1 (loopback only; not reachable from the network)\n");
    report.push_str(&format!(
        "  Port             {port} ({})\n",
        if std::env::var("RENX_MCP_PORT").is_ok() {
            "from RENX_MCP_PORT"
        } else {
            "default; override with RENX_MCP_PORT"
        }
    ));

    report.push_str("\nActivity\n");
    report.push_str(&format!(
        "  Connections      {}\n  Tool calls       {}\n  Policy refusals  {}\n  Rate blocks      \
         {}\n  Editor ticks     {}\n",
        CONNECTIONS_ACCEPTED.load(Ordering::Relaxed),
        TOOL_CALLS.load(Ordering::Relaxed),
        POLICY_REFUSALS.load(Ordering::Relaxed),
        guard::rate_blocks(),
        TICK_COUNT.load(Ordering::Relaxed),
    ));

    // The number that matters after something went wrong: how many times to
    // press Ctrl+Z to put the map back the way it was.
    report.push_str(&format!(
        "\nChanges this session\n  Undoable edits   {}  (each is one step in the editor's Undo \
         history)\n  Mutation budget  {}\n",
        MUTATIONS_APPLIED.load(Ordering::Relaxed),
        guard::rate_usage(),
    ));

    report.push_str(&format!(
        "\nProcess {}\nPolicy file {}\nAudit log   {} ({} entries this session)\n",
        std::process::id(),
        policy::policy_file_path().to_string_lossy(),
        audit::path().to_string_lossy(),
        audit::entries_written(),
    ));

    if !error.is_empty() {
        report.push_str(&format!("\nLast error\n  {error}\n"));
    }
    report
}

/// One line for the panel, where there is no room for the full report.
pub(crate) fn status_line() -> String {
    let port = SERVER_PORT.load(Ordering::Relaxed);
    if SERVER_LISTENING.load(Ordering::Acquire) {
        if policy::confirmations_suppressed() {
            return format!("Running - http://127.0.0.1:{port}/mcp   (!) DANGEROUS - nothing asks");
        }
        format!("Running - http://127.0.0.1:{port}/mcp")
    } else if last_server_error().is_empty() {
        "Stopped - nothing can reach the editor".to_string()
    } else {
        format!("Stopped - port {port} could not be bound")
    }
}

pub(crate) fn server_running() -> bool {
    SERVER_LISTENING.load(Ordering::Acquire)
}

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = match read_http_request(&mut stream) {
        Ok(request) => request,
        Err(message) => return write_http(&mut stream, 400, "text/plain", &message),
    };

    let path = request.path.split('?').next().unwrap_or("");
    if !matches!(path, "/mcp" | "/control/policy") {
        return write_http(&mut stream, 404, "text/plain", "no such endpoint");
    }

    // The control endpoint carries the same origin and bearer checks as /mcp.
    // It is strictly more sensitive - it decides what /mcp may do - so it must
    // never be the easier door.
    if !origin_allowed(request.header("origin")) {
        return write_http(&mut stream, 403, "text/plain", "Origin is not allowed");
    }
    if !authorized(request.header("authorization")) {
        return write_http(&mut stream, 401, "text/plain", "Bearer token required");
    }

    if path == "/control/policy" {
        return handle_control_policy(&mut stream, &request);
    }

    if request.method != "POST" {
        return write_http(&mut stream, 405, "text/plain", "POST /mcp required");
    }
    match handle_json_rpc(&request.body) {
        Some(body) => write_http(&mut stream, 200, "application/json", &body),
        None => write_http(&mut stream, 202, "application/json", ""),
    }
}

/// The surface a GUI drives.
///
/// `GET` returns the whole policy - current mode, every mode with its
/// description, every capability with its description and destructive flag - so
/// a panel can render the mode picker and the advanced menu without hardcoding
/// a list that would drift from [`policy`].
///
/// `POST` takes `{"mode":"context"}`, `{"capabilities":{"exec.command":false}}`,
/// or both, and returns the resulting policy so the GUI can redraw from the
/// authoritative answer rather than assuming its request applied verbatim -
/// which matters because editing a preset's bits moves it to `custom`.
fn handle_control_policy(stream: &mut TcpStream, request: &HttpRequest) -> std::io::Result<()> {
    match request.method.as_str() {
        "GET" => write_http(stream, 200, "application/json", &policy::policy_json()),
        "POST" => {
            let change = match policy::plan(&request.body) {
                Ok(change) => change,
                Err(message) => {
                    return write_http(
                        stream,
                        400,
                        "application/json",
                        &format!("{{\"error\":\"{}\"}}", json_escape(&message)),
                    )
                }
            };

            // Everything reaching this endpoint is untrusted: it arrived over
            // the same socket the model uses, so it may well *be* the model
            // asking to widen its own permissions. A policy the caller can
            // rewrite is not a policy.
            // Already in dangerous mode means the operator has said not to be
            // asked. Entering it is the exception: `grants_anything` reports
            // true for that transition even though no capability bit moves, so
            // the one prompt that turns the prompts off is never skipped.
            if change.grants_anything() && !policy::confirmations_suppressed() {
                let decision = request_confirmation(
                    "RenX MCP - Allow this policy change?",
                    change.summary(),
                    "The user did not answer the approval prompt in the editor within two \
                     minutes, so this was treated as a refusal. The policy is unchanged.",
                );
                match decision {
                    Ok(true) => audit::record(
                        audit::Entry::new("policy", "control/policy", audit::Outcome::Ok)
                            .detail(&request.body)
                            .note("approved by the user"),
                    ),
                    Ok(false) => {
                        audit::record(
                            audit::Entry::new("policy", "control/policy", audit::Outcome::Denied)
                                .detail(&request.body)
                                .note("declined by the user"),
                        );
                        return write_http(
                            stream,
                            403,
                            "application/json",
                            &format!(
                                "{{\"error\":\"{}\",\"policy\":{}}}",
                                json_escape(POLICY_CHANGE_DECLINED),
                                policy::policy_json()
                            ),
                        )
                    }
                    Err(message) => {
                        return write_http(
                            stream,
                            503,
                            "application/json",
                            &format!(
                                "{{\"error\":\"{}\",\"policy\":{}}}",
                                json_escape(&message),
                                policy::policy_json()
                            ),
                        )
                    }
                }
            }

            let updated = policy::commit(&change);
            debug_log!("RenX MCP policy changed to {}", policy::current_mode().id());
            write_http(stream, 200, "application/json", &updated)
        }
        _ => write_http(stream, 405, "text/plain", "GET or POST required"),
    }
}

const POLICY_CHANGE_DECLINED: &str =
    "The user declined this policy change in the editor. The policy is unchanged and you still \
     have exactly the capabilities you had before. This was a person's decision, not a fault: do \
     not retry it, do not ask for a different set of permissions to get the same effect, and do \
     not try to reach the same result through another tool. If you believe you need it, say so in \
     conversation and let the user decide.";

/// Asks the human at the editor, and blocks until they answer.
///
/// The prompt has to be raised on the editor thread - it owns the windows - so
/// the request is queued for the tick to pick up, exactly like every other piece
/// of editor work here. A timeout counts as "no", because an unattended editor
/// must not be a way to get past a prompt by waiting.
fn request_confirmation(title: &str, summary: String, on_timeout: &str) -> Result<bool, String> {
    if EDITOR_THIS.load(Ordering::Acquire) == 0 {
        return Err("The editor is not running a frame yet, so the user cannot be asked to \
                    approve this. Nothing was changed."
            .to_string());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    // Cleared as soon as this caller stops listening, whether that is because it
    // got an answer or because it gave up waiting. The tick reads it before
    // raising the prompt, so an abandoned request cannot put a dialog in front
    // of the user minutes later for something nobody is waiting on.
    let waiting = std::sync::Arc::new(AtomicBool::new(true));
    {
        let mut queue = confirmations()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Queued rather than refused. Two prompts is a person answering two
        // questions; refusing the second would fail a concurrent client for a
        // reason that has nothing to do with what it asked.
        if queue.len() >= MAX_QUEUED_CONFIRMATIONS {
            return Err("Too many approval prompts are already waiting for the user. Nothing was \
                        changed."
                .to_string());
        }
        queue.push_back(Confirmation {
            title: title.to_string(),
            summary,
            waiting: waiting.clone(),
            response: sender,
        });
    }
    let answer = receiver.recv_timeout(CONFIRM_TIMEOUT);
    waiting.store(false, Ordering::Release);
    answer.map_err(|_| on_timeout.to_string())
}

struct Confirmation {
    title: String,
    summary: String,
    waiting: std::sync::Arc<AtomicBool>,
    response: SyncSender<bool>,
}

fn confirmations() -> &'static Mutex<VecDeque<Confirmation>> {
    static QUEUE: OnceLock<Mutex<VecDeque<Confirmation>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Raises one pending approval prompt. Called from the tick, so it runs on the
/// thread that owns the editor's windows.
///
/// One per tick: the prompt is modal and stops the editor's loop until it is
/// answered, so there is never a second one to show until this returns anyway.
///
/// A prompt whose asker has already gone - client disconnected, or it timed out
/// and stopped listening - is dropped without being shown. Otherwise a dialog
/// nobody is waiting for appears in front of the user and holds the editor's
/// main loop until they dismiss something they never triggered.
fn drain_confirmations() {
    loop {
        let pending = {
            let mut queue = confirmations()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            queue.pop_front()
        };
        let Some(pending) = pending else {
            return;
        };
        // Nobody is listening any more: skip to the next rather than interrupt
        // the user for a question that can no longer be answered usefully.
        if !pending.waiting.load(Ordering::Acquire) {
            continue;
        }
        let approved = panel::confirm_change(&pending.title, &pending.summary);
        let _ = pending.response.send(approved);
        return;
    }
}

const CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_QUEUED_CONFIRMATIONS: usize = 4;

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut bytes = Vec::new();
    let header_end;
    loop {
        if bytes.len() >= MAX_HTTP_HEADERS {
            return Err("HTTP headers are too large".to_string());
        }
        let mut chunk = [0u8; 4096];
        let count = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("connection closed before HTTP headers".to_string());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
    }

    let header_text = std::str::from_utf8(&bytes[..header_end - 4])
        .map_err(|_| "HTTP headers must be UTF-8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or_else(|| "missing HTTP request line".to_string())?
        .split_whitespace();
    let method = request_line
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?
        .to_string();
    let path = request_line
        .next()
        .ok_or_else(|| "missing HTTP path".to_string())?
        .to_string();
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed HTTP header".to_string())?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    // Absent means no body, which is what a bodyless GET/DELETE sends and what
    // RFC 7230 says to assume. Requiring the header made `GET /control/policy`
    // fail with "Content-Length is required" for every well-formed client - a
    // present-but-unparseable value is still an error, because that is a
    // genuinely malformed request rather than an absent one.
    let content_length = match headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        Some((_, value)) => value
            .parse::<usize>()
            .map_err(|_| "invalid Content-Length".to_string())?,
        None => 0,
    };
    if content_length > MAX_HTTP_BODY {
        return Err("HTTP body is too large".to_string());
    }
    while bytes.len() - header_end < content_length {
        let remaining = content_length - (bytes.len() - header_end);
        let mut chunk = vec![0u8; remaining.min(4096)];
        let count = stream.read(&mut chunk).map_err(|error| error.to_string())?;
        if count == 0 {
            return Err("connection closed before HTTP body".to_string());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let body = String::from_utf8(bytes[header_end..header_end + content_length].to_vec())
        .map_err(|_| "JSON body must be UTF-8".to_string())?;
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn origin_allowed(origin: Option<&str>) -> bool {
    let Some(origin) = origin else {
        return true;
    };
    let lower = origin.to_ascii_lowercase();
    let Some(authority) = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .map(|rest| rest.split('/').next().unwrap_or(rest))
    else {
        return false;
    };
    local_authority(authority, "localhost") || local_authority(authority, "127.0.0.1")
}

fn local_authority(authority: &str, expected_host: &str) -> bool {
    authority == expected_host
        || authority
            .strip_prefix(expected_host)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn authorized(authorization: Option<&str>) -> bool {
    match std::env::var("RENX_MCP_TOKEN") {
        Ok(token) if !token.is_empty() => {
            let expected = format!("Bearer {token}");
            authorization == Some(expected.as_str())
        }
        _ => true,
    }
}

fn write_http(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn handle_json_rpc(body: &str) -> Option<String> {
    let id = json_field_raw(body, "id")?;
    let method = json_field_string(body, "method");
    let result = match method.as_deref() {
        Some("initialize") => Ok(initialize_result()),
        Some("ping") => Ok("{}".to_string()),
        Some("tools/list") => Ok(tools_list_result()),
        Some("tools/call") => tools_call(body),
        Some(other) => Err((-32601, format!("method not found: {other}"))),
        None => Err((-32600, "invalid JSON-RPC request".to_string())),
    };
    Some(match result {
        Ok(result) => format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}"),
        Err((code, message)) => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":\"{}\"}}}}",
            json_escape(&message)
        ),
    })
}

/// Names the active mode in `instructions`.
///
/// The tool list already reflects the policy, but a model that is told *why*
/// the list is short will report the restriction instead of hunting for a way
/// around it. `listChanged` stays false: this transport closes the connection
/// after every response, so there is no channel to push a notification down if
/// the operator changes the mode mid-session.
fn initialize_result() -> String {
    let mode = policy::current_mode();
    format!(
        "{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}},\"serverInfo\":{{\"name\":\"renx-udk-editor\",\"version\":\"0.12.0\"}},\"instructions\":\"Controls the local Renegade X Win64 UDK editor. Actor indices refer to the current selection and can change whenever selection changes. Object paths returned by scene search are stable for the current loaded map. Viewport point inspection returns an exact UE3 scene-view ray; check cameraRay.approximate before trusting a world hit position. Mutation tools participate in UE3 undo transactions.\\n\\nEditor policy mode is '{}': {} Only the tools this mode permits are listed; the operator sets this in the RenX MCP control panel and it cannot be changed through this connection. If a task needs something the mode forbids, say so rather than looking for another route to the same effect.\"}}",
        mode.id(),
        json_escape(mode.describe())
    )
}

/// Which capability each tool needs, for filtering `tools/list` and rejecting
/// `tools/call` early. `renx_actor_action` is absent because its capability
/// depends on the action argument - it is gated per call in
/// [`submit_editor_operation`] instead, and listed whenever any action is
/// permitted.
fn tool_capability(tool: &str) -> Option<policy::Capability> {
    Some(match tool {
        "renx_editor_status" | "renx_get_recent_events" | "renx_get_exception_context" => {
            policy::Capability::ReadStatus
        }
        "renx_get_selection_counts" | "renx_get_selected_actors" => {
            policy::Capability::ReadSelection
        }
        "renx_list_actor_properties"
        | "renx_get_actor_property"
        | "renx_get_object_property" => {
            policy::Capability::ReadProperties
        }
        "renx_get_map_info" | "renx_get_map_health" => policy::Capability::ReadMap,
        "renx_get_pie_status" => policy::Capability::ReadPie,
        "renx_start_pie" | "renx_stop_pie" => policy::Capability::ControlPie,
        "renx_get_viewport_context"
        | "renx_inspect_viewport_point"
        | "renx_capture_viewport" => {
            policy::Capability::ReadViewport
        }
        "renx_focus_viewport_actor" => policy::Capability::ControlViewport,
        "renx_find_actors"
        | "renx_get_asset_usage"
        | "renx_get_missing_asset_diagnostics"
        | "renx_get_reference_graph"
        | "renx_find_actors_in_volume" => policy::Capability::ReadScene,
        "renx_get_change_state" | "renx_capture_editor_state" | "renx_diff_editor_state" => {
            policy::Capability::ReadState
        }
        "renx_get_engine_log" => policy::Capability::ReadLog,
        "renx_set_actor_property" => policy::Capability::WriteActorProperty,
        "renx_set_object_property" => policy::Capability::WriteObjectProperty,
        "renx_exec" => policy::Capability::Exec,
        _ => return None,
    })
}

/// True when at least one of the actions `renx_actor_action` offers is allowed.
fn any_actor_action_allowed() -> bool {
    policy::allows(policy::Capability::WriteTransform)
        || policy::allows(policy::Capability::WriteDuplicate)
        || policy::allows(policy::Capability::WriteDelete)
}

fn tool_permitted(tool: &str) -> bool {
    match tool_capability(tool) {
        Some(capability) => policy::allows(capability),
        None if tool == "renx_actor_action" => any_actor_action_allowed(),
        None => false,
    }
}

/// Advertises only what the current mode permits.
///
/// Filtering here rather than returning everything and failing later is what
/// stops a read-only session from reading like a broken one: the model never
/// sees `renx_exec`, so it never plans around it. The per-call check in
/// [`submit_editor_operation`] remains the actual boundary.
fn tools_list_result() -> String {
    tools_list_with(tool_permitted)
}

/// Split from [`tools_list_result`] so it can be exercised against a chosen
/// policy without writing to the process-wide one, which every other test would
/// then race against.
fn tools_list_with(permitted: impl Fn(&str) -> bool) -> String {
    let mut tools = String::from("{\"tools\":[");
    let mut first = true;
    for (name, definition) in TOOL_DEFINITIONS {
        if !permitted(name) {
            continue;
        }
        if !first {
            tools.push(',');
        }
        first = false;
        tools.push_str(definition);
    }
    tools.push_str("]}");
    tools
}

/// Paired with their names so the list can be filtered without parsing it back.
const TOOL_DEFINITIONS: &[(&str, &str)] = &[
    ("renx_focus_viewport_actor", r#"{"name":"renx_focus_viewport_actor","description":"Move only the active camera to frame a selected actor, an actor at a viewport point, or an exact stable objectPath returned by scene inspection. Does not change selection or the map.","inputSchema":{"type":"object","properties":{"actorIndex":{"type":"integer","minimum":0},"x":{"type":"integer","minimum":0},"y":{"type":"integer","minimum":0},"objectPath":{"type":"string","description":"Exact loaded actor path, such as Map.TheWorld:PersistentLevel.Actor_0."},"selectionToken":{"type":"string"}},"anyOf":[{"required":["actorIndex"]},{"required":["x","y"]},{"required":["objectPath"]}],"additionalProperties":false}}"#),
    ("renx_capture_viewport", r#"{"name":"renx_capture_viewport","description":"Capture the active viewport as a downscaled image. Use only when pixels matter; semantic viewport context is much lighter.","inputSchema":{"type":"object","properties":{"maxWidth":{"type":"integer","minimum":160,"maximum":1280,"default":640}},"additionalProperties":false}}"#),
    ("renx_get_viewport_context", r#"{"name":"renx_get_viewport_context","description":"Read camera pose, center hit, and occlusion-aware visible actors from a bounded adaptive UE3 hit-proxy scan. Use this before the heavier screenshot tool.","inputSchema":{"type":"object","properties":{"gridWidth":{"type":"integer","minimum":3,"maximum":31,"default":17},"gridHeight":{"type":"integer","minimum":3,"maximum":21,"default":11},"maxActors":{"type":"integer","minimum":1,"maximum":100,"default":32},"adaptive":{"type":"boolean","default":true,"description":"Refine cells where actor or proxy identity changes."},"maxSamples":{"type":"integer","minimum":9,"maximum":2048,"default":512,"description":"Hard cap including the initial grid."}},"additionalProperties":false}}"#),
    ("renx_inspect_viewport_point", r#"{"name":"renx_inspect_viewport_point","description":"Inspect one exact viewport pixel through UE3 hit proxies and a native world collision trace. Returns proxy hierarchy, stable actor path and transform, selected index, camera ray, hit location/normal/component/material/level, and proxy details without changing selection.","inputSchema":{"type":"object","properties":{"x":{"type":"integer","minimum":0},"y":{"type":"integer","minimum":0}},"required":["x","y"],"additionalProperties":false}}"#),
    ("renx_find_actors", r#"{"name":"renx_find_actors","description":"Search loaded actors without changing selection. Returns paginated stable object paths, actual classes, levels, maps, and UE3 memory figures. Use a narrow class filter when possible.","inputSchema":{"type":"object","properties":{"class":{"type":"string","default":"Actor","description":"UE3 class; subclasses are included."},"query":{"type":"string","default":"","description":"Case-insensitive substring matched against name, path, or actual class."},"level":{"type":"string","default":"","description":"Optional case-insensitive level-path substring."},"offset":{"type":"integer","minimum":0,"maximum":50000,"default":0},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}},"additionalProperties":false}}"#),
    ("renx_capture_editor_state", r#"{"name":"renx_capture_editor_state","description":"Store a bounded semantic snapshot of the map, loaded actor identities, selection and selected transforms, plus active camera. Returns a stable snapshotId; no map or selection changes are made.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}"#),
    ("renx_diff_editor_state", r#"{"name":"renx_diff_editor_state","description":"Compare two retained semantic editor snapshots, or compare one snapshot with a newly captured current state. Reports map, actor, selection, selected-transform, and camera changes without returning bulky unchanged state.","inputSchema":{"type":"object","properties":{"fromSnapshot":{"type":"string","description":"snapshotId returned by renx_capture_editor_state."},"toSnapshot":{"type":"string","description":"Optional retained snapshotId; omit to capture and compare current state."}},"required":["fromSnapshot"],"additionalProperties":false}}"#),
    ("renx_get_pie_status", r#"{"name":"renx_get_pie_status","description":"Report whether a Play In Editor session is running or queued. Check this before reading or editing anything: while a session runs, property reads see the play world's copy of the map rather than the map on disk, and edits made then are discarded when it ends. pieQueued means a start was requested but has not happened yet.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}"#),
    ("renx_start_pie", r#"{"name":"renx_start_pie","description":"Queue a Play In Editor session on the current map, started from its own PlayerStart. This returns as soon as the request is queued - the editor begins the session on one of its own next frames, so poll renx_get_pie_status until pieActive is true rather than assuming it started.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}"#),
    ("renx_stop_pie", r#"{"name":"renx_stop_pie","description":"End the running Play In Editor session and return the editor to its own world. Anything that happened during play is discarded. Refuses if no session is running.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}"#),
    ("renx_get_recent_events", r#"{"name":"renx_get_recent_events","description":"Read a bounded structured tail of MCP calls, policy refusals, failures, and timings from this editor session. Each call reports ms (total), queueWaitMs (time waiting for the editor thread) and executionMs (time on it), so a slow call can be attributed to a busy editor rather than to the bridge; both are null when the call never crossed to the editor thread. Use sinceSequence to poll incrementally; the durable JSONL audit remains on disk.","inputSchema":{"type":"object","properties":{"sinceSequence":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}},"additionalProperties":false}}"#),
    ("renx_get_exception_context", r#"{"name":"renx_get_exception_context","description":"Read persistent first-chance Windows exception context, register state, possible previous-session crash candidates, and nearby dump artifacts. First-chance records may have been handled and never imply a confirmed crash by themselves.","inputSchema":{"type":"object","properties":{"sinceSequence":{"type":"integer","minimum":0,"default":0},"limit":{"type":"integer","minimum":1,"maximum":64,"default":32},"includePreviousSessions":{"type":"boolean","default":true}},"additionalProperties":false}}"#),
    ("renx_get_change_state", r#"{"name":"renx_get_change_state","description":"Inspect UE3's native undo/redo history and loaded dirty packages without changing either. Undo and redo entries are ordered with the next action first.","inputSchema":{"type":"object","properties":{"historyLimit":{"type":"integer","minimum":1,"maximum":128,"default":32},"includeCleanPackages":{"type":"boolean","default":false},"packageQuery":{"type":"string","default":"","description":"Optional case-insensitive loaded-package path substring."},"packageLimit":{"type":"integer","minimum":1,"maximum":500,"default":100}},"additionalProperties":false}}"#),
    ("renx_get_asset_usage", r#"{"name":"renx_get_asset_usage","description":"Find loaded objects that reference one exact loaded asset/object path using UE3's native reference serializer. Returns external/internal referencers and referencing properties without changing selection.","inputSchema":{"type":"object","properties":{"objectPath":{"type":"string","description":"Exact loaded object path without a class prefix."},"scope":{"type":"string","enum":["all","external","internal"],"default":"all"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}},"required":["objectPath"],"additionalProperties":false}}"#),
    ("renx_find_actors_in_volume", r#"{"name":"renx_find_actors_in_volume","description":"Find loaded actors by position: inside a sphere or box, inside the active viewport's view frustum, or nearest to a point. Tests real attached-component bounds by default, so a large actor whose pivot is outside the volume is still found. Results are sorted nearest first then by path. Makes no selection or map change.","inputSchema":{"type":"object","properties":{"shape":{"type":"string","enum":["sphere","box","frustum","nearest"],"default":"sphere"},"originX":{"type":"number"},"originY":{"type":"number"},"originZ":{"type":"number"},"originActor":{"type":"string","description":"Exact loaded actor path to measure from. Omit both this and originX/Y/Z to use the active viewport camera."},"radius":{"type":"number","default":2048,"description":"Sphere and nearest only."},"extentX":{"type":"number","default":1024,"description":"Box half-size along X."},"extentY":{"type":"number","default":1024},"extentZ":{"type":"number","default":1024},"class":{"type":"string","default":"","description":"Optional UE3 class name; subclasses are included."},"level":{"type":"string","default":"","description":"Optional case-insensitive level-path substring."},"useBounds":{"type":"boolean","default":true,"description":"Test component bounds. Set false to test the actor pivot only."},"lineOfSight":{"type":"boolean","default":false,"description":"Trace from the origin to each returned actor and report what blocks it."},"limit":{"type":"integer","minimum":1,"maximum":200,"default":25},"maxScan":{"type":"integer","minimum":1,"maximum":200000,"default":20000}},"additionalProperties":false}}"#),
    ("renx_get_reference_graph", r#"{"name":"renx_get_reference_graph","description":"Walk the reference graph around one exact loaded object. Outbound edges come from UE3's reflected property export and are cheap to follow; inbound edges come from the native referencer scan, where every hop re-serialises all loaded objects, so inbound depth is bounded by maxInboundScans rather than by maxDepth. Native C++ references are visible inbound but not outbound. Makes no selection or map change.","inputSchema":{"type":"object","properties":{"objectPath":{"type":"string","description":"Exact loaded object path without a class prefix."},"direction":{"type":"string","enum":["outbound","inbound","both"],"default":"outbound"},"classFilter":{"type":"string","default":"","description":"Optional bare UE3 class name; only edges whose far end has this exact class are followed."},"maxDepth":{"type":"integer","minimum":1,"maximum":8,"default":2},"maxNodes":{"type":"integer","minimum":1,"maximum":400,"default":60},"maxInboundScans":{"type":"integer","minimum":1,"maximum":8,"default":1,"description":"How many whole-heap referencer scans this call may spend. Each one can take seconds."}},"required":["objectPath"],"additionalProperties":false}}"#),
    ("renx_get_engine_log", r#"{"name":"renx_get_engine_log","description":"Read a bounded structured tail of the editor's own UE3 log: warnings, errors, script warnings, load/save and build messages, with category, verbosity and sequence. Omit sinceSequence to get the newest lines, then poll with the returned nextSequence. Lines logged before the editor's first tick are not here and categories the engine suppresses never reach it; the on-disk logs cover startup.","inputSchema":{"type":"object","properties":{"sinceSequence":{"type":"integer","minimum":0,"default":0,"description":"Return lines after this sequence. Omit or 0 for the newest page."},"limit":{"type":"integer","minimum":1,"maximum":500,"default":100},"category":{"type":"string","default":"","description":"Optional exact UE3 log category such as Warning, Error, DevLoad, DevSave, or DevShaders."},"minVerbosity":{"type":"string","enum":["log","warning","error"],"default":"log"},"query":{"type":"string","default":"","description":"Optional case-insensitive message substring."}},"additionalProperties":false}}"#),
    ("renx_get_missing_asset_diagnostics", r#"{"name":"renx_get_missing_asset_diagnostics","description":"Scan bounded tails of recent UE3 editor logs for failed asset/package loads and unresolved imports, including referring object/property when UE3 logged them.","inputSchema":{"type":"object","properties":{"query":{"type":"string","default":"","description":"Optional case-insensitive missing path or message substring."},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50},"maxLogFiles":{"type":"integer","minimum":1,"maximum":8,"default":3}},"additionalProperties":false}}"#),
    ("renx_editor_status", "{\"name\":\"renx_editor_status\",\"description\":\"Report whether the Renegade X editor-thread bridge is ready.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_get_selection_counts", "{\"name\":\"renx_get_selection_counts\",\"description\":\"Return selected actor and selected object counts from the editor.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_get_selected_actors", "{\"name\":\"renx_get_selected_actors\",\"description\":\"Return selected actor names, paths, classes, levels, locations, rotations, and scales. Also returns selectionToken: pass it to a later mutation and that mutation is refused if the user changed the selection in between.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_list_actor_properties", "{\"name\":\"renx_list_actor_properties\",\"description\":\"List reflected properties on a selected actor class using UE3 UProperty metadata.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"actorIndex\":{\"type\":\"integer\",\"minimum\":0},\"pattern\":{\"type\":\"string\",\"default\":\"*\",\"description\":\"Property wildcard using * and ?\"}},\"required\":[\"actorIndex\"],\"additionalProperties\":false}}"),
    ("renx_get_actor_property", "{\"name\":\"renx_get_actor_property\",\"description\":\"Export one reflected property from a selected actor through UProperty::ExportText.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"actorIndex\":{\"type\":\"integer\",\"minimum\":0},\"property\":{\"type\":\"string\"}},\"required\":[\"actorIndex\",\"property\"],\"additionalProperties\":false}}"),
    ("renx_get_object_property", r#"{"name":"renx_get_object_property","description":"Read one reflected property from an exact loaded UObject path without changing selection. Paths returned by scene and viewport tools can be passed directly.","inputSchema":{"type":"object","properties":{"objectPath":{"type":"string","description":"Exact loaded object path without a class prefix."},"property":{"type":"string","description":"Reflected UE3 property identifier."}},"required":["objectPath","property"],"additionalProperties":false}}"#),
    ("renx_set_actor_property", "{\"name\":\"renx_set_actor_property\",\"description\":\"Import one reflected property on a selected actor inside an undo transaction.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"actorIndex\":{\"type\":\"integer\",\"minimum\":0},\"property\":{\"type\":\"string\"},\"value\":{\"type\":\"string\"},\"dryRun\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Report what would change without changing it.\"},\"selectionToken\":{\"type\":\"string\",\"description\":\"Token from renx_get_selected_actors; refuses the call if the selection changed since.\"},\"confirmLargeChange\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Required when more than 50 actors are selected. Only pass this after telling the user the count and being told to proceed.\"}},\"required\":[\"actorIndex\",\"property\",\"value\"],\"additionalProperties\":false}}"),
    ("renx_set_object_property", "{\"name\":\"renx_set_object_property\",\"description\":\"Import one reflected property on a UObject path inside an undo transaction.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"objectPath\":{\"type\":\"string\",\"description\":\"UE3 object path without the class prefix\"},\"property\":{\"type\":\"string\"},\"value\":{\"type\":\"string\"},\"dryRun\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Report what would change without changing it.\"}},\"required\":[\"objectPath\",\"property\",\"value\"],\"additionalProperties\":false}}"),
    ("renx_actor_action", "{\"name\":\"renx_actor_action\",\"description\":\"Run an undo-aware native editor action on selected actors. Delete requires confirm=true. Individual actions may be disabled by editor policy.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"duplicate\",\"delete\",\"reset_location\",\"reset_rotation\",\"reset_scale\",\"snap_to_floor\",\"move_to_grid\"]},\"confirm\":{\"type\":\"boolean\",\"default\":false},\"dryRun\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Report what would change without changing it.\"},\"selectionToken\":{\"type\":\"string\",\"description\":\"Token from renx_get_selected_actors; refuses the call if the selection changed since.\"},\"confirmLargeChange\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Required when more than 50 actors are selected. Only pass this after telling the user the count and being told to proceed.\"}},\"required\":[\"action\"],\"additionalProperties\":false}}"),
    ("renx_get_map_info", "{\"name\":\"renx_get_map_info\",\"description\":\"Report the current map inferred from selected actors, selected levels, and UE3 WorldInfo listing.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_get_map_health", r#"{"name":"renx_get_map_health","description":"Run UE3's native Map Check without opening a dialog or clearing existing results, then return bounded structured findings. Does not change selection or map/package contents.","inputSchema":{"type":"object","properties":{"includeSlowReferenceChecks":{"type":"boolean","default":false,"description":"Enable UE3's slower reference checks."},"categories":{"type":"array","items":{"type":"string"},"maxItems":32,"default":[],"description":"Optional exact MapCheck category identifiers such as MatchingLightGUID."},"limit":{"type":"integer","minimum":1,"maximum":500,"default":200}},"additionalProperties":false}}"#),
    ("renx_exec", "{\"name\":\"renx_exec\",\"description\":\"Execute a UE3 editor command on the editor thread and return captured FOutputDevice text. Commands may modify maps and packages. Read-only commands (OBJ LIST, LISTPROPS, GETALL, SHOW, STAT, SELECT, CAMERA, MODE) run directly; anything else raises a prompt in the editor that the user must accept, so expect a delay and a possible refusal.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"UE3 editor Exec command\"},\"dryRun\":{\"type\":\"boolean\",\"default\":false,\"description\":\"Report what would run without running it, and without prompting the user.\"}},\"required\":[\"command\"],\"additionalProperties\":false}}"),
];

/// Records every call, then dispatches it.
///
/// Wrapping rather than sprinkling `audit::record` through the arms: a tool
/// added later is logged whether or not its author remembered to, which is the
/// same reason the policy check lives on the one path to the editor thread.
fn tools_call(body: &str) -> Result<String, (i32, String)> {
    let started = Instant::now();
    // Anything still in the slot belongs to an earlier call on this connection
    // that never reached its own audit line. Dropping it loses a measurement;
    // keeping it would file that measurement under the wrong tool.
    let _ = take_editor_timing();
    let name = json_field_raw(body, "params")
        .and_then(|params| json_field_string(params, "name"))
        .unwrap_or_else(|| "?".to_string());
    let arguments = json_field_raw(body, "params")
        .and_then(|params| json_field_raw(params, "arguments"))
        .unwrap_or("{}")
        .to_string();

    let result = dispatch_tool_call(body);

    let outcome = match &result {
        Ok(payload) if payload.contains("\"isError\":true") => {
            // Matched on the fixed opening words of each refusal, which are
            // constants in this crate rather than anything a caller can supply.
            // A decline counts as denied, not failed: a person said no, and
            // filing that under "something went wrong" would misread the log in
            // exactly the direction that matters.
            if payload.contains("Blocked by MCP policy") || payload.contains("The user declined") {
                audit::Outcome::Denied
            } else if payload.contains("Blocked by the MCP") {
                audit::Outcome::Blocked
            } else {
                audit::Outcome::Failed
            }
        }
        Ok(_) => audit::Outcome::Ok,
        Err(_) => audit::Outcome::Failed,
    };
    let note = match &result {
        Ok(payload) if outcome != audit::Outcome::Ok => first_text_field(payload),
        Err((_, message)) => message.clone(),
        _ => String::new(),
    };
    let mut entry = audit::Entry::new("tool", &name, outcome)
        .detail(&arguments)
        .note(&note)
        .millis(started.elapsed().as_millis() as u64);
    // Note what this does *not* cover: an approval prompt is answered on this
    // thread before anything is queued, so a person taking a minute to click
    // Yes lands in neither half and shows up as bridge overhead. The `note`
    // field says "approved by the user" on exactly those lines.
    if let Some(timing) = take_editor_timing() {
        entry = entry.editor_timing(
            timing.queue_wait.as_millis() as u64,
            timing.execution.as_millis() as u64,
        );
    }
    audit::record(entry);
    result
}

/// Pulls the human-readable message out of a tool payload, for the audit note.
fn first_text_field(payload: &str) -> String {
    let Some(start) = payload.find("\"text\":\"") else {
        return String::new();
    };
    let rest = &payload[start + 8..];
    let mut text = String::new();
    let mut escaped = false;
    for character in rest.chars() {
        if escaped {
            // Decode, rather than skip. Skipping silently deleted every escaped
            // character, which turned "granted.\n\nIf you" into "granted.If you"
            // and would have swallowed any quote or backslash in a property
            // value - in the one field whose whole job is to say what happened.
            text.push(match character {
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                other => other,
            });
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => break,
            _ => text.push(character),
        }
        if text.len() > 300 {
            break;
        }
    }
    text
}

fn dispatch_tool_call(body: &str) -> Result<String, (i32, String)> {
    let params = json_field_raw(body, "params")
        .ok_or_else(|| (-32602, "tools/call requires params".to_string()))?;
    let name = json_field_string(params, "name")
        .ok_or_else(|| (-32602, "tools/call requires a tool name".to_string()))?;

    // Refuse before any argument parsing, so a forbidden tool cannot be probed
    // for what it would have accepted. `renx_actor_action` is not decided here -
    // its capability depends on which action was asked for.
    TOOL_CALLS.fetch_add(1, Ordering::Relaxed);
    if !tool_permitted(&name) {
        POLICY_REFUSALS.fetch_add(1, Ordering::Relaxed);
        if let Some(capability) = tool_capability(&name) {
            return Ok(tool_error(&policy::deny_message(capability)));
        }
        if name == "renx_actor_action" {
            return Ok(tool_error(&policy::deny_message_any(&[
                policy::Capability::WriteTransform,
                policy::Capability::WriteDuplicate,
                policy::Capability::WriteDelete,
            ])));
        }
    }

    match name.as_str() {
        "renx_editor_status" => {
            let ticks = TICK_COUNT.load(Ordering::Relaxed);
            let port = SERVER_PORT.load(Ordering::Relaxed);
            let listening = SERVER_LISTENING.load(Ordering::Acquire);
            let structured = format!(
                "{{\"editorReady\":{},\"listening\":{},\"port\":{port},\"tickCount\":{ticks},\"processId\":{},\"policyMode\":\"{}\"}}",
                EDITOR_THIS.load(Ordering::Acquire) != 0,
                listening,
                std::process::id(),
                policy::current_mode().id()
            );
            Ok(tool_success(&structured))
        }
        "renx_get_recent_events" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let since_sequence = optional_usize(arguments, "sinceSequence")?.unwrap_or(0) as u64;
            let limit = optional_usize(arguments, "limit")?.unwrap_or(audit::DEFAULT_RECENT_LIMIT);
            match audit::recent_json(since_sequence, limit) {
                Ok(structured) => Ok(tool_success(&structured)),
                Err(error) => Err((-32602, error)),
            }
        }
        "renx_get_exception_context" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let since_sequence = optional_usize(arguments, "sinceSequence")?.unwrap_or(0) as u64;
            let limit = optional_usize(arguments, "limit")?.unwrap_or(exceptions::DEFAULT_LIMIT);
            let include_previous_sessions =
                optional_bool(arguments, "includePreviousSessions")?.unwrap_or(true);
            match exceptions::query(since_sequence, limit, include_previous_sessions) {
                Ok(structured) => Ok(tool_success(&structured)),
                Err(error) => Err((-32602, error)),
            }
        }
        // Deliberately answered without the editor thread. The ring lives in
        // this DLL, so the one moment the log matters most - the editor busy or
        // wedged - is the moment a queued editor operation would never return.
        "renx_get_engine_log" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let since_sequence = optional_usize(arguments, "sinceSequence")?.unwrap_or(0) as u64;
            let limit = optional_usize(arguments, "limit")?.unwrap_or(events::DEFAULT_LIMIT);
            let category = json_field_string(arguments, "category").unwrap_or_default();
            let query = json_field_string(arguments, "query").unwrap_or_default();
            let min_verbosity = match json_field_string(arguments, "minVerbosity") {
                Some(value) => events::Verbosity::parse(&value).map_err(|error| (-32602, error))?,
                None => events::Verbosity::Log,
            };
            let filters = events::Filters {
                since_sequence,
                limit,
                category: &category,
                min_verbosity,
                query: &query,
            };
            match events::query(&filters) {
                Ok(structured) => Ok(tool_success(&structured)),
                Err(error) => Err((-32602, error)),
            }
        }
        "renx_get_missing_asset_diagnostics" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let query = json_field_string(arguments, "query").unwrap_or_default();
            let limit = optional_usize(arguments, "limit")?.unwrap_or(assets::DEFAULT_MISSING_LIMIT);
            let max_log_files = optional_usize(arguments, "maxLogFiles")?
                .unwrap_or(assets::DEFAULT_LOG_FILES);
            match assets::missing_diagnostics(&query, limit, max_log_files) {
                Ok(structured) => Ok(tool_success(&structured)),
                Err(error) => Err((-32602, error)),
            }
        }
        "renx_get_selection_counts" => {
            match submit_editor_operation(EditorOperation::SelectionCounts) {
                Ok(EditorValue::SelectionCounts { actors, objects }) => Ok(tool_success(&format!(
                    "{{\"actorCount\":{actors},\"objectCount\":{objects},\"selectionToken\":\"{}\"}}",
                    guard::selection_token(actors.max(0) as usize)
                ))),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_selected_actors" => {
            match submit_editor_operation(EditorOperation::SelectedActors) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_list_actor_properties" => {
            let arguments = tool_arguments(params, &name)?;
            let actor_index = required_usize(arguments, "actorIndex")?;
            let pattern =
                json_field_string(arguments, "pattern").unwrap_or_else(|| "*".to_string());
            match submit_editor_operation(EditorOperation::ListActorProperties {
                actor_index,
                pattern,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_actor_property" => {
            let arguments = tool_arguments(params, &name)?;
            let actor_index = required_usize(arguments, "actorIndex")?;
            let property = required_string(arguments, "property")?;
            match submit_editor_operation(EditorOperation::GetActorProperty {
                actor_index,
                property,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_object_property" => {
            let arguments = tool_arguments(params, &name)?;
            let object_path = required_string(arguments, "objectPath")?;
            let property = required_string(arguments, "property")?;
            match submit_editor_operation(EditorOperation::GetObjectProperty {
                object_path,
                property,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_set_actor_property" => {
            let arguments = tool_arguments(params, &name)?;
            let actor_index = required_usize(arguments, "actorIndex")?;
            let property = required_string(arguments, "property")?;
            let value = required_string(arguments, "value")?;
            match submit_guarded(
                EditorOperation::SetActorProperty {
                    actor_index,
                    property,
                    value,
                },
                Guards::from_arguments(arguments),
            ) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_set_object_property" => {
            let arguments = tool_arguments(params, &name)?;
            let object_path = required_string(arguments, "objectPath")?;
            let property = required_string(arguments, "property")?;
            let value = required_string(arguments, "value")?;
            match submit_guarded(
                EditorOperation::SetObjectProperty {
                    object_path,
                    property,
                    value,
                },
                Guards::from_arguments(arguments),
            ) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_actor_action" => {
            let arguments = tool_arguments(params, &name)?;
            let action_name = required_string(arguments, "action")?;
            let action = match action_name.as_str() {
                "duplicate" => ActorAction::Duplicate,
                "delete" => {
                    if json_field_bool(arguments, "confirm") != Some(true)
                        && !policy::confirmations_suppressed()
                    {
                        return Ok(tool_error("delete requires confirm=true"));
                    }
                    ActorAction::Delete
                }
                "reset_location" => ActorAction::ResetLocation,
                "reset_rotation" => ActorAction::ResetRotation,
                "reset_scale" => ActorAction::ResetScale,
                "snap_to_floor" => ActorAction::SnapToFloor,
                "move_to_grid" => ActorAction::MoveToGrid,
                _ => return Err((-32602, format!("unknown actor action: {action_name}"))),
            };
            match submit_guarded(
                EditorOperation::ActorAction { action },
                Guards::from_arguments(arguments),
            ) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_pie_status" => match submit_editor_operation(EditorOperation::PieStatus) {
            Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
            Ok(_) => Err((-32603, "unexpected editor result".to_string())),
            Err(error) => Ok(tool_error(&error)),
        },
        "renx_start_pie" => match submit_editor_operation(EditorOperation::PieStart) {
            Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
            Ok(_) => Err((-32603, "unexpected editor result".to_string())),
            Err(error) => Ok(tool_error(&error)),
        },
        "renx_stop_pie" => match submit_editor_operation(EditorOperation::PieStop) {
            Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
            Ok(_) => Err((-32603, "unexpected editor result".to_string())),
            Err(error) => Ok(tool_error(&error)),
        },
        "renx_get_map_info" => match submit_editor_operation(EditorOperation::MapInfo) {
            Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
            Ok(_) => unreachable!(),
            Err(error) => Ok(tool_error(&error)),
        },
        "renx_get_map_health" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let include_slow_reference_checks =
                optional_bool(arguments, "includeSlowReferenceChecks")?.unwrap_or(false);
            let categories = optional_string_array(arguments, "categories")?;
            let limit = optional_usize(arguments, "limit")?.unwrap_or(health::DEFAULT_LIMIT);
            if !(1..=health::MAX_LIMIT).contains(&limit) {
                return Err((
                    -32602,
                    format!("limit must be between 1 and {}", health::MAX_LIMIT),
                ));
            }
            match submit_editor_operation(EditorOperation::MapHealth {
                include_slow_reference_checks,
                categories,
                limit,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_viewport_context" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let grid_width = optional_usize(arguments, "gridWidth")?
                .unwrap_or(viewport::DEFAULT_GRID_WIDTH);
            let grid_height = optional_usize(arguments, "gridHeight")?
                .unwrap_or(viewport::DEFAULT_GRID_HEIGHT);
            let max_actors = optional_usize(arguments, "maxActors")?
                .unwrap_or(viewport::DEFAULT_MAX_ACTORS);
            let adaptive = optional_bool(arguments, "adaptive")?.unwrap_or(true);
            let initial_samples = grid_width.saturating_mul(grid_height);
            let max_samples = optional_usize(arguments, "maxSamples")?
                .unwrap_or(viewport::DEFAULT_MAX_SAMPLES.max(initial_samples));
            if let Err(error) = viewport::validate_scan(
                grid_width,
                grid_height,
                max_actors,
                max_samples,
            ) {
                return Err((-32602, error));
            }
            match submit_editor_operation(EditorOperation::ViewportContext {
                grid_width,
                grid_height,
                max_actors,
                adaptive,
                max_samples,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_inspect_viewport_point" => {
            let arguments = tool_arguments(params, &name)?;
            let x = i32::try_from(required_usize(arguments, "x")?)
                .map_err(|_| (-32602, "x is too large".to_string()))?;
            let y = i32::try_from(required_usize(arguments, "y")?)
                .map_err(|_| (-32602, "y is too large".to_string()))?;
            match submit_editor_operation(EditorOperation::InspectViewportPoint { x, y }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_capture_viewport" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let max_width = optional_usize(arguments, "maxWidth")?
                .unwrap_or(viewport::DEFAULT_SCREENSHOT_WIDTH);
            if let Err(error) = viewport::validate_screenshot_width(max_width) {
                return Err((-32602, error));
            }
            match submit_editor_operation(EditorOperation::ViewportScreenshot { max_width }) {
                Ok(EditorValue::Image {
                    mime_type,
                    data,
                    metadata,
                }) => Ok(tool_image(mime_type, &data, &metadata)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_focus_viewport_actor" => {
            let arguments = tool_arguments(params, &name)?;
            let actor_index = optional_usize(arguments, "actorIndex")?;
            let x = optional_usize(arguments, "x")?;
            let y = optional_usize(arguments, "y")?;
            let object_path = json_field_string(arguments, "objectPath");
            let source = match (actor_index, x, y, object_path) {
                (Some(index), None, None, None) => ViewportActorSource::Selected(index),
                (None, Some(x), Some(y), None) => ViewportActorSource::ScreenPoint {
                    x: i32::try_from(x)
                        .map_err(|_| (-32602, "x is too large".to_string()))?,
                    y: i32::try_from(y)
                        .map_err(|_| (-32602, "y is too large".to_string()))?,
                },
                (None, None, None, Some(path)) => ViewportActorSource::ObjectPath(path),
                (Some(_), _, _, _) => {
                    return Err((
                        -32602,
                        "use exactly one of actorIndex, x/y, or objectPath".to_string(),
                    ))
                }
                _ => {
                    return Err((
                        -32602,
                        "renx_focus_viewport_actor requires actorIndex, both x and y, or objectPath"
                            .to_string(),
                    ))
                }
            };
            match submit_guarded(
                EditorOperation::FocusViewportActor { source },
                Guards::from_arguments(arguments),
            ) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_find_actors" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let class_name =
                json_field_string(arguments, "class").unwrap_or_else(|| "Actor".to_string());
            let query = json_field_string(arguments, "query").unwrap_or_default();
            let level = json_field_string(arguments, "level").unwrap_or_default();
            let offset = optional_usize(arguments, "offset")?.unwrap_or(0);
            let limit =
                optional_usize(arguments, "limit")?.unwrap_or(scene::DEFAULT_LIMIT);
            if let Err(error) =
                scene::validate_find(&class_name, &query, &level, offset, limit)
            {
                return Err((-32602, error));
            }
            match submit_editor_operation(EditorOperation::FindActors {
                class_name,
                query,
                level,
                offset,
                limit,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_change_state" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let history_limit = optional_usize(arguments, "historyLimit")?
                .unwrap_or(changes::DEFAULT_HISTORY_LIMIT);
            let include_clean_packages =
                optional_bool(arguments, "includeCleanPackages")?.unwrap_or(false);
            let package_query =
                json_field_string(arguments, "packageQuery").unwrap_or_default();
            let package_limit = optional_usize(arguments, "packageLimit")?
                .unwrap_or(changes::DEFAULT_PACKAGE_LIMIT);
            if let Err(error) =
                changes::validate_query(&package_query, history_limit, package_limit)
            {
                return Err((-32602, error));
            }
            match submit_editor_operation(EditorOperation::ChangeState {
                include_clean_packages,
                package_query,
                history_limit,
                package_limit,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_asset_usage" => {
            let arguments = tool_arguments(params, &name)?;
            let object_path = required_string(arguments, "objectPath")?;
            let scope =
                json_field_string(arguments, "scope").unwrap_or_else(|| "all".to_string());
            let limit =
                optional_usize(arguments, "limit")?.unwrap_or(assets::DEFAULT_USAGE_LIMIT);
            if let Err(error) = assets::validate_usage(&scope, limit) {
                return Err((-32602, error));
            }
            match submit_editor_operation(EditorOperation::AssetUsage {
                object_path,
                scope,
                limit,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_find_actors_in_volume" => {
            let arguments = json_field_raw(params, "arguments").unwrap_or("{}");
            let shape_name =
                json_field_string(arguments, "shape").unwrap_or_else(|| "sphere".to_string());
            let shape = spatial::Shape::parse(&shape_name).map_err(|error| (-32602, error))?;
            let coordinates = [
                optional_f64(arguments, "originX")?,
                optional_f64(arguments, "originY")?,
                optional_f64(arguments, "originZ")?,
            ];
            // Partial coordinates are a mistake worth naming rather than
            // silently completing with zeroes.
            let origin = if coordinates.iter().all(Option::is_some) {
                Some([
                    coordinates[0].unwrap_or_default(),
                    coordinates[1].unwrap_or_default(),
                    coordinates[2].unwrap_or_default(),
                ])
            } else if coordinates.iter().any(Option::is_some) {
                return Err((
                    -32602,
                    "originX, originY and originZ must be given together".to_string(),
                ));
            } else {
                None
            };
            let query = spatial::Query {
                shape,
                origin,
                origin_actor: json_field_string(arguments, "originActor").unwrap_or_default(),
                radius: optional_f64(arguments, "radius")?.unwrap_or(2048.0),
                extent: [
                    optional_f64(arguments, "extentX")?.unwrap_or(1024.0),
                    optional_f64(arguments, "extentY")?.unwrap_or(1024.0),
                    optional_f64(arguments, "extentZ")?.unwrap_or(1024.0),
                ],
                class_name: json_field_string(arguments, "class").unwrap_or_default(),
                level: json_field_string(arguments, "level").unwrap_or_default(),
                use_bounds: optional_bool(arguments, "useBounds")?.unwrap_or(true),
                line_of_sight: optional_bool(arguments, "lineOfSight")?.unwrap_or(false),
                limit: optional_usize(arguments, "limit")?.unwrap_or(spatial::DEFAULT_LIMIT),
                max_scan: optional_usize(arguments, "maxScan")?
                    .unwrap_or(spatial::DEFAULT_MAX_SCAN),
            };
            if let Err(error) = spatial::validate(&query) {
                return Err((-32602, error));
            }
            match submit_editor_operation(EditorOperation::SpatialQuery(Box::new(query))) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_reference_graph" => {
            let arguments = tool_arguments(params, &name)?;
            let object_path = required_string(arguments, "objectPath")?;
            let direction = json_field_string(arguments, "direction")
                .unwrap_or_else(|| "outbound".to_string());
            let class_filter = json_field_string(arguments, "classFilter").unwrap_or_default();
            let max_depth =
                optional_usize(arguments, "maxDepth")?.unwrap_or(dependencies::DEFAULT_MAX_DEPTH);
            let max_nodes =
                optional_usize(arguments, "maxNodes")?.unwrap_or(dependencies::DEFAULT_MAX_NODES);
            let max_inbound_scans = optional_usize(arguments, "maxInboundScans")?
                .unwrap_or(dependencies::DEFAULT_INBOUND_SCANS);
            if let Err(error) = dependencies::validate_query(
                &direction,
                &class_filter,
                max_depth,
                max_nodes,
                max_inbound_scans,
            ) {
                return Err((-32602, error));
            }
            match submit_editor_operation(EditorOperation::ReferenceGraph {
                object_path,
                direction,
                class_filter,
                max_depth,
                max_nodes,
                max_inbound_scans,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_capture_editor_state" => {
            match submit_editor_operation(EditorOperation::CaptureEditorState) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_diff_editor_state" => {
            let arguments = tool_arguments(params, &name)?;
            let from_snapshot = required_string(arguments, "fromSnapshot")?;
            let to_snapshot = json_field_string(arguments, "toSnapshot");
            match submit_editor_operation(EditorOperation::DiffEditorState {
                from_snapshot,
                to_snapshot,
            }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_exec" => {
            let arguments = json_field_raw(params, "arguments")
                .ok_or_else(|| (-32602, "renx_exec requires arguments".to_string()))?;
            let command = json_field_string(arguments, "command").ok_or_else(|| {
                (
                    -32602,
                    "renx_exec requires string argument 'command'".to_string(),
                )
            })?;
            match submit_guarded(
                EditorOperation::Exec(command),
                Guards::from_arguments(arguments),
            ) {
                Ok(EditorValue::ExecResult { handled, output }) => Ok(tool_success(&format!(
                    "{{\"handled\":{handled},\"output\":\"{}\"}}",
                    json_escape(&output)
                ))),
                // A dry run answers with a description instead of running.
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        _ => Err((-32602, format!("unknown tool: {name}"))),
    }
}

fn tool_arguments<'a>(params: &'a str, tool: &str) -> Result<&'a str, (i32, String)> {
    json_field_raw(params, "arguments")
        .ok_or_else(|| (-32602, format!("{tool} requires arguments")))
}

fn required_string(arguments: &str, key: &str) -> Result<String, (i32, String)> {
    json_field_string(arguments, key)
        .ok_or_else(|| (-32602, format!("requires string argument '{key}'")))
}

fn required_usize(arguments: &str, key: &str) -> Result<usize, (i32, String)> {
    json_field_raw(arguments, key)
        .and_then(|raw| raw.parse::<usize>().ok())
        .ok_or_else(|| {
            (
                -32602,
                format!("requires non-negative integer argument '{key}'"),
            )
        })
}

fn optional_usize(arguments: &str, key: &str) -> Result<Option<usize>, (i32, String)> {
    let Some(raw) = json_field_raw(arguments, key) else {
        return Ok(None);
    };
    raw.parse::<usize>().map(Some).map_err(|_| {
        (
            -32602,
            format!("argument '{key}' must be a non-negative integer"),
        )
    })
}

fn optional_f64(arguments: &str, key: &str) -> Result<Option<f64>, (i32, String)> {
    let Some(raw) = json_field_raw(arguments, key) else {
        return Ok(None);
    };
    let value = raw
        .parse::<f64>()
        .map_err(|_| (-32602, format!("argument '{key}' must be a number")))?;
    if !value.is_finite() {
        return Err((-32602, format!("argument '{key}' must be finite")));
    }
    Ok(Some(value))
}

fn optional_bool(arguments: &str, key: &str) -> Result<Option<bool>, (i32, String)> {
    let Some(raw) = json_field_raw(arguments, key) else {
        return Ok(None);
    };
    match raw {
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err((-32602, format!("argument '{key}' must be a boolean"))),
    }
}

fn optional_string_array(arguments: &str, key: &str) -> Result<Vec<String>, (i32, String)> {
    let Some(raw) = json_field_raw(arguments, key) else {
        return Ok(Vec::new());
    };
    let bytes = raw.as_bytes();
    let mut cursor = skip_ws(bytes, 0);
    if bytes.get(cursor) != Some(&b'[') {
        return Err((-32602, format!("argument '{key}' must be an array of strings")));
    }
    cursor += 1;
    let mut values = Vec::new();
    loop {
        cursor = skip_ws(bytes, cursor);
        if bytes.get(cursor) == Some(&b']') {
            cursor = skip_ws(bytes, cursor + 1);
            if cursor == bytes.len() {
                return Ok(values);
            }
            break;
        }
        let Some((value, end)) = parse_json_string(raw, cursor) else {
            break;
        };
        values.push(value);
        if values.len() > 32 {
            return Err((-32602, format!("argument '{key}' has more than 32 entries")));
        }
        cursor = skip_ws(bytes, end);
        match bytes.get(cursor) {
            Some(b',') => cursor += 1,
            Some(b']') => {
                cursor = skip_ws(bytes, cursor + 1);
                if cursor == bytes.len() {
                    return Ok(values);
                }
                break;
            }
            _ => break,
        }
    }
    Err((
        -32602,
        format!("argument '{key}' must be a valid array of strings"),
    ))
}

fn json_field_bool(object: &str, key: &str) -> Option<bool> {
    match json_field_raw(object, key)? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn tool_success(structured: &str) -> String {
    format!(
        "{{\"content\":[{{\"type\":\"text\",\"text\":\"{}\"}}],\"structuredContent\":{structured},\"isError\":false}}",
        json_escape(structured)
    )
}

fn tool_image(mime_type: &str, data: &str, metadata: &str) -> String {
    format!(
        r#"{{"content":[{{"type":"image","data":"{data}","mimeType":"{}"}},{{"type":"text","text":"{}"}}],"structuredContent":{metadata},"isError":false}}"#,
        json_escape(mime_type),
        json_escape(metadata),
    )
}

fn tool_error(message: &str) -> String {
    format!(
        "{{\"content\":[{{\"type\":\"text\",\"text\":\"{}\"}}],\"isError\":true}}",
        json_escape(message)
    )
}

fn json_field_string(object: &str, key: &str) -> Option<String> {
    let raw = json_field_raw(object, key)?;
    let (value, end) = parse_json_string(raw, 0)?;
    if !raw[end..].trim().is_empty() {
        return None;
    }
    Some(value)
}

fn json_field_raw<'a>(object: &'a str, wanted: &str) -> Option<&'a str> {
    let bytes = object.as_bytes();
    let mut index = skip_ws(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return None;
    }
    index += 1;
    loop {
        index = skip_ws(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            return None;
        }
        let (key, next) = parse_json_string(object, index)?;
        index = skip_ws(bytes, next);
        if bytes.get(index) != Some(&b':') {
            return None;
        }
        index = skip_ws(bytes, index + 1);
        let start = index;
        let end = skip_json_value(bytes, start)?;
        if key == wanted {
            return Some(object[start..end].trim());
        }
        index = skip_ws(bytes, end);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => return None,
            _ => return None,
        }
    }
}

fn skip_ws(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        index += 1;
    }
    index
}

fn skip_json_value(bytes: &[u8], index: usize) -> Option<usize> {
    match *bytes.get(index)? {
        b'"' => skip_json_string(bytes, index),
        b'{' | b'[' => {
            let open = bytes[index];
            let close = if open == b'{' { b'}' } else { b']' };
            let mut stack = vec![close];
            let mut cursor = index + 1;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'"' => cursor = skip_json_string(bytes, cursor)?,
                    b'{' => {
                        stack.push(b'}');
                        cursor += 1;
                    }
                    b'[' => {
                        stack.push(b']');
                        cursor += 1;
                    }
                    byte if Some(&byte) == stack.last() => {
                        stack.pop();
                        cursor += 1;
                        if stack.is_empty() {
                            return Some(cursor);
                        }
                    }
                    _ => cursor += 1,
                }
            }
            None
        }
        _ => {
            let mut cursor = index;
            while bytes.get(cursor).is_some_and(|byte| {
                !matches!(byte, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
            }) {
                cursor += 1;
            }
            (cursor > index).then_some(cursor)
        }
    }
}

fn skip_json_string(bytes: &[u8], index: usize) -> Option<usize> {
    if bytes.get(index) != Some(&b'"') {
        return None;
    }
    let mut cursor = index + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => return Some(cursor + 1),
            b'\\' => cursor += 2,
            byte if byte < 0x20 => return None,
            _ => cursor += 1,
        }
    }
    None
}

fn parse_json_string(input: &str, index: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    if bytes.get(index) != Some(&b'"') {
        return None;
    }
    let mut result = String::new();
    let mut cursor = index + 1;
    let mut plain_start = cursor;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => {
                result.push_str(std::str::from_utf8(&bytes[plain_start..cursor]).ok()?);
                return Some((result, cursor + 1));
            }
            b'\\' => {
                result.push_str(std::str::from_utf8(&bytes[plain_start..cursor]).ok()?);
                cursor += 1;
                let escaped = *bytes.get(cursor)?;
                match escaped {
                    b'"' => result.push('"'),
                    b'\\' => result.push('\\'),
                    b'/' => result.push('/'),
                    b'b' => result.push('\u{0008}'),
                    b'f' => result.push('\u{000C}'),
                    b'n' => result.push('\n'),
                    b'r' => result.push('\r'),
                    b't' => result.push('\t'),
                    b'u' => {
                        let end = cursor.checked_add(5)?;
                        let hex = std::str::from_utf8(bytes.get(cursor + 1..end)?).ok()?;
                        let unit = u16::from_str_radix(hex, 16).ok()?;
                        result.push(char::from_u32(unit as u32)?);
                        cursor = end - 1;
                    }
                    _ => return None,
                }
                cursor += 1;
                plain_start = cursor;
            }
            byte if byte < 0x20 => return None,
            _ => cursor += 1,
        }
    }
    None
}

fn json_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            character if character < '\u{20}' => {
                result.push_str(&format!("\\u{:04x}", character as u32))
            }
            _ => result.push(character),
        }
    }
    result
}

pub fn init() -> anyhow::Result<()> {
    if !editor_launch() {
        debug_log!("RenX MCP disabled: UDK.exe was not launched with the editor argument");
        return Ok(());
    }
    let tick = validate_tick_hook()?;
    exceptions::init().context("failed to initialize persistent exception context capture")?;
    unsafe {
        EditorTickHook
            .initialize(tick, |editor, delta_seconds| {
                editor_tick_hook(editor, delta_seconds)
            })
            .context("failed to set up UUnrealEdEngine::Tick MCP hook")?;
        health::init().context("failed to initialize native Map Check capture")?;
        EditorTickHook
            .enable()
            .context("failed to enable UUnrealEdEngine::Tick MCP hook")?;
    }
    debug_log!("RenX MCP editor-thread, Map Check, and exception context capture enabled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        editor_exec_this, handle_json_rpc, json_escape, json_field_raw, json_field_string,
        optional_string_array, origin_allowed, policy, required_capability, spatial,
        tool_capability, tools_list_with, ActorAction, EditorOperation, ViewportActorSource,
    };
    use std::ffi::c_void;

    /// The audit note is extracted from an already-escaped payload, so it has to
    /// decode what it finds. An earlier version skipped escaped characters
    /// instead, which quietly deleted every newline, quote and backslash from
    /// the field whose only job is to record what happened.
    /// A tool that submits twice should be described by one audit line, so the
    /// halves add rather than the last one winning.
    #[test]
    fn editor_timings_accumulate_within_a_call() {
        use std::time::Duration;

        assert!(super::take_editor_timing().is_none());
        super::record_editor_timing(super::EditorTiming {
            queue_wait: Duration::from_millis(30),
            execution: Duration::from_millis(4),
        });
        super::record_editor_timing(super::EditorTiming {
            queue_wait: Duration::from_millis(12),
            execution: Duration::from_millis(9),
        });

        let total = super::take_editor_timing().expect("two operations were recorded");
        assert_eq!(total.queue_wait, Duration::from_millis(42));
        assert_eq!(total.execution, Duration::from_millis(13));

        // Taken, not read: the next call on this connection starts unmeasured,
        // which is what keeps one tool's wait off another tool's line.
        assert!(super::take_editor_timing().is_none());
    }

    /// A timeout is the one case the split cannot describe, so the message has
    /// to carry the distinction instead - and the two must not give the same
    /// advice, which is the whole reason for splitting them.
    #[test]
    fn a_timeout_says_which_of_the_two_things_went_wrong() {
        let budget = std::time::Duration::from_secs(60);
        let never_started = super::timeout_message(false, budget);
        let did_not_finish = super::timeout_message(true, budget);

        assert!(never_started.contains("never started"), "{never_started}");
        assert!(never_started.contains("modal dialog"), "{never_started}");
        assert!(!never_started.contains("Ask for less"), "{never_started}");
        // A menu was measured to defer this work, not stop it, so the message
        // must not send the user hunting for a menu as the likely cause.
        assert!(
            never_started.contains("merely slows it"),
            "{never_started}"
        );

        assert!(did_not_finish.contains("Ask for less"), "{did_not_finish}");
        assert!(
            !did_not_finish.contains("close any open menu"),
            "{did_not_finish}"
        );

        // The two make opposite promises about retrying, and each must only
        // make the one it can keep. A request that never started is genuinely
        // cancelled and cannot apply later; one already underway cannot be
        // recalled and must not invite a second copy of itself.
        assert!(never_started.contains("retrying is safe"), "{never_started}");
        assert!(
            never_started.contains("will NOT run later"),
            "{never_started}"
        );
        assert!(
            did_not_finish.contains("do not retry"),
            "{did_not_finish}"
        );
        assert!(
            !did_not_finish.contains("retrying is safe"),
            "{did_not_finish}"
        );
        for message in [&never_started, &did_not_finish] {
            assert!(message.contains("60 seconds"), "{message}");
        }
    }

    /// The mutation count is what tells a user how far to undo, so a read must
    /// never inflate it - including a read that arrives as an Exec.
    #[test]
    fn read_only_exec_does_not_count_as_a_mutation() {
        assert!(!super::is_mutation(&EditorOperation::Exec(
            "OBJ LIST CLASS=WorldInfo".to_string()
        )));
        assert!(!super::is_mutation(&EditorOperation::Exec(
            "ACTOR SELECT OFCLASS CLASS=StaticMeshActor".to_string()
        )));
        assert!(super::is_mutation(&EditorOperation::Exec(
            "MAP SAVE FILE=x.udk".to_string()
        )));
        assert!(!super::is_mutation(&EditorOperation::MapInfo));
        assert!(!super::is_mutation(&EditorOperation::MapHealth {
            include_slow_reference_checks: false,
            categories: Vec::new(),
            limit: 200,
        }));
        assert!(!super::is_mutation(&EditorOperation::FocusViewportActor {
            source: ViewportActorSource::ScreenPoint { x: 10, y: 20 },
        }));
        assert!(super::is_mutation(&EditorOperation::ActorAction {
            action: ActorAction::Delete
        }));
    }

    #[test]
    fn audit_note_decodes_escapes_rather_than_dropping_them() {
        let payload = r#"{"content":[{"type":"text","text":"line one\n\nsaid \"no\" to C:\\path"}],"isError":true}"#;
        assert_eq!(
            super::first_text_field(payload),
            "line one\n\nsaid \"no\" to C:\\path"
        );
    }

    #[test]
    fn audit_note_is_empty_when_there_is_no_text() {
        assert_eq!(super::first_text_field(r#"{"isError":false}"#), "");
    }

    #[test]
    fn selection_token_is_appended_to_objects_this_module_built() {
        assert_eq!(
            super::with_selection_token(r#"{"actorCount":2}"#, "sel-1-2"),
            r#"{"actorCount":2,"selectionToken":"sel-1-2"}"#
        );
        // An empty object must not gain a stray comma.
        assert_eq!(
            super::with_selection_token("{}", "sel-1-0"),
            r#"{"selectionToken":"sel-1-0"}"#
        );
    }

    #[test]
    fn adjusts_exec_receiver_to_secondary_base() {
        let editor = 0x1000usize as *mut c_void;
        assert_eq!(editor_exec_this(editor).unwrap() as usize, 0x1060);
    }

    #[test]
    fn extracts_nested_json_fields_and_escapes_strings() {
        let input = r#"{"id":7,"params":{"name":"renx_exec","arguments":{"command":"MAP SAVE FILE=\"Test Map\""}}}"#;
        assert_eq!(json_field_raw(input, "id"), Some("7"));
        let params = json_field_raw(input, "params").unwrap();
        let arguments = json_field_raw(params, "arguments").unwrap();
        assert_eq!(
            json_field_string(arguments, "command").as_deref(),
            Some("MAP SAVE FILE=\"Test Map\"")
        );
        assert_eq!(json_escape("a\n\"b\\c"), "a\\n\\\"b\\\\c");
    }

    #[test]
    fn parses_bounded_string_arrays() {
        assert_eq!(
            optional_string_array(
                r#"{"categories":["MatchingLightGUID", "PathNodeInvalidGUID"]}"#,
                "categories"
            )
            .unwrap(),
            vec!["MatchingLightGUID", "PathNodeInvalidGUID"]
        );
        assert!(optional_string_array(r#"{"categories":[1]}"#, "categories").is_err());
        assert!(optional_string_array(r#"{"categories":"warning"}"#, "categories").is_err());
    }

    #[test]
    fn handles_initialize_and_notifications() {
        let response =
            handle_json_rpc(r#"{"jsonrpc":"2.0","id":"abc","method":"initialize","params":{}}"#)
                .unwrap();
        assert!(response.contains(r#""id":"abc""#));
        assert!(response.contains("renx-udk-editor"));
        assert!(
            handle_json_rpc(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none()
        );
    }

    const READ_TOOLS: [&str; 24] = [
        "renx_get_engine_log",
        "renx_get_pie_status",
        "renx_get_viewport_context",
        "renx_inspect_viewport_point",
        "renx_focus_viewport_actor",
        "renx_capture_viewport",
        "renx_find_actors",
        "renx_find_actors_in_volume",
        "renx_capture_editor_state",
        "renx_diff_editor_state",
        "renx_get_recent_events",
        "renx_get_exception_context",
        "renx_get_change_state",
        "renx_get_asset_usage",
        "renx_get_reference_graph",
        "renx_get_missing_asset_diagnostics",
        "renx_editor_status",
        "renx_get_selection_counts",
        "renx_get_selected_actors",
        "renx_list_actor_properties",
        "renx_get_actor_property",
        "renx_get_object_property",
        "renx_get_map_info",
        "renx_get_map_health",
    ];
    const WRITE_TOOLS: [&str; 4] = [
        "renx_set_actor_property",
        "renx_set_object_property",
        "renx_actor_action",
        "renx_exec",
    ];

    #[test]
    fn lists_every_tool_when_everything_is_permitted() {
        let response = tools_list_with(|_| true);
        for tool in READ_TOOLS.iter().chain(WRITE_TOOLS.iter()) {
            assert!(response.contains(tool), "{tool} missing");
        }
    }

    /// The property the whole policy layer exists for: in a read-only mode a
    /// mutation tool is not merely refused, it is never offered.
    #[test]
    fn context_mode_advertises_no_mutation_tools() {
        let response = tools_list_with(|tool| match tool_capability(tool) {
            Some(capability) => capability.is_read_only(),
            None => false, // renx_actor_action: every action mutates
        });
        for tool in READ_TOOLS {
            assert!(response.contains(tool), "{tool} should still be listed");
        }
        for tool in WRITE_TOOLS {
            assert!(!response.contains(tool), "{tool} must not be listed");
        }
    }

    /// Every operation must map to a capability, and no read operation may map
    /// to a write one - the classification is what actually contains a tool that
    /// forgets to check.
    #[test]
    fn operations_are_classified_consistently() {
        use policy::Capability;
        let cases: [(EditorOperation, Capability); 19] = [
            (EditorOperation::SelectionCounts, Capability::ReadSelection),
            (EditorOperation::MapInfo, Capability::ReadMap),
            (
                EditorOperation::MapHealth {
                    include_slow_reference_checks: false,
                    categories: Vec::new(),
                    limit: 200,
                },
                Capability::ReadMap,
            ),
            (
                EditorOperation::ViewportContext {
                    grid_width: 17,
                    grid_height: 11,
                    max_actors: 32,
                    adaptive: true,
                    max_samples: 512,
                },
                Capability::ReadViewport,
            ),
            (
                EditorOperation::InspectViewportPoint { x: 10, y: 20 },
                Capability::ReadViewport,
            ),
            (
                EditorOperation::ViewportScreenshot { max_width: 640 },
                Capability::ReadViewport,
            ),
            (
                EditorOperation::FocusViewportActor {
                    source: ViewportActorSource::Selected(0),
                },
                Capability::ControlViewport,
            ),
            (
                EditorOperation::Exec("MAP REBUILD".to_string()),
                Capability::Exec,
            ),
            (
                EditorOperation::ActorAction {
                    action: ActorAction::Delete,
                },
                Capability::WriteDelete,
            ),
            (
                EditorOperation::ActorAction {
                    action: ActorAction::SnapToFloor,
                },
                Capability::WriteTransform,
            ),
            (
                EditorOperation::SetObjectProperty {
                    object_path: "a".to_string(),
                    property: "b".to_string(),
                    value: "c".to_string(),
                },
                Capability::WriteObjectProperty,
            ),
            (
                EditorOperation::GetObjectProperty {
                    object_path: "a".to_string(),
                    property: "b".to_string(),
                },
                Capability::ReadProperties,
            ),
            (
                EditorOperation::FindActors {
                    class_name: "Actor".to_string(),
                    query: String::new(),
                    level: String::new(),
                    offset: 0,
                    limit: 50,
                },
                Capability::ReadScene,
            ),
            (
                EditorOperation::AssetUsage {
                    object_path: "Pkg.Asset".to_string(),
                    scope: "all".to_string(),
                    limit: 50,
                },
                Capability::ReadScene,
            ),
            (
                EditorOperation::SpatialQuery(Box::new(spatial::Query {
                    shape: spatial::Shape::Sphere,
                    origin: Some([0.0, 0.0, 0.0]),
                    origin_actor: String::new(),
                    radius: 1024.0,
                    extent: [1024.0, 1024.0, 1024.0],
                    class_name: String::new(),
                    level: String::new(),
                    use_bounds: true,
                    line_of_sight: false,
                    limit: 25,
                    max_scan: 20_000,
                })),
                Capability::ReadScene,
            ),
            (
                EditorOperation::ReferenceGraph {
                    object_path: "Pkg.Asset".to_string(),
                    direction: "outbound".to_string(),
                    class_filter: String::new(),
                    max_depth: 2,
                    max_nodes: 60,
                    max_inbound_scans: 1,
                },
                Capability::ReadScene,
            ),
            (
                EditorOperation::ChangeState {
                    include_clean_packages: false,
                    package_query: String::new(),
                    history_limit: 32,
                    package_limit: 100,
                },
                Capability::ReadState,
            ),
            (EditorOperation::CaptureEditorState, Capability::ReadState),
            (
                EditorOperation::DiffEditorState {
                    from_snapshot: "state-1".to_string(),
                    to_snapshot: None,
                },
                Capability::ReadState,
            ),
        ];
        for (operation, expected) in cases {
            let actual = required_capability(&operation);
            assert!(actual == expected, "{} misclassified", expected.id());
        }
    }

    /// A denial has to say which switch would lift it, and has to steer away
    /// from the obvious workaround.
    #[test]
    fn denial_names_the_capability_and_discourages_routing_around_it() {
        let message = policy::deny_message(policy::Capability::WriteDelete);
        assert!(message.contains("write.delete"));
        assert!(message.contains("another tool"));
    }

    #[test]
    fn only_allows_exact_loopback_origins() {
        assert!(origin_allowed(None));
        assert!(origin_allowed(Some("http://localhost:3000")));
        assert!(origin_allowed(Some("https://127.0.0.1")));
        assert!(!origin_allowed(Some("null")));
        assert!(!origin_allowed(Some("http://localhost.example.com")));
        assert!(!origin_allowed(Some("https://127.0.0.1.example.com")));
    }
}
