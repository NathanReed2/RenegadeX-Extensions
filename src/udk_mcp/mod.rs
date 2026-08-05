//! Loopback MCP bridge for the Win64 Renegade X editor.
//!
//! Function RVAs were mapped with the live Ghidra MCP instance by comparing
//! the symbolized UDK source build with the RenXSDK target. Unreal calls are
//! drained by `UUnrealEdEngine::Tick`, so they run on the editor thread.

use anyhow::{bail, Context};
use retour::static_detour;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

pub mod panel;
pub mod policy;

const DEFAULT_PORT: u16 = 8765;
const MAX_HTTP_BODY: usize = 1024 * 1024;
const MAX_HTTP_HEADERS: usize = 64 * 1024;
const MAX_QUEUED_REQUESTS: usize = 128;
const MAX_COMMAND_UNITS: usize = 4096;
const MAX_CAPTURE_UNITS: usize = 1024 * 1024;
const MAX_SELECTED_ACTORS: i32 = 16_384;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

const EDITOR_TICK_RVA: usize = 0x013C_6960;
const EDITOR_EXEC_RVA: usize = 0x013C_EA70;
// `UUnrealEdEngine::Exec` is emitted for the secondary FExec base. Ghidra
// shows that its parent call subtracts 0x60 before accessing UEditorEngine.
const EDITOR_EXEC_THIS_OFFSET: usize = 0x60;
const GET_SELECTED_ACTORS_RVA: usize = 0x0126_6530;
const GET_SELECTED_OBJECTS_RVA: usize = 0x0126_6540;
const SELECTION_NUM_RVA: usize = 0x0017_C3A0;
const UOBJECT_STATIC_EXEC_RVA: usize = 0x0027_BBA0;
const UOBJECT_GET_NAME_RVA: usize = 0x0005_7AA0;
const UOBJECT_GET_FULL_NAME_RVA: usize = 0x0026_8A30;
const APP_FREE_RVA: usize = 0x001C_AFE0;
const BEGIN_TRANSACTION_RVA: usize = 0x0128_8A90;
const END_TRANSACTION_RVA: usize = 0x0128_8AB0;

const UOBJECT_OUTER_OFFSET: usize = 0x40;
const UOBJECT_CLASS_OFFSET: usize = 0x50;
const USELECTION_OBJECTS_OFFSET: usize = 0x60;
const USELECTION_COUNT_OFFSET: usize = 0x68;
const ACTOR_LOCATION_OFFSET: usize = 0x80;
const ACTOR_ROTATION_OFFSET: usize = 0x8C;
const ACTOR_DRAW_SCALE_OFFSET: usize = 0x98;
const ACTOR_DRAW_SCALE3D_OFFSET: usize = 0x9C;

const EDITOR_TICK_PROLOGUE: &[u8] = &[
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x0F, 0x29, 0x74, 0x24, 0x20, 0x48,
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

struct EditorRequest {
    operation: EditorOperation,
    response: SyncSender<Result<EditorValue, String>>,
}

enum EditorValue {
    ExecResult { handled: bool, output: String },
    SelectionCounts { actors: i32, objects: i32 },
    Json(String),
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
    start_server_once();
    drain_editor_requests(editor);

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
        let result = execute_editor_operation(editor, request.operation);
        let _ = request.response.send(result);
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

unsafe fn read_pointer(object: *mut c_void, offset: usize) -> *mut c_void {
    *((object as *const u8).add(offset) as *const *mut c_void)
}

fn unreal_object_string(object: *mut c_void, full: bool) -> Result<String, String> {
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

fn object_path_from_full_name(full_name: &str) -> &str {
    full_name
        .split_once(' ')
        .map_or(full_name, |(_, path)| path)
}

fn validate_identifier(value: &str, pattern: bool) -> Result<(), String> {
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

fn run_editor_exec(editor: *mut c_void, command: &str) -> Result<(bool, String), String> {
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

fn run_static_exec(command: &str) -> Result<(bool, String), String> {
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

fn actor_identity(actor: *mut c_void) -> Result<(String, String, String), String> {
    let name = unreal_object_string(actor, false)?;
    let full_name = unreal_object_string(actor, true)?;
    let class = unsafe { read_pointer(actor, UOBJECT_CLASS_OFFSET) };
    let class_name = unreal_object_string(class, false)?;
    Ok((name, full_name, class_name))
}

fn actor_json(index: usize, actor: *mut c_void) -> Result<String, String> {
    let (name, full_name, class_name) = actor_identity(actor)?;
    let outer = unsafe { read_pointer(actor, UOBJECT_OUTER_OFFSET) };
    let level = unreal_object_string(outer, true)?;
    let location = unsafe { *((actor as *const u8).add(ACTOR_LOCATION_OFFSET) as *const Vector3) };
    let rotation = unsafe { *((actor as *const u8).add(ACTOR_ROTATION_OFFSET) as *const Rotator) };
    let draw_scale = unsafe { *((actor as *const u8).add(ACTOR_DRAW_SCALE_OFFSET) as *const f32) };
    let draw_scale3d =
        unsafe { *((actor as *const u8).add(ACTOR_DRAW_SCALE3D_OFFSET) as *const Vector3) };
    Ok(format!(
        "{{\"index\":{index},\"name\":\"{}\",\"path\":\"{}\",\"fullName\":\"{}\",\"class\":\"{}\",\"level\":\"{}\",\"location\":{{\"x\":{},\"y\":{},\"z\":{}}},\"rotation\":{{\"pitch\":{},\"yaw\":{},\"roll\":{}}},\"scale\":{{\"uniform\":{},\"x\":{},\"y\":{},\"z\":{}}}}}",
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
            let transaction_name = widestring::U16CString::from_str("MCP Set Actor Property")
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
            let transaction_name = widestring::U16CString::from_str("MCP Set Object Property")
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
        EditorOperation::ListActorProperties { .. } | EditorOperation::GetActorProperty { .. } => {
            policy::Capability::ReadProperties
        }
        EditorOperation::SetActorProperty { .. } => policy::Capability::WriteActorProperty,
        EditorOperation::SetObjectProperty { .. } => policy::Capability::WriteObjectProperty,
        EditorOperation::MapInfo => policy::Capability::ReadMap,
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
    // Before the readiness check and before anything is queued: a denied
    // operation must never reach the editor thread, and must not be able to
    // distinguish "forbidden" from "editor busy" by the error it gets back.
    let capability = required_capability(&operation);
    if !policy::allows(capability) {
        POLICY_REFUSALS.fetch_add(1, Ordering::Relaxed);
        return Err(policy::deny_message(capability));
    }
    if EDITOR_THIS.load(Ordering::Acquire) == 0 {
        return Err("The editor is still starting up and has not run a frame yet. This is not a \
                    policy refusal - retry in a few seconds."
            .to_string());
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    {
        let mut queue = request_queue()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if queue.len() >= MAX_QUEUED_REQUESTS {
            return Err("the editor request queue is full".to_string());
        }
        queue.push_back(EditorRequest {
            operation,
            response: sender,
        });
    }
    // Work is done on the editor's own thread, which only runs it between
    // frames. Anything that suspends the editor's loop - an open menu, a modal
    // dialog, a long import or build - stops that thread from getting here, and
    // the symptom is this timeout. Saying so matters because the alternative
    // reading is "the bridge is broken", which it is not.
    receiver.recv_timeout(REQUEST_TIMEOUT).map_err(|_| {
        "The editor did not process this within the timeout. This is not a policy refusal and not \
         a bridge fault: the editor runs bridge work between frames, so anything holding its main \
         loop - an open menu, a modal dialog, or a long operation such as a build or import - \
         defers it. Ask the user to close any open menu or dialog in the editor, then retry."
            .to_string()
    })?
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
        "  Connections      {}\n  Tool calls       {}\n  Policy refusals  {}\n  Editor ticks     \
         {}\n",
        CONNECTIONS_ACCEPTED.load(Ordering::Relaxed),
        TOOL_CALLS.load(Ordering::Relaxed),
        POLICY_REFUSALS.load(Ordering::Relaxed),
        TICK_COUNT.load(Ordering::Relaxed),
    ));

    report.push_str(&format!(
        "\nProcess {}\nPolicy file {}\n",
        std::process::id(),
        policy::policy_file_path().to_string_lossy()
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
        "POST" => match policy::apply(&request.body) {
            Ok(updated) => {
                debug_log!("RenX MCP policy changed to {}", policy::current_mode().id());
                write_http(stream, 200, "application/json", &updated)
            }
            Err(message) => write_http(
                stream,
                400,
                "application/json",
                &format!("{{\"error\":\"{}\"}}", json_escape(&message)),
            ),
        },
        _ => write_http(stream, 405, "text/plain", "GET or POST required"),
    }
}

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
        "{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}},\"serverInfo\":{{\"name\":\"renx-udk-editor\",\"version\":\"0.3.0\"}},\"instructions\":\"Controls the local Renegade X Win64 UDK editor. Actor indices refer to the current selection and can change whenever selection changes. Mutation tools participate in UE3 undo transactions.\\n\\nEditor policy mode is '{}': {} Only the tools this mode permits are listed; the operator sets this in the RenX MCP control panel and it cannot be changed through this connection. If a task needs something the mode forbids, say so rather than looking for another route to the same effect.\"}}",
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
        "renx_editor_status" => policy::Capability::ReadStatus,
        "renx_get_selection_counts" | "renx_get_selected_actors" => {
            policy::Capability::ReadSelection
        }
        "renx_list_actor_properties" | "renx_get_actor_property" => {
            policy::Capability::ReadProperties
        }
        "renx_get_map_info" => policy::Capability::ReadMap,
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
    ("renx_editor_status", "{\"name\":\"renx_editor_status\",\"description\":\"Report whether the Renegade X editor-thread bridge is ready.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_get_selection_counts", "{\"name\":\"renx_get_selection_counts\",\"description\":\"Return selected actor and selected object counts from the editor.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_get_selected_actors", "{\"name\":\"renx_get_selected_actors\",\"description\":\"Return selected actor names, paths, classes, levels, locations, rotations, and scales.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_list_actor_properties", "{\"name\":\"renx_list_actor_properties\",\"description\":\"List reflected properties on a selected actor class using UE3 UProperty metadata.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"actorIndex\":{\"type\":\"integer\",\"minimum\":0},\"pattern\":{\"type\":\"string\",\"default\":\"*\",\"description\":\"Property wildcard using * and ?\"}},\"required\":[\"actorIndex\"],\"additionalProperties\":false}}"),
    ("renx_get_actor_property", "{\"name\":\"renx_get_actor_property\",\"description\":\"Export one reflected property from a selected actor through UProperty::ExportText.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"actorIndex\":{\"type\":\"integer\",\"minimum\":0},\"property\":{\"type\":\"string\"}},\"required\":[\"actorIndex\",\"property\"],\"additionalProperties\":false}}"),
    ("renx_set_actor_property", "{\"name\":\"renx_set_actor_property\",\"description\":\"Import one reflected property on a selected actor inside an undo transaction.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"actorIndex\":{\"type\":\"integer\",\"minimum\":0},\"property\":{\"type\":\"string\"},\"value\":{\"type\":\"string\"}},\"required\":[\"actorIndex\",\"property\",\"value\"],\"additionalProperties\":false}}"),
    ("renx_set_object_property", "{\"name\":\"renx_set_object_property\",\"description\":\"Import one reflected property on a UObject path inside an undo transaction.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"objectPath\":{\"type\":\"string\",\"description\":\"UE3 object path without the class prefix\"},\"property\":{\"type\":\"string\"},\"value\":{\"type\":\"string\"}},\"required\":[\"objectPath\",\"property\",\"value\"],\"additionalProperties\":false}}"),
    ("renx_actor_action", "{\"name\":\"renx_actor_action\",\"description\":\"Run an undo-aware native editor action on selected actors. Delete requires confirm=true. Individual actions may be disabled by editor policy.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"action\":{\"type\":\"string\",\"enum\":[\"duplicate\",\"delete\",\"reset_location\",\"reset_rotation\",\"reset_scale\",\"snap_to_floor\",\"move_to_grid\"]},\"confirm\":{\"type\":\"boolean\",\"default\":false}},\"required\":[\"action\"],\"additionalProperties\":false}}"),
    ("renx_get_map_info", "{\"name\":\"renx_get_map_info\",\"description\":\"Report the current map inferred from selected actors, selected levels, and UE3 WorldInfo listing.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}"),
    ("renx_exec", "{\"name\":\"renx_exec\",\"description\":\"Execute a UE3 editor command on the editor thread and return captured FOutputDevice text. Commands may modify maps and packages.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\",\"description\":\"UE3 editor Exec command\"}},\"required\":[\"command\"],\"additionalProperties\":false}}"),
];

fn tools_call(body: &str) -> Result<String, (i32, String)> {
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
        "renx_get_selection_counts" => {
            match submit_editor_operation(EditorOperation::SelectionCounts) {
                Ok(EditorValue::SelectionCounts { actors, objects }) => Ok(tool_success(&format!(
                    "{{\"actorCount\":{actors},\"objectCount\":{objects}}}"
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
        "renx_set_actor_property" => {
            let arguments = tool_arguments(params, &name)?;
            let actor_index = required_usize(arguments, "actorIndex")?;
            let property = required_string(arguments, "property")?;
            let value = required_string(arguments, "value")?;
            match submit_editor_operation(EditorOperation::SetActorProperty {
                actor_index,
                property,
                value,
            }) {
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
            match submit_editor_operation(EditorOperation::SetObjectProperty {
                object_path,
                property,
                value,
            }) {
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
                    if json_field_bool(arguments, "confirm") != Some(true) {
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
            match submit_editor_operation(EditorOperation::ActorAction { action }) {
                Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
                Ok(_) => unreachable!(),
                Err(error) => Ok(tool_error(&error)),
            }
        }
        "renx_get_map_info" => match submit_editor_operation(EditorOperation::MapInfo) {
            Ok(EditorValue::Json(structured)) => Ok(tool_success(&structured)),
            Ok(_) => unreachable!(),
            Err(error) => Ok(tool_error(&error)),
        },
        "renx_exec" => {
            let arguments = json_field_raw(params, "arguments")
                .ok_or_else(|| (-32602, "renx_exec requires arguments".to_string()))?;
            let command = json_field_string(arguments, "command").ok_or_else(|| {
                (
                    -32602,
                    "renx_exec requires string argument 'command'".to_string(),
                )
            })?;
            match submit_editor_operation(EditorOperation::Exec(command)) {
                Ok(EditorValue::ExecResult { handled, output }) => Ok(tool_success(&format!(
                    "{{\"handled\":{handled},\"output\":\"{}\"}}",
                    json_escape(&output)
                ))),
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
    unsafe {
        EditorTickHook
            .initialize(tick, |editor, delta_seconds| {
                editor_tick_hook(editor, delta_seconds)
            })
            .context("failed to set up UUnrealEdEngine::Tick MCP hook")?;
        EditorTickHook
            .enable()
            .context("failed to enable UUnrealEdEngine::Tick MCP hook")?;
    }
    debug_log!("RenX MCP editor-thread hook enabled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        editor_exec_this, handle_json_rpc, json_escape, json_field_raw, json_field_string,
        origin_allowed, policy, required_capability, tool_capability, tools_list_with, ActorAction,
        EditorOperation,
    };
    use std::ffi::c_void;

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

    const READ_TOOLS: [&str; 6] = [
        "renx_editor_status",
        "renx_get_selection_counts",
        "renx_get_selected_actors",
        "renx_list_actor_properties",
        "renx_get_actor_property",
        "renx_get_map_info",
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
        let cases: [(EditorOperation, Capability); 6] = [
            (EditorOperation::SelectionCounts, Capability::ReadSelection),
            (EditorOperation::MapInfo, Capability::ReadMap),
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
