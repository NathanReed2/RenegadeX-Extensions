//! Active level-viewport inspection and camera navigation.
//!
//! UE3 already renders a hit-proxy buffer for editor picking. Sampling that
//! buffer is both more faithful and much cheaper than asking a model to infer
//! an entire scene from pixels: it is occlusion aware, returns real AActor
//! pointers, and only renders the buffer once when its cache is stale.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;

use windows::Win32::Foundation::{HANDLE, HWND, RECT};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC, SelectObject,
    SetStretchBltMode, StretchBlt, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HALFTONE,
    SRCCOPY,
};
use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

use super::{
    actor_data_json, actor_identity, actor_json, find_actor_by_path, image_address, json_escape,
    Rotator, Vector3,
};

const ACTIVE_LEVEL_VIEWPORT_CLIENT_RVA: usize = 0x036B_9ED0;
const GET_HIT_PROXY_RVA: usize = 0x005C_1D80;
const MOVE_VIEWPORT_TO_ACTOR_RVA: usize = 0x0129_1F80;
const SINGLE_LINE_CHECK_RVA: usize = 0x0072_9860;
const GWORLD_RVA: usize = 0x0369_13D8;

const CLIENT_VIEWPORT_OFFSET: usize = 0x20;
const CLIENT_LOCATION_OFFSET: usize = 0x28;
const CLIENT_ROTATION_OFFSET: usize = 0x40;
const CLIENT_FOV_OFFSET: usize = 0x4C;
const CLIENT_TYPE_OFFSET: usize = 0x50;
const CLIENT_ORTHO_ZOOM_OFFSET: usize = 0x54;
const EDITOR_VIEWPORT_CLIENTS_OFFSET: usize = 0x97C;
const EDITOR_VIEWPORT_CLIENT_COUNT_OFFSET: usize = 0x984;
const HIT_PROXY_ACTOR_OFFSET: usize = 0x18;
const HIT_PROXY_GET_TYPE_SLOT: usize = 1;
const GET_SIZE_X_SLOT: usize = 2;
const GET_SIZE_Y_SLOT: usize = 3;
// FWindowsViewport derives FViewportFrame first. The FViewport pointer held by
// the client is the +8 subobject; Window is +0xBC from the complete object.
const VIEWPORT_WINDOW_FROM_VIEWPORT_OFFSET: usize = 0xB4;
const GET_HIT_PROXY_PROLOGUE: &[u8] = &[
    0x40, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83,
    0xEC, 0x50,
];
const MOVE_VIEWPORT_TO_ACTOR_PROLOGUE: &[u8] = &[
    0x40, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF,
    0xFF,
];
const SINGLE_LINE_CHECK_PROLOGUE: &[u8] = &[
    0x48, 0x8B, 0xC4, 0x55, 0x41, 0x54, 0x41, 0x55, 0x48, 0x8B, 0xEC, 0x48, 0x81, 0xEC,
    0x80, 0x00, 0x00, 0x00,
];
const HALF_WORLD_MAX: f32 = 262_144.0;
const TRACE_WORLD_AND_ACTORS_COMPLEX_MATERIAL: u32 = 0x0002_2897;

pub(super) const DEFAULT_GRID_WIDTH: usize = 17;
pub(super) const DEFAULT_GRID_HEIGHT: usize = 11;
pub(super) const DEFAULT_MAX_ACTORS: usize = 32;
pub(super) const DEFAULT_MAX_SAMPLES: usize = 512;
pub(super) const DEFAULT_SCREENSHOT_WIDTH: usize = 640;
pub(super) const MAX_GRID_WIDTH: usize = 31;
pub(super) const MAX_GRID_HEIGHT: usize = 21;
pub(super) const MAX_VISIBLE_ACTORS: usize = 100;
pub(super) const MAX_PROXY_SAMPLES: usize = 2048;
pub(super) const MAX_SCREENSHOT_WIDTH: usize = 1280;
const MAX_ADAPTIVE_DEPTH: u8 = 4;
const MIN_ADAPTIVE_CELL_PIXELS: i32 = 4;

type GetViewportSizeFn = unsafe extern "C" fn(*mut c_void) -> u32;
type GetHitProxyFn = unsafe extern "C" fn(*mut c_void, i32, i32) -> *mut c_void;
type GetHitProxyTypeFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type MoveViewportToActorFn = unsafe extern "C" fn(*mut c_void, *mut c_void, u32);
type SingleLineCheckFn = unsafe extern "C" fn(
    *mut c_void,
    *mut CheckResult,
    *mut c_void,
    *const Vector3,
    *const Vector3,
    u32,
    *const Vector3,
    *mut c_void,
) -> u32;

#[repr(C)]
struct CheckResult {
    next: *mut c_void,
    actor: *mut c_void,
    location: Vector3,
    normal: Vector3,
    time: f32,
    item: i32,
    material: *mut c_void,
    physical_material: *mut c_void,
    component: *mut c_void,
    source_component: *mut c_void,
    bone_name: [u8; 8],
    level: *mut c_void,
    level_index: i32,
    start_penetrating: u32,
}

impl CheckResult {
    fn empty() -> Self {
        Self {
            next: std::ptr::null_mut(),
            actor: std::ptr::null_mut(),
            location: Vector3 { x: 0.0, y: 0.0, z: 0.0 },
            normal: Vector3 { x: 0.0, y: 0.0, z: 0.0 },
            time: 1.0,
            item: -1,
            material: std::ptr::null_mut(),
            physical_material: std::ptr::null_mut(),
            component: std::ptr::null_mut(),
            source_component: std::ptr::null_mut(),
            bone_name: [0; 8],
            level: std::ptr::null_mut(),
            level_index: -1,
            start_penetrating: 0,
        }
    }
}

const _: [(); 0x68] = [(); std::mem::size_of::<CheckResult>()];

struct CameraRay {
    origin: Vector3,
    direction: Vector3,
}

#[derive(Clone)]
pub(super) struct CameraSnapshot {
    pub(super) viewport_type: i32,
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) location: Vector3,
    pub(super) rotation: Rotator,
    pub(super) field_of_view: f32,
    pub(super) ortho_zoom: f32,
}

impl CameraSnapshot {
    pub(super) fn json(&self) -> String {
        format!(
            r#"{{"viewportType":"{}","width":{},"height":{},"location":{{"x":{},"y":{},"z":{}}},"rotation":{{"pitch":{},"yaw":{},"roll":{}}},"fieldOfViewDegrees":{},"orthoZoom":{}}}"#,
            viewport_type_name(self.viewport_type),
            self.width,
            self.height,
            self.location.x,
            self.location.y,
            self.location.z,
            self.rotation.pitch,
            self.rotation.yaw,
            self.rotation.roll,
            self.field_of_view,
            self.ortho_zoom,
        )
    }
}

fn mapped_function(rva: usize, name: &str, prologue: &[u8]) -> Result<usize, String> {
    let address = image_address(rva, prologue.len(), name).map_err(|error| error.to_string())?;
    let actual = unsafe { std::slice::from_raw_parts(address as *const u8, prologue.len()) };
    if actual != prologue {
        return Err(format!(
            "{name} does not match the verified RenXSDK build at RVA 0x{rva:X}; viewport operation was refused"
        ));
    }
    Ok(address)
}

#[derive(Clone)]
struct ProxyInfo {
    raw: *mut c_void,
    proxy_type: String,
    hierarchy: Vec<String>,
    actor: Option<*mut c_void>,
}

impl ProxyInfo {
    fn same_target(&self, other: &Self) -> bool {
        self.proxy_type == other.proxy_type && self.actor == other.actor
    }
}

struct ActorHit {
    actor: *mut c_void,
    proxy_types: HashSet<String>,
    samples: usize,
    min_x: i32,
    min_y: i32,
    max_x: i32,
    max_y: i32,
    focus_x: i32,
    focus_y: i32,
    focus_distance2: i64,
}

unsafe fn read_pointer(object: *mut c_void, offset: usize) -> *mut c_void {
    *((object as *const u8).add(offset) as *const *mut c_void)
}

fn active_client_slot() -> Result<*mut *mut c_void, String> {
    let address = image_address(
        ACTIVE_LEVEL_VIEWPORT_CLIENT_RVA,
        std::mem::size_of::<usize>(),
        "GCurrentLevelEditingViewportClient",
    )
    .map_err(|error| error.to_string())?;
    Ok(address as *mut *mut c_void)
}

fn active_client(editor: *mut c_void) -> Result<(*mut c_void, bool), String> {
    let slot = active_client_slot()?;
    let active = unsafe { *slot };
    if !active.is_null() {
        return Ok((active, true));
    }
    let count = unsafe {
        *((editor as *const u8).add(EDITOR_VIEWPORT_CLIENT_COUNT_OFFSET) as *const i32)
    };
    if !(0..=64).contains(&count) {
        return Err(format!("invalid editor viewport-client count: {count}"));
    }
    let data = unsafe {
        std::ptr::read_unaligned(
            (editor as *const u8).add(EDITOR_VIEWPORT_CLIENTS_OFFSET)
                as *const *const *mut c_void,
        )
    };
    if count == 0 || data.is_null() {
        return Err("the editor has not created a level viewport yet".to_string());
    }
    let clients = unsafe { std::slice::from_raw_parts(data, count as usize) };
    let valid = |client: &&*mut c_void| {
        !client.is_null()
            && !unsafe { read_pointer(**client, CLIENT_VIEWPORT_OFFSET) }.is_null()
    };
    // Prefer perspective for an unambiguous camera/FOV view, then accept any
    // valid ortho viewport if the user's layout contains no perspective pane.
    let client = clients
        .iter()
        .filter(valid)
        .find(|client| unsafe {
            *((**client as *const u8).add(CLIENT_TYPE_OFFSET) as *const i32) == 3
        })
        .or_else(|| clients.iter().find(valid))
        .copied()
        .ok_or_else(|| "the editor has no initialized level viewport".to_string())?;
    Ok((client, false))
}

fn active_viewport(editor: *mut c_void) -> Result<(*mut c_void, *mut c_void, bool), String> {
    let (client, was_active) = active_client(editor)?;
    let viewport = unsafe { read_pointer(client, CLIENT_VIEWPORT_OFFSET) };
    if viewport.is_null() {
        Err("the active level viewport has no FViewport yet".to_string())
    } else {
        Ok((client, viewport, was_active))
    }
}

unsafe fn viewport_size(viewport: *mut c_void) -> Result<(u32, u32), String> {
    let vtable = *(viewport as *const *const *const ());
    if vtable.is_null() {
        return Err("the active FViewport has no vtable".to_string());
    }
    let get_x: GetViewportSizeFn = std::mem::transmute(*vtable.add(GET_SIZE_X_SLOT));
    let get_y: GetViewportSizeFn = std::mem::transmute(*vtable.add(GET_SIZE_Y_SLOT));
    let size = (get_x(viewport), get_y(viewport));
    if size.0 == 0 || size.1 == 0 {
        Err("the active viewport has zero size".to_string())
    } else {
        Ok(size)
    }
}

fn viewport_type_name(value: i32) -> &'static str {
    match value {
        0 => "ortho_xy",
        1 => "ortho_xz",
        2 => "ortho_yz",
        3 => "perspective",
        _ => "unknown",
    }
}

fn camera_json(client: *mut c_void, width: u32, height: u32) -> String {
    let location = unsafe { *((client as *const u8).add(CLIENT_LOCATION_OFFSET) as *const Vector3) };
    let rotation = unsafe { *((client as *const u8).add(CLIENT_ROTATION_OFFSET) as *const Rotator) };
    let fov = unsafe { *((client as *const u8).add(CLIENT_FOV_OFFSET) as *const f32) };
    let viewport_type = unsafe { *((client as *const u8).add(CLIENT_TYPE_OFFSET) as *const i32) };
    let ortho_zoom = unsafe { *((client as *const u8).add(CLIENT_ORTHO_ZOOM_OFFSET) as *const f32) };
    let unit_to_radians = std::f64::consts::TAU / 65_536.0;
    let pitch = rotation.pitch as f64 * unit_to_radians;
    let yaw = rotation.yaw as f64 * unit_to_radians;
    let forward_x = pitch.cos() * yaw.cos();
    let forward_y = pitch.cos() * yaw.sin();
    let forward_z = pitch.sin();
    format!(
        r#"{{"viewportType":"{}","width":{width},"height":{height},"location":{{"x":{},"y":{},"z":{}}},"rotation":{{"pitch":{},"yaw":{},"roll":{},"pitchDegrees":{},"yawDegrees":{},"rollDegrees":{}}},"forward":{{"x":{forward_x},"y":{forward_y},"z":{forward_z}}},"fieldOfViewDegrees":{fov},"orthoZoom":{ortho_zoom}}}"#,
        viewport_type_name(viewport_type),
        location.x,
        location.y,
        location.z,
        rotation.pitch,
        rotation.yaw,
        rotation.roll,
        rotation.pitch as f64 * 360.0 / 65_536.0,
        rotation.yaw as f64 * 360.0 / 65_536.0,
        rotation.roll as f64 * 360.0 / 65_536.0,
    )
}

fn wide_string(pointer: *const u16) -> String {
    if pointer.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    unsafe {
        while length < 128 && *pointer.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
    }
}

fn proxy_info(proxy: *mut c_void) -> ProxyInfo {
    if proxy.is_null() {
        return ProxyInfo {
            raw: proxy,
            proxy_type: "none".to_string(),
            hierarchy: vec!["HHitProxy".to_string()],
            actor: None,
        };
    }
    let mut hierarchy = Vec::new();
    unsafe {
        let vtable = *(proxy as *const *const *const ());
        if vtable.is_null() {
            return ProxyInfo {
                raw: proxy,
                proxy_type: "invalid".to_string(),
                hierarchy: Vec::new(),
                actor: None,
            };
        }
        let get_type: GetHitProxyTypeFn =
            std::mem::transmute(*vtable.add(HIT_PROXY_GET_TYPE_SLOT));
        let mut kind = get_type(proxy);
        for _ in 0..16 {
            if kind.is_null() {
                break;
            }
            let name = *((kind as *const u8).add(8) as *const *const u16);
            hierarchy.push(wide_string(name));
            kind = *(kind as *const *mut c_void);
        }
    }
    let proxy_type = hierarchy
        .first()
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    // These types all have an AActor (or ABrush, which is an AActor) as their
    // first field at +0x18. Everything else is deliberately ignored: many UI
    // hit proxies put an unrelated pointer at the same offset.
    let actor_backed = hierarchy.iter().any(|kind| {
        matches!(
            kind.as_str(),
            "HActor" | "HActorComplex" | "HStaticMeshVert" | "HBSPBrushVert"
        )
    });
    let actor = actor_backed.then(|| unsafe { read_pointer(proxy, HIT_PROXY_ACTOR_OFFSET) });
    ProxyInfo {
        raw: proxy,
        proxy_type,
        hierarchy,
        actor: actor.filter(|value| !value.is_null()),
    }
}

fn proxy_category(proxy_type: &str) -> &'static str {
    match proxy_type {
        "none" => "background",
        "HModel" => "bsp_geometry",
        "HActor" | "HActorComplex" | "HTranslucentActor" | "HStaticMeshVert"
        | "HBSPBrushVert" => "actor",
        kind if kind.starts_with("HWidget") => "transform_gizmo",
        _ => "editor_proxy",
    }
}

fn hit_proxy_function() -> Result<GetHitProxyFn, String> {
    Ok(unsafe {
        std::mem::transmute(
            mapped_function(
                GET_HIT_PROXY_RVA,
                "FViewport::GetHitProxy",
                GET_HIT_PROXY_PROLOGUE,
            )?,
        )
    })
}

pub(super) fn camera_snapshot(editor: *mut c_void) -> Result<CameraSnapshot, String> {
    let (client, viewport, _) = active_viewport(editor)?;
    let (width, height) = unsafe { viewport_size(viewport)? };
    Ok(CameraSnapshot {
        viewport_type: unsafe {
            *((client as *const u8).add(CLIENT_TYPE_OFFSET) as *const i32)
        },
        width,
        height,
        location: unsafe {
            *((client as *const u8).add(CLIENT_LOCATION_OFFSET) as *const Vector3)
        },
        rotation: unsafe {
            *((client as *const u8).add(CLIENT_ROTATION_OFFSET) as *const Rotator)
        },
        field_of_view: unsafe {
            *((client as *const u8).add(CLIENT_FOV_OFFSET) as *const f32)
        },
        ortho_zoom: unsafe {
            *((client as *const u8).add(CLIENT_ORTHO_ZOOM_OFFSET) as *const f32)
        },
    })
}

fn get_hit_proxy(
    function: GetHitProxyFn,
    viewport: *mut c_void,
    x: i32,
    y: i32,
) -> ProxyInfo {
    proxy_info(unsafe { function(viewport, x, y) })
}

fn inline_unreal_string(object: *mut c_void, offset: usize) -> String {
    if object.is_null() {
        return String::new();
    }
    let base = unsafe { (object as *const u8).add(offset) };
    let data = unsafe { std::ptr::read_unaligned(base as *const *const u16) };
    let len = unsafe { std::ptr::read_unaligned(base.add(8) as *const i32) };
    if data.is_null() || len <= 0 || len > 4096 {
        return String::new();
    }
    let units = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let content_len = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    String::from_utf16_lossy(&units[..content_len])
}

fn object_summary_json(object: *mut c_void) -> Result<String, String> {
    if object.is_null() {
        return Ok("null".to_string());
    }
    let (name, full_name, class_name) = actor_identity(object)?;
    Ok(format!(
        r#"{{"name":"{}","fullName":"{}","class":"{}"}}"#,
        json_escape(&name),
        json_escape(&full_name),
        json_escape(&class_name),
    ))
}

fn proxy_details_json(info: &ProxyInfo) -> Result<String, String> {
    if info.raw.is_null() {
        return Ok("{}".to_string());
    }
    match info.proxy_type.as_str() {
        "HActorComplex" => {
            let description = inline_unreal_string(info.raw, 0x20);
            let index =
                unsafe { std::ptr::read_unaligned((info.raw as *const u8).add(0x30) as *const i32) };
            Ok(format!(
                r#"{{"description":"{}","detailIndex":{index}}}"#,
                json_escape(&description)
            ))
        }
        "HStaticMeshVert" => {
            let vertex = unsafe {
                std::ptr::read_unaligned((info.raw as *const u8).add(0x20) as *const Vector3)
            };
            Ok(format!(
                r#"{{"vertex":{{"x":{},"y":{},"z":{}}}}}"#,
                vertex.x, vertex.y, vertex.z
            ))
        }
        "HBSPBrushVert" => {
            let vertex_pointer =
                unsafe { read_pointer(info.raw, 0x20) } as *const Vector3;
            if vertex_pointer.is_null() {
                Ok(r#"{"vertex":null}"#.to_string())
            } else {
                let vertex = unsafe { std::ptr::read_unaligned(vertex_pointer) };
                Ok(format!(
                    r#"{{"vertex":{{"x":{},"y":{},"z":{}}}}}"#,
                    vertex.x, vertex.y, vertex.z
                ))
            }
        }
        "HModel" => {
            let component = unsafe { read_pointer(info.raw, 0x18) };
            let model = unsafe { read_pointer(info.raw, 0x20) };
            Ok(format!(
                r#"{{"modelComponent":{},"model":{},"surfaceResolution":"A later world-trace phase is required for the exact BSP surface index."}}"#,
                object_summary_json(component)?,
                object_summary_json(model)?,
            ))
        }
        _ => Ok("{}".to_string()),
    }
}

fn proxy_json(info: &ProxyInfo) -> Result<String, String> {
    let hierarchy = info
        .hierarchy
        .iter()
        .map(|kind| format!(r#""{}""#, json_escape(kind)))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        r#"{{"type":"{}","category":"{}","hierarchy":[{hierarchy}],"actorBacked":{},"details":{}}}"#,
        json_escape(&info.proxy_type),
        proxy_category(&info.proxy_type),
        info.actor.is_some(),
        proxy_details_json(info)?,
    ))
}

fn camera_ray(
    client: *mut c_void,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
) -> Result<CameraRay, String> {
    let viewport_type = unsafe { *((client as *const u8).add(CLIENT_TYPE_OFFSET) as *const i32) };
    if viewport_type != 3 {
        return Err("camera-derived rays are currently limited to perspective viewports".to_string());
    }
    let location = unsafe { *((client as *const u8).add(CLIENT_LOCATION_OFFSET) as *const Vector3) };
    let rotation = unsafe { *((client as *const u8).add(CLIENT_ROTATION_OFFSET) as *const Rotator) };
    let fov = unsafe { *((client as *const u8).add(CLIENT_FOV_OFFSET) as *const f32) } as f64;
    if !fov.is_finite() || !(1.0..179.0).contains(&fov) {
        return Err("the viewport FOV is invalid".to_string());
    }

    let units = std::f64::consts::TAU / 65_536.0;
    let pitch = rotation.pitch as f64 * units;
    let yaw = rotation.yaw as f64 * units;
    let roll = rotation.roll as f64 * units;
    let (sp, cp) = pitch.sin_cos();
    let (sy, cy) = yaw.sin_cos();
    let (sr, cr) = roll.sin_cos();
    let forward = [cp * cy, cp * sy, sp];
    let right = [sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, -sr * cp];
    let up = [
        -(cr * sp * cy + sr * sy),
        cy * sr - cr * sp * sy,
        cr * cp,
    ];
    let ndc_x = (2.0 * (x as f64 + 0.5) / width as f64) - 1.0;
    let ndc_y = 1.0 - (2.0 * (y as f64 + 0.5) / height as f64);
    let tan_half_horizontal = (fov.to_radians() * 0.5).tan();
    let aspect = width as f64 / height as f64;
    let horizontal = ndc_x * tan_half_horizontal;
    let vertical = ndc_y * tan_half_horizontal / aspect;
    let mut direction = [
        forward[0] + right[0] * horizontal + up[0] * vertical,
        forward[1] + right[1] * horizontal + up[1] * vertical,
        forward[2] + right[2] * horizontal + up[2] * vertical,
    ];
    let length =
        (direction[0] * direction[0] + direction[1] * direction[1] + direction[2] * direction[2])
            .sqrt();
    if length > 0.0 {
        direction.iter_mut().for_each(|component| *component /= length);
    }
    Ok(CameraRay {
        origin: location,
        direction: Vector3 {
            x: direction[0] as f32,
            y: direction[1] as f32,
            z: direction[2] as f32,
        },
    })
}

fn camera_ray_json(ray: &Result<CameraRay, String>) -> String {
    match ray {
        Ok(ray) => format!(
            r#"{{"available":true,"origin":{{"x":{},"y":{},"z":{}}},"direction":{{"x":{},"y":{},"z":{}}},"projection":"camera-derived perspective","approximate":true,"note":"The hit-proxy identity is exact. The ray is derived from camera fields and does not yet include UE3 projection-matrix overrides."}}"#,
            ray.origin.x,
            ray.origin.y,
            ray.origin.z,
            ray.direction.x,
            ray.direction.y,
            ray.direction.z,
        ),
        Err(reason) => format!(
            r#"{{"available":false,"reason":"{}"}}"#,
            json_escape(reason)
        ),
    }
}

fn world_trace_json(ray: &Result<CameraRay, String>) -> Result<String, String> {
    let Ok(ray) = ray else {
        return Ok(r#"{"available":false,"reason":"no perspective camera ray is available"}"#.to_string());
    };
    let world_slot = image_address(GWORLD_RVA, std::mem::size_of::<usize>(), "GWorld")
        .map_err(|error| error.to_string())? as *const *mut c_void;
    let world = unsafe { *world_slot };
    if world.is_null() {
        return Ok(r#"{"available":false,"reason":"GWorld is null"}"#.to_string());
    }
    let function: SingleLineCheckFn = unsafe {
        std::mem::transmute(mapped_function(
            SINGLE_LINE_CHECK_RVA,
            "UWorld::SingleLineCheck",
            SINGLE_LINE_CHECK_PROLOGUE,
        )?)
    };
    let end = Vector3 {
        x: ray.origin.x + ray.direction.x * HALF_WORLD_MAX,
        y: ray.origin.y + ray.direction.y * HALF_WORLD_MAX,
        z: ray.origin.z + ray.direction.z * HALF_WORLD_MAX,
    };
    let extent = Vector3 { x: 0.0, y: 0.0, z: 0.0 };
    let mut hit = CheckResult::empty();
    let clear = unsafe {
        function(
            world,
            &mut hit,
            std::ptr::null_mut(),
            &end,
            &ray.origin,
            TRACE_WORLD_AND_ACTORS_COMPLEX_MATERIAL,
            &extent,
            std::ptr::null_mut(),
        ) != 0
    };
    if clear {
        return Ok(format!(
            r#"{{"available":true,"hit":false,"start":{{"x":{},"y":{},"z":{}}},"end":{{"x":{},"y":{},"z":{}}},"distance":{HALF_WORLD_MAX},"rayApproximate":true}}"#,
            ray.origin.x, ray.origin.y, ray.origin.z, end.x, end.y, end.z
        ));
    }
    let dx = hit.location.x - ray.origin.x;
    let dy = hit.location.y - ray.origin.y;
    let dz = hit.location.z - ray.origin.z;
    let distance = (dx * dx + dy * dy + dz * dz).sqrt();
    Ok(format!(
        r#"{{"available":true,"hit":true,"location":{{"x":{},"y":{},"z":{}}},"normal":{{"x":{},"y":{},"z":{}}},"distance":{distance},"time":{},"item":{},"startPenetrating":{},"actor":{},"component":{},"material":{},"physicalMaterial":{},"level":{},"levelIndex":{},"traceFlags":["world","actors","complexCollision","material"],"rayApproximate":true}}"#,
        hit.location.x,
        hit.location.y,
        hit.location.z,
        hit.normal.x,
        hit.normal.y,
        hit.normal.z,
        hit.time,
        hit.item,
        hit.start_penetrating != 0,
        object_summary_json(hit.actor)?,
        object_summary_json(hit.component)?,
        object_summary_json(hit.material)?,
        object_summary_json(hit.physical_material)?,
        object_summary_json(hit.level)?,
        hit.level_index,
    ))
}

pub(super) fn inspect_point(
    editor: *mut c_void,
    selected: &[*mut c_void],
    x: i32,
    y: i32,
) -> Result<String, String> {
    let (client, viewport, was_active) = active_viewport(editor)?;
    let (width, height) = unsafe { viewport_size(viewport)? };
    if x < 0 || y < 0 || x >= width as i32 || y >= height as i32 {
        return Err(format!(
            "screen point ({x},{y}) is outside the {width}x{height} active viewport"
        ));
    }
    let info = get_hit_proxy(hit_proxy_function()?, viewport, x, y);
    let ray = camera_ray(client, x, y, width, height);
    let selected_index = info
        .actor
        .and_then(|actor| selected.iter().position(|selected| *selected == actor))
        .map_or_else(|| "null".to_string(), |index| index.to_string());
    let actor = match info.actor {
        Some(actor) => actor_data_json(actor)?,
        None => "null".to_string(),
    };
    Ok(format!(
        r#"{{"viewportSelection":"{}","screenPoint":{{"x":{x},"y":{y},"normalizedX":{},"normalizedY":{}}},"camera":{},"cameraRay":{},"worldTrace":{},"hitProxy":{},"selectedActorIndex":{selected_index},"actor":{actor},"mapChanged":false,"selectionChanged":false}}"#,
        if was_active { "active" } else { "editor_fallback" },
        (x as f64 + 0.5) / width as f64,
        (y as f64 + 0.5) / height as f64,
        camera_json(client, width, height),
        camera_ray_json(&ray),
        world_trace_json(&ray)?,
        proxy_json(&info)?,
    ))
}

pub(super) fn validate_scan(
    grid_width: usize,
    grid_height: usize,
    max_actors: usize,
    max_samples: usize,
) -> Result<(), String> {
    if !(3..=MAX_GRID_WIDTH).contains(&grid_width) {
        return Err(format!("gridWidth must be between 3 and {MAX_GRID_WIDTH}"));
    }
    if !(3..=MAX_GRID_HEIGHT).contains(&grid_height) {
        return Err(format!("gridHeight must be between 3 and {MAX_GRID_HEIGHT}"));
    }
    if !(1..=MAX_VISIBLE_ACTORS).contains(&max_actors) {
        return Err(format!("maxActors must be between 1 and {MAX_VISIBLE_ACTORS}"));
    }
    let initial_samples = grid_width
        .checked_mul(grid_height)
        .ok_or_else(|| "initial viewport grid overflows".to_string())?;
    if max_samples < initial_samples || max_samples > MAX_PROXY_SAMPLES {
        return Err(format!(
            "maxSamples must be at least the initial grid size ({initial_samples}) and at most {MAX_PROXY_SAMPLES}"
        ));
    }
    Ok(())
}

fn sample_coordinate(index: usize, count: usize, extent: u32) -> i32 {
    if count <= 1 || extent <= 1 {
        0
    } else {
        (index as u64 * (extent - 1) as u64 / (count - 1) as u64) as i32
    }
}

#[derive(Clone, Copy)]
struct AdaptiveCell {
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    depth: u8,
}

fn sample_cached(
    cache: &mut HashMap<(i32, i32), ProxyInfo>,
    function: GetHitProxyFn,
    viewport: *mut c_void,
    x: i32,
    y: i32,
    max_samples: usize,
    budget_exhausted: &mut bool,
) -> bool {
    if cache.contains_key(&(x, y)) {
        return true;
    }
    if cache.len() >= max_samples {
        *budget_exhausted = true;
        return false;
    }
    cache.insert((x, y), get_hit_proxy(function, viewport, x, y));
    true
}

fn collect_proxy_samples(
    viewport: *mut c_void,
    width: u32,
    height: u32,
    grid_width: usize,
    grid_height: usize,
    adaptive: bool,
    max_samples: usize,
) -> Result<(HashMap<(i32, i32), ProxyInfo>, usize, bool), String> {
    let function = hit_proxy_function()?;
    let xs = (0..grid_width)
        .map(|index| sample_coordinate(index, grid_width, width))
        .collect::<Vec<_>>();
    let ys = (0..grid_height)
        .map(|index| sample_coordinate(index, grid_height, height))
        .collect::<Vec<_>>();
    let mut cache = HashMap::with_capacity(max_samples.min(MAX_PROXY_SAMPLES));
    let mut budget_exhausted = false;
    for y in &ys {
        for x in &xs {
            // validate_scan guarantees enough room for the initial grid.
            let _ = sample_cached(
                &mut cache,
                function,
                viewport,
                *x,
                *y,
                max_samples,
                &mut budget_exhausted,
            );
        }
    }
    if !adaptive {
        return Ok((cache, 0, false));
    }

    let mut queue = VecDeque::new();
    for row in 0..ys.len() - 1 {
        for column in 0..xs.len() - 1 {
            queue.push_back(AdaptiveCell {
                x0: xs[column],
                y0: ys[row],
                x1: xs[column + 1],
                y1: ys[row + 1],
                depth: 0,
            });
        }
    }
    let mut subdivided_cells = 0usize;
    while let Some(cell) = queue.pop_front() {
        if cell.depth >= MAX_ADAPTIVE_DEPTH
            || cell.x1 - cell.x0 <= MIN_ADAPTIVE_CELL_PIXELS
            || cell.y1 - cell.y0 <= MIN_ADAPTIVE_CELL_PIXELS
        {
            continue;
        }
        let mid_x = cell.x0 + (cell.x1 - cell.x0) / 2;
        let mid_y = cell.y0 + (cell.y1 - cell.y0) / 2;
        let points = [
            (cell.x0, cell.y0),
            (cell.x1, cell.y0),
            (cell.x0, cell.y1),
            (cell.x1, cell.y1),
            (mid_x, mid_y),
        ];
        if points.iter().any(|(x, y)| {
            !sample_cached(
                &mut cache,
                function,
                viewport,
                *x,
                *y,
                max_samples,
                &mut budget_exhausted,
            )
        }) {
            break;
        }
        let first = cache.get(&points[0]).expect("sample inserted");
        let boundary = points[1..]
            .iter()
            .any(|point| !first.same_target(cache.get(point).expect("sample inserted")));
        if !boundary {
            continue;
        }
        subdivided_cells += 1;
        let depth = cell.depth + 1;
        queue.extend([
            AdaptiveCell {
                x0: cell.x0,
                y0: cell.y0,
                x1: mid_x,
                y1: mid_y,
                depth,
            },
            AdaptiveCell {
                x0: mid_x,
                y0: cell.y0,
                x1: cell.x1,
                y1: mid_y,
                depth,
            },
            AdaptiveCell {
                x0: cell.x0,
                y0: mid_y,
                x1: mid_x,
                y1: cell.y1,
                depth,
            },
            AdaptiveCell {
                x0: mid_x,
                y0: mid_y,
                x1: cell.x1,
                y1: cell.y1,
                depth,
            },
        ]);
    }
    Ok((cache, subdivided_cells, budget_exhausted))
}

pub(super) fn semantic_context(
    editor: *mut c_void,
    selected: &[*mut c_void],
    grid_width: usize,
    grid_height: usize,
    max_actors: usize,
    adaptive: bool,
    max_samples: usize,
) -> Result<String, String> {
    validate_scan(grid_width, grid_height, max_actors, max_samples)?;
    let (client, viewport, was_active) = active_viewport(editor)?;
    let (width, height) = unsafe { viewport_size(viewport)? };
    let center_x = (width / 2) as i32;
    let center_y = (height / 2) as i32;
    let function = hit_proxy_function()?;
    let center = get_hit_proxy(function, viewport, center_x, center_y);
    let (samples, subdivided_cells, budget_exhausted) = collect_proxy_samples(
        viewport,
        width,
        height,
        grid_width,
        grid_height,
        adaptive,
        max_samples,
    )?;
    let mut hits: HashMap<usize, ActorHit> = HashMap::new();
    let mut proxy_counts: HashMap<String, usize> = HashMap::new();

    let total_samples = samples.len();
    for ((x, y), info) in samples {
        *proxy_counts.entry(info.proxy_type.clone()).or_default() += 1;
        let Some(actor) = info.actor else {
            continue;
        };
        let distance_x = i64::from(x - center_x);
        let distance_y = i64::from(y - center_y);
        let distance2 = distance_x * distance_x + distance_y * distance_y;
        let entry = hits.entry(actor as usize).or_insert_with(|| ActorHit {
            actor,
            proxy_types: HashSet::new(),
            samples: 0,
            min_x: x,
            min_y: y,
            max_x: x,
            max_y: y,
            focus_x: x,
            focus_y: y,
            focus_distance2: distance2,
        });
        entry.proxy_types.insert(info.proxy_type);
        entry.samples += 1;
        entry.min_x = entry.min_x.min(x);
        entry.min_y = entry.min_y.min(y);
        entry.max_x = entry.max_x.max(x);
        entry.max_y = entry.max_y.max(y);
        if distance2 < entry.focus_distance2 {
            entry.focus_distance2 = distance2;
            entry.focus_x = x;
            entry.focus_y = y;
        }
    }

    let total_actor_count = hits.len();
    let mut hits: Vec<ActorHit> = hits.into_values().collect();
    hits.sort_by(|left, right| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left.focus_distance2.cmp(&right.focus_distance2))
    });
    hits.truncate(max_actors);
    let mut proxy_counts: Vec<(String, usize)> = proxy_counts.into_iter().collect();
    proxy_counts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let proxy_summary = proxy_counts
        .iter()
        .map(|(kind, count)| {
            format!(
                r#"{{"proxyType":"{}","category":"{}","sampleCount":{count},"sampleRatio":{}}}"#,
                json_escape(kind),
                proxy_category(kind),
                *count as f64 / total_samples as f64,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut actors = Vec::with_capacity(hits.len());
    for (viewport_index, hit) in hits.into_iter().enumerate() {
        let mut proxy_types: Vec<String> = hit.proxy_types.into_iter().collect();
        proxy_types.sort();
        let selected_index = selected.iter().position(|actor| *actor == hit.actor);
        let selected_json = selected_index
            .map(|index| index.to_string())
            .unwrap_or_else(|| "null".to_string());
        let actor = actor_json(viewport_index, hit.actor)?;
        actors.push(format!(
            r#"{{"viewportActorIndex":{viewport_index},"selectedActorIndex":{selected_json},"sampleCount":{},"sampleRatio":{},"proxyTypes":[{}],"sampleBounds":{{"minX":{},"minY":{},"maxX":{},"maxY":{}}},"focusPoint":{{"x":{},"y":{}}},"actor":{actor}}}"#,
            hit.samples,
            hit.samples as f64 / total_samples as f64,
            proxy_types
                .iter()
                .map(|kind| format!(r#""{}""#, json_escape(kind)))
                .collect::<Vec<_>>()
                .join(","),
            hit.min_x,
            hit.min_y,
            hit.max_x,
            hit.max_y,
            hit.focus_x,
            hit.focus_y,
        ));
    }

    let center_actor = match center.actor {
        Some(actor) => {
            let (name, full_name, class_name) = actor_identity(actor)?;
            format!(
                r#",
                "actor":{{"name":"{}","fullName":"{}","class":"{}"}}"#,
                json_escape(&name),
                json_escape(&full_name),
                json_escape(&class_name),
            )
        }
        None => String::new(),
    };
    let camera = camera_json(client, width, height);
    Ok(format!(
        r#"{{"viewportSelection":"{}","camera":{camera},"centerHit":{{"x":{center_x},"y":{center_y},"proxyType":"{}","category":"{}"{center_actor}}},"sampling":{{"method":"occlusion-aware UE3 hit-proxy adaptive grid","gridWidth":{grid_width},"gridHeight":{grid_height},"adaptive":{adaptive},"maxSamples":{max_samples},"sampleCount":{total_samples},"subdividedCells":{subdivided_cells},"budgetExhausted":{budget_exhausted},"approximateBounds":true,"note":"Refinement concentrates samples along proxy and actor boundaries. Completely enclosed objects smaller than the initial sampling interval can still be missed; inspect a point or request a screenshot when pixels matter."}},"surfaceSummary":[{proxy_summary}],"visibleActorCount":{total_actor_count},"returnedActorCount":{},"truncated":{},"visibleActors":[{}]}}"#,
        if was_active { "active" } else { "editor_fallback" },
        json_escape(&center.proxy_type),
        proxy_category(&center.proxy_type),
        actors.len(),
        total_actor_count > actors.len(),
        actors.join(","),
    ))
}

pub(super) fn focus_actor(
    editor: *mut c_void,
    selected: &[*mut c_void],
    source: super::ViewportActorSource,
) -> Result<String, String> {
    let (client, viewport, was_active) = active_viewport(editor)?;
    let (width, height) = unsafe { viewport_size(viewport)? };
    let (actor, source_json) = match source {
        super::ViewportActorSource::Selected(index) => {
            let actor = selected
                .get(index)
                .copied()
                .ok_or_else(|| format!("selected actor index {index} is out of range"))?;
            (actor, format!(r#"{{"selectedActorIndex":{index}}}"#))
        }
        super::ViewportActorSource::ScreenPoint { x, y } => {
            if x < 0 || y < 0 || x >= width as i32 || y >= height as i32 {
                return Err(format!(
                    "screen point ({x},{y}) is outside the {width}x{height} active viewport"
                ));
            }
            let hit = get_hit_proxy(hit_proxy_function()?, viewport, x, y);
            let actor = hit.actor.ok_or_else(|| {
                format!(
                    "screen point ({x},{y}) hit '{}' rather than an actor",
                    hit.proxy_type
                )
            })?;
            (
                actor,
                format!(
                    r#"{{"screenPoint":{{"x":{x},"y":{y}}},"proxyType":"{}"}}"#,
                    json_escape(&hit.proxy_type)
                ),
            )
        }
        super::ViewportActorSource::ObjectPath(path) => {
            let actor = find_actor_by_path(&path)?;
            (actor, format!(r#"{{"objectPath":"{}"}}"#, json_escape(&path)))
        }
    };
    let before = camera_json(client, width, height);
    let function: MoveViewportToActorFn = unsafe {
        std::mem::transmute(
            mapped_function(
                MOVE_VIEWPORT_TO_ACTOR_RVA,
                "UEditorEngine::MoveViewportCamerasToActor",
                MOVE_VIEWPORT_TO_ACTOR_PROLOGUE,
            )?,
        )
    };
    let active_slot = active_client_slot()?;
    let previous_active = unsafe { *active_slot };
    if !was_active {
        unsafe { *active_slot = client };
    }
    unsafe { function(editor, actor, 1) };
    if !was_active {
        unsafe { *active_slot = previous_active };
    }
    let after = camera_json(client, width, height);
    let (name, full_name, class_name) = actor_identity(actor)?;
    Ok(format!(
        r#"{{"framed":true,"activeViewportOnly":true,"mapChanged":false,"selectionChanged":false,"source":{source_json},"actor":{{"name":"{}","fullName":"{}","class":"{}"}},"cameraBefore":{before},"cameraAfter":{after}}}"#,
        json_escape(&name),
        json_escape(&full_name),
        json_escape(&class_name),
    ))
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0F) << 2) | (third >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3F) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_i32(output: &mut Vec<u8>, value: i32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn bmp_bytes(width: i32, height: i32, pixels: &[u8]) -> Result<Vec<u8>, String> {
    let expected = width
        .checked_mul(height)
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| "screenshot dimensions overflow".to_string())? as usize;
    if width <= 0 || height <= 0 || pixels.len() != expected {
        return Err("screenshot pixel buffer has an invalid size".to_string());
    }
    let file_size = 54usize
        .checked_add(pixels.len())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "screenshot BMP is too large".to_string())?;
    let mut output = Vec::with_capacity(file_size as usize);
    output.extend_from_slice(b"BM");
    push_u32(&mut output, file_size);
    push_u32(&mut output, 0);
    push_u32(&mut output, 54);
    push_u32(&mut output, 40);
    push_i32(&mut output, width);
    // Negative height means the DIB is top-down, matching CreateDIBSection.
    push_i32(&mut output, -height);
    push_u16(&mut output, 1);
    push_u16(&mut output, 32);
    push_u32(&mut output, 0);
    push_u32(&mut output, pixels.len() as u32);
    push_i32(&mut output, 0);
    push_i32(&mut output, 0);
    push_u32(&mut output, 0);
    push_u32(&mut output, 0);
    output.extend_from_slice(pixels);
    Ok(output)
}

pub(super) fn validate_screenshot_width(max_width: usize) -> Result<(), String> {
    if !(160..=MAX_SCREENSHOT_WIDTH).contains(&max_width) {
        Err(format!(
            "maxWidth must be between 160 and {MAX_SCREENSHOT_WIDTH}"
        ))
    } else {
        Ok(())
    }
}

pub(super) fn screenshot(
    editor: *mut c_void,
    max_width: usize,
) -> Result<(String, String), String> {
    validate_screenshot_width(max_width)?;
    let (_, viewport, _) = active_viewport(editor)?;
    let window = unsafe {
        HWND(std::ptr::read_unaligned(
            (viewport as *const u8).add(VIEWPORT_WINDOW_FROM_VIEWPORT_OFFSET) as *const isize,
        ))
    };
    if window.0 == 0 {
        return Err("the active viewport has no native window".to_string());
    }
    let mut client = RECT::default();
    unsafe { GetClientRect(window, &mut client) }
        .map_err(|error| format!("could not read active viewport bounds: {error}"))?;
    let source_width = client.right - client.left;
    let source_height = client.bottom - client.top;
    if source_width <= 0 || source_height <= 0 {
        return Err("the active viewport window has zero client size".to_string());
    }
    let output_width = source_width.min(max_width as i32);
    let output_height = ((i64::from(source_height) * i64::from(output_width)
        + i64::from(source_width) / 2)
        / i64::from(source_width))
    .max(1) as i32;

    let window_dc = unsafe { GetDC(window) };
    if window_dc.is_invalid() {
        return Err("GetDC failed for the active viewport".to_string());
    }
    let memory_dc = unsafe { CreateCompatibleDC(window_dc) };
    if memory_dc.is_invalid() {
        unsafe { ReleaseDC(window, window_dc) };
        return Err("CreateCompatibleDC failed for the viewport screenshot".to_string());
    }

    let mut info = BITMAPINFO::default();
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: output_width,
        biHeight: -output_height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB.0,
        ..Default::default()
    };
    let mut bits = std::ptr::null_mut();
    let bitmap = match unsafe {
        CreateDIBSection(
            memory_dc,
            &info,
            DIB_RGB_COLORS,
            &mut bits,
            HANDLE(0),
            0,
        )
    } {
        Ok(bitmap) => bitmap,
        Err(error) => {
            unsafe {
                DeleteDC(memory_dc);
                ReleaseDC(window, window_dc);
            }
            return Err(format!("CreateDIBSection failed: {error}"));
        }
    };
    let old_bitmap = unsafe { SelectObject(memory_dc, bitmap) };
    unsafe { SetStretchBltMode(memory_dc, HALFTONE) };
    let copied = unsafe {
        StretchBlt(
            memory_dc,
            0,
            0,
            output_width,
            output_height,
            window_dc,
            0,
            0,
            source_width,
            source_height,
            SRCCOPY,
        )
        .as_bool()
    };
    let pixel_len = output_width as usize * output_height as usize * 4;
    let pixels = if copied && !bits.is_null() {
        unsafe { std::slice::from_raw_parts(bits as *const u8, pixel_len) }.to_vec()
    } else {
        Vec::new()
    };
    unsafe {
        if !old_bitmap.is_invalid() {
            SelectObject(memory_dc, old_bitmap);
        }
        DeleteObject(bitmap);
        DeleteDC(memory_dc);
        ReleaseDC(window, window_dc);
    }
    if !copied {
        return Err("StretchBlt failed while capturing the active viewport".to_string());
    }
    let bmp = bmp_bytes(output_width, output_height, &pixels)?;
    let metadata = format!(
        r#"{{"mimeType":"image/bmp","width":{output_width},"height":{output_height},"sourceWidth":{source_width},"sourceHeight":{source_height},"downscaled":{},"note":"Explicit pixel fallback; prefer renx_get_viewport_context for ordinary scene understanding."}}"#,
        output_width != source_width
    );
    Ok((base64_encode(&bmp), metadata))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_coordinates_include_both_edges_and_center() {
        assert_eq!((0..5).map(|i| sample_coordinate(i, 5, 101)).collect::<Vec<_>>(), vec![0, 25, 50, 75, 100]);
    }

    #[test]
    fn base64_matches_rfc_examples() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn bmp_has_top_down_32_bit_header() {
        let bytes = bmp_bytes(2, 1, &[0; 8]).unwrap();
        assert_eq!(&bytes[..2], b"BM");
        assert_eq!(u32::from_le_bytes(bytes[10..14].try_into().unwrap()), 54);
        assert_eq!(i32::from_le_bytes(bytes[18..22].try_into().unwrap()), 2);
        assert_eq!(i32::from_le_bytes(bytes[22..26].try_into().unwrap()), -1);
        assert_eq!(u16::from_le_bytes(bytes[28..30].try_into().unwrap()), 32);
        assert_eq!(bytes.len(), 62);
    }

    #[test]
    fn scan_and_screenshot_limits_are_bounded() {
        assert!(validate_scan(3, 3, 1, 9).is_ok());
        assert!(validate_scan(MAX_GRID_WIDTH + 1, 3, 1, MAX_PROXY_SAMPLES).is_err());
        assert!(validate_scan(3, MAX_GRID_HEIGHT + 1, 1, MAX_PROXY_SAMPLES).is_err());
        assert!(validate_scan(3, 3, MAX_VISIBLE_ACTORS + 1, 9).is_err());
        assert!(validate_scan(17, 11, 1, 186).is_err());
        assert!(validate_scan(3, 3, 1, MAX_PROXY_SAMPLES + 1).is_err());
        assert!(validate_screenshot_width(DEFAULT_SCREENSHOT_WIDTH).is_ok());
        assert!(validate_screenshot_width(MAX_SCREENSHOT_WIDTH + 1).is_err());
    }
}
