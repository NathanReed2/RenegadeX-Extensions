//! Active level-viewport inspection and camera navigation.
//!
//! UE3 already renders a hit-proxy buffer for editor picking. Sampling that
//! buffer is both more faithful and much cheaper than asking a model to infer
//! an entire scene from pixels: it is occlusion aware, returns real AActor
//! pointers, and only renders the buffer once when its cache is stale.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;

use windows::Win32::Foundation::{HANDLE, HWND, RECT};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetDC, ReleaseDC, SelectObject,
    SetStretchBltMode, StretchBlt, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HALFTONE,
    SRCCOPY,
};
use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

use super::{actor_identity, actor_json, image_address, json_escape, Rotator, Vector3};

const ACTIVE_LEVEL_VIEWPORT_CLIENT_RVA: usize = 0x036B_9ED0;
const GET_HIT_PROXY_RVA: usize = 0x005C_1D80;
const MOVE_VIEWPORT_TO_ACTOR_RVA: usize = 0x0129_1F80;

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

pub(super) const DEFAULT_GRID_WIDTH: usize = 17;
pub(super) const DEFAULT_GRID_HEIGHT: usize = 11;
pub(super) const DEFAULT_MAX_ACTORS: usize = 32;
pub(super) const DEFAULT_SCREENSHOT_WIDTH: usize = 640;
pub(super) const MAX_GRID_WIDTH: usize = 31;
pub(super) const MAX_GRID_HEIGHT: usize = 21;
pub(super) const MAX_VISIBLE_ACTORS: usize = 100;
pub(super) const MAX_SCREENSHOT_WIDTH: usize = 1280;

type GetViewportSizeFn = unsafe extern "C" fn(*mut c_void) -> u32;
type GetHitProxyFn = unsafe extern "C" fn(*mut c_void, i32, i32) -> *mut c_void;
type GetHitProxyTypeFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type MoveViewportToActorFn = unsafe extern "C" fn(*mut c_void, *mut c_void, u32);

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
    proxy_type: String,
    actor: Option<*mut c_void>,
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
            proxy_type: "none".to_string(),
            actor: None,
        };
    }
    let mut hierarchy = Vec::new();
    unsafe {
        let vtable = *(proxy as *const *const *const ());
        if vtable.is_null() {
            return ProxyInfo {
                proxy_type: "invalid".to_string(),
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
        proxy_type,
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

fn get_hit_proxy(viewport: *mut c_void, x: i32, y: i32) -> Result<ProxyInfo, String> {
    let function: GetHitProxyFn = unsafe {
        std::mem::transmute(
            mapped_function(
                GET_HIT_PROXY_RVA,
                "FViewport::GetHitProxy",
                GET_HIT_PROXY_PROLOGUE,
            )?,
        )
    };
    Ok(proxy_info(unsafe { function(viewport, x, y) }))
}

pub(super) fn validate_scan(
    grid_width: usize,
    grid_height: usize,
    max_actors: usize,
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
    Ok(())
}

fn sample_coordinate(index: usize, count: usize, extent: u32) -> i32 {
    if count <= 1 || extent <= 1 {
        0
    } else {
        (index as u64 * (extent - 1) as u64 / (count - 1) as u64) as i32
    }
}

pub(super) fn semantic_context(
    editor: *mut c_void,
    selected: &[*mut c_void],
    grid_width: usize,
    grid_height: usize,
    max_actors: usize,
) -> Result<String, String> {
    validate_scan(grid_width, grid_height, max_actors)?;
    let (client, viewport, was_active) = active_viewport(editor)?;
    let (width, height) = unsafe { viewport_size(viewport)? };
    let center_x = (width / 2) as i32;
    let center_y = (height / 2) as i32;
    let center = get_hit_proxy(viewport, center_x, center_y)?;
    let mut hits: HashMap<usize, ActorHit> = HashMap::new();
    let mut proxy_counts: HashMap<String, usize> = HashMap::new();

    for row in 0..grid_height {
        let y = sample_coordinate(row, grid_height, height);
        for column in 0..grid_width {
            let x = sample_coordinate(column, grid_width, width);
            let info = get_hit_proxy(viewport, x, y)?;
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
    let total_samples = grid_width * grid_height;
    let mut proxy_counts: Vec<(String, usize)> = proxy_counts.into_iter().collect();
    proxy_counts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let proxy_summary = proxy_counts
        .iter()
        .map(|(kind, count)| {
            format!(
                r#"{{"proxyType":"{}","category":"{}","sampleCount":{count},"sampleCoverage":{}}}"#,
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
            r#"{{"viewportActorIndex":{viewport_index},"selectedActorIndex":{selected_json},"sampleCount":{},"sampleCoverage":{},"proxyTypes":[{}],"sampleBounds":{{"minX":{},"minY":{},"maxX":{},"maxY":{}}},"focusPoint":{{"x":{},"y":{}}},"actor":{actor}}}"#,
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
        r#"{{"viewportSelection":"{}","camera":{camera},"centerHit":{{"x":{center_x},"y":{center_y},"proxyType":"{}","category":"{}"{center_actor}}},"sampling":{{"method":"occlusion-aware UE3 hit-proxy grid","gridWidth":{grid_width},"gridHeight":{grid_height},"sampleCount":{total_samples},"approximateBounds":true,"note":"Actors smaller than the sampling interval can be missed; increase the grid or request a screenshot when pixels matter."}},"surfaceSummary":[{proxy_summary}],"visibleActorCount":{total_actor_count},"returnedActorCount":{},"truncated":{},"visibleActors":[{}]}}"#,
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
            let hit = get_hit_proxy(viewport, x, y)?;
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
        assert!(validate_scan(3, 3, 1).is_ok());
        assert!(validate_scan(MAX_GRID_WIDTH + 1, 3, 1).is_err());
        assert!(validate_scan(3, MAX_GRID_HEIGHT + 1, 1).is_err());
        assert!(validate_scan(3, 3, MAX_VISIBLE_ACTORS + 1).is_err());
        assert!(validate_screenshot_width(DEFAULT_SCREENSHOT_WIDTH).is_ok());
        assert!(validate_screenshot_width(MAX_SCREENSHOT_WIDTH + 1).is_err());
    }
}
