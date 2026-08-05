//! Bounded spatial queries over the actors the editor has loaded.
//!
//! This walks `UWorld`'s levels and their `Actors` arrays directly rather than
//! going through `OBJ LIST` like `scene.rs`. A spatial query needs the actor's
//! transform and bounds, and resolving thousands of printed paths back to
//! pointers to get them would cost a string round trip per actor for data that
//! is three pointer hops away.
//!
//! Containment is tested against real component bounds by default, because an
//! actor's origin says very little about where it is: a building whose pivot
//! sits outside the query sphere is still in the query sphere.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;

use super::{
    actor_data_json, image_address, json_escape, read_pointer, unreal_object_string, Vector3,
    ACTOR_LOCATION_OFFSET, UOBJECT_CLASS_OFFSET, USTRUCT_SUPER_STRUCT_OFFSET,
};

const GWORLD_RVA: usize = 0x0369_13D8;
const GET_WORLD_INFO_RVA: usize = 0x009F_D770;
const WORLD_ACTORS_DATA_SITE_RVA: usize = 0x009F_D7AC;
const ACTOR_COMPONENTS_SITE_RVA: usize = 0x0128_DBAE;
const MARK_COMPONENTS_PENDING_KILL_RVA: usize = 0x0053_E8B0;
const ACTOR_ALL_COMPONENTS_NUM_SITE_RVA: usize = 0x0053_E974;
const ACTOR_ALL_COMPONENTS_DATA_SITE_RVA: usize = 0x0053_E9B6;
const COMPONENT_BOUNDS_SITE_RVA: usize = 0x0128_DC09;

const WORLD_LEVELS_DATA_OFFSET: usize = 0x70;
const WORLD_LEVELS_NUM_OFFSET: usize = 0x78;
const WORLD_PERSISTENT_LEVEL_OFFSET: usize = 0x80;
const LEVEL_ACTORS_DATA_OFFSET: usize = 0x60;
const LEVEL_ACTORS_NUM_OFFSET: usize = 0x68;
const ACTOR_COMPONENTS_DATA_OFFSET: usize = 0x60;
const ACTOR_COMPONENTS_NUM_OFFSET: usize = 0x68;
const ACTOR_ALL_COMPONENTS_DATA_OFFSET: usize = 0x70;
const ACTOR_ALL_COMPONENTS_NUM_OFFSET: usize = 0x78;
const COMPONENT_ATTACHED_OFFSET: usize = 0x80;
const COMPONENT_BOUNDS_ORIGIN_OFFSET: usize = 0x8C;
const COMPONENT_BOUNDS_EXTENT_OFFSET: usize = 0x98;
const COMPONENT_BOUNDS_RADIUS_OFFSET: usize = 0xA4;

/// `UWorld::GetWorldInfo`, which reaches `PersistentLevel->Actors(0)` and so
/// pins the persistent-level pointer and the actor array's count in one place.
const GET_WORLD_INFO_PROLOGUE: &[u8] = &[
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x99, 0x80, 0x00, 0x00,
    0x00, 0x8B, 0xFA, 0x8B, 0x43, 0x68, 0x85, 0xC0, 0x7F, 0x22,
];
/// The `MOV RAX,[RBX+0x60]` that reads `ULevel::Actors`' data pointer.
const WORLD_ACTORS_DATA_GUARD: &[u8] = &[0x48, 0x8B, 0x43, 0x60, 0x48, 0x8B, 0x18];
/// `MOV RAX,[R12+0x60]` reading `AActor::Components`' data pointer inside the
/// editor's own bounding-box walk.
const ACTOR_COMPONENTS_GUARD: &[u8] = &[
    0x49, 0x8B, 0x44, 0x24, 0x60, 0x48, 0x8B, 0x1C, 0x06, 0x48, 0x85, 0xDB,
];
/// `AActor::MarkComponentsAsPendingKill` walks `Components` and then
/// `AllComponents`, so one function pins both arrays. The prologue anchors it
/// and the two sites below carry the offsets.
const MARK_COMPONENTS_PENDING_KILL_PROLOGUE: &[u8] = &[
    0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48, 0x89, 0x7C, 0x24, 0x20,
];
/// `CMP dword ptr [RSI+0x78],EDI` - the `AllComponents` count.
const ACTOR_ALL_COMPONENTS_NUM_GUARD: &[u8] = &[0x39, 0x7E, 0x78, 0x0F, 0x8E];
/// `MOV RAX,[RSI+0x70]; MOV RBX,[RAX+RDI*8]; TEST RBX,RBX` - its data pointer.
const ACTOR_ALL_COMPONENTS_DATA_GUARD: &[u8] = &[
    0x48, 0x8B, 0x46, 0x70, 0x48, 0x8B, 0x1C, 0xF8, 0x48, 0x85, 0xDB, 0x74, 0x30,
];
/// The attached test and the `FBoxSphereBounds` reads that follow it, taken
/// from `UEditorEngine::MoveViewportCamerasToActor`. The offsets this module
/// relies on are literals inside these bytes, so a build whose layout moved
/// cannot match.
const COMPONENT_BOUNDS_GUARD: &[u8] = &[
    0xF6, 0x83, 0x80, 0x00, 0x00, 0x00, 0x01, 0x0F, 0x84, 0x22, 0x01, 0x00, 0x00, 0xF3, 0x0F, 0x10,
    0x93, 0xA0, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x10, 0xAB, 0x94, 0x00, 0x00, 0x00, 0x44, 0x0F, 0x28,
    0xC5, 0xF3, 0x44, 0x0F, 0x58, 0xC2, 0xF3, 0x0F, 0x10, 0x8B, 0x9C, 0x00, 0x00, 0x00, 0xF3, 0x0F,
    0x10, 0xA3, 0x90, 0x00, 0x00, 0x00, 0x0F, 0x28, 0xFC, 0xF3, 0x0F, 0x58, 0xF9, 0xF3, 0x0F, 0x10,
    0x83, 0x98, 0x00, 0x00, 0x00, 0xF3, 0x0F, 0x10, 0x9B, 0x8C, 0x00, 0x00, 0x00, 0x0F,
];

pub(super) const DEFAULT_LIMIT: usize = 25;
pub(super) const MAX_LIMIT: usize = 200;
pub(super) const DEFAULT_MAX_SCAN: usize = 20_000;
pub(super) const MAX_MAX_SCAN: usize = 200_000;
const MAX_LEVELS: usize = 4096;
const MAX_ACTORS_PER_LEVEL: usize = 1_000_000;
// A landscape attaches one component per terrain patch; CNC-Field's has 236,
// and a larger map's can run well past that.
const MAX_COMPONENTS_PER_ACTOR: usize = 16_384;
const MAX_CLASS_CHAIN: usize = 128;
const MAX_FILTER_LENGTH: usize = 256;
const HALF_WORLD_MAX: f64 = 262_144.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shape {
    Sphere,
    Box,
    Frustum,
    Nearest,
}

impl Shape {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "sphere" => Ok(Shape::Sphere),
            "box" => Ok(Shape::Box),
            "frustum" => Ok(Shape::Frustum),
            "nearest" => Ok(Shape::Nearest),
            _ => Err("shape must be 'sphere', 'box', 'frustum', or 'nearest'".to_string()),
        }
    }

    pub(super) fn id(self) -> &'static str {
        match self {
            Shape::Sphere => "sphere",
            Shape::Box => "box",
            Shape::Frustum => "frustum",
            Shape::Nearest => "nearest",
        }
    }
}

/// An axis-aligned box in world space, which is what every shape reduces to
/// when it meets an actor.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Bounds {
    min: [f64; 3],
    max: [f64; 3],
    sphere_radius: f64,
}

impl Bounds {
    fn point(location: [f64; 3]) -> Self {
        Self {
            min: location,
            max: location,
            sphere_radius: 0.0,
        }
    }

    fn union(self, other: Self) -> Self {
        Self {
            min: std::array::from_fn(|i| self.min[i].min(other.min[i])),
            max: std::array::from_fn(|i| self.max[i].max(other.max[i])),
            sphere_radius: self.sphere_radius.max(other.sphere_radius),
        }
    }

    fn center(&self) -> [f64; 3] {
        std::array::from_fn(|i| (self.min[i] + self.max[i]) * 0.5)
    }

    fn extent(&self) -> [f64; 3] {
        std::array::from_fn(|i| (self.max[i] - self.min[i]) * 0.5)
    }

    /// Zero when the point is inside, otherwise the distance to the nearest
    /// face. This is what makes "how far away is that building" answerable.
    fn distance_to(&self, point: [f64; 3]) -> f64 {
        let mut square = 0.0;
        for axis in 0..3 {
            let outside = (self.min[axis] - point[axis]).max(point[axis] - self.max[axis]);
            if outside > 0.0 {
                square += outside * outside;
            }
        }
        square.sqrt()
    }

    fn intersects_sphere(&self, center: [f64; 3], radius: f64) -> bool {
        self.distance_to(center) <= radius
    }

    fn intersects_box(&self, other: &Bounds) -> bool {
        (0..3).all(|axis| self.min[axis] <= other.max[axis] && other.min[axis] <= self.max[axis])
    }

    /// Positive-vertex test: the box is outside only when the corner furthest
    /// along a plane's normal is still behind it.
    fn intersects_frustum(&self, planes: &[[f64; 4]; 6]) -> bool {
        let center = self.center();
        let extent = self.extent();
        planes.iter().all(|plane| {
            let distance = plane[0] * center[0] + plane[1] * center[1] + plane[2] * center[2]
                + plane[3];
            let reach =
                plane[0].abs() * extent[0] + plane[1].abs() * extent[1] + plane[2].abs() * extent[2];
            distance + reach >= 0.0
        })
    }
}

pub(super) struct Query {
    pub(super) shape: Shape,
    pub(super) origin: Option<[f64; 3]>,
    pub(super) origin_actor: String,
    pub(super) radius: f64,
    pub(super) extent: [f64; 3],
    pub(super) class_name: String,
    pub(super) level: String,
    pub(super) use_bounds: bool,
    pub(super) line_of_sight: bool,
    pub(super) limit: usize,
    pub(super) max_scan: usize,
}

fn valid_filter(value: &str) -> bool {
    value.len() <= MAX_FILTER_LENGTH
        && !value
            .chars()
            .any(|character| character == '\0' || character.is_control())
}

fn finite_in_world(value: f64) -> bool {
    value.is_finite() && value.abs() <= HALF_WORLD_MAX * 2.0
}

pub(super) fn validate(query: &Query) -> Result<(), String> {
    if !query.class_name.is_empty()
        && !query
            .class_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err("class must be a bare UE3 class name".to_string());
    }
    if !valid_filter(&query.level) {
        return Err(format!(
            "level must be at most {MAX_FILTER_LENGTH} characters and contain no control characters"
        ));
    }
    if !valid_filter(&query.origin_actor) {
        return Err("originActor must be a plain object path".to_string());
    }
    if let Some(origin) = query.origin {
        if !origin.iter().copied().all(finite_in_world) {
            return Err("origin must be finite and inside the world bounds".to_string());
        }
    }
    if query.shape != Shape::Frustum && query.origin.is_none() && query.origin_actor.is_empty() {
        // The camera is the default origin, so this only fails when the caller
        // asked for something contradictory.
    }
    match query.shape {
        Shape::Sphere | Shape::Nearest => {
            if !(query.radius > 0.0 && finite_in_world(query.radius)) {
                return Err(format!(
                    "radius must be greater than 0 and at most {}",
                    HALF_WORLD_MAX * 2.0
                ));
            }
        }
        Shape::Box => {
            if !query.extent.iter().copied().all(|value| value > 0.0 && finite_in_world(value)) {
                return Err(format!(
                    "extent components must be greater than 0 and at most {}",
                    HALF_WORLD_MAX * 2.0
                ));
            }
        }
        Shape::Frustum => {}
    }
    if !(1..=MAX_LIMIT).contains(&query.limit) {
        return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
    }
    if !(1..=MAX_MAX_SCAN).contains(&query.max_scan) {
        return Err(format!("maxScan must be between 1 and {MAX_MAX_SCAN}"));
    }
    Ok(())
}

fn guarded_site(rva: usize, name: &str, expected: &[u8]) -> Result<(), String> {
    let address = image_address(rva, expected.len(), name).map_err(|error| error.to_string())?;
    let actual = unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) };
    if actual != expected {
        return Err(format!(
            "{name} does not match the verified RenXSDK build at RVA 0x{rva:X}; the spatial query was refused"
        ));
    }
    Ok(())
}

/// Every offset this module reads is proven by one of these sites. Checking
/// them once per query is cheaper than a single actor's bounds read and is what
/// keeps a changed build from being walked with stale offsets.
fn verify_layout() -> Result<(), String> {
    guarded_site(
        GET_WORLD_INFO_RVA,
        "UWorld::GetWorldInfo",
        GET_WORLD_INFO_PROLOGUE,
    )?;
    guarded_site(
        WORLD_ACTORS_DATA_SITE_RVA,
        "ULevel::Actors layout site",
        WORLD_ACTORS_DATA_GUARD,
    )?;
    guarded_site(
        ACTOR_COMPONENTS_SITE_RVA,
        "AActor::Components layout site",
        ACTOR_COMPONENTS_GUARD,
    )?;
    guarded_site(
        MARK_COMPONENTS_PENDING_KILL_RVA,
        "AActor::MarkComponentsAsPendingKill",
        MARK_COMPONENTS_PENDING_KILL_PROLOGUE,
    )?;
    guarded_site(
        ACTOR_ALL_COMPONENTS_NUM_SITE_RVA,
        "AActor::AllComponents count site",
        ACTOR_ALL_COMPONENTS_NUM_GUARD,
    )?;
    guarded_site(
        ACTOR_ALL_COMPONENTS_DATA_SITE_RVA,
        "AActor::AllComponents data site",
        ACTOR_ALL_COMPONENTS_DATA_GUARD,
    )?;
    guarded_site(
        COMPONENT_BOUNDS_SITE_RVA,
        "UPrimitiveComponent::Bounds layout site",
        COMPONENT_BOUNDS_GUARD,
    )
}

unsafe fn read_array(object: *mut c_void, data_offset: usize, num_offset: usize, cap: usize) -> Option<(*const *mut c_void, usize)> {
    let count = *((object as *const u8).add(num_offset) as *const i32);
    if count < 0 || count as usize > cap {
        return None;
    }
    let data = std::ptr::read_unaligned(
        (object as *const u8).add(data_offset) as *const *const *mut c_void
    );
    if count == 0 {
        return Some((std::ptr::null(), 0));
    }
    if data.is_null() {
        return None;
    }
    Some((data, count as usize))
}

/// Class-chain test by name, cached on the class pointer. A cold call costs an
/// FString per link, and a scan asks the same question of the same few classes
/// tens of thousands of times.
struct ClassCache {
    answers: HashMap<usize, bool>,
    target: String,
}

impl ClassCache {
    fn new(target: &str) -> Self {
        Self {
            answers: HashMap::new(),
            target: target.to_string(),
        }
    }

    fn matches(&mut self, object: *mut c_void) -> Result<bool, String> {
        if self.target.is_empty() {
            return Ok(true);
        }
        let class = unsafe { read_pointer(object, UOBJECT_CLASS_OFFSET) };
        if class.is_null() {
            return Ok(false);
        }
        if let Some(answer) = self.answers.get(&(class as usize)) {
            return Ok(*answer);
        }
        let mut cursor = class;
        let mut answer = false;
        for _ in 0..MAX_CLASS_CHAIN {
            if cursor.is_null() {
                break;
            }
            if unreal_object_string(cursor, false)?.eq_ignore_ascii_case(&self.target) {
                answer = true;
                break;
            }
            cursor = unsafe { read_pointer(cursor, USTRUCT_SUPER_STRUCT_OFFSET) };
        }
        self.answers.insert(class as usize, answer);
        Ok(answer)
    }
}

/// One component's contribution, or `None` if it has nothing to contribute.
fn component_bounds(
    component: *mut c_void,
    primitives: &mut ClassCache,
) -> Result<Option<Bounds>, String> {
    if component.is_null() || !primitives.matches(component)? {
        return Ok(None);
    }
    // The engine's own rule at the site these offsets came from: a primitive
    // component contributes its bounds only once attached, because an
    // unattached one has never had them computed.
    let attached = unsafe { *((component as *const u8).add(COMPONENT_ATTACHED_OFFSET)) } & 1 != 0;
    if !attached {
        return Ok(None);
    }
    let origin =
        unsafe { *((component as *const u8).add(COMPONENT_BOUNDS_ORIGIN_OFFSET) as *const Vector3) };
    let extent =
        unsafe { *((component as *const u8).add(COMPONENT_BOUNDS_EXTENT_OFFSET) as *const Vector3) };
    let radius =
        unsafe { *((component as *const u8).add(COMPONENT_BOUNDS_RADIUS_OFFSET) as *const f32) }
            as f64;
    let origin = [origin.x as f64, origin.y as f64, origin.z as f64];
    let extent = [extent.x as f64, extent.y as f64, extent.z as f64];
    if !origin
        .iter()
        .chain(extent.iter())
        .all(|value| value.is_finite())
    {
        return Ok(None);
    }
    Ok(Some(Bounds {
        min: std::array::from_fn(|i| origin[i] - extent[i].abs()),
        max: std::array::from_fn(|i| origin[i] + extent[i].abs()),
        sphere_radius: if radius.is_finite() { radius } else { 0.0 },
    }))
}

/// Both component arrays, because neither alone is the actor's extent.
///
/// `Components` is the editable list, and it is what the editor's own framing
/// walk uses. `AllComponents` is what `UActorComponent::Attach` appends to, so
/// it holds everything actually attached - including components an actor
/// creates outside the editable list. A Landscape is the case that matters:
/// its `Components` holds one editor sprite while its 236 terrain patches live
/// only in `AllComponents`, so walking `Components` alone would place a
/// map-sized landscape at a point and miss it in every volume query.
fn actor_bounds(
    actor: *mut c_void,
    location: [f64; 3],
    primitives: &mut ClassCache,
) -> Result<(Bounds, usize), String> {
    let mut bounds: Option<Bounds> = None;
    let mut used = 0usize;
    // A landscape brings hundreds of components; a linear membership scan
    // would be quadratic in exactly the case this walk was widened for.
    let mut seen: HashSet<usize> = HashSet::new();
    for (data_offset, num_offset) in [
        (ACTOR_COMPONENTS_DATA_OFFSET, ACTOR_COMPONENTS_NUM_OFFSET),
        (
            ACTOR_ALL_COMPONENTS_DATA_OFFSET,
            ACTOR_ALL_COMPONENTS_NUM_OFFSET,
        ),
    ] {
        let Some((data, count)) = (unsafe {
            read_array(actor, data_offset, num_offset, MAX_COMPONENTS_PER_ACTOR)
        }) else {
            continue;
        };
        for index in 0..count {
            let component = unsafe { *data.add(index) };
            // The two arrays overlap heavily, and a component counted twice
            // would inflate componentCount without changing the union.
            if !seen.insert(component as usize) {
                continue;
            }
            let Some(contribution) = component_bounds(component, primitives)? else {
                continue;
            };
            bounds = Some(match bounds {
                Some(existing) => existing.union(contribution),
                None => contribution,
            });
            used += 1;
        }
    }
    Ok((bounds.unwrap_or_else(|| Bounds::point(location)), used))
}

struct Candidate {
    actor: *mut c_void,
    path: String,
    level: String,
    distance: f64,
    bounds_distance: f64,
    bounds: Bounds,
    component_count: usize,
}

fn level_path(level: *mut c_void) -> String {
    unreal_object_string(level, true)
        .map(|full_name| super::object_path_from_full_name(&full_name).to_string())
        .unwrap_or_default()
}

fn levels(world: *mut c_void) -> (Vec<*mut c_void>, &'static str) {
    let persistent = unsafe { read_pointer(world, WORLD_PERSISTENT_LEVEL_OFFSET) };
    let listed = unsafe {
        read_array(
            world,
            WORLD_LEVELS_DATA_OFFSET,
            WORLD_LEVELS_NUM_OFFSET,
            MAX_LEVELS,
        )
    };
    // UE3 asserts Levels(0) == PersistentLevel, so that equality is a free
    // check that the array really is Levels and not whatever else lives at this
    // offset in some other build. If it does not hold, fall back rather than
    // walk a misread pointer.
    if let Some((data, count)) = listed {
        if count > 0 && !persistent.is_null() && unsafe { *data } == persistent {
            let mut all = Vec::with_capacity(count);
            for index in 0..count {
                let level = unsafe { *data.add(index) };
                if !level.is_null() && !all.contains(&level) {
                    all.push(level);
                }
            }
            return (all, "world_levels");
        }
    }
    if persistent.is_null() {
        (Vec::new(), "none")
    } else {
        (vec![persistent], "persistent_only")
    }
}

fn vector_json(value: [f64; 3]) -> String {
    format!(
        r#"{{"x":{},"y":{},"z":{}}}"#,
        value[0] as f32, value[1] as f32, value[2] as f32
    )
}

pub(super) fn query(editor: *mut c_void, request: &Query) -> Result<String, String> {
    validate(request)?;
    verify_layout()?;

    let world_slot = image_address(GWORLD_RVA, std::mem::size_of::<usize>(), "GWorld")
        .map_err(|error| error.to_string())? as *const *mut c_void;
    let world = unsafe { *world_slot };
    if world.is_null() {
        return Err("GWorld is null; no map is loaded".to_string());
    }

    // Frustum planes come from the active viewport, which also supplies the
    // camera position every distance is measured from.
    let mut frustum = None;
    let mut origin_source = "explicit";
    let origin = if request.shape == Shape::Frustum {
        let (planes, camera) = super::viewport::active_frustum(editor)?;
        frustum = Some(planes);
        origin_source = "camera";
        [camera.x as f64, camera.y as f64, camera.z as f64]
    } else if let Some(origin) = request.origin {
        origin
    } else if !request.origin_actor.is_empty() {
        let actor = super::find_object_by_path(&request.origin_actor)?;
        let location =
            unsafe { *((actor as *const u8).add(ACTOR_LOCATION_OFFSET) as *const Vector3) };
        origin_source = "actor";
        [location.x as f64, location.y as f64, location.z as f64]
    } else {
        let camera = super::viewport::camera_snapshot(editor)?;
        origin_source = "camera";
        [
            camera.location.x as f64,
            camera.location.y as f64,
            camera.location.z as f64,
        ]
    };

    let query_box = Bounds {
        min: std::array::from_fn(|i| origin[i] - request.extent[i]),
        max: std::array::from_fn(|i| origin[i] + request.extent[i]),
        sphere_radius: 0.0,
    };

    let (level_list, level_source) = levels(world);
    let level_filter = request.level.to_ascii_lowercase();
    let mut classes = ClassCache::new(&request.class_name);
    let mut primitives = ClassCache::new("PrimitiveComponent");
    let mut scanned = 0usize;
    let mut scan_limit_reached = false;
    let mut scanned_levels = 0usize;
    let mut candidates: Vec<Candidate> = Vec::new();

    'levels: for level in &level_list {
        let path = level_path(*level);
        if !level_filter.is_empty() && !path.to_ascii_lowercase().contains(&level_filter) {
            continue;
        }
        scanned_levels += 1;
        let Some((data, count)) = (unsafe {
            read_array(
                *level,
                LEVEL_ACTORS_DATA_OFFSET,
                LEVEL_ACTORS_NUM_OFFSET,
                MAX_ACTORS_PER_LEVEL,
            )
        }) else {
            continue;
        };
        for index in 0..count {
            if scanned >= request.max_scan {
                scan_limit_reached = true;
                break 'levels;
            }
            let actor = unsafe { *data.add(index) };
            // The array is sparse: destroyed actors leave null slots behind.
            if actor.is_null() {
                continue;
            }
            scanned += 1;
            if !classes.matches(actor)? {
                continue;
            }
            let location =
                unsafe { *((actor as *const u8).add(ACTOR_LOCATION_OFFSET) as *const Vector3) };
            let location = [location.x as f64, location.y as f64, location.z as f64];
            if !location.iter().copied().all(f64::is_finite) {
                continue;
            }
            let (bounds, component_count) = if request.use_bounds {
                actor_bounds(actor, location, &mut primitives)?
            } else {
                (Bounds::point(location), 0)
            };

            let inside = match request.shape {
                Shape::Sphere => bounds.intersects_sphere(origin, request.radius),
                Shape::Nearest => bounds.intersects_sphere(origin, request.radius),
                Shape::Box => bounds.intersects_box(&query_box),
                Shape::Frustum => frustum
                    .as_ref()
                    .is_some_and(|planes| bounds.intersects_frustum(planes)),
            };
            if !inside {
                continue;
            }
            let offset: [f64; 3] = std::array::from_fn(|i| location[i] - origin[i]);
            let distance =
                (offset[0] * offset[0] + offset[1] * offset[1] + offset[2] * offset[2]).sqrt();
            candidates.push(Candidate {
                actor,
                path: unreal_object_string(actor, true)
                    .map(|full_name| super::object_path_from_full_name(&full_name).to_string())
                    .unwrap_or_default(),
                level: path.clone(),
                distance,
                bounds_distance: bounds.distance_to(origin),
                bounds,
                component_count,
            });
        }
    }

    // Deterministic: nearest first, then path, so two identical queries return
    // the same page even when distances tie.
    candidates.sort_by(|left, right| {
        left.distance
            .partial_cmp(&right.distance)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.path.cmp(&right.path))
    });
    let match_count = candidates.len();
    candidates.truncate(request.limit);

    let mut entries = Vec::with_capacity(candidates.len());
    let mut traced = 0usize;
    for candidate in &candidates {
        let line_of_sight = if request.line_of_sight {
            traced += 1;
            let start = Vector3 {
                x: origin[0] as f32,
                y: origin[1] as f32,
                z: origin[2] as f32,
            };
            let location = unsafe {
                *((candidate.actor as *const u8).add(ACTOR_LOCATION_OFFSET) as *const Vector3)
            };
            match super::viewport::line_check(start, location, super::viewport::TRACE_WORLD_AND_ACTORS) {
                Ok(None) => r#"{"clear":true,"blockedBy":null}"#.to_string(),
                Ok(Some(hit)) => {
                    let blocker = hit.actor_full_name().unwrap_or_default();
                    // A trace toward an actor usually stops on that actor, which
                    // is not an obstruction.
                    let self_hit = blocker
                        .split_once(' ')
                        .is_some_and(|(_, path)| path.eq_ignore_ascii_case(&candidate.path));
                    if self_hit {
                        r#"{"clear":true,"blockedBy":null}"#.to_string()
                    } else {
                        format!(
                            r#"{{"clear":false,"blockedBy":"{}","hitLocation":{}}}"#,
                            json_escape(&blocker),
                            vector_json([
                                hit.location.x as f64,
                                hit.location.y as f64,
                                hit.location.z as f64
                            ])
                        )
                    }
                }
                Err(reason) => format!(
                    r#"{{"clear":null,"reason":"{}"}}"#,
                    json_escape(&reason)
                ),
            }
        } else {
            "null".to_string()
        };
        let data = actor_data_json(candidate.actor)?;
        entries.push(format!(
            r#"{{"distance":{},"boundsDistance":{},"bounds":{{"min":{},"max":{},"center":{},"boxExtent":{},"sphereRadius":{},"source":"{}","componentCount":{}}},"lineOfSight":{line_of_sight},"level":"{}","actor":{data}}}"#,
            candidate.distance as f32,
            candidate.bounds_distance as f32,
            vector_json(candidate.bounds.min),
            vector_json(candidate.bounds.max),
            vector_json(candidate.bounds.center()),
            vector_json(candidate.bounds.extent()),
            candidate.bounds.sphere_radius as f32,
            if candidate.component_count > 0 {
                "attached_primitive_components"
            } else {
                "actor_location"
            },
            candidate.component_count,
            json_escape(&candidate.level),
        ));
    }

    let shape_json = match request.shape {
        Shape::Sphere | Shape::Nearest => format!(r#"{{"radius":{}}}"#, request.radius as f32),
        Shape::Box => format!(
            r#"{{"extent":{},"min":{},"max":{}}}"#,
            vector_json(request.extent),
            vector_json(query_box.min),
            vector_json(query_box.max)
        ),
        Shape::Frustum => r#"{"source":"active viewport view-projection"}"#.to_string(),
    };

    Ok(format!(
        r#"{{"shape":"{}","shapeParameters":{shape_json},"origin":{},"originSource":"{origin_source}","containment":"{}","classFilter":{},"levelFilter":{},"scan":{{"levelSource":"{level_source}","levelsAvailable":{},"levelsScanned":{scanned_levels},"actorsScanned":{scanned},"maxScan":{},"scanLimitReached":{scan_limit_reached}}},"matchCount":{match_count},"returnedCount":{},"limit":{},"truncated":{},"resultsTruncated":{},"lineOfSight":{{"requested":{},"traced":{traced}}},"mapChanged":false,"selectionChanged":false,"actors":[{}]}}"#,
        request.shape.id(),
        vector_json(origin),
        if request.use_bounds {
            "component bounds"
        } else {
            "actor location"
        },
        if request.class_name.is_empty() {
            "null".to_string()
        } else {
            format!("\"{}\"", json_escape(&request.class_name))
        },
        if request.level.is_empty() {
            "null".to_string()
        } else {
            format!("\"{}\"", json_escape(&request.level))
        },
        level_list.len(),
        request.max_scan,
        entries.len(),
        request.limit,
        // Incomplete for any reason. A caller that only reads this must not be
        // able to mistake a scan that stopped early for a complete answer, so
        // the specific causes are reported alongside rather than instead.
        match_count > entries.len() || scan_limit_reached,
        match_count > entries.len(),
        request.line_of_sight,
        entries.join(","),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Query {
        Query {
            shape: Shape::Sphere,
            origin: Some([0.0, 0.0, 0.0]),
            origin_actor: String::new(),
            radius: 1000.0,
            extent: [100.0, 100.0, 100.0],
            class_name: String::new(),
            level: String::new(),
            use_bounds: true,
            line_of_sight: false,
            limit: DEFAULT_LIMIT,
            max_scan: DEFAULT_MAX_SCAN,
        }
    }

    fn box_at(center: [f64; 3], half: f64) -> Bounds {
        Bounds {
            min: std::array::from_fn(|i| center[i] - half),
            max: std::array::from_fn(|i| center[i] + half),
            sphere_radius: half * 3.0f64.sqrt(),
        }
    }

    #[test]
    fn bounds_distance_is_zero_inside_and_face_distance_outside() {
        let bounds = box_at([0.0, 0.0, 0.0], 100.0);
        assert_eq!(bounds.distance_to([0.0, 0.0, 0.0]), 0.0);
        assert_eq!(bounds.distance_to([50.0, 50.0, 50.0]), 0.0);
        assert_eq!(bounds.distance_to([200.0, 0.0, 0.0]), 100.0);
        // Diagonal from a corner, not from the centre.
        let diagonal = bounds.distance_to([200.0, 200.0, 0.0]);
        assert!((diagonal - (100.0f64 * 100.0 + 100.0 * 100.0).sqrt()).abs() < 1e-9);
    }

    #[test]
    fn a_large_actor_is_found_even_when_its_origin_is_outside_the_sphere() {
        // The case that makes bounds testing worth the component walk: a
        // building whose pivot is 900 units away but whose wall is at 100.
        let building = box_at([900.0, 0.0, 0.0], 800.0);
        assert!(building.intersects_sphere([0.0, 0.0, 0.0], 200.0));
        assert!(!Bounds::point([900.0, 0.0, 0.0]).intersects_sphere([0.0, 0.0, 0.0], 200.0));
    }

    #[test]
    fn box_intersection_is_inclusive_at_the_touching_face() {
        let left = box_at([0.0, 0.0, 0.0], 100.0);
        let touching = box_at([200.0, 0.0, 0.0], 100.0);
        let apart = box_at([201.0, 0.0, 0.0], 100.0);
        assert!(left.intersects_box(&touching));
        assert!(!left.intersects_box(&apart));
    }

    #[test]
    fn union_grows_to_cover_both_and_keeps_the_larger_radius() {
        let merged = box_at([0.0, 0.0, 0.0], 10.0).union(box_at([100.0, 0.0, 0.0], 50.0));
        assert_eq!(merged.min, [-10.0, -50.0, -50.0]);
        assert_eq!(merged.max, [150.0, 50.0, 50.0]);
        assert!((merged.sphere_radius - 50.0 * 3.0f64.sqrt()).abs() < 1e-9);
    }

    /// Planes of an axis-aligned unit box, in the inward-facing form the
    /// frustum test expects.
    fn box_planes(half: f64) -> [[f64; 4]; 6] {
        [
            [1.0, 0.0, 0.0, half],
            [-1.0, 0.0, 0.0, half],
            [0.0, 1.0, 0.0, half],
            [0.0, -1.0, 0.0, half],
            [0.0, 0.0, 1.0, half],
            [0.0, 0.0, -1.0, half],
        ]
    }

    #[test]
    fn frustum_test_accepts_straddling_boxes_and_rejects_distant_ones() {
        let planes = box_planes(100.0);
        assert!(box_at([0.0, 0.0, 0.0], 10.0).intersects_frustum(&planes));
        // Centre outside, but the box reaches in.
        assert!(box_at([150.0, 0.0, 0.0], 100.0).intersects_frustum(&planes));
        assert!(!box_at([500.0, 0.0, 0.0], 10.0).intersects_frustum(&planes));
        assert!(!box_at([0.0, 0.0, -500.0], 50.0).intersects_frustum(&planes));
    }

    #[test]
    fn query_bounds_are_enforced() {
        assert!(validate(&query()).is_ok());
        assert!(validate(&Query { radius: 0.0, ..query() }).is_err());
        assert!(validate(&Query { radius: f64::NAN, ..query() }).is_err());
        assert!(validate(&Query { limit: 0, ..query() }).is_err());
        assert!(validate(&Query { limit: MAX_LIMIT + 1, ..query() }).is_err());
        assert!(validate(&Query { max_scan: MAX_MAX_SCAN + 1, ..query() }).is_err());
        assert!(validate(&Query { class_name: "Static Mesh".to_string(), ..query() }).is_err());
        assert!(validate(&Query { class_name: "StaticMeshActor".to_string(), ..query() }).is_ok());
        assert!(validate(&Query {
            origin: Some([f64::INFINITY, 0.0, 0.0]),
            ..query()
        })
        .is_err());
        assert!(validate(&Query {
            shape: Shape::Box,
            extent: [0.0, 100.0, 100.0],
            ..query()
        })
        .is_err());
        // A frustum query needs neither an origin nor a radius.
        assert!(validate(&Query {
            shape: Shape::Frustum,
            origin: None,
            radius: 0.0,
            ..query()
        })
        .is_ok());
    }

    #[test]
    fn shapes_parse_and_reject_unknown_names() {
        assert_eq!(Shape::parse("sphere").unwrap(), Shape::Sphere);
        assert_eq!(Shape::parse("frustum").unwrap(), Shape::Frustum);
        assert_eq!(Shape::parse("nearest").unwrap(), Shape::Nearest);
        assert!(Shape::parse("cylinder").is_err());
    }
}
