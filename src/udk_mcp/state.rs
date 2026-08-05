//! Bounded editor-state snapshots and semantic diffs.
//!
//! A screenshot answers what the viewport looked like once. A snapshot answers
//! what changed: loaded actor identity, selection, selected transforms, map,
//! and camera pose. Only compact summaries cross MCP; up to 32 full snapshots
//! are retained in-process for comparisons.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use super::viewport::CameraSnapshot;
use super::{
    actor_identity, json_escape, object_path_from_full_name, run_static_exec,
    Rotator, Vector3, ACTOR_DRAW_SCALE3D_OFFSET, ACTOR_DRAW_SCALE_OFFSET, ACTOR_LOCATION_OFFSET,
    ACTOR_ROTATION_OFFSET,
};

const MAX_SNAPSHOTS: usize = 32;
const MAX_DIFF_PATHS: usize = 100;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static SNAPSHOTS: OnceLock<Mutex<VecDeque<Snapshot>>> = OnceLock::new();

#[derive(Clone)]
struct SelectedActorState {
    path: String,
    location: Vector3,
    rotation: Rotator,
    draw_scale: f32,
    draw_scale3d: Vector3,
}

#[derive(Clone)]
struct Snapshot {
    id: u64,
    captured_unix_ms: u128,
    map: String,
    actor_paths: Vec<String>,
    selected: Vec<SelectedActorState>,
    camera: CameraSnapshot,
}

fn snapshots() -> &'static Mutex<VecDeque<Snapshot>> {
    SNAPSHOTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_SNAPSHOTS)))
}

fn scene_fingerprint(paths: &[String]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in paths.iter().flat_map(|path| path.bytes().chain([0])) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64-{hash:016x}")
}

fn parse_actor_paths(output: &str) -> Vec<String> {
    let mut paths = output
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 6 || fields[2..].iter().any(|field| field.parse::<u64>().is_err()) {
                return None;
            }
            Some(fields[1].to_string())
        })
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn selected_state(actor: *mut c_void) -> Result<SelectedActorState, String> {
    let (_, full_name, _) = actor_identity(actor)?;
    Ok(SelectedActorState {
        path: object_path_from_full_name(&full_name).to_string(),
        location: unsafe {
            *((actor as *const u8).add(ACTOR_LOCATION_OFFSET) as *const Vector3)
        },
        rotation: unsafe {
            *((actor as *const u8).add(ACTOR_ROTATION_OFFSET) as *const Rotator)
        },
        draw_scale: unsafe {
            *((actor as *const u8).add(ACTOR_DRAW_SCALE_OFFSET) as *const f32)
        },
        draw_scale3d: unsafe {
            *((actor as *const u8).add(ACTOR_DRAW_SCALE3D_OFFSET) as *const Vector3)
        },
    })
}

fn make_snapshot(editor: *mut c_void, selected: &[*mut c_void]) -> Result<Snapshot, String> {
    let (handled, output) = run_static_exec("OBJ LIST CLASS=Actor ALPHASORT")?;
    if !handled {
        return Err("UE3 did not handle the actor listing used for the snapshot".to_string());
    }
    if !output
        .lines()
        .rev()
        .any(|line| line.trim().contains(" Objects ("))
    {
        return Err(
            "the actor listing was incomplete, so a trustworthy scene snapshot was not stored"
                .to_string(),
        );
    }
    let actor_paths = parse_actor_paths(&output);
    let map = actor_paths
        .iter()
        .find_map(|path| path.split_once(".TheWorld").map(|(map, _)| map.to_string()))
        .unwrap_or_default();
    let selected = selected
        .iter()
        .map(|actor| selected_state(*actor))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Snapshot {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        captured_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0),
        map,
        actor_paths,
        selected,
        camera: super::viewport::camera_snapshot(editor)?,
    })
}

fn store(snapshot: Snapshot) {
    let mut entries = snapshots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if entries.len() == MAX_SNAPSHOTS {
        entries.pop_front();
    }
    entries.push_back(snapshot);
}

fn snapshot_json(snapshot: &Snapshot) -> String {
    let selected_paths = snapshot
        .selected
        .iter()
        .map(|actor| format!(r#""{}""#, json_escape(&actor.path)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"snapshotId":"state-{}","capturedUnixMs":{},"map":"{}","actorCount":{},"sceneFingerprint":"{}","selectionCount":{},"selectedActorPaths":[{}],"camera":{},"retainedSnapshotLimit":{MAX_SNAPSHOTS}}}"#,
        snapshot.id,
        snapshot.captured_unix_ms,
        json_escape(&snapshot.map),
        snapshot.actor_paths.len(),
        scene_fingerprint(&snapshot.actor_paths),
        snapshot.selected.len(),
        selected_paths,
        snapshot.camera.json(),
    )
}

pub(super) fn capture(editor: *mut c_void, selected: &[*mut c_void]) -> Result<String, String> {
    let snapshot = make_snapshot(editor, selected)?;
    let result = snapshot_json(&snapshot);
    store(snapshot);
    Ok(result)
}

fn parse_id(token: &str) -> Result<u64, String> {
    token
        .strip_prefix("state-")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("invalid snapshotId '{token}'; expected state-N"))
}

fn load(token: &str) -> Result<Snapshot, String> {
    let id = parse_id(token)?;
    snapshots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|snapshot| snapshot.id == id)
        .cloned()
        .ok_or_else(|| {
            format!(
                "snapshot '{token}' is not retained; at most {MAX_SNAPSHOTS} snapshots are kept"
            )
        })
}

fn path_list_json(paths: &[String]) -> String {
    paths
        .iter()
        .take(MAX_DIFF_PATHS)
        .map(|path| format!(r#""{}""#, json_escape(path)))
        .collect::<Vec<_>>()
        .join(",")
}

fn transform_changed(left: &SelectedActorState, right: &SelectedActorState) -> bool {
    left.location.x != right.location.x
        || left.location.y != right.location.y
        || left.location.z != right.location.z
        || left.rotation.pitch != right.rotation.pitch
        || left.rotation.yaw != right.rotation.yaw
        || left.rotation.roll != right.rotation.roll
        || left.draw_scale != right.draw_scale
        || left.draw_scale3d.x != right.draw_scale3d.x
        || left.draw_scale3d.y != right.draw_scale3d.y
        || left.draw_scale3d.z != right.draw_scale3d.z
}

fn transform_diff_json(before: &Snapshot, after: &Snapshot) -> (usize, String) {
    let before_by_path = before
        .selected
        .iter()
        .map(|actor| (actor.path.as_str(), actor))
        .collect::<HashMap<_, _>>();
    let mut changed = Vec::new();
    for actor in &after.selected {
        let Some(previous) = before_by_path.get(actor.path.as_str()) else {
            continue;
        };
        if transform_changed(previous, actor) {
            changed.push(format!(
                r#"{{"path":"{}","locationBefore":{{"x":{},"y":{},"z":{}}},"locationAfter":{{"x":{},"y":{},"z":{}}},"rotationBefore":{{"pitch":{},"yaw":{},"roll":{}}},"rotationAfter":{{"pitch":{},"yaw":{},"roll":{}}},"scaleBefore":{{"uniform":{},"x":{},"y":{},"z":{}}},"scaleAfter":{{"uniform":{},"x":{},"y":{},"z":{}}}}}"#,
                json_escape(&actor.path),
                previous.location.x, previous.location.y, previous.location.z,
                actor.location.x, actor.location.y, actor.location.z,
                previous.rotation.pitch, previous.rotation.yaw, previous.rotation.roll,
                actor.rotation.pitch, actor.rotation.yaw, actor.rotation.roll,
                previous.draw_scale, previous.draw_scale3d.x, previous.draw_scale3d.y, previous.draw_scale3d.z,
                actor.draw_scale, actor.draw_scale3d.x, actor.draw_scale3d.y, actor.draw_scale3d.z,
            ));
        }
    }
    let count = changed.len();
    changed.truncate(MAX_DIFF_PATHS);
    (count, changed.join(","))
}

fn camera_changed(before: &CameraSnapshot, after: &CameraSnapshot) -> bool {
    before.viewport_type != after.viewport_type
        || before.location.x != after.location.x
        || before.location.y != after.location.y
        || before.location.z != after.location.z
        || before.rotation.pitch != after.rotation.pitch
        || before.rotation.yaw != after.rotation.yaw
        || before.rotation.roll != after.rotation.roll
        || before.field_of_view != after.field_of_view
        || before.ortho_zoom != after.ortho_zoom
}

pub(super) fn diff(
    editor: *mut c_void,
    selected: &[*mut c_void],
    from_token: &str,
    to_token: Option<&str>,
) -> Result<String, String> {
    let before = load(from_token)?;
    let after = match to_token {
        Some(token) => load(token)?,
        None => {
            let snapshot = make_snapshot(editor, selected)?;
            store(snapshot.clone());
            snapshot
        }
    };
    let before_paths = before.actor_paths.iter().cloned().collect::<HashSet<_>>();
    let after_paths = after.actor_paths.iter().cloned().collect::<HashSet<_>>();
    let mut added = after_paths.difference(&before_paths).cloned().collect::<Vec<_>>();
    let mut removed = before_paths.difference(&after_paths).cloned().collect::<Vec<_>>();
    added.sort_unstable();
    removed.sort_unstable();
    let before_selection = before
        .selected
        .iter()
        .map(|actor| actor.path.as_str())
        .collect::<Vec<_>>();
    let after_selection = after
        .selected
        .iter()
        .map(|actor| actor.path.as_str())
        .collect::<Vec<_>>();
    let selection_changed = before_selection != after_selection;
    let map_changed = before.map != after.map;
    let camera_changed = camera_changed(&before.camera, &after.camera);
    let (transform_count, transforms) = transform_diff_json(&before, &after);
    let changed = map_changed
        || selection_changed
        || camera_changed
        || !added.is_empty()
        || !removed.is_empty()
        || transform_count != 0;
    Ok(format!(
        r#"{{"fromSnapshot":"state-{}","toSnapshot":"state-{}","changed":{changed},"map":{{"changed":{map_changed},"before":"{}","after":"{}"}},"scene":{{"changed":{},"actorCountBefore":{},"actorCountAfter":{},"fingerprintBefore":"{}","fingerprintAfter":"{}","addedCount":{},"removedCount":{},"pathsTruncated":{},"addedPaths":[{}],"removedPaths":[{}]}},"selection":{{"changed":{selection_changed},"before":[{}],"after":[{}]}},"camera":{{"changed":{camera_changed},"before":{},"after":{}}},"selectedTransformChanges":{{"count":{transform_count},"truncated":{},"actors":[{transforms}]}}}}"#,
        before.id,
        after.id,
        json_escape(&before.map),
        json_escape(&after.map),
        !added.is_empty() || !removed.is_empty(),
        before.actor_paths.len(),
        after.actor_paths.len(),
        scene_fingerprint(&before.actor_paths),
        scene_fingerprint(&after.actor_paths),
        added.len(),
        removed.len(),
        added.len() > MAX_DIFF_PATHS || removed.len() > MAX_DIFF_PATHS,
        path_list_json(&added),
        path_list_json(&removed),
        path_list_json(&before.selected.iter().map(|actor| actor.path.clone()).collect::<Vec<_>>()),
        path_list_json(&after.selected.iter().map(|actor| actor.path.clone()).collect::<Vec<_>>()),
        before.camera.json(),
        after.camera.json(),
        transform_count > MAX_DIFF_PATHS,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_rows_are_parsed_but_summaries_are_not() {
        let output = "StaticMeshActor Map.TheWorld:PersistentLevel.Mesh_0 10 20 3 4\n2 Objects (1K / 2K)";
        assert_eq!(
            parse_actor_paths(output),
            vec!["Map.TheWorld:PersistentLevel.Mesh_0"]
        );
    }

    #[test]
    fn fingerprints_are_stable_and_order_sensitive() {
        let one = vec!["A".to_string(), "B".to_string()];
        let two = vec!["B".to_string(), "A".to_string()];
        assert_eq!(scene_fingerprint(&one), scene_fingerprint(&one));
        assert_ne!(scene_fingerprint(&one), scene_fingerprint(&two));
    }

    #[test]
    fn snapshot_tokens_are_strict() {
        assert_eq!(parse_id("state-42").unwrap(), 42);
        assert!(parse_id("42").is_err());
        assert!(parse_id("state-x").is_err());
    }
}
