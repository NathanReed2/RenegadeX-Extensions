//! Bounded capture of UE3's native Map Check findings.
//!
//! MAP CHECK sends structured records to FFeedbackContextEditor::MapCheck_Add;
//! it does not write those records to the command's FOutputDevice. Hooking this
//! small wrapper preserves the engine's own validation rules and avoids parsing
//! localized UI/log strings.

use anyhow::{bail, Context};
use retour::static_detour;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use super::{
    actor_identity, image_address, json_escape, object_path_from_full_name, run_editor_exec,
};

const MAP_CHECK_ADD_RVA: usize = 0x00F0_42F0;
const MAP_CHECK_ADD_PROLOGUE: &[u8] = &[
    0x48, 0x83, 0xEC, 0x38, 0x48, 0x8B, 0x44, 0x24, 0x60, 0x8B, 0xCA, 0x8B, 0x54, 0x24, 0x68,
    0x48, 0x89, 0x44, 0x24, 0x20, 0xE8, 0xE7, 0x49, 0x71, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3,
];
const MAX_CAPTURED_FINDINGS: usize = 4096;
pub(super) const DEFAULT_LIMIT: usize = 200;
pub(super) const MAX_LIMIT: usize = 500;
const MAX_WIDE_UNITS: usize = 32 * 1024;

type MapCheckAddFn = extern "C" fn(
    *mut c_void,
    u32,
    *mut c_void,
    *const u16,
    *const u16,
    u32,
);

static_detour! {
    static MapCheckAddHook: extern "C" fn(
        *mut c_void,
        u32,
        *mut c_void,
        *const u16,
        *const u16,
        u32
    );
}

#[derive(Default)]
struct Capture {
    findings: Vec<Finding>,
    total_seen: usize,
    dropped: usize,
}

struct Finding {
    severity: &'static str,
    group: String,
    category: String,
    object_path: String,
    full_name: String,
    class_name: String,
    message: String,
}

static CAPTURE: OnceLock<Mutex<Option<Capture>>> = OnceLock::new();

fn capture_slot() -> &'static Mutex<Option<Capture>> {
    CAPTURE.get_or_init(|| Mutex::new(None))
}

pub(super) fn init() -> anyhow::Result<()> {
    let address = image_address(
        MAP_CHECK_ADD_RVA,
        MAP_CHECK_ADD_PROLOGUE.len(),
        "FFeedbackContextEditor::MapCheck_Add",
    )?;
    let actual = unsafe {
        std::slice::from_raw_parts(address as *const u8, MAP_CHECK_ADD_PROLOGUE.len())
    };
    if actual != MAP_CHECK_ADD_PROLOGUE {
        bail!(
            "FFeedbackContextEditor::MapCheck_Add validation failed at RVA 0x{MAP_CHECK_ADD_RVA:X}: expected {:02X?}, found {:02X?}",
            MAP_CHECK_ADD_PROLOGUE,
            actual
        );
    }
    let function: MapCheckAddFn = unsafe { std::mem::transmute(address) };
    unsafe {
        MapCheckAddHook
            .initialize(
                function,
                |feedback, kind, object, message, udn_page, group| {
                    map_check_add_hook(feedback, kind, object, message, udn_page, group)
                },
            )
            .context("failed to set up MapCheck_Add capture hook")?;
        MapCheckAddHook
            .enable()
            .context("failed to enable MapCheck_Add capture hook")?;
    }
    Ok(())
}

extern "C" fn map_check_add_hook(
    feedback: *mut c_void,
    kind: u32,
    object: *mut c_void,
    message: *const u16,
    udn_page: *const u16,
    group: u32,
) {
    MapCheckAddHook.call(feedback, kind, object, message, udn_page, group);

    let mut capture = capture_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(capture) = capture.as_mut() else {
        return;
    };
    capture.total_seen = capture.total_seen.saturating_add(1);
    if capture.findings.len() >= MAX_CAPTURED_FINDINGS {
        capture.dropped = capture.dropped.saturating_add(1);
        return;
    }

    let (full_name, class_name) = if object.is_null() {
        (String::new(), String::new())
    } else {
        actor_identity(object)
            .map(|(_, full_name, class_name)| (full_name, class_name))
            .unwrap_or_default()
    };
    capture.findings.push(Finding {
        severity: severity_name(kind),
        group: group_name(group),
        category: unsafe { wide_string(udn_page) },
        object_path: object_path_from_full_name(&full_name).to_string(),
        full_name,
        class_name,
        message: unsafe { wide_string(message) },
    });
}

unsafe fn wide_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while len < MAX_WIDE_UNITS && *value.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(value, len))
}

fn severity_name(kind: u32) -> &'static str {
    match kind {
        1 => "critical",
        2 => "error",
        4 => "performance_warning",
        8 => "warning",
        16 => "note",
        32 => "info",
        _ => "unknown",
    }
}

fn group_name(group: u32) -> String {
    match group {
        0 => "default".to_string(),
        1 => "kismet".to_string(),
        2 => "mobile".to_string(),
        value => format!("unknown_{value}"),
    }
}

pub(super) fn report(
    editor: *mut c_void,
    include_slow_reference_checks: bool,
    categories: &[String],
    limit: usize,
) -> Result<String, String> {
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
    }
    if categories.len() > 32
        || categories.iter().any(|category| {
            category.is_empty()
                || category.len() > 128
                || !category
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
        })
    {
        return Err("categories must contain at most 32 UE3 MapCheck identifiers".to_string());
    }

    {
        let mut slot = capture_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.is_some() {
            return Err("a map-health capture is already active".to_string());
        }
        *slot = Some(Capture::default());
    }

    let command = if include_slow_reference_checks {
        "MAP CHECK DONTCLEARMESSAGES DONTDISPLAYDIALOG"
    } else {
        "MAP CHECK DONTCLEARMESSAGES DONTDISPLAYDIALOG DONTDOSLOWREFCHECK"
    };
    let exec_result = run_editor_exec(editor, command);
    let capture = capture_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or_else(|| "map-health capture ended unexpectedly".to_string())?;
    let (handled, output) = exec_result?;
    if !handled {
        return Err("UE3 did not handle MAP CHECK".to_string());
    }

    let filtered = capture
        .findings
        .iter()
        .filter(|finding| {
            categories.is_empty()
                || categories
                    .iter()
                    .any(|category| finding.category.eq_ignore_ascii_case(category))
        })
        .collect::<Vec<_>>();
    let matching_count = filtered.len();
    let findings = filtered
        .into_iter()
        .take(limit)
        .map(finding_json)
        .collect::<Vec<_>>()
        .join(",");

    let mut counts = [0usize; 7];
    for finding in &capture.findings {
        let index = match finding.severity {
            "critical" => 0,
            "error" => 1,
            "performance_warning" => 2,
            "warning" => 3,
            "note" => 4,
            "info" => 5,
            _ => 6,
        };
        counts[index] += 1;
    }
    let category_filter = categories
        .iter()
        .map(|category| format!("\"{}\"", json_escape(category)))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"handled\":true,\"engineCheck\":\"MAP CHECK\",\"includeSlowReferenceChecks\":{include_slow_reference_checks},\"selectionTouched\":false,\"mapMutated\":false,\"categoryFilter\":[{category_filter}],\"totalFindings\":{},\"capturedFindings\":{},\"matchingFindings\":{matching_count},\"returnedFindings\":{},\"truncated\":{},\"droppedDuringCapture\":{},\"severityCounts\":{{\"critical\":{},\"error\":{},\"performanceWarning\":{},\"warning\":{},\"note\":{},\"info\":{},\"unknown\":{}}},\"findings\":[{findings}],\"commandOutput\":\"{}\"}}",
        capture.total_seen,
        capture.findings.len(),
        matching_count.min(limit),
        matching_count > limit || capture.dropped > 0,
        capture.dropped,
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        counts[4],
        counts[5],
        counts[6],
        json_escape(&output),
    ))
}

fn finding_json(finding: &Finding) -> String {
    format!(
        "{{\"severity\":\"{}\",\"group\":\"{}\",\"category\":\"{}\",\"objectPath\":\"{}\",\"fullName\":\"{}\",\"class\":\"{}\",\"message\":\"{}\"}}",
        finding.severity,
        json_escape(&finding.group),
        json_escape(&finding.category),
        json_escape(&finding.object_path),
        json_escape(&finding.full_name),
        json_escape(&finding.class_name),
        json_escape(&finding.message),
    )
}

#[cfg(test)]
mod tests {
    use super::{group_name, severity_name};

    #[test]
    fn maps_source_backed_map_check_enums() {
        assert_eq!(severity_name(1), "critical");
        assert_eq!(severity_name(2), "error");
        assert_eq!(severity_name(4), "performance_warning");
        assert_eq!(severity_name(8), "warning");
        assert_eq!(severity_name(16), "note");
        assert_eq!(severity_name(32), "info");
        assert_eq!(group_name(0), "default");
        assert_eq!(group_name(1), "kismet");
        assert_eq!(group_name(2), "mobile");
    }
}
