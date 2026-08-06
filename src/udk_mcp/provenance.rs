//! What is actually on disk behind an answer, and whether this session put it
//! there.
//!
//! # Why
//!
//! A tool that reports on a derived file - a Play-In-Editor package, a map, a
//! log - is only ever as current as that file, and nothing in the reply used to
//! say when the file was written. That gap cost an afternoon: three consecutive
//! experiments ran against one four-hour-old `UEDPIE*.udk`, every result agreed
//! with every other, and the agreement was read as a finding rather than as the
//! tell that nothing was being rebuilt between runs.
//!
//! The rule here is deliberately narrow and mechanical. When a tool's answer
//! depends on a file, the reply names the file, its size, when it was last
//! written, and whether that was before or after this editor session started.
//!
//! # The field that earns this module
//!
//! `writtenThisSession`. Size and time are facts a caller then has to reason
//! about; this one is the conclusion, and it is the sentence that ends an
//! invalid experiment early: an artifact that predates the session cannot be
//! the product of anything the session did, no matter what the tool that read
//! it reports.
//!
//! # What it does not claim
//!
//! Nothing here explains *why* a file is old. A stale Play-In-Editor package
//! might mean the engine reused it, or that the save failed, or that the run
//! never happened. Reporting the timestamp answers a question; guessing the
//! mechanism from it would invent one.

use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{assets, flight, json_escape};

/// A reply is not a directory listing.
const MAX_ARTIFACTS: usize = 8;
/// Content/Maps nests by project, not deeply. Enough to find a map, bounded so
/// a mistaken root cannot walk the whole content tree.
const MAX_MAP_SEARCH_DEPTH: usize = 4;
const MAX_MAP_SEARCH_ENTRIES: usize = 4096;

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

fn modified_unix_ms(metadata: &Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_millis() as u64)
}

/// `None` when either side is unknown, because "the file has no usable
/// timestamp" and "the file is older than the session" are different findings
/// and only one of them is evidence.
fn written_this_session(modified_unix_ms: u64, session_started_unix_ms: u64) -> Option<bool> {
    if modified_unix_ms == 0 || session_started_unix_ms == 0 {
        return None;
    }
    Some(modified_unix_ms >= session_started_unix_ms)
}

/// Deliberately factual and role-agnostic.
///
/// An earlier version told the reader what the staleness meant for them - "if
/// you expected this call to have rebuilt it, it did not" - which reads as
/// nonsense on an input nobody was rebuilding, like the policy file. The note
/// states when the file was written relative to the session; what that implies
/// belongs in the legend attached to the list, where it can be said once.
fn note(written: Option<bool>, modified_unix_ms: u64, session_started_unix_ms: u64) -> String {
    match written {
        Some(false) => format!(
            "Last written {}s before this editor session started, so nothing in this session \
             wrote it.",
            session_started_unix_ms.saturating_sub(modified_unix_ms) / 1000
        ),
        Some(true) => format!(
            "Written {}s into this editor session.",
            modified_unix_ms.saturating_sub(session_started_unix_ms) / 1000
        ),
        None => "Cannot tell whether this session wrote it: either the file has no usable \
                 timestamp or the session start is unknown."
            .to_string(),
    }
}

/// Said once, beside the list, rather than repeated into every record.
pub(super) const ARTIFACT_FIELDS_NOTE: &str = "artifacts are the files this answer depended on. \
     writtenThisSession is false when the file predates this editor session, so nothing this \
     session did produced it - treat any result derived from it as describing an earlier state, \
     and do not read it as confirmation that the call rebuilt anything.";

/// One file, described. `role` says what the file is to the caller rather than
/// what it is on disk, because a caller deciding whether to trust an answer is
/// asking about the former.
pub(super) fn artifact_json(role: &str, path: &Path) -> String {
    let displayed = json_escape(&path.display().to_string());
    let role = json_escape(role);
    let Some(metadata) = fs::metadata(path).ok().filter(Metadata::is_file) else {
        return format!(
            r#"{{"role":"{role}","path":"{displayed}","exists":false,"sizeBytes":null,"modifiedUnixMs":null,"ageSeconds":null,"writtenThisSession":null,"note":"No file at this path, so nothing was read from it."}}"#
        );
    };
    let modified = modified_unix_ms(&metadata);
    let session = flight::session_started_unix_ms();
    let written = written_this_session(modified, session);
    format!(
        r#"{{"role":"{role}","path":"{displayed}","exists":true,"sizeBytes":{},"modifiedUnixMs":{},"ageSeconds":{},"writtenThisSession":{},"note":"{}"}}"#,
        metadata.len(),
        optional_u64(modified),
        match modified {
            0 => "null".to_string(),
            modified => (now_unix_ms().saturating_sub(modified) / 1000).to_string(),
        },
        match written {
            Some(value) => value.to_string(),
            None => "null".to_string(),
        },
        json_escape(&note(written, modified, session)),
    )
}

fn optional_u64(value: u64) -> String {
    match value {
        0 => "null".to_string(),
        value => value.to_string(),
    }
}

pub(super) fn artifacts_json(items: &[(&str, PathBuf)]) -> String {
    items
        .iter()
        .take(MAX_ARTIFACTS)
        .map(|(role, path)| artifact_json(role, path))
        .collect::<Vec<_>>()
        .join(",")
}

/// The packages the editor writes when it plays a map.
///
/// Listed by scanning rather than by deriving the name from the map currently
/// loaded, which also surfaces leftovers from other maps - and a leftover is
/// exactly the thing that looks like a fresh result.
pub(super) fn play_in_editor_packages() -> Vec<(&'static str, PathBuf)> {
    let Some(directory) = assets::udk_game_directory().map(|root| root.join("Autosaves")) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        // UE3 names them UEDPIE<map>.udk in the autosave directory.
        if name.len() > 6 && name[..6].eq_ignore_ascii_case("UEDPIE") {
            found.push(("playInEditorPackage", path));
        }
    }
    found.sort_by(|left, right| left.1.cmp(&right.1));
    found.truncate(MAX_ARTIFACTS);
    found
}

/// The `.udk` a map was loaded from, searched for by package name.
///
/// UE3 knows the answer exactly, in the linker, but that is a struct offset in
/// a stripped binary. A bounded search of the content tree is one directory
/// walk and cannot be wrong about a file it actually found.
pub(super) fn map_package(map: &str) -> Option<PathBuf> {
    if map.is_empty() || !map.chars().all(is_safe_package_character) {
        return None;
    }
    let root = assets::udk_game_directory()?.join("Content").join("Maps");
    let target = format!("{map}.udk");
    let mut budget = MAX_MAP_SEARCH_ENTRIES;
    find_file(&root, &target, MAX_MAP_SEARCH_DEPTH, &mut budget)
}

/// Package names come from engine output, so this is a guard against a search
/// path assembled out of something unexpected rather than against a caller.
fn is_safe_package_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ' ')
}

fn find_file(directory: &Path, target: &str, depth: usize, budget: &mut usize) -> Option<PathBuf> {
    if depth == 0 || *budget == 0 {
        return None;
    }
    let entries = fs::read_dir(directory).ok()?;
    let mut directories = Vec::new();
    for entry in entries.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            directories.push(path);
            continue;
        }
        if path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case(target))
        {
            return Some(path);
        }
    }
    // Breadth first: a map is far more often directly under Content/Maps than
    // buried, and this stops one deep branch from eating the whole budget.
    for child in directories {
        if let Some(found) = find_file(&child, target, depth - 1, budget) {
            return Some(found);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_artifact_older_than_the_session_is_not_this_sessions_work() {
        assert_eq!(written_this_session(500, 1000), Some(false));
        assert_eq!(written_this_session(1500, 1000), Some(true));
        // Written at the very instant the session began still counts as this
        // session's: the alternative is to call a file the session wrote
        // "stale" over a millisecond of clock resolution.
        assert_eq!(written_this_session(1000, 1000), Some(true));
    }

    /// The distinction the `Option` exists for. Without a session start there
    /// is no comparison to make, and answering `false` would read as "this is
    /// stale" - an accusation drawn from a missing number.
    #[test]
    fn an_unknown_timestamp_answers_nothing_rather_than_false() {
        assert_eq!(written_this_session(0, 1000), None);
        assert_eq!(written_this_session(1000, 0), None);
        assert_eq!(written_this_session(0, 0), None);
    }

    #[test]
    fn a_stale_artifact_says_how_far_it_predates_the_session() {
        let stale = note(Some(false), 1_000_000, 1_030_000);
        assert!(stale.contains("30s before"), "{stale}");
        assert!(stale.contains("nothing in this session wrote it"), "{stale}");
        assert!(note(Some(true), 6000, 1000).contains("5s into"));
        assert!(note(None, 0, 0).contains("Cannot tell"));
    }

    /// The note is attached to inputs as well as to derived files, so it must
    /// not assume the caller was trying to produce the thing it describes - the
    /// policy file is read by a status call that was never going to write it.
    #[test]
    fn the_note_does_not_assume_the_caller_built_the_file() {
        for text in [
            note(Some(false), 1_000, 2_000),
            note(Some(true), 2_000, 1_000),
        ] {
            assert!(!text.contains("rebuil"), "{text}");
            assert!(!text.contains("expected"), "{text}");
        }
    }

    #[test]
    fn the_legend_needs_no_escaping() {
        assert!(!ARTIFACT_FIELDS_NOTE.contains('"'));
        assert!(!ARTIFACT_FIELDS_NOTE.contains('\\'));
        assert!(!ARTIFACT_FIELDS_NOTE.contains('\n'));
    }

    #[test]
    fn a_missing_file_reports_absence_rather_than_a_zero_size() {
        let json = artifact_json("mapPackage", Path::new("Z:\\nothing\\here.udk"));
        assert_eq!(super::super::json_field_raw(&json, "exists"), Some("false"));
        assert_eq!(super::super::json_field_raw(&json, "sizeBytes"), Some("null"));
        assert_eq!(
            super::super::json_field_raw(&json, "writtenThisSession"),
            Some("null")
        );
    }

    /// This file exists, so the shape can be checked against something real
    /// rather than against a fixture that agrees with the code by construction.
    #[test]
    fn a_real_file_reports_a_size_and_a_time() {
        let executable = std::env::current_exe().unwrap();
        let json = artifact_json("selfTest", &executable);
        assert_eq!(super::super::json_field_raw(&json, "exists"), Some("true"));
        let size = super::super::json_field_raw(&json, "sizeBytes")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap();
        assert!(size > 0);
        assert!(super::super::json_field_raw(&json, "modifiedUnixMs") != Some("null"));
    }

    #[test]
    fn a_package_name_that_could_redirect_the_search_is_refused() {
        assert!(map_package("").is_none());
        assert!(map_package("../../Windows/System32/config").is_none());
        assert!(map_package("CNC-Field/../../..").is_none());
        // The characters a real UE3 package name uses have to survive.
        assert!(is_safe_package_character('C'));
        assert!(is_safe_package_character('-'));
        assert!(is_safe_package_character('_'));
        assert!(!is_safe_package_character('/'));
        assert!(!is_safe_package_character('\\'));
    }

    #[test]
    fn the_artifact_list_is_bounded() {
        let many = (0..MAX_ARTIFACTS + 5)
            .map(|index| ("log", PathBuf::from(format!("Z:\\missing\\{index}.log"))))
            .collect::<Vec<_>>();
        let json = artifacts_json(&many);
        assert_eq!(json.matches("\"role\"").count(), MAX_ARTIFACTS);
    }
}
