//! Asset-usage and missing-reference diagnostics.
//!
//! Usage queries delegate to UE3's own `OBJ REFS`, which serializes loaded
//! objects to find inbound references and names the referencing properties.
//! Missing references cannot be loaded as UObjects, so they are recovered from
//! the bounded tail of the editor logs where UE3 records the failed import and
//! its referring object/property.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::{
    actor_identity, find_object_by_path, json_escape, object_path_from_full_name,
    run_static_exec, validate_identifier,
};

pub(super) const DEFAULT_USAGE_LIMIT: usize = 50;
pub(super) const MAX_USAGE_LIMIT: usize = 200;
pub(super) const DEFAULT_MISSING_LIMIT: usize = 50;
pub(super) const MAX_MISSING_LIMIT: usize = 200;
pub(super) const DEFAULT_LOG_FILES: usize = 3;
pub(super) const MAX_LOG_FILES: usize = 8;
const MAX_PROPERTIES_PER_REFERENCER: usize = 32;
const MAX_REACHABILITY_LINES: usize = 32;
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_QUERY_LENGTH: usize = 256;
const MAX_MESSAGE_LENGTH: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferenceScope {
    External,
    Internal,
}

impl ReferenceScope {
    fn id(self) -> &'static str {
        match self {
            ReferenceScope::External => "external",
            ReferenceScope::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Referencer {
    scope: ReferenceScope,
    full_name: String,
    total_references: usize,
    properties: Vec<String>,
    property_reference_count: usize,
    native_reference_count: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct UsageReport {
    referencers: Vec<Referencer>,
    reachability: Vec<String>,
    explicitly_unreferenced: bool,
}

fn parse_counted_identity(line: &str) -> Option<(String, usize)> {
    let trimmed = line.trim();
    let (identity, count) = trimmed.rsplit_once(" (")?;
    let count = count.strip_suffix(')')?.parse().ok()?;
    if identity.is_empty() {
        return None;
    }
    Some((identity.to_string(), count))
}

fn parse_usage_output(output: &str) -> UsageReport {
    let mut report = UsageReport::default();
    let mut scope = None;
    let mut current: Option<Referencer> = None;
    let mut reachability = false;

    let finish_current = |current: &mut Option<Referencer>, report: &mut UsageReport| {
        if let Some(value) = current.take() {
            report.referencers.push(value);
        }
    };

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("External referencers of ") {
            finish_current(&mut current, &mut report);
            scope = Some(ReferenceScope::External);
            reachability = false;
            continue;
        }
        if trimmed.starts_with("Internal referencers of ") {
            finish_current(&mut current, &mut report);
            scope = Some(ReferenceScope::Internal);
            reachability = false;
            continue;
        }
        if trimmed.starts_with("Shortest reachability from root to ") {
            finish_current(&mut current, &mut report);
            scope = None;
            reachability = true;
            continue;
        }
        if trimmed.ends_with(" is not referenced") {
            report.explicitly_unreferenced = true;
            continue;
        }
        if reachability {
            if !trimmed.is_empty() && report.reachability.len() < MAX_REACHABILITY_LINES {
                report.reachability.push(trimmed.to_string());
            }
            continue;
        }

        let leading_spaces = line.len().saturating_sub(line.trim_start().len());
        if leading_spaces >= 6 {
            let Some(referencer) = current.as_mut() else {
                continue;
            };
            let Some((_, detail)) = trimmed.split_once(") ") else {
                continue;
            };
            if detail == "[[native reference]]" {
                referencer.native_reference_count += 1;
            } else {
                referencer.property_reference_count += 1;
                if referencer.properties.len() < MAX_PROPERTIES_PER_REFERENCER {
                    referencer.properties.push(detail.to_string());
                }
            }
            continue;
        }
        if leading_spaces >= 3 {
            let Some(current_scope) = scope else {
                continue;
            };
            if let Some((full_name, total_references)) = parse_counted_identity(line) {
                finish_current(&mut current, &mut report);
                current = Some(Referencer {
                    scope: current_scope,
                    full_name,
                    total_references,
                    properties: Vec::new(),
                    property_reference_count: 0,
                    native_reference_count: 0,
                });
            }
        }
    }
    finish_current(&mut current, &mut report);
    report
}

pub(super) fn validate_usage(scope: &str, limit: usize) -> Result<(), String> {
    if !matches!(scope, "all" | "external" | "internal") {
        return Err("scope must be 'all', 'external', or 'internal'".to_string());
    }
    if !(1..=MAX_USAGE_LIMIT).contains(&limit) {
        return Err(format!(
            "limit must be between 1 and {MAX_USAGE_LIMIT}"
        ));
    }
    Ok(())
}

fn referencer_json(referencer: &Referencer) -> String {
    let (class_name, path) = referencer
        .full_name
        .split_once(' ')
        .unwrap_or(("", referencer.full_name.as_str()));
    let properties = referencer
        .properties
        .iter()
        .map(|property| format!("\"{}\"", json_escape(property)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"scope\":\"{}\",\"fullName\":\"{}\",\"class\":\"{}\",\"objectPath\":\"{}\",\"totalReferences\":{},\"propertyReferenceCount\":{},\"nativeReferenceCount\":{},\"propertiesTruncated\":{},\"properties\":[{properties}]}}",
        referencer.scope.id(),
        json_escape(&referencer.full_name),
        json_escape(class_name),
        json_escape(path),
        referencer.total_references,
        referencer.property_reference_count,
        referencer.native_reference_count,
        referencer.property_reference_count > referencer.properties.len(),
    )
}

pub(super) fn usage(object_path: &str, scope: &str, limit: usize) -> Result<String, String> {
    validate_usage(scope, limit)?;
    let object = find_object_by_path(object_path)?;
    let (_, full_name, class_name) = actor_identity(object)?;
    validate_identifier(&class_name, false)?;
    let resolved_path = object_path_from_full_name(&full_name);
    let command = format!("OBJ REFS CLASS={class_name} NAME={resolved_path}");
    let (handled, output) = run_static_exec(&command)?;
    if !handled {
        return Err("UE3 did not handle the object-reference query".to_string());
    }
    let report = parse_usage_output(&output);
    let filtered = report
        .referencers
        .iter()
        .filter(|referencer| scope == "all" || referencer.scope.id() == scope)
        .collect::<Vec<_>>();
    let total_referencers = filtered.len();
    let total_references = filtered
        .iter()
        .map(|referencer| referencer.total_references)
        .sum::<usize>();
    let external_count = report
        .referencers
        .iter()
        .filter(|referencer| referencer.scope == ReferenceScope::External)
        .count();
    let internal_count = report.referencers.len() - external_count;
    let entries = filtered
        .into_iter()
        .take(limit)
        .map(referencer_json)
        .collect::<Vec<_>>();
    let reachability = report
        .reachability
        .iter()
        .map(|line| format!("\"{}\"", json_escape(line)))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"source\":\"UE3 UObject::OutputReferencers via OBJ REFS\",\"objectPath\":\"{}\",\"fullName\":\"{}\",\"class\":\"{}\",\"scope\":\"{}\",\"explicitlyUnreferenced\":{},\"externalReferencerCount\":{external_count},\"internalReferencerCount\":{internal_count},\"totalReferencers\":{total_referencers},\"totalReferences\":{total_references},\"returnedCount\":{},\"truncated\":{},\"referencers\":[{}],\"shortestRootReachability\":[{reachability}]}}",
        json_escape(resolved_path),
        json_escape(&full_name),
        json_escape(&class_name),
        json_escape(scope),
        report.explicitly_unreferenced,
        entries.len(),
        total_referencers > entries.len(),
        entries.join(","),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MissingReference {
    kind: &'static str,
    missing_path: Option<String>,
    referenced_by: Option<String>,
    property: Option<String>,
    message: String,
}

fn quoted_after<'a>(message: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let rest = message.split_once(marker)?.1;
    let (value, remainder) = rest.split_once('\'')?;
    Some((value, remainder))
}

fn parse_missing_line(line: &str) -> Option<MissingReference> {
    let message = line.trim();
    if let Some((missing, rest)) = quoted_after(message, "Failed to load '") {
        if let Some((referenced_by, rest)) = quoted_after(rest, "Referenced by '") {
            let property = quoted_after(rest, "('")
                .map(|(value, _)| value)
                .filter(|value| *value != "---")
                .map(str::to_string);
            return Some(MissingReference {
                kind: "failed_load_reference",
                missing_path: Some(missing.to_string()),
                referenced_by: Some(referenced_by.to_string()),
                property,
                message: message.chars().take(MAX_MESSAGE_LENGTH).collect(),
            });
        }
        return Some(MissingReference {
            kind: "failed_load",
            missing_path: Some(missing.to_string()),
            referenced_by: None,
            property: None,
            message: message.chars().take(MAX_MESSAGE_LENGTH).collect(),
        });
    }

    for (marker, kind) in [
        ("Can't find file '", "missing_file"),
        ("Can't find object '", "missing_object"),
        ("Failed to find object '", "missing_object"),
        ("Failed to load package '", "missing_package"),
        ("Failed to load object '", "missing_object"),
    ] {
        if let Some((missing, _)) = quoted_after(message, marker) {
            return Some(MissingReference {
                kind,
                missing_path: Some(missing.to_string()),
                referenced_by: None,
                property: None,
                message: message.chars().take(MAX_MESSAGE_LENGTH).collect(),
            });
        }
    }

    let lower = message.to_ascii_lowercase();
    if lower.contains("unresolved import")
        || lower.contains("missing import")
        || lower.contains("missing asset")
    {
        return Some(MissingReference {
            kind: "unresolved_import",
            missing_path: None,
            referenced_by: None,
            property: None,
            message: message.chars().take(MAX_MESSAGE_LENGTH).collect(),
        });
    }
    None
}

/// `UDKGame`, from `UDKGame/Binaries/Win64/UDK.exe`.
pub(super) fn udk_game_directory() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    Some(executable.parent()?.parent()?.parent()?.join("UDKGame"))
}

pub(super) fn editor_log_directory() -> Option<PathBuf> {
    Some(udk_game_directory()?.join("Logs"))
}

fn recent_log_files(max_files: usize) -> (Option<PathBuf>, Vec<(PathBuf, u64)>, Vec<String>) {
    let Some(directory) = editor_log_directory() else {
        return (
            None,
            Vec::new(),
            vec!["could not derive UDKGame/Logs from the executable path".to_string()],
        );
    };
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) => return (Some(directory), Vec::new(), vec![error.to_string()]),
    };
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                if errors.len() < 8 {
                    errors.push(error.to_string());
                }
                continue;
            }
        };
        let path = entry.path();
        if !path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("log"))
        {
            continue;
        }
        match entry.metadata() {
            Ok(metadata) if metadata.is_file() => {
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .map_or(0, |duration| duration.as_millis() as u64);
                files.push((path, modified));
            }
            Ok(_) => {}
            Err(error) => {
                if errors.len() < 8 {
                    errors.push(error.to_string());
                }
            }
        }
    }
    files.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    files.truncate(max_files);
    (Some(directory), files, errors)
}

fn read_tail(path: &Path) -> Result<(String, u64, bool), String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    let start = length.saturating_sub(MAX_LOG_BYTES);
    file.seek(SeekFrom::Start(start))
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity((length - start).min(MAX_LOG_BYTES) as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if start > 0 {
        if let Some(newline) = text.find('\n') {
            text.drain(..=newline);
        } else {
            text.clear();
        }
    }
    Ok((text, start, start > 0))
}

pub(super) fn validate_missing(query: &str, limit: usize, max_log_files: usize) -> Result<(), String> {
    if query.len() > MAX_QUERY_LENGTH
        || query
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(format!(
            "query must be at most {MAX_QUERY_LENGTH} characters and contain no control characters"
        ));
    }
    if !(1..=MAX_MISSING_LIMIT).contains(&limit) {
        return Err(format!(
            "limit must be between 1 and {MAX_MISSING_LIMIT}"
        ));
    }
    if !(1..=MAX_LOG_FILES).contains(&max_log_files) {
        return Err(format!(
            "maxLogFiles must be between 1 and {MAX_LOG_FILES}"
        ));
    }
    Ok(())
}

fn optional_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_string())
}

pub(super) fn missing_diagnostics(
    query: &str,
    limit: usize,
    max_log_files: usize,
) -> Result<String, String> {
    validate_missing(query, limit, max_log_files)?;
    let (directory, files, mut errors) = recent_log_files(max_log_files);
    let query_lower = query.to_ascii_lowercase();
    let mut diagnostics = Vec::new();
    let mut total_matches = 0usize;
    let mut duplicate_count = 0usize;
    let mut seen = HashSet::new();
    let mut scanned_bytes = 0u64;
    let mut tail_truncated = false;

    for (path, modified_unix_ms) in &files {
        let (text, start_offset, truncated) = match read_tail(path) {
            Ok(value) => value,
            Err(error) => {
                if errors.len() < 8 {
                    errors.push(format!("{}: {error}", path.display()));
                }
                continue;
            }
        };
        scanned_bytes += text.len() as u64;
        tail_truncated |= truncated;
        let lines = text.lines().collect::<Vec<_>>();
        for (tail_line, line) in lines.iter().enumerate().rev() {
            let Some(diagnostic) = parse_missing_line(line) else {
                continue;
            };
            if !query_lower.is_empty()
                && !diagnostic.message.to_ascii_lowercase().contains(&query_lower)
                && !diagnostic
                    .missing_path
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&query_lower)
            {
                continue;
            }
            let signature = format!(
                "{}\0{}\0{}\0{}\0{}",
                diagnostic.kind,
                diagnostic.missing_path.as_deref().unwrap_or_default(),
                diagnostic.referenced_by.as_deref().unwrap_or_default(),
                diagnostic.property.as_deref().unwrap_or_default(),
                diagnostic.message
            );
            if !seen.insert(signature) {
                duplicate_count += 1;
                continue;
            }
            total_matches += 1;
            if diagnostics.len() >= limit {
                continue;
            }
            diagnostics.push(format!(
                "{{\"kind\":\"{}\",\"missingPath\":{},\"referencedBy\":{},\"property\":{},\"message\":\"{}\",\"sourceFile\":\"{}\",\"sourcePath\":\"{}\",\"fileModifiedUnixMs\":{modified_unix_ms},\"tailLine\":{},\"tailStartByte\":{start_offset}}}",
                diagnostic.kind,
                optional_json(diagnostic.missing_path.as_deref()),
                optional_json(diagnostic.referenced_by.as_deref()),
                optional_json(diagnostic.property.as_deref()),
                json_escape(&diagnostic.message),
                json_escape(path.file_name().and_then(|value| value.to_str()).unwrap_or("")),
                json_escape(&path.display().to_string()),
                tail_line + 1,
            ));
        }
    }
    let error_json = errors
        .iter()
        .map(|error| format!("\"{}\"", json_escape(error)))
        .collect::<Vec<_>>()
        .join(",");
    // Which logs, not just how many. A diagnostic recovered from a log written
    // last week is a fact about last week, and the count alone cannot say so.
    let scanned = files
        .iter()
        .map(|(path, _)| ("editorLog", path.clone()))
        .collect::<Vec<_>>();
    Ok(format!(
        "{{\"source\":\"bounded tails of UE3 editor log files\",\"logDirectory\":{},\"query\":\"{}\",\"filesScanned\":{},\"artifacts\":[{}],\"artifactFields\":\"{}\",\"scannedBytes\":{scanned_bytes},\"maxBytesPerFile\":{MAX_LOG_BYTES},\"tailTruncated\":{tail_truncated},\"totalMatches\":{total_matches},\"duplicatesSkipped\":{duplicate_count},\"returnedCount\":{},\"truncated\":{},\"scanErrors\":[{error_json}],\"diagnostics\":[{}]}}",
        optional_json(directory.as_ref().map(|path| path.to_string_lossy()).as_deref()),
        json_escape(query),
        files.len(),
        super::provenance::artifacts_json(&scanned),
        super::provenance::ARTIFACT_FIELDS_NOTE,
        diagnostics.len(),
        total_matches > diagnostics.len(),
        diagnostics.join(","),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ue3_referencer_sections_and_properties() {
        let output = concat!(
            "External referencers of Material Pkg.Mat:\r\n",
            "   StaticMeshActor Map.TheWorld:PersistentLevel.Mesh_0 (2)\r\n",
            "      0) ObjectProperty Engine.StaticMeshComponent.Materials\r\n",
            "      1) [[native reference]]\r\n",
            "Internal referencers of Material Pkg.Mat:\r\n",
            "   MaterialExpression Pkg.Mat.Expression_0 (1)\r\n",
            "      0) ObjectProperty Engine.MaterialExpression.Owner\r\n",
            "Shortest reachability from root to Material Pkg.Mat:\r\n",
            "Root -> Package Pkg -> Material Pkg.Mat\r\n",
        );
        let parsed = parse_usage_output(output);
        assert_eq!(parsed.referencers.len(), 2);
        assert_eq!(parsed.referencers[0].scope, ReferenceScope::External);
        assert_eq!(parsed.referencers[0].total_references, 2);
        assert_eq!(parsed.referencers[0].property_reference_count, 1);
        assert_eq!(parsed.referencers[0].native_reference_count, 1);
        assert_eq!(parsed.reachability.len(), 1);
    }

    #[test]
    fn parses_failed_load_with_referring_object_and_property() {
        let parsed = parse_missing_line(
            "Warning: Failed to load 'Texture2D Pkg.Missing'! Referenced by 'Map.Actor_0' ('StaticMeshComponent.Materials').",
        )
        .unwrap();
        assert_eq!(parsed.kind, "failed_load_reference");
        assert_eq!(parsed.missing_path.as_deref(), Some("Texture2D Pkg.Missing"));
        assert_eq!(parsed.referenced_by.as_deref(), Some("Map.Actor_0"));
        assert_eq!(
            parsed.property.as_deref(),
            Some("StaticMeshComponent.Materials")
        );
    }

    #[test]
    fn parses_common_missing_file_and_import_forms() {
        assert_eq!(
            parse_missing_line("Error: Can't find file 'Pkg_Gone'")
                .unwrap()
                .kind,
            "missing_file"
        );
        assert_eq!(
            parse_missing_line("Warning: unresolved import Texture2D Pkg.Missing")
                .unwrap()
                .kind,
            "unresolved_import"
        );
        assert!(parse_missing_line("Log: package loaded normally").is_none());
    }

    #[test]
    fn diagnostic_limits_and_scope_are_bounded() {
        assert!(validate_usage("all", DEFAULT_USAGE_LIMIT).is_ok());
        assert!(validate_usage("outbound", 1).is_err());
        assert!(validate_usage("all", MAX_USAGE_LIMIT + 1).is_err());
        assert!(validate_missing("", DEFAULT_MISSING_LIMIT, DEFAULT_LOG_FILES).is_ok());
        assert!(validate_missing("bad\nquery", 1, 1).is_err());
        assert!(validate_missing("", 1, MAX_LOG_FILES + 1).is_err());
    }
}
