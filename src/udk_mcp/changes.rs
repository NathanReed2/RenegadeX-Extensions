//! Read-only inspection of UE3's native transaction buffer and package dirtiness.
//!
//! The offsets below come from the symbolized source build and were checked
//! against the RenXSDK target. Runtime byte guards cover both the editor's
//! `Trans` pointer and the two package dirty fields before any layout read.

use std::ffi::c_void;

use super::{
    find_object_by_path, find_object_by_path_of_class, image_address, json_escape,
    run_static_exec,
};

pub(super) const DEFAULT_HISTORY_LIMIT: usize = 32;
pub(super) const MAX_HISTORY_LIMIT: usize = 128;
pub(super) const DEFAULT_PACKAGE_LIMIT: usize = 100;
pub(super) const MAX_PACKAGE_LIMIT: usize = 500;
const MAX_PACKAGE_SCAN: usize = 4096;
const MAX_QUERY_LENGTH: usize = 256;

const EDITOR_TRANS_OFFSET: usize = 0x8B0;
const TRANS_UNDO_DATA_OFFSET: usize = 0x60;
const TRANS_UNDO_NUM_OFFSET: usize = 0x68;
const TRANS_UNDO_CAPACITY_OFFSET: usize = 0x6C;
const TRANS_UNDO_COUNT_OFFSET: usize = 0x70;
const TRANS_RESET_REASON_OFFSET: usize = 0x74;
const TRANS_ACTIVE_COUNT_OFFSET: usize = 0x84;
const TRANS_MAX_MEMORY_OFFSET: usize = 0x88;
const TRANSACTION_SIZE: usize = 0x7C;
const TRANSACTION_TITLE_OFFSET: usize = 0x18;

const PACKAGE_DIRTY_OFFSET: usize = 0x60;
const PACKAGE_DIRTY_FOR_PIE_OFFSET: usize = 0x64;

const BEGIN_TRANSACTION_RVA: usize = 0x0128_8A90;
const BEGIN_TRANSACTION_LAYOUT_GUARD: &[u8] = &[
    0x48, 0x8B, 0x89, 0xB0, 0x08, 0x00, 0x00, 0x48, 0x8B, 0x01, 0x48, 0xFF, 0xA0, 0x68,
    0x02, 0x00, 0x00,
];
const TRANSACTION_ENTRY_LAYOUT_RVA: usize = 0x012B_DF1C;
const TRANSACTION_ENTRY_LAYOUT_GUARD: &[u8] = &[
    0x48, 0x63, 0xED, 0x48, 0x6B, 0xED, 0x7C, 0x48, 0x03, 0x6E, 0x60, 0x8B, 0x45, 0x20,
];
const CAN_UNDO_LAYOUT_RVA: usize = 0x012C_0FE0;
const CAN_UNDO_LAYOUT_GUARD: &[u8] = &[
    0x48, 0x8B, 0xC4, 0x57, 0x48, 0x83, 0xEC, 0x70, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE,
    0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x8B, 0xDA,
    0x48, 0x8B, 0xF9, 0x83, 0xB9, 0x84, 0x00, 0x00, 0x00, 0x00,
];
const RESET_REASON_LAYOUT_RVA: usize = 0x012C_1093;
const RESET_REASON_LAYOUT_GUARD: &[u8] = &[
    0x4C, 0x8D, 0x47, 0x74, 0x48, 0x8D, 0x54, 0x24, 0x38,
];
const PACKAGE_DIRTY_WRITE_RVA: usize = 0x001E_921D;
const PACKAGE_DIRTY_LAYOUT_GUARD: &[u8] = &[
    0x89, 0x77, 0x60, 0x85, 0xF6, 0x74, 0x07, 0xC7, 0x47, 0x64, 0x01, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListedPackage {
    path: String,
    num_bytes: u64,
    max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransactionState {
    buffered_count: usize,
    slot_capacity: usize,
    undo_count: usize,
    redo_count: usize,
    active_count: i32,
    reset_reason: String,
    max_memory_bytes: usize,
    undo_titles: Vec<(usize, String)>,
    redo_titles: Vec<(usize, String)>,
}

fn validate_bytes(rva: usize, expected: &[u8], name: &str) -> Result<(), String> {
    let address = image_address(rva, expected.len(), name).map_err(|error| error.to_string())?;
    let actual = unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) };
    if actual != expected {
        return Err(format!(
            "{name} no longer matches the verified RenXSDK layout at RVA 0x{rva:X}; inspection was refused"
        ));
    }
    Ok(())
}

unsafe fn read_unaligned<T: Copy>(base: *const u8, offset: usize) -> T {
    unsafe { std::ptr::read_unaligned(base.add(offset).cast::<T>()) }
}

unsafe fn read_fstring(base: *const u8, offset: usize, context: &str) -> Result<String, String> {
    let data = unsafe { read_unaligned::<*const u16>(base, offset) };
    let len = unsafe { read_unaligned::<i32>(base, offset + 8) };
    let capacity = unsafe { read_unaligned::<i32>(base, offset + 12) };
    if len < 0 || capacity < len || capacity > 16_384 {
        return Err(format!(
            "{context} has invalid FString bounds ({len}/{capacity}); native layout read was refused"
        ));
    }
    if len == 0 {
        return Ok(String::new());
    }
    if data.is_null() {
        return Err(format!("{context} has a null FString buffer"));
    }
    let units = unsafe { std::slice::from_raw_parts(data, len as usize) };
    let content_len = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    Ok(String::from_utf16_lossy(&units[..content_len]))
}

fn read_transactions(editor: *mut c_void) -> Result<TransactionState, String> {
    validate_bytes(
        BEGIN_TRANSACTION_RVA,
        BEGIN_TRANSACTION_LAYOUT_GUARD,
        "UEditorEngine::BeginTransaction transaction-layout guard",
    )?;
    validate_bytes(
        TRANSACTION_ENTRY_LAYOUT_RVA,
        TRANSACTION_ENTRY_LAYOUT_GUARD,
        "UTransBuffer::GetUndoDesc entry-layout guard",
    )?;
    validate_bytes(
        CAN_UNDO_LAYOUT_RVA,
        CAN_UNDO_LAYOUT_GUARD,
        "UTransBuffer::CanUndo state-layout guard",
    )?;
    validate_bytes(
        RESET_REASON_LAYOUT_RVA,
        RESET_REASON_LAYOUT_GUARD,
        "UTransBuffer::CanUndo reset-reason guard",
    )?;
    if editor.is_null() {
        return Err("editor pointer is null".to_string());
    }
    let editor_bytes = editor.cast::<u8>();
    let trans = unsafe { read_unaligned::<*const u8>(editor_bytes, EDITOR_TRANS_OFFSET) };
    if trans.is_null() {
        return Err("the editor has no transaction buffer".to_string());
    }

    let data = unsafe { read_unaligned::<*const u8>(trans, TRANS_UNDO_DATA_OFFSET) };
    let num = unsafe { read_unaligned::<i32>(trans, TRANS_UNDO_NUM_OFFSET) };
    let capacity = unsafe { read_unaligned::<i32>(trans, TRANS_UNDO_CAPACITY_OFFSET) };
    let redo_count = unsafe { read_unaligned::<i32>(trans, TRANS_UNDO_COUNT_OFFSET) };
    let active_count = unsafe { read_unaligned::<i32>(trans, TRANS_ACTIVE_COUNT_OFFSET) };
    let max_memory_bytes = unsafe { read_unaligned::<usize>(trans, TRANS_MAX_MEMORY_OFFSET) };
    if num < 0
        || capacity < num
        || capacity > 16_384
        || redo_count < 0
        || redo_count > num
        || !(0..=1024).contains(&active_count)
        || (num > 0 && data.is_null())
    {
        return Err(format!(
            "transaction buffer bounds are invalid (num={num}, capacity={capacity}, redo={redo_count}, active={active_count}); native layout read was refused"
        ));
    }

    let num = num as usize;
    let redo_count = redo_count as usize;
    let undo_count = num - redo_count;
    let reset_reason = unsafe { read_fstring(trans, TRANS_RESET_REASON_OFFSET, "reset reason")? };
    let mut titles = Vec::with_capacity(num);
    for index in 0..num {
        let transaction = unsafe { data.add(index * TRANSACTION_SIZE) };
        let title = unsafe {
            read_fstring(
                transaction,
                TRANSACTION_TITLE_OFFSET,
                &format!("transaction {index} title"),
            )?
        };
        titles.push(title);
    }

    let undo_titles = (0..undo_count)
        .rev()
        .map(|index| (index, titles[index].clone()))
        .collect();
    let redo_titles = (undo_count..num)
        .map(|index| (index, titles[index].clone()))
        .collect();
    Ok(TransactionState {
        buffered_count: num,
        slot_capacity: capacity as usize,
        undo_count,
        redo_count,
        active_count,
        reset_reason,
        max_memory_bytes,
        undo_titles,
        redo_titles,
    })
}

fn parse_package_line(line: &str) -> Option<ListedPackage> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 6 || !fields[0].eq_ignore_ascii_case("Package") {
        return None;
    }
    Some(ListedPackage {
        path: fields[1].to_string(),
        num_bytes: fields[2].parse().ok()?,
        max_bytes: fields[3].parse().ok()?,
    })
}

pub(super) fn validate_query(
    package_query: &str,
    history_limit: usize,
    package_limit: usize,
) -> Result<(), String> {
    if package_query.len() > MAX_QUERY_LENGTH
        || package_query
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(format!(
            "packageQuery must be at most {MAX_QUERY_LENGTH} characters and contain no control characters"
        ));
    }
    if !(1..=MAX_HISTORY_LIMIT).contains(&history_limit) {
        return Err(format!(
            "historyLimit must be between 1 and {MAX_HISTORY_LIMIT}"
        ));
    }
    if !(1..=MAX_PACKAGE_LIMIT).contains(&package_limit) {
        return Err(format!(
            "packageLimit must be between 1 and {MAX_PACKAGE_LIMIT}"
        ));
    }
    Ok(())
}

fn transaction_entries_json(entries: &[(usize, String)], limit: usize) -> String {
    entries
        .iter()
        .take(limit)
        .enumerate()
        .map(|(position, (buffer_index, title))| {
            format!(
                "{{\"position\":{position},\"bufferIndex\":{buffer_index},\"title\":\"{}\"}}",
                json_escape(title)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn inspect(
    editor: *mut c_void,
    include_clean_packages: bool,
    package_query: &str,
    history_limit: usize,
    package_limit: usize,
) -> Result<String, String> {
    validate_query(package_query, history_limit, package_limit)?;
    let transactions = read_transactions(editor)?;
    validate_bytes(
        PACKAGE_DIRTY_WRITE_RVA,
        PACKAGE_DIRTY_LAYOUT_GUARD,
        "UPackage::SetDirtyFlag package-layout guard",
    )?;

    let (handled, output) = run_static_exec("OBJ LIST CLASS=Package ALPHASORT")?;
    if !handled {
        return Err("UE3 did not handle the loaded-package query".to_string());
    }
    let all_packages = output
        .lines()
        .filter_map(parse_package_line)
        .take(MAX_PACKAGE_SCAN)
        .collect::<Vec<_>>();
    let query = package_query.to_ascii_lowercase();
    let package_class = find_object_by_path("Core.Package")?;
    let mut package_json = Vec::new();
    let mut matching_count = 0usize;
    let mut dirty_count = 0usize;
    let mut dirty_for_pie_count = 0usize;
    let mut group_packages_skipped = 0usize;
    let mut resolution_failure_count = 0usize;
    let mut resolution_failures = Vec::new();
    for package in all_packages
        .iter()
        .filter(|package| query.is_empty() || package.path.to_ascii_lowercase().contains(&query))
    {
        let object = match find_object_by_path_of_class(&package.path, package_class) {
            Ok(object) => object,
            Err(error) => {
                // OBJ LIST prints the short name for nested UPackage group
                // objects. They are not independently saveable file packages;
                // class-constrained lookup exposes the longer outer-qualified
                // path, so exclude them from dirty-file reporting.
                if error.starts_with("object lookup was ambiguous:") {
                    group_packages_skipped += 1;
                    continue;
                }
                resolution_failure_count += 1;
                if resolution_failures.len() < 8 {
                    resolution_failures.push(format!(
                        "{{\"path\":\"{}\",\"error\":\"{}\"}}",
                        json_escape(&package.path),
                        json_escape(&error)
                    ));
                }
                continue;
            }
        };
        let bytes = object.cast::<u8>();
        let dirty = unsafe { read_unaligned::<i32>(bytes, PACKAGE_DIRTY_OFFSET) != 0 };
        let dirty_for_pie =
            unsafe { read_unaligned::<i32>(bytes, PACKAGE_DIRTY_FOR_PIE_OFFSET) != 0 };
        if dirty {
            dirty_count += 1;
        }
        if dirty_for_pie {
            dirty_for_pie_count += 1;
        }
        if !include_clean_packages && !dirty && !dirty_for_pie {
            continue;
        }
        matching_count += 1;
        if package_json.len() < package_limit {
            package_json.push(format!(
                "{{\"path\":\"{}\",\"dirty\":{dirty},\"dirtyForPIE\":{dirty_for_pie},\"memory\":{{\"numBytes\":{},\"maxBytes\":{}}}}}",
                json_escape(&package.path),
                package.num_bytes,
                package.max_bytes
            ));
        }
    }

    let undo_entries = transaction_entries_json(&transactions.undo_titles, history_limit);
    let redo_entries = transaction_entries_json(&transactions.redo_titles, history_limit);
    let next_undo = transactions
        .undo_titles
        .first()
        .map(|(_, title)| format!("\"{}\"", json_escape(title)))
        .unwrap_or_else(|| "null".to_string());
    let next_redo = transactions
        .redo_titles
        .first()
        .map(|(_, title)| format!("\"{}\"", json_escape(title)))
        .unwrap_or_else(|| "null".to_string());
    let package_output_complete = output
        .lines()
        .rev()
        .any(|line| line.trim().contains(" Objects ("));
    Ok(format!(
        "{{\"transactionBuffer\":{{\"bufferedTransactionCount\":{},\"slotCapacity\":{},\"activeTransactionDepth\":{},\"maxMemoryBytes\":{},\"resetReason\":\"{}\",\"undo\":{{\"available\":{},\"count\":{},\"nextTitle\":{next_undo},\"returnedCount\":{},\"truncated\":{},\"entries\":[{undo_entries}]}},\"redo\":{{\"available\":{},\"count\":{},\"nextTitle\":{next_redo},\"returnedCount\":{},\"truncated\":{},\"entries\":[{redo_entries}]}}}},\"packages\":{{\"source\":\"UE3 OBJ LIST plus verified UPackage dirty fields\",\"includeClean\":{include_clean_packages},\"query\":\"{}\",\"parsedPackageCount\":{},\"topLevelPackageCount\":{},\"groupPackagesSkipped\":{group_packages_skipped},\"matchingCount\":{matching_count},\"returnedCount\":{},\"dirtyCount\":{dirty_count},\"dirtyForPIECount\":{dirty_for_pie_count},\"truncated\":{},\"sourceOutputComplete\":{package_output_complete},\"resolutionFailureCount\":{resolution_failure_count},\"resolutionFailures\":[{}],\"entries\":[{}]}}}}",
        transactions.buffered_count,
        transactions.slot_capacity,
        transactions.active_count,
        transactions.max_memory_bytes,
        json_escape(&transactions.reset_reason),
        transactions.active_count == 0 && transactions.undo_count > 0,
        transactions.undo_count,
        transactions.undo_titles.len().min(history_limit),
        transactions.undo_titles.len() > history_limit,
        transactions.active_count == 0 && transactions.redo_count > 0,
        transactions.redo_count,
        transactions.redo_titles.len().min(history_limit),
        transactions.redo_titles.len() > history_limit,
        json_escape(package_query),
        all_packages.len(),
        all_packages
            .len()
            .saturating_sub(group_packages_skipped + resolution_failure_count),
        package_json.len(),
        matching_count > package_json.len(),
        resolution_failures.join(","),
        package_json.join(","),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_detailed_package_rows() {
        assert_eq!(
            parse_package_line("Package DM-Test 632 800 0 0"),
            Some(ListedPackage {
                path: "DM-Test".to_string(),
                num_bytes: 632,
                max_bytes: 800,
            })
        );
        assert!(parse_package_line("Package 1 1K 1K 0K 0K").is_none());
        assert!(parse_package_line("World DM-Test.TheWorld 1 1 0 0").is_none());
    }

    #[test]
    fn change_query_limits_are_bounded() {
        assert!(validate_query("", DEFAULT_HISTORY_LIMIT, DEFAULT_PACKAGE_LIMIT).is_ok());
        assert!(validate_query("bad\nquery", 1, 1).is_err());
        assert!(validate_query("", MAX_HISTORY_LIMIT + 1, 1).is_err());
        assert!(validate_query("", 1, MAX_PACKAGE_LIMIT + 1).is_err());
    }

    #[test]
    fn transaction_entries_are_next_action_first() {
        let entries = vec![(8, "Move Actor".to_string()), (7, "Delete".to_string())];
        let json = transaction_entries_json(&entries, 1);
        assert!(json.contains("\"position\":0"));
        assert!(json.contains("\"bufferIndex\":8"));
        assert!(json.contains("Move Actor"));
        assert!(!json.contains("Delete"));
    }
}
