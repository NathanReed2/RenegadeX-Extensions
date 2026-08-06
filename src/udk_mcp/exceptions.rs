//! Persistent, allocation-free first-chance exception context capture.
//!
//! A vectored handler writes fixed-size records to a file-backed memory map.
//! The handler never allocates, locks, logs, calls UE3, or consumes an
//! exception. Records can therefore be inspected after a restart when the
//! previous process ended before a clean DLL detach.

use std::cell::UnsafeCell;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use windows::Win32::System::{
    Diagnostics::Debug::{AddVectoredExceptionHandler, EXCEPTION_POINTERS},
    SystemInformation::GetSystemTimeAsFileTime,
    Threading::{GetCurrentProcessId, GetCurrentThreadId},
};

use super::mapped::{Region, Zeroable};
use super::{assets, json_escape};

pub(super) const DEFAULT_LIMIT: usize = 32;
pub(super) const MAX_LIMIT: usize = 64;
const SLOT_COUNT: usize = 64;
const FATAL_SLOT_COUNT: usize = 48;
const DIAGNOSTIC_SLOT_COUNT: usize = SLOT_COUNT - FATAL_SLOT_COUNT;
const FORMAT_MAGIC: u64 = 0x3147_4F4C_5845_4D52; // "RMEXLOG1" little-endian
const FORMAT_VERSION: u32 = 2;
const WINDOWS_TO_UNIX_100NS: u64 = 116_444_736_000_000_000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ExceptionPayload {
    session_id: u64,
    timestamp_filetime: u64,
    process_id: u32,
    thread_id: u32,
    code: u32,
    flags: u32,
    parameter_count: u32,
    _reserved: u32,
    exception_address: u64,
    rip: u64,
    rsp: u64,
    rbp: u64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    parameters: [u64; 15],
}

#[repr(C)]
struct ExceptionSlot {
    published_sequence: AtomicU64,
    payload: UnsafeCell<ExceptionPayload>,
}

unsafe impl Sync for ExceptionSlot {}

#[repr(C)]
struct PersistentLog {
    magic: u64,
    version: u32,
    capacity: u32,
    next_sequence: AtomicU64,
    next_fatal_slot: AtomicU64,
    next_diagnostic_slot: AtomicU64,
    last_session_id: AtomicU64,
    last_session_clean: AtomicU32,
    _header_pad: u32,
    previous_session_id: AtomicU64,
    previous_session_clean: AtomicU32,
    _previous_pad: u32,
    slots: [ExceptionSlot; SLOT_COUNT],
}

unsafe impl Zeroable for PersistentLog {}

static STORAGE: OnceLock<Region<PersistentLog>> = OnceLock::new();
static ACTIVE_LOG: AtomicPtr<PersistentLog> = AtomicPtr::new(std::ptr::null_mut());
static SESSION_ID: AtomicU64 = AtomicU64::new(0);
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);
static DIAGNOSTIC_FINGERPRINTS: [AtomicU64; DIAGNOSTIC_SLOT_COUNT] =
    [const { AtomicU64::new(0) }; DIAGNOSTIC_SLOT_COUNT];

fn make_storage() -> Region<PersistentLog> {
    Region::open("RenXMCPExceptionContext.bin")
}

unsafe fn initialize_header(log: *mut PersistentLog, session_id: u64) {
    let invalid = unsafe {
        (*log).magic != FORMAT_MAGIC
            || (*log).version != FORMAT_VERSION
            || (*log).capacity != SLOT_COUNT as u32
    };
    if invalid {
        unsafe { log.write_bytes(0, 1) };
        unsafe {
            (*log).magic = FORMAT_MAGIC;
            (*log).version = FORMAT_VERSION;
            (*log).capacity = SLOT_COUNT as u32;
        }
    }
    let previous_id = unsafe { (*log).last_session_id.load(Ordering::Acquire) };
    let previous_clean = unsafe { (*log).last_session_clean.load(Ordering::Acquire) };
    unsafe {
        (*log)
            .previous_session_id
            .store(previous_id, Ordering::Release);
        (*log)
            .previous_session_clean
            .store(previous_clean, Ordering::Release);
        (*log).last_session_id.store(session_id, Ordering::Release);
        (*log).last_session_clean.store(0, Ordering::Release);
    }
}

fn skipped_exception(code: u32) -> bool {
    matches!(
        code,
        0x4001_0006 // debugger print, ANSI
            | 0x4001_000A // debugger print, wide
            | 0x406D_1388 // MSVC thread-name notification
            | 0x8000_0003 // breakpoint
            | 0x8000_0004 // single-step
    )
}

/// UE3 uses handled C++/RPC exceptions during normal startup. Retaining every
/// throw would evict the hardware faults this feature exists to diagnose, so
/// the diagnostic partition keeps only the first code/address fingerprint per
/// session. Fatal-candidate records bypass this table entirely.
fn first_diagnostic_occurrence(code: u32, address: u64) -> bool {
    let mut fingerprint = ((code as u64) << 32) ^ address.rotate_left(17);
    if fingerprint == 0 {
        fingerprint = 1;
    }
    let start = fingerprint as usize % DIAGNOSTIC_SLOT_COUNT;
    for offset in 0..DIAGNOSTIC_SLOT_COUNT {
        let slot = &DIAGNOSTIC_FINGERPRINTS[(start + offset) % DIAGNOSTIC_SLOT_COUNT];
        let current = slot.load(Ordering::Acquire);
        if current == fingerprint {
            return false;
        }
        if current == 0
            && slot
                .compare_exchange(0, fingerprint, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return true;
        }
    }
    false
}

unsafe extern "system" fn vectored_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let log = ACTIVE_LOG.load(Ordering::Acquire);
    if log.is_null() || info.is_null() {
        return 0;
    }
    let exception_record = unsafe { (*info).ExceptionRecord };
    let context = unsafe { (*info).ContextRecord };
    if exception_record.is_null() || context.is_null() {
        return 0;
    }
    let record = unsafe { &*exception_record };
    let code = record.ExceptionCode.0 as u32;
    if skipped_exception(code) {
        return 0;
    }
    let fatal_candidate = likely_fatal(code);
    if !fatal_candidate
        && !first_diagnostic_occurrence(code, record.ExceptionAddress as usize as u64)
    {
        return 0;
    }
    let context = unsafe { &*context };
    let filetime = unsafe { GetSystemTimeAsFileTime() };
    let timestamp_filetime =
        ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64;
    let mut payload = ExceptionPayload {
        session_id: SESSION_ID.load(Ordering::Relaxed),
        timestamp_filetime,
        process_id: unsafe { GetCurrentProcessId() },
        thread_id: unsafe { GetCurrentThreadId() },
        code,
        flags: record.ExceptionFlags,
        parameter_count: record.NumberParameters.min(15),
        exception_address: record.ExceptionAddress as usize as u64,
        rip: context.Rip,
        rsp: context.Rsp,
        rbp: context.Rbp,
        rax: context.Rax,
        rbx: context.Rbx,
        rcx: context.Rcx,
        rdx: context.Rdx,
        rsi: context.Rsi,
        rdi: context.Rdi,
        r8: context.R8,
        r9: context.R9,
        r10: context.R10,
        r11: context.R11,
        r12: context.R12,
        r13: context.R13,
        r14: context.R14,
        r15: context.R15,
        ..ExceptionPayload::default()
    };
    for index in 0..payload.parameter_count as usize {
        payload.parameters[index] = record.ExceptionInformation[index] as u64;
    }

    let sequence = unsafe { (*log).next_sequence.fetch_add(1, Ordering::Relaxed) + 1 };
    let slot_index = if fatal_candidate {
        unsafe { (*log).next_fatal_slot.fetch_add(1, Ordering::Relaxed) as usize % FATAL_SLOT_COUNT }
    } else {
        FATAL_SLOT_COUNT
            + unsafe {
                (*log)
                    .next_diagnostic_slot
                    .fetch_add(1, Ordering::Relaxed) as usize
                    % DIAGNOSTIC_SLOT_COUNT
            }
    };
    let slot = unsafe { &(*log).slots[slot_index] };
    slot.published_sequence.store(0, Ordering::Relaxed);
    unsafe { std::ptr::write(slot.payload.get(), payload) };
    slot.published_sequence.store(sequence, Ordering::Release);
    0 // EXCEPTION_CONTINUE_SEARCH
}

pub(super) fn init() -> anyhow::Result<()> {
    if HANDLER_INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }
    let session_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before Unix epoch")?
        .as_millis() as u64;
    let storage = STORAGE.get_or_init(make_storage);
    unsafe { initialize_header(storage.get(), session_id) };
    SESSION_ID.store(session_id, Ordering::Release);
    ACTIVE_LOG.store(storage.get(), Ordering::Release);
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(vectored_handler)) };
    if handler.is_null() {
        ACTIVE_LOG.store(std::ptr::null_mut(), Ordering::Release);
        bail!("AddVectoredExceptionHandler returned null");
    }
    HANDLER_INSTALLED.store(true, Ordering::Release);
    storage.flush();
    Ok(())
}

/// The id this session's records are stamped with, or `0` before capture has
/// started. Shared with the flight recorder so a crash and the call that was
/// running when it happened can be recognised as the same event.
pub(super) fn session_id() -> u64 {
    SESSION_ID.load(Ordering::Acquire)
}

pub(crate) fn mark_clean_shutdown() {
    let log = ACTIVE_LOG.load(Ordering::Acquire);
    if !log.is_null() {
        unsafe { (*log).last_session_clean.store(1, Ordering::Release) };
    }
}

#[derive(Clone, Copy)]
struct CapturedException {
    sequence: u64,
    payload: ExceptionPayload,
}

fn filetime_to_unix_ms(filetime: u64) -> u64 {
    filetime
        .saturating_sub(WINDOWS_TO_UNIX_100NS)
        .saturating_div(10_000)
}

fn exception_name(code: u32) -> &'static str {
    match code {
        0x8000_0001 => "GUARD_PAGE",
        0xC000_0005 => "ACCESS_VIOLATION",
        0xC000_0006 => "IN_PAGE_ERROR",
        0xC000_0008 => "INVALID_HANDLE",
        0xC000_001D => "ILLEGAL_INSTRUCTION",
        0xC000_008E => "FLOAT_DIVIDE_BY_ZERO",
        0xC000_0094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC000_0096 => "PRIVILEGED_INSTRUCTION",
        0xC000_00FD => "STACK_OVERFLOW",
        0xC000_0374 => "HEAP_CORRUPTION",
        0xC000_0409 => "STACK_BUFFER_OVERRUN",
        0xE06D_7363 => "MSVC_CPP_EXCEPTION",
        _ => "UNKNOWN",
    }
}

fn likely_fatal(code: u32) -> bool {
    matches!(
        code,
        0xC000_0005
            | 0xC000_0006
            | 0xC000_001D
            | 0xC000_008E
            | 0xC000_0094
            | 0xC000_0096
            | 0xC000_00FD
            | 0xC000_0374
            | 0xC000_0409
    )
}

fn hex(value: u64) -> String {
    format!("0x{value:016X}")
}

fn optional_json(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".to_string())
}

fn access_violation_json(payload: &ExceptionPayload) -> String {
    if payload.code != 0xC000_0005 || payload.parameter_count < 2 {
        return "null".to_string();
    }
    let operation = match payload.parameters[0] {
        0 => "read",
        1 => "write",
        8 => "execute",
        _ => "unknown",
    };
    format!(
        "{{\"operation\":\"{operation}\",\"address\":\"{}\"}}",
        hex(payload.parameters[1])
    )
}

fn event_json(
    event: &CapturedException,
    current_session: u64,
    previous_session: u64,
    previous_clean: bool,
) -> String {
    let payload = &event.payload;
    let session_scope = if payload.session_id == current_session {
        "current"
    } else if previous_session != 0 && payload.session_id == previous_session {
        "previous"
    } else {
        "historical"
    };
    let ended_cleanly = if session_scope == "previous" {
        if previous_clean { "true" } else { "false" }
    } else {
        "null"
    };
    let fatal_candidate = likely_fatal(payload.code);
    let possible_crash = fatal_candidate && session_scope == "previous" && !previous_clean;
    let parameters = payload.parameters[..payload.parameter_count.min(15) as usize]
        .iter()
        .map(|value| format!("\"{}\"", hex(*value)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"sequence\":{},\"sessionId\":{},\"sessionScope\":\"{session_scope}\",\"previousSessionEndedCleanly\":{ended_cleanly},\"firstChance\":true,\"fatalCandidate\":{fatal_candidate},\"possibleCrash\":{possible_crash},\"crashConfirmed\":false,\"timestampUnixMs\":{},\"processId\":{},\"threadId\":{},\"exceptionCode\":\"0x{:08X}\",\"exceptionName\":\"{}\",\"exceptionFlags\":{},\"exceptionAddress\":\"{}\",\"instructionPointer\":\"{}\",\"stackPointer\":\"{}\",\"framePointer\":\"{}\",\"accessViolation\":{},\"registers\":{{\"rax\":\"{}\",\"rbx\":\"{}\",\"rcx\":\"{}\",\"rdx\":\"{}\",\"rsi\":\"{}\",\"rdi\":\"{}\",\"r8\":\"{}\",\"r9\":\"{}\",\"r10\":\"{}\",\"r11\":\"{}\",\"r12\":\"{}\",\"r13\":\"{}\",\"r14\":\"{}\",\"r15\":\"{}\"}},\"parameters\":[{parameters}]}}",
        event.sequence,
        payload.session_id,
        filetime_to_unix_ms(payload.timestamp_filetime),
        payload.process_id,
        payload.thread_id,
        payload.code,
        exception_name(payload.code),
        payload.flags,
        hex(payload.exception_address),
        hex(payload.rip),
        hex(payload.rsp),
        hex(payload.rbp),
        access_violation_json(payload),
        hex(payload.rax),
        hex(payload.rbx),
        hex(payload.rcx),
        hex(payload.rdx),
        hex(payload.rsi),
        hex(payload.rdi),
        hex(payload.r8),
        hex(payload.r9),
        hex(payload.r10),
        hex(payload.r11),
        hex(payload.r12),
        hex(payload.r13),
        hex(payload.r14),
        hex(payload.r15),
    )
}

fn snapshot_events(log: *mut PersistentLog) -> Vec<CapturedException> {
    let mut events = Vec::new();
    for slot in unsafe { &(*log).slots } {
        let before = slot.published_sequence.load(Ordering::Acquire);
        if before == 0 {
            continue;
        }
        let payload = unsafe { std::ptr::read(slot.payload.get()) };
        let after = slot.published_sequence.load(Ordering::Acquire);
        if before == after && after != 0 {
            events.push(CapturedException {
                sequence: after,
                payload,
            });
        }
    }
    events.sort_by_key(|event| event.sequence);
    events.dedup_by_key(|event| event.sequence);
    events
}

fn crash_artifacts() -> Vec<String> {
    let mut directories = Vec::new();
    if let Some(logs) = assets::editor_log_directory() {
        directories.push(logs);
    }
    if let Some(binary) = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
    {
        if !directories.contains(&binary) {
            directories.push(binary);
        }
    }
    let mut artifacts = Vec::new();
    for directory in directories {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let extension = path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !matches!(extension.as_str(), "dmp" | "mdmp") {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_millis() as u64);
            artifacts.push((path, metadata.len(), modified));
        }
    }
    artifacts.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    artifacts.truncate(8);
    // Through the shared describer rather than formatted here, so a dump says
    // whether it belongs to this session. "Is this the crash I am looking at,
    // or one from last week?" is the first question anyone asks of a dump, and
    // a bare timestamp makes the reader do that arithmetic themselves.
    artifacts
        .into_iter()
        .map(|(path, _, _)| super::provenance::artifact_json("crashDump", &path))
        .collect()
}

pub(super) fn validate_query(limit: usize) -> Result<(), String> {
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
    }
    Ok(())
}

pub(super) fn query(
    since_sequence: u64,
    limit: usize,
    include_previous_sessions: bool,
) -> Result<String, String> {
    validate_query(limit)?;
    let storage = STORAGE
        .get()
        .ok_or_else(|| "exception capture is not initialized".to_string())?;
    let log = storage.get();
    let current_session = SESSION_ID.load(Ordering::Acquire);
    let previous_session = unsafe { (*log).previous_session_id.load(Ordering::Acquire) };
    let previous_clean =
        unsafe { (*log).previous_session_clean.load(Ordering::Acquire) != 0 };
    let latest_sequence = unsafe { (*log).next_sequence.load(Ordering::Acquire) };
    let mut events = snapshot_events(log)
        .into_iter()
        .filter(|event| event.sequence > since_sequence)
        .filter(|event| include_previous_sessions || event.payload.session_id == current_session)
        .collect::<Vec<_>>();
    let total_matches = events.len();
    if events.len() > limit {
        events = events.split_off(events.len() - limit);
    }
    let earliest_available = snapshot_events(log)
        .first()
        .map_or(0, |event| event.sequence);
    let event_json = events
        .iter()
        .map(|event| event_json(event, current_session, previous_session, previous_clean))
        .collect::<Vec<_>>()
        .join(",");
    let artifacts = crash_artifacts();
    let persistence_path = storage.path().map(|path| path.display().to_string());
    Ok(format!(
        "{{\"capture\":{{\"handlerInstalled\":{},\"scope\":\"first-chance Windows exceptions\",\"capacity\":{SLOT_COUNT},\"fatalCapacity\":{FATAL_SLOT_COUNT},\"diagnosticCapacity\":{DIAGNOSTIC_SLOT_COUNT},\"diagnosticsDeduplicatedByCodeAndAddress\":true,\"persistent\":{},\"path\":{},\"persistenceError\":{}}},\"currentSessionId\":{current_session},\"previousSessionId\":{},\"previousSessionEndedCleanly\":{},\"sinceSequence\":{since_sequence},\"latestSequence\":{latest_sequence},\"earliestAvailableSequence\":{earliest_available},\"includePreviousSessions\":{include_previous_sessions},\"totalMatches\":{total_matches},\"returnedCount\":{},\"truncated\":{},\"events\":[{event_json}],\"crashArtifacts\":[{}],\"interpretation\":\"These are first-chance records: handled exceptions are included. Fatal-candidate records have a protected 48-slot partition; ordinary diagnostics are code/address deduplicated into 16 slots. possibleCrash additionally requires an unclean previous-session end. Neither field confirms a crash; correlate with a dump or UE3 log.\"}}",
        HANDLER_INSTALLED.load(Ordering::Acquire),
        storage.is_persistent(),
        optional_json(persistence_path.as_deref()),
        optional_json(storage.error()),
        if previous_session == 0 {
            "null".to_string()
        } else {
            previous_session.to_string()
        },
        if previous_session == 0 {
            "null"
        } else if previous_clean {
            "true"
        } else {
            "false"
        },
        events.len(),
        total_matches > events.len(),
        artifacts.join(","),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_classifies_high_value_exception_codes() {
        assert_eq!(exception_name(0xC000_0005), "ACCESS_VIOLATION");
        assert_eq!(exception_name(0xE06D_7363), "MSVC_CPP_EXCEPTION");
        assert!(likely_fatal(0xC000_00FD));
        assert!(!likely_fatal(0xE06D_7363));
    }

    #[test]
    fn skips_debug_protocol_exceptions_only() {
        assert!(skipped_exception(0x406D_1388));
        assert!(skipped_exception(0x4001_0006));
        assert!(!skipped_exception(0xC000_0005));
    }

    #[test]
    fn decodes_access_violation_operation_and_address() {
        let mut payload = ExceptionPayload {
            code: 0xC000_0005,
            parameter_count: 2,
            ..ExceptionPayload::default()
        };
        payload.parameters[0] = 8;
        payload.parameters[1] = 0x1234;
        let json = access_violation_json(&payload);
        assert!(json.contains("\"operation\":\"execute\""));
        assert!(json.contains("0x0000000000001234"));
    }

    #[test]
    fn converts_windows_epoch_to_unix_milliseconds() {
        assert_eq!(filetime_to_unix_ms(WINDOWS_TO_UNIX_100NS), 0);
        assert_eq!(
            filetime_to_unix_ms(WINDOWS_TO_UNIX_100NS + 12_340_000),
            1234
        );
    }

    #[test]
    fn exception_query_limit_is_bounded() {
        assert!(validate_query(DEFAULT_LIMIT).is_ok());
        assert!(validate_query(0).is_err());
        assert!(validate_query(MAX_LIMIT + 1).is_err());
    }
}
