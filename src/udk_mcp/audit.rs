//! An append-only record of everything the bridge was asked to do.
//!
//! # Why
//!
//! The status view can say "4 tool calls, 1 refusal". It cannot say *what* the
//! four were, and after the fact that is the only question anyone asks. A model
//! with `edit` mode can rename fifty properties in a minute; if one of them was
//! wrong, the editor's undo stack is the only other record, and it does not say
//! who asked or with what arguments.
//!
//! So: one line of JSON per event, flushed immediately, beside `UDK.exe`. Not a
//! debugging aid - `debug_log!` is compiled out of release builds and this is
//! not - but a record the user can read after something surprising happened.
//!
//! # What it deliberately does not do
//!
//! It does not try to be tamper-proof. Anything running in this process can
//! rewrite the file, and a model that can reach the bridge can reach the disk.
//! It is a record for an honest reader, which is what the threat here actually
//! is: not a hostile agent covering its tracks, but a well-meaning one that did
//! something unexpected and nobody can reconstruct what.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use super::flight;

/// Rotated at this size, keeping one previous generation. Big enough to hold a
/// long session, small enough to open in an editor.
const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Arguments are recorded to make a line reconstructable, not to archive
/// content. A property value can be a whole material expression.
pub(super) const MAX_DETAIL: usize = 600;
pub const DEFAULT_RECENT_LIMIT: usize = 50;
pub const MAX_RECENT_LIMIT: usize = 200;

/// Carried in every reply because the three numbers are only useful together,
/// and a reader that guesses at them will reach for the wrong one. Kept to a
/// sentence: it is a legend, not documentation.
const TIMING_FIELDS_NOTE: &str = "ms is the whole call; queueWaitMs is time spent waiting for the \
     editor thread and executionMs is time spent on it, so ms minus both is bridge overhead. Both \
     are null when the call never crossed to the editor thread - answered in-process, refused, or \
     timed out.";

static WRITE_LOCK: Mutex<()> = Mutex::new(());
static WRITTEN: AtomicU64 = AtomicU64::new(0);

/// What happened, and whether it was allowed to happen.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Ran, and the editor accepted it.
    Ok,
    /// Refused by the capability policy.
    Denied,
    /// Refused by a limit - rate, blast radius, exec allowlist, stale selection.
    Blocked,
    /// Reached the editor and failed there, or never reached it.
    Failed,
}

impl Outcome {
    const fn id(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Denied => "denied",
            Outcome::Blocked => "blocked",
            Outcome::Failed => "failed",
        }
    }
}

pub struct Entry<'a> {
    pub kind: &'a str,
    pub tool: &'a str,
    pub outcome: Outcome,
    pub detail: &'a str,
    pub note: &'a str,
    /// Wall time for the whole call, measured on the connection thread.
    pub millis: u64,
    /// How long the operation sat in the queue before the editor thread reached
    /// it, and how long that thread then spent on it. `None` means the call
    /// never crossed to the editor thread - either it was answered entirely in
    /// this process, or it was refused, or it timed out before an answer came
    /// back. That is why these are optional rather than zero: "did not happen"
    /// and "took under a millisecond" are different findings.
    pub queue_wait_millis: Option<u64>,
    pub execution_millis: Option<u64>,
}

impl<'a> Entry<'a> {
    pub fn new(kind: &'a str, tool: &'a str, outcome: Outcome) -> Self {
        Entry {
            kind,
            tool,
            outcome,
            detail: "",
            note: "",
            millis: 0,
            queue_wait_millis: None,
            execution_millis: None,
        }
    }

    pub fn detail(mut self, detail: &'a str) -> Self {
        self.detail = detail;
        self
    }

    pub fn note(mut self, note: &'a str) -> Self {
        self.note = note;
        self
    }

    pub fn millis(mut self, millis: u64) -> Self {
        self.millis = millis;
        self
    }

    /// Both halves at once, because recording one without the other would
    /// invite the subtraction that this whole split exists to make unnecessary.
    pub fn editor_timing(mut self, queue_wait_millis: u64, execution_millis: u64) -> Self {
        self.queue_wait_millis = Some(queue_wait_millis);
        self.execution_millis = Some(execution_millis);
        self
    }
}

/// JSON has a word for "not measured" and it is not `0`.
fn millis_or_null(millis: Option<u64>) -> String {
    match millis {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    }
}

pub fn path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("RenXMcpAudit.jsonl")))
        .unwrap_or_else(|| std::path::PathBuf::from("RenXMcpAudit.jsonl"))
}

pub fn entries_written() -> u64 {
    WRITTEN.load(Ordering::Relaxed)
}

/// Appends one event.
///
/// Best effort by design: a bridge that refuses to work because it cannot write
/// its log would turn a full disk into an outage. A failure here is silent in
/// release, which is the one place a comment is worth more than the code.
pub fn record(entry: Entry<'_>) {
    let stamp = timestamp();
    let detail = clamp(entry.detail);
    let note = clamp(entry.note);
    let mode = super::policy::current_mode();
    // Into the mapped ring rather than a heap one, so this line is still
    // readable from the next session if this one does not survive to write the
    // next. The on-disk JSONL below stays the durable, human-readable record.
    flight::append(&flight::Completed {
        kind: entry.kind,
        tool: entry.tool,
        outcome: entry.outcome.id(),
        mode: mode.id(),
        detail: &detail,
        note: &note,
        millis: entry.millis,
        queue_wait_millis: entry.queue_wait_millis,
        execution_millis: entry.execution_millis,
    });
    let line = format!(
        "{{\"time\":\"{}\",\"kind\":\"{}\",\"tool\":\"{}\",\"outcome\":\"{}\",\"mode\":\"{}\",\
         \"detail\":\"{}\",\"note\":\"{}\",\"ms\":{},\"queueWaitMs\":{},\"executionMs\":{}}}\n",
        stamp,
        super::json_escape(entry.kind),
        super::json_escape(entry.tool),
        entry.outcome.id(),
        mode.id(),
        super::json_escape(&detail),
        super::json_escape(&note),
        entry.millis,
        millis_or_null(entry.queue_wait_millis),
        millis_or_null(entry.execution_millis),
    );

    let Ok(_guard) = WRITE_LOCK.lock() else {
        return;
    };
    let target = path();
    if std::fs::metadata(&target).map(|meta| meta.len()).unwrap_or(0) > MAX_BYTES {
        // One generation back. Keeping more would need a retention policy, and
        // an unbounded pile of logs beside UDK.exe is its own kind of mess.
        let _ = std::fs::rename(&target, target.with_extension("jsonl.1"));
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&target)
    {
        if file.write_all(line.as_bytes()).is_ok() {
            WRITTEN.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Which session an event belongs to, relative to the one asking.
///
/// The ring now outlives the process that filled it, so "this call happened"
/// stopped being a complete answer - a caller reading it after a restart needs
/// to know whether it is looking at its own work or at a dead session's.
fn session_scope(event_session: u64, sessions: &flight::Sessions) -> &'static str {
    if event_session == sessions.current {
        "current"
    } else if sessions.previous != 0 && event_session == sessions.previous {
        "previous"
    } else {
        "historical"
    }
}

/// One ring entry as JSON. Its own function so the shape can be tested against
/// a known event rather than against whatever the process happened to log.
fn event_json(event: &flight::Call, sessions: &flight::Sessions) -> String {
    format!(
        r#"{{"sequence":{},"time":"{}","sessionId":{},"sessionScope":"{}","threadId":{},"kind":"{}","tool":"{}","outcome":"{}","mode":"{}","detail":"{}","note":"{}","ms":{},"queueWaitMs":{},"executionMs":{}}}"#,
        event.sequence,
        format_unix_ms(event.unix_ms),
        event.session_id,
        session_scope(event.session_id, sessions),
        event.thread_id,
        super::json_escape(&event.kind),
        super::json_escape(&event.tool),
        super::json_escape(&event.outcome),
        super::json_escape(&event.mode),
        super::json_escape(&event.detail),
        super::json_escape(&event.note),
        event.millis,
        millis_or_null(event.queue_wait_millis),
        millis_or_null(event.execution_millis),
    )
}

pub fn validate_recent(limit: usize) -> Result<(), String> {
    if !(1..=MAX_RECENT_LIMIT).contains(&limit) {
        return Err(format!(
            "limit must be between 1 and {MAX_RECENT_LIMIT}"
        ));
    }
    Ok(())
}

/// Explains the two blocks that only ever have anything in them when something
/// went wrong, so a reader does not have to infer what an empty array meant.
const UNFINISHED_CALLS_NOTE: &str = "interruptedCalls are calls that never returned because the \
     session holding them ended; check sessionEndedUncleanly to tell a crash from an editor that \
     was closed. inFlightCalls are running right now and include the call asking. phase says how \
     far each got: only the editor phase means the editor thread was inside the operation.";

/// Returns the tail of the audit stream, across sessions.
///
/// Previous sessions are included by default, and that default is the point:
/// after a crash the useful history is the history of the process that died,
/// and a caller that had to know to ask for it would only ask once it already
/// suspected. Sequence numbers do not restart, so `sinceSequence` polling
/// survives the restart it is most needed across.
pub fn recent_json(
    since_sequence: u64,
    limit: usize,
    include_previous_sessions: bool,
) -> Result<String, String> {
    validate_recent(limit)?;
    let sessions = flight::sessions();
    let events = flight::snapshot();
    let oldest = events.first().map(|event| event.sequence).unwrap_or(0);
    let latest = events.last().map(|event| event.sequence).unwrap_or(0);
    let dropped_before_window = since_sequence != 0 && oldest > since_sequence.saturating_add(1);
    let selected = events
        .iter()
        .filter(|event| event.sequence > since_sequence)
        .filter(|event| include_previous_sessions || event.session_id == sessions.current)
        .take(limit)
        .collect::<Vec<_>>();
    let next_sequence = selected
        .last()
        .map(|event| event.sequence)
        .unwrap_or(since_sequence);
    let matches = selected
        .iter()
        .map(|event| event_json(event, &sessions))
        .collect::<Vec<_>>();
    let interrupted = flight::interrupted()
        .iter()
        .map(|call| flight::in_flight_json(call, sessions.previous_clean))
        .collect::<Vec<_>>();
    let in_flight = flight::in_flight()
        .iter()
        .map(|call| flight::in_flight_json(call, None))
        .collect::<Vec<_>>();
    Ok(format!(
        r#"{{"source":"persistent MCP flight recorder","storage":{},"currentSessionId":{},"previousSessionId":{},"previousSessionEndedCleanly":{},"oldestSequence":{oldest},"latestSequence":{latest},"sinceSequence":{since_sequence},"nextSequence":{next_sequence},"includePreviousSessions":{include_previous_sessions},"droppedBeforeWindow":{dropped_before_window},"returnedCount":{},"retainedEventLimit":{},"timingFields":"{TIMING_FIELDS_NOTE}","unfinishedCalls":"{UNFINISHED_CALLS_NOTE}","interruptedCalls":[{}],"inFlightCalls":[{}],"events":[{}]}}"#,
        flight::persistence_json(),
        sessions.current,
        optional_u64(sessions.previous),
        optional_bool(sessions.previous_clean),
        matches.len(),
        flight::CALL_SLOTS,
        interrupted.join(","),
        in_flight.join(","),
        matches.join(","),
    ))
}

/// `0` is the absence of a session id, not a session.
fn optional_u64(value: u64) -> String {
    match value {
        0 => "null".to_string(),
        value => value.to_string(),
    }
}

fn optional_bool(value: Option<bool>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    }
}

fn clamp(text: &str) -> String {
    if text.len() <= MAX_DETAIL {
        return text.to_string();
    }
    // On a character boundary, or the escape below would see half a code point.
    let mut end = MAX_DETAIL;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[{} bytes]", &text[..end], text.len())
}

/// UTC, as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Done by hand rather than by pulling in a date crate: this is the only place
/// in the DLL that needs a wall clock, and the conversion is a well-defined
/// piece of arithmetic rather than something worth a dependency.
fn timestamp() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0);
    format_unix_ms(millis)
}

/// The same format, for a time the ring recorded rather than one happening now.
/// Records store an instant, not a rendering of one, because a fixed-size field
/// holding a formatted string would be twenty bytes spent saying what eight
/// already say.
fn format_unix_ms(unix_ms: u64) -> String {
    let seconds = unix_ms / 1000;
    let (days, rest) = ((seconds / 86_400) as i64, seconds % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a calendar date.
///
/// It shifts the era to start in March so the leap day lands at the end of a
/// year, which is what removes every special case for February.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // 2024 was a leap year: day 59 of it is the 29th of February.
        assert_eq!(civil_from_days(19_723 + 59), (2024, 2, 29));
        assert_eq!(civil_from_days(20_638), (2026, 7, 4));
    }

    #[test]
    fn timestamp_is_well_formed() {
        let stamp = timestamp();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert_eq!(stamp.as_bytes()[4], b'-', "{stamp}");
        assert_eq!(stamp.as_bytes()[10], b'T', "{stamp}");
        // Sanity: this code did not exist before 2026 and will not run after 2100.
        let year: i32 = stamp[..4].parse().unwrap();
        assert!((2026..2100).contains(&year), "{stamp}");
    }

    #[test]
    fn clamps_long_detail_on_a_character_boundary() {
        let long = "é".repeat(MAX_DETAIL);
        let clamped = clamp(&long);
        assert!(clamped.contains("...["), "{clamped}");
        // The point of the boundary walk: this must not panic or produce
        // invalid UTF-8, which a plain slice at MAX_DETAIL would.
        assert!(clamped.is_char_boundary(0));
    }

    #[test]
    fn short_detail_is_untouched() {
        assert_eq!(clamp("ACTOR DELETE"), "ACTOR DELETE");
    }

    #[test]
    fn recent_limits_are_bounded() {
        assert!(validate_recent(DEFAULT_RECENT_LIMIT).is_ok());
        assert!(validate_recent(0).is_err());
        assert!(validate_recent(MAX_RECENT_LIMIT + 1).is_err());
    }

    fn sample_event() -> flight::Call {
        flight::Call {
            sequence: 7,
            session_id: 1000,
            unix_ms: 1_754_438_400_000,
            thread_id: 4,
            kind: "tool".to_string(),
            tool: "renx_get_viewport_context".to_string(),
            outcome: "ok".to_string(),
            mode: "context".to_string(),
            detail: "{}".to_string(),
            note: String::new(),
            millis: 3570,
            queue_wait_millis: None,
            execution_millis: None,
        }
    }

    fn sample_sessions() -> flight::Sessions {
        flight::Sessions {
            current: 1000,
            previous: 900,
            previous_clean: Some(false),
        }
    }

    fn sample_json(event: &flight::Call) -> String {
        event_json(event, &sample_sessions())
    }

    /// The distinction the split exists for: a call that never reached the
    /// editor thread must not be indistinguishable from one that got there in
    /// under a millisecond.
    #[test]
    fn unmeasured_timings_serialise_as_null_not_zero() {
        let unmeasured = sample_json(&sample_event());
        assert_eq!(
            super::super::json_field_raw(&unmeasured, "queueWaitMs"),
            Some("null")
        );
        assert_eq!(
            super::super::json_field_raw(&unmeasured, "executionMs"),
            Some("null")
        );

        let measured = sample_json(&flight::Call {
            queue_wait_millis: Some(0),
            execution_millis: Some(0),
            ..sample_event()
        });
        assert_eq!(
            super::super::json_field_raw(&measured, "queueWaitMs"),
            Some("0")
        );
        assert_eq!(
            super::super::json_field_raw(&measured, "executionMs"),
            Some("0")
        );
    }

    /// The 3.57s viewport call that prompted this: the total alone said
    /// nothing, and these two say the editor thread was busy rather than the
    /// work being slow.
    #[test]
    fn attribution_survives_the_round_trip_through_json() {
        let event = flight::Call {
            queue_wait_millis: Some(3540),
            execution_millis: Some(28),
            ..sample_event()
        };
        let line = sample_json(&event);
        assert_eq!(super::super::json_field_raw(&line, "ms"), Some("3570"));
        assert_eq!(
            super::super::json_field_raw(&line, "queueWaitMs"),
            Some("3540")
        );
        assert_eq!(
            super::super::json_field_raw(&line, "executionMs"),
            Some("28")
        );
    }

    #[test]
    fn the_timing_legend_needs_no_escaping() {
        // Emitted into the reply unescaped, so it must not contain anything
        // that would end the string it is placed in.
        for legend in [TIMING_FIELDS_NOTE, UNFINISHED_CALLS_NOTE] {
            assert!(!legend.contains('"'), "{legend}");
            assert!(!legend.contains('\\'), "{legend}");
            assert!(!legend.contains('\n'), "{legend}");
        }
    }

    /// The ring outlives the process that filled it, so an event has to say
    /// whose work it was. A caller reading history from a session that crashed
    /// must not mistake it for its own.
    #[test]
    fn an_event_says_which_session_it_belongs_to() {
        let sessions = sample_sessions();
        assert_eq!(session_scope(1000, &sessions), "current");
        assert_eq!(session_scope(900, &sessions), "previous");
        assert_eq!(session_scope(42, &sessions), "historical");

        let line = sample_json(&sample_event());
        assert_eq!(
            super::super::json_field_string(&line, "sessionScope"),
            Some("current".to_string())
        );
        assert_eq!(super::super::json_field_raw(&line, "sessionId"), Some("1000"));
    }

    /// With no previous session recorded, `0` is the absence of one rather than
    /// a session that happened to be numbered zero.
    #[test]
    fn a_missing_previous_session_is_null_not_zero() {
        assert_eq!(optional_u64(0), "null");
        assert_eq!(optional_u64(17), "17");
        assert_eq!(optional_bool(None), "null");
        assert_eq!(optional_bool(Some(false)), "false");
    }

    #[test]
    fn a_recorded_instant_formats_the_same_way_a_live_one_does() {
        assert_eq!(format_unix_ms(0), "1970-01-01T00:00:00Z");
        // Sub-second precision is deliberately dropped rather than rounded, so
        // a stored instant and a live one cannot disagree by a second.
        assert_eq!(format_unix_ms(1_754_438_400_999), "2025-08-06T00:00:00Z");
        assert_eq!(timestamp().len(), format_unix_ms(0).len());
    }

    #[test]
    fn an_entry_is_unmeasured_until_it_is_told_otherwise() {
        let plain = Entry::new("tool", "renx_editor_status", Outcome::Ok);
        assert_eq!(plain.queue_wait_millis, None);
        assert_eq!(plain.execution_millis, None);

        let timed = Entry::new("tool", "renx_get_map_info", Outcome::Ok).editor_timing(4, 91);
        assert_eq!(timed.queue_wait_millis, Some(4));
        assert_eq!(timed.execution_millis, Some(91));
    }
}
