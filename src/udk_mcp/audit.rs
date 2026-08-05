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

/// Rotated at this size, keeping one previous generation. Big enough to hold a
/// long session, small enough to open in an editor.
const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Arguments are recorded to make a line reconstructable, not to archive
/// content. A property value can be a whole material expression.
const MAX_DETAIL: usize = 600;

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
    pub millis: u64,
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
    let line = format!(
        "{{\"time\":\"{}\",\"kind\":\"{}\",\"tool\":\"{}\",\"outcome\":\"{}\",\"mode\":\"{}\",\
         \"detail\":\"{}\",\"note\":\"{}\",\"ms\":{}}}\n",
        timestamp(),
        super::json_escape(entry.kind),
        super::json_escape(entry.tool),
        entry.outcome.id(),
        super::policy::current_mode().id(),
        super::json_escape(&clamp(entry.detail)),
        super::json_escape(&clamp(entry.note)),
        entry.millis,
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
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
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
}
