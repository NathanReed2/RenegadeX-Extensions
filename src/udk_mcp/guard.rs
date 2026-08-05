//! Limits that apply *after* the policy has said yes.
//!
//! The capability mask answers "may this kind of thing happen at all". These
//! answer "may this particular one happen, now, at this size". They exist
//! because the failures worth worrying about are not a model doing a forbidden
//! thing - the policy covers that - but a model doing a permitted thing at a
//! scale or a speed nobody intended:
//!
//! - `edit` mode permits transforms. It does not imply permission to snap four
//!   thousand actors to the floor in one call, which is one `ACTOR ALIGN` away
//!   whenever the user has done a select-all.
//! - A retry loop that has misread an error can issue permitted mutations
//!   forever. Each one is legal; the sequence is not.
//! - `exec.command` is all-or-nothing, and it is the capability that makes every
//!   other restriction moot, because `ACTOR DELETE` is one `renx_exec` away from
//!   anyone who has it.
//!
//! Each limit refuses with an explanation aimed at a model, for the same reason
//! [`super::policy::deny_message`] does: a bare refusal gets retried, and the
//! retry for a blocked tool is `renx_exec`.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A mutation touching more than this many actors has to be confirmed by
/// passing `confirmLargeChange`. Chosen to sit above any plausible hand
/// selection and below the select-all that causes the accident.
pub const BLAST_RADIUS: i32 = 50;

/// Mutations allowed in [`RATE_WINDOW`]. Generous for someone working, low
/// enough that a runaway loop trips it in seconds rather than after a thousand
/// edits.
pub const RATE_LIMIT: u32 = 30;
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

static RATE_COUNT: AtomicU32 = AtomicU32::new(0);
static RATE_WINDOW_START: Mutex<Option<Instant>> = Mutex::new(None);
static RATE_BLOCKS: AtomicU64 = AtomicU64::new(0);

/// Bumped whenever the editor's selection is known to have changed under us.
static SELECTION_GENERATION: AtomicU64 = AtomicU64::new(1);
static LAST_SELECTION_COUNT: AtomicUsize = AtomicUsize::new(usize::MAX);

// ---------------------------------------------------------------- rate limit

/// Counts one mutation, refusing when the window is already full.
///
/// A fixed window rather than a sliding one: the goal is to stop a runaway, not
/// to meter fairly, and a fixed window is something a person can reason about
/// from the refusal text ("30 a minute") without knowing the algorithm.
pub fn check_rate() -> Result<(), String> {
    let mut start = RATE_WINDOW_START
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    let elapsed = start.map(|began| now.duration_since(began));
    match elapsed {
        Some(since) if since < RATE_WINDOW => {}
        _ => {
            *start = Some(now);
            RATE_COUNT.store(0, Ordering::Relaxed);
        }
    }
    let used = RATE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if used > RATE_LIMIT {
        RATE_COUNT.store(RATE_LIMIT, Ordering::Relaxed);
        RATE_BLOCKS.fetch_add(1, Ordering::Relaxed);
        let remaining = RATE_WINDOW
            .checked_sub(elapsed.unwrap_or_default())
            .unwrap_or_default();
        return Err(format!(
            "Blocked by the MCP rate limit: more than {RATE_LIMIT} editor changes in {} seconds. \
             This is a runaway guard, not a policy refusal - the capability is still granted.\n\n\
             If you are retrying because something failed, stop: the retry is what tripped this, \
             and repeating it will not help. Read the last error properly, or ask the user what \
             they want. If you genuinely have this much work to do, say so and do it in batches \
             about {} seconds apart.",
            RATE_WINDOW.as_secs(),
            remaining.as_secs() + 1
        ));
    }
    Ok(())
}

pub fn rate_blocks() -> u64 {
    RATE_BLOCKS.load(Ordering::Relaxed)
}

/// What the status view shows, e.g. `3/30 this minute`.
pub fn rate_usage() -> String {
    format!(
        "{}/{RATE_LIMIT} this minute",
        RATE_COUNT.load(Ordering::Relaxed).min(RATE_LIMIT)
    )
}

// --------------------------------------------------------------- blast radius

/// Refuses a mutation that would touch an unexpected number of actors.
///
/// Deliberately counted from the live selection at the moment of the call
/// rather than from anything the caller said, because the number the caller
/// believes is exactly the thing that goes stale.
pub fn check_blast_radius(count: i32, action: &str, confirmed: bool) -> Result<(), String> {
    if count <= BLAST_RADIUS || confirmed {
        return Ok(());
    }
    Err(format!(
        "Blocked by the MCP blast-radius limit: '{action}' would affect {count} actors, and \
         anything over {BLAST_RADIUS} needs to be confirmed. This is a size guard, not a policy \
         refusal - the capability is still granted.\n\nA selection this large is usually a \
         select-all that was not intended to be edited, so check it is really what the user \
         wants. Tell them how many actors it is and what you are about to do. If they agree, \
         repeat the call with \"confirmLargeChange\": true. Do not pass that flag on your own \
         initiative, and do not work around this by acting on the actors in smaller batches."
    ))
}

// ----------------------------------------------------------- selection tokens

/// A token naming the selection a read returned.
///
/// The problem it solves: a model reads the selection, decides which actor is
/// index 3, and then mutates index 3 - but the user clicked something in
/// between, and index 3 is now a different actor. Nothing in the protocol makes
/// that visible, and the mutation succeeds against the wrong object.
///
/// The token is a generation counter, not a hash of the selection: it only has
/// to change when the selection might have, and it must never fail to change.
pub fn selection_token(count: usize) -> String {
    note_selection(count);
    format!(
        "sel-{}-{}",
        SELECTION_GENERATION.load(Ordering::Acquire),
        count
    )
}

/// Records the selection size seen on the editor thread, bumping the generation
/// when it differs from last time.
///
/// Size is a coarse signal - swapping one actor for another keeps the count -
/// so this is a guard against the common accident, not a guarantee. Said plainly
/// here so nobody later mistakes it for one.
pub fn note_selection(count: usize) {
    if LAST_SELECTION_COUNT.swap(count, Ordering::AcqRel) != count {
        SELECTION_GENERATION.fetch_add(1, Ordering::AcqRel);
    }
}

/// Invalidates every outstanding token. Called after anything that changes the
/// selection as a side effect, such as duplicate or delete.
pub fn invalidate_selection() {
    LAST_SELECTION_COUNT.store(usize::MAX, Ordering::Release);
    SELECTION_GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// Checks a caller-supplied token against the live selection.
///
/// Absent is allowed: the token is opt-in, so a caller that never reads the
/// selection is not forced to. Present and stale is refused.
pub fn check_selection_token(supplied: Option<&str>, count: usize) -> Result<(), String> {
    let Some(supplied) = supplied else {
        return Ok(());
    };
    let current = selection_token(count);
    if supplied == current {
        return Ok(());
    }
    Err(format!(
        "Blocked by the MCP selection check: you passed selectionToken '{supplied}', but the \
         editor's selection is now '{current}'. This is a staleness guard, not a policy refusal.\n\n\
         The user changed the selection after you read it, so actor indices no longer mean what \
         they meant. Call renx_get_selected_actors again, work out the indices from the fresh \
         result, and retry with the new token. Do not simply drop the token to get past this."
    ))
}

// ------------------------------------------------------------- exec allowlist

/// Commands that only read.
///
/// Matched on the leading verb (and the second word where the verb alone is not
/// decisive), because UE3 `Exec` dispatch is itself prefix-based. Anything not
/// listed is treated as a mutation - the list is what is known safe, never a
/// list of what is known dangerous, because the unknown command is the one that
/// deletes something.
const READ_ONLY_EXEC: &[&str] = &[
    "OBJ LIST",
    "OBJ CLASSES",
    "OBJ REFS",
    "OBJ GARBAGE",
    "LISTPROPS",
    "GETALL",
    "SHOW",
    "STAT",
    "MEMREPORT",
    "DUMPALLOCS",
    "SELECT",
    "CAMERA",
    "MODE",
    "MAP LIST",
    "ACTOR SELECT",
];

/// Whether an `Exec` command only reads.
pub fn exec_is_read_only(command: &str) -> bool {
    let normalized = command.trim().to_ascii_uppercase();
    let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    READ_ONLY_EXEC.iter().any(|allowed| {
        // Exact, or the allowed prefix followed by a space - so "OBJ LIST" does
        // not also admit "OBJ LISTWHATEVER".
        normalized == *allowed
            || normalized
                .strip_prefix(allowed)
                .is_some_and(|rest| rest.starts_with(' '))
    })
}

/// The prompt shown before an `Exec` that is not on the read-only list.
pub fn exec_confirmation(command: &str) -> String {
    format!(
        "A program connected to this editor's MCP bridge wants to run an editor command that is \
         not known to be read-only.\n\nCommand:\n    {command}\n\nEditor commands can save \
         packages, delete actors, rebuild lighting, and change things undo does not recover. Only \
         allow this if you were expecting it.\n\nChoosing No refuses the command and changes \
         nothing."
    )
}

pub const EXEC_DECLINED: &str =
    "The user declined this command in the editor. Nothing was run and nothing changed. This was \
     a person's decision, not a fault: do not retry it, do not rephrase the command to get the \
     same effect, and do not try to reach it through another tool. If you believe it is needed, \
     say so in conversation and let the user decide.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_exec_is_recognised_case_and_space_insensitively() {
        assert!(exec_is_read_only("OBJ LIST CLASS=WorldInfo"));
        assert!(exec_is_read_only("  obj   list   class=Actor  "));
        assert!(exec_is_read_only("LISTPROPS Actor *"));
        assert!(exec_is_read_only("CAMERA ALIGN"));
    }

    #[test]
    fn anything_that_writes_is_not_read_only() {
        for command in [
            "MAP SAVE FILE=x.udk",
            "ACTOR DELETE",
            "ACTOR DUPLICATE",
            "DELETE",
            "BUILDLIGHTING",
            "OBJ SAVEPACKAGE",
            "EXIT",
        ] {
            assert!(!exec_is_read_only(command), "{command} must not be allowed");
        }
    }

    /// The prefix match must not admit a longer verb that merely starts the same.
    #[test]
    fn a_prefix_is_not_a_licence_for_a_longer_verb() {
        assert!(!exec_is_read_only("OBJ LISTPACKAGES"));
        assert!(!exec_is_read_only("SELECTNONEANDDELETE"));
        assert!(!exec_is_read_only("SHOWDELETED"));
    }

    #[test]
    fn blast_radius_only_stops_large_unconfirmed_changes() {
        assert!(check_blast_radius(1, "ACTOR DELETE", false).is_ok());
        assert!(check_blast_radius(BLAST_RADIUS, "ACTOR DELETE", false).is_ok());
        assert!(check_blast_radius(BLAST_RADIUS + 1, "ACTOR DELETE", false).is_err());
        assert!(check_blast_radius(100_000, "ACTOR DELETE", true).is_ok());
    }

    #[test]
    fn blast_radius_refusal_names_the_flag_and_the_count() {
        let message = check_blast_radius(4000, "ACTOR ALIGN SNAPTOFLOOR", false).unwrap_err();
        assert!(message.contains("4000"), "{message}");
        assert!(message.contains("confirmLargeChange"), "{message}");
        assert!(message.contains("not a policy refusal"), "{message}");
    }

    #[test]
    fn a_selection_token_changes_when_the_selection_size_does() {
        invalidate_selection();
        let first = selection_token(3);
        assert_eq!(first, selection_token(3), "a stable selection keeps a token");
        let second = selection_token(4);
        assert_ne!(first, second);
    }

    #[test]
    fn a_stale_selection_token_is_refused_but_an_absent_one_is_not() {
        invalidate_selection();
        let token = selection_token(2);
        assert!(check_selection_token(Some(&token), 2).is_ok());
        assert!(check_selection_token(None, 9).is_ok(), "opt-in");
        assert!(check_selection_token(Some(&token), 7).is_err());
    }
}
