//! Run something from a known-clean state and prove whether it did anything.
//!
//! # Why
//!
//! An afternoon of this project was spent on three consecutive Play-In-Editor
//! runs that all agreed with each other. The agreement was read as a finding.
//! It was not: every run had reloaded the same four-hour-old `UEDPIE*.udk`,
//! because nothing deleted it first and nothing checked whether it had been
//! rewritten. Three experiments had been performed on one fixed artifact, and
//! they eliminated nothing.
//!
//! Two disciplines would have caught it, and neither is hard - they are just
//! easy to skip when each run takes a minute and the result looks plausible:
//!
//! 1. **Establish the precondition, or do not run.** The scratch artifact has
//!    to be gone before the run starts, and if it cannot be removed the
//!    experiment is invalid *before* it begins rather than inconclusive after.
//! 2. **Prove the run produced something.** If no observed artifact changed,
//!    the run was inert and its result describes the previous state.
//!
//! So this module refuses to start when it cannot clear the state, and reports
//! `producedNoArtifact` when nothing was written. That second field is the one
//! that would have ended the afternoon after the first run instead of the third.
//!
//! # Why it waits
//!
//! `renx_start_pie` queues a request and returns; the engine acts frames later.
//! Sampling the artifacts the instant the act returns would find nothing every
//! time and call every PIE run inert. So the observation polls until something
//! changes or a deadline passes - which also makes "nothing ever changed" a
//! measured result rather than an artefact of looking too early.
//!
//! # What it will delete
//!
//! Only the Play-In-Editor scratch packages, and it never takes a path from the
//! caller - the list comes from [`super::provenance::play_in_editor_packages`],
//! which reads one known directory. A tool that deleted caller-named files
//! would be a far more useful primitive and a far worse idea; the case that
//! actually caused harm here is narrow, and so is this.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::{json_escape, provenance};

/// Long enough for a queued play request to reach a map load and a save, short
/// enough that a caller waiting on it has not lost the thread.
pub(super) const MAX_SETTLE_SECONDS: u64 = 120;
pub(super) const DEFAULT_SETTLE_SECONDS: u64 = 30;
/// Frequent enough to return promptly once the artifact lands, rare enough that
/// polling a handful of files is not itself a load.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

const _: () = {
    assert!(DEFAULT_SETTLE_SECONDS <= MAX_SETTLE_SECONDS);
    // A poll slower than the window would sample once and call every run inert.
    assert!(POLL_INTERVAL.as_secs() < DEFAULT_SETTLE_SECONDS);
};

/// What a file looked like at one moment: present or not, and if present, its
/// size and modification time.
///
/// Size is carried alongside the timestamp because a rewrite can land inside a
/// filesystem's timestamp resolution, and a same-second write with a different
/// length is still a rewrite.
type Fingerprint = (PathBuf, Option<(u64, u64)>);

fn fingerprint_of(path: &std::path::Path) -> Option<(u64, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_millis() as u64);
    Some((metadata.len(), modified))
}

/// The observed set, sampled now.
///
/// Sampled by directory rather than by remembering a list, so a package created
/// during the run - the normal case, since the run starts with none - is seen.
pub(super) fn sample() -> Vec<Fingerprint> {
    let mut sampled = provenance::play_in_editor_packages()
        .into_iter()
        .map(|(_, path)| {
            let state = fingerprint_of(&path);
            (path, state)
        })
        .collect::<Vec<_>>();
    sampled.sort_by(|left, right| left.0.cmp(&right.0));
    sampled
}

/// Whether anything in the observed set appeared, vanished, or was rewritten.
pub(super) fn changed(before: &[Fingerprint], after: &[Fingerprint]) -> bool {
    if before.len() != after.len() {
        return true;
    }
    before
        .iter()
        .zip(after)
        .any(|(left, right)| left.0 != right.0 || left.1 != right.1)
}

pub(super) struct Cleared {
    pub removed: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
}

impl Cleared {
    /// The precondition holds only when nothing is left. A file the editor
    /// still has open cannot be removed, and continuing would run the exact
    /// experiment this module exists to prevent.
    pub(super) fn established(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Deletes the Play-In-Editor scratch packages.
///
/// These are regenerable: the editor writes one whenever it plays a map, which
/// is precisely why a leftover one is dangerous - it looks exactly like the one
/// the current run would have produced.
pub(super) fn clear() -> Cleared {
    let mut removed = Vec::new();
    let mut failed = Vec::new();
    for (_, path) in provenance::play_in_editor_packages() {
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(error) => failed.push((path, error.to_string())),
        }
    }
    Cleared { removed, failed }
}

/// Waits until the observed set differs from `before` and has stopped moving,
/// or the deadline passes.
///
/// Returns whether a change was seen and how long it took, because "it changed
/// after 12 seconds" and "it changed immediately" mean different things about
/// what the act actually did.
///
/// The second half - waiting for the size to stop changing - is not tidiness.
/// A 31MB package takes seconds to write, and returning at the first difference
/// reported it at 8MB: a real change, but a size no caller should compare
/// against anything. The original experiments this module exists for were
/// distinguished by 31,161,654 bytes against 31,161,639, so a mid-write figure
/// would have been worse than none.
pub(super) fn wait_for_change(
    before: &[Fingerprint],
    settle: Duration,
) -> (bool, Duration, Vec<Fingerprint>) {
    let started = Instant::now();
    let mut previous: Option<Vec<Fingerprint>> = None;
    loop {
        let now = sample();
        let differs = changed(before, &now);
        // Stable means two consecutive samples agree, which for a file being
        // written means one poll interval passed without a byte landing.
        if differs && previous.as_ref().is_some_and(|last| !changed(last, &now)) {
            return (true, started.elapsed(), now);
        }
        let remaining = settle.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            // Out of time. A change that was seen but never settled is still a
            // change - the act produced something, and saying otherwise would
            // call a slow write an inert run.
            return (differs, started.elapsed(), now);
        }
        previous = Some(now);
        std::thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn path_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| format!("\"{}\"", json_escape(&path.display().to_string())))
        .collect::<Vec<_>>()
        .join(",")
}

pub(super) fn cleared_json(cleared: &Cleared) -> String {
    let failed = cleared
        .failed
        .iter()
        .map(|(path, error)| {
            format!(
                r#"{{"path":"{}","error":"{}"}}"#,
                json_escape(&path.display().to_string()),
                json_escape(error)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"established":{},"removedCount":{},"removed":[{}],"failed":[{failed}]}}"#,
        cleared.established(),
        cleared.removed.len(),
        path_list(&cleared.removed),
    )
}

/// The sentence a caller should read before the act's own result.
pub(super) fn verdict(established: bool, produced: bool, waited: Duration) -> String {
    if !established {
        return "The starting state could not be cleared, so the act was not run and nothing was \
                measured. A file that will not delete is usually one the editor still has open - \
                stop any play session and retry."
            .to_string();
    }
    if produced {
        format!(
            "Valid run: the state was cleared first and the act wrote a new artifact after {}s, \
             so the result describes this run.",
            waited.as_secs()
        )
    } else {
        format!(
            "INERT RUN - do not draw a conclusion from this. The state was cleared, but nothing \
             was written in the {}s that followed, so the act produced no new artifact. Whatever \
             the act reported describes the state before it, and repeating this will keep \
             producing the same non-result. Check that the act actually does what you think \
             triggers the work.",
            waited.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(path: &str, state: Option<(u64, u64)>) -> Fingerprint {
        (PathBuf::from(path), state)
    }

    #[test]
    fn an_unchanged_set_is_not_a_change() {
        let before = vec![at("a.udk", Some((10, 100)))];
        assert!(!changed(&before, &before.clone()));
    }

    #[test]
    fn appearing_vanishing_and_rewriting_all_count_as_change() {
        let before = vec![at("a.udk", Some((10, 100)))];
        assert!(changed(&before, &[at("a.udk", Some((10, 200)))]), "mtime");
        assert!(changed(&before, &[at("a.udk", Some((11, 100)))]), "size");
        assert!(changed(&before, &[at("a.udk", None)]), "vanished");
        assert!(changed(&before, &[]), "removed from the set");
        assert!(
            changed(&before, &[at("a.udk", Some((10, 100))), at("b.udk", None)]),
            "appeared"
        );
    }

    /// The case that caused the harm: a rewrite whose timestamp did not move
    /// because it landed inside the filesystem's resolution. Size is what
    /// catches it, and without size this whole module would report the inert
    /// runs as valid ones.
    #[test]
    fn a_same_timestamp_rewrite_of_a_different_length_is_a_change() {
        let before = vec![at("a.udk", Some((31_161_654, 100)))];
        let after = vec![at("a.udk", Some((31_161_639, 100)))];
        assert!(changed(&before, &after));
    }

    /// A package still being written must not be reported as the finished
    /// artifact, because its size is the number a caller compares between runs.
    #[test]
    fn a_write_in_progress_is_not_yet_a_settled_change() {
        let before = vec![at("a.udk", None)];
        let growing = vec![at("a.udk", Some((8_112_593, 100)))];
        let settled = vec![at("a.udk", Some((31_161_639, 140)))];
        // Differs from the baseline, but also from the previous sample, so the
        // write is still running.
        assert!(changed(&before, &growing));
        assert!(changed(&growing, &settled));
        // Two consecutive agreeing samples is what "finished" looks like.
        assert!(!changed(&settled, &settled.clone()));
    }

    #[test]
    fn a_precondition_holds_only_when_nothing_is_left() {
        assert!(Cleared {
            removed: vec![PathBuf::from("a.udk")],
            failed: Vec::new(),
        }
        .established());
        assert!(!Cleared {
            removed: Vec::new(),
            failed: vec![(PathBuf::from("a.udk"), "locked".to_string())],
        }
        .established());
        // Nothing there to begin with is a clean state, not a failure.
        assert!(Cleared {
            removed: Vec::new(),
            failed: Vec::new(),
        }
        .established());
    }

    /// The verdict is the field a reader acts on, so an inert run has to be
    /// unmistakable rather than merely reported.
    #[test]
    fn an_inert_run_says_so_before_anything_else() {
        let inert = verdict(true, false, Duration::from_secs(30));
        assert!(inert.contains("INERT RUN"), "{inert}");
        assert!(inert.contains("do not draw a conclusion"), "{inert}");

        let valid = verdict(true, true, Duration::from_secs(12));
        assert!(valid.contains("Valid run"), "{valid}");
        assert!(valid.contains("12s"), "{valid}");

        let refused = verdict(false, false, Duration::ZERO);
        assert!(refused.contains("was not run"), "{refused}");
    }

    #[test]
    fn a_failed_precondition_never_reads_as_a_measurement() {
        // Whatever `produced` says, an unestablished precondition means the act
        // did not run, so the verdict must not describe a result either way.
        for produced in [true, false] {
            let text = verdict(false, produced, Duration::from_secs(5));
            assert!(!text.contains("Valid run"), "{text}");
            assert!(!text.contains("INERT"), "{text}");
        }
    }

}
