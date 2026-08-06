//! What the bridge was doing, readable after it can no longer be asked.
//!
//! # Why
//!
//! The audit ring lives in this DLL's heap, which means it answers questions
//! right up until the only moment anyone urgently wants it: the editor died. A
//! crash takes the ring, the socket, and the answer with it, and what reaches
//! the caller is a dropped connection - the least informative failure there is.
//! Reconstructing the session afterwards meant reading the JSONL by hand and
//! guessing which line was the last one to *start*, because the log only records
//! calls that finished.
//!
//! That guessing is what this removes. Two things go into a file-backed mapping
//! instead of the heap:
//!
//! - the ring of completed calls, so a new session can read the history of a
//!   dead one; and
//! - a record of each call currently in flight, written before the work starts
//!   and cleared when it returns.
//!
//! An in-flight record that outlives its process is the evidence. If the file
//! says a call was in [`Phase::Editor`] and the session ended uncleanly, the
//! editor died inside that operation - which is a claim the JSONL could never
//! make, since a call that kills the process never writes its line.
//!
//! # Cost of being wrong
//!
//! Both directions of error are cheap, deliberately. A record left behind by a
//! process that was merely killed says "interrupted", not "crashed" - the clean
//! shutdown flag is what separates them, and it is reported rather than folded
//! in. A record lost because the mapping could not be opened degrades to an
//! ordinary heap ring and says so.

use std::cell::{Cell, UnsafeCell};
use std::sync::atomic::{fence, AtomicPtr, AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::System::Threading::GetCurrentThreadId;

use super::mapped::{Region, Text, Zeroable};
use super::{exceptions, json_escape};

const FORMAT_MAGIC: u64 = 0x3154_4847_494C_464D; // "MFLIGHT1" little-endian
const FORMAT_VERSION: u32 = 1;

/// Matches the ring size the tool has always advertised, so moving the storage
/// under it does not change what a caller can ask for.
pub(super) const CALL_SLOTS: usize = 256;
/// One per thread that can have a call in flight. The bridge serves connections
/// serially today, so one is used; the rest are headroom for when it does not.
const INTENT_SLOTS: usize = 8;
/// Only ever describes the session immediately before this one. Keeping more
/// generations would need a retention rule to answer "which crash is this?",
/// and the previous session is the one anybody is asking about.
const INTERRUPTED_SLOTS: usize = 8;

const KIND_BYTES: usize = 24;
const TOOL_BYTES: usize = 64;
const OUTCOME_BYTES: usize = 16;
const MODE_BYTES: usize = 16;
/// Wide enough for the audit's own clamp plus the `...[N bytes]` suffix it
/// appends, so the ring and the on-disk log never disagree about a call.
const DETAIL_BYTES: usize = 704;
const NOTE_BYTES: usize = 704;

/// `0` is a real duration, so it cannot mean "never measured".
const NOT_MEASURED: u64 = u64::MAX;

/// Checked by the compiler rather than by a test, because the failure it
/// prevents is silent: a ring field narrower than the audit's own clamp would
/// make the ring and the on-disk JSONL disagree about what a call did, and
/// nothing at runtime would report the disagreement.
const _: () = {
    assert!(DETAIL_BYTES > super::audit::MAX_DETAIL);
    assert!(NOTE_BYTES > super::audit::MAX_DETAIL);
    // Text prefixes its body with a length, so the record is wider than the sum
    // of the strings it holds; if it ever is not, a field has been dropped.
    assert!(std::mem::size_of::<CallRecord>() > DETAIL_BYTES + NOTE_BYTES);
};

/// How far into the bridge a call had got.
///
/// The distinction that matters is the last one: `Editor` means the editor's own
/// thread was inside the operation. Everything before it means the editor was
/// fine and the bridge was still holding the request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Phase {
    /// No call occupies this slot.
    Free,
    /// On a bridge thread: parsing, policy checks, formatting a reply, or
    /// waiting for a human to answer an approval prompt.
    Bridge,
    /// Handed to the editor thread and waiting for it to reach the queue.
    Queued,
    /// Running on the editor thread.
    Editor,
}

impl Phase {
    const fn id(self) -> u32 {
        match self {
            Phase::Free => 0,
            Phase::Bridge => 1,
            Phase::Queued => 2,
            Phase::Editor => 3,
        }
    }

    fn from_id(id: u32) -> Phase {
        match id {
            1 => Phase::Bridge,
            2 => Phase::Queued,
            3 => Phase::Editor,
            // Includes anything a torn or foreign record might hold: an
            // unrecognised phase is not evidence of anything.
            _ => Phase::Free,
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Phase::Free => "free",
            Phase::Bridge => "bridge",
            Phase::Queued => "queued",
            Phase::Editor => "editor",
        }
    }

    /// Written for a reader looking at a session that ended badly, which is the
    /// only time these records are worth reading.
    const fn interrupted_meaning(self) -> &'static str {
        match self {
            Phase::Editor => {
                "the editor thread was inside this operation when the session ended, so this \
                 operation is the strongest available suspect"
            }
            Phase::Queued => {
                "the operation was waiting for the editor thread and had not started, so it did \
                 not run and cannot be the cause"
            }
            Phase::Bridge => {
                "the bridge was still preparing this call and had not handed it to the editor, so \
                 it did not run and cannot be the cause"
            }
            Phase::Free => "the slot held no call",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CallRecord {
    session_id: u64,
    sequence: u64,
    unix_ms: u64,
    millis: u64,
    queue_wait_millis: u64,
    execution_millis: u64,
    thread_id: u32,
    _reserved: u32,
    kind: Text<KIND_BYTES>,
    tool: Text<TOOL_BYTES>,
    outcome: Text<OUTCOME_BYTES>,
    mode: Text<MODE_BYTES>,
    detail: Text<DETAIL_BYTES>,
    note: Text<NOTE_BYTES>,
}

#[repr(C)]
struct CallSlot {
    /// The sequence number this slot holds, or `0` while it is being written.
    /// A reader that sees `0`, or a different value either side of the copy,
    /// skips the slot rather than reporting half of two calls.
    published: AtomicU64,
    payload: UnsafeCell<CallRecord>,
}

unsafe impl Sync for CallSlot {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IntentRecord {
    session_id: u64,
    started_unix_ms: u64,
    phase_unix_ms: u64,
    thread_id: u32,
    phase: u32,
    /// Set when this record was copied out of a slot that was mid-write, which
    /// can only happen if the writing process died between the two halves.
    torn: u32,
    _reserved: u32,
    tool: Text<TOOL_BYTES>,
    detail: Text<DETAIL_BYTES>,
}

#[repr(C)]
struct IntentSlot {
    /// Sequence lock: odd while a write is in progress, even once settled. A
    /// live record is updated in place rather than replaced, so the published
    /// counter that works for the call ring is not enough here.
    version: AtomicU64,
    /// Whether a call owns this slot. Separate from the phase so a reader never
    /// has to take the lock just to find a free slot.
    claimed: AtomicU32,
    _reserved: u32,
    payload: UnsafeCell<IntentRecord>,
}

unsafe impl Sync for IntentSlot {}

#[repr(C)]
struct Recorder {
    magic: u64,
    version: u32,
    /// Checked on open. Two builds of this DLL with different record layouts
    /// would otherwise read each other's bytes as if they meant something.
    record_size: u32,
    call_capacity: u32,
    intent_capacity: u32,
    interrupted_capacity: u32,
    _reserved: u32,
    /// Deliberately not reset between sessions: a caller polling with
    /// `sinceSequence` keeps working across a restart, which is precisely the
    /// case where it is asking about a crash.
    next_sequence: AtomicU64,
    next_call_slot: AtomicU64,
    current_session: AtomicU64,
    current_clean: AtomicU32,
    _reserved_two: u32,
    previous_session: AtomicU64,
    previous_clean: AtomicU32,
    _reserved_three: u32,
    calls: [CallSlot; CALL_SLOTS],
    intents: [IntentSlot; INTENT_SLOTS],
    /// The editor thread's own slot, written by nobody else.
    ///
    /// The obvious design was for the editor thread to mark a phase on the
    /// submitting thread's slot, and it is wrong: a caller that gives up waiting
    /// releases its slot while the operation is still running, the next call on
    /// that thread claims the same index, and the editor thread's write then
    /// lands on an unrelated call. That mislabels a crash in the one report
    /// whose entire purpose is to label it correctly. One slot per writer costs
    /// a few hundred bytes and removes the race rather than narrowing it - and
    /// it puts the record in the hands of the thread that actually dies.
    editor: IntentSlot,
    interrupted: [IntentSlot; INTERRUPTED_SLOTS],
}

unsafe impl Zeroable for Recorder {}

static STORAGE: OnceLock<Region<Recorder>> = OnceLock::new();
static ACTIVE: AtomicPtr<Recorder> = AtomicPtr::new(std::ptr::null_mut());
static SESSION_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// The intent slot this thread's current call owns, so the phase can be
    /// updated from deep inside the bridge without threading a handle through
    /// every layer that does not care about it.
    static CURRENT_SLOT: Cell<Option<usize>> = const { Cell::new(None) };
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

fn active() -> Option<*mut Recorder> {
    let recorder = ACTIVE.load(Ordering::Acquire);
    (!recorder.is_null()).then_some(recorder)
}

/// Opens the recorder, rotates the session, and preserves whatever the previous
/// session left in flight.
///
/// Infallible on purpose. Every failure mode here - a read-only directory, a
/// full disk - costs post-mortem evidence and nothing else, and a bridge that
/// refused to start over its own diagnostics would be the worse trade.
pub(super) fn init() {
    // Shared with the exception log so a reader can put the two together: the
    // access violation and the call that was running when it happened belong to
    // the same session id or they are not the same event.
    let session_id = match exceptions::session_id() {
        0 => now_unix_ms(),
        id => id,
    };
    let storage = STORAGE.get_or_init(|| Region::open("RenXMCPFlightRecorder.bin"));
    unsafe { prepare(storage.get(), session_id) };
    SESSION_ID.store(session_id, Ordering::Release);
    ACTIVE.store(storage.get(), Ordering::Release);
    storage.flush();
}

unsafe fn prepare(recorder: *mut Recorder, session_id: u64) {
    let unusable = unsafe {
        (*recorder).magic != FORMAT_MAGIC
            || (*recorder).version != FORMAT_VERSION
            || (*recorder).record_size != std::mem::size_of::<CallRecord>() as u32
            || (*recorder).call_capacity != CALL_SLOTS as u32
            || (*recorder).intent_capacity != INTENT_SLOTS as u32
            || (*recorder).interrupted_capacity != INTERRUPTED_SLOTS as u32
    };
    if unusable {
        // A file from an older layout is not salvageable and not worth trying
        // to migrate: it holds one previous session's diagnostics, and the cost
        // of discarding it is one session of history after an upgrade.
        unsafe { recorder.write_bytes(0, 1) };
        unsafe {
            (*recorder).magic = FORMAT_MAGIC;
            (*recorder).version = FORMAT_VERSION;
            (*recorder).record_size = std::mem::size_of::<CallRecord>() as u32;
            (*recorder).call_capacity = CALL_SLOTS as u32;
            (*recorder).intent_capacity = INTENT_SLOTS as u32;
            (*recorder).interrupted_capacity = INTERRUPTED_SLOTS as u32;
        }
    }

    let previous = unsafe { (*recorder).current_session.load(Ordering::Acquire) };
    let previous_clean = unsafe { (*recorder).current_clean.load(Ordering::Acquire) };
    unsafe {
        (*recorder)
            .previous_session
            .store(previous, Ordering::Release);
        (*recorder)
            .previous_clean
            .store(previous_clean, Ordering::Release);
        (*recorder)
            .current_session
            .store(session_id, Ordering::Release);
        (*recorder).current_clean.store(0, Ordering::Release);
    }

    unsafe { harvest(recorder, session_id) };
}

/// Moves anything the previous session left in flight into the interrupted set,
/// then frees the live slots for this session.
///
/// The copy is what makes both halves work: the evidence lands somewhere this
/// session will not overwrite, and all eight live slots start empty rather than
/// permanently occupied by a dead process's leftovers.
unsafe fn harvest(recorder: *mut Recorder, session_id: u64) {
    for index in 0..INTERRUPTED_SLOTS {
        let slot = unsafe { &(*recorder).interrupted[index] };
        write_intent(slot, |record| *record = IntentRecord::default());
        slot.claimed.store(0, Ordering::Release);
    }
    let mut next = 0;
    for slot in unsafe { live_slots(recorder) } {
        let (mut record, torn) = read_intent(slot);
        let occupied = record.phase != Phase::Free.id() || slot.claimed.load(Ordering::Acquire) != 0;
        if occupied && record.session_id != session_id && next < INTERRUPTED_SLOTS {
            record.torn = u32::from(torn);
            let target = unsafe { &(*recorder).interrupted[next] };
            write_intent(target, |slot| *slot = record);
            target.claimed.store(1, Ordering::Release);
            next += 1;
        }
        write_intent(slot, |record| *record = IntentRecord::default());
        slot.claimed.store(0, Ordering::Release);
    }
}

/// Every slot a call can currently occupy: one per bridge thread, plus the
/// editor thread's.
unsafe fn live_slots<'a>(recorder: *mut Recorder) -> Vec<&'a IntentSlot> {
    let mut slots = unsafe { (*recorder).intents.iter().collect::<Vec<_>>() };
    slots.push(unsafe { &(*recorder).editor });
    slots
}

/// Sequence-lock write: bump to odd, edit in place, bump back to even.
///
/// The fences are what make a reader able to tell a settled record from one it
/// caught mid-write, which on this path is the same thing as telling a live
/// record from the remains of a process that died between the two halves.
fn write_intent(slot: &IntentSlot, edit: impl FnOnce(&mut IntentRecord)) {
    slot.version.fetch_add(1, Ordering::Relaxed);
    fence(Ordering::Release);
    unsafe { edit(&mut *slot.payload.get()) };
    fence(Ordering::Release);
    slot.version.fetch_add(1, Ordering::Relaxed);
}

/// Returns the record and whether it was caught mid-write.
///
/// A torn record is still returned rather than dropped. After a crash it is the
/// only account of the call that was running, and a tool name that is probably
/// right beats no tool name at all - as long as the doubt travels with it.
fn read_intent(slot: &IntentSlot) -> (IntentRecord, bool) {
    let before = slot.version.load(Ordering::Acquire);
    let record = unsafe { std::ptr::read(slot.payload.get()) };
    fence(Ordering::Acquire);
    let after = slot.version.load(Ordering::Acquire);
    (record, before % 2 == 1 || before != after)
}

/// Claims an intent slot for the call about to run on this thread.
///
/// Returns `None` when every slot is taken, which drops the record rather than
/// blocking: the recorder exists to explain a call, never to gate one.
pub(super) fn begin(tool: &str, detail: &str) -> Option<Ticket> {
    let recorder = active()?;
    let session_id = SESSION_ID.load(Ordering::Acquire);
    let stamp = now_unix_ms();
    let thread_id = unsafe { GetCurrentThreadId() };
    for index in 0..INTENT_SLOTS {
        let slot = unsafe { &(*recorder).intents[index] };
        if slot
            .claimed
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        write_intent(slot, |record| {
            *record = IntentRecord {
                session_id,
                started_unix_ms: stamp,
                phase_unix_ms: stamp,
                thread_id,
                phase: Phase::Bridge.id(),
                torn: 0,
                _reserved: 0,
                tool: Text::new(tool),
                detail: Text::new(detail),
            };
        });
        let previous = CURRENT_SLOT.with(|cell| cell.replace(Some(index)));
        return Some(Ticket {
            slot: index,
            previous,
        });
    }
    None
}

/// Releases the intent slot when the call finishes, however it finishes.
///
/// A guard rather than a paired call because the interesting exits from a tool
/// call are the ones nobody wrote on purpose - an early return on a policy
/// refusal, a `?` on a malformed argument. A slot leaked on one of those paths
/// would read, later, as a call that never came back.
pub(super) struct Ticket {
    slot: usize,
    previous: Option<usize>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        CURRENT_SLOT.with(|cell| cell.set(self.previous));
        let Some(recorder) = active() else {
            return;
        };
        let slot = unsafe { &(*recorder).intents[self.slot] };
        write_intent(slot, |record| *record = IntentRecord::default());
        slot.claimed.store(0, Ordering::Release);
    }
}

/// Moves this thread's own record to a new phase.
///
/// Only ever the calling thread's own slot. Every slot has exactly one writer,
/// which is what lets the seqlock above stay a seqlock rather than needing a
/// lock that a dying process could leave held.
pub(super) fn set_phase(phase: Phase) {
    let Some(index) = CURRENT_SLOT.with(|cell| cell.get()) else {
        return;
    };
    let Some(recorder) = active() else {
        return;
    };
    let stamp = now_unix_ms();
    write_intent(unsafe { &(*recorder).intents[index] }, |record| {
        record.phase = phase.id();
        record.phase_unix_ms = stamp;
    });
}

/// What the editor thread needs in order to describe the work it is about to
/// run, copied out of the submitting thread's record while that record is
/// still definitely the caller's.
#[derive(Clone)]
pub(super) struct Handoff {
    tool: String,
    detail: String,
}

pub(super) fn handoff() -> Option<Handoff> {
    let index = CURRENT_SLOT.with(|cell| cell.get())?;
    let recorder = active()?;
    let (record, _) = read_intent(unsafe { &(*recorder).intents[index] });
    Some(Handoff {
        tool: record.tool.as_str().to_string(),
        detail: record.detail.as_str().to_string(),
    })
}

/// Publishes, for as long as the guard lives, that the editor thread is inside
/// this operation.
///
/// A record found in this slot after a session ended uncleanly is the strongest
/// statement this module can make: the thread that wrote it is the thread that
/// died, and it had not reached the line that clears it.
pub(super) fn enter_editor(work: &Handoff) -> Option<EditorGuard> {
    let recorder = active()?;
    let session_id = SESSION_ID.load(Ordering::Acquire);
    let stamp = now_unix_ms();
    let thread_id = unsafe { GetCurrentThreadId() };
    let slot = unsafe { &(*recorder).editor };
    write_intent(slot, |record| {
        *record = IntentRecord {
            session_id,
            started_unix_ms: stamp,
            phase_unix_ms: stamp,
            thread_id,
            phase: Phase::Editor.id(),
            torn: 0,
            _reserved: 0,
            tool: Text::new(&work.tool),
            detail: Text::new(&work.detail),
        };
    });
    slot.claimed.store(1, Ordering::Release);
    Some(EditorGuard { _private: () })
}

pub(super) struct EditorGuard {
    _private: (),
}

impl Drop for EditorGuard {
    fn drop(&mut self) {
        let Some(recorder) = active() else {
            return;
        };
        let slot = unsafe { &(*recorder).editor };
        write_intent(slot, |record| *record = IntentRecord::default());
        slot.claimed.store(0, Ordering::Release);
    }
}

/// One completed call, on its way into the ring.
pub(super) struct Completed<'a> {
    pub kind: &'a str,
    pub tool: &'a str,
    pub outcome: &'a str,
    pub mode: &'a str,
    pub detail: &'a str,
    pub note: &'a str,
    pub millis: u64,
    pub queue_wait_millis: Option<u64>,
    pub execution_millis: Option<u64>,
}

/// Appends to the ring and returns the sequence number it was given, or `0` if
/// the recorder is not running.
pub(super) fn append(call: &Completed<'_>) -> u64 {
    let Some(recorder) = active() else {
        return 0;
    };
    let sequence = unsafe { (*recorder).next_sequence.fetch_add(1, Ordering::Relaxed) } + 1;
    let index =
        unsafe { (*recorder).next_call_slot.fetch_add(1, Ordering::Relaxed) } as usize % CALL_SLOTS;
    let record = CallRecord {
        session_id: SESSION_ID.load(Ordering::Acquire),
        sequence,
        unix_ms: now_unix_ms(),
        millis: call.millis,
        queue_wait_millis: call.queue_wait_millis.unwrap_or(NOT_MEASURED),
        execution_millis: call.execution_millis.unwrap_or(NOT_MEASURED),
        thread_id: unsafe { GetCurrentThreadId() },
        _reserved: 0,
        kind: Text::new(call.kind),
        tool: Text::new(call.tool),
        outcome: Text::new(call.outcome),
        mode: Text::new(call.mode),
        detail: Text::new(call.detail),
        note: Text::new(call.note),
    };
    let slot = unsafe { &(*recorder).calls[index] };
    // Unpublish, write, republish. A reader that arrives in the middle sees a
    // slot claiming to hold nothing rather than one claiming to hold a call it
    // has only half of.
    slot.published.store(0, Ordering::Release);
    unsafe { std::ptr::write(slot.payload.get(), record) };
    slot.published.store(sequence, Ordering::Release);
    sequence
}

pub(crate) fn mark_clean_shutdown() {
    let Some(recorder) = active() else {
        return;
    };
    unsafe { (*recorder).current_clean.store(1, Ordering::Release) };
    if let Some(storage) = STORAGE.get() {
        storage.flush();
    }
}

/// One completed call, read back out.
pub(super) struct Call {
    pub sequence: u64,
    pub session_id: u64,
    pub unix_ms: u64,
    pub thread_id: u32,
    pub kind: String,
    pub tool: String,
    pub outcome: String,
    pub mode: String,
    pub detail: String,
    pub note: String,
    pub millis: u64,
    pub queue_wait_millis: Option<u64>,
    pub execution_millis: Option<u64>,
}

fn measured(value: u64) -> Option<u64> {
    (value != NOT_MEASURED).then_some(value)
}

pub(super) fn snapshot() -> Vec<Call> {
    let Some(recorder) = active() else {
        return Vec::new();
    };
    let mut calls = Vec::new();
    for index in 0..CALL_SLOTS {
        let slot = unsafe { &(*recorder).calls[index] };
        let before = slot.published.load(Ordering::Acquire);
        if before == 0 {
            continue;
        }
        let record = unsafe { std::ptr::read(slot.payload.get()) };
        let after = slot.published.load(Ordering::Acquire);
        if before != after || after == 0 {
            continue;
        }
        calls.push(Call {
            sequence: record.sequence,
            session_id: record.session_id,
            unix_ms: record.unix_ms,
            thread_id: record.thread_id,
            kind: record.kind.as_str().to_string(),
            tool: record.tool.as_str().to_string(),
            outcome: record.outcome.as_str().to_string(),
            mode: record.mode.as_str().to_string(),
            detail: record.detail.as_str().to_string(),
            note: record.note.as_str().to_string(),
            millis: record.millis,
            queue_wait_millis: measured(record.queue_wait_millis),
            execution_millis: measured(record.execution_millis),
        });
    }
    calls.sort_by_key(|call| call.sequence);
    calls.dedup_by_key(|call| call.sequence);
    calls
}

pub(super) struct Sessions {
    pub current: u64,
    pub previous: u64,
    /// `None` when there was no previous session to have ended either way.
    pub previous_clean: Option<bool>,
}

/// When this session started, as Unix milliseconds, or `0` before the recorder
/// opened. The session id is that instant, which is what lets a file's mtime be
/// compared against it without carrying a second clock.
pub(super) fn session_started_unix_ms() -> u64 {
    SESSION_ID.load(Ordering::Acquire)
}

pub(super) fn sessions() -> Sessions {
    let Some(recorder) = active() else {
        return Sessions {
            current: 0,
            previous: 0,
            previous_clean: None,
        };
    };
    let previous = unsafe { (*recorder).previous_session.load(Ordering::Acquire) };
    Sessions {
        current: SESSION_ID.load(Ordering::Acquire),
        previous,
        previous_clean: (previous != 0)
            .then(|| unsafe { (*recorder).previous_clean.load(Ordering::Acquire) } != 0),
    }
}

/// A call that was in flight, either right now or when a previous session ended.
pub(super) struct InFlight {
    pub session_id: u64,
    pub thread_id: u32,
    pub phase: Phase,
    pub tool: String,
    pub detail: String,
    pub started_unix_ms: u64,
    pub phase_unix_ms: u64,
    pub torn: bool,
}

fn collect(slots: &[&IntentSlot]) -> Vec<InFlight> {
    let mut found = Vec::new();
    for slot in slots {
        if slot.claimed.load(Ordering::Acquire) == 0 {
            continue;
        }
        let (record, torn) = read_intent(slot);
        let phase = Phase::from_id(record.phase);
        if phase == Phase::Free {
            continue;
        }
        found.push(InFlight {
            session_id: record.session_id,
            thread_id: record.thread_id,
            phase,
            tool: record.tool.as_str().to_string(),
            detail: record.detail.as_str().to_string(),
            started_unix_ms: record.started_unix_ms,
            phase_unix_ms: record.phase_unix_ms,
            torn: torn || record.torn != 0,
        });
    }
    found
}

/// Calls that never finished because the session holding them ended.
pub(super) fn interrupted() -> Vec<InFlight> {
    match active() {
        Some(recorder) => collect(&unsafe { (*recorder).interrupted.iter().collect::<Vec<_>>() }),
        None => Vec::new(),
    }
}

/// Calls running right now, this one included.
pub(super) fn in_flight() -> Vec<InFlight> {
    match active() {
        Some(recorder) => collect(&unsafe { live_slots(recorder) }),
        None => Vec::new(),
    }
}

pub(super) fn in_flight_json(call: &InFlight, previous_clean: Option<bool>) -> String {
    // An interrupted record only means "crash" if the session it belongs to
    // also ended uncleanly. Saying so is the difference between evidence and an
    // accusation: an editor closed with Task Manager leaves exactly this record.
    let died = matches!(previous_clean, Some(false));
    format!(
        r#"{{"tool":"{}","detail":"{}","phase":"{}","meaning":"{}","sessionId":{},"threadId":{},"startedUnixMs":{},"phaseEnteredUnixMs":{},"recordTorn":{},"sessionEndedUncleanly":{}}}"#,
        json_escape(&call.tool),
        json_escape(&call.detail),
        call.phase.label(),
        call.phase.interrupted_meaning(),
        call.session_id,
        call.thread_id,
        call.started_unix_ms,
        call.phase_unix_ms,
        call.torn,
        match previous_clean {
            Some(_) => died.to_string(),
            None => "null".to_string(),
        },
    )
}

/// Where the records live, and why they might not be anywhere.
pub(super) fn persistence_json() -> String {
    let Some(storage) = STORAGE.get() else {
        return r#"{"persistent":false,"path":null,"error":"the flight recorder is not running"}"#
            .to_string();
    };
    format!(
        r#"{{"persistent":{},"path":{},"error":{}}}"#,
        storage.is_persistent(),
        storage
            .path()
            .map(|path| format!("\"{}\"", json_escape(&path.display().to_string())))
            .unwrap_or_else(|| "null".to_string()),
        storage
            .error()
            .map(|error| format!("\"{}\"", json_escape(error)))
            .unwrap_or_else(|| "null".to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_identifiers_round_trip() {
        for phase in [Phase::Free, Phase::Bridge, Phase::Queued, Phase::Editor] {
            assert_eq!(Phase::from_id(phase.id()), phase);
        }
    }

    /// A record written by another build, or caught mid-write, can hold any
    /// value at all here. It must not be readable as a phase that would let a
    /// reader blame an operation.
    #[test]
    fn an_unrecognised_phase_accuses_nothing() {
        assert_eq!(Phase::from_id(9999), Phase::Free);
        assert_eq!(Phase::from_id(u32::MAX), Phase::Free);
    }

    #[test]
    fn only_the_editor_phase_implicates_its_operation() {
        assert!(Phase::Editor.interrupted_meaning().contains("suspect"));
        assert!(Phase::Queued.interrupted_meaning().contains("cannot be the cause"));
        assert!(Phase::Bridge.interrupted_meaning().contains("cannot be the cause"));
    }

    #[test]
    fn a_zero_duration_is_measured_and_the_sentinel_is_not() {
        assert_eq!(measured(0), Some(0));
        assert_eq!(measured(42), Some(42));
        assert_eq!(measured(NOT_MEASURED), None);
    }

    fn sample() -> InFlight {
        InFlight {
            session_id: 1234,
            thread_id: 7,
            phase: Phase::Editor,
            tool: "renx_start_pie".to_string(),
            detail: "{}".to_string(),
            started_unix_ms: 100,
            phase_unix_ms: 200,
            torn: false,
        }
    }

    /// The claim this whole module exists to make, and the one it must not
    /// overstate: an unfinished call is a crash only if the session also ended
    /// badly.
    #[test]
    fn an_interrupted_call_is_only_a_crash_when_the_session_ended_uncleanly() {
        let crashed = in_flight_json(&sample(), Some(false));
        assert_eq!(
            super::super::json_field_raw(&crashed, "sessionEndedUncleanly"),
            Some("true")
        );

        let closed = in_flight_json(&sample(), Some(true));
        assert_eq!(
            super::super::json_field_raw(&closed, "sessionEndedUncleanly"),
            Some("false")
        );

        let live = in_flight_json(&sample(), None);
        assert_eq!(
            super::super::json_field_raw(&live, "sessionEndedUncleanly"),
            Some("null")
        );
    }

    #[test]
    fn a_torn_record_says_so() {
        let torn = in_flight_json(
            &InFlight {
                torn: true,
                ..sample()
            },
            Some(false),
        );
        assert_eq!(super::super::json_field_raw(&torn, "recordTorn"), Some("true"));
    }

    #[test]
    fn nothing_is_reported_before_the_recorder_starts() {
        // Every reader has to tolerate being called on a bridge whose recorder
        // never opened, because the fallback path is silent by design.
        assert!(ACTIVE.load(Ordering::Acquire).is_null());
        assert!(snapshot().is_empty());
        assert!(interrupted().is_empty());
        assert!(in_flight().is_empty());
        assert_eq!(sessions().current, 0);
        assert!(persistence_json().contains("\"persistent\":false"));
    }
}
