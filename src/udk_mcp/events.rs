//! A bounded structured tail of the editor's own log output.
//!
//! # Why an output device and not a hook
//!
//! UE3 already has a supported extension point for exactly this. `GLog` is an
//! `FOutputDeviceRedirector`, and everything the engine logs - `debugf`,
//! `warnf`, script warnings, load and save messages, shader compilation, the
//! Map Check summary - arrives at `FOutputDeviceRedirector::Serialize`, which
//! fans it out to every registered `FOutputDevice`. Registering one more is what
//! the log window, the log file, and the console window all do.
//!
//! The alternative - detouring `FOutputDeviceRedirector::Serialize` - would see
//! the same text while patching a function that every thread in the process
//! calls, including during crash handling, and would have to be unpatched while
//! another thread might be inside the trampoline. Registration has none of that:
//! it is one `AddOutputDevice` call under the engine's own lock, and one
//! `RemoveOutputDevice` to undo it.
//!
//! [`super::CaptureOutputDevice`] already builds an `FOutputDevice` this way to
//! capture `Exec` output, so the vtable shape is not new here. What is new is
//! that this device outlives the call that made it and is owned by the engine,
//! which is what the rest of this module is careful about.
//!
//! # What runs inside the engine's logging critical section
//!
//! `FOutputDeviceRedirector::Serialize` holds `SynchronizationObject` across the
//! whole fan-out, so [`serialize`] runs with an engine lock held. It therefore
//! does no allocation, takes no other engine lock, makes no MCP call, and - most
//! importantly - never logs. The ring and every message buffer in it are
//! allocated once at attach; a message longer than a slot is truncated in place
//! rather than growing anything.
//!
//! The only lock it takes is this module's own, and the ordering is strictly
//! `GLog` -> [`RING`]. Nothing takes `GLog`'s lock while holding [`RING`], so
//! there is no inversion. The read path keeps its critical section to a bounded
//! memcpy into a `Vec` it reserved *before* locking, so a poll cannot stall the
//! editor inside the engine's lock for longer than that copy.
//!
//! # What it cannot see
//!
//! Two things, both worth knowing before trusting an empty result:
//!
//! 1. **Suppressed categories.** `FOutputDevice::Logf` tests
//!    `FName::SafeSuppressed(Event)` *before* calling `GLog->Serialize`, so a
//!    category switched off in the ini never reaches any output device. This
//!    stream sees exactly what the editor's own log sees - no more, no less.
//! 2. **Everything logged before the first editor tick.** The device is
//!    registered from `UUnrealEdEngine::Tick` because at `DLL_PROCESS_ATTACH`
//!    the redirector is a raw `.bss` object whose constructor has not run.
//!    UE3 keeps a startup backlog for the log window, but
//!    `WxUnrealEdApp::OnInit` discards it before the first tick, so there is
//!    nothing to replay. Startup lives in the log *files*, which
//!    `renx_get_missing_asset_diagnostics` already reads.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::{image_address, json_escape};

/// `GLog`. Proven by [`APP_EXIT_GUARD`], which contains the RIP-relative
/// displacement that reaches it.
const GLOG_RVA: usize = 0x0345_3908;
/// `appExit`, whose first instructions load `GLog` and pass `NAME_Exit`.
const APP_EXIT_RVA: usize = 0x0024_88C0;
const ADD_OUTPUT_DEVICE_RVA: usize = 0x0028_C520;
const REMOVE_OUTPUT_DEVICE_RVA: usize = 0x0028_C5A0;
/// `FOutputDeviceRedirector`'s vtable. Used to prove that the object `GLog`
/// points at really is a redirector before its `this` is handed to the two
/// functions above.
const REDIRECTOR_VTABLE_RVA: usize = 0x025E_8710;
const REDIRECTOR_ADD_SLOT: usize = 4;
const REDIRECTOR_REMOVE_SLOT: usize = 5;

/// `SUB RSP,0x28; MOV RCX,[GLog]; LEA R8,["Exiting."]; MOV EDX,0x2FB`.
///
/// One guard for three facts. The `MOV RCX` displacement is RIP-relative and so
/// is fixed in the image regardless of where Windows loads it, which makes this
/// a byte-exact proof that [`GLOG_RVA`] is right. The `0x2FB` immediate is
/// `NAME_Exit`, which pins the hardcoded name numbering that [`CATEGORIES`]
/// depends on.
const APP_EXIT_GUARD: &[u8] = &[
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x0D, 0x3D, 0xB0, 0x20, 0x03, 0x4C, 0x8D, 0x05, 0x1E, 0xD7,
    0x38, 0x02, 0xBA, 0xFB, 0x02, 0x00, 0x00,
];
/// `FOutputDeviceRedirector::AddOutputDevice` up to its first relocated call.
/// The `LEA RAX,[RCX+0x4c]` is the `FCriticalSection` member, so a build whose
/// redirector layout moved cannot match this.
const ADD_OUTPUT_DEVICE_PROLOGUE: &[u8] = &[
    0x48, 0x89, 0x54, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE,
    0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x5C, 0x24, 0x50, 0x48, 0x89, 0x74, 0x24, 0x58, 0x48, 0x8B, 0xFA,
    0x48, 0x8B, 0xF1, 0x48, 0x8D, 0x41, 0x4C, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x8D, 0x58, 0x08,
    0x48, 0x8B, 0xCB,
];
/// `FOutputDeviceRedirector::RemoveOutputDevice`. Shares a prefix with
/// `AddOutputDevice` and diverges at `MOV RDI,RDX` / `MOV RDI,RCX`.
const REMOVE_OUTPUT_DEVICE_PROLOGUE: &[u8] = &[
    0x48, 0x89, 0x54, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE,
    0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x5C, 0x24, 0x50, 0x48, 0x8B, 0xF9, 0x48, 0x8D, 0x41, 0x4C, 0x48,
    0x89, 0x44, 0x24, 0x40, 0x48, 0x8D, 0x58, 0x08, 0x48, 0x8B, 0xCB,
];

/// How many lines the ring holds. A map load logs thousands of lines, so this
/// is sized to survive one and still show what came before it.
const RING_CAPACITY: usize = 4096;
/// Bytes of UTF-8 kept per line. UE3 lines are rarely near this; the ones that
/// are get truncated with `messageTruncated` set rather than being dropped or
/// allowed to allocate.
const MESSAGE_CAPACITY: usize = 512;
/// Upper bound on the UTF-16 scan, so a missing terminator cannot walk the heap.
const MAX_LOG_UNITS: usize = 16_384;

pub(super) const DEFAULT_LIMIT: usize = 100;
pub(super) const MAX_LIMIT: usize = 500;
const MAX_FILTER_LENGTH: usize = 256;

/// How serious a line is, derived from its category because UE3 carries no
/// separate verbosity on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Verbosity {
    Log = 0,
    Warning = 1,
    Error = 2,
}

impl Verbosity {
    fn id(self) -> &'static str {
        match self {
            Verbosity::Log => "log",
            Verbosity::Warning => "warning",
            Verbosity::Error => "error",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "log" => Ok(Verbosity::Log),
            "warning" => Ok(Verbosity::Warning),
            "error" => Ok(Verbosity::Error),
            _ => Err("minVerbosity must be 'log', 'warning', or 'error'".to_string()),
        }
    }
}

/// `EName` values that mean something went wrong. Everything else is `Log`.
///
/// UE3 has no verbosity field: `warnf` is `Logf(NAME_Warning, ...)` and that
/// name is the only signal there is. These are the names the engine itself
/// treats as warnings and errors.
const ERROR_CATEGORIES: &[i32] = &[
    761, // Critical
    789, // Error
    792, // FriendlyError
];
const WARNING_CATEGORIES: &[i32] = &[
    209, // DevGFxUIWarning
    757, // PerfWarning
    767, // Warning
    768, // ExecWarning
    769, // ScriptWarning
    815, // LocalizationWarning
    819, // ParticleWarn
];

fn verbosity_for(category_id: i32) -> Verbosity {
    if ERROR_CATEGORIES.contains(&category_id) {
        Verbosity::Error
    } else if WARNING_CATEGORIES.contains(&category_id) {
        Verbosity::Warning
    } else {
        Verbosity::Log
    }
}

/// The hardcoded `EName`s UE3 uses as log categories, from `UnNames.h`.
///
/// These are resolved here rather than through the engine's name table on
/// purpose. The numbering is not incidental: `UnNames.h` assigns every one of
/// them an explicit value and freezes everything below
/// `MAX_NETWORKED_HARDCODED_NAME` (1250) because the values are replicated by
/// index, so renumbering breaks network compatibility. Reading `FName::Names`
/// instead would mean mapping the name-table layout and touching it from inside
/// the logging lock, to learn something the header already states.
///
/// [`APP_EXIT_GUARD`] pins `NAME_Exit` at 763 in the target build, which is the
/// runtime check that this table is describing the right numbering. An id that
/// is not in this table is reported with a null `category` and its number, never
/// a guess. Must stay sorted by id - [`category_name`] binary searches it.
const CATEGORIES: &[(i32, &str)] = &[
    (200, "GameStats"),
    (201, "DevFaceFX"),
    (202, "DevCrossLevel"),
    (203, "DevConfig"),
    (204, "DevCamera"),
    (205, "DebugState"),
    (206, "DevAbsorbFuncs"),
    (207, "DevLevelTools"),
    (208, "DevGFxUI"),
    (209, "DevGFxUIWarning"),
    (210, "DevNavMesh"),
    (756, "DevDecals"),
    (757, "PerfWarning"),
    (758, "DevStreaming"),
    (759, "DevLive"),
    (760, "Log"),
    (761, "Critical"),
    (762, "Init"),
    (763, "Exit"),
    (764, "Cmd"),
    (765, "Play"),
    (766, "Console"),
    (767, "Warning"),
    (768, "ExecWarning"),
    (769, "ScriptWarning"),
    (770, "ScriptLog"),
    (771, "Dev"),
    (772, "DevNet"),
    (773, "DevPath"),
    (774, "DevNetTraffic"),
    (775, "DevAudio"),
    (776, "DevLoad"),
    (777, "DevSave"),
    (778, "DevGarbage"),
    (779, "DevKill"),
    (780, "DevReplace"),
    (781, "DevUI"),
    (782, "DevSound"),
    (783, "DevCompile"),
    (784, "DevBind"),
    (785, "Localization"),
    (786, "Compatibility"),
    (787, "NetComeGo"),
    (788, "Title"),
    (789, "Error"),
    (790, "Heading"),
    (791, "SubHeading"),
    (792, "FriendlyError"),
    (793, "Progress"),
    (794, "UserPrompt"),
    (795, "SourceControl"),
    (796, "DevPhysics"),
    (797, "DevTick"),
    (798, "DevStats"),
    (799, "DevComponents"),
    (809, "DevMemory"),
    (810, "XMA"),
    (811, "WAV"),
    (812, "AILog"),
    (813, "DevParticle"),
    (814, "PerfEvent"),
    (815, "LocalizationWarning"),
    (816, "DevUIStyles"),
    (817, "DevUIStates"),
    (818, "DevUIFocus"),
    (819, "ParticleWarn"),
    (854, "UTrace"),
    (855, "DevCollision"),
    (856, "DevSHA"),
    (857, "DevSpawn"),
    (858, "DevAnim"),
    (859, "Hack"),
    (1118, "DevShaders"),
    (1119, "DevDataBase"),
    (1120, "DevDataStore"),
    (1121, "DevAudioVerbose"),
    (1125, "DevUIAnimation"),
    (1126, "DevHDDCaching"),
    (1127, "DevMovie"),
    (1128, "DevShadersDetailed"),
    (1129, "PlayerManagement"),
    (1130, "DevPatch"),
    (1131, "DevLightmassSolver"),
    (1132, "DevAssetDataBase"),
];

fn category_name(id: i32) -> Option<&'static str> {
    CATEGORIES
        .binary_search_by_key(&id, |(key, _)| *key)
        .ok()
        .map(|index| CATEGORIES[index].1)
}

/// One captured line. Fixed size so the ring never allocates after attach.
#[derive(Clone, Copy)]
struct Slot {
    sequence: u64,
    /// Microseconds since [`State::attached_at`], not a wall clock. One
    /// monotonic read in the hot path; wall clock is derived at poll time from
    /// the anchor so the two can never disagree.
    micros: u64,
    category_id: i32,
    thread_id: u32,
    length: u16,
    message_truncated: bool,
    text: [u8; MESSAGE_CAPACITY],
}

impl Slot {
    const fn empty() -> Self {
        Self {
            sequence: 0,
            micros: 0,
            category_id: 0,
            thread_id: 0,
            length: 0,
            message_truncated: false,
            text: [0; MESSAGE_CAPACITY],
        }
    }

    fn message(&self) -> &str {
        let length = (self.length as usize).min(MESSAGE_CAPACITY);
        std::str::from_utf8(&self.text[..length]).unwrap_or("")
    }
}

struct Ring {
    slots: Box<[Slot]>,
    /// Sequences handed out so far. The newest resident sequence, and also the
    /// count of everything ever accepted.
    written: u64,
    /// Lines evicted by wraparound. Reported so a caller that fell behind learns
    /// it lost something instead of silently seeing a gap.
    overwritten: u64,
    messages_truncated: u64,
}

impl Ring {
    fn new() -> Self {
        Self {
            slots: vec![Slot::empty(); RING_CAPACITY].into_boxed_slice(),
            written: 0,
            overwritten: 0,
            messages_truncated: 0,
        }
    }

    /// Lowest sequence still resident, or 0 when nothing has been captured.
    fn oldest(&self) -> u64 {
        if self.written == 0 {
            0
        } else {
            self.written.saturating_sub(RING_CAPACITY as u64 - 1).max(1)
        }
    }
}

struct State {
    ring: Mutex<Ring>,
    attached_at: Instant,
    attached_unix_ms: u64,
}

static RING: OnceLock<State> = OnceLock::new();
static ATTACHED: AtomicBool = AtomicBool::new(false);
/// Set when the device is registered and cleared on detach, so [`serialize`]
/// can be a no-op the instant we stop wanting lines rather than depending on
/// the engine having finished removing us.
static CAPTURING: AtomicBool = AtomicBool::new(false);
static ATTACH_ERROR: Mutex<String> = Mutex::new(String::new());
/// Lines the engine handed us while [`RING`] was not yet initialised. Should
/// always be zero; reported rather than assumed.
static UNROUTED: AtomicU64 = AtomicU64::new(0);

/// The device the engine holds a pointer to.
///
/// Field order and types are `FOutputDevice`'s: a vtable pointer and three
/// `UBOOL`s, 0x14 bytes under UE3's `#pragma pack(4)`. Rust pads the tail to 24;
/// the engine only ever touches the first 20, and it never allocates or frees
/// this object, so the padding is ours to waste.
#[repr(C)]
struct LogDevice {
    vtable: *const usize,
    allow_suppression: i32,
    suppress_event_tag: i32,
    auto_emit_line_terminator: i32,
}

// The engine calls into this from its own threads. Nothing in it is read or
// written outside the vtable functions, which touch only the (Sync) statics
// above.
unsafe impl Sync for LogDevice {}

static DEVICE_VTABLE: OnceLock<[usize; 4]> = OnceLock::new();
static DEVICE: OnceLock<&'static LogDevice> = OnceLock::new();

extern "C" fn device_destructor(this: *mut LogDevice, _flags: u32) -> *mut LogDevice {
    // The engine never owns this allocation, so there is nothing to free. UE3
    // only reaches slot 0 through `delete`, which it does not do to devices it
    // did not create.
    this
}

extern "C" fn device_flush(_this: *mut LogDevice) {}

/// Called by `FOutputDeviceRedirector::TearDown` at engine shutdown, just before
/// it empties its device array. Stopping here means the window between teardown
/// and our own detach cannot capture anything.
extern "C" fn device_teardown(_this: *mut LogDevice) {
    CAPTURING.store(false, Ordering::Release);
}

/// Runs with `GLog`'s critical section held. See the module docs for the rules
/// this obeys; the short version is that it allocates nothing, logs nothing, and
/// cannot panic.
extern "C" fn device_serialize(_this: *mut LogDevice, text: *const u16, event: i32) {
    if text.is_null() || !CAPTURING.load(Ordering::Acquire) {
        return;
    }
    let Some(state) = RING.get() else {
        UNROUTED.fetch_add(1, Ordering::Relaxed);
        return;
    };

    let micros = state.attached_at.elapsed().as_micros().min(u64::MAX as u128) as u64;
    let thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };

    let mut units = 0usize;
    unsafe {
        while units < MAX_LOG_UNITS && *text.add(units) != 0 {
            units += 1;
        }
    }
    let encoded = unsafe { std::slice::from_raw_parts(text, units) };

    let mut guard = state
        .ring
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Reborrowed once so the slot and the counters below are disjoint field
    // borrows rather than two borrows of the guard.
    let ring = &mut *guard;

    if ring.written >= RING_CAPACITY as u64 {
        ring.overwritten += 1;
    }
    ring.written += 1;
    let sequence = ring.written;
    let index = ((sequence - 1) % RING_CAPACITY as u64) as usize;

    let Some(slot) = ring.slots.get_mut(index) else {
        return;
    };
    slot.sequence = sequence;
    slot.micros = micros;
    slot.category_id = event;
    slot.thread_id = thread_id;
    slot.length = 0;
    slot.message_truncated = false;

    // UTF-16 to UTF-8 straight into the slot. `decode_utf16` allocates nothing
    // and yields a replacement character for an unpaired surrogate, so a
    // malformed line is recorded rather than dropped.
    let mut written = 0usize;
    let mut buffer = [0u8; 4];
    for character in char::decode_utf16(encoded.iter().copied()) {
        let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
        let piece = character.encode_utf8(&mut buffer).as_bytes();
        if written + piece.len() > MESSAGE_CAPACITY {
            slot.message_truncated = true;
            break;
        }
        slot.text[written..written + piece.len()].copy_from_slice(piece);
        written += piece.len();
    }
    slot.length = written as u16;
    let truncated = slot.message_truncated;
    if truncated {
        ring.messages_truncated += 1;
    }
}

fn guarded_site(rva: usize, name: &str, expected: &[u8]) -> Result<usize, String> {
    let address = image_address(rva, expected.len(), name).map_err(|error| error.to_string())?;
    let actual = unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) };
    if actual != expected {
        return Err(format!(
            "{name} does not match the verified RenXSDK build at RVA 0x{rva:X}; the engine log stream was not attached"
        ));
    }
    Ok(address)
}

/// Proves that the object `GLog` points at is an `FOutputDeviceRedirector` whose
/// `AddOutputDevice` and `RemoveOutputDevice` are the two functions we verified.
///
/// The byte guards alone say the code at those RVAs is what we think. This says
/// the `this` we are about to hand them belongs to it - which is the half that
/// would otherwise be assumed.
fn redirector() -> Result<(*mut c_void, AddOutputDeviceFn, AddOutputDeviceFn), String> {
    let add = guarded_site(
        ADD_OUTPUT_DEVICE_RVA,
        "FOutputDeviceRedirector::AddOutputDevice",
        ADD_OUTPUT_DEVICE_PROLOGUE,
    )?;
    let remove = guarded_site(
        REMOVE_OUTPUT_DEVICE_RVA,
        "FOutputDeviceRedirector::RemoveOutputDevice",
        REMOVE_OUTPUT_DEVICE_PROLOGUE,
    )?;
    guarded_site(APP_EXIT_RVA, "appExit", APP_EXIT_GUARD)?;

    let vtable = image_address(
        REDIRECTOR_VTABLE_RVA,
        (REDIRECTOR_REMOVE_SLOT + 1) * std::mem::size_of::<usize>(),
        "FOutputDeviceRedirector vtable",
    )
    .map_err(|error| error.to_string())? as *const usize;
    let slots = unsafe { std::slice::from_raw_parts(vtable, REDIRECTOR_REMOVE_SLOT + 1) };
    if slots[REDIRECTOR_ADD_SLOT] != add || slots[REDIRECTOR_REMOVE_SLOT] != remove {
        return Err(
            "the FOutputDeviceRedirector vtable does not point at the verified AddOutputDevice and \
             RemoveOutputDevice; the engine log stream was not attached"
                .to_string(),
        );
    }

    let glog_slot = image_address(GLOG_RVA, std::mem::size_of::<usize>(), "GLog")
        .map_err(|error| error.to_string())?;
    let glog = unsafe { std::ptr::read_unaligned(glog_slot as *const *mut c_void) };
    if glog.is_null() {
        return Err("GLog is null; the engine is shutting down".to_string());
    }
    let object_vtable = unsafe { std::ptr::read_unaligned(glog as *const *const usize) };
    if object_vtable != vtable {
        return Err(
            "GLog does not point at an FOutputDeviceRedirector in this build; the engine log \
             stream was not attached"
                .to_string(),
        );
    }

    Ok(unsafe {
        (
            glog,
            std::mem::transmute::<usize, AddOutputDeviceFn>(add),
            std::mem::transmute::<usize, AddOutputDeviceFn>(remove),
        )
    })
}

type AddOutputDeviceFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

fn device() -> &'static LogDevice {
    DEVICE.get_or_init(|| {
        let vtable = DEVICE_VTABLE.get_or_init(|| {
            [
                device_destructor as *const () as usize,
                device_serialize as *const () as usize,
                device_flush as *const () as usize,
                device_teardown as *const () as usize,
            ]
        });
        // Leaked on purpose. The engine keeps this pointer in an array we do not
        // own; freeing it while a device is still registered would hand the
        // engine a dangling `this`, and there is nothing to gain from reclaiming
        // 24 bytes at shutdown.
        Box::leak(Box::new(LogDevice {
            vtable: vtable.as_ptr(),
            allow_suppression: 1,
            suppress_event_tag: 0,
            auto_emit_line_terminator: 0,
        }))
    })
}

/// Registers the device with `GLog`.
///
/// Called from the editor tick rather than from DLL attach: at attach the
/// redirector is still uninitialised `.bss`, and calling into it would enter a
/// critical section that has not been created.
pub(super) fn attach() {
    if ATTACHED.swap(true, Ordering::AcqRel) {
        return;
    }
    let (glog, add, _remove) = match redirector() {
        Ok(parts) => parts,
        Err(error) => {
            if let Ok(mut slot) = ATTACH_ERROR.lock() {
                *slot = error;
            }
            return;
        }
    };

    // Everything the hot path touches has to exist before the engine can reach
    // it, so the ring is built and published first.
    let _ = RING.set(State {
        ring: Mutex::new(Ring::new()),
        attached_at: Instant::now(),
        attached_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0),
    });
    let device = device();
    CAPTURING.store(true, Ordering::Release);
    unsafe {
        add(glog, device as *const LogDevice as *mut c_void);
    }
}

/// Unregisters the device.
///
/// Only meaningful for a `FreeLibrary` unload, where the process keeps running
/// and the engine would otherwise hold function pointers into an unmapped image.
/// On normal shutdown `FOutputDeviceRedirector::TearDown` has already emptied
/// its array before the DLL goes away.
pub fn detach() {
    CAPTURING.store(false, Ordering::Release);
    if !ATTACHED.load(Ordering::Acquire) {
        return;
    }
    let Ok((glog, _add, remove)) = redirector() else {
        return;
    };
    let Some(device) = DEVICE.get() else {
        return;
    };
    unsafe {
        remove(glog, *device as *const LogDevice as *mut c_void);
    }
}

#[derive(Clone, Copy)]
pub(super) struct Filters<'a> {
    pub(super) since_sequence: u64,
    pub(super) limit: usize,
    pub(super) category: &'a str,
    pub(super) min_verbosity: Verbosity,
    pub(super) query: &'a str,
}

pub(super) fn validate(filters: &Filters) -> Result<(), String> {
    if !(1..=MAX_LIMIT).contains(&filters.limit) {
        return Err(format!("limit must be between 1 and {MAX_LIMIT}"));
    }
    for (name, value) in [("category", filters.category), ("query", filters.query)] {
        if value.len() > MAX_FILTER_LENGTH {
            return Err(format!(
                "{name} must be at most {MAX_FILTER_LENGTH} characters"
            ));
        }
        if value.chars().any(|character| character == '\0') {
            return Err(format!("{name} must not contain a null character"));
        }
    }
    if !filters.category.is_empty() && category_id_for(filters.category).is_none() {
        return Err(format!(
            "unknown category '{}'; it must be a UE3 log category name such as Warning, Error, \
             DevLoad, or DevSave",
            filters.category
        ));
    }
    Ok(())
}

fn category_id_for(name: &str) -> Option<i32> {
    CATEGORIES
        .iter()
        .find(|(_, candidate)| candidate.eq_ignore_ascii_case(name))
        .map(|(id, _)| *id)
}

/// ASCII-case-insensitive substring test. Written out rather than using
/// `to_lowercase` because this runs while the ring lock is held, where an
/// allocation is exactly what the module promises not to do.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn matches(slot: &Slot, filters: &Filters, category: Option<i32>) -> bool {
    if let Some(wanted) = category {
        if slot.category_id != wanted {
            return false;
        }
    }
    if verbosity_for(slot.category_id) < filters.min_verbosity {
        return false;
    }
    contains_ignore_ascii_case(slot.message(), filters.query)
}

pub(super) fn query(filters: &Filters) -> Result<String, String> {
    validate(filters)?;

    let Some(state) = RING.get() else {
        return Ok(unattached_json(filters));
    };
    let category = if filters.category.is_empty() {
        None
    } else {
        category_id_for(filters.category)
    };

    // Reserved before the lock is taken. Everything under the lock is a memcpy
    // into space that already exists, which is what keeps the editor thread from
    // waiting on an allocator inside the engine's logging critical section.
    let mut page: Vec<Slot> = Vec::with_capacity(filters.limit);
    let scan = {
        let ring = state
            .ring
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        scan_ring(&ring, filters, category, &mut page)
    };

    // Two different things can be incomplete, and collapsing them into one flag
    // would make polling wrong. `moreAvailable` means there is unread matching
    // history *after* `nextSequence`, which is what a caller loops on;
    // `olderMatchesOmitted` means the newest-first default page left older
    // matches behind, which is not something polling can recover - the caller
    // has to ask for a bigger page or a narrower filter.
    let dropped_before_requested = if filters.since_sequence > 0 && scan.oldest > 0 {
        scan.oldest
            .saturating_sub(1)
            .saturating_sub(filters.since_sequence)
    } else {
        0
    };
    let retained = if scan.written == 0 {
        0
    } else {
        scan.written - scan.oldest + 1
    };

    let mut events = String::new();
    for (index, slot) in page.iter().enumerate() {
        if index > 0 {
            events.push(',');
        }
        let category = match category_name(slot.category_id) {
            Some(name) => format!("\"{name}\""),
            None => "null".to_string(),
        };
        events.push_str(&format!(
            "{{\"sequence\":{},\"unixMs\":{},\"uptimeSeconds\":{:.3},\"categoryId\":{},\
             \"category\":{category},\"verbosity\":\"{}\",\"threadId\":{},\
             \"messageTruncated\":{},\"message\":\"{}\"}}",
            slot.sequence,
            state.attached_unix_ms + slot.micros / 1_000,
            slot.micros as f64 / 1_000_000.0,
            slot.category_id,
            verbosity_for(slot.category_id).id(),
            slot.thread_id,
            slot.message_truncated,
            json_escape(slot.message())
        ));
    }

    let requested_category = match category_name_of(filters.category) {
        Some(name) => format!("\"{name}\""),
        None => "null".to_string(),
    };

    Ok(format!(
        "{{\"attached\":true,\"source\":\"GLog\",\"events\":[{events}],\
         \"returnedCount\":{returned},\"nextSequence\":{next},\"moreAvailable\":{more},\
         \"olderMatchesOmitted\":{omitted},\"droppedBeforeRequested\":{dropped_before_requested},\
         \"stream\":{{\"capacity\":{RING_CAPACITY},\"messageCapacityBytes\":{MESSAGE_CAPACITY},\
         \"retained\":{retained},\"oldestSequence\":{oldest},\"newestSequence\":{written},\
         \"overwritten\":{overwritten},\"messagesTruncated\":{truncated},\"unrouted\":{unrouted},\
         \"attachedAtUnixMs\":{attached_at},\"capturing\":{capturing}}},\
         \"filters\":{{\"sinceSequence\":{since},\"limit\":{limit},\"category\":{requested_category},\
         \"minVerbosity\":\"{verbosity}\",\"query\":\"{query}\"}},\
         \"note\":\"Lines logged before the first editor tick are not in this stream, and \
         categories suppressed by the engine never reach any output device. The on-disk editor \
         logs cover startup.\"}}",
        returned = page.len(),
        next = scan.next_sequence,
        more = scan.more_available,
        omitted = scan.older_matches_omitted,
        oldest = scan.oldest,
        written = scan.written,
        overwritten = scan.overwritten,
        truncated = scan.messages_truncated,
        unrouted = UNROUTED.load(Ordering::Relaxed),
        attached_at = state.attached_unix_ms,
        capturing = CAPTURING.load(Ordering::Acquire),
        since = filters.since_sequence,
        limit = filters.limit,
        verbosity = filters.min_verbosity.id(),
        query = json_escape(filters.query),
    ))
}

struct Scan {
    written: u64,
    oldest: u64,
    overwritten: u64,
    messages_truncated: u64,
    next_sequence: u64,
    more_available: bool,
    older_matches_omitted: bool,
}

/// Fills `page` from the ring and reports what it left behind.
///
/// Split out so everything that runs while the ring lock is held is in one
/// place and stays free of allocation and formatting.
fn scan_ring(ring: &Ring, filters: &Filters, category: Option<i32>, page: &mut Vec<Slot>) -> Scan {
    let oldest = ring.oldest();
    let mut result = Scan {
        written: ring.written,
        oldest,
        overwritten: ring.overwritten,
        messages_truncated: ring.messages_truncated,
        // Advancing to the newest sequence even when nothing matched is what
        // keeps a filtered poll from rescanning the whole ring forever.
        next_sequence: ring.written,
        more_available: false,
        older_matches_omitted: false,
    };
    if ring.written == 0 {
        return result;
    }

    let resident = |sequence: u64| -> Option<&Slot> {
        let index = ((sequence - 1) % RING_CAPACITY as u64) as usize;
        ring.slots
            .get(index)
            .filter(|slot| slot.sequence == sequence)
    };

    if filters.since_sequence == 0 {
        // No cursor: the newest lines are what anyone wants first. Walking
        // backwards gets them in one pass with no shifting, and the page is
        // reversed at the end so the caller still reads oldest to newest.
        let mut sequence = ring.written;
        loop {
            if let Some(slot) = resident(sequence) {
                if matches(slot, filters, category) {
                    if page.len() == filters.limit {
                        result.older_matches_omitted = true;
                        break;
                    }
                    page.push(*slot);
                }
            }
            if sequence == oldest {
                break;
            }
            sequence -= 1;
        }
        page.reverse();
        return result;
    }

    let start = oldest.max(filters.since_sequence.saturating_add(1));
    for sequence in start..=ring.written {
        let Some(slot) = resident(sequence) else {
            continue;
        };
        if !matches(slot, filters, category) {
            continue;
        }
        if page.len() == filters.limit {
            result.more_available = true;
            result.next_sequence = page.last().map(|last| last.sequence).unwrap_or(oldest);
            break;
        }
        page.push(*slot);
    }
    result
}

/// Echoes the caller's category back in the engine's own spelling, so a request
/// for `devload` is confirmed as `DevLoad` rather than as whatever was typed.
fn category_name_of(value: &str) -> Option<&'static str> {
    category_id_for(value).and_then(category_name)
}

/// What a caller sees when the device never registered. It names the reason
/// rather than returning an empty stream, because an empty stream and a broken
/// one look identical and only one of them is worth retrying.
fn unattached_json(filters: &Filters) -> String {
    let reason = ATTACH_ERROR
        .lock()
        .map(|slot| slot.clone())
        .unwrap_or_default();
    let reason = if reason.is_empty() {
        "The editor has not ticked yet, so the log device is not registered.".to_string()
    } else {
        reason
    };
    format!(
        "{{\"attached\":false,\"source\":\"GLog\",\"events\":[],\"returnedCount\":0,\
         \"nextSequence\":0,\"moreAvailable\":false,\"droppedBeforeRequested\":0,\
         \"reason\":\"{}\",\"filters\":{{\"sinceSequence\":{},\"limit\":{}}}}}",
        json_escape(&reason),
        filters.since_sequence,
        filters.limit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_table_is_sorted_and_unique() {
        for pair in CATEGORIES.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "binary_search_by_key needs a sorted table: {} then {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    /// The one value the byte guard pins in the target build. If this drifts,
    /// the guard and the table disagree and every category is suspect.
    #[test]
    fn name_exit_matches_the_guarded_immediate() {
        assert_eq!(category_name(763), Some("Exit"));
        let immediate = u32::from_le_bytes([
            APP_EXIT_GUARD[19],
            APP_EXIT_GUARD[20],
            APP_EXIT_GUARD[21],
            APP_EXIT_GUARD[22],
        ]);
        assert_eq!(immediate, 763);
    }

    #[test]
    fn verbosity_follows_the_category() {
        assert_eq!(verbosity_for(789), Verbosity::Error);
        assert_eq!(verbosity_for(761), Verbosity::Error);
        assert_eq!(verbosity_for(767), Verbosity::Warning);
        assert_eq!(verbosity_for(769), Verbosity::Warning);
        assert_eq!(verbosity_for(760), Verbosity::Log);
        assert_eq!(verbosity_for(776), Verbosity::Log);
        // Unknown ids are ordinary log lines, never guessed into a severity.
        assert_eq!(verbosity_for(4242), Verbosity::Log);
    }

    #[test]
    fn min_verbosity_orders_correctly() {
        assert!(Verbosity::Error > Verbosity::Warning);
        assert!(Verbosity::Warning > Verbosity::Log);
    }

    #[test]
    fn unknown_category_ids_are_reported_not_guessed() {
        assert_eq!(category_name(4242), None);
        assert_eq!(category_name(0), None);
    }

    #[test]
    fn category_lookup_is_case_insensitive_and_canonicalises() {
        assert_eq!(category_id_for("devload"), Some(776));
        assert_eq!(category_id_for("DEVLOAD"), Some(776));
        assert_eq!(category_name_of("devload"), Some("DevLoad"));
        assert_eq!(category_id_for("NotACategory"), None);
    }

    #[test]
    fn unknown_category_filter_is_refused() {
        let filters = Filters {
            since_sequence: 0,
            limit: 10,
            category: "Nonsense",
            min_verbosity: Verbosity::Log,
            query: "",
        };
        let error = validate(&filters).unwrap_err();
        assert!(error.contains("unknown category"), "{error}");
    }

    #[test]
    fn limits_are_bounded() {
        let base = Filters {
            since_sequence: 0,
            limit: 0,
            category: "",
            min_verbosity: Verbosity::Log,
            query: "",
        };
        assert!(validate(&base).is_err());
        assert!(validate(&Filters {
            limit: MAX_LIMIT + 1,
            ..base
        })
        .is_err());
        assert!(validate(&Filters {
            limit: MAX_LIMIT,
            ..base
        })
        .is_ok());
    }

    #[test]
    fn long_filters_are_refused() {
        let long = "x".repeat(MAX_FILTER_LENGTH + 1);
        let error = validate(&Filters {
            since_sequence: 0,
            limit: 10,
            category: "",
            min_verbosity: Verbosity::Log,
            query: &long,
        })
        .unwrap_err();
        assert!(error.contains("at most"), "{error}");
    }

    #[test]
    fn substring_search_ignores_ascii_case_without_allocating() {
        assert!(contains_ignore_ascii_case("Failed to load Package", "load"));
        assert!(contains_ignore_ascii_case("Failed to load Package", "LOAD"));
        assert!(contains_ignore_ascii_case("anything", ""));
        assert!(!contains_ignore_ascii_case("short", "much longer needle"));
        assert!(!contains_ignore_ascii_case("Failed", "loaded"));
    }

    fn slot_with(sequence: u64, category_id: i32, message: &str) -> Slot {
        let mut slot = Slot::empty();
        slot.sequence = sequence;
        slot.category_id = category_id;
        let bytes = message.as_bytes();
        let length = bytes.len().min(MESSAGE_CAPACITY);
        slot.text[..length].copy_from_slice(&bytes[..length]);
        slot.length = length as u16;
        slot
    }

    #[test]
    fn filters_combine() {
        let warning = slot_with(1, 767, "Static mesh has no collision");
        let load = slot_with(2, 776, "Loading package Foo");

        let all = Filters {
            since_sequence: 0,
            limit: 10,
            category: "",
            min_verbosity: Verbosity::Log,
            query: "",
        };
        assert!(matches(&warning, &all, None));
        assert!(matches(&load, &all, None));

        let warnings_only = Filters {
            min_verbosity: Verbosity::Warning,
            ..all
        };
        assert!(matches(&warning, &warnings_only, None));
        assert!(!matches(&load, &warnings_only, None));

        let by_text = Filters { query: "package", ..all };
        assert!(matches(&load, &by_text, None));
        assert!(!matches(&warning, &by_text, None));

        // An explicit category wins over verbosity ordering: asking for DevLoad
        // must not also return warnings just because they rank higher.
        assert!(matches(&load, &all, Some(776)));
        assert!(!matches(&warning, &all, Some(776)));
    }

    #[test]
    fn a_message_longer_than_a_slot_is_truncated_not_dropped() {
        let long = "A".repeat(MESSAGE_CAPACITY * 2);
        let slot = slot_with(1, 760, &long);
        assert_eq!(slot.message().len(), MESSAGE_CAPACITY);
        assert!(slot.message().chars().all(|character| character == 'A'));
    }

    #[test]
    fn the_oldest_resident_sequence_tracks_wraparound() {
        let mut ring = Ring::new();
        assert_eq!(ring.oldest(), 0);
        ring.written = 1;
        assert_eq!(ring.oldest(), 1);
        ring.written = RING_CAPACITY as u64;
        assert_eq!(ring.oldest(), 1);
        ring.written = RING_CAPACITY as u64 + 1;
        assert_eq!(ring.oldest(), 2);
        ring.written = RING_CAPACITY as u64 * 3;
        assert_eq!(ring.oldest(), RING_CAPACITY as u64 * 2 + 1);
    }

    /// Builds a ring holding `count` lines, alternating Log and Warning, so the
    /// scan can be exercised without an engine.
    fn ring_with(count: u64) -> Ring {
        let mut ring = Ring::new();
        for sequence in 1..=count {
            if sequence > RING_CAPACITY as u64 {
                ring.overwritten += 1;
            }
            let category = if sequence % 2 == 0 { 767 } else { 760 };
            let index = ((sequence - 1) % RING_CAPACITY as u64) as usize;
            ring.slots[index] = slot_with(sequence, category, &format!("line {sequence}"));
            ring.written = sequence;
        }
        ring
    }

    fn all_filters<'a>(since: u64, limit: usize) -> Filters<'a> {
        Filters {
            since_sequence: since,
            limit,
            category: "",
            min_verbosity: Verbosity::Log,
            query: "",
        }
    }

    /// The default page is the newest lines, not the oldest, but still ordered
    /// oldest to newest so a caller can print it as it arrives.
    #[test]
    fn no_cursor_returns_the_newest_page_in_ascending_order() {
        let ring = ring_with(50);
        let filters = all_filters(0, 10);
        let mut page = Vec::with_capacity(10);
        let scan = scan_ring(&ring, &filters, None, &mut page);

        assert_eq!(page.len(), 10);
        assert_eq!(page.first().unwrap().sequence, 41);
        assert_eq!(page.last().unwrap().sequence, 50);
        assert!(page.windows(2).all(|pair| pair[0].sequence < pair[1].sequence));
        assert!(scan.older_matches_omitted, "40 older lines were left behind");
        assert!(
            !scan.more_available,
            "nothing newer exists, so polling has nothing to fetch"
        );
        assert_eq!(scan.next_sequence, 50);
    }

    #[test]
    fn a_cursor_resumes_forwards_and_reports_more() {
        let ring = ring_with(50);
        let filters = all_filters(10, 5);
        let mut page = Vec::with_capacity(5);
        let scan = scan_ring(&ring, &filters, None, &mut page);

        assert_eq!(page.first().unwrap().sequence, 11);
        assert_eq!(page.last().unwrap().sequence, 15);
        assert!(scan.more_available);
        assert_eq!(
            scan.next_sequence, 15,
            "resuming from here must not skip line 16"
        );
    }

    /// The bug this guards against: a caller polling for errors in a stream that
    /// is mostly ordinary logging would never advance its cursor, and would
    /// rescan the whole ring on every call.
    #[test]
    fn a_filtered_poll_that_matches_nothing_still_advances() {
        let ring = ring_with(50);
        let filters = Filters {
            min_verbosity: Verbosity::Error,
            ..all_filters(10, 5)
        };
        let mut page = Vec::with_capacity(5);
        let scan = scan_ring(&ring, &filters, None, &mut page);

        assert!(page.is_empty());
        assert!(!scan.more_available);
        assert_eq!(scan.next_sequence, 50);
    }

    #[test]
    fn a_filtered_page_only_contains_matches() {
        let ring = ring_with(50);
        let filters = Filters {
            min_verbosity: Verbosity::Warning,
            ..all_filters(0, 100)
        };
        let mut page = Vec::with_capacity(100);
        scan_ring(&ring, &filters, None, &mut page);

        assert_eq!(page.len(), 25);
        assert!(page.iter().all(|slot| slot.category_id == 767));
    }

    #[test]
    fn an_empty_ring_answers_without_pretending_to_have_history() {
        let ring = Ring::new();
        let filters = all_filters(0, 10);
        let mut page = Vec::with_capacity(10);
        let scan = scan_ring(&ring, &filters, None, &mut page);

        assert!(page.is_empty());
        assert_eq!(scan.oldest, 0);
        assert_eq!(scan.written, 0);
        assert_eq!(scan.next_sequence, 0);
        assert!(!scan.more_available);
        assert!(!scan.older_matches_omitted);
    }

    /// Once the ring wraps, the oldest lines are gone. A caller resuming from a
    /// cursor that fell off the back has to be told how many it missed, not
    /// handed a silent gap.
    #[test]
    fn wraparound_is_reported_as_loss_not_hidden() {
        let count = RING_CAPACITY as u64 + 100;
        let ring = ring_with(count);
        assert_eq!(ring.oldest(), 101);
        assert_eq!(ring.overwritten, 100);

        let filters = all_filters(10, 5);
        let mut page = Vec::with_capacity(5);
        let scan = scan_ring(&ring, &filters, None, &mut page);

        // Resuming from 10 when 101 is the oldest resident line means 90 lines
        // (11..=100) were evicted unseen.
        assert_eq!(scan.oldest.saturating_sub(1) - filters.since_sequence, 90);
        assert_eq!(page.first().unwrap().sequence, 101);
    }

    /// The device is what the engine holds a pointer to, so its shape is not an
    /// implementation detail - it is an ABI contract with `FOutputDevice`.
    #[test]
    fn the_device_matches_the_engine_output_device_layout() {
        assert_eq!(std::mem::offset_of!(LogDevice, vtable), 0x00);
        assert_eq!(std::mem::offset_of!(LogDevice, allow_suppression), 0x08);
        assert_eq!(std::mem::offset_of!(LogDevice, suppress_event_tag), 0x0C);
        assert_eq!(
            std::mem::offset_of!(LogDevice, auto_emit_line_terminator),
            0x10
        );
        // UE3 packs to 4, so the engine's own object is 0x14. Ours may be padded
        // past that but must never be shorter.
        assert!(std::mem::size_of::<LogDevice>() >= 0x14);
    }

    /// Slot 4 and slot 5 are only meaningful if the four `FOutputDevice` slots
    /// come first, which is what makes our own 4-entry vtable interchangeable
    /// with the engine's devices.
    #[test]
    fn redirector_slots_sit_after_the_output_device_vtable() {
        assert_eq!(REDIRECTOR_ADD_SLOT, 4);
        assert_eq!(REDIRECTOR_REMOVE_SLOT, 5);
    }
}
