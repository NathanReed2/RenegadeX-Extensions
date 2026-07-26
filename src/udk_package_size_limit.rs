//! Early warning for cooked packages approaching UE3's 2 GiB size limit, and a
//! clear diagnosis when one crosses it.
//!
//! # The limit
//!
//! Every file offset in UE3's archive layer is an `INT` (signed 32-bit):
//! `FArchive::Tell`/`Seek`/`TotalSize`, `FObjectExport::SerialOffset`,
//! `FUntypedBulkData::BulkDataOffsetInFile`, and the offsets in
//! `FPackageFileSummary`. A cooked package therefore cannot exceed
//! [`PACKAGE_LIMIT`] bytes. One byte past it, the position wraps negative,
//! `SetFilePointer` rejects it with `ERROR_NEGATIVE_SEEK`,
//! `FArchiveFileWriterWindows::Seek` sets `ArIsError`, and
//! `UObject::SavePackage` silently discards the package.
//!
//! The engine's own reporting makes this very hard to recognise. All the cook
//! log says is:
//!
//! ```text
//! Warning: Warning, Error seeking file
//! Error:   Destination file exists does not exist after cooking ...\RenX-MenuMap.udk
//! Critical: World renx-menumap.TheWorld not cleaned up by garbage collection!
//! ```
//!
//! Nothing names the package, the size, or the limit; the second and third
//! lines are downstream consequences of the first. Diagnosing one instance of
//! this took a `SetFilePointer` import hook, a stack walk, and per-file size
//! sampling across several 13-minute cooks. This module exists so that never
//! needs repeating: it names the package and its remaining headroom *before*
//! the cook dies, and explains the cause when it does.
//!
//! # Why both a detour and an import hook
//!
//! The two hooks cover different halves of the problem, and neither is
//! sufficient alone:
//!
//! * The detour on `FArchiveFileWriterWindows::Seek` sees the position climbing
//!   and can warn early, while there is still time to act. It reliably observes
//!   *successful* seeks - positions up to 2,105,008,148 were reported this way.
//! * It does **not** reliably observe the seek that finally fails. In repeated
//!   runs the engine logged `SeekFailed` while this detour, with an uncapped
//!   report path and an explicit `position < 0` test, recorded nothing. A stack
//!   walk of the failing call showed the writer `Seek` frame absent between the
//!   `SetFilePointer` call and its caller in `FUntypedBulkData::Serialize`, so
//!   the failing call reaches the OS without traversing the detoured entry.
//!   Hooking the `SetFilePointer` import catches it regardless of route, since
//!   all four call sites in the image share one IAT slot.
use crate::dll::get_udk_ptr;
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use crate::udk_log;
use anyhow::Context;
use retour::static_detour;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Largest byte offset an `INT` archive position can address.
const PACKAGE_LIMIT: i64 = i32::MAX as i64;

/// Positions below this are ignored outright. Keeps the common case to a single
/// signed compare, since this runs on every file-writer seek during a cook
/// (~19 million of them).
const REGISTER_ABOVE: i32 = 1024 * 1024 * 1024;

/// Escalating positions at which a package is reported, so a cook that is
/// merely large stays quiet while one that is genuinely close gets louder.
/// Each writer reports each tier at most once.
const WARN_TIERS: [i32; 4] = [
    1_610_612_736, // 1.50 GiB
    1_879_048_192, // 1.75 GiB
    2_040_109_465, // 1.90 GiB
    2_126_008_811, // 1.98 GiB
];

/// Known static offset of `FArchiveFileWriterWindows::Seek` in the 12791
/// (UDK-2015-01) x64 build, found via the sole reference to the ASCII
/// `"SeekFailed"` localization key at RVA 0x25B9E98 - one string, one
/// referencing instruction (0x1A3A42), inside 0x1A39F0-0x1A3AC4.
#[cfg(target_arch = "x86_64")]
const FILE_WRITER_SEEK_OFFSET: usize = 0x001A_39F0;

/// Prologue of `FArchiveFileWriterWindows::Seek`, extended through the
/// `Flush()` virtual call and the `SetFilePointer` argument setup:
///
/// ```asm
/// PUSH RDI; SUB RSP,0x40; MOV [RSP+0x20],-2
/// MOV  [RSP+0x50],RBX; MOV [RSP+0x58],RSI
/// MOV  EDI,EDX           ; InPos
/// MOV  RBX,RCX           ; this
/// MOV  RAX,[RCX]; CALL [RAX+0x98]   ; this->Flush()
/// XOR  R9D,R9D; XOR R8D,R8D; MOV EDX,EDI
/// ```
///
/// The bare prologue (through `MOV RBX,RCX`) also matches at RVA 0xA4E890,
/// whose next instruction is `MOV RDX,[RIP+...]` rather than `MOV RAX,[RCX]`.
/// Extending past that divergence makes this match 0x1A39F0 and nothing else,
/// so the hook target does not depend on nearest-match tie-breaking.
#[cfg(target_arch = "x86_64")]
const FILE_WRITER_SEEK_SIG: [u8; 47] = [
    0x40, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF, 0x48,
    0x89, 0x5C, 0x24, 0x50, 0x48, 0x89, 0x74, 0x24, 0x58, 0x8B, 0xFA, 0x48, 0x8B, 0xD9, 0x48, 0x8B,
    0x01, 0xFF, 0x90, 0x98, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC9, 0x45, 0x33, 0xC0, 0x8B, 0xD7,
];

/// `FArchiveFileWriterWindows::Handle`, loaded into RCX for `SetFilePointer`
/// at udk.exe+0x1A3A1F.
const HANDLE_OFFSET: usize = 0x88;

/// `Filename`, an `FString` (`TArray<TCHAR>`): data pointer at +0x94, length at
/// +0x9C. This is what puts `Error` on the unaligned +0xA4 seen at
/// udk.exe+0x1A3A8B, corroborating the whole layout: `Handle`(0x88)
/// `StatsHandle`(0x90) `Filename`(0x94) `Error`(0xA4) `Pos`(0xAC)
/// `BufferCount`(0xB0) `Buffer`(0xB4).
const FILENAME_DATA_OFFSET: usize = 0x94;
const FILENAME_LENGTH_OFFSET: usize = 0x9C;

/// Upper bound on a filename read out of a writer, so a garbage length cannot
/// turn a diagnostic into a fault.
const MAX_FILENAME_CHARS: usize = 512;

/// RVA of the `KERNEL32.dll!SetFilePointer` IAT slot (`FirstThunk` entry),
/// resolved from the import directory of the 12791 x64 image. All four
/// `SetFilePointer` call sites in the image (0x1A1A31, 0x1A3A26, 0x1A4C15,
/// 0x1E64CF) read this one slot, so patching it observes every seek the process
/// makes regardless of which archive class issued it.
#[cfg(target_arch = "x86_64")]
const SET_FILE_POINTER_IAT_RVA: usize = 0x024B_D6A8;

/// `INVALID_SET_FILE_POINTER`. Ambiguous when `lpDistanceToMoveHigh` is
/// non-NULL (it is then a legitimate low dword), so failure is only concluded
/// when `GetLastError` also reports one.
const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;

/// `ERROR_NEGATIVE_SEEK` - what Windows returns for a wrapped position.
const ERROR_NEGATIVE_SEEK: i32 = 131;

/// Caps reports of seek failures that are *not* the size limit (a failing disk,
/// a closed handle), which could otherwise repeat per call.
const MAX_UNRELATED_FAILURES: usize = 8;

type SetFilePointerFn = unsafe extern "system" fn(*mut c_void, i32, *mut i32, u32) -> u32;

static ORIGINAL_SET_FILE_POINTER: AtomicUsize = AtomicUsize::new(0);
static UNRELATED_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// A writer seen above [`REGISTER_ABOVE`].
struct WatchedWriter {
    filename: String,
    /// Number of [`WARN_TIERS`] already reported for this writer.
    tier: usize,
}

/// Writers being watched, keyed by OS file handle.
///
/// The handle is also what the `SetFilePointer` hook has available, which is how
/// a failure gets attributed to a filename. A handle reused for a different file
/// after a close could carry a stale name into a warning; that is accepted, as
/// the alternative is reading the filename on every seek.
static WATCHED: Mutex<BTreeMap<usize, WatchedWriter>> = Mutex::new(BTreeMap::new());

thread_local! {
    /// Guards against re-entry: [`udk_log`] writes through the engine's output
    /// device, which is itself backed by an archive, so logging from inside a
    /// seek hook can re-enter this code.
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

static_detour! {
    static FileWriterSeekHook: extern "C" fn(*mut c_void, i32);
}

unsafe fn read_i32(base: *mut c_void, offset: usize) -> i32 {
    ((base as *const u8).add(offset) as *const i32).read_unaligned()
}

unsafe fn read_usize(base: *mut c_void, offset: usize) -> usize {
    ((base as *const u8).add(offset) as *const usize).read_unaligned()
}

/// Reads the writer's `Filename` so a report can name a file rather than an
/// opaque handle. Returns a placeholder instead of risking a fault on a garbage
/// pointer or length.
unsafe fn read_writer_filename(writer: *mut c_void) -> String {
    let data = read_usize(writer, FILENAME_DATA_OFFSET);
    let length = read_i32(writer, FILENAME_LENGTH_OFFSET);

    if data == 0 || length <= 0 || length as usize > MAX_FILENAME_CHARS {
        return "<unknown file>".to_string();
    }

    // An FString's length includes the trailing NUL.
    let characters = (length as usize) - 1;
    let mut units = Vec::with_capacity(characters);
    for index in 0..characters {
        units.push(((data as *const u16).add(index)).read_unaligned());
    }

    String::from_utf16_lossy(&units)
}

fn mebibytes(bytes: i64) -> i64 {
    bytes / (1024 * 1024)
}

/// Records a writer's position and reports it if it has entered a new
/// [`WARN_TIERS`] band.
fn note_position(writer: *mut c_void, handle: usize, position: i32) {
    let reached = WARN_TIERS
        .iter()
        .rposition(|tier| position >= *tier)
        .map_or(0, |index| index + 1);

    // Scoped so the lock is released before logging, which can re-enter.
    let announce = {
        let Ok(mut watched) = WATCHED.lock() else {
            return;
        };
        let entry = watched.entry(handle).or_insert_with(|| WatchedWriter {
            filename: unsafe { read_writer_filename(writer) },
            tier: 0,
        });

        if reached > entry.tier {
            entry.tier = reached;
            Some(entry.filename.clone())
        } else {
            None
        }
    };

    let Some(filename) = announce else {
        return;
    };

    let remaining = PACKAGE_LIMIT - position as i64;
    IN_HOOK.set(true);
    udk_log::log(
        udk_log::LogType::Warning,
        &format!(
            "cooked package '{filename}' has reached {position} bytes ({} MiB) - only {} MiB \
             below the {PACKAGE_LIMIT}-byte (2 GiB) package limit. UE3 stores every archive \
             offset as a signed 32-bit INT, so crossing that limit makes the position wrap \
             negative and SavePackage discards the package, reporting only 'Error seeking file' \
             and a missing cooked file. Reduce the content this package references, or move \
             shared content into a startup package so it is not inlined per-map.",
            mebibytes(position as i64),
            mebibytes(remaining),
        ),
    );
    IN_HOOK.set(false);
}

/// Passes the seek through untouched, then records how far into the file it
/// went. Purely observational.
fn file_writer_seek_hook(writer: *mut c_void, position: i32) {
    FileWriterSeekHook.call(writer, position);

    if writer.is_null() || position < REGISTER_ABOVE || IN_HOOK.get() {
        return;
    }

    let handle = unsafe { read_usize(writer, HANDLE_OFFSET) };
    note_position(writer, handle, position);
}

/// Reports a seek the OS rejected. A negative position with `FILE_BEGIN` is the
/// size limit being exceeded and gets the actionable explanation; anything else
/// is reported plainly and rate-limited.
#[cfg(target_arch = "x86_64")]
fn report_failure(handle: usize, distance: i32, move_method: u32, last_error: i32) {
    let known = WATCHED
        .lock()
        .ok()
        .and_then(|watched| watched.get(&handle).map(|entry| entry.filename.clone()));

    IN_HOOK.set(true);
    if distance < 0 && move_method == 0 && last_error == ERROR_NEGATIVE_SEEK {
        // A negative FILE_BEGIN offset is not a real position: it is an offset
        // past 2 GiB that has wrapped. Recover the value the engine wanted.
        let wanted = distance as u32 as i64;
        let filename = known.unwrap_or_else(|| "<unknown file>".to_string());
        udk_log::log(
            udk_log::LogType::Error,
            &format!(
                "cooked package '{filename}' EXCEEDED the 2 GiB package limit: it tried to \
                 address byte {wanted} ({} MiB), which is {} bytes past the {PACKAGE_LIMIT}-byte \
                 maximum and wraps to {distance} as a signed 32-bit INT. Windows rejected the \
                 seek (ERROR_NEGATIVE_SEEK), so ArIsError is now set and SavePackage will \
                 discard this package - the cook will report 'Error seeking file' and the cooked \
                 file will be missing. This is a hard format limit, not a transient error: \
                 reduce the content this package references, or move shared content into a \
                 startup package so it is not inlined into every map.",
                mebibytes(wanted),
                wanted - PACKAGE_LIMIT,
            ),
        );
    } else {
        let seen = UNRELATED_FAILURES.fetch_add(1, Ordering::Relaxed);
        if seen < MAX_UNRELATED_FAILURES {
            let filename = known.unwrap_or_else(|| "<unregistered file>".to_string());
            udk_log::log(
                udk_log::LogType::Warning,
                &format!(
                    "SetFilePointer failed on '{filename}' (handle 0x{handle:X}): \
                     lDistanceToMove={distance} dwMoveMethod={move_method} \
                     GetLastError={last_error}. The archive is now in an error state and any \
                     package being written to it will be discarded."
                ),
            );
        }
    }
    IN_HOOK.set(false);
}

/// Wraps `KERNEL32!SetFilePointer` via the import table, catching failures that
/// never traverse the `Seek` detour.
#[cfg(target_arch = "x86_64")]
unsafe extern "system" fn set_file_pointer_thunk(
    handle: *mut c_void,
    distance_low: i32,
    distance_high: *mut i32,
    move_method: u32,
) -> u32 {
    let original = ORIGINAL_SET_FILE_POINTER.load(Ordering::Relaxed);
    if original == 0 {
        return INVALID_SET_FILE_POINTER;
    }
    let original: SetFilePointerFn = std::mem::transmute(original);

    let result = original(handle, distance_low, distance_high, move_method);

    // Read before anything else can clobber this thread's last error.
    let last_error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    let failed = result == INVALID_SET_FILE_POINTER && (distance_high.is_null() || last_error != 0);
    if failed && !IN_HOOK.get() {
        report_failure(handle as usize, distance_low, move_method, last_error);
    }

    result
}

#[cfg(target_arch = "x86_64")]
fn find_file_writer_seek_offset() -> Option<usize> {
    let (best, count) = find_signature_offset(&FILE_WRITER_SEEK_SIG, FILE_WRITER_SEEK_OFFSET, 0);
    debug_log!("FArchiveFileWriterWindows::Seek signature matches: {count}");
    best
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_package_size_limit::init start");

    #[cfg(target_arch = "x86_64")]
    {
        let udk = get_udk_ptr();

        let offset = find_file_writer_seek_offset()
            .context("Failed to find FArchiveFileWriterWindows::Seek signature")?;
        debug_log!("FArchiveFileWriterWindows::Seek hook offset: 0x{offset:X}");

        unsafe {
            FileWriterSeekHook
                .initialize(std::mem::transmute(udk.add(offset)), file_writer_seek_hook)
                .context("Failed to setup FArchiveFileWriterWindows::Seek hook")?;
            FileWriterSeekHook.enable()?;

            let slot = udk.add(SET_FILE_POINTER_IAT_RVA) as *mut usize;
            let original = std::ptr::read_volatile(slot);
            if original == 0 {
                debug_log!("SetFilePointer IAT slot is NULL; limit reporting will be partial");
            } else {
                ORIGINAL_SET_FILE_POINTER.store(original, Ordering::Relaxed);

                let _guard = region::protect_with_handle(
                    slot as *const u8,
                    std::mem::size_of::<usize>(),
                    region::Protection::READ_WRITE,
                )
                .context("Failed to make the SetFilePointer IAT slot writable")?;

                std::ptr::write_volatile(slot, set_file_pointer_thunk as *const () as usize);
                debug_log!("SetFilePointer IAT slot 0x{:X} hooked", slot as usize);
            }
        }
    }

    debug_log!("udk_package_size_limit::init done");

    Ok(())
}
