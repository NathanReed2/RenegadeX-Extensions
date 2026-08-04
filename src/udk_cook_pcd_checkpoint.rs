//! Checkpoints the multithreaded cook's persistent cooker data periodically, so
//! that a cook which dies partway through resumes from the packages it already
//! finished instead of recooking all of them.
//!
//! # What goes wrong
//!
//! Whether a package is recooked is decided in
//! `UCookPackagesCommandlet::CookPackages` (`UnrealEd/Src/UnContentCookers.cpp`):
//!
//! ```c
//! INT CookedVersion = PersistentCookerData->GetFileCookedVersion(*DstFilename);
//! if (CookedVersion != GPackageFileCookedContentVersion) { bCookedVersionIsOutDated = TRUE; }
//! ...
//! if( ( DstFileNewer == TRUE ) && ( bCookedVersionIsOutDated == FALSE ) && ... )
//! {
//!     warnf(NAME_Log, TEXT("UpToDate %s"), *SrcFilename);
//!     continue;
//! }
//! ```
//!
//! `GetFileCookedVersion` returns 0 for a filename it has never heard of, so a
//! package is only skipped if the persistent cooker data (PCD,
//! `<CookedDir>\GlobalPersistentCookerData.upk`) remembers cooking it. The
//! cooked `.upk` sitting on disk is not by itself enough.
//!
//! A single-process cook writes that record after **every** package:
//!
//! ```c
//! if (!bIsMTChild && !bIsMTMaster)
//! {
//!     PersistentCookerData->SaveToDisk();
//! }
//! ```
//!
//! An MT master is excluded from that path, and writes its authoritative PCD in
//! exactly two places: once in `StartChildren`, *before* any work has happened -
//!
//! ```c
//! BulletProofPCDSave(PersistentCookerData,*(CookedDir * GetBulkDataContainerFilename()));
//! SaveLocalShaderCaches(); // children will load this, and maybe we did some work here.
//! ```
//!
//! - and once more at the end of a **successful** run. Nothing in between: the
//! per-child syncs in `CheckForTFCSync` write `P_GlobalPersistentCookerData.upk`
//! into the child's own directory, never the master's file.
//!
//! So any failure before the end - a crashed child, a full disk, Ctrl-C, a
//! reboot - rolls the incremental state back to where the run started, and the
//! next cook redoes every package that had already succeeded. The larger
//! `-Processes=N` is, the more work each failure throws away, which is the
//! opposite of what the flag is for.
//!
//! # The fix
//!
//! Two detours, and deliberately no hardcoded structure offsets.
//!
//! `StartChildren` already performs precisely the call this module wants to
//! repeat, so rather than reconstructing its three arguments from member offsets
//! (`PersistentCookerData` at `this+0x3E8`, `CookedDir` at `this+0x10C`), the
//! call is simply **captured and replayed**:
//!
//! 1. **`BulletProofPCDSave(this, Who, Where)`** - record `this`, `Who` and a
//!    copy of `Where` the first time it is called for the master's own PCD.
//!    The per-child saves that `SavePersistentCookerDataForChild` makes go to
//!    `<childdir>\P_GlobalPersistentCookerData.upk`, so filtering on an exact
//!    `GlobalPersistentCookerData.upk` basename keeps only the master's.
//!
//! 2. **`ChildIsIdle(this, ProcessIndex)`** - once it reports a child idle and
//!    the throttle has elapsed, replay the captured call. An idle child is a job
//!    boundary, which is the same kind of moment the engine already saves at.
//!
//! Replaying the engine's own call means the file, the format and the
//! `SetFilename`/`ResetLoaders`/existence-check handling inside
//! `BulletProofPCDSave` are whatever the engine does, not a reimplementation.
//!
//! # Why this is safe to do mid-run
//!
//! `BulletProofPCDSave` is already called at arbitrary points during a live MT
//! cook - `CheckForTFCSync` calls it per child sync - so writing the PCD while
//! children are working is stock behaviour, not something introduced here. The
//! replay is throttled (default 120s, `-PCDCheckpointSeconds=N`) because the
//! write is a full serialise of every bulk data record and is not free.
//!
//! `PersistentCookerData->SetMinimalSave(TRUE)` is only in effect inside
//! `SavePersistentCookerDataForChild`, which returns before any `ChildIsIdle`
//! call this module hooks, so a replayed checkpoint always writes a full record.
//!
//! # Scope
//!
//! Installs only in an MT **master**: a `cookpackages` process with
//! `-Processes=` and without `-MTCHILD`. A single-process cook already saves per
//! package and a child never owns the master PCD, so neither is touched. Failing
//! to find either signature stands the whole module down rather than installing
//! half of it.
//!
//! # Provenance
//!
//! RVAs read from `RenXSDK/UDK.exe`, whose `.text` hash is pinned in `dll.rs`.
//! `BulletProofPCDSave` (`0x11BC5D0`) is the call target at the end of the
//! `CookedDir * GetBulkDataContainerFilename()` sequence in `StartChildren`
//! (`0x11BC6E0`, the same function [`crate::udk_mt_cook_processes`] patches);
//! `ChildIsIdle` (`0x11A20C0`) was matched from its `Job[%d] %s done in %5.1fs`
//! literal and confirmed by its `ChildProcesses` access - a `0x68`-stride array
//! at `this+0x2AD4`, which is `sizeof(FChildProcess)` under UE3's `pack(4)`.

#![cfg(target_arch = "x86_64")]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use anyhow::Context;
use retour::static_detour;

use crate::dll::get_udk_ptr;
use crate::patch_utils::{debug_log, find_signature_offset};
use crate::udk_log;

/// `UCookPackagesCommandlet::BulletProofPCDSave` in the 12791 (UDK-2015-01)
/// x64 build.
const BULLET_PROOF_PCD_SAVE_OFFSET: usize = 0x0011_BC5D0;

/// `UCookPackagesCommandlet::ChildIsIdle` in the same build.
const CHILD_IS_IDLE_OFFSET: usize = 0x0011_A20C0;

/// Prologue of `BulletProofPCDSave`, up to the point the three arguments have
/// been shuffled into non-volatile registers:
///
/// ```asm
/// PUSH RDI
/// SUB  RSP, 0x40
/// MOV  qword [RSP+0x20], -2       ; EH state
/// MOV  qword [RSP+0x50], RBX
/// MOV  qword [RSP+0x58], RSI
/// MOV  RSI, R8                    ; Where
/// MOV  RBX, RDX                   ; Who
/// MOV  RDI, RCX                   ; this
/// ```
///
/// Contains no rip-relative displacement, so it is a plain byte match.
const BULLET_PROOF_PCD_SAVE_SIG: [u8; 34] = [
    0x40, 0x57, // PUSH RDI
    0x48, 0x83, 0xEC, 0x40, // SUB RSP,0x40
    0x48, 0xC7, 0x44, 0x24, 0x20, 0xFE, 0xFF, 0xFF, 0xFF, // MOV [RSP+0x20],-2
    0x48, 0x89, 0x5C, 0x24, 0x50, // MOV [RSP+0x50],RBX
    0x48, 0x89, 0x74, 0x24, 0x58, // MOV [RSP+0x58],RSI
    0x49, 0x8B, 0xF0, // MOV RSI,R8
    0x48, 0x8B, 0xDA, // MOV RBX,RDX
    0x48, 0x8B, 0xF9, // MOV RDI,RCX
];

/// Prologue of `ChildIsIdle`, through the `ChildProcesses.ArrayNum` bounds
/// check that makes it unmistakable:
///
/// ```asm
/// MOV    qword [RSP+0x20], RBX
/// PUSH   RBP ; PUSH RSI ; PUSH RDI
/// SUB    RSP, 0x40
/// MOVSXD RBX, EDX                  ; ProcessIndex
/// MOV    RDI, RCX                  ; this
/// TEST   EDX, EDX
/// JS     <range check failure>
/// MOV    EAX, dword [RCX+0x2ADC]   ; ChildProcesses.ArrayNum
/// ```
const CHILD_IS_IDLE_SIG: [u8; 28] = [
    0x48, 0x89, 0x5C, 0x24, 0x20, // MOV [RSP+0x20],RBX
    0x55, // PUSH RBP
    0x56, // PUSH RSI
    0x57, // PUSH RDI
    0x48, 0x83, 0xEC, 0x40, // SUB RSP,0x40
    0x48, 0x63, 0xDA, // MOVSXD RBX,EDX
    0x48, 0x8B, 0xF9, // MOV RDI,RCX
    0x85, 0xD2, // TEST EDX,EDX
    0x78, 0x12, // JS +0x12
    0x8B, 0x81, 0xDC, 0x2A, 0x00, 0x00, // MOV EAX,[RCX+0x2ADC]
];

/// The master's own PCD file. `SavePersistentCookerDataForChild` writes the same
/// name with a `P_` prefix into each child's directory, so an exact match on the
/// basename keeps only the master's.
const MASTER_PCD_FILENAME: &str = "globalpersistentcookerdata.upk";

/// How long to leave between checkpoints when `-PCDCheckpointSeconds=` is absent.
///
/// A complete 50-map PCServer cook measured 190s end to end, of which only 117s
/// was multithreaded - so a 120s interval never fired once across an entire cook.
/// The interval has to be well inside the shortest run worth protecting, not
/// merely inside the longest.
const DEFAULT_CHECKPOINT_SECONDS: u64 = 45;

/// Never checkpoint more often than this, whatever was asked for; the write is a
/// full serialise of every bulk data record.
const MINIMUM_CHECKPOINT_SECONDS: u64 = 15;

static_detour! {
    static BulletProofPcdSaveHook: extern "C" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, *const u16);
    static ChildIsIdleHook: extern "C" fn(*mut core::ffi::c_void, i32) -> i32;
}

/// The captured `BulletProofPCDSave` arguments for the master's own PCD.
struct CheckpointTarget {
    commandlet: usize,
    cooker_data: usize,
    /// NUL-terminated copy of `Where`, owned so it outlives the engine's temporary.
    path: Vec<u16>,
}

// The two pointers are engine-owned and only ever handed straight back to the
// engine on the same thread that gave them to us.
unsafe impl Send for CheckpointTarget {}
unsafe impl Sync for CheckpointTarget {}

static TARGET: OnceLock<CheckpointTarget> = OnceLock::new();

/// Start of the run, plus the elapsed seconds at the last checkpoint. `Instant`
/// is not const-constructible, so the base is stored in a `OnceLock` and the
/// mark as seconds since it.
static EPOCH: OnceLock<Instant> = OnceLock::new();
static LAST_CHECKPOINT_SECONDS: AtomicU64 = AtomicU64::new(0);

/// Guards against a checkpoint re-entering itself. `BulletProofPCDSave` spins in
/// `WaitToDeleteFile`, which calls `CheckForCrashedChildren`; that path does not
/// currently reach `ChildIsIdle`, but this module must not depend on it.
static IN_CHECKPOINT: AtomicBool = AtomicBool::new(false);

static CHECKPOINT_SECONDS: AtomicU64 = AtomicU64::new(DEFAULT_CHECKPOINT_SECONDS);
static CHECKPOINTS_WRITTEN: AtomicU64 = AtomicU64::new(0);

fn elapsed_seconds() -> u64 {
    EPOCH
        .get()
        .map(|epoch| epoch.elapsed().as_secs())
        .unwrap_or(0)
}

/// Reads a NUL-terminated UTF-16 string, bounded so a missing terminator cannot
/// run away.
unsafe fn read_wide(pointer: *const u16, limit: usize) -> Option<Vec<u16>> {
    if pointer.is_null() {
        return None;
    }

    let mut length = 0usize;
    while length < limit && pointer.add(length).read_unaligned() != 0 {
        length += 1;
    }

    if length == 0 || length == limit {
        return None;
    }

    let mut owned = Vec::with_capacity(length + 1);
    owned.extend_from_slice(std::slice::from_raw_parts(pointer, length));
    owned.push(0);
    Some(owned)
}

/// TRUE when `path` names the master's PCD rather than a child's `P_` copy.
fn is_master_pcd(path: &[u16]) -> bool {
    let text = String::from_utf16_lossy(&path[..path.len().saturating_sub(1)]);
    text.rsplit(['\\', '/'])
        .next()
        .map(|name| name.eq_ignore_ascii_case(MASTER_PCD_FILENAME))
        .unwrap_or(false)
}

/// Hook for `UCookPackagesCommandlet::BulletProofPCDSave`.
///
/// Only observes; every call is passed straight through. The first master save -
/// the one `StartChildren` makes before launching any child - is what supplies
/// the arguments replayed later.
fn bullet_proof_pcd_save_hook(
    commandlet: *mut core::ffi::c_void,
    cooker_data: *mut core::ffi::c_void,
    path: *const u16,
) {
    let is_master = unsafe { read_wide(path, 1024) }
        .map(|owned| {
            let master = is_master_pcd(&owned);
            if master && TARGET.get().is_none() && !commandlet.is_null() && !cooker_data.is_null() {
                let _ = TARGET.set(CheckpointTarget {
                    commandlet: commandlet as usize,
                    cooker_data: cooker_data as usize,
                    path: owned,
                });
            }
            master
        })
        .unwrap_or(false);

    BulletProofPcdSaveHook.call(commandlet, cooker_data, path);

    // Only a *master* save resets the throttle. The per-child saves that
    // SavePersistentCookerDataForChild makes go to P_GlobalPersistentCookerData.upk
    // inside the child's own directory and do nothing for the master's file, and
    // they fire on every TFC sync - counting those would starve the checkpoint
    // indefinitely on a texture-heavy cook, which is exactly when it matters most.
    if is_master {
        LAST_CHECKPOINT_SECONDS.store(elapsed_seconds(), Ordering::Relaxed);
    }
}

/// Writes the checkpoint by replaying the engine's captured call.
fn checkpoint(target: &CheckpointTarget) {
    let started = Instant::now();

    BulletProofPcdSaveHook.call(
        target.commandlet as *mut core::ffi::c_void,
        target.cooker_data as *mut core::ffi::c_void,
        target.path.as_ptr(),
    );

    let count = CHECKPOINTS_WRITTEN.fetch_add(1, Ordering::Relaxed) + 1;
    udk_log::log(
        udk_log::LogType::Init,
        &format!(
            "PCD checkpoint {count} written in {:.1}s. A multithreaded cook otherwise only \
             records what it has cooked at the very end, so anything that stops this run early \
             would have made the next one recook every package that already succeeded.",
            started.elapsed().as_secs_f32()
        ),
    );
}

/// Hook for `UCookPackagesCommandlet::ChildIsIdle`.
///
/// An idle child means no job is in flight for it, which is the same sort of
/// boundary the engine itself saves at.
fn child_is_idle_hook(commandlet: *mut core::ffi::c_void, process_index: i32) -> i32 {
    let idle = ChildIsIdleHook.call(commandlet, process_index);

    // Two detours cannot share one address, so the progress bar is driven from
    // here rather than hooking ChildIsIdle a second time. It is throttled
    // internally and never touches the cook's control flow.
    crate::udk_cook_progress::tick(commandlet);

    if idle == 0 {
        return idle;
    }

    let Some(target) = TARGET.get() else {
        return idle;
    };

    let now = elapsed_seconds();
    let interval = CHECKPOINT_SECONDS.load(Ordering::Relaxed);
    if now.saturating_sub(LAST_CHECKPOINT_SECONDS.load(Ordering::Relaxed)) < interval {
        return idle;
    }

    // Claim the checkpoint before doing it, so a re-entrant call cannot start a
    // second one on top of the first.
    if IN_CHECKPOINT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return idle;
    }

    checkpoint(target);

    LAST_CHECKPOINT_SECONDS.store(elapsed_seconds(), Ordering::Relaxed);
    IN_CHECKPOINT.store(false, Ordering::SeqCst);

    idle
}

/// Case-insensitive search for a `-Switch` or `-Switch=value` argument.
fn has_switch(name: &str) -> bool {
    std::env::args_os().any(|argument| {
        let text = argument.to_string_lossy();
        let trimmed = text.trim_start_matches(['-', '/']);
        trimmed.eq_ignore_ascii_case(name)
            || trimmed
                .split_once('=')
                .map(|(key, _)| key.eq_ignore_ascii_case(name))
                .unwrap_or(false)
    })
}

/// Value of `-Name=N`, if present and parseable.
fn switch_value(name: &str) -> Option<u64> {
    std::env::args_os().find_map(|argument| {
        let text = argument.to_string_lossy();
        let trimmed = text.trim_start_matches(['-', '/']);
        let (key, value) = trimmed.split_once('=')?;
        if !key.eq_ignore_ascii_case(name) {
            return None;
        }
        value.trim().parse::<u64>().ok()
    })
}

/// The master of a multithreaded cook: `cookpackages`, `-Processes=` given, and
/// not itself a child.
fn is_mt_cook_master() -> bool {
    let is_cook = std::env::args_os().any(|argument| {
        argument
            .to_string_lossy()
            .trim_start_matches(['-', '/'])
            .eq_ignore_ascii_case("cookpackages")
    });

    is_cook && has_switch("Processes") && !has_switch("MTCHILD")
}

pub fn init() -> anyhow::Result<()> {
    if !is_mt_cook_master() {
        return Ok(());
    }

    debug_log!("udk_cook_pcd_checkpoint::init start");

    let interval = switch_value("PCDCheckpointSeconds")
        .unwrap_or(DEFAULT_CHECKPOINT_SECONDS)
        .max(MINIMUM_CHECKPOINT_SECONDS);
    CHECKPOINT_SECONDS.store(interval, Ordering::Relaxed);

    let udk = get_udk_ptr();

    // Resolve both before installing either, so a binary that does not match
    // this module's expectations is left completely alone.
    let (save_offset, save_matches) =
        find_signature_offset(&BULLET_PROOF_PCD_SAVE_SIG, BULLET_PROOF_PCD_SAVE_OFFSET, 0);
    let (idle_offset, idle_matches) =
        find_signature_offset(&CHILD_IS_IDLE_SIG, CHILD_IS_IDLE_OFFSET, 0);
    debug_log!(
        "udk_cook_pcd_checkpoint: BulletProofPCDSave matches={save_matches}, \
         ChildIsIdle matches={idle_matches}"
    );

    let (Some(save_offset), Some(idle_offset)) = (save_offset, idle_offset) else {
        debug_log!(
            "udk_cook_pcd_checkpoint: refusing to install - BulletProofPCDSave \
             {save_offset:?}, ChildIsIdle {idle_offset:?}"
        );
        return Ok(());
    };

    let _ = EPOCH.set(Instant::now());

    unsafe {
        BulletProofPcdSaveHook
            .initialize(
                std::mem::transmute(udk.add(save_offset)),
                bullet_proof_pcd_save_hook,
            )
            .context("Failed to setup BulletProofPCDSave hook")?;
        BulletProofPcdSaveHook.enable()?;

        ChildIsIdleHook
            .initialize(std::mem::transmute(udk.add(idle_offset)), child_is_idle_hook)
            .context("Failed to setup ChildIsIdle hook")?;
        ChildIsIdleHook.enable()?;
    }

    debug_log!(
        "udk_cook_pcd_checkpoint: installed, checkpointing the master PCD every {interval}s"
    );

    Ok(())
}
