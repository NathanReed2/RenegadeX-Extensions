//! Restores Epic's own dedicated-server guard in
//! `USkeletalMeshComponent::InitClothSim` (udk.exe+0xA4AFD0,
//! `UnPhysComponent.cpp:3534`), which UDK ships compiled out.
//!
//! # The crash this fixes
//!
//! A dedicated server loading a map that spawns a cloth-enabled skeletal mesh
//! dies instantly during `ULevel::RouteBeginPlay`. Symbolicated from
//! `Launch-backup-2026.08.03-22.34.50.log`, launched as
//! `server cnc-field ... -seekfreeloadingserver -cooked`:
//!
//! ```text
//! GuardedMain -> FEngineLoop::PreInit -> UGameEngine::Init -> Browse
//!   -> LoadMap -> UWorld::BeginPlay -> ULevel::RouteBeginPlay
//!   -> AActor::PostBeginPlay -> UObject::ProcessEvent -> AActor::execSpawn
//!   -> UWorld::SpawnActor -> AActor::InitRBPhys
//!   -> USkeletalMeshComponent::InitComponentRBPhys
//!   -> USkeletalMeshComponent::InitClothSim
//!   -> USkeletalMesh::GetClothMeshForScale
//!   -> USkeletalMesh::ComputeClothSectionVertices + 0x113   <- access violation
//! ```
//!
//! That particular log faults during map load, but the trigger is incidental.
//! Everything above `InitComponentRBPhys` is just "an actor with a cloth
//! skeletal mesh was spawned" - `RouteBeginPlay` here, but equally an
//! UnrealScript `Spawn()` once the match is live and the game starts spawning
//! pawns and vehicles, which is where servers are more commonly seen to fall
//! over. The hook is placed on `InitClothSim` itself rather than on any caller
//! precisely so that every one of those paths is covered by one guard.
//!
//! The faulting instruction is the vertex fetch itself:
//!
//! ```asm
//! 14099e700  MOV  EDX, [RSI]          ; Chunk.GetRigidVertexBufferIndex()
//! 14099e702  ADD  EDX, EDI            ; + VertIdx
//! 14099e704  IMUL EDX, [R14 + 0xbc]   ; * VertexBufferGPUSkin.Stride
//! 14099e70c  ADD  RDX, [R14 + 0xb4]   ; + VertexBufferGPUSkin.Data
//! 14099e713  MOV  EAX, [RDX + 0x10]   ; <- Data is NULL
//! ```
//!
//! which is `FSkeletalMeshVertexBuffer::GetVertexPtr` verbatim
//! (`UnSkeletalMesh.h:2613`): `(FGPUSkinVertexBase*)(Data + VertexIndex *
//! Stride)`. Server-cooked content (`-seekfreeloadingserver`) has its skeletal
//! mesh vertex buffers stripped, so `Data` is NULL and cloth cooking walks off
//! a null base.
//!
//! # Why the engine does not already stop this
//!
//! It tries to. `InitClothSim` opens with exactly this:
//!
//! ```cpp
//! #if DEDICATED_SERVER
//!     //Vertex buffers have been removed, so this is not supported @TODO JM
//!     return;
//! #endif
//! ```
//!
//! Epic knew. But UDK ships a single game binary that is not built with
//! `DEDICATED_SERVER`, so the guard is preprocessed away and nothing remains -
//! confirmed by the shipping `InitClothSim` still being a full 0xD81-byte body
//! that reaches `GetClothMeshForScale`, rather than the near-empty stub the
//! guard would produce.
//!
//! Note this is *not* the "Accessed None 'SkeletalMesh'" script warning that
//! appears nearby in the same logs. `InitClothSim` returns harmlessly on a NULL
//! `SkeletalMesh`; reaching the fault requires a perfectly valid mesh whose
//! vertex *data* was stripped. The two are unrelated.
//!
//! # Scope
//!
//! Cloth is purely cosmetic and a dedicated server renders nothing, so skipping
//! it costs a server exactly nothing and saves the cloth cook besides. Clients
//! and listen servers are untouched: they load client content with vertex
//! buffers intact, and their cloth keeps working.
//!
//! Fixing it here rather than in content immunises every map at once. Stripping
//! cloth from one map's assets fixes that map and leaves the next one exposed.

use crate::dll::{get_udk_ptr, UDK_RANGE};
use crate::patch_utils::debug_log;
use crate::udk_log::{log, LogType};
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;
use retour::static_detour;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

/// `USkeletalMeshComponent::InitClothSim`, `UnPhysComponent.cpp:3534`.
#[cfg(target_arch = "x86_64")]
const INIT_CLOTH_SIM_OFFSET: usize = 0x00A4_AFD0;

/// The signature starts 5 bytes in, past the bytes a detour would overwrite.
#[cfg(target_arch = "x86_64")]
const INIT_CLOTH_SIM_SIG_SKEW: usize = 5;

/// Prologue of `InitClothSim`, captured from udk.exe+0xA4AFD5 onward. The
/// `LEA RBP,[RAX-0x208]` / `SUB RSP,0x2D0` pair makes this distinctive.
#[cfg(target_arch = "x86_64")]
const INIT_CLOTH_SIM_SIG: [u8; 40] = [
    0x50, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8,
    0xF8, 0xFD, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0xD0, 0x02, 0x00, 0x00, 0x48, 0xC7, 0x85, 0xF0, 0x00,
    0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89,
];

static_detour! {
    /// `void USkeletalMeshComponent::InitClothSim(FRBPhysScene* Scene)`
    static InitClothSimHook: extern "C" fn(usize, usize);
}

/// Whether this process was launched as a dedicated server.
///
/// UDK decides this from the command line rather than a build flag, so this
/// mirrors that: UE3's `LaunchEngineLoop` treats a leading `server` token as
/// "not a client". `-seekfreeloadingserver` is accepted as well because that is
/// the flag which actually selects the vertex-buffer-stripped content, and it
/// is the condition that makes cloth unsafe in the first place.
///
/// Computed once - the answer cannot change while the process is alive, and
/// this sits on an engine path that runs for every spawned actor.
fn is_dedicated_server() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let mut first_positional = true;
        for argument in std::env::args_os().skip(1) {
            let argument = argument.to_string_lossy().to_ascii_lowercase();

            if argument.starts_with('-') {
                if argument == "-seekfreeloadingserver" {
                    return true;
                }
                continue;
            }

            // Only the *first* non-switch token selects the mode; a map or URL
            // that merely contains the word must not trip this.
            if first_positional {
                if argument == "server" {
                    return true;
                }
                first_positional = false;
            }
        }
        false
    })
}

/// Counts suppressed calls, so a run can be told apart from one where the hook
/// simply never fired. Without this, "no crash" is ambiguous: it could mean the
/// guard worked, or that no cloth mesh was ever spawned.
static SUPPRESSED: AtomicUsize = AtomicUsize::new(0);

/// Where the hook actually bound, reported on first use.
static HOOK_OFFSET: AtomicUsize = AtomicUsize::new(0);
static ANNOUNCED: AtomicBool = AtomicBool::new(false);

/// Stands in for the `#if DEDICATED_SERVER` early return.
fn init_cloth_sim_hook(this: usize, scene: usize) {
    // First call is the earliest point it is safe to touch the engine log.
    if !ANNOUNCED.swap(true, Ordering::Relaxed) {
        log(
            LogType::Init,
            &format!(
                "server cloth guard active at udk.exe+0x{:X} (dedicated server: {})",
                HOOK_OFFSET.load(Ordering::Relaxed),
                is_dedicated_server()
            ),
        );
    }

    if is_dedicated_server() {
        let n = SUPPRESSED.fetch_add(1, Ordering::Relaxed) + 1;
        // Log the first few and then powers of two, so a map full of cloth
        // meshes cannot flood the log.
        //
        // This goes through udk_log rather than debug_log! because the latter
        // is compiled to nothing in release (see patch_utils), which is exactly
        // the build that runs on a server - and without a line in the log,
        // "server did not crash" cannot be told apart from "hook never fired".
        if n <= 3 || n.is_power_of_two() {
            log(
                LogType::Init,
                &format!("InitClothSim suppressed on dedicated server (count: {n})"),
            );
        }
        return;
    }
    InitClothSimHook.call(this, scene)
}

/// How many `InitClothSim` calls have been suppressed this session.
#[allow(dead_code)]
pub fn suppressed_count() -> usize {
    SUPPRESSED.load(Ordering::Relaxed)
}

pub fn init() -> anyhow::Result<()> {
    let udk = get_udk_ptr();
    debug_log!("udk_server_cloth::init start");

    // Nothing to do on a client, but the hook is installed either way: it is a
    // single predictable branch, and installing unconditionally keeps the
    // enabled/disabled state from depending on argument parsing being right.
    debug_log!("dedicated server: {}", is_dedicated_server());

    if let Some(range) = UDK_RANGE.get() {
        debug_log!(
            "UDK range: start=0x{:X} end=0x{:X}",
            range.start,
            range.end
        );
    }

    #[cfg(target_arch = "x86_64")]
    let hook_offset = {
        let (best, count) = find_signature_offset(
            &INIT_CLOTH_SIM_SIG,
            INIT_CLOTH_SIM_OFFSET,
            INIT_CLOTH_SIM_SIG_SKEW,
        );
        debug_log!("InitClothSim signature matches: {count}");
        best.unwrap_or(INIT_CLOTH_SIM_OFFSET)
    };

    debug_log!("InitClothSim hook offset selected: 0x{hook_offset:X}");

    // NOTE: do not call udk_log::log() from here. init() runs from
    // post_udk_init(), which DllMain invokes on DLL_PROCESS_ATTACH - so this
    // executes under the Windows loader lock, before UDK has constructed the
    // global log object this would dereference. Doing so hangs the process
    // before it writes a single line, which is very hard to diagnose because
    // there is no log to look at. Install confirmation is deferred to the first
    // time the hook actually runs, which is safely after startup.
    HOOK_OFFSET.store(hook_offset, Ordering::Relaxed);

    unsafe {
        InitClothSimHook
            .initialize(
                std::mem::transmute(udk.add(hook_offset)),
                init_cloth_sim_hook,
            )
            .context("Failed to setup InitClothSim hook")?;

        InitClothSimHook.enable()?;
    }

    debug_log!("udk_server_cloth::init done");

    Ok(())
}
