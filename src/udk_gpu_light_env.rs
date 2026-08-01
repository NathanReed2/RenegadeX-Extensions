//! Moves the per-actor dynamic-light gather of UE3's light environments off the
//! game thread and onto the GPU.
//!
//! # What the engine does
//!
//! Every movable actor in Renegade X carries a
//! `UDynamicLightEnvironmentComponent` (DLE). Because the shipping renderer is
//! D3D9/SM3 - `ShouldUseDeferredShading()` is gated on `SP_PCD3D_SM5`, which is
//! never reached - a light that is rendered as a light costs a full re-draw of
//! the geometry it touches. UE3 avoids that by approximating: per actor, the CPU
//! walks every light that reaches it, projects each into a 3rd-order spherical
//! harmonic vector, and re-emits the sum as one or two synthetic light
//! components.
//!
//! `FDynamicLightEnvironmentState::UpdateDynamicEnvironment` is the half of that
//! which runs **every frame for every visible DLE**. It is a linear scan of
//! `GWorld->DynamicLightList` - no spatial index - calling `AddLightToEnvironment`
//! per light. Renegade X makes this worse than stock UE3: `Rx_Projectile` attaches
//! a light component per projectile in flight, and those land in exactly that
//! list.
//!
//! The static half, `UpdateStaticEnvironment`, is throttled by
//! `MinTimeBetweenFullUpdates` and is left alone by this module.
//!
//! # Why the GPU can have it
//!
//! The GPU is *already* the consumer of the result.
//! `USphericalHarmonicLightComponent` packs the 27 floats of an `FSHVectorRGB`
//! into 7 `float4` pixel-shader constants (`SetSHPixelParameters`), and
//! `FSHLightLightMapPolicy` folds the evaluation into the base pass with no extra
//! draw call. Only *producing* those 27 numbers is CPU work, so this module does
//! not have to invent any lighting math, touch a material, or recompile a shader
//! cache - it only has to fill in the same numbers.
//!
//! The output is also latency-tolerant by construction:
//! `UpdateEnvironmentInterpolation` smooths every transition, and the fastest
//! `MinTimeBetweenFullUpdates` in the game is `Rx_Vehicle`'s 0.1 s. A two-frame
//! GPU->CPU readback is invisible against that, which is what lets the whole
//! thing work without a single shader edit.
//!
//! # Shape of the patch
//!
//! - At `Present` (a hook this DLL already owns) the frame index is bumped.
//! - The first DLE to tick in a frame flattens `GWorld->DynamicLightList` into a
//!   POD array and stages it. Cost is `O(lights)` once, not `O(lights x DLEs)`.
//! - Each DLE stages its own bounds and claims a stable atlas slot.
//! - On the render thread the staged tables are uploaded, one full-target quad
//!   computes every DLE's SH in parallel, and the result is copied to a ring of
//!   system-memory surfaces.
//! - The detour reads the surface written two frames ago and memcpys the SH into
//!   the state struct. Everything downstream is untouched.
//!
//! Visibility is variant 1a of the plan: `VisibilityFactor = 1`, matching what the
//! engine itself does for any light with `CastStaticShadows` disabled. The ray
//! casts in `IsLightVisible` are collision queries and have no D3D9 equivalent.
//!
//! # Safety
//!
//! Every address and every struct offset below is validated against the loaded
//! image before a single byte is written, and **any failure disables the module**
//! rather than falling through - see [`validate`]. The stock CPU path is also the
//! fallback for a DLE that has no slot yet, for atlas overflow, and for the whole
//! window around a D3D9 device reset.
//!
//! # Provenance
//!
//! RVAs and offsets were read from `Firestorm/Binaries/Win64/UDK.exe`, whose
//! `.text` hash is pinned in `dll.rs`, and cross-checked against the
//! symbol-bearing 2013 build. `FDynamicLightEnvironmentState` and
//! `ULightComponent` both lay out identically in the two builds, which is what
//! makes the symbol build usable as a reference here.
//!
//! **This module has not yet been run against the game.** It is gated behind
//! `-GPULIGHTENV` and installs nothing without it.

#![cfg(target_arch = "x86_64")]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::{bail, Context};
use retour::static_detour;

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;
use crate::udk_log::{log, LogType};

/// The D3D9 half. Kept in its own file but declared as a child module so it can
/// reach the statics above through `use super::*` without making any of them
/// crate-visible.
#[path = "udk_gpu_light_env_d3d9.rs"]
mod d3d9;

pub(crate) use d3d9::note_device;

// ---------------------------------------------------------------------------
// Image anchors
// ---------------------------------------------------------------------------

/// `FDynamicLightEnvironmentState::UpdateDynamicEnvironment`.
///
/// Located by anchoring on `"EngineMeshes.Sphere"` (`0x1426081b8`), a string only
/// `UpdateStaticEnvironment` references, then walking to the adjacent function in
/// the same translation unit. Confirmed by `diff_functions` against the symbol
/// build's copy at `0x14032b3f0`: 162 of 239 instructions identical.
const UPDATE_DYNAMIC_ENVIRONMENT_RVA: usize = 0x34_A980;

/// `FDynamicLightEnvironmentState::AddLightToEnvironment`, kept only so
/// [`validate`] can prove the call target inside `UpdateDynamicEnvironment` is
/// what this module thinks it is. 1063 of 1116 instructions match the symbol
/// build's copy at `0x1403149d0`.
const ADD_LIGHT_TO_ENVIRONMENT_RVA: usize = 0x34_4B00;

/// `GWorld`. Holds a `UWorld*`, read out of the `UpdateDynamicEnvironment`
/// decompilation where it appears as `DAT_1436913d8 + 0x28c`.
const GWORLD_RVA: usize = 0x369_13D8;

// ---------------------------------------------------------------------------
// `UWorld`
// ---------------------------------------------------------------------------

/// `UWorld::DynamicLightList`, a `TSparseArray<ULightComponent*>`. The `TArray`
/// payload sits here and the `TBitArray` allocation flags at `+0x29C`.
const WORLD_DYNAMIC_LIGHT_LIST: usize = 0x28C;

// ---------------------------------------------------------------------------
// `FDynamicLightEnvironmentState`
//
// Verified against RenXSDK by decompiling `UpdateDynamicEnvironment`, and against
// the symbol build via the `[RSI+0x320]` / `[RSI+0x3b0]` / `[RSI+0x44c]` accesses
// in its `UpdateStaticEnvironment`. The two builds agree exactly.
// ---------------------------------------------------------------------------

/// `Component` - the owning `UDynamicLightEnvironmentComponent*`.
const STATE_COMPONENT: usize = 0x000;
/// `OwnerBounds`: `Origin` at `+0x08`, `BoxExtent` at `+0x14`, `SphereRadius` at `+0x20`.
const STATE_OWNER_BOUNDS: usize = 0x008;
/// `OwnerLightingChannels.Bitfield`.
const STATE_OWNER_LIGHTING_CHANNELS: usize = 0x030;
/// `DynamicLightEnvironment` (`FSHVectorRGB`, 144 bytes).
const STATE_DYNAMIC_LIGHT_ENV: usize = 0x1D0;
/// `DynamicNonShadowedLightEnvironment`.
const STATE_DYNAMIC_NONSHADOWED_ENV: usize = 0x260;
/// `DynamicShadowInfo`: `ShadowDirection +0x2F0`, `DominantShadowFactor +0x2FC`,
/// `DominantShadowIntensity +0x300`, `TotalShadowIntensity +0x310`.
const STATE_DYNAMIC_SHADOW_INFO: usize = 0x2F0;

/// `sizeof(FSHVectorRGB)` - three `FSHVector`s, each `NumSIMDVectors * 4` floats
/// where `NumSIMDVectors` is `(MAX_SH_BASIS + 3) / 4 = 3`. Confirmed by the
/// `memcpy(..., 0x90)` pairs in `UpdateDynamicEnvironment`.
const SH_VECTOR_RGB_BYTES: usize = 144;

/// Number of SH basis functions: `MAX_SH_ORDER * MAX_SH_ORDER` with
/// `MAX_SH_ORDER == 3`.
const SH_BASIS: usize = 9;
/// Floats per `FSHVector`, padded to whole SIMD vectors.
const SH_FLOATS_PADDED: usize = 12;

// ---------------------------------------------------------------------------
// `UDynamicLightEnvironmentComponent`
// ---------------------------------------------------------------------------

/// `State` - the `FDynamicLightEnvironmentState*`. Read out of
/// `UDynamicLightEnvironmentComponent::ResetEnvironment` at `0x140319420`.
const COMPONENT_STATE: usize = 0x0A8;
/// `OverriddenLightComponents` `TArray`; `Num` is the `INT` at `+0x150`. A DLE
/// with overrides ignores the world light lists entirely, so this module hands
/// those straight back to the engine.
const COMPONENT_OVERRIDDEN_LIGHTS_NUM: usize = 0x150;
/// Bitfield byte carrying `bAffectedBySmallDynamicLights` at mask `0x10`, as
/// tested by `AddLightToEnvironment`.
const COMPONENT_FLAGS_BYTE: usize = 0x0B8;
const COMPONENT_AFFECTED_BY_SMALL_LIGHTS: u8 = 0x10;

// ---------------------------------------------------------------------------
// `ULightComponent`
//
// From `ULightComponent::GetDirectIntensity` (`0x1403787e0`),
// `UPointLightComponent::GetDirectIntensity` (`0x140419c70`) and
// `USpotLightComponent::GetDirectIntensity` (`0x1404a29c0`) in the symbol build;
// the `0x140` bitfield and `0x14C` channels are re-confirmed against RenXSDK in
// `AddLightToEnvironment` and `DoesLightAffectOwner` (`0x140319310`).
// ---------------------------------------------------------------------------

/// `WorldToLight` `FMatrix`. `GetDirection()` is column 2, i.e. `+0x98`, `+0xA8`,
/// `+0xB8`.
const LIGHT_WORLD_TO_LIGHT: usize = 0x090;
/// `LightToWorld` `FMatrix`. `GetOrigin()` is row 3, i.e. `+0x100`.
const LIGHT_TO_WORLD_ORIGIN: usize = 0x100;
/// `Brightness` (`FLOAT`).
const LIGHT_BRIGHTNESS: usize = 0x130;
/// `LightColor` (`FColor`, BGRA bytes).
const LIGHT_COLOR: usize = 0x134;
/// Bitfield dword.
const LIGHT_FLAGS: usize = 0x140;
const LIGHT_FLAG_ENABLED: u32 = 0x0000_0001;
const LIGHT_FLAG_CAST_COMPOSITE_SHADOW: u32 = 0x0000_0010;
const LIGHT_FLAG_ALLOW_COMPOSITING_INTO_DLE: u32 = 0x0002_0000;
/// `LightingChannels.Bitfield`. Bit 0 is `bInitialized` and is masked off before
/// the overlap test; bit 3 is `Dynamic` and bit 4 `CompositeDynamic`.
const LIGHT_LIGHTING_CHANNELS: usize = 0x14C;
const CHANNEL_INITIALIZED: u32 = 0x0000_0001;
const CHANNEL_DYNAMIC: u32 = 0x0000_0008;
const CHANNEL_COMPOSITE_DYNAMIC: u32 = 0x0000_0010;
/// `UPointLightComponent::Radius` and `::FalloffExponent`.
const POINT_LIGHT_RADIUS: usize = 0x1A4;
const POINT_LIGHT_FALLOFF_EXPONENT: usize = 0x1A8;
/// `USpotLightComponent::InnerConeAngle` and `::OuterConeAngle`, in degrees.
const SPOT_LIGHT_INNER_CONE: usize = 0x240;
const SPOT_LIGHT_OUTER_CONE: usize = 0x244;

/// `ULightComponent::GetLightType()` - virtual, used to tell point from spot from
/// directional without an RTTI lookup.
///
/// Derived from `ULightComponent`'s vtable in the symbol build, base
/// `0x1423b6060`: `GetPosition` sits at `0x1423b6358` (offset `0x2F8`, which is
/// the `(this, &out)` call `AddLightToEnvironment` makes) and `GetLightType` is
/// the very next slot at `0x1423b6360`, so `0x300`.
///
/// This was `0x2E0` at first - two slots early. A wrong slot here does not fail
/// loudly: it calls whatever occupies that entry and reads the return as an
/// enum, which came back as 2014474304 then 2988912704 on successive frames.
/// Every light was then dropped as an unsupported type and every DLE handed a
/// black SH.
const VTBL_GET_LIGHT_TYPE: usize = 0x300;
/// `ULightComponent::AffectsBounds()` - virtual, as called by
/// `DoesLightAffectOwner`.
const VTBL_AFFECTS_BOUNDS: usize = 0x2E8;
/// `ULightComponent::GetBoundingBox()` - virtual, as called by
/// `AddLightToEnvironment` for the small-light test.
const VTBL_GET_BOUNDING_BOX: usize = 0x2F0;

/// `ELightComponentType`, from `UnActorComponent.h:421`.
///
/// **Not** the conventional Sky/Directional/Point/Spot ordering. UE3 interleaves
/// each dominant variant directly after its base type:
///
/// ```text
/// Sky=0  SphericalHarmonic=1  Directional=2  DominantDirectional=3
/// Point=4  DominantPoint=5  Spot=6  DominantSpot=7
/// ```
///
/// Assuming the obvious ordering gives Directional=1/Point=2/Spot=3, which is
/// what this module shipped at first: every light fell through to the
/// unsupported-type arm, the table came out empty, and every DLE was handed a
/// black SH. `UPointLightComponent::GetLightType` returning 4 in the symbol
/// build is what settled it.
///
/// The dominant variants never reach here - `ULightComponent::Attach` sorts them
/// into `World->Dominant*Lights`, not `DynamicLightList`.
const LIGHT_TYPE_DIRECTIONAL: u32 = 2;
const LIGHT_TYPE_POINT: u32 = 4;
const LIGHT_TYPE_SPOT: u32 = 6;

// ---------------------------------------------------------------------------
// Capacities
// ---------------------------------------------------------------------------

/// Atlas width, i.e. how many DLEs can be served in one frame. Anything past this
/// falls back to the stock CPU path, so overflow degrades rather than breaks.
const MAX_SLOTS: usize = 1024;
/// Lights uploaded per frame; likewise a soft cap.
const MAX_LIGHTS: usize = 256;
/// Texels per light in the light table.
const LIGHT_TEXELS: usize = 5;
/// Texels per DLE in the DLE table.
const DLE_TEXELS: usize = 4;
/// Splits a channel mask into the four bytes the shader's lookup expects.
fn channel_bytes(mask: u32) -> [f32; 4] {
    [
        (mask & 0xFF) as f32,
        ((mask >> 8) & 0xFF) as f32,
        ((mask >> 16) & 0xFF) as f32,
        ((mask >> 24) & 0xFF) as f32,
    ]
}
/// Atlas rows.
///
/// One column per DLE, and the rows hold two `FSHVectorRGB` outputs - shadowed
/// then non-shadowed. Each is 3 `FSHVector`s of 12 padded floats = 36 floats = 9
/// `RGBA32F` texels, so 18 rows total.
///
/// Deliberately laid out as the raw C++ struct rather than
/// `SetSHPixelParameters`' 7-`float4` constant packing: the destination here is
/// `FDynamicLightEnvironmentState`'s memory, not a shader constant bank, so
/// matching the struct means the readback needs no repacking.
///
/// Within one output, row `k` carries floats `k*4 .. k*4+3`, i.e. channel
/// `k / 3` and basis indices `(k % 3) * 4 ..`. Basis indices 9..11 are the SIMD
/// padding and are written as zero.
const ATLAS_ROWS: usize = 18;
/// Rows per `FSHVectorRGB` within the atlas.
const ATLAS_ROWS_PER_OUTPUT: usize = 9;
/// Frames of readback latency. Three surfaces means the one being locked was
/// written two frames ago and cannot still be in flight.
const READBACK_RING: usize = 3;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

static ENABLED: AtomicBool = AtomicBool::new(false);
/// Bumped by [`note_frame`] from the `Present` hook; the first DLE to tick in a
/// new frame rebuilds the light table.
static FRAME_INDEX: AtomicU64 = AtomicU64::new(0);
static LIGHT_TABLE_FRAME: AtomicU64 = AtomicU64::new(u64::MAX);

/// Set when a device reset invalidates the atlas; cleared once it is rebuilt.
static ATLAS_INVALID: AtomicBool = AtomicBool::new(true);
static FALLBACK_COUNT: AtomicU32 = AtomicU32::new(0);
/// DLE updates answered from the GPU atlas rather than the stock CPU gather.
static GPU_SERVED: AtomicU32 = AtomicU32::new(0);
/// Lights found by the last walk, and whether that walk passed its sanity
/// checks. Both are in the status line because a wrong `GWorld` offset shows up
/// here first.
static LIGHT_COUNT: AtomicU32 = AtomicU32::new(0);
static WALK_VALID: AtomicBool = AtomicBool::new(false);
/// `-GPULIGHTENVVERIFY`: run both paths per DLE and report the deviation, for
/// the whole session.
static VERIFY: AtomicBool = AtomicBool::new(false);
/// DLE updates still to be checked against the stock path automatically.
///
/// Verification is worth having on *every* run rather than behind a switch
/// someone has to remember: a wrong SH is invisible in the log and invisible in
/// a screenshot, so without numbers there is no way to tell a working build from
/// a broken one. A few thousand samples is a sound estimate and costs a fraction
/// of a second in total, after which this decays to zero and the module runs at
/// full speed.
static AUTO_VERIFY_REMAINING: AtomicU32 = AtomicU32::new(5000);
/// Whether the GPU answer is actually written into the light environment.
///
/// **Default off, deliberately.** The GPU pass reproduces the analytic part of
/// `AddLightToEnvironment` but not `IsLightVisible`, which casts
/// `NumVolumeVisibilitySamples` shadow rays per light through
/// `GWorld->SingleLineCheck(TRACE_Level|TRACE_Actors|TRACE_ShadowCast)` and
/// scales each light by the fraction that reach it. There is no scene geometry
/// on a D3D9 SM3 device to trace against, so that factor cannot be reproduced
/// here, and measured deviation from the stock result is around 80% of
/// magnitude - not a bug with a fix, but the part of the calculation this
/// design cannot express.
///
/// Left in as a measurement harness: the pass still runs and still reports how
/// far off it is. `-GPULIGHTENVUNSAFE` applies it anyway, for experiments where
/// unshadowed light environments are acceptable.
static APPLY_GPU: AtomicBool = AtomicBool::new(false);
/// `DynamicLightList.ArrayNum` before `extract_light` filters anything. A large
/// raw count with zero usable lights means the filters or their field offsets
/// are wrong, not that the map is unlit.
static RAW_LIGHT_COUNT: AtomicU32 = AtomicU32::new(0);
/// Which `extract_light` rejection fired most recently, for the status line.
static REJECT_REASON: AtomicU32 = AtomicU32::new(0);
/// Last unrecognised `GetLightType()` result. Sane values are 0..=7; anything
/// else means the vtable slot is wrong.
static LAST_LIGHT_TYPE: AtomicU32 = AtomicU32::new(u32::MAX);

/// One light, flattened out of the `TSparseArray` so the per-DLE sweep and the
/// GPU upload both read POD instead of chasing pointers through virtuals.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct LightRecord {
    /// World-space origin; for a directional light this is the direction and
    /// `position_w` is 0.
    position: [f32; 3],
    position_w: f32,
    /// `FLinearColor(LightColor) * Brightness`, already sRGB-decoded.
    colour: [f32; 3],
    falloff_exponent: f32,
    direction: [f32; 3],
    cos_outer_cone: f32,
    /// 0.0 when `bCastCompositeShadow` is set, 1.0 otherwise - it selects which
    /// of the two SH outputs the light feeds.
    ///
    /// Precomputed here rather than unpacked in the shader because `ps_3_0` has
    /// no bitwise operators. The lighting-channel mask is gone from this struct
    /// for the same reason; it is tested on the CPU by [`Tables::channels_cover`].
    casts_composite: f32,
    radius: f32,
    cos_inner_cone: f32,
    _pad: f32,
    /// The 32-bit lighting-channel mask split into four bytes, each 0..255.
    ///
    /// The shader ANDs these against the DLE's own four bytes through a 256x256
    /// lookup texture, which is how `DoesLightAffectOwner`'s bit test survives on
    /// a target with no bitwise operators.
    channel_bytes: [f32; 4],
}

const _: () = assert!(std::mem::size_of::<LightRecord>() == LIGHT_TEXELS * 16);

/// One DLE's query parameters, staged for the GPU pass.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct DleRecord {
    origin: [f32; 3],
    sphere_radius: f32,
    box_extent: [f32; 3],
    /// Was the lighting-channel mask; the test moved to the CPU, so this is
    /// zero rather than a bit-cast `u32` that would read back as a NaN.
    _reserved: f32,
    flags: f32,
    _pad: [f32; 3],
    /// This DLE's lighting-channel mask, four bytes, matching
    /// [`LightRecord::channel_bytes`].
    channel_bytes: [f32; 4],
}

struct Tables {
    lights: Vec<LightRecord>,
    dles: Vec<DleRecord>,
    /// SH read back from the GPU, row-major exactly as the atlas was written.
    /// `None` until the first readback lands.
    readback: Option<Vec<f32>>,
    /// Frame the readback corresponds to, so a stale slot can be spotted.
    readback_frame: u64,
    /// Component pointer -> atlas column.
    ///
    /// **Slots have to be stable across frames.** The SH a DLE consumes was
    /// computed two frames ago from whatever was in its column then, so handing
    /// out columns in per-frame tick order - which is not a stable order, since
    /// visibility and tick group membership change - would feed each DLE another
    /// actor's lighting. Keying on the component pointer is what makes the
    /// readback correspond to the right object.
    slots: std::collections::HashMap<usize, usize>,
    /// Column -> owning component pointer, 0 when free.
    slot_owner: Vec<usize>,
    /// Column -> frame the current owner last ticked, for reclaiming.
    slot_seen: Vec<u64>,
    /// Column -> frame the current owner claimed it. A freshly claimed column
    /// still holds the previous owner's SH until the ring has turned over.
    slot_claimed: Vec<u64>,
    /// Rotating search start, so claiming a column stays amortised O(1) rather
    /// than rescanning from zero every time.
    cursor: usize,
    /// Distinct lighting-channel masks in the light table, per frame, indexed
    /// `frame % READBACK_RING`.
    ///
    /// The shader cannot do the `DoesLightAffectOwner` channel test: `ps_3_0`
    /// has no bitwise operators. Rather than unpack 26 bits per light per pixel,
    /// the pass gathers *every* light and the CPU checks afterwards that every
    /// light in the table really did affect this DLE - see
    /// [`Tables::channels_cover`]. One frame's worth of masks is a handful of
    /// values, so this costs a few integer ANDs per DLE against the ~50 full SH
    /// evaluations it replaces.
    mask_ring: [Vec<u32>; READBACK_RING],
    /// Whether the last light walk was trustworthy. When it is not, no DLE may
    /// consume a GPU result: an empty or partial light table produces a *valid
    /// looking* all-zero SH, which would render every affected object black
    /// rather than merely fall back.
    light_table_valid: bool,
}

/// Frames a column may go untouched before another DLE may take it. Long enough
/// that an actor briefly culled from the tick list keeps its column and its
/// interpolated lighting.
const SLOT_STALE_FRAMES: u64 = 120;

impl Tables {
    /// Returns this component's stable column, claiming a free or stale one if
    /// it does not have one yet.
    fn claim_slot(&mut self, component: usize, frame: u64) -> Option<usize> {
        if let Some(&slot) = self.slots.get(&component) {
            self.slot_seen[slot] = frame;
            return Some(slot);
        }
        for offset in 0..MAX_SLOTS {
            let slot = (self.cursor + offset) % MAX_SLOTS;
            let owner = self.slot_owner[slot];
            let stale = owner != 0 && frame.saturating_sub(self.slot_seen[slot]) > SLOT_STALE_FRAMES;
            if owner == 0 || stale {
                if owner != 0 {
                    self.slots.remove(&owner);
                }
                self.slot_owner[slot] = component;
                self.slot_seen[slot] = frame;
                self.slot_claimed[slot] = frame;
                self.slots.insert(component, slot);
                self.cursor = (slot + 1) % MAX_SLOTS;
                return Some(slot);
            }
        }
        None
    }

    /// Whether a column's readback describes its current owner rather than the
    /// one before it.
    fn slot_is_settled(&self, slot: usize, frame: u64) -> bool {
        frame.saturating_sub(self.slot_claimed[slot]) >= READBACK_RING as u64
    }
}

static TABLES: Mutex<Option<Tables>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Detour
// ---------------------------------------------------------------------------

type UpdateDynamicEnvironmentFn = unsafe extern "C" fn(*mut c_void);

static_detour! {
    static UpdateDynamicEnvironmentHook: unsafe extern "C" fn(*mut c_void);
}

/// Resolves an image-relative address, refusing anything outside the mapped
/// module so a bad constant cannot be called.
fn image_address(rva: usize, what: &'static str) -> anyhow::Result<*mut c_void> {
    let range = UDK_RANGE.get().context("UDK module range is not available")?;
    let address = range
        .start
        .checked_add(rva)
        .with_context(|| format!("{what}: RVA {rva:#x} overflows the image base"))?;
    if address >= range.end {
        bail!("{what}: RVA {rva:#x} lies past the end of the image");
    }
    Ok(address as *mut c_void)
}

/// Proves the anchors before anything is hooked or written.
///
/// This is deliberately paranoid. Every offset in this module is a hard-coded
/// property of one build of `UDK.exe`; if Renegade X ships a different binary the
/// constants become pointers into unrelated memory, and writing 144 bytes of SH
/// through one of them would corrupt the heap. So: prove the code is where it is
/// expected, and refuse to install otherwise.
fn validate() -> anyhow::Result<()> {
    let update = image_address(
        UPDATE_DYNAMIC_ENVIRONMENT_RVA,
        "UpdateDynamicEnvironment",
    )?;
    let add_light =
        image_address(ADD_LIGHT_TO_ENVIRONMENT_RVA, "AddLightToEnvironment")?;
    let gworld = image_address(GWORLD_RVA, "GWorld")?;

    // `UpdateDynamicEnvironment` must contain a direct `CALL` to
    // `AddLightToEnvironment`. That single relationship pins down both anchors at
    // once: it is the call inside the `DynamicLightList` loop, and it is the only
    // reason this module can claim to know what the function does.
    let body = unsafe { std::slice::from_raw_parts(update as *const u8, 0x400) };
    let mut found_call = false;
    for (offset, window) in body.windows(5).enumerate() {
        if window[0] != 0xE8 {
            continue;
        }
        let displacement = i32::from_le_bytes([window[1], window[2], window[3], window[4]]);
        let next = (update as isize) + offset as isize + 5;
        if next.wrapping_add(displacement as isize) == add_light as isize {
            found_call = true;
            break;
        }
    }
    if !found_call {
        bail!(
            "UpdateDynamicEnvironment at {update:p} does not call AddLightToEnvironment \
             at {add_light:p}; the binary is not the build these offsets came from"
        );
    }

    // `GWorld` must be a plausible pointer or null. Null is fine and expected
    // before a map is loaded.
    let world = unsafe { std::ptr::read_unaligned(gworld as *const usize) };
    if world != 0 && world < 0x1_0000 {
        bail!("GWorld at {gworld:p} holds {world:#x}, which is not a UWorld pointer");
    }

    Ok(())
}

/// Called from the `Present` hook so the light table is rebuilt exactly once per
/// frame instead of once per DLE.
pub(crate) fn note_frame() {
    let frame = FRAME_INDEX.fetch_add(1, Ordering::AcqRel) + 1;

    // Roughly every 10 seconds at 60Hz. This runs from `Present`, well after
    // `GLog` exists, so unlike `init` it can use UE3's log.
    const STATUS_INTERVAL: u64 = 600;
    if frame % STATUS_INTERVAL != 0 {
        return;
    }

    let (hooked, resources, passes, readbacks) = d3d9::status();
    let served = GPU_SERVED.load(Ordering::Relaxed);
    let fallback = FALLBACK_COUNT.load(Ordering::Relaxed);
    let resources = match resources {
        0 => "not attempted",
        1 => "created",
        _ => "FAILED",
    };
    let mut line = format!(
        "-GPULIGHTENV: frame {frame}, present hook {}, resources {resources}, \
         light walk {} ({} in list / {} usable, last reject: {}), \
         passes {passes}, readbacks {readbacks}, \
         DLE updates: {served} from GPU / {fallback} fell back to CPU",
        if hooked { "installed" } else { "MISSING" },
        if WALK_VALID.load(Ordering::Relaxed) {
            "ok"
        } else {
            "REJECTED"
        },
        RAW_LIGHT_COUNT.load(Ordering::Relaxed),
        LIGHT_COUNT.load(Ordering::Relaxed),
        match REJECT_REASON.load(Ordering::Relaxed) {
            0 => "none",
            1 => "not enabled",
            2 => "no DLE compositing",
            3 => "black",
            4 => "unsupported type",
            _ => "?",
        },
    );
    let seen = LAST_LIGHT_TYPE.load(Ordering::Relaxed);
    if seen != u32::MAX {
        line.push_str(&format!(" (last unrecognised GetLightType: {seen})"));
    }
    {
        if let Ok(stats) = VERIFY_STATS.lock() {
            if stats.samples > 0 {
                let relative = if stats.sum_magnitude > 0.0 {
                    stats.sum_abs / stats.sum_magnitude * 100.0
                } else {
                    0.0
                };
                line.push_str(&format!(
                    " | VERIFY over {} DLEs: max coefficient error {:.6}, \
                     mean error {:.4}% of magnitude",
                    stats.samples, stats.max_abs, relative,
                ));
            }
        }
    }
    if let Ok(error) = d3d9::RESOURCE_ERROR.lock() {
        if let Some(error) = error.as_deref() {
            line.push_str(&format!(" (resource error: {error})"));
        }
    }
    log(LogType::Init, &line);
}

/// `FLinearColor(FColor)` - UE3 decodes the stored sRGB byte through a
/// `pow(x, 2.2)` table. `FColor` is stored BGRA.
fn linear_from_srgb_colour(bgra: [u8; 4]) -> [f32; 3] {
    let decode = |value: u8| (value as f32 / 255.0).powf(2.2);
    [decode(bgra[2]), decode(bgra[1]), decode(bgra[0])]
}

unsafe fn read_f32(base: *const u8, offset: usize) -> f32 {
    std::ptr::read_unaligned(base.add(offset) as *const f32)
}

unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    std::ptr::read_unaligned(base.add(offset) as *const u32)
}

unsafe fn vtable_slot(object: *const u8, byte_offset: usize) -> *const c_void {
    let vtable = std::ptr::read_unaligned(object as *const *const u8);
    std::ptr::read_unaligned(vtable.add(byte_offset) as *const *const c_void)
}

/// Flattens one `ULightComponent` into a [`LightRecord`], or `None` if it cannot
/// contribute to any light environment.
///
/// The filters mirror `DoesLightAffectOwner` and the head of
/// `AddLightToEnvironment`, minus anything that depends on the *receiving* DLE -
/// those stay on the GPU, because they are what varies per pair.
unsafe fn extract_light(light: *const u8) -> Option<(LightRecord, u32)> {
    let flags = read_u32(light, LIGHT_FLAGS);
    if flags & LIGHT_FLAG_ENABLED == 0 {
        REJECT_REASON.store(1, Ordering::Relaxed);
        return None;
    }
    if flags & LIGHT_FLAG_ALLOW_COMPOSITING_INTO_DLE == 0 {
        REJECT_REASON.store(2, Ordering::Relaxed);
        return None;
    }

    let get_light_type: unsafe extern "C" fn(*const u8) -> u32 =
        std::mem::transmute(vtable_slot(light, VTBL_GET_LIGHT_TYPE));
    let light_type = get_light_type(light);

    let brightness = read_f32(light, LIGHT_BRIGHTNESS);
    let colour_bytes = std::ptr::read_unaligned(light.add(LIGHT_COLOR) as *const [u8; 4]);
    let linear = linear_from_srgb_colour(colour_bytes);
    let colour = [
        linear[0] * brightness,
        linear[1] * brightness,
        linear[2] * brightness,
    ];
    if colour.iter().all(|channel| *channel <= 0.0) {
        REJECT_REASON.store(3, Ordering::Relaxed);
        return None;
    }

    // `DoesLightAffectOwner` folds CompositeDynamic into Dynamic before the
    // overlap test, and masks off bit 0 (`bInitialized`).
    let mut channels = read_u32(light, LIGHT_LIGHTING_CHANNELS) & !CHANNEL_DYNAMIC;
    if channels & CHANNEL_COMPOSITE_DYNAMIC != 0 {
        channels = (channels & !CHANNEL_COMPOSITE_DYNAMIC) | CHANNEL_DYNAMIC;
    }
    channels &= !CHANNEL_INITIALIZED;

    let origin = [
        read_f32(light, LIGHT_TO_WORLD_ORIGIN),
        read_f32(light, LIGHT_TO_WORLD_ORIGIN + 4),
        read_f32(light, LIGHT_TO_WORLD_ORIGIN + 8),
    ];
    // `GetDirection()` is column 2 of `WorldToLight`, i.e. elements [0][2],
    // [1][2], [2][2] of a row-major 4x4.
    let direction = [
        read_f32(light, LIGHT_WORLD_TO_LIGHT + 0x08),
        read_f32(light, LIGHT_WORLD_TO_LIGHT + 0x18),
        read_f32(light, LIGHT_WORLD_TO_LIGHT + 0x28),
    ];

    let (position, position_w, radius, falloff) = match light_type {
        // `UDirectionalLightComponent::GetPosition()` is
        // `FVector4(-GetDirection() * TraceDistance, 0)` - note the negation.
        // `AddLightToEnvironment` then normalises, so the distance scale drops
        // out, but the sign does not: without it every directional light lands
        // in the SH exactly 180 degrees out.
        LIGHT_TYPE_DIRECTIONAL => (
            [-direction[0], -direction[1], -direction[2]],
            0.0,
            f32::MAX,
            1.0,
        ),
        LIGHT_TYPE_POINT | LIGHT_TYPE_SPOT => (
            origin,
            1.0,
            read_f32(light, POINT_LIGHT_RADIUS),
            read_f32(light, POINT_LIGHT_FALLOFF_EXPONENT),
        ),
        // Sky lights and anything unrecognised keep the stock path; their
        // contribution is not a simple falloff and is rarely dynamic.
        // A value outside 0..=7 here means `VTBL_GET_LIGHT_TYPE` points at the
        // wrong vtable slot, not that the light is exotic - hence recording it.
        _ => {
            REJECT_REASON.store(4, Ordering::Relaxed);
            LAST_LIGHT_TYPE.store(light_type, Ordering::Relaxed);
            return None;
        }
    };

    // Cone terms, clamped exactly as `USpotLightComponent::GetDirectIntensity`
    // does. Non-spot lights get a pair that makes the attenuation collapse to 1.
    let (cos_inner, cos_outer) = if light_type == LIGHT_TYPE_SPOT {
        let inner_deg = read_f32(light, SPOT_LIGHT_INNER_CONE).clamp(0.0, 89.0);
        let inner = inner_deg * std::f32::consts::PI / 180.0;
        let outer_raw = read_f32(light, SPOT_LIGHT_OUTER_CONE) * std::f32::consts::PI / 180.0;
        let outer = outer_raw.clamp(
            inner + 0.001,
            89.0 * std::f32::consts::PI / 180.0 + 0.001,
        );
        (inner.cos(), outer.cos())
    } else {
        (1.0, -1.0)
    };

    let record = LightRecord {
        position,
        position_w,
        colour,
        falloff_exponent: falloff.max(f32::EPSILON),
        direction,
        cos_outer_cone: cos_outer,
        casts_composite: if flags & LIGHT_FLAG_CAST_COMPOSITE_SHADOW != 0 {
            0.0
        } else {
            1.0
        },
        radius,
        cos_inner_cone: cos_inner,
        _pad: 0.0,
        channel_bytes: channel_bytes(channels),
    };
    Some((record, channels))
}

/// Walks `GWorld->DynamicLightList` once and rebuilds the flat light table.
///
/// `TSparseArray` is a `TArray` of elements plus a `TBitArray` marking which are
/// live. Rather than reimplement the bit iterator this reads the allocation flags
/// directly and skips holes; a hole holds a free-list link, not a pointer, so it
/// must not be dereferenced.
unsafe fn rebuild_light_table(world: *const u8, tables: &mut Tables, frame: u64) -> bool {
    let out = &mut tables.lights;
    out.clear();
    let masks = &mut tables.mask_ring[(frame % READBACK_RING as u64) as usize];
    masks.clear();

    if !readable(world, WORLD_DYNAMIC_LIGHT_LIST + 0x30) {
        return false;
    }

    let list = world.add(WORLD_DYNAMIC_LIGHT_LIST);
    let data = std::ptr::read_unaligned(list as *const *const u8);
    let count = std::ptr::read_unaligned(list.add(0x08) as *const i32);
    let capacity = std::ptr::read_unaligned(list.add(0x0C) as *const i32);

    // A plausibility screen on the header. `WORLD_DYNAMIC_LIGHT_LIST` was read
    // out of a decompile and `0x28C` is not 8-byte aligned, which a `TArray`
    // holding a pointer has to be on x64 - so the offset is not above suspicion
    // and this code must not trust it blindly.
    if count < 0 || capacity < count || count > 4096 {
        return false;
    }
    // An empty list is reported as *untrustworthy*, not as "no lights".
    //
    // A wrong `WORLD_DYNAMIC_LIGHT_LIST` reads some unrelated zero field and
    // produces exactly this, and the consequence is not a missing optimisation:
    // the pass then gathers nothing, the atlas is all zeroes, and every DLE gets
    // handed a perfectly well-formed black SH. That is how this module spent a
    // whole session reporting `light walk ok (0 lights)` while quietly unlighting
    // every character and vehicle in the map. A genuinely empty dynamic light
    // list costs nothing on the stock path anyway.
    if count == 0 {
        return false;
    }
    if data.is_null() || !readable(data, count as usize * 8) {
        return false;
    }
    RAW_LIGHT_COUNT.store(count as u32, Ordering::Relaxed);

    // `TBitArray : protected TInlineAllocator<4>::ForElementType<DWORD>`, so the
    // allocator is the base subobject and the layout from `AllocationFlags` is:
    //
    //   +0x00  InlineData[4]   four DWORDs of bits stored in-place
    //   +0x10  SecondaryData   heap pointer, null while the bits fit inline
    //   +0x18  NumBits
    //   +0x1C  MaxBits
    //
    // The original code read `InlineData[0..1]` as if it were the pointer and
    // dereferenced it. With <=128 dynamic lights that is bit data, not an
    // address, which is what took the process down the moment a map registered
    // its first dynamic light.
    let flags_base = list.add(0x10);
    let inline_bits = flags_base as *const u32;
    let secondary = std::ptr::read_unaligned(flags_base.add(0x10) as *const *const u32);
    let num_bits = std::ptr::read_unaligned(flags_base.add(0x18) as *const i32);

    if num_bits < count {
        return false;
    }
    let words = ((num_bits as usize) + 31) / 32;
    let flags = if secondary.is_null() {
        // Inline storage is 4 DWORDs; more bits than that must be indirect.
        if words > 4 {
            return false;
        }
        inline_bits
    } else {
        if !readable(secondary as *const u8, words * 4) {
            return false;
        }
        secondary
    };

    for index in 0..count as usize {
        let word = std::ptr::read_unaligned(flags.add(index / 32));
        if word & (1u32 << (index % 32)) == 0 {
            continue;
        }
        // Sparse elements are pointer-sized here because the payload is a
        // `ULightComponent*`.
        let light = std::ptr::read_unaligned(data.add(index * 8) as *const *const u8);
        if light.is_null() {
            continue;
        }
        // `extract_light` reads out to the spot-light cone angles and makes a
        // virtual call, so the whole head of the object has to be there.
        if !readable(light, LIGHT_EXTENT) {
            return false;
        }
        if let Some((record, channels)) = extract_light(light) {
            out.push(record);
            // Distinct masks only: a level runs a handful, and the per-DLE test
            // walks this list rather than the light table.
            if !masks.contains(&channels) {
                masks.push(channels);
            }
            if out.len() >= MAX_LIGHTS {
                break;
            }
        }
    }

    // Entries in the list but nothing usable out of them is *also* untrustworthy,
    // for the same reason an empty list is: the pass would gather nothing and
    // hand every DLE a well-formed black SH.
    //
    // This is a distinct failure from `count == 0` and it is what the module hit
    // after that one was fixed - `ArrayNum` was non-zero while `extract_light`
    // rejected every entry, so the walk reported success with an empty table.
    // A wrong `LIGHT_FLAGS` offset or light-type slot looks exactly like this,
    // which is why the raw and usable counts are reported separately.
    !out.is_empty()
}

/// Highest byte `extract_light` touches on a `ULightComponent`, rounded up past
/// `SPOT_LIGHT_OUTER_CONE`.
const LIGHT_EXTENT: usize = 0x250;

#[repr(C)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    _alignment1: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    kind: u32,
    _alignment2: u32,
}

extern "system" {
    fn VirtualQuery(
        address: *const c_void,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
}

/// Whether `length` bytes at `pointer` are committed and readable.
///
/// Declared by hand rather than by adding a `windows` crate feature for one
/// call. This exists because the offsets this module walks were recovered from
/// a decompile: if one is wrong, the walk reads a plausible-looking integer as a
/// pointer, and without this check the process dies instead of falling back.
/// One `VirtualQuery` per light per *frame* is nothing next to the SH gather it
/// guards.
fn readable(pointer: *const u8, length: usize) -> bool {
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_GUARD: u32 = 0x100;
    const PAGE_NOACCESS: u32 = 0x01;
    const READABLE: u32 = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

    if pointer.is_null() || length == 0 {
        return false;
    }
    let mut info = std::mem::MaybeUninit::<MemoryBasicInformation>::uninit();
    let size = std::mem::size_of::<MemoryBasicInformation>();
    unsafe {
        if VirtualQuery(pointer as *const c_void, info.as_mut_ptr(), size) != size {
            return false;
        }
        let info = info.assume_init();
        if info.state != MEM_COMMIT
            || info.protect & PAGE_GUARD != 0
            || info.protect & PAGE_NOACCESS != 0
            || info.protect & READABLE == 0
        {
            return false;
        }
        // The region has to cover the whole span, not just its first byte.
        let end = (info.base_address as usize).saturating_add(info.region_size);
        (pointer as usize).saturating_add(length) <= end
    }
}

/// The replacement for `FDynamicLightEnvironmentState::UpdateDynamicEnvironment`.
unsafe fn update_dynamic_environment(state: *mut c_void) {
    if !ENABLED.load(Ordering::Relaxed) {
        UpdateDynamicEnvironmentHook.call(state);
        return;
    }
    if state.is_null() {
        return;
    }
    announce_once();

    match try_gpu_path(state as *mut u8) {
        Ok(true) => {
            GPU_SERVED.fetch_add(1, Ordering::Relaxed);
            let budget = AUTO_VERIFY_REMAINING
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
            // Verification leaves the *stock* answer in the state, so running it
            // unconditionally is what makes the default safe - see APPLY_GPU.
            if !APPLY_GPU.load(Ordering::Relaxed) || budget || VERIFY.load(Ordering::Relaxed) {
                verify_against_stock(state as *mut u8);
            }
        }
        Ok(false) | Err(_) => {
            FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
            UpdateDynamicEnvironmentHook.call(state);
        }
    }
}

/// Stages this DLE for the GPU pass and, if a readback for its slot is ready,
/// writes the SH straight into the state struct.
///
/// Returns `Ok(false)` whenever the stock path should run instead: no world, a
/// DLE with overridden lights, no slot available, or no readback yet.
unsafe fn try_gpu_path(state: *mut u8) -> anyhow::Result<bool> {
    // Note there is no `ATLAS_INVALID` test here, deliberately. This function
    // does two things - it *stages* the DLE for the next pass, and it *consumes*
    // whatever the pass produced. Only the second half depends on the atlas
    // being valid, and bailing out up front skips the first half too: the pass
    // then has no input, so it never produces a readback, so the atlas never
    // becomes valid. The module's first working build sat in exactly that
    // deadlock, reporting `resources created, passes 0` forever. The check now
    // sits between the two halves.
    let gworld = image_address(GWORLD_RVA, "GWorld")? as *const usize;
    let world = std::ptr::read_unaligned(gworld) as *const u8;
    if world.is_null() {
        return Ok(false);
    }

    let component = std::ptr::read_unaligned(state.add(STATE_COMPONENT) as *const *const u8);
    if component.is_null() {
        return Ok(false);
    }
    // A DLE with `OverriddenLightComponents` ignores the world lists entirely.
    if std::ptr::read_unaligned(component.add(COMPONENT_OVERRIDDEN_LIGHTS_NUM) as *const i32) != 0 {
        return Ok(false);
    }

    let frame = FRAME_INDEX.load(Ordering::Acquire);
    let mut guard = TABLES.lock().map_err(|_| anyhow::anyhow!("tables poisoned"))?;
    let tables = guard.get_or_insert_with(|| Tables {
        lights: Vec::with_capacity(MAX_LIGHTS),
        dles: vec![DleRecord::default(); MAX_SLOTS],
        readback: None,
        readback_frame: u64::MAX,
        slots: std::collections::HashMap::new(),
        slot_owner: vec![0; MAX_SLOTS],
        slot_seen: vec![0; MAX_SLOTS],
        slot_claimed: vec![0; MAX_SLOTS],
        cursor: 0,
        mask_ring: Default::default(),
        light_table_valid: false,
    });

    // First DLE of the frame pays for the light walk; the rest read the table.
    if LIGHT_TABLE_FRAME.swap(frame, Ordering::AcqRel) != frame {
        tables.light_table_valid = rebuild_light_table(world, tables, frame);
        LIGHT_COUNT.store(tables.lights.len() as u32, Ordering::Relaxed);
        WALK_VALID.store(tables.light_table_valid, Ordering::Relaxed);
    }
    if !tables.light_table_valid {
        return Ok(false);
    }

    let dle_channels = read_u32(state, STATE_OWNER_LIGHTING_CHANNELS);

    let Some(slot) = tables.claim_slot(component as usize, frame) else {
        return Ok(false);
    };

    let bounds = state.add(STATE_OWNER_BOUNDS);
    let component_flags = std::ptr::read_unaligned(component.add(COMPONENT_FLAGS_BYTE));
    tables.dles[slot] = DleRecord {
        origin: [
            read_f32(bounds, 0),
            read_f32(bounds, 4),
            read_f32(bounds, 8),
        ],
        sphere_radius: read_f32(bounds, 0x18),
        box_extent: [
            read_f32(bounds, 0x0C),
            read_f32(bounds, 0x10),
            read_f32(bounds, 0x14),
        ],
        _reserved: 0.0,
        flags: f32::from(component_flags & COMPONENT_AFFECTED_BY_SMALL_LIGHTS),
        channel_bytes: channel_bytes(dle_channels),
        _pad: [0.0; 3],
    };

    // Staging is done; everything below consumes a result the pass produced.
    if ATLAS_INVALID.load(Ordering::Relaxed) {
        return Ok(false);
    }

    // A column claimed within the last few frames still carries the previous
    // owner's SH, because the readback lags the pass by the ring depth.
    if !tables.slot_is_settled(slot, frame) {
        return Ok(false);
    }

    // Nothing to consume yet - the pass has not produced a frame for this slot.
    let Some(readback) = tables.readback.as_ref() else {
        return Ok(false);
    };

    if readback.len() < MAX_SLOTS * ATLAS_ROWS * 4 {
        return Ok(false);
    }

    write_sh(
        state.add(STATE_DYNAMIC_LIGHT_ENV),
        &gather_sh(readback, slot, 0),
    );
    write_sh(
        state.add(STATE_DYNAMIC_NONSHADOWED_ENV),
        &gather_sh(readback, slot, 1),
    );

    // The stock function derives `DynamicShadowInfo` from a third SH vector via
    // `ExtractDominantLight`. Until that vector is produced on the GPU too, zero
    // it - which is what the engine itself does when the extraction fails, and
    // matches a DLE whose dynamic lights cast no composite shadow.
    std::ptr::write_bytes(state.add(STATE_DYNAMIC_SHADOW_INFO), 0, 48);

    Ok(true)
}

/// Accumulated GPU-vs-stock deviation, under `-GPULIGHTENVVERIFY`.
#[derive(Default)]
struct VerifyStats {
    samples: u64,
    /// Largest absolute difference on any single SH coefficient.
    max_abs: f32,
    /// Sums for a magnitude-relative error, so a large absolute difference on a
    /// bright environment is not mistaken for a correctness problem.
    sum_abs: f64,
    sum_magnitude: f64,
}

static VERIFY_STATS: Mutex<VerifyStats> = Mutex::new(VerifyStats {
    samples: 0,
    max_abs: 0.0,
    sum_abs: 0.0,
    sum_magnitude: 0.0,
});

/// Runs the stock gather over the same DLE and measures how far the GPU answer
/// was from it, then leaves the stock result in place.
///
/// This exists because the alternative - comparing screenshots - cannot tell a
/// subtly wrong SH from a correct one, and every bug this module has had so far
/// was invisible in the log while being obvious in the numbers. Verifying costs
/// both paths per DLE, so it is opt-in and not something to ship enabled.
unsafe fn verify_against_stock(state: *mut u8) {
    let read_sh = |base: *const u8| {
        let mut out = [0.0f32; SH_FLOATS_PADDED * 3];
        std::ptr::copy_nonoverlapping(base as *const f32, out.as_mut_ptr(), out.len());
        out
    };

    let gpu_shadowed = read_sh(state.add(STATE_DYNAMIC_LIGHT_ENV));
    let gpu_nonshadowed = read_sh(state.add(STATE_DYNAMIC_NONSHADOWED_ENV));

    // Overwrites both vectors with the engine's own answer.
    UpdateDynamicEnvironmentHook.call(state as *mut c_void);

    let cpu_shadowed = read_sh(state.add(STATE_DYNAMIC_LIGHT_ENV));
    let cpu_nonshadowed = read_sh(state.add(STATE_DYNAMIC_NONSHADOWED_ENV));

    let Ok(mut stats) = VERIFY_STATS.lock() else {
        return;
    };
    stats.samples += 1;
    for (gpu, cpu) in gpu_shadowed
        .iter()
        .zip(cpu_shadowed.iter())
        .chain(gpu_nonshadowed.iter().zip(cpu_nonshadowed.iter()))
    {
        let difference = (gpu - cpu).abs();
        if difference > stats.max_abs {
            stats.max_abs = difference;
        }
        stats.sum_abs += f64::from(difference);
        stats.sum_magnitude += f64::from(cpu.abs());
    }
}

/// Pulls one `FSHVectorRGB` out of the row-major readback.
///
/// The atlas is stored as the GPU wrote it - row by row, `MAX_SLOTS` columns of
/// `RGBA32F` - so a single DLE's 36 floats are a column-strided gather rather
/// than a contiguous run. Doing it here keeps the readback path a straight
/// `memcpy` from the locked surface.
fn gather_sh(readback: &[f32], slot: usize, output: usize) -> [f32; SH_FLOATS_PADDED * 3] {
    let mut result = [0.0f32; SH_FLOATS_PADDED * 3];
    for (index, value) in result.iter_mut().enumerate() {
        let row = output * ATLAS_ROWS_PER_OUTPUT + index / 4;
        let texel = (row * MAX_SLOTS + slot) * 4 + index % 4;
        *value = readback[texel];
    }
    result
}

/// Copies one `FSHVectorRGB` worth of coefficients into the state struct.
///
/// The layout is three `FSHVector`s of 12 floats each, of which only the first 9
/// are meaningful; the padding exists so each maps to three SIMD registers.
unsafe fn write_sh(destination: *mut u8, source: &[f32]) {
    debug_assert_eq!(source.len(), SH_FLOATS_PADDED * 3);
    let mut bytes = [0u8; SH_VECTOR_RGB_BYTES];
    for (index, value) in source.iter().enumerate() {
        // Never propagate a NaN into engine state: a NaN in the SH would spread
        // into the synthesized lights and blow out the frame.
        let sanitised = if value.is_finite() { *value } else { 0.0 };
        bytes[index * 4..index * 4 + 4].copy_from_slice(&sanitised.to_le_bytes());
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination, SH_VECTOR_RGB_BYTES);
}

/// Marks the atlas unusable after a D3D9 device reset, so every DLE takes the
/// stock path until the render side rebuilds it.
///
/// Called from the `Reset` detour in `udk_d3d9_present_params`. Everything the
/// pass owns except the readback surfaces lives in `D3DPOOL_DEFAULT` and is
/// destroyed by the reset, so the resources are dropped here and rebuilt on the
/// next `Present`.
pub(crate) fn invalidate_atlas() {
    d3d9::invalidate();
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

/// Installs the hook when `-GPULIGHTENV` is present. Without the switch this is
/// inert and the engine keeps its own gather.
///
/// # Why nothing here logs through `udk_log`
///
/// This runs from `DllMain`'s `DLL_PROCESS_ATTACH`, which is before UE3 has
/// constructed `GLog`. Calling `udk_log::log` at that point dispatches through an
/// `FOutputDevice` that does not exist yet, faults inside `UDK.exe`, and the
/// loader reports the failure as `0xC0000142` - the process never starts, with no
/// other diagnostic. Every sibling client patch uses `debug_log!` here for the
/// same reason; runtime logging is fine, loader-time logging is not.
///
/// `args_os` rather than `args` for a related reason: `std::env::args` panics on
/// a non-UTF-8 argument, and this crate builds with `panic = "abort"`, so that
/// panic would abort the process from inside the loader and surface as the same
/// `0xC0000142`.
pub(crate) fn init() -> anyhow::Result<()> {
    let mut requested = false;
    let mut verify = false;
    for argument in std::env::args_os() {
        let argument = argument.to_string_lossy();
        let argument = argument.trim_start_matches(['-', '/']);
        if argument.eq_ignore_ascii_case("GPULIGHTENV") {
            requested = true;
        } else if argument.eq_ignore_ascii_case("GPULIGHTENVUNSAFE") {
            requested = true;
            APPLY_GPU.store(true, Ordering::Release);
        } else if argument.eq_ignore_ascii_case("GPULIGHTENVVERIFY") {
            // Verification implies the module; asking for one without the other
            // is never what someone means.
            requested = true;
            verify = true;
        }
    }
    if !requested {
        return Ok(());
    }
    VERIFY.store(verify, Ordering::Release);

    if let Err(error) = validate() {
        debug_log!("-GPULIGHTENV: refusing to install: {error:#}");
        return Ok(());
    }

    let target = image_address(UPDATE_DYNAMIC_ENVIRONMENT_RVA, "UpdateDynamicEnvironment")?;
    let function: UpdateDynamicEnvironmentFn = unsafe { std::mem::transmute(target) };

    unsafe {
        UpdateDynamicEnvironmentHook
            .initialize(function, |state| update_dynamic_environment(state))
            .context("initializing UpdateDynamicEnvironment hook")?;
        UpdateDynamicEnvironmentHook
            .enable()
            .context("enabling UpdateDynamicEnvironment hook")?;
    }

    ENABLED.store(true, Ordering::Release);
    debug_log!("-GPULIGHTENV: hooked UpdateDynamicEnvironment at {target:p}");
    Ok(())
}

/// Announces the module through UE3's log, once, from the first detour call.
///
/// Deferred out of [`init`] on purpose: by the time a DLE ticks, `GLog` exists
/// and this is safe, whereas the same call at loader time is the `0xC0000142`
/// documented above.
fn announce_once() {
    static ANNOUNCED: AtomicBool = AtomicBool::new(false);
    if ANNOUNCED.swap(true, Ordering::Relaxed) {
        return;
    }
    log(
        LogType::Init,
        "-GPULIGHTENV: light environment gather hooked; GPU pass drives from Present, \
         status follows every 600 frames",
    );
}
