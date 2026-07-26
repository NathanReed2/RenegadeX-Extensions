//! Drives exponential height fog's two-tone inscattering from the fog actor's rotation.
//!
//! `FSceneRenderer::InitFogConstants` picks the direction that blends
//! `LightInscatteringColor` into `OppositeLightColor` by scanning the scene's
//! light list for a `LightType_DominantDirectional` light:
//!
//! ```text
//! View.DominantDirectionalLightDirection =
//!     DominantDirectionalLight ? -DominantDirectionalLight->GetDirection() : FVector(0,0,1);
//! ```
//!
//! That scan comes up empty in two situations, and both end at the world-up
//! fallback, which collapses the sun-relative gradient into a vertical one:
//!
//!  * the level has no `DominantDirectionalLight` - a plain `DirectionalLight`
//!    is `LightType_Directional`, a different value, so it never matches; and
//!  * dynamic lighting is disabled, because `FScene::AddLight` skips a light
//!    whose lighting is entirely precomputed, and skips every light without a
//!    light environment when `GSystemSettings.bAllowDynamicLights` is FALSE.
//!    The light is then absent from the list whatever its type.
//!
//! This module detours `InitFogConstants`, lets it run, and replaces only that
//! world-up fallback with the fog actor's own rotation. A level that already
//! resolves a dominant directional light is left untouched.
//!
//! Rotating the fog actor is exactly equivalent to rotating the dominant light.
//! `ULightComponent::SetParentToWorld` builds `WorldToLight` as
//! `Rt * ParentToLight`, where `ParentToLight` is the self-inverse X<->Z swap
//! declared there and `Rt` is the transpose of the actor's rotation.
//! `GetDirection()` reads column 2 of that product, and under UE3's row-vector
//! convention `(Rt * P)[i][2]` collapses to `R[0][i]` - row 0 of the actor's
//! rotation, i.e. `Rotation.Vector()`. So the engine's `-GetDirection()` and
//! this module's `-Rotation.Vector()` are the same vector.
//!
//! RVAs and offsets were read in Ghidra from `RenXSDK/UDK.exe`, whose `.text`
//! hash is pinned in `dll.rs`. The object offsets are additionally proven at
//! runtime before anything is written - see [`fog_actor_rotation`].

#![cfg(target_arch = "x86_64")]

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{bail, Context};
use retour::static_detour;

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

/// Forces the fog actor's rotation to win even when the renderer did resolve a
/// dominant directional light. Without it the actor's rotation only replaces
/// the world-up fallback, which means a level that still has a working dominant
/// light shows no change - useful in production, useless for checking the hook.
const FORCE_OPTION: &str = "-FogActorRotation";

/// TRUE when [`FORCE_OPTION`] was passed.
static FORCE_ACTOR_ROTATION: AtomicBool = AtomicBool::new(false);

/// Last (pitch, yaw) that was applied, packed, so the log records changes
/// instead of one line per view per frame. Starts at a value no rotation
/// produces, because both halves are masked to 16 bits before packing.
static LAST_LOGGED_ROTATION: AtomicU64 = AtomicU64::new(u64::MAX);

/// `FSceneRenderer::InitFogConstants`.
const INIT_FOG_CONSTANTS_RVA: usize = 0x00AF_5E90;
const INIT_FOG_CONSTANTS_PROLOGUE: &[u8] = &[
    0x48, 0x8B, 0xC4, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0xA8, 0x48,
    0xFF, 0xFF, 0xFF, 0x48, 0x81, 0xEC, 0x90, 0x01,
];

/// `FSceneRenderer::Scene`.
const SCENE_RENDERER_SCENE: usize = 0x00;
/// `FSceneRenderer::Views`, a `TArray<FViewInfo>`.
const SCENE_RENDERER_VIEWS_DATA: usize = 0x68;
const SCENE_RENDERER_VIEWS_NUM: usize = 0x70;
/// `sizeof(FViewInfo)`.
const VIEW_STRIDE: usize = 0x12D0;

/// `FViewInfo::DominantDirectionalLightDirection`, three consecutive floats.
const VIEW_FOG_LIGHT_DIRECTION: usize = 0x1138;
/// The bitfield word holding `FViewInfo::bRenderExponentialFog` in bit 0.
const VIEW_FOG_FLAGS: usize = 0x1148;
const RENDER_EXPONENTIAL_FOG_BIT: u32 = 1;

/// `FScene::ExponentialFogs`, a `TArray<FExponentialHeightFogSceneInfo>`.
const SCENE_EXPONENTIAL_FOGS_DATA: usize = 0x4EC8;
const SCENE_EXPONENTIAL_FOGS_NUM: usize = 0x4ED0;
/// `FExponentialHeightFogSceneInfo::Component`, at the very start of the struct.
const FOG_COMPONENT: usize = 0x00;

/// `UActorComponent::Owner`.
const ACTOR_COMPONENT_OWNER: usize = 0x78;
/// `AActor::AllComponents`, a `TArray<UActorComponent*>`.
const ACTOR_ALL_COMPONENTS_DATA: usize = 0x70;
const ACTOR_ALL_COMPONENTS_NUM: usize = 0x78;
/// `AActor::Rotation`, an `FRotator` of three INTs (Pitch, Yaw, Roll).
const ACTOR_ROTATION: usize = 0x8C;

/// An actor with more components than this is treated as a bad read rather than
/// walked, so a wrong offset cannot turn into a long scan over arbitrary memory.
const MAX_PLAUSIBLE_COMPONENTS: i32 = 4096;

type InitFogConstants = extern "C" fn(*mut c_void);

static_detour! {
    static InitFogConstantsHook: extern "C" fn(*mut c_void);
}

fn image_contains(address: usize) -> bool {
    UDK_RANGE
        .get()
        .is_some_and(|range| range.contains(&address))
}

unsafe fn read_ptr(base: *mut c_void, offset: usize) -> *mut c_void {
    *((base as *const u8).add(offset) as *const *mut c_void)
}

unsafe fn read_i32(base: *mut c_void, offset: usize) -> i32 {
    *((base as *const u8).add(offset) as *const i32)
}

unsafe fn read_u32(base: *mut c_void, offset: usize) -> u32 {
    *((base as *const u8).add(offset) as *const u32)
}

/// The owning actor's `FRotator`, or `None` when the layout cannot be confirmed.
///
/// The offsets this walks were derived from a single decompiled function, so
/// they are checked rather than trusted: the owner's vtable has to point into
/// `UDK.exe`, and the component has to appear in the owner's `AllComponents`.
/// That second check can only pass when `Owner` and `AllComponents` are both
/// where this module thinks they are, so a build that moved either one bails
/// out here and leaves the engine's own result in place.
unsafe fn fog_actor_rotation(component: *mut c_void) -> Option<[i32; 3]> {
    if component.is_null() {
        return None;
    }

    let owner = read_ptr(component, ACTOR_COMPONENT_OWNER);
    if owner.is_null() {
        return None;
    }
    let owner_vtable = *(owner as *const usize);
    if !image_contains(owner_vtable) {
        debug_log!("[fog] owner vtable {owner_vtable:#X} is outside UDK.exe; leaving fog alone");
        return None;
    }

    let components = read_ptr(owner, ACTOR_ALL_COMPONENTS_DATA) as *const *mut c_void;
    let count = read_i32(owner, ACTOR_ALL_COMPONENTS_NUM);
    if components.is_null() || count <= 0 || count > MAX_PLAUSIBLE_COMPONENTS {
        debug_log!("[fog] implausible AllComponents (data={components:p} num={count})");
        return None;
    }
    if !(0..count).any(|index| *components.add(index as usize) == component) {
        debug_log!("[fog] fog component not in owner's AllComponents; offsets do not match");
        return None;
    }

    let rotation = (owner as *const u8).add(ACTOR_ROTATION) as *const i32;
    Some([rotation.read(), rotation.add(1).read(), rotation.add(2).read()])
}

/// `FRotator::Vector()`: the rotation's forward axis.
///
/// UE3 angles are 16-bit, 65536 to the turn. Roll does not affect the forward
/// axis, so it is ignored exactly as `FRotationMatrix::GetAxis(0)` does.
fn rotator_to_vector(rotation: [i32; 3]) -> [f32; 3] {
    const UNREAL_TO_RADIANS: f64 = std::f64::consts::TAU / 65536.0;

    let pitch = f64::from(rotation[0] & 0xFFFF) * UNREAL_TO_RADIANS;
    let yaw = f64::from(rotation[1] & 0xFFFF) * UNREAL_TO_RADIANS;
    let (sin_pitch, cos_pitch) = pitch.sin_cos();
    let (sin_yaw, cos_yaw) = yaw.sin_cos();

    [
        (cos_pitch * cos_yaw) as f32,
        (cos_pitch * sin_yaw) as f32,
        sin_pitch as f32,
    ]
}

/// TRUE when the engine wrote its `FVector(0,0,1)` fallback, i.e. when it found
/// no dominant directional light. The constants are stored verbatim, so an
/// exact comparison is the reliable test.
fn is_world_up(direction: [f32; 3]) -> bool {
    direction == [0.0, 0.0, 1.0]
}

unsafe fn override_fog_direction(scene_renderer: *mut c_void) {
    if scene_renderer.is_null() {
        return;
    }
    let scene = read_ptr(scene_renderer, SCENE_RENDERER_SCENE);
    if scene.is_null() {
        return;
    }

    // InitFogConstants only ever reads ExponentialFogs(0).
    if read_i32(scene, SCENE_EXPONENTIAL_FOGS_NUM) <= 0 {
        return;
    }
    let fog = read_ptr(scene, SCENE_EXPONENTIAL_FOGS_DATA);
    if fog.is_null() {
        return;
    }

    let Some(rotation) = fog_actor_rotation(read_ptr(fog, FOG_COMPONENT)) else {
        return;
    };
    let forward = rotator_to_vector(rotation);
    // The engine stores the direction *toward* the light, hence -GetDirection().
    let direction = [-forward[0], -forward[1], -forward[2]];

    let force = FORCE_ACTOR_ROTATION.load(Ordering::Relaxed);
    let packed = (u64::from(rotation[0] as u32 & 0xFFFF) << 16) | u64::from(rotation[1] as u32 & 0xFFFF);
    if LAST_LOGGED_ROTATION.swap(packed, Ordering::Relaxed) != packed {
        debug_log!(
            "[fog] actor rotation pitch={} yaw={} roll={} -> direction ({:.3},{:.3},{:.3}) force={force}",
            rotation[0],
            rotation[1],
            rotation[2],
            direction[0],
            direction[1],
            direction[2]
        );
    }

    let views = read_ptr(scene_renderer, SCENE_RENDERER_VIEWS_DATA);
    let view_count = read_i32(scene_renderer, SCENE_RENDERER_VIEWS_NUM);
    if views.is_null() || view_count <= 0 {
        return;
    }

    for index in 0..view_count {
        let view = (views as *mut u8).add(index as usize * VIEW_STRIDE) as *mut c_void;
        if read_u32(view, VIEW_FOG_FLAGS) & RENDER_EXPONENTIAL_FOG_BIT == 0 {
            continue;
        }

        let slot = (view as *mut u8).add(VIEW_FOG_LIGHT_DIRECTION) as *mut f32;
        let current = [slot.read(), slot.add(1).read(), slot.add(2).read()];
        if !force && !is_world_up(current) {
            // A dominant directional light was found; leave the engine's answer.
            continue;
        }

        slot.write(direction[0]);
        slot.add(1).write(direction[1]);
        slot.add(2).write(direction[2]);
    }
}

extern "C" fn init_fog_constants_hook(scene_renderer: *mut c_void) {
    InitFogConstantsHook.call(scene_renderer);
    unsafe { override_fog_direction(scene_renderer) };
}

pub fn init() -> anyhow::Result<()> {
    let range = UDK_RANGE.get().context("UDK_RANGE not set")?;
    let address = range
        .start
        .checked_add(INIT_FOG_CONSTANTS_RVA)
        .context("InitFogConstants address overflow")?;
    if address
        .checked_add(INIT_FOG_CONSTANTS_PROLOGUE.len())
        .is_none_or(|end| end > range.end)
    {
        bail!("InitFogConstants lies outside UDK.exe");
    }

    let actual =
        unsafe { std::slice::from_raw_parts(address as *const u8, INIT_FOG_CONSTANTS_PROLOGUE.len()) };
    if actual != INIT_FOG_CONSTANTS_PROLOGUE {
        bail!(
            "FSceneRenderer::InitFogConstants validation failed at RVA {INIT_FOG_CONSTANTS_RVA:#X}: expected {INIT_FOG_CONSTANTS_PROLOGUE:02X?}, found {actual:02X?}"
        );
    }

    unsafe {
        let original: InitFogConstants = std::mem::transmute(address as *const ());
        InitFogConstantsHook
            .initialize(original, |scene_renderer| {
                init_fog_constants_hook(scene_renderer)
            })
            .context("failed to set up FSceneRenderer::InitFogConstants hook")?;
        InitFogConstantsHook
            .enable()
            .context("failed to enable FSceneRenderer::InitFogConstants hook")?;
    }

    let force = std::env::args_os()
        .skip(1)
        .any(|arg| arg.to_string_lossy().eq_ignore_ascii_case(FORCE_OPTION));
    FORCE_ACTOR_ROTATION.store(force, Ordering::Relaxed);

    debug_log!("exponential fog light direction hook enabled (force actor rotation: {force})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_world_up, rotator_to_vector};

    fn close(actual: [f32; 3], expected: [f32; 3]) {
        for (a, e) in actual.iter().zip(expected.iter()) {
            assert!((a - e).abs() < 1e-4, "{actual:?} != {expected:?}");
        }
    }

    #[test]
    fn zero_rotation_points_down_positive_x() {
        close(rotator_to_vector([0, 0, 0]), [1.0, 0.0, 0.0]);
    }

    #[test]
    fn yaw_is_a_quarter_turn_at_16384_units() {
        // 65536 units to the turn, so a quarter turn of yaw swings X onto Y.
        close(rotator_to_vector([0, 16384, 0]), [0.0, 1.0, 0.0]);
        close(rotator_to_vector([0, 32768, 0]), [-1.0, 0.0, 0.0]);
    }

    #[test]
    fn pitch_drives_the_z_axis_and_roll_is_ignored() {
        close(rotator_to_vector([16384, 0, 0]), [0.0, 0.0, 1.0]);
        // Roll must not move the forward axis.
        close(rotator_to_vector([0, 0, 20000]), [1.0, 0.0, 0.0]);
    }

    #[test]
    fn angles_outside_one_turn_wrap() {
        close(rotator_to_vector([0, 16384 + 65536, 0]), [0.0, 1.0, 0.0]);
    }

    #[test]
    fn only_the_exact_fallback_is_replaced() {
        assert!(is_world_up([0.0, 0.0, 1.0]));
        assert!(!is_world_up([0.0, 0.0, -1.0]));
        assert!(!is_world_up([0.0, 0.0, 0.9999]));
    }
}
