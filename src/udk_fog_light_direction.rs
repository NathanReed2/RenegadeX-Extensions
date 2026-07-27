//! Drives exponential height fog's two-tone inscattering from a dedicated
//! `HeightFog` actor's rotation.
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
//! This module detours `InitFogConstants`, lets it run, and then overwrites that
//! direction with the rotation of a **separate** fog actor, so the direction is
//! authored independently of the `ExponentialHeightFog` actor that supplies
//! every other fog parameter.
//!
//! # The direction actor
//!
//! Place a legacy `HeightFog` actor (`Engine.HeightFog`, ClassGroup `Fog`,
//! `showcategories(Movement)`) anywhere in the level and rotate it. Its rotation
//! is the only thing read; nothing else about it matters.
//!
//! `HeightFog` is the right carrier because in a level that also has an
//! `ExponentialHeightFog` it is provably inert on PC:
//!
//!  * `SetFogShaders` takes the `Scene->ExponentialFogs.Num() > 0` branch and
//!    binds `TExponentialHeightFogPixelShader`, so the four-layer height fog
//!    shaders that would consume `Scene->Fogs` are never selected;
//!  * the vertex shader that branch does bind, `THeightFogVertexShader<1>`,
//!    passes the layer heights down in `OutTexCoordAndHeightRelativeZ.zw`, and
//!    `ExponentialPixelMain` reads only `.xy` and `ScreenVector` - the layer
//!    values reach no arithmetic; and
//!  * the one path that renders one-layer height fog outside `RenderFog`,
//!    `RenderQuarterDownsampledDepthAndFog` behind ambient occlusion, has its
//!    whole body inside `#if XBOX` and returns FALSE here, so
//!    `bOneLayerHeightFogRenderedInAO` stays FALSE.
//!
//! `UHeightFogComponent::SetParentToWorld` only reads the origin's Z, so
//! rotating the actor has no effect on the engine either. The actor is a pure
//! marker.
//!
//! The corollary is worth stating: in a level with **no** `ExponentialHeightFog`
//! a `HeightFog` actor renders normally, as it always has. This module writes
//! nothing in that case - `DominantDirectionalLightDirection` only reaches a
//! shader through the exponential fog path.
//!
//! When the level has no `HeightFog` actor, the engine's own result is left
//! alone, so this hook is inert until a direction actor is placed. When one is
//! present its rotation always wins, including over a `DominantDirectionalLight`
//! the renderer did resolve; placing the actor is the opt-in.
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
//! RVAs and offsets were read from `Firestorm/Binaries/Win64/UDK.exe`, whose
//! `.text` hash is pinned in `dll.rs`. The object offsets are additionally
//! proven at runtime before anything is written - see [`owning_actor_rotation`].

#![cfg(target_arch = "x86_64")]

use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context};
use retour::static_detour;

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

/// Last (pitch, yaw) that was applied, packed, so the log records changes
/// instead of one line per view per frame. Starts at a value no rotation
/// produces, because both halves are masked to 16 bits before packing.
static LAST_LOGGED_ROTATION: AtomicU64 = AtomicU64::new(u64::MAX);

/// Stored in [`LAST_LOGGED_ROTATION`] once the "no direction actor" line has
/// been logged, so a level without one does not repeat it every frame. No real
/// rotation packs this high; the packed form fits in 32 bits.
const NO_DIRECTION_ACTOR: u64 = u64::MAX - 1;

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

/// `FScene::Fogs`, a `TArray<FHeightFogSceneInfo>` - the legacy `HeightFog`
/// components, and so where the direction actor is found. Confirmed by
/// `mov ecx,[rax+0x4EC0]` feeding the `Min(Scene->Fogs.Num(),4)` clamp and
/// `mov rax,[rdi+0x4EB8]` loading the array that the layer loop indexes.
const SCENE_FOGS_DATA: usize = 0x4EB8;
const SCENE_FOGS_NUM: usize = 0x4EC0;
/// `sizeof(FHeightFogSceneInfo)`, from the layer loop's `lea rsi,[rax+rax*4];
/// shl rsi,3` index scaling and its matching `sub rsi,0x28` step.
const HEIGHT_FOG_STRIDE: usize = 0x28;
/// `FHeightFogSceneInfo::Component`, at the very start of the struct: the same
/// loop reads `Height` at `[rax+rsi+8]`, one pointer in.
const HEIGHT_FOG_COMPONENT: usize = 0x00;

/// `FScene::ExponentialFogs`, a `TArray<FExponentialHeightFogSceneInfo>`,
/// declared immediately after `Fogs` - hence exactly one `TArray` (0x10) later.
const SCENE_EXPONENTIAL_FOGS_NUM: usize = 0x4ED0;

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

/// Likewise for the fog array: `InitFogConstants` itself only ever looks at the
/// first four layers, so a count past this is a bad read, not a level.
const MAX_PLAUSIBLE_FOGS: i32 = 256;

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
unsafe fn owning_actor_rotation(component: *mut c_void) -> Option<[i32; 3]> {
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

/// Rotation of the level's direction actor, i.e. the first `HeightFog` in
/// `FScene::Fogs` whose actor layout checks out.
///
/// The array is sorted by height, so with more than one `HeightFog` the highest
/// wins. Levels are expected to carry a single one; the log names the count so
/// an accidental second actor is visible.
unsafe fn direction_actor_rotation(scene: *mut c_void) -> Option<[i32; 3]> {
    let count = read_i32(scene, SCENE_FOGS_NUM);
    if count <= 0 {
        return None;
    }
    if count > MAX_PLAUSIBLE_FOGS {
        debug_log!("[fog] implausible Fogs count ({count}); leaving fog alone");
        return None;
    }

    let fogs = read_ptr(scene, SCENE_FOGS_DATA);
    if fogs.is_null() {
        return None;
    }

    (0..count).find_map(|index| {
        let info = (fogs as *mut u8).add(index as usize * HEIGHT_FOG_STRIDE) as *mut c_void;
        owning_actor_rotation(read_ptr(info, HEIGHT_FOG_COMPONENT))
    })
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

/// Packs (pitch, yaw) for [`LAST_LOGGED_ROTATION`].
fn pack_rotation(rotation: [i32; 3]) -> u64 {
    (u64::from(rotation[0] as u32 & 0xFFFF) << 16) | u64::from(rotation[1] as u32 & 0xFFFF)
}

unsafe fn override_fog_direction(scene_renderer: *mut c_void) {
    if scene_renderer.is_null() {
        return;
    }
    let scene = read_ptr(scene_renderer, SCENE_RENDERER_SCENE);
    if scene.is_null() {
        return;
    }

    // The direction only reaches a shader through the exponential fog path, and
    // that path is also what keeps the direction actor from rendering. Without
    // an exponential fog there is nothing to steer and nothing to correct.
    if read_i32(scene, SCENE_EXPONENTIAL_FOGS_NUM) <= 0 {
        return;
    }

    let Some(rotation) = direction_actor_rotation(scene) else {
        if LAST_LOGGED_ROTATION.swap(NO_DIRECTION_ACTOR, Ordering::Relaxed) != NO_DIRECTION_ACTOR {
            debug_log!("[fog] no HeightFog direction actor in this level; keeping the engine's fog direction");
        }
        return;
    };
    let forward = rotator_to_vector(rotation);
    // The engine stores the direction *toward* the light, hence -GetDirection().
    let direction = [-forward[0], -forward[1], -forward[2]];

    let packed = pack_rotation(rotation);
    if LAST_LOGGED_ROTATION.swap(packed, Ordering::Relaxed) != packed {
        debug_log!(
            "[fog] direction actor rotation pitch={} yaw={} roll={} -> direction ({:.3},{:.3},{:.3})",
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

    debug_log!("exponential fog light direction hook enabled (rotate a HeightFog actor to aim it)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        pack_rotation, rotator_to_vector, NO_DIRECTION_ACTOR, SCENE_EXPONENTIAL_FOGS_NUM,
        SCENE_FOGS_DATA, SCENE_FOGS_NUM,
    };

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
    fn no_rotation_collides_with_the_missing_actor_sentinel() {
        // Both halves are masked to 16 bits, so a packed rotation cannot reach
        // the high sentinel however far out of range the actor's angles are.
        for rotation in [[0, 0, 0], [-1, -1, -1], [i32::MAX, i32::MIN, 0]] {
            assert!(pack_rotation(rotation) <= u64::from(u32::MAX));
            assert_ne!(pack_rotation(rotation), NO_DIRECTION_ACTOR);
        }
    }

    #[test]
    fn the_two_fog_arrays_are_one_tarray_apart() {
        // FScene declares ExponentialFogs immediately after Fogs, and a TArray
        // is 16 bytes. If a future build moves one, this pins the other.
        const TARRAY_SIZE: usize = 0x10;
        assert_eq!(SCENE_FOGS_DATA + 8, SCENE_FOGS_NUM);
        assert_eq!(SCENE_FOGS_NUM + TARRAY_SIZE, SCENE_EXPONENTIAL_FOGS_NUM);
    }
}
