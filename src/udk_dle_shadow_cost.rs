//! Cuts the CPU cost of Dynamic Light Environments by reducing how often they
//! re-gather, and measures what that costs in the first place.
//!
//! # Why this exists rather than a GPU port
//!
//! [`crate::udk_gpu_light_env`] moved the DLE SH accumulation onto the GPU and
//! was measured against the stock result at 70-87% deviation on two machines.
//! That was not a bug: `AddLightToEnvironment` scales every light by a
//! `VisibilityFactor` from `IsLightVisible`, which casts
//! `NumVolumeVisibilitySamples` shadow rays through
//! `GWorld->SingleLineCheck(TRACE_Level|TRACE_Actors|TRACE_ShadowCast)`. The
//! gather is a shadowing computation, and a D3D9 SM3 device has no scene
//! geometry to trace against.
//!
//! The corollary is what this module acts on: **the cost is the ray casts, not
//! the SH arithmetic.** Reducing the arithmetic was never going to help. What
//! helps is casting fewer rays, and the engine's own knob for that is how often
//! a light environment performs a full update.
//!
//! # What it does
//!
//! `FDynamicLightEnvironmentState::Update` runs `UpdateStaticEnvironment` - the
//! expensive walk of `StaticLightList`, one `SingleLineCheck` per shadow-casting
//! light - no more often than
//!
//! ```text
//! TimeBetweenUpdates = (bVisible ? MinTimeBetweenFullUpdates : InvisibleUpdateTime)
//!                    * DistanceFactor / VelocityFactor
//! ```
//!
//! and only when the owner has moved. `Rx_Vehicle.uc:6402` sets
//! `MinTimeBetweenFullUpdates=0.1`, so a moving vehicle re-gathers ten times a
//! second. Raising that floor is a direct, linear reduction in ray casts, and it
//! costs only lighting latency - the SH is interpolated toward its new value by
//! `UpdateEnvironmentInterpolation` either way, so the result stays smooth.
//!
//! Both fields are re-read from the component on every full update
//! (`DynamicLightEnvironmentComponent.cpp:1166`), so writing them on the
//! component takes effect without touching the cached state copy.
//!
//! # Where it hooks
//!
//! `IsLightVisible` - the single function every visibility ray passes through.
//! Hooking it gives an exact ray-cast count for free, and its `this` is the
//! `FDynamicLightEnvironmentState`, whose first field is the owning component,
//! so the same hook reaches the fields to tune.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{bail, Context};
use retour::static_detour;

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;
use crate::udk_log::{log, LogType};

/// `FDynamicLightEnvironmentState::IsLightVisible`.
///
/// Located by matching the symbol build's `IsLightVisible` (`140314470`) against
/// RenXSDK with `/diff_functions`: 134 instructions body-equal, both carrying the
/// `Array.h` bounds assert from indexing `LightVisibilitySamplePoints`, and the
/// symbol side calling `SingleLineCheck`. It sits `0x590` below
/// `AddLightToEnvironment` (`0x344B00`), mirroring the `0x560` gap in the symbol
/// build.
const IS_LIGHT_VISIBLE_RVA: usize = 0x34_4570;

/// `FDynamicLightEnvironmentState::Component`, the owning
/// `UDynamicLightEnvironmentComponent*`.
const STATE_COMPONENT: usize = 0x000;

/// `UDynamicLightEnvironmentComponent::InvisibleUpdateTime` and
/// `MinTimeBetweenFullUpdates`.
///
/// Read out of the state constructor, whose initialiser list copies
/// `InComponent->InvisibleUpdateTime` then `InComponent->MinTimeBetweenFullUpdates`
/// from `+0xB0` and `+0xB4` - adjacent floats, in the order the two are declared
/// in `DynamicLightEnvironmentComponent.uc`.
const COMPONENT_INVISIBLE_UPDATE_TIME: usize = 0x0B0;
const COMPONENT_MIN_TIME_BETWEEN_FULL_UPDATES: usize = 0x0B4;

/// Plausible range for either field, used to refuse tuning rather than corrupt
/// an object when an offset is wrong.
///
/// Stock values run from `0.1` (`Rx_Vehicle`) to `3.0`
/// (`ParticleLightEnvironmentComponent`); anything outside this window is not a
/// value the engine would hold, so it means the offset does not point where this
/// module thinks it does.
const PLAUSIBLE_UPDATE_TIME: std::ops::RangeInclusive<f32> = 0.0..=60.0;

type IsLightVisibleFn =
    unsafe extern "system" fn(*mut u8, *const c_void, *const c_void, u32, *mut f32) -> u32;

static_detour! {
    static IsLightVisibleHook: unsafe extern "system" fn(*mut u8, *const c_void, *const c_void, u32, *mut f32) -> u32;
}

static ENABLED: AtomicBool = AtomicBool::new(false);
/// Visibility queries seen. Not every one casts a ray - the engine early-outs
/// for sky lights and for lights that do not cast static shadows - but every ray
/// comes through here, so this bounds the cost.
static QUERIES: AtomicU64 = AtomicU64::new(0);
/// Components whose update interval this module has raised.
static TUNED: AtomicU64 = AtomicU64::new(0);
/// Refused because a field did not hold a plausible value.
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// Floors applied to the two component fields, in seconds, as `f32` bits.
///
/// Atomics rather than a `Mutex` because this is read on every single visibility
/// query - thousands per frame - and taking a lock there would spend more than
/// the module saves. NaN means "leave this field alone".
static INVISIBLE_FLOOR: AtomicU32 = AtomicU32::new(f32::NAN.to_bits());
static VISIBLE_FLOOR: AtomicU32 = AtomicU32::new(f32::NAN.to_bits());
static REPORT: Mutex<Option<Instant>> = Mutex::new(None);

fn floor_of(cell: &AtomicU32) -> Option<f32> {
    let value = f32::from_bits(cell.load(Ordering::Relaxed));
    value.is_finite().then_some(value)
}

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

/// Raises this DLE's update interval, once per component.
///
/// Writing the component rather than the state's cached copy is deliberate: the
/// state refreshes both from the component on every full update, so a component
/// write survives and a state write would be overwritten.
unsafe fn tune(state: *mut u8) {
    let component = std::ptr::read_unaligned(state.add(STATE_COMPONENT) as *const *mut u8);
    if component.is_null() {
        return;
    }

    for (offset, floor) in [
        (COMPONENT_INVISIBLE_UPDATE_TIME, floor_of(&INVISIBLE_FLOOR)),
        (
            COMPONENT_MIN_TIME_BETWEEN_FULL_UPDATES,
            floor_of(&VISIBLE_FLOOR),
        ),
    ] {
        let Some(floor) = floor else { continue };
        let field = component.add(offset) as *mut f32;
        let current = std::ptr::read_unaligned(field);

        // A wrong offset shows up as a value no update interval would ever hold.
        if !current.is_finite() || !PLAUSIBLE_UPDATE_TIME.contains(&current) {
            REFUSED.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if current < floor {
            std::ptr::write_unaligned(field, floor);
            TUNED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

unsafe fn is_light_visible(
    state: *mut u8,
    light: *const c_void,
    owner_position: *const c_void,
    is_dynamic: u32,
    out_visibility: *mut f32,
) -> u32 {
    if !ENABLED.load(Ordering::Relaxed) || state.is_null() {
        return IsLightVisibleHook.call(state, light, owner_position, is_dynamic, out_visibility);
    }

    QUERIES.fetch_add(1, Ordering::Relaxed);
    tune(state);
    report_periodically();

    IsLightVisibleHook.call(state, light, owner_position, is_dynamic, out_visibility)
}

/// Logs the query rate every ten seconds, which is what makes the effect of a
/// floor visible without a profiler.
fn report_periodically() {
    const INTERVAL_SECONDS: u64 = 10;

    // Cheap gate so the clock is not read on every single query.
    if QUERIES.load(Ordering::Relaxed) % 4096 != 0 {
        return;
    }
    let Ok(mut last) = REPORT.lock() else { return };
    let now = Instant::now();
    let previous = last.get_or_insert(now);
    let elapsed = now.duration_since(*previous);
    if elapsed.as_secs() < INTERVAL_SECONDS {
        return;
    }
    let queries = QUERIES.swap(0, Ordering::Relaxed);
    *last = Some(now);
    drop(last);

    let per_second = queries as f64 / elapsed.as_secs_f64();
    let refused = REFUSED.load(Ordering::Relaxed);
    let mut line = format!(
        "-DLETUNE: {per_second:.0} light-visibility queries/sec \
         ({queries} over {:.1}s), {} component update intervals raised",
        elapsed.as_secs_f64(),
        TUNED.load(Ordering::Relaxed),
    );
    if refused > 0 {
        line.push_str(&format!(
            " | REFUSED {refused} writes - a component field held an implausible \
             value, so the offset is wrong and nothing was tuned"
        ));
    }
    log(LogType::Init, &line);
}

/// Installs on `-DLETUNE`. Optional `-DLEVISIBLEUPDATE=<seconds>` and
/// `-DLEINVISIBLEUPDATE=<seconds>` override the floors.
///
/// Nothing here logs through `udk_log`: this runs from `DllMain`, before UE3 has
/// built `GLog`, and a `FOutputDevice` call at that point faults inside UDK.exe
/// and surfaces as `0xC0000142`.
pub(crate) fn init() -> anyhow::Result<()> {
    let mut requested = false;
    let mut visible_floor = 0.25f32;
    let mut invisible_floor: Option<f32> = None;

    for argument in std::env::args_os() {
        let argument = argument.to_string_lossy();
        let argument = argument.trim_start_matches(['-', '/']);
        let (name, value) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (argument, None),
        };
        if name.eq_ignore_ascii_case("DLETUNE") {
            requested = true;
        } else if name.eq_ignore_ascii_case("DLEVISIBLEUPDATE") {
            requested = true;
            if let Some(parsed) = value.and_then(|value| value.parse::<f32>().ok()) {
                visible_floor = parsed;
            }
        } else if name.eq_ignore_ascii_case("DLEINVISIBLEUPDATE") {
            requested = true;
            invisible_floor = value.and_then(|value| value.parse::<f32>().ok());
        }
    }
    if !requested {
        return Ok(());
    }
    if !visible_floor.is_finite() || !PLAUSIBLE_UPDATE_TIME.contains(&visible_floor) {
        debug_log!("-DLETUNE: refusing an out-of-range visible update floor");
        return Ok(());
    }

    VISIBLE_FLOOR.store(visible_floor.to_bits(), Ordering::Release);
    if let Some(invisible_floor) = invisible_floor {
        if invisible_floor.is_finite() && PLAUSIBLE_UPDATE_TIME.contains(&invisible_floor) {
            INVISIBLE_FLOOR.store(invisible_floor.to_bits(), Ordering::Release);
        }
    }

    let target = image_address(IS_LIGHT_VISIBLE_RVA, "IsLightVisible")?;
    let function: IsLightVisibleFn = unsafe { std::mem::transmute(target) };
    unsafe {
        IsLightVisibleHook
            .initialize(function, |state, light, position, dynamic, out| {
                is_light_visible(state, light, position, dynamic, out)
            })
            .context("initializing IsLightVisible hook")?;
        IsLightVisibleHook
            .enable()
            .context("enabling IsLightVisible hook")?;
    }

    ENABLED.store(true, Ordering::Release);
    debug_log!("-DLETUNE: hooked IsLightVisible at {target:p}");
    Ok(())
}
