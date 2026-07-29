#![recursion_limit = "256"]

mod dinput8;
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod xaudio27;

mod dll;
mod patch_utils;
mod udk_log;

// Cooking - any -platform.
mod udk_bulk_data_count;
mod udk_compress_from_memory;
mod udk_cook;
mod udk_filename_length;
mod udk_mt_shader_sandbox;
mod udk_package_size_limit;
mod udk_substance;

// Cooking - one -platform each.
mod udk_pc_map_cook;
#[cfg(target_arch = "x86_64")]
mod udk_pcserver_script_cook;

// Engine-wide: editor, game and cooker alike.
#[cfg(target_arch = "x86_64")]
mod udk_audio_channels;
mod udk_xaudio;

// Game client only.
mod udk_borderless_fullscreen;
#[cfg(target_arch = "x86_64")]
mod udk_client_vehicle_physics;
#[cfg(target_arch = "x86_64")]
mod udk_d3d9_flipex;
#[cfg(target_arch = "x86_64")]
mod udk_d3d9_present_params;
#[cfg(target_arch = "x86_64")]
mod udk_fog_light_direction;

// Development tooling.
#[cfg(target_arch = "x86_64")]
mod udk_mcp;

/// Installs all in-process hooks/patches once `udk.exe` has finished its own
/// init and [`crate::dll::UDK_RANGE`] is available. Each one targets an
/// independent crash or limitation found via reverse engineering.
///
/// The calls are split by what they are for, so a whole category can be
/// commented out at once and an individual patch can be commented out inside
/// it. Every `init` detours a distinct function and none depend on each other,
/// so the order they run in does not matter.
///
/// # Not built
///
/// `src/udk_flip_model.rs` and `src/udk_emitter_pool.rs` are present in the
/// tree but deliberately not declared above, so nothing in them compiles. Add a
/// `mod` line and a call to the right group below to bring one back.
pub fn post_udk_init() -> anyhow::Result<()> {
    init_cook_patches()?;
    init_platform_cook_patches()?;
    init_engine_patches()?;
    init_client_patches()?;
    init_tooling_patches()?;
    Ok(())
}

/// Crashes and hard limits hit while cooking, whatever the target platform.
/// Disabling any of these only matters to a cook; a game client never reaches
/// them.
///
/// - `udk_cook`: patches a NULL-`this` crash in a lookup accessor
///   (`FUN_140a1f740`), observed to be reachable during package cooking.
/// - `udk_substance`: patches a crash in a generic bit-array iterator
///   constructor (`FUN_1401491b0`) caused by a bad/dangling array
///   reference, observed while cooking a SubstanceAir texture with no
///   `ParentInstance`.
/// - `udk_filename_length`: disables the "filename is too long for cooking"
///   check (30-character limit) in `UObject::SavePackage`.
/// - `udk_compress_from_memory`: forces `UObject::SavePackage` to stage cooked
///   seekfree packages through a temp file instead of a 32-bit-indexed
///   in-RAM `FBufferArchive`, so the combined `Startup.upk` no longer
///   overflows that buffer's `INT` bookkeeping while being written.
/// - `udk_bulk_data_count`: clamps an invalid (negative or overflowing)
///   `FUntypedBulkData::ElementCount` to zero at the entry to
///   `FUntypedBulkData::Serialize`, before it is written to disk. Fixes a PC
///   cook crash where a texture's editor-only `SourceArt` had
///   `ElementCount == INDEX_NONE`, so `ElementCount * GetElementSize()` came
///   out `-1` and reached `appMemcpy` as a byte count. Names the offending
///   object in the UDK log.
/// - `udk_package_size_limit`: warns, naming the package and its remaining
///   headroom, as a cooked package approaches the 2 GiB ceiling imposed by
///   UE3's `INT` archive offsets, and explains the cause if one crosses it.
///   Without this the only symptom is `Error seeking file` followed by a
///   missing cooked file, which names neither the package nor the limit.
/// - `udk_mt_shader_sandbox`: stages the shader subdirectories that
///   `UCookPackagesCommandlet::PrepareShaderFiles` leaves out of each
///   multithreaded cook child's private sandbox. It copies `Shaders\Binaries`
///   non-recursively, so `Binaries\RealD` never arrives and any map needing
///   `RealD/CommonDepth.usf` dies with `Couldn't load shader file` - which then
///   takes down every sibling child, and with them the whole `-Processes=N`
///   cook, behind the parent's uninformative `Child process crashed:`.
fn init_cook_patches() -> anyhow::Result<()> {
    udk_cook::init()?;
    udk_substance::init()?;
    udk_filename_length::init()?;
    udk_compress_from_memory::init()?;
    udk_bulk_data_count::init()?;
    udk_package_size_limit::init()?;
    udk_mt_shader_sandbox::init()?;
    Ok(())
}

/// Cook patches that each apply to exactly one `-platform=` target, and are
/// inert for every other cook. Disable one only if you are not shipping that
/// platform.
///
/// - `udk_pc_map_cook` (`-platform=PC`): preserves separately cooked
///   content-package imports for explicit `-platform=PC` map cooks instead of
///   force-exporting every dependency into one map, while retaining the
///   caller's seek-free handling.
/// - `udk_pcserver_script_cook` (`-platform=PCServer`): makes the cook produce
///   script a `-seekfreeloadingserver` dedicated server can load, by removing
///   four places where `PLATFORM_WindowsServer` is treated as console-like even
///   though the cook is written and read back by this same non-console binary:
///   the path/extension test in `GetCookedPackageFilename` (script was written
///   as `.upk` and overwritten by same-named content), `UClass::Serialize`'s
///   editor-only field guard (written against `GCookingTarget` but read against
///   `GPatchingTarget`, so 28 fewer bytes per class were written than read -
///   `Bad name index -1/822`), `PLATFORM_FilterEditorOnly` (which drops
///   editor-only `UProperty` objects that this binary's native class layout
///   still has, so class defaults deserialise onto native fields), and the two
///   gates that discard non-native (mod) script. Needs
///   `UDKGame\Config\PCServer\PCServerEngine.ini` - see the module docs.
fn init_platform_cook_patches() -> anyhow::Result<()> {
    udk_pc_map_cook::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_pcserver_script_cook::init()?;
    Ok(())
}

/// Engine-wide fixes that apply the same way to the editor, the game and the
/// cooker, because they patch subsystem setup rather than any one workflow.
///
/// - `udk_xaudio`: XAudio2 device setup fixes.
/// - `udk_audio_channels`: raises the compiled-in `MAX_AUDIOCHANNELS` clamp
///   (64) inside `UXAudio2Device::Init` so the ini `MaxChannels` setting can
///   actually take effect above 64.
fn init_engine_patches() -> anyhow::Result<()> {
    udk_xaudio::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_audio_channels::init()?;
    Ok(())
}

/// Presentation and gameplay changes that only reach a running game client.
/// These are the ones to reach for when something looks or plays wrong, and the
/// safe ones to disable when isolating a rendering or physics regression.
///
/// - `udk_borderless_fullscreen`: borderless fullscreen window support.
/// - `udk_d3d9_flipex`: opt-in D3D9Ex/FlipEx presentation path, enabled only
///   by the `-D3D9EX`/`-D3D9FLIPEX` command line switches; installs no hooks
///   otherwise.
/// - `udk_d3d9_present_params`: rewrites two `D3DPRESENT_PARAMETERS` fields
///   that `FD3D9DynamicRHI::UpdateD3DDeviceFromViewports` hard-codes, by
///   detouring `IDirect3D9::CreateDevice` and `IDirect3DDevice9::Reset`. It
///   drops `D3DPRESENTFLAG_LOCKABLE_BACKBUFFER`, which forces a linear
///   uncompressed back buffer that nothing in the D3D9 RHI ever locks
///   (`ReadSurfaceData` goes through `GetRenderTargetData` into a SYSTEMMEM
///   texture), and raises `BackBufferCount` from 1 to 2 so exclusive fullscreen
///   is triple buffered instead of dropping to half refresh on one missed vsync.
///   The extra buffer is added only to a `D3DSWAPEFFECT_DISCARD` chain, because
///   the `D3DSWAPEFFECT_COPY` that every windowed and borderless viewport uses
///   is defined for a single back buffer only. Stands down under
///   `-D3D9EX`/`-D3D9FLIPEX`, which hand the same export to `udk_d3d9_flipex`.
/// - `udk_fog_light_direction`: makes exponential height fog's two-tone
///   inscattering follow the fog actor's own rotation, instead of the world-up
///   direction `InitFogConstants` falls back to when it finds no dominant
///   directional light. Applies only when the level's rendering fog is an
///   `Rx_ExponentialHeightFog_Rotatable`, a copy of `ExponentialHeightFog` whose
///   rotation is given that meaning; a stock fog actor is left alone - see the
///   module docs and
///   `RenX_Extra/Classes/Rx_ExponentialHeightFog_Rotatable.uc`.
/// - `udk_client_vehicle_physics`: lets the driving client own its vehicle's
///   rigid body instead of being corrected to a round-trip-stale server pose,
///   by presenting `Role` as `ROLE_Authority` to `ASVehicle::physRigidBody` for
///   the one vehicle a client owns. Inert until `Rx_Vehicle` arms it, which it
///   only does when the server replicates `bClientPhysicsAuthority`, so a
///   dedicated server and any client on a server without the matching script
///   keep stock behaviour - see the module docs.
fn init_client_patches() -> anyhow::Result<()> {
    udk_borderless_fullscreen::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_d3d9_flipex::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_d3d9_present_params::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_fog_light_direction::init()?;
    //#[cfg(target_arch = "x86_64")]
    //udk_client_vehicle_physics::init()?;
    Ok(())
}

/// Development tooling: not part of shipping behaviour, and off by default.
///
/// - `udk_mcp`: loopback MCP bridge for the Win64 editor, draining its Unreal
///   calls from `UUnrealEdEngine::Tick` so they run on the editor thread.
fn init_tooling_patches() -> anyhow::Result<()> {
    //#[cfg(target_arch = "x86_64")]
    //udk_mcp::init()?;
    Ok(())
}
