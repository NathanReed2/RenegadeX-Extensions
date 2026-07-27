#![recursion_limit = "256"]

mod dinput8;
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod xaudio27;

mod dll;
mod patch_utils;
#[cfg(target_arch = "x86_64")]
mod udk_audio_channels;
mod udk_borderless_fullscreen;
mod udk_bulk_data_count;
#[cfg(target_arch = "x86_64")]
mod udk_client_vehicle_physics;
mod udk_compress_from_memory;
mod udk_cook;
#[cfg(target_arch = "x86_64")]
mod udk_d3d9_flipex;
mod udk_filename_length;
#[cfg(target_arch = "x86_64")]
mod udk_fog_light_direction;
mod udk_log;
#[cfg(target_arch = "x86_64")]
mod udk_mcp;
mod udk_mt_shader_sandbox;
mod udk_package_size_limit;
mod udk_pc_map_cook;
#[cfg(target_arch = "x86_64")]
mod udk_pcserver_script_cook;
mod udk_substance;
mod udk_xaudio;

/// Installs all in-process hooks/patches once `udk.exe` has finished its own
/// init and [`crate::dll::UDK_RANGE`] is available. Each call below targets
/// an independent crash/limitation found via reverse engineering:
///
/// - `udk_xaudio`: XAudio2 device setup fixes.
/// - `udk_cook`: patches a NULL-`this` crash in a lookup accessor
///   (`FUN_140a1f740`), observed to be reachable during package cooking.
/// - `udk_substance`: patches a crash in a generic bit-array iterator
///   constructor (`FUN_1401491b0`) caused by a bad/dangling array
///   reference, observed while cooking a SubstanceAir texture with no
///   `ParentInstance`.
/// - `udk_audio_channels`: raises the compiled-in `MAX_AUDIOCHANNELS` clamp
///   (64) inside `UXAudio2Device::Init` so the ini `MaxChannels` setting can
///   actually take effect above 64.
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
/// - `udk_pc_map_cook`: preserves separately cooked content-package imports
///   for explicit `-platform=PC` map cooks instead of force-exporting every
///   dependency into one map, while retaining the caller's seek-free handling.
/// - `udk_pcserver_script_cook`: makes a `-platform=PCServer` cook produce
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
/// - `udk_array_append`: backstop for the crash the above overflow produced
///   (`FMemoryWriter::Serialize` with a negative byte count). With
///   `udk_compress_from_memory` in place this should never fire; if it does,
///   the package being written is genuinely too large and the log tells you so.
/// - `udk_borderless_fullscreen`: borderless fullscreen window support.
/// - `udk_client_vehicle_physics`: lets the driving client own its vehicle's
///   rigid body instead of being corrected to a round-trip-stale server pose,
///   by presenting `Role` as `ROLE_Authority` to `ASVehicle::physRigidBody` for
///   the one vehicle a client owns. Inert until `Rx_Vehicle` arms it, which it
///   only does when the server replicates `bClientPhysicsAuthority`, so a
///   dedicated server and any client on a server without the matching script
///   keep stock behaviour - see the module docs.
/// - `udk_d3d9_flipex`: opt-in D3D9Ex/FlipEx presentation path, enabled only
///   by the `-D3D9EX`/`-D3D9FLIPEX` command line switches; installs no hooks
///   otherwise.
/// - `udk_fog_light_direction`: makes exponential height fog's two-tone
///   inscattering follow the rotation of an `Rx_FogLightDirection` actor placed
///   in the level, instead of the world-up direction `InitFogConstants` falls
///   back to when it finds no dominant directional light. That actor is a
///   marker that renders nothing, and the `ExponentialHeightFog` supplying the
///   fog itself is untouched. No marker in the level, no change - see the module
///   docs and `RenX_Extra/Classes/Rx_FogLightDirection.uc`.
pub fn post_udk_init() -> anyhow::Result<()> {
    udk_xaudio::init()?;
    udk_cook::init()?;
    udk_substance::init()?;
    udk_audio_channels::init()?;
    udk_filename_length::init()?;
    udk_compress_from_memory::init()?;
    udk_bulk_data_count::init()?;
    udk_package_size_limit::init()?;
    udk_mt_shader_sandbox::init()?;
    udk_pc_map_cook::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_pcserver_script_cook::init()?;
    udk_borderless_fullscreen::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_client_vehicle_physics::init()?;
    //#[cfg(target_arch = "x86_64")]
    //udk_d3d9_flipex::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_fog_light_direction::init()?;
    //#[cfg(target_arch = "x86_64")]
    //udk_mcp::init()?;
    Ok(())
}
