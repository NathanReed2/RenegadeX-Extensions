#![recursion_limit = "256"]

mod dinput8;
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod xaudio27;

mod dll;
mod patch_utils;
#[cfg(target_arch = "x86_64")]
mod udk_array_append;
mod udk_audio_channels;
mod udk_borderless_fullscreen;
mod udk_bulk_data_count;
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
mod udk_package_size_limit;
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
/// - `udk_array_append`: backstop for the crash the above overflow produced
///   (`FMemoryWriter::Serialize` with a negative byte count). With
///   `udk_compress_from_memory` in place this should never fire; if it does,
///   the package being written is genuinely too large and the log tells you so.
/// - `udk_borderless_fullscreen`: borderless fullscreen window support.
/// - `udk_d3d9_flipex`: opt-in D3D9Ex/FlipEx presentation path, enabled only
///   by the `-D3D9EX`/`-D3D9FLIPEX` command line switches; installs no hooks
///   otherwise.
/// - `udk_fog_light_direction`: makes exponential height fog's two-tone
///   inscattering follow the fog actor's rotation when `InitFogConstants`
///   finds no dominant directional light, instead of falling back to world up.
pub fn post_udk_init() -> anyhow::Result<()> {
    udk_xaudio::init()?;
    udk_cook::init()?;
    udk_substance::init()?;
    udk_audio_channels::init()?;
    udk_filename_length::init()?;
    udk_compress_from_memory::init()?;
    udk_bulk_data_count::init()?;
    udk_package_size_limit::init()?;
    // Do not enable udk_array_append for production cooks: if it fires, it
    // deliberately truncates the package and the result cannot be shipped.
    udk_borderless_fullscreen::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_d3d9_flipex::init()?;
    //#[cfg(target_arch = "x86_64")]
    //udk_fog_light_direction::init()?;
    //#[cfg(target_arch = "x86_64")]
    //udk_mcp::init()?;
    Ok(())
}
