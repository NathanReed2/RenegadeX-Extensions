#![recursion_limit = "256"]

mod dinput8;
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod xaudio27;

mod dll;
mod patch_utils;
mod udk_audio_channels;
mod udk_borderless_fullscreen;
mod udk_cook;
mod udk_filename_length;
mod udk_log;
#[cfg(target_arch = "x86_64")]
mod udk_mcp;
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
/// - `udk_borderless_fullscreen`: borderless fullscreen window support.
pub fn post_udk_init() -> anyhow::Result<()> {
    udk_xaudio::init()?;
    udk_cook::init()?;
    udk_substance::init()?;
    udk_audio_channels::init()?;
    udk_filename_length::init()?;
    udk_borderless_fullscreen::init()?;
    #[cfg(target_arch = "x86_64")]
    udk_mcp::init()?;
    Ok(())
}
