//! Patches the hard-coded `MAX_AUDIOCHANNELS` clamp (`#define MAX_AUDIOCHANNELS 64`
//! in `Engine/Inc/UnAudio.h`) inside `UXAudio2Device::Init` (udk.exe+0x1712A40) up
//! to [`NEW_MAX_AUDIOCHANNELS`].
//!
//! `MaxChannels` itself is already ini-configurable (`AudioDevice.uc`:
//! `var config const int MaxChannels;`), but no matter what it's set to in
//! `UDKEngine.ini`, `UXAudio2Device::Init` clamps the number of sources it
//! actually creates to `Min(MaxChannels, MAX_AUDIOCHANNELS)`, and
//! `MAX_AUDIOCHANNELS` is a compile-time constant baked directly into the
//! executable, not a variable - so ini alone can never raise the real cap.
//!
//! Ghidra decompile of the relevant snippet of `UXAudio2Device::Init`
//! (confirmed via a debug-symbol-assisted Version Tracking match):
//!
//! ```c
//! iVar1 = 0x40;
//! if (*(int *)(param_1 + 0xd) < 0x41) {
//!     iVar1 = *(int *)(param_1 + 0xd);
//! }
//! ```
//!
//! which is `Min(MaxChannels, MAX_AUDIOCHANNELS)`. The corresponding assembly
//! at udk.exe+0x1712C58:
//!
//! ```asm
//! MOV EAX, dword ptr [RBX + 0x68]   ; EAX = MaxChannels
//! MOV ECX, 0x40                     ; ECX = MAX_AUDIOCHANNELS (64)
//! CMP EAX, ECX
//! CMOVLE ECX, EAX                   ; ECX = Min(MaxChannels, 64)
//! ```
//!
//! `MOV ECX, 0x40` (opcode `B9`) encodes its immediate as a full 4-byte
//! `imm32`, not a 1-byte `imm8` - so the constant can be widened from 64 up
//! to 256 by overwriting those 4 immediate bytes in place, without touching
//! or relocating any surrounding instructions. The rest of the function
//! (source allocation loop, `Sources.AddItem`/`FreeSources.AddItem`) is
//! completely unaffected since `Sources`/`FreeSources` are dynamically-sized
//! `TArray`s - the engine will simply loop more times and allocate more
//! sources on its own.
use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;

/// New value to replace the compiled-in `MAX_AUDIOCHANNELS` (64) with.
const NEW_MAX_AUDIOCHANNELS: u32 = 512;

/// Known static offset (from udk.exe module base) of the start of the
/// `MOV EAX, dword ptr [RBX+0x68]` instruction that begins the clamp
/// sequence, captured from Ghidra (udk.exe+0x1712C55). Used only to pick the
/// best match if the signature scan below finds more than one hit.
#[cfg(target_arch = "x86_64")]
const CLAMP_KNOWN_OFFSET: usize = 0x0017_12C55;

/// Signature: `MOV EAX,[RBX+0x68]; MOV ECX,0x40; CMP EAX,ECX; CMOVLE ECX,EAX`.
#[cfg(target_arch = "x86_64")]
const CLAMP_SIG: [u8; 13] = [
    0x8B, 0x43, 0x68, 0xB9, 0x40, 0x00, 0x00, 0x00, 0x3B, 0xC1, 0x0F, 0x4E, 0xC8,
];

/// Offset of the 4-byte `imm32` (the `0x40`/64 constant) within [`CLAMP_SIG`].
#[cfg(target_arch = "x86_64")]
const CLAMP_SIG_IMMEDIATE_SKEW: usize = 4;

/// Appends a line to `renxhook.log` next to the game executable, so the
/// patched offset and outcome can be verified after the fact.
/// Scans the loaded `udk.exe` image for [`CLAMP_SIG`] (the
/// `Min(MaxChannels, MAX_AUDIOCHANNELS)` instruction sequence) and returns
/// the best matching offset (closest to the known [`CLAMP_KNOWN_OFFSET`]),
/// so the patch keeps working even if the game binary shifts slightly
/// between builds.
#[cfg(target_arch = "x86_64")]
fn find_clamp_offset() -> Option<usize> {
    let (best, count) = find_signature_offset(&CLAMP_SIG, CLAMP_KNOWN_OFFSET, 0);
    debug_log!("XAudio2 MAX_AUDIOCHANNELS clamp signature matches: {count}");
    best
}

/// Finds the compiled-in `MAX_AUDIOCHANNELS` (64) constant inside
/// `UXAudio2Device::Init` and overwrites it in place with
/// [`NEW_MAX_AUDIOCHANNELS`], raising the real hard cap on audio sources
/// the engine will ever allocate (the ini `MaxChannels` setting still
/// applies on top of this, via `Min(MaxChannels, MAX_AUDIOCHANNELS)`).
pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_audio_channels::init start");

    #[cfg(target_arch = "x86_64")]
    {
        let range = UDK_RANGE.get().context("UDK_RANGE not set")?;

        let offset = find_clamp_offset()
            .context("Failed to find XAudio2 MAX_AUDIOCHANNELS clamp signature")?;

        let imm_addr = range
            .start
            .saturating_add(offset)
            .saturating_add(CLAMP_SIG_IMMEDIATE_SKEW);

        debug_log!(
            "udk_audio_channels: patching MAX_AUDIOCHANNELS clamp at 0x{imm_addr:X} (sig offset 0x{offset:X}) from 64 to {NEW_MAX_AUDIOCHANNELS}"
        );

        let new_bytes = NEW_MAX_AUDIOCHANNELS.to_le_bytes();

        unsafe {
            let addr = imm_addr as *mut u8;

            let _guard =
                region::protect_with_handle(addr, 4, region::Protection::READ_WRITE_EXECUTE)
                    .context("Failed to make MAX_AUDIOCHANNELS immediate writable")?;

            std::ptr::copy_nonoverlapping(new_bytes.as_ptr(), addr, 4);
        }

        debug_log!("udk_audio_channels: patch applied successfully");
    }

    debug_log!("udk_audio_channels::init done");

    Ok(())
}
