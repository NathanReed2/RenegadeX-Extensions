//! Disables the engine's "filename is too long for cooking" check, which
//! rejects/warns on any package base filename longer than
//! `MAX_UNREAL_FILENAME_LENGTH` (30 characters, see `Core/Src/SavePackage.cpp`).
//!
//! Source-level check (`UObject::SavePackage`, `Core/Src/SavePackage.cpp`):
//!
//! ```c
//! static const INT MAX_UNREAL_FILENAME_LENGTH = 30;
//! ...
//! if( bWarnOfLongFilename == TRUE )
//! {
//!     if ( BaseFilename.Len() > MaxFilenameLength )
//!     {
//!         ... warnf(..., *LocalizeError(TEXT("Error_FilenameIsTooLongForCooking"), TEXT("Core")), ...);
//!     }
//! }
//! ```
//!
//! Ghidra decompile of the compiled check (found via XREF search on the
//! `Error_FilenameIsTooLongForCookin` string, inside the large `SavePackage`
//! function):
//!
//! ```c
//! if (((int)local_c88 != 0) && (0x1e < (int)local_c88 + -1)) {
//!     // ... Error_FilenameIsTooLongForCooking warning/error block ...
//! }
//! ```
//!
//! The corresponding assembly:
//!
//! ```asm
//! MOV EAX, dword ptr [RSP + local_c88]
//! TEST EAX,EAX
//! JZ   LAB_1401bf7ab      ; empty filename -> skip check
//! DEC  EAX
//! CMP  EAX,0x1e           ; compare (Len - 1) against 30
//! JLE  LAB_1401bf7ab      ; Len - 1 <= 30 -> skip warning/error block
//! ... (Error_FilenameIsTooLongForCooking block) ...
//! LAB_1401bf7ab:          ; code continues normally here regardless
//! ```
//!
//! Both branches already converge on `LAB_1401bf7ab`, which is exactly the
//! code that runs right after the whole check (whether or not it fired).
//! So rather than touching the length comparison itself, the first `JZ` is
//! converted into an unconditional `JMP` to that same target: the entire
//! check (and the `DEC`/`CMP`/`JLE` that follows it) becomes dead code that
//! is always skipped, so no filename length is ever flagged as too long.
use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;

/// Known static offset (from udk.exe module base) of the start of the
/// `MOV EAX, [RSP+local_c88]` instruction that begins the filename-length
/// check, captured from Ghidra (udk.exe+0x1BF66F). Used only to pick the
/// best match if the signature scan below finds more than one hit.
#[cfg(target_arch = "x86_64")]
const FILENAME_LENGTH_KNOWN_OFFSET: usize = 0x001B_F66F;

/// Signature: `MOV EAX,[RSP+0x170]; TEST EAX,EAX; JZ rel32`.
#[cfg(target_arch = "x86_64")]
const FILENAME_LENGTH_SIG: [u8; 15] = [
    0x8B, 0x84, 0x24, 0x70, 0x01, 0x00, 0x00, // MOV EAX, dword ptr [RSP+0x170]
    0x85, 0xC0, // TEST EAX,EAX
    0x0F, 0x84, 0x2D, 0x01, 0x00, 0x00, // JZ rel32 (-> LAB_1401bf7ab)
];

/// Offset of the 6-byte `JZ rel32` within [`FILENAME_LENGTH_SIG`].
#[cfg(target_arch = "x86_64")]
const FILENAME_LENGTH_SIG_JZ_SKEW: usize = 9;

/// Replacement bytes for the 6-byte `JZ rel32`: an unconditional `JMP rel32`
/// (1 byte shorter) to the same target, padded with a single NOP so the
/// following `DEC EAX`/`CMP`/`JLE` instructions keep their original
/// addresses (they become unreachable dead code, which is harmless).
///
/// `rel32` is relative to the end of the new 5-byte `JMP` instruction, i.e.
/// one byte later than the original `JZ`'s relative-to point, so it's
/// `original_target - (jz_addr + 5)` = `0x12E`.
#[cfg(target_arch = "x86_64")]
const JMP_PATCH: [u8; 6] = [0xE9, 0x2E, 0x01, 0x00, 0x00, 0x90];

#[cfg(target_arch = "x86_64")]
fn find_filename_length_offset() -> Option<usize> {
    let (best, count) =
        find_signature_offset(&FILENAME_LENGTH_SIG, FILENAME_LENGTH_KNOWN_OFFSET, 0);
    debug_log!("filename-too-long signature matches: {count}");
    best
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_filename_length::init start");

    #[cfg(target_arch = "x86_64")]
    {
        let range = UDK_RANGE.get().context("UDK_RANGE not set")?;

        let offset = find_filename_length_offset()
            .context("Failed to find filename-too-long check signature")?;

        let jz_addr = range
            .start
            .saturating_add(offset)
            .saturating_add(FILENAME_LENGTH_SIG_JZ_SKEW);

        debug_log!(
            "udk_filename_length: patching JZ at 0x{jz_addr:X} (sig offset 0x{offset:X}) to unconditional JMP, disabling the filename-too-long-for-cooking check"
        );

        unsafe {
            let addr = jz_addr as *mut u8;

            let _guard = region::protect_with_handle(
                addr,
                JMP_PATCH.len(),
                region::Protection::READ_WRITE_EXECUTE,
            )
            .context("Failed to make JZ instruction writable")?;

            std::ptr::copy_nonoverlapping(JMP_PATCH.as_ptr(), addr, JMP_PATCH.len());
        }

        debug_log!("udk_filename_length: patch applied successfully");
    }

    debug_log!("udk_filename_length::init done");

    Ok(())
}
