//! Forces `UObject::SavePackage` to never take its "compress from memory"
//! shortcut, so large cooked seekfree packages (in practice: the combined
//! `Startup.upk`) are streamed through a temp file instead of being
//! accumulated whole in a 32-bit-indexed `TArray<BYTE>` in RAM.
//!
//! # Why
//!
//! Source-level decision (`UObject::SavePackage`, `Core/Src/SavePackage.cpp`):
//!
//! ```c
//! /** If TRUE, we are going to compress the package to memory to save a little time */
//! UBOOL bCompressFromMemory = FALSE;
//! ...
//! // limit in memory compression to cooked packages; cooked packages are though to be of
//! // reasonable size for in memory compression
//! if( (InOuter->PackageFlags & PKG_StoreCompressed) && (InOuter->PackageFlags & PKG_Cooked))
//! {
//!     bCompressFromMemory = TRUE;
//!     // Allocate the linker with a memory writer, forcing byte swapping if wanted.
//!     Linker = new ULinkerSave( InOuter, bForceByteSwapping );
//! }
//! else
//! {
//!     // Allocate the linker, forcing byte swapping if wanted.
//!     Linker = new ULinkerSave( InOuter, *TempFilename, bForceByteSwapping );
//! }
//! ```
//!
//! Epic's assumption ("cooked packages are thought to be of reasonable size")
//! does not hold for the combined startup package. The memory variant of the
//! constructor allocates an `FBufferArchive`:
//!
//! ```c
//! ULinkerSave::ULinkerSave( UPackage* InParent, UBOOL bForceByteSwapping )
//! :   ULinker( InParent, TEXT("$$Memory$$") ) ...
//! { Saver = new FBufferArchive(); ... }
//! ```
//!
//! and `FBufferArchive : public FMemoryWriter, public TArray<BYTE>` funnels
//! every write through `FMemoryWriter::Serialize`, whose position and array
//! bookkeeping are all `INT` (32-bit signed):
//!
//! ```c
//! void Serialize( void* Data, INT Num )
//! {
//!     const INT NumBytesToAdd = Offset + Num - Bytes.Num();
//!     if( NumBytesToAdd > 0 ) { ... Bytes.Add( NumBytesToAdd ); }
//!     if( Num ) { appMemcpy( &Bytes( Offset ), Data, Num ); Offset += Num; }
//! }
//! ```
//!
//! Because `TArray` grows geometrically, `ArrayMax` reaches roughly twice the
//! live byte count, and `FMalloc::Realloc` takes a `DWORD` count - so the
//! growth arithmetic goes bad well before the data itself reaches 2 GB. Once
//! it does, the `Offset`/`Num` bounds check inside `Bytes( Offset )` trips
//! `i>=0 && (i<ArrayNum||(i==0 && ArrayNum==0))` (`Array.h:575`) and the cook
//! dies while finalizing `Startup.upk` - after every other package has
//! already been written. See [`crate::udk_array_append`] for a hook on the
//! resulting crash; this module removes the cause instead.
//!
//! # Why this is safe
//!
//! Taking the `else` branch is not a downgrade in output. `bCompressFromMemory`
//! only selects *where the uncompressed bytes are staged*; the package is
//! compressed either way, by two overloads of the same helper:
//!
//! ```c
//! if( bCompressFromMemory )   // reads from the in-RAM FBufferArchive
//!     Success = CompressionHelper.CompressFile( *NewPath, Linker );
//! else if( InOuter->PackageFlags & PKG_StoreCompressed )   // reads from the temp file
//!     Success = CompressionHelper.CompressFile( *TempFilename, *NewPath, Linker );
//! ```
//!
//! The resulting `.upk` keeps `PKG_StoreCompressed` and its `COMPRESS_ZLIB`
//! chunks exactly as before - it just costs a temp file and some extra I/O,
//! which is precisely the path every non-cooked save already takes.
//!
//! # The compiled branch
//!
//! Located in `udk.exe` by finding the sole call to the memory-writer
//! `ULinkerSave` constructor (identified as the function that passes the
//! `$$Memory$$` linker name, at udk.exe+0x238AD0) from inside
//! `UObject::SavePackage` (udk.exe+0x1B9AA0..0x1BFBCC, confirmed by its
//! `Save=%f` / `Compressing '%s' to '%s'` / `Compressing from memory to '%s'`
//! debugf string references):
//!
//! ```asm
//! 1401baf6b  MOV  EAX, dword ptr [R13 + 0x118]  ; InOuter->PackageFlags
//! 1401baf72  BT   EAX, 0x19                     ; bit 25 == PKG_StoreCompressed (0x02000000)
//! 1401baf76  MOV  R15D, dword ptr [RSP + 0x78]  ; bForceByteSwapping (shared by both branches)
//! 1401baf7b  JAE  LAB_1401bafd9                 ; not compressed -> file-backed linker
//! 1401baf7d  TEST AL, 0x8                       ; PKG_Cooked
//! 1401baf7f  JZ   LAB_1401bafd9                 ; not cooked     -> file-backed linker
//! 1401baf81  ...                                ; bCompressFromMemory = TRUE ([RSP+0x18C])
//! 1401bafbf  CALL FUN_140238ad0                 ; ULinkerSave(InOuter, bForceByteSwapping)
//! 1401bafd4  JMP  LAB_1401bb088
//! LAB_1401bafd9:                                ; <- both conditional jumps land here
//! 1401bb04d  CALL FUN_1402386d0                 ; ULinkerSave(InOuter, *TempFilename, bForceByteSwapping)
//! LAB_1401bb088:                                ; <- both branches rejoin
//! ```
//!
//! MSVC emitted `BT`/`TEST AL` rather than folding the two flag tests into a
//! single `AND EAX, 0x02000008`, which is why the mask does not appear as an
//! immediate anywhere in the image.
//!
//! Two details make the patch a one-byte change rather than a detour:
//!
//! 1. Both conditional jumps already target `LAB_1401bafd9`, so widening the
//!    first `JAE` into an unconditional `JMP` to the same place skips the
//!    entire memory path and leaves the `TEST AL, 0x8`/`JZ` pair as harmless
//!    dead code - the same trick [`crate::udk_filename_length`] uses.
//! 2. `bForceByteSwapping` is loaded into `R15D` at `1401baf76`, *before* the
//!    branch, and `R13` (`InOuter`) is live across it, so the `else` block's
//!    argument setup is complete without anything from the skipped block.
//!
//! `bCompressFromMemory` lives in the stack slot at `[RSP+0x18C]` and is only
//! ever written inside the skipped block, so it stays `FALSE` and the two
//! later reads of it (`Linker->Detach()` and the `CompressFile` selection)
//! stay consistent with the linker that was actually constructed.
//!
//! `JAE rel8` (`0x73`) and `JMP rel8` (`0xEB`) are both two-byte instructions
//! sharing the same displacement encoding, so only the opcode byte is
//! rewritten and the existing `rel8` is left untouched.
use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;

/// Known static offset (from the `udk.exe` module base) of the
/// `MOV EAX, [R13+0x118]` that begins the `bCompressFromMemory` test, taken
/// from the 12791 (UDK-2015-01, CL 2424394) x64 build. Used only to pick the
/// nearest match if the signature scan below ever finds more than one hit.
#[cfg(target_arch = "x86_64")]
const COMPRESS_FROM_MEMORY_KNOWN_OFFSET: usize = 0x001B_AF6B;

/// Signature covering the whole two-test sequence:
/// `MOV EAX,[R13+0x118]; BT EAX,0x19; MOV R15D,[RSP+0x78]; JAE rel8; TEST AL,8; JZ rel8`.
///
/// Verified unique in the 12791 x64 image (exactly one match).
#[cfg(target_arch = "x86_64")]
const COMPRESS_FROM_MEMORY_SIG: [u8; 22] = [
    0x41, 0x8B, 0x85, 0x18, 0x01, 0x00, 0x00, // MOV EAX, dword ptr [R13 + 0x118]
    0x0F, 0xBA, 0xE0, 0x19, // BT EAX, 0x19
    0x44, 0x8B, 0x7C, 0x24, 0x78, // MOV R15D, dword ptr [RSP + 0x78]
    0x73, 0x5C, // JAE LAB_1401bafd9
    0xA8, 0x08, // TEST AL, 0x8
    0x74, 0x58, // JZ  LAB_1401bafd9
];

/// Offset of the `JAE rel8` opcode byte within [`COMPRESS_FROM_MEMORY_SIG`].
#[cfg(target_arch = "x86_64")]
const COMPRESS_FROM_MEMORY_SIG_JAE_SKEW: usize = 16;

/// `JMP rel8`. Replaces the `JAE rel8` opcode in place; the following
/// displacement byte already points at the file-backed-linker branch.
#[cfg(target_arch = "x86_64")]
const JMP_REL8_OPCODE: u8 = 0xEB;

#[cfg(target_arch = "x86_64")]
fn find_compress_from_memory_offset() -> Option<usize> {
    let (best, count) = find_signature_offset(
        &COMPRESS_FROM_MEMORY_SIG,
        COMPRESS_FROM_MEMORY_KNOWN_OFFSET,
        0,
    );
    debug_log!("compress-from-memory signature matches: {count}");
    best
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_compress_from_memory::init start");

    #[cfg(target_arch = "x86_64")]
    {
        let range = UDK_RANGE.get().context("UDK_RANGE not set")?;

        let offset = find_compress_from_memory_offset()
            .context("Failed to find compress-from-memory branch signature")?;

        let jae_addr = range
            .start
            .saturating_add(offset)
            .saturating_add(COMPRESS_FROM_MEMORY_SIG_JAE_SKEW);

        debug_log!(
            "udk_compress_from_memory: patching JAE at 0x{jae_addr:X} (sig offset 0x{offset:X}) to unconditional JMP, forcing SavePackage onto the file-backed ULinkerSave path"
        );

        unsafe {
            let addr = jae_addr as *mut u8;

            let _guard = region::protect_with_handle(
                addr,
                1,
                region::Protection::READ_WRITE_EXECUTE,
            )
            .context("Failed to make JAE instruction writable")?;

            std::ptr::write_volatile(addr, JMP_REL8_OPCODE);
        }

        debug_log!("udk_compress_from_memory: patch applied successfully");
    }

    debug_log!("udk_compress_from_memory::init done");

    Ok(())
}
