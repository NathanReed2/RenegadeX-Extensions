//! Completes the private shader sandbox that a multithreaded cook child
//! (`-Processes=N`) runs out of, which `UCookPackagesCommandlet::PrepareShaderFiles`
//! populates only one directory level deep.
//!
//! # The crash this fixes
//!
//! A `-Processes=3` PC cook dies partway through with the parent reporting
//! nothing more useful than `appError called: Child process crashed:`, while the
//! child log (`CookPCServer_2.log` / `_3` / `_4`) carries the real error:
//!
//! ```text
//! Error: Failed to read file '..\..\UDKGame\CookedPC\Process_16fc\Shaders\Binaries\RealD\CommonDepth.bin' error ()
//! Critical: appError called: Couldn't load shader file 'RealD/CommonDepth.usf'
//! ```
//!
//! Only some maps trip it, because `RealD/CommonDepth.usf` is a stereo depth
//! shader that is pulled in only when a map's materials need that permutation
//! and it is not already cached. Observed dying on `CQ-Pharaoh`, `CQ-Phoenix`
//! and `CQ-Island_City`; `CQ-Bridge`, `CQ-Devastation` and `CQ-Haven` cook clean.
//!
//! # Root cause
//!
//! An MT child redirects its shader directory into a per-process sandbox and
//! then copies the engine's shaders into it (`UnrealEd/Src/UnContentCookers.cpp`,
//! `UCookPackagesCommandlet::PrepareShaderFiles`):
//!
//! ```c
//! appSetShaderDir(*(CookedDirForPerProcessData * TEXT("Shaders")));
//! FFilename UserShaderDir = FString(appBaseDir()) * appShaderDir();
//!
//! CopyFiles( ShaderDir,                    UserShaderDir,                    TEXT("*.*") );
//! CopyFiles( ShaderDir * TEXT("Binaries"), UserShaderDir * TEXT("Binaries"), TEXT("*.*") );
//! if( Platform == PLATFORM_Xbox360 ) { CopyFiles( ShaderDir * TEXT("Xbox360"), ... ); }
//! ```
//!
//! `CopyFiles` enumerates with `FindFiles(Results, *WildcardPattern, TRUE, FALSE)`
//! - files only, non-recursive - so `Engine\Shaders\Binaries\RealD\` is never
//! copied. `Engine\Shaders\Binaries\*.bin` (147 files here) arrives intact; the
//! `RealD` subdirectory beneath it does not.
//!
//! The reader has no fallback to the engine directory
//! (`Engine/Src/ShaderManager.cpp`, `LoadShaderSourceFile`):
//!
//! ```c
//! FFilename BinaryShaderFilename = FString(appBaseDir()) * appShaderDir() * TEXT("Binaries") * FFilename(Filename).GetBaseFilename(TRUE);
//! #if WITH_REALD
//! if (bRealDFile == TRUE) {
//!     BinaryShaderFilename = FString(appBaseDir()) * appShaderDir() * TEXT("Binaries") * TEXT("RealD") * FFilename(Filename).GetBaseFilename(TRUE);
//! }
//! #endif
//! ...
//! if ( !bLoadedSuccessfully ) { appErrorf(TEXT("Couldn't load shader file \'%s\'"),Filename); }
//! ```
//!
//! so the miss is fatal. Because the parent's `CheckForCrashedChildren()` kills
//! every sibling and calls `appErrorf` as soon as any one child dies, a single
//! map hitting this takes the whole cook down with it - including children that
//! had already finished their maps.
//!
//! # The fix
//!
//! Hook `appSetShaderDir` (`Core/Src/UnVcWin32.cpp`), which exists solely to
//! `appStrncpy` into the static `ShaderDir[1024]` buffer that `appShaderDir()`
//! returns:
//!
//! ```asm
//! 14029bf60  MOV  RDX, RCX                  ; Where
//! 14029bf63  LEA  RCX, [0x143456770]        ; ShaderDir
//! 14029bf6a  MOV  R8D, 0x400                ; 1024
//! 14029bf70  JMP  appStrncpy
//! ```
//!
//! It has exactly one caller in the engine - the `PrepareShaderFiles` line
//! above - so it fires once per MT child, at the moment the sandbox path is
//! chosen, and hands us that path directly. Reading the buffer *before* calling
//! the original yields the engine shader directory being redirected away from,
//! so neither path has to be assumed.
//!
//! After the original runs, every *subdirectory* of `<engine>\Shaders\Binaries`
//! is mirrored into `<sandbox>\Shaders\Binaries`, which is precisely the gap the
//! non-recursive `CopyFiles` leaves. Mirroring subdirectories generally, rather
//! than `RealD` by name, also covers any other nested shader binaries without
//! needing to know about them.
//!
//! Ordering is safe: the two `CopyFiles` calls run *after* `appSetShaderDir`
//! returns, and `CopyFiles` only does `MakeDirectory` plus per-file `Copy` - it
//! never deletes - so the subdirectories staged here survive, and they sit
//! beneath the level `CopyFiles` writes into, so nothing is clobbered either way.
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::dll::get_udk_ptr;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
#[cfg(target_arch = "x86_64")]
use crate::udk_log;
#[cfg(target_arch = "x86_64")]
use anyhow::Context;
#[cfg(target_arch = "x86_64")]
use retour::static_detour;
#[cfg(target_arch = "x86_64")]
use std::path::{Path, PathBuf};
#[cfg(target_arch = "x86_64")]
use std::sync::OnceLock;

/// Known static offset of `appSetShaderDir` in the 12791 (UDK-2015-01,
/// CL 2424394) x64 build.
#[cfg(target_arch = "x86_64")]
const APP_SET_SHADER_DIR_OFFSET: usize = 0x0029_BF60;

/// The whole of `appSetShaderDir`, a four-instruction tail call:
///
/// ```asm
/// MOV  RDX, RCX             ; Where
/// LEA  RCX, [ShaderDir]     ; rip-relative, -> 0x143456770
/// MOV  R8D, 0x400           ; ARRAY_COUNT(ShaderDir)
/// JMP  appStrncpy
/// ```
///
/// Verified unique in the 12791 x64 image (exactly one match). Both
/// displacements are included because [`crate::dll`] pins this DLL to one exact
/// `UDK.exe` by `.text` hash, so they are fixed.
#[cfg(target_arch = "x86_64")]
const APP_SET_SHADER_DIR_SIG: [u8; 21] = [
    0x48, 0x8B, 0xD1, // MOV RDX,RCX
    0x48, 0x8D, 0x0D, 0x06, 0xA8, 0x1B, 0x03, // LEA RCX,[rip+0x031BA806]
    0x41, 0xB8, 0x00, 0x04, 0x00, 0x00, // MOV R8D,0x400
    0xE9, 0x0B, 0xF1, 0xF2, 0xFF, // JMP appStrncpy
];

/// Offset of the `LEA`'s `disp32` field within [`APP_SET_SHADER_DIR_SIG`], and
/// the offset of the first byte after that `LEA` (what the displacement is
/// relative to). Used to recover the `ShaderDir` buffer from the instruction
/// itself rather than hardcoding a second address.
#[cfg(target_arch = "x86_64")]
const SHADER_DIR_LEA_DISPLACEMENT: usize = 6;
#[cfg(target_arch = "x86_64")]
const SHADER_DIR_LEA_END: usize = 10;

/// `ShaderDir[1024]`, per the `MOV R8D, 0x400` above.
#[cfg(target_arch = "x86_64")]
const SHADER_DIR_CAPACITY: usize = 1024;

/// Subdirectory of the shader directory that holds the compiled `.bin` shader
/// files, and the one `CopyFiles` populates non-recursively.
#[cfg(target_arch = "x86_64")]
const BINARIES_SUBDIRECTORY: &str = "Binaries";

/// Address of the engine's static `ShaderDir` buffer, recovered at init from
/// the `LEA` inside `appSetShaderDir`.
#[cfg(target_arch = "x86_64")]
static SHADER_DIR_BUFFER: OnceLock<usize> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
static_detour! {
    static AppSetShaderDirHook: extern "C" fn(*const u16);
}

#[cfg(target_arch = "x86_64")]
fn find_app_set_shader_dir_offset() -> Option<usize> {
    let (best, count) =
        find_signature_offset(&APP_SET_SHADER_DIR_SIG, APP_SET_SHADER_DIR_OFFSET, 0);
    debug_log!("appSetShaderDir signature matches: {count}");
    best
}

/// Reads a NUL-terminated UTF-16 string, bounded by [`SHADER_DIR_CAPACITY`] so
/// a missing terminator can't run away.
#[cfg(target_arch = "x86_64")]
unsafe fn read_wide(pointer: *const u16) -> Option<String> {
    if pointer.is_null() {
        return None;
    }

    let mut length = 0usize;
    while length < SHADER_DIR_CAPACITY && pointer.add(length).read_unaligned() != 0 {
        length += 1;
    }

    if length == 0 {
        return None;
    }

    Some(String::from_utf16_lossy(std::slice::from_raw_parts(
        pointer, length,
    )))
}

/// `appBaseDir()` - shader directories are stored relative to it.
#[cfg(target_arch = "x86_64")]
fn base_directory() -> Option<PathBuf> {
    Some(std::env::current_exe().ok()?.parent()?.to_path_buf())
}

/// Recursively copies `source` into `destination`, returning the number of
/// files copied.
#[cfg(target_arch = "x86_64")]
fn copy_tree(source: &Path, destination: &Path) -> std::io::Result<usize> {
    std::fs::create_dir_all(destination)?;

    let mut copied = 0usize;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());

        if entry.file_type()?.is_dir() {
            copied += copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
            copied += 1;
        }
    }

    Ok(copied)
}

/// Mirrors every subdirectory of `<engine>\Binaries` into `<sandbox>\Binaries`.
#[cfg(target_arch = "x86_64")]
fn mirror_binaries_subdirectories(engine_relative: &str, sandbox_relative: &str) {
    let Some(base) = base_directory() else {
        debug_log!("udk_mt_shader_sandbox: could not resolve appBaseDir()");
        return;
    };

    let source = base.join(engine_relative).join(BINARIES_SUBDIRECTORY);
    let destination = base.join(sandbox_relative).join(BINARIES_SUBDIRECTORY);

    let entries = match std::fs::read_dir(&source) {
        Ok(entries) => entries,
        Err(error) => {
            debug_log!(
                "udk_mt_shader_sandbox: cannot read {}: {error}",
                source.display()
            );
            return;
        }
    };

    let mut copied = 0usize;
    let mut mirrored = Vec::new();

    for entry in entries.flatten() {
        if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            continue;
        }

        let name = entry.file_name();
        match copy_tree(&entry.path(), &destination.join(&name)) {
            Ok(count) => {
                copied += count;
                mirrored.push(name.to_string_lossy().into_owned());
            }
            Err(error) => udk_log::log(
                udk_log::LogType::Error,
                &format!(
                    "failed to stage shader subdirectory '{}' into this cook child's sandbox \
                     ({}): {error}. If it holds shaders this child needs, the cook will die with \
                     \"Couldn't load shader file\".",
                    name.to_string_lossy(),
                    destination.display()
                ),
            ),
        }
    }

    if copied > 0 {
        udk_log::log(
            udk_log::LogType::Init,
            &format!(
                "staged {copied} shader binary file(s) from {} subdirectory/ies ({}) into this \
                 cook child's sandbox at {}. PrepareShaderFiles copies Shaders\\Binaries \
                 non-recursively, so without this a map needing RealD/CommonDepth.usf kills the \
                 child - and with it the whole multithreaded cook.",
                mirrored.len(),
                mirrored.join(", "),
                destination.display()
            ),
        );
    }
}

/// Hook for `appSetShaderDir(const TCHAR* Where)`.
///
/// Captures the shader directory being redirected away from, lets the original
/// install the new one, then fills in the subdirectories `PrepareShaderFiles`
/// will not copy. A redirect to the same directory is not a sandbox, so it is
/// left alone.
#[cfg(target_arch = "x86_64")]
fn app_set_shader_dir_hook(new_directory: *const u16) {
    let previous = SHADER_DIR_BUFFER
        .get()
        .and_then(|address| unsafe { read_wide(*address as *const u16) });

    AppSetShaderDirHook.call(new_directory);

    let Some(previous) = previous else {
        return;
    };
    let Some(sandbox) = (unsafe { read_wide(new_directory) }) else {
        return;
    };

    if sandbox.eq_ignore_ascii_case(&previous) {
        return;
    }

    debug_log!("udk_mt_shader_sandbox: shader dir '{previous}' -> '{sandbox}'");

    mirror_binaries_subdirectories(&previous, &sandbox);
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_mt_shader_sandbox::init start");

    #[cfg(target_arch = "x86_64")]
    {
        let udk = get_udk_ptr();

        let offset = find_app_set_shader_dir_offset()
            .context("Failed to find appSetShaderDir signature")?;

        debug_log!("appSetShaderDir hook offset selected: 0x{offset:X}");

        // Recover `ShaderDir` from the `LEA`'s rip-relative displacement:
        // target = (address of the byte after the LEA) + disp32.
        let displacement = i32::from_le_bytes(
            APP_SET_SHADER_DIR_SIG
                [SHADER_DIR_LEA_DISPLACEMENT..SHADER_DIR_LEA_DISPLACEMENT + 4]
                .try_into()
                .expect("displacement slice is 4 bytes"),
        );
        let buffer = (udk as usize)
            .checked_add(offset)
            .and_then(|address| address.checked_add(SHADER_DIR_LEA_END))
            .and_then(|address| address.checked_add_signed(displacement as isize))
            .context("ShaderDir buffer address out of range")?;

        debug_log!("udk_mt_shader_sandbox: ShaderDir buffer at 0x{buffer:X}");
        let _ = SHADER_DIR_BUFFER.set(buffer);

        unsafe {
            AppSetShaderDirHook
                .initialize(
                    std::mem::transmute(udk.add(offset)),
                    app_set_shader_dir_hook,
                )
                .context("Failed to setup appSetShaderDir hook")?;

            AppSetShaderDirHook.enable()?;
        }

        debug_log!("udk_mt_shader_sandbox: hook installed successfully");
    }

    debug_log!("udk_mt_shader_sandbox::init done");

    Ok(())
}
