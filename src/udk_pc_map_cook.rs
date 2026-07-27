//! Keeps PC map cooks below UE3's signed 32-bit package-offset ceiling.
//!
//! UCookPackagesCommandlet::PrepPackageForObjectCooking normally responds to
//! a seek-free map by force-exporting every loaded dependency into that map.
//! RenX-MenuMap crosses 2 GiB while serializing those exports, at which point
//! archive positions wrap negative and SavePackage discards the cooked map.
//!
//! PC can load ordinary cooked-package imports from disk. During an explicit
//! CookPackages -platform=PC run, this detour bypasses only the blanket
//! dependency force-export block for map packages. The caller still treats
//! the map as seek-free for naming, localization, cleanup, and compression;
//! script, startup, and standalone seek-free packages remain unchanged.

use crate::dll::{get_udk_ptr, UDK_RANGE};
use crate::patch_utils::debug_log;
#[cfg(target_arch = "x86_64")]
use crate::patch_utils::find_signature_offset;
use anyhow::Context;
use retour::RawDetour;
use std::ffi::c_void;
use std::sync::OnceLock;

/// Exact target RVA of UCookPackagesCommandlet::PrepPackageForObjectCooking.
#[cfg(target_arch = "x86_64")]
const PREP_PACKAGE_KNOWN_OFFSET: usize = 0x011D_9C40;

/// Unique entry signature verified in the copied RenX UDK.exe.
#[cfg(target_arch = "x86_64")]
const PREP_PACKAGE_SIG: [u8; 47] = [
    0x48, 0x8B, 0xC4, 0x48, 0x89, 0x48, 0x08, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
    0x48, 0x83, 0xEC, 0x60, 0x48, 0xC7, 0x44, 0x24, 0x30, 0xFE, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x58,
    0x10, 0x48, 0x89, 0x68, 0x18, 0x48, 0x89, 0x70, 0x20, 0x41, 0x8B, 0xF1, 0x45, 0x8B, 0xF0,
];

const COOK_PLATFORM_OFFSET: usize = 0xC4;
const PACKAGE_FLAGS_OFFSET: usize = 0x118;

const PLATFORM_WINDOWS: u32 = 0x0000_0001;
const PKG_CONTAINS_MAP: u32 = 0x0002_0000;
const PKG_REQUIRE_IMPORTS_ALREADY_LOADED: u32 = 0x0080_0000;
const PKG_STORE_COMPRESSED: u32 = 0x0200_0000;

type PrepPackageFn = extern "C" fn(*mut c_void, *mut c_void, u32, u32, u32, u32, u32, u32);

static PREP_PACKAGE_HOOK: OnceLock<RawDetour> = OnceLock::new();

fn is_explicit_pc_cook() -> bool {
    let args: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().to_ascii_lowercase())
        .collect();

    let is_cook = args
        .iter()
        .any(|arg| arg.trim_start_matches(['-', '/']) == "cookpackages");
    let is_pc = args.iter().any(|arg| {
        matches!(
            arg.trim_start_matches(['-', '/']),
            "platform=pc" | "platform:pc"
        )
    }) || args.windows(2).any(|pair| {
        pair[0].trim_start_matches(['-', '/']) == "platform"
            && pair[1].trim_start_matches(['-', '/']) == "pc"
    });

    is_cook && is_pc
}

fn pc_map_flags(flags: u32, fully_compressed: bool) -> u32 {
    let mut result = flags & !PKG_REQUIRE_IMPORTS_ALREADY_LOADED;
    if !fully_compressed {
        result |= PKG_STORE_COMPRESSED;
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn call_original(
    commandlet: *mut c_void,
    package: *mut c_void,
    should_be_seek_free: u32,
    should_be_fully_compressed: u32,
    is_native_script: u32,
    is_combined_startup: u32,
    strip_everything_but_textures: u32,
    process_shader_caches: u32,
) {
    let hook = PREP_PACKAGE_HOOK
        .get()
        .expect("PrepPackageForObjectCooking detour must be initialized before it can fire");
    let original: PrepPackageFn = unsafe { std::mem::transmute(hook.trampoline()) };
    original(
        commandlet,
        package,
        should_be_seek_free,
        should_be_fully_compressed,
        is_native_script,
        is_combined_startup,
        strip_everything_but_textures,
        process_shader_caches,
    );
}

#[allow(clippy::too_many_arguments)]
extern "C" fn prep_package_hook(
    commandlet: *mut c_void,
    package: *mut c_void,
    should_be_seek_free: u32,
    should_be_fully_compressed: u32,
    is_native_script: u32,
    is_combined_startup: u32,
    strip_everything_but_textures: u32,
    process_shader_caches: u32,
) {
    let is_pc_map = if commandlet.is_null() || package.is_null() || should_be_seek_free == 0 {
        false
    } else {
        unsafe {
            let platform = ((commandlet as *const u8).add(COOK_PLATFORM_OFFSET) as *const u32)
                .read_unaligned();
            let flags =
                ((package as *const u8).add(PACKAGE_FLAGS_OFFSET) as *const u32).read_unaligned();
            platform == PLATFORM_WINDOWS && flags & PKG_CONTAINS_MAP != 0
        }
    };

    if !is_pc_map {
        call_original(
            commandlet,
            package,
            should_be_seek_free,
            should_be_fully_compressed,
            is_native_script,
            is_combined_startup,
            strip_everything_but_textures,
            process_shader_caches,
        );
        return;
    }

    debug_log!(
        "udk_pc_map_cook: retaining package imports for PC map at 0x{:X}",
        package as usize
    );

    unsafe {
        let flags = (package as *mut u8).add(PACKAGE_FLAGS_OFFSET) as *mut u32;
        flags.write_unaligned(pc_map_flags(
            flags.read_unaligned(),
            should_be_fully_compressed != 0,
        ));

        // FALSE skips only PrepPackageForObjectCooking's seek-free setup and
        // blanket RF_ForceTagExp loop. The caller retains its original TRUE.
        call_original(
            commandlet,
            package,
            0,
            should_be_fully_compressed,
            is_native_script,
            is_combined_startup,
            strip_everything_but_textures,
            process_shader_caches,
        );

        // Defensive: an imported-content map must never demand that every
        // import was preloaded as if it were still self-contained.
        flags.write_unaligned(flags.read_unaligned() & !PKG_REQUIRE_IMPORTS_ALREADY_LOADED);
    }
}

pub fn init() -> anyhow::Result<()> {
    debug_log!("udk_pc_map_cook::init start");

    if !is_explicit_pc_cook() {
        debug_log!("udk_pc_map_cook: not an explicit -platform=PC CookPackages run; skipped");
        return Ok(());
    }

    #[cfg(target_arch = "x86_64")]
    {
        let _range = UDK_RANGE.get().context("UDK_RANGE not set")?;
        let offset = find_signature_offset(&PREP_PACKAGE_SIG, PREP_PACKAGE_KNOWN_OFFSET, 0)
            .0
            .context("Failed to find PrepPackageForObjectCooking signature")?;
        let udk = get_udk_ptr();

        debug_log!("udk_pc_map_cook: PrepPackageForObjectCooking signature at RVA 0x{offset:X}");

        unsafe {
            let hook = RawDetour::new(udk.add(offset) as *const (), prep_package_hook as *const ())
                .context("Failed to set up PrepPackageForObjectCooking detour")?;
            PREP_PACKAGE_HOOK.set(hook).map_err(|_| {
                anyhow::anyhow!("PrepPackageForObjectCooking detour already initialized")
            })?;
            PREP_PACKAGE_HOOK
                .get()
                .context("PrepPackageForObjectCooking detour was not retained")?
                .enable()
                .context("Failed to enable PrepPackageForObjectCooking detour")?;
        }
    }

    debug_log!("udk_pc_map_cook::init done");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{pc_map_flags, PKG_REQUIRE_IMPORTS_ALREADY_LOADED, PKG_STORE_COMPRESSED};

    #[test]
    fn imported_pc_map_is_compressed_but_does_not_require_preloaded_imports() {
        let result = pc_map_flags(PKG_REQUIRE_IMPORTS_ALREADY_LOADED, false);
        assert_eq!(result & PKG_REQUIRE_IMPORTS_ALREADY_LOADED, 0);
        assert_ne!(result & PKG_STORE_COMPRESSED, 0);
    }

    #[test]
    fn fully_compressed_map_does_not_gain_export_compression() {
        let result = pc_map_flags(PKG_REQUIRE_IMPORTS_ALREADY_LOADED, true);
        assert_eq!(result & PKG_REQUIRE_IMPORTS_ALREADY_LOADED, 0);
        assert_eq!(result & PKG_STORE_COMPRESSED, 0);
    }
}
