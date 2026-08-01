//! Lets a multithreaded cook (`-Processes=N`) actually use every hardware
//! thread, and lowers the unattended default from 5 child processes to 4.
//!
//! # What the engine does
//!
//! `UCookPackagesCommandlet::StartChildren` (`UnrealEd/Src/UnContentCookers.cpp`)
//! decides how many child cookers a `-Processes=N` run gets. Stock UE3:
//!
//! ```c
//! INT NumChildProcesses = 5;
//! UBOOL Overridden = FALSE;
//! if (Parse(appCmdLine(), TEXT("Processes="),NumChildProcesses)) { Overridden = TRUE; }
//! ...
//! INT RamLimit = Max<INT>(2,INT(FLOAT(GPhysicalGBRam - 2)/2.2f));
//! NumChildProcesses = Min<INT>(NumChildProcesses,RamLimit);
//! NumChildProcesses = Min<INT>(NumChildProcesses,GNumHardwareThreads - 1);
//! NumChildProcesses = Min<INT>(NumChildProcesses,NumFiles);
//! NumChildProcesses = Clamp<INT>(NumChildProcesses,1,48);
//! ```
//!
//! The `Clamp(1,48)` ceiling that looks like the limit almost never binds. The
//! two that actually do are `RamLimit` and `GNumHardwareThreads - 1`. On a
//! 16-thread / 32 GB machine they compute to:
//!
//! - `RamLimit` = `Max(2, (31 - 2) / 2.2)` = **13**
//! - `GNumHardwareThreads - 1` = **15**
//!
//! so `-Processes=16` silently yields 13. Both have to be lifted to reach 16;
//! raising the 48 would change nothing.
//!
//! # The patches
//!
//! Three edits, all inside `StartChildren`, none changing instruction length.
//!
//! 1. **Default 5 -> 4.** `MOV dword ptr [RSP+0x40], 5` is the initialiser that
//!    `Parse` overwrites when `-Processes=` is present, so this only moves the
//!    unattended default; an explicit `-Processes=N` still wins.
//!
//! 2. **Drop the `RamLimit` clamp.** The compiled sequence is
//!
//!    ```asm
//!    MOV    EAX, dword ptr [RSP + 0x40]   ; EAX = NumChildProcesses
//!    CMP    EAX, ECX                      ; ECX = Max(2, RamLimit)
//!    CMOVLE ECX, EAX                      ; ECX = Min(N, RamLimit)
//!    ```
//!
//!    rewritten to load `NumChildProcesses` straight into `ECX` and pad the
//!    comparison out with `NOP`s, so `ECX` carries `N` unclamped:
//!
//!    ```asm
//!    MOV ECX, dword ptr [RSP + 0x40]
//!    NOP ; NOP ; NOP ; NOP ; NOP
//!    ```
//!
//!    `EAX` is left holding the `2` from the preceding `Max` instead of `N`,
//!    which is harmless: the next instruction to touch it,
//!    `LEA EAX,[RDX + ...]` in patch 3, overwrites it before any read.
//!
//!    This clamp is removed rather than relaxed because the `/2.2` divisor is
//!    not a constant this module can safely edit. It is the shared `float`
//!    `0.45454544` at `.rdata` `0x1425B80DC`, which **26 xrefs across 20+
//!    unrelated functions** read - rewriting it would perturb all of them.
//!
//! 3. **`GNumHardwareThreads - 1` -> `GNumHardwareThreads`.** `LEA EAX,[RDX-1]`
//!    (`8D 42 FF`) becomes `LEA EAX,[RDX+0]` (`8D 42 00`) - a one-byte edit at
//!    the same length, since the encoding already carries a `disp8`.
//!
//! What survives: `Min(N, NumFiles)`, `Clamp(N, 1, 48)`, the `< 2 processes`
//! and `< 2 jobs` early-outs, and the `< 3 hardware threads` / `< 7 GB RAM`
//! refusals (those last two are already skipped when `-Processes=` is given,
//! which is stock behaviour and not changed here).
//!
//! # Cost
//!
//! Removing the RAM clamp removes a real guard. That `/2.2` encodes roughly
//! 2.2 GB of headroom per child, and a child that runs out of memory dies
//! inside `SavePackage` - which takes down every sibling and the whole cook,
//! behind the parent's uninformative `Child process crashed:` (the same
//! failure surface [`crate::udk_mt_shader_sandbox`] documents). On 32 GB,
//! `-Processes=16` leaves under 2 GB per child. The default stays at a
//! conservative 4 precisely so that the unattended path is unaffected; the
//! high counts are opt-in through `-Processes=N`.
//!
//! # Provenance
//!
//! RVAs read from `RenXSDK/UDK.exe`, whose `.text` hash is pinned in `dll.rs`.
//! `StartChildren` is `FUN_1411BC6E0` there, matched from the symbol-bearing
//! 2013 build (`StartChildren @ 141146FF0`) by its `-Processes=` parse string
//! and the four `*** Ignoring mutithreaded, ...` literals, and confirmed to
//! decompile line-for-line against the 2013 source above.

#![cfg(target_arch = "x86_64")]

use anyhow::{bail, Context};
use windows::Win32::System::{
    Diagnostics::Debug::FlushInstructionCache, Threading::GetCurrentProcess,
};

use crate::dll::UDK_RANGE;
use crate::patch_utils::debug_log;

/// A byte range whose current contents are verified before anything is written.
struct CodePatch {
    name: &'static str,
    rva: usize,
    expected: &'static [u8],
    replacement: &'static [u8],
}

const PATCHES: &[CodePatch] = &[
    CodePatch {
        name: "MT cook default process count 5 -> 4",
        // MOV dword ptr [RSP + 0x40], 5   (the NumChildProcesses initialiser)
        rva: 0x0011_BC725,
        expected: &[0xC7, 0x44, 0x24, 0x40, 0x05, 0x00, 0x00, 0x00],
        replacement: &[0xC7, 0x44, 0x24, 0x40, 0x04, 0x00, 0x00, 0x00],
    },
    CodePatch {
        name: "MT cook RAM-budget process clamp",
        // MOV EAX,[RSP+0x40] / CMP EAX,ECX / CMOVLE ECX,EAX
        //   -> MOV ECX,[RSP+0x40] / NOP x5
        rva: 0x0011_BC865,
        expected: &[0x8B, 0x44, 0x24, 0x40, 0x3B, 0xC1, 0x0F, 0x4E, 0xC8],
        replacement: &[0x8B, 0x4C, 0x24, 0x40, 0x90, 0x90, 0x90, 0x90, 0x90],
    },
    CodePatch {
        name: "MT cook hardware-thread process clamp",
        // LEA EAX,[RDX + -1]  ->  LEA EAX,[RDX + 0]
        rva: 0x0011_BC874,
        expected: &[0x8D, 0x42, 0xFF],
        replacement: &[0x8D, 0x42, 0x00],
    },
];

fn image_address(rva: usize, length: usize, name: &str) -> anyhow::Result<*mut u8> {
    let range = UDK_RANGE.get().context("UDK_RANGE not set")?;
    let address = range
        .start
        .checked_add(rva)
        .with_context(|| format!("{name} address overflow"))?;
    let end = address
        .checked_add(length)
        .with_context(|| format!("{name} end overflow"))?;
    if end > range.end {
        bail!("{name} lies outside UDK.exe");
    }
    Ok(address as *mut u8)
}

fn patch_address(patch: &CodePatch) -> anyhow::Result<*mut u8> {
    if patch.expected.len() != patch.replacement.len() {
        bail!("{} changes instruction length", patch.name);
    }
    image_address(patch.rva, patch.expected.len(), patch.name)
}

/// Accepts an already-patched image so a second `init` is not an error.
fn validate(patch: &CodePatch) -> anyhow::Result<()> {
    let address = patch_address(patch)?;
    let actual = unsafe { std::slice::from_raw_parts(address, patch.expected.len()) };
    if actual != patch.expected && actual != patch.replacement {
        bail!(
            "{} validation failed at RVA 0x{:X}: expected {:02X?} or {:02X?}, found {:02X?}",
            patch.name,
            patch.rva,
            patch.expected,
            patch.replacement,
            actual
        );
    }
    Ok(())
}

fn write(patch: &CodePatch) -> anyhow::Result<()> {
    let address = patch_address(patch)?;
    let actual = unsafe { std::slice::from_raw_parts(address, patch.replacement.len()) };
    if actual == patch.replacement {
        return Ok(());
    }

    unsafe {
        let _guard = region::protect_with_handle(
            address,
            patch.replacement.len(),
            region::Protection::READ_WRITE_EXECUTE,
        )
        .with_context(|| format!("failed to make {} writable", patch.name))?;
        std::ptr::copy_nonoverlapping(
            patch.replacement.as_ptr(),
            address,
            patch.replacement.len(),
        );
        FlushInstructionCache(
            GetCurrentProcess(),
            Some(address.cast()),
            patch.replacement.len(),
        )
        .with_context(|| format!("failed to flush {} instructions", patch.name))?;
    }

    debug_log!("applied {} at UDK.exe+0x{:X}", patch.name, patch.rva);
    Ok(())
}

/// `StartChildren` is only reachable from a `cookpackages` commandlet, so the
/// game client's `.text` is left alone entirely.
fn is_cook_run() -> bool {
    std::env::args_os().any(|argument| {
        argument
            .to_string_lossy()
            .trim_start_matches(['-', '/'])
            .eq_ignore_ascii_case("cookpackages")
    })
}

/// Applies all three clamp edits, or none of them.
///
/// Nothing here logs through `udk_log`: this runs from `DllMain`, before UE3
/// has built `GLog`, and a `FOutputDevice` call at that point faults inside
/// UDK.exe and surfaces as `0xC0000142`.
pub fn init() -> anyhow::Result<()> {
    if !is_cook_run() {
        return Ok(());
    }

    // Verify every site before the first byte is written, so a binary that does
    // not match this module's expectations is left completely untouched rather
    // than half-patched.
    for patch in PATCHES {
        if let Err(error) = validate(patch) {
            debug_log!("udk_mt_cook_processes: refusing to install: {error:#}");
            return Ok(());
        }
    }
    for patch in PATCHES {
        write(patch)?;
    }

    debug_log!(
        "udk_mt_cook_processes: default 4 children, -Processes=N now bounded by \
         hardware threads rather than the 2.2GB/child RAM budget"
    );
    Ok(())
}
