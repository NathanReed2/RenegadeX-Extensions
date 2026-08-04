//! Detects foreign inline hooks in `udk.exe`'s `.text`.
//!
//! Every UE3 cheat of consequence installs an inline hook - overwhelmingly on
//! `UObject::ProcessEvent`, which is how UnrealScript events get intercepted and
//! script functions get called from outside. Installing one means writing a jump
//! over the target's first bytes. This module watches for exactly that.
//!
//! # How the baseline is chosen
//!
//! Two obvious baselines are both wrong:
//!
//! - *The bytes on disk* would flag our own 33 detours as foreign, so it would
//!   need a hand-maintained whitelist that silently rots the moment somebody
//!   adds or moves a hook.
//! - *A hardcoded table of RVAs* would go blind the moment the target binary
//!   changes, while still cheerfully reporting "clean" - the worst possible
//!   failure mode for a detector.
//!
//! Instead the baseline is a snapshot of **live memory taken after our own hooks
//! are installed**. Our detours are therefore part of the baseline by
//! construction: no whitelist to maintain, and new hooks are picked up for free.
//! Anything that changes *after* that snapshot is, by definition, not ours.
//!
//! The snapshot is also diffed against the file on disk. In a stock `udk.exe`
//! that difference should be precisely our own hook sites, so the count is a
//! cheap sanity check - and a cheat that hooked *before* us shows up there
//! rather than hiding inside the baseline.
//!
//! # What this is and is not
//!
//! This runs inside the process it is inspecting, so anyone who can hook the
//! game can also disable this. It is a cost imposer, not a wall: it invalidates
//! the existing stock of UE3 cheats and forces them to be rebuilt. Treat a
//! report as a signal to be judged server-side, never as proof, and never let
//! the client act on it - see [`report`].

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::dll::UDK_RANGE;
use crate::udk_log::{log, LogType};

/// Bytes compared per function. An inline hook has to clobber the first
/// instruction, and the longest common patch (`mov rax, imm64; jmp rax`) is 12,
/// so 16 covers every practical encoding without inflating the snapshot.
const PROLOGUE_LEN: usize = 16;

/// How long to wait before snapshotting, so lazily-installed hooks (the D3D9
/// device hooks only land once a device exists) are already in place.
const BASELINE_DELAY: Duration = Duration::from_secs(60);

/// Sweep period. The cost is a ~1.6 MB read, so this is not load bearing.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Guards against reporting the same site over and over once something is hooked.
static REPORTED: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

/// One watched location: an RVA and its first [`PROLOGUE_LEN`] bytes.
#[derive(Clone, Copy)]
struct Site {
    rva: u32,
    bytes: u128,
}

pub fn init() -> Result<()> {
    // The sweep owns no pointers: it re-derives them from the cached module
    // range, so nothing here has to be Send.
    std::thread::Builder::new()
        .name("renx-hook-guard".into())
        .spawn(guard_thread)
        .map_err(|e| anyhow!("failed to spawn hook guard thread: {e}"))?;
    Ok(())
}

fn guard_thread() {
    std::thread::sleep(BASELINE_DELAY);

    let (base, image_size) = match UDK_RANGE.get() {
        Some(r) => (r.start, r.end - r.start),
        None => {
            log(LogType::Warning, "hook guard: UDK range unavailable");
            return;
        }
    };

    let functions = match function_rvas() {
        Ok(f) if !f.is_empty() => f,
        Ok(_) => {
            log(LogType::Warning, "hook guard: .pdata listed no functions");
            return;
        }
        Err(e) => {
            log(LogType::Warning, &format!("hook guard: {e}"));
            return;
        }
    };

    // Snapshot live memory. This is the baseline everything is judged against.
    let baseline = snapshot(base, image_size, &functions);
    if baseline.is_empty() {
        log(LogType::Warning, "hook guard: baseline snapshot was empty");
        return;
    }

    // Sanity check against the file: in a stock binary the only differences
    // should be our own detours. A wildly different count means either the
    // binary is not the one we expect, or something hooked before we did.
    let preexisting = match diff_against_disk(&baseline) {
        Ok(n) => n,
        Err(e) => {
            log(LogType::Warning, &format!("hook guard: disk diff failed: {e}"));
            usize::MAX
        }
    };

    report(&format!(
        "{{\"ev\":\"baseline\",\"functions\":{},\"patched_vs_disk\":{}}}",
        baseline.len(),
        preexisting as i64
    ));

    ARMED.store(true, Ordering::Relaxed);

    loop {
        std::thread::sleep(SWEEP_INTERVAL);
        sweep(base, image_size, &baseline);
    }
}

/// Compare current memory against the baseline and report any drift.
fn sweep(base: usize, image_size: usize, baseline: &[Site]) {
    let mut hits = 0usize;

    for site in baseline {
        let addr = base + site.rva as usize;
        if site.rva as usize + PROLOGUE_LEN >= image_size {
            continue;
        }
        let now = unsafe { read_u128(addr) };
        if now == site.bytes {
            continue;
        }

        hits += 1;
        // Report a bounded number of distinct sites; a cheat that rewrites a
        // large region should not turn into thousands of log lines.
        if REPORTED.fetch_add(1, Ordering::Relaxed) < 32 {
            report(&format!(
                "{{\"ev\":\"hook\",\"rva\":\"0x{:X}\",\"was\":\"{:032X}\",\"now\":\"{:032X}\"}}",
                site.rva, site.bytes, now
            ));
        }
    }

    if hits > 0 {
        log(
            LogType::Warning,
            &format!("hook guard: {hits} function(s) modified since baseline"),
        );
    }
}

/// Read the first bytes of every function out of the mapped image.
fn snapshot(base: usize, image_size: usize, functions: &[u32]) -> Vec<Site> {
    let mut out = Vec::with_capacity(functions.len());
    for &rva in functions {
        if rva as usize + PROLOGUE_LEN >= image_size {
            continue;
        }
        out.push(Site {
            rva,
            bytes: unsafe { read_u128(base + rva as usize) },
        });
    }
    out
}

/// Count how many baseline sites differ from the same bytes on disk.
///
/// `.text` is mapped verbatim apart from relocations, and this image carries
/// exactly one relocation inside `.text`, so a mismatch here means a patch
/// rather than a fixup. The count is informational: it should equal the number
/// of hooks this DLL installed.
fn diff_against_disk(baseline: &[Site]) -> Result<usize> {
    let path = std::env::current_exe()?;
    let mut file = File::open(path)?;
    let (sections, _) = read_sections(&mut file)?;

    let mut differing = 0usize;
    let mut buf = [0u8; PROLOGUE_LEN];
    for site in baseline {
        let Some(offset) = rva_to_offset(&sections, site.rva) else {
            continue;
        };
        file.seek(SeekFrom::Start(offset))?;
        if file.read_exact(&mut buf).is_err() {
            continue;
        }
        if u128::from_le_bytes(buf) != site.bytes {
            differing += 1;
        }
    }
    Ok(differing)
}

#[inline]
unsafe fn read_u128(addr: usize) -> u128 {
    // `.text` is mapped readable for the life of the process; this only ever
    // reads inside the module range the caller bounds-checked.
    std::ptr::read_unaligned(addr as *const u128)
}

/// A PE section, as far as this module cares.
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
}

fn rva_to_offset(sections: &[Section], rva: u32) -> Option<u64> {
    for s in sections {
        let span = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_address && rva < s.virtual_address.wrapping_add(span) {
            let delta = rva - s.virtual_address;
            if delta < s.raw_size {
                return Some(s.raw_pointer as u64 + delta as u64);
            }
            return None;
        }
    }
    None
}

/// Parse the section table and the exception directory location.
fn read_sections(file: &mut File) -> Result<(Vec<Section>, (u32, u32))> {
    let mut dos = [0u8; 0x40];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut dos)?;
    if &dos[..2] != b"MZ" {
        return Err(anyhow!("not a PE image"));
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap()) as u64;

    let mut coff = [0u8; 24];
    file.seek(SeekFrom::Start(e_lfanew))?;
    file.read_exact(&mut coff)?;
    if &coff[..4] != b"PE\0\0" {
        return Err(anyhow!("bad PE signature"));
    }
    let num_sections = u16::from_le_bytes(coff[6..8].try_into().unwrap()) as usize;
    let opt_size = u16::from_le_bytes(coff[20..22].try_into().unwrap()) as u64;

    // Optional header: only the exception directory (index 3) is needed.
    let opt_off = e_lfanew + 24;
    let mut magic = [0u8; 2];
    file.seek(SeekFrom::Start(opt_off))?;
    file.read_exact(&mut magic)?;
    if u16::from_le_bytes(magic) != 0x20B {
        return Err(anyhow!("not a PE32+ image"));
    }
    let mut dir = [0u8; 8];
    file.seek(SeekFrom::Start(opt_off + 112 + 3 * 8))?;
    file.read_exact(&mut dir)?;
    let exception = (
        u32::from_le_bytes(dir[0..4].try_into().unwrap()),
        u32::from_le_bytes(dir[4..8].try_into().unwrap()),
    );

    let mut sections = Vec::with_capacity(num_sections);
    let sec_off = opt_off + opt_size;
    let mut raw = [0u8; 40];
    for i in 0..num_sections {
        file.seek(SeekFrom::Start(sec_off + (i * 40) as u64))?;
        file.read_exact(&mut raw)?;
        sections.push(Section {
            virtual_size: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
            virtual_address: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
            raw_size: u32::from_le_bytes(raw[16..20].try_into().unwrap()),
            raw_pointer: u32::from_le_bytes(raw[20..24].try_into().unwrap()),
        });
    }
    Ok((sections, exception))
}

/// Every function start listed in `.pdata`.
///
/// x64 PE images describe each non-leaf function with a `RUNTIME_FUNCTION`, so
/// this is an authoritative function list straight out of the binary - no
/// symbols, no hardcoded addresses, and it re-derives itself if the target
/// binary is ever replaced. Chained fragments are kept as-is: each one is a real
/// code location and is worth watching in its own right.
fn function_rvas() -> Result<Vec<u32>> {
    let path = std::env::current_exe()?;
    let mut file = File::open(path)?;
    let (sections, (pdata_rva, pdata_size)) = read_sections(&mut file)?;
    if pdata_rva == 0 || pdata_size == 0 {
        return Err(anyhow!("image has no exception directory"));
    }
    let offset = rva_to_offset(&sections, pdata_rva).ok_or_else(|| anyhow!("bad .pdata rva"))?;

    let mut raw = vec![0u8; pdata_size as usize];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut raw)?;

    let mut out = Vec::with_capacity(raw.len() / 12);
    for entry in raw.chunks_exact(12) {
        let begin = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        let end = u32::from_le_bytes(entry[4..8].try_into().unwrap());
        if begin != 0 && end > begin {
            out.push(begin);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// The single place a finding leaves this module.
///
/// Deliberately does not kick, crash, or tell the player anything: a cheater who
/// learns they were detected just fixes their cheat, and the process they are
/// being told from is one they control. Findings go to `renxhook-guard.jsonl`
/// next to `udk.exe` and to the UDK log.
///
/// **This is the seam to wire a network report to.** Until it reports somewhere
/// the operator can see, only the player learns anything - which is backwards.
/// When adding one, send raw observations rather than a verdict, have the server
/// judge, and treat a client that stops reporting the same as one that fails.
fn report(line: &str) {
    log(LogType::Warning, &format!("hook guard: {line}"));

    let path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("renxhook-guard.jsonl")));

    if let Some(path) = path {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

/// Whether the baseline has been taken and sweeping is live.
#[allow(dead_code)]
pub fn is_armed() -> bool {
    ARMED.load(Ordering::Relaxed)
}
