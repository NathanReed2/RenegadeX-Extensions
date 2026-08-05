use std::io::{self, ErrorKind};
use std::os::windows::fs::FileExt;
use std::sync::OnceLock;
use std::{fs::File, ops::Range};

use crate::{post_udk_init, udk_log};
use sha2::{Digest, Sha256};

use windows::{
    core::Error,
    Win32::{
        Foundation::{HANDLE, HINSTANCE},
        System::{
            LibraryLoader::GetModuleHandleA,
            ProcessStatus::{K32GetModuleInformation, MODULEINFO},
            SystemServices::{
                DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
            },
            Threading::GetCurrentProcess,
        },
    },
};

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: usize,
) -> i32 {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            dll_attach();
            if let Err(error) = post_udk_init() {
                udk_log::log(
                    udk_log::LogType::Error,
                    &format!("An error occurred initializing the library: {}", error),
                )
            }
        }
        DLL_PROCESS_DETACH => {
            #[cfg(target_arch = "x86_64")]
            crate::udk_mcp::exceptions::mark_clean_shutdown();
        }

        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}

        _ => return 0,
    }

    1
}

/// Compact constants for locating the section table in a PE file.
const DOS_HEADER_SIZE: usize = 64;
const PE_HEADER_SIZE: usize = 24;
const SECTION_HEADER_SIZE: u64 = 40;

fn invalid_pe(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let position = offset
            .checked_add(filled as u64)
            .ok_or_else(|| invalid_pe("file offset overflow"))?;
        let read = file.seek_read(&mut buffer[filled..], position)?;
        if read == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        filled += read;
    }
    Ok(())
}

fn text_file_range(file: &File) -> io::Result<Range<u64>> {
    let mut dos_header = [0u8; DOS_HEADER_SIZE];
    read_exact_at(file, &mut dos_header, 0)?;
    if &dos_header[..2] != b"MZ" {
        return Err(invalid_pe("missing DOS signature"));
    }

    let pe_offset = u32::from_le_bytes(dos_header[0x3c..0x40].try_into().unwrap()) as u64;
    let mut pe_header = [0u8; PE_HEADER_SIZE];
    read_exact_at(file, &mut pe_header, pe_offset)?;
    if &pe_header[..4] != b"PE\0\0" {
        return Err(invalid_pe("missing PE signature"));
    }

    let section_count = u16::from_le_bytes(pe_header[6..8].try_into().unwrap()) as u64;
    let optional_header_size = u16::from_le_bytes(pe_header[20..22].try_into().unwrap()) as u64;
    let section_table = pe_offset
        .checked_add(PE_HEADER_SIZE as u64)
        .and_then(|offset| offset.checked_add(optional_header_size))
        .ok_or_else(|| invalid_pe("section table overflow"))?;
    let file_length = file.metadata()?.len();

    for index in 0..section_count {
        let section_offset = section_table
            .checked_add(
                index
                    .checked_mul(SECTION_HEADER_SIZE)
                    .ok_or_else(|| invalid_pe("section offset overflow"))?,
            )
            .ok_or_else(|| invalid_pe("section offset overflow"))?;
        let mut section = [0u8; SECTION_HEADER_SIZE as usize];
        read_exact_at(file, &mut section, section_offset)?;

        if &section[..5] != b".text" || section[5..8].iter().any(|byte| *byte != 0) {
            continue;
        }

        let size = u32::from_le_bytes(section[16..20].try_into().unwrap()) as u64;
        let start = u32::from_le_bytes(section[20..24].try_into().unwrap()) as u64;
        let end = start
            .checked_add(size)
            .ok_or_else(|| invalid_pe("text range overflow"))?;
        if end > file_length {
            return Err(invalid_pe("text range outside file"));
        }
        return Ok(start..end);
    }

    Err(io::Error::new(ErrorKind::NotFound, "missing .text section"))
}

fn hash_file_range(file: &File, range: Range<u64>) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];
    let mut offset = range.start;
    let mut remaining = range.end - range.start;

    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        read_exact_at(file, &mut buffer[..length], offset)?;
        hasher.update(&buffer[..length]);
        offset += length as u64;
        remaining -= length as u64;
    }

    Ok(hasher.finalize().into())
}

/// Called upon DLL attach. Verifies the UDK and initializes its hooks.
fn dll_attach() {
    let process = unsafe { GetCurrentProcess() };
    let module: windows::Win32::Foundation::HMODULE =
        unsafe { GetModuleHandleA(None) }.expect("Couldn't get Module Handle for the UDK process");

    let exe_information = get_module_information(process, module.into())
        .expect("Failed to get module information for UDK");
    let udk_range = Range {
        start: exe_information.lpBaseOfDll as usize,
        end: exe_information.lpBaseOfDll as usize + exe_information.SizeOfImage as usize,
    };

    // Now that we're attached, let's hash the UDK executable.
    // If the hash does not match what we think it should be, do not attach detours.
    let exe_file = File::open(std::env::current_exe().unwrap()).unwrap();
    let text_range = text_file_range(&exe_file).expect("Failed to locate the UDK .text section");
    let hash =
        hash_file_range(&exe_file, text_range).expect("Failed to hash the UDK .text section");

    // Ensure the hash matches a known hash.
    if hash[..] != UDK_KNOWN_HASH {
        panic!("Unknown UDK hash");
    }

    // Cache the UDK slice.
    UDK_RANGE.set(udk_range).unwrap();
}

#[cfg(target_arch = "x86_64")]
const UDK_KNOWN_HASH: [u8; 32] = [
    0xF0, 0x2F, 0x13, 0x1E, 0xF2, 0xE, 0xA3, 0xCE, 0xD1, 0xCE, 0x93, 0x14, 0x53, 0xDE, 0x37, 0xB9,
    0x51, 0x1B, 0x92, 0xD0, 0xBA, 0x7C, 0x7, 0x27, 0x5B, 0xA0, 0xAE, 0xFB, 0x7D, 0xFB, 0xE3, 0xE3,
];

#[cfg(target_arch = "x86")]
const UDK_KNOWN_HASH: [u8; 32] = [
    0x70, 0xC2, 0x91, 0x73, 0xE0, 0x0F, 0x2F, 0xCA, 0x5E, 0xBB, 0x92, 0x76, 0x00, 0x43, 0xDF, 0x70,
    0xE0, 0xC0, 0x16, 0xFA, 0xB2, 0x80, 0xF8, 0x20, 0x88, 0x31, 0xD9, 0x99, 0xFE, 0xF0, 0xFF, 0x33,
];

/// Cached memory range for UDK.exe
pub static UDK_RANGE: OnceLock<Range<usize>> = OnceLock::new();

/// Return the base pointer for UDK.exe
pub fn get_udk_ptr() -> *const u8 {
    let range = UDK_RANGE.get().unwrap();

    // TODO: Once Rust gets better raw slice support, we should return a `*const [u8]` instead.
    range.start as *const u8
}

/// Wrapped version of the Win32 GetModuleInformation.
fn get_module_information(process: HANDLE, module: HINSTANCE) -> windows::core::Result<MODULEINFO> {
    let mut module_info = MODULEINFO {
        ..Default::default()
    };

    match unsafe {
        K32GetModuleInformation(
            process,
            module,
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
        .as_bool()
    } {
        true => Ok(module_info),
        false => Err(Error::from_win32()),
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_file_range, text_file_range, File};

    #[test]
    fn locates_and_hashes_current_pe_text() {
        let executable = File::open(std::env::current_exe().unwrap()).unwrap();
        let range = text_file_range(&executable).unwrap();

        assert!(range.start < range.end);
        assert_ne!(hash_file_range(&executable, range).unwrap(), [0; 32]);
    }
}
