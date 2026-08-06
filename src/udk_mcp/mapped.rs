//! A fixed-size record that outlives the process which wrote it.
//!
//! Two things in this bridge have to be readable after `UDK.exe` has *died*
//! rather than exited: the exception context, and what the bridge was in the
//! middle of doing. Both want the same storage - a file-backed mapping written
//! in place. Nothing has to be flushed for the contents to survive the process,
//! because the pages belong to the file rather than to the heap; the kernel
//! writes them back whether or not anyone is left to ask.
//!
//! The fallback matters as much as the mapping. If the file cannot be opened -
//! a read-only install directory, a full disk - the caller gets an ordinary heap
//! allocation and a recorded reason, and the current session works normally.
//! Losing post-mortem evidence is a degradation; refusing to start the bridge
//! over it would be a fault.
//!
//! # What this does not do
//!
//! It does not coordinate between processes. Two editors from one install map
//! the same file and write into each other's records. Every user of this module
//! stamps a session id, which keeps records attributable after the fact, but a
//! second editor can still evict the first one's history. Locking it down would
//! cost a named mutex and an error path for the loser, to defend a case - two
//! editors on one install - that the rest of the bridge does not support either.

use std::fs::{self, File, OpenOptions};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::Memory::{
            CreateFileMappingW, FlushViewOfFile, MapViewOfFile, FILE_MAP_ALL_ACCESS,
            MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
        },
    },
};

use super::assets;

/// A type whose all-zero bit pattern is a valid, empty value.
///
/// # Safety
///
/// Both backings hand out zeroed memory, and a mapping opened for the first
/// time is a file of zeroes, so every field has to read sensibly as zero. In
/// practice that means plain data: integers, atomics, byte arrays, and
/// `UnsafeCell`s of those. No references, no `NonZero`, no enum with a niche.
pub(super) unsafe trait Zeroable {}

enum Backing<T> {
    Mapped {
        _file: File,
        mapping: HANDLE,
        view: MEMORY_MAPPED_VIEW_ADDRESS,
    },
    /// Kept alive purely so the pointer handed out stays valid. Moving the `Box`
    /// into this variant does not move the allocation it points at.
    Heap { _block: Box<T> },
}

pub(super) struct Region<T> {
    pointer: *mut T,
    backing: Backing<T>,
    path: Option<PathBuf>,
    error: Option<String>,
}

// The region hands out a raw pointer and takes no position on how it is used;
// every caller publishes through atomics in the mapped structure itself, which
// is where the synchronisation actually lives.
unsafe impl<T> Send for Region<T> {}
unsafe impl<T> Sync for Region<T> {}

fn zeroed<T>() -> Box<T> {
    let mut value = Box::<T>::new_uninit();
    unsafe {
        value.as_mut_ptr().write_bytes(0, 1);
        value.assume_init()
    }
}

/// Beside the editor's own logs, so post-mortem evidence sits with the crash
/// dump and the launch log rather than somewhere a user has to be told about.
fn directory() -> Result<PathBuf, String> {
    let directory = assets::editor_log_directory()
        .or_else(|| std::env::current_exe().ok()?.parent().map(Path::to_path_buf))
        .ok_or_else(|| "could not choose a directory for the record".to_string())?;
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    Ok(directory)
}

impl<T: Zeroable> Region<T> {
    /// Opens `file_name` in the editor's log directory, falling back to memory.
    ///
    /// Never fails: a region that could not be persisted still works for the
    /// life of the process, and reports why through [`Region::error`].
    pub(super) fn open(file_name: &str) -> Region<T> {
        match Self::mapped(file_name) {
            Ok((backing, pointer, path)) => Region {
                pointer,
                backing,
                path: Some(path),
                error: None,
            },
            Err(error) => {
                let mut block = zeroed::<T>();
                let pointer = (&mut *block) as *mut T;
                Region {
                    pointer,
                    backing: Backing::Heap { _block: block },
                    path: None,
                    error: Some(error),
                }
            }
        }
    }

    fn mapped(file_name: &str) -> Result<(Backing<T>, *mut T, PathBuf), String> {
        let path = directory()?.join(file_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Stated rather than left to the default, because it is the whole
            // point: the previous session's contents are the payload, and
            // truncating on open would discard the evidence at the exact moment
            // a new session opens the file to read it.
            .truncate(false)
            .open(&path)
            .map_err(|error| error.to_string())?;
        let size = std::mem::size_of::<T>();
        // Also truncates a file left by a build whose record was larger, which
        // is the case the caller's own header check is about to notice.
        file.set_len(size as u64)
            .map_err(|error| error.to_string())?;
        let handle = HANDLE(file.as_raw_handle() as isize);
        let mapping =
            unsafe { CreateFileMappingW(handle, None, PAGE_READWRITE, 0, size as u32, PCWSTR::null()) }
                .map_err(|error| error.to_string())?;
        let view = unsafe { MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size) };
        if view.Value.is_null() {
            let _ = unsafe { CloseHandle(mapping) };
            return Err("MapViewOfFile returned null".to_string());
        }
        let pointer = view.Value.cast::<T>();
        Ok((
            Backing::Mapped {
                _file: file,
                mapping,
                view,
            },
            pointer,
            path,
        ))
    }

    pub(super) fn get(&self) -> *mut T {
        self.pointer
    }

    pub(super) fn is_persistent(&self) -> bool {
        matches!(self.backing, Backing::Mapped { .. })
    }

    pub(super) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub(super) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Hurries the pages to disk. Not required for the data to survive a crash -
    /// the kernel owns them either way - but it narrows the window in which a
    /// machine losing power loses the last few records.
    pub(super) fn flush(&self) {
        if let Backing::Mapped { view, .. } = &self.backing {
            let _ = unsafe { FlushViewOfFile(view.Value, std::mem::size_of::<T>()) };
        }
    }
}

impl<T> Drop for Region<T> {
    fn drop(&mut self) {
        if let Backing::Mapped { mapping, .. } = &self.backing {
            let _ = unsafe { CloseHandle(*mapping) };
        }
    }
}

/// A fixed-capacity string inside a mapped record.
///
/// Records are copied byte for byte into a file, so every field has to have one
/// size forever; a `String` would be a pointer into a heap that no longer exists
/// by the time anyone reads it.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Text<const N: usize> {
    length: u16,
    bytes: [u8; N],
}

impl<const N: usize> Default for Text<N> {
    fn default() -> Self {
        Text {
            length: 0,
            bytes: [0; N],
        }
    }
}

impl<const N: usize> Text<N> {
    pub(super) fn new(text: &str) -> Self {
        // On a character boundary, so the reader below gets valid UTF-8 rather
        // than a byte sequence it has to decide what to do with.
        let mut end = text.len().min(N);
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        let mut value = Text::<N>::default();
        value.bytes[..end].copy_from_slice(&text.as_bytes()[..end]);
        value.length = end as u16;
        value
    }

    /// Empty rather than an error for a length or a byte sequence that does not
    /// make sense: this reads records written by a process that died, and a
    /// half-written field is a thing that happens.
    ///
    /// A length past the capacity is rejected outright rather than clamped to
    /// it. Clamping looks like the forgiving choice and is not - it turns a
    /// corrupt field into a plausible-looking one, and a reader trying to
    /// explain a crash would have no way to tell the difference.
    pub(super) fn as_str(&self) -> &str {
        let length = self.length as usize;
        if length > N {
            return "";
        }
        std::str::from_utf8(&self.bytes[..length]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips_within_capacity() {
        let value = Text::<16>::new("renx_start_pie");
        assert_eq!(value.as_str(), "renx_start_pie");
    }

    #[test]
    fn text_truncates_on_a_character_boundary() {
        // Three bytes each, so a capacity of 8 cuts mid-character unless the
        // walk backwards happens.
        let value = Text::<8>::new(&"€".repeat(4));
        assert_eq!(value.as_str(), "€€");
    }

    #[test]
    fn an_empty_text_reads_as_empty() {
        assert_eq!(Text::<32>::default().as_str(), "");
    }

    /// The case this type exists for: a record recovered from a file written by
    /// a process that died mid-write must not panic the reader.
    #[test]
    fn a_corrupt_length_or_body_reads_as_empty_rather_than_panicking() {
        let mut overlong = Text::<8>::new("ok");
        overlong.length = 4096;
        assert_eq!(overlong.as_str(), "");

        let mut invalid = Text::<8>::default();
        invalid.bytes[0] = 0xFF;
        invalid.length = 1;
        assert_eq!(invalid.as_str(), "");
    }

    #[test]
    fn text_is_a_plain_fixed_size_field() {
        // Layout is a wire format here: it has to be a header plus a body, with
        // no pointer and no padding surprises across builds.
        assert!(std::mem::size_of::<Text<64>>() >= 66);
        assert_eq!(std::mem::align_of::<Text<64>>(), 2);
    }
}
