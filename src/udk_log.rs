//! This module contains functionality relevant to UDK logging.
use crate::dll::get_udk_ptr;

/// Offset from the beginning of UDK64.exe to the debug log object.
#[cfg(target_arch = "x86_64")]
const DEBUG_LOG_OFFSET: usize = 0x0355_1720;
/// Address of UDK's log function.
#[cfg(target_arch = "x86_64")]
const DEBUG_FN_OFFSET: usize = 0x0024_6A20;

/// Offset from the beginning of UDK64.exe to the debug log object.
#[cfg(target_arch = "x86")]
const DEBUG_LOG_OFFSET: usize = 0x029a_31a8;
/// Address of UDK's log function.
#[cfg(target_arch = "x86")]
const DEBUG_FN_OFFSET: usize = 0x0002_1c500;

/// This is the type signature of UDK's log function.
type UDKLogFn = unsafe extern "C" fn(usize, u32, *const widestring::WideChar);

/// This enum represents the UDK message types.
#[repr(u32)]
pub enum LogType {
    Init = 0x2fa,
    //Debug = 0x36c,
    //Log = 0x2f8,
    Warning = 0x2ff,
    Error = 0x315,
    //Critical = 0x2f9,
}

/// Log a message via the UDK logging framework.
///
/// # A literal `%` in `msg` will kill the process unless it is escaped
///
/// The function behind [`DEBUG_FN_OFFSET`] is UE3's variadic `Logf`, so `msg`
/// arrives as the printf **format string**, not as data. A stray `%` is then
/// read as a conversion specifier with no argument behind it, MSVCR100's
/// invalid-parameter handler fires, and UE3 escalates that to `appError` - which
/// takes the whole process down, not just the log line.
///
/// Measured 2026-08-04: a cook died 58s in, mid-run, because a progress line read
/// `cook progress: 12% (689/741 pkgs...)` and `% (` is not a valid specifier. The
/// stack blamed `MSVCR100` under a UDK frame under this one, which is a long way
/// from anything that looks like a logging mistake.
///
/// Doubling them makes printf emit a literal `%`, so callers can pass arbitrary
/// text - including percentages and file paths - without knowing any of this.
pub fn log(typ: LogType, msg: &str) {
    let udk_ptr = get_udk_ptr();
    let log_obj = unsafe { udk_ptr.add(DEBUG_LOG_OFFSET) };
    let log_fn: UDKLogFn = unsafe { std::mem::transmute(udk_ptr.add(DEBUG_FN_OFFSET)) };

    // Convert the UTF-8 Rust string into an OS wide string.
    let wmsg: widestring::U16CString = widestring::WideCString::from_str(format!(
        "TotemArts Extensions: {}",
        msg.replace('%', "%%")
    ))
    .unwrap();

    unsafe {
        (log_fn)(log_obj as usize, typ as u32, wmsg.as_ptr());
    }
}
