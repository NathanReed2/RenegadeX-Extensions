//! Shared helpers used by the small binary patches.

#[cfg(debug_assertions)]
pub(crate) fn write_debug_log(args: std::fmt::Arguments<'_>) {
    use std::fs::OpenOptions;
    use std::io::Write;

    let path = std::env::current_exe().ok().and_then(|path| {
        path.parent()
            .map(|directory| directory.join("renxhook.log"))
    });

    if let Some(path) = path {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{args}");
        }
    }
}

#[cfg(debug_assertions)]
macro_rules! debug_log {
    ($($argument:tt)*) => {
        $crate::patch_utils::write_debug_log(format_args!($($argument)*))
    };
}

#[cfg(not(debug_assertions))]
macro_rules! debug_log {
    ($($argument:tt)*) => {{
        if false {
            let _ = format_args!($($argument)*);
        }
    }};
}

pub(crate) use debug_log;

/// Finds the signature match nearest `expected`, without allocating a list
/// containing every match. `skew` converts a signature offset to its owning
/// function or instruction offset.
#[cfg(target_arch = "x86_64")]
pub(crate) fn find_signature_offset(
    signature: &[u8],
    expected: usize,
    skew: usize,
) -> (Option<usize>, usize) {
    let Some(range) = crate::dll::UDK_RANGE.get() else {
        return (None, 0);
    };
    let Some(length) = range.end.checked_sub(range.start) else {
        return (None, 0);
    };
    if signature.is_empty() || length < signature.len() {
        return (None, 0);
    }

    let image = unsafe { std::slice::from_raw_parts(range.start as *const u8, length) };
    let mut best = None;
    let mut count = 0;

    for (offset, bytes) in image.windows(signature.len()).enumerate() {
        if bytes != signature {
            continue;
        }
        let Some(candidate) = offset.checked_sub(skew) else {
            continue;
        };

        count += 1;
        if best
            .is_none_or(|current: usize| candidate.abs_diff(expected) < current.abs_diff(expected))
        {
            best = Some(candidate);
        }
    }

    (best, count)
}
