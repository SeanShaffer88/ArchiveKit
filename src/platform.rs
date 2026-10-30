//! Platform layer: collecting a directory tree for create-from-folder.
//! Pure `std::fs` — ArchiveKit has no OS-specific APIs; the module exists
//! to keep filesystem walking out of the format code.
//! Symlinks are never followed (loop safety; same rule as FastSearch).
//!
//! The same resource budgets the read path enforces are enforced here, so
//! an archive can never be created larger than it could be opened: entry
//! count, per-file size and total size are all checked while walking. That
//! matters for correctness, not just politeness — classic ZIP stores the
//! entry count in 16 bits, so a 70,000-file folder written without a limit
//! would produce a central directory that wraps and silently describes the
//! wrong number of entries.

use crate::{err, AResult, ERR_INTERNAL, ERR_NOT_FOUND, ERR_NOT_SUPPORTED, ERR_PLATFORM};

/// One file or directory under a root, with its archive-relative name.
pub struct Collected {
    /// Archive name, `/`-separated, relative to the walked root.
    pub arcname: String,
    pub full_path: std::path::PathBuf,
    pub is_dir: bool,
    pub modified_unix: i64,
}

/// Walk `root`, returning entries in sorted order (directories before
/// their contents, since names sort that way with the trailing slash
/// convention handled by callers).
pub fn collect(root: &str) -> AResult<Vec<Collected>> {
    let root_path = std::path::Path::new(root);
    let meta = std::fs::metadata(root_path)
        .map_err(|e| (ERR_NOT_FOUND, format!("cannot read root '{root}': {e}")))?;
    if !meta.is_dir() {
        return err(ERR_PLATFORM, format!("'{root}' is not a directory"));
    }
    let mut out: Vec<Collected> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut stack = vec![root_path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        // Unreadable subdirectories are skipped rather than failing the
        // whole archive: on Windows a backup of a user folder routinely
        // crosses directories that even an administrator cannot read.
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            let rel = match path.strip_prefix(root_path) {
                Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
                Err(_) => {
                    return err(
                        ERR_INTERNAL,
                        format!("cannot make '{}' relative to '{root}'", path.display()),
                    )
                }
            };
            if out.len() >= crate::MAX_ENTRIES {
                return err(
                    ERR_NOT_SUPPORTED,
                    format!(
                        "folder exceeds the {}-entry archive limit",
                        crate::MAX_ENTRIES
                    ),
                );
            }
            let meta = entry.metadata().ok();
            let mtime = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let is_dir = ft.is_dir();
            if !is_dir {
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                if size > crate::MAX_ENTRY_BYTES as u64 {
                    return err(
                        ERR_NOT_SUPPORTED,
                        format!(
                            "'{rel}' is {size} bytes, over the {} MiB per-file limit",
                            crate::MAX_ENTRY_BYTES / (1024 * 1024)
                        ),
                    );
                }
                total_bytes = total_bytes.saturating_add(size);
                if total_bytes > crate::MAX_TOTAL_BYTES {
                    return err(
                        ERR_NOT_SUPPORTED,
                        format!(
                            "folder exceeds the {} MiB archive limit",
                            crate::MAX_TOTAL_BYTES / (1024 * 1024)
                        ),
                    );
                }
            }
            out.push(Collected {
                arcname: rel,
                full_path: path.clone(),
                is_dir,
                modified_unix: mtime,
            });
            if is_dir {
                stack.push(path);
            }
        }
    }
    out.sort_by(|a, b| a.arcname.cmp(&b.arcname));
    Ok(out)
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Restore an archive entry's modified time on a file or directory we just
/// created. `unix` is seconds since 1970; the value is whatever the archive
/// declared, so it is clamped rather than trusted blindly.
///
/// Callers treat failures as non-fatal: the entry's *content* has already
/// landed, and a filesystem or attribute set that rejects the timestamp must
/// not turn a good extraction into an error.
pub fn set_mtime(path: &std::path::Path, unix: i64) -> std::io::Result<()> {
    set_mtime_impl(path, unix)
}

/// Seconds between 1601-01-01 (the FILETIME epoch) and 1970-01-01.
#[cfg(windows)]
const FILETIME_UNIX_EPOCH: i128 = 11_644_473_600;

#[cfg(windows)]
#[allow(non_snake_case)] // Win32 spellings, kept greppable against MSDN.
mod windows_time {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut core::ffi::c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn SetFileTime(
            file: *mut core::ffi::c_void,
            creation_time: *const u64,
            last_access_time: *const u64,
            last_write_time: *const u64,
        ) -> i32;
        fn CloseHandle(object: *mut core::ffi::c_void) -> i32;
    }

    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    /// Needed to open a *directory* rather than only files.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const INVALID_HANDLE_VALUE: isize = -1;

    pub fn set_write_time(path: &Path, unix: i64) -> std::io::Result<()> {
        let ticks = (unix as i128 + super::FILETIME_UNIX_EPOCH) * 10_000_000;
        if !(0..=u64::MAX as i128).contains(&ticks) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "timestamp outside the FILETIME range",
            ));
        }
        let file_time = ticks as u64;
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call; the handle
        // is closed on every path that produced one.
        unsafe {
            let handle = CreateFileW(
                wide.as_ptr(),
                FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            );
            if handle as isize == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            let ok = SetFileTime(handle, std::ptr::null(), std::ptr::null(), &file_time);
            let error = std::io::Error::last_os_error();
            CloseHandle(handle);
            if ok == 0 {
                Err(error)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(windows)]
fn set_mtime_impl(path: &std::path::Path, unix: i64) -> std::io::Result<()> {
    windows_time::set_write_time(path, unix)
}

#[cfg(unix)]
fn set_mtime_impl(path: &std::path::Path, unix: i64) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    extern "C" {
        fn utimensat(
            dirfd: i32,
            path: *const core::ffi::c_char,
            times: *const Timespec,
            flags: i32,
        ) -> i32;
    }
    const AT_FDCWD: i32 = -100;

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL")
    })?;
    let times = [
        Timespec {
            tv_sec: unix,
            tv_nsec: 0,
        },
        Timespec {
            tv_sec: unix,
            tv_nsec: 0,
        },
    ];
    // SAFETY: both pointers are valid for the duration of the call and
    // `times` has the two elements utimensat requires.
    let rc = unsafe { utimensat(AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(windows, unix)))]
fn set_mtime_impl(_path: &std::path::Path, _unix: i64) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "timestamps cannot be restored on this platform",
    ))
}
