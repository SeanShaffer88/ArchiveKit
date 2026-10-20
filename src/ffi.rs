//! C ABI surface — everything declared in `include/archivekit.h`.
//! Conventions (house standard):
//! - `*mut c_char` results are caller-owned; free with [`ak_free_string`].
//! - Failures return null / -1 / an `AK_ERR_*` code plus a thread-local
//!   last-error message ([`ak_last_error`]).
//! - Extraction refuses entries that would escape the destination.
//! - Nothing unwinds across the FFI boundary.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::Path;

use crate::tar::NewTarEntry;
use crate::zip::NewEntry;
use crate::{
    detect_format, list_json, platform, safe_join, tar, zip, AResult, EntryMeta, Format, AK_OK,
    ERR_CORRUPT, ERR_INTERNAL, ERR_INVALID_ARG, ERR_NOT_FOUND, ERR_PLATFORM,
};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((AK_OK, CString::new("").unwrap()));
}

fn set_error(code: i32, msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(AK_OK, "");
}

fn require_str(p: *const c_char, what: &str) -> AResult<String> {
    if p.is_null() {
        return crate::err(ERR_INVALID_ARG, format!("{what} must not be null"));
    }
    // SAFETY: caller contract — valid NUL-terminated UTF-8 or null.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str()
        .map(|v| v.to_string())
        .map_err(|_| (ERR_INVALID_ARG, format!("{what} is not valid UTF-8")))
}

fn into_c_string(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => {
            set_error(ERR_INTERNAL, "result contained an interior NUL byte");
            std::ptr::null_mut()
        }
    }
}

fn guard<T>(f: impl FnOnce() -> AResult<T>) -> AResult<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => crate::err(ERR_INTERNAL, "internal panic caught at the FFI boundary"),
    }
}

fn read_archive(path: &str) -> AResult<(Vec<u8>, Format)> {
    let bytes =
        std::fs::read(path).map_err(|e| (ERR_NOT_FOUND, format!("cannot read '{path}': {e}")))?;
    let fmt = detect_format(&bytes, path)?;
    Ok((bytes, fmt))
}

fn list_entries(bytes: &[u8], fmt: Format) -> AResult<Vec<EntryMeta>> {
    match fmt {
        Format::Zip => Ok(zip::list(bytes)?.into_iter().map(|e| e.meta).collect()),
        Format::Tar => Ok(tar::list(bytes)?.into_iter().map(|e| e.meta).collect()),
    }
}

fn read_one(bytes: &[u8], fmt: Format, name: &str) -> AResult<Option<Vec<u8>>> {
    match fmt {
        Format::Zip => {
            let entries = zip::list(bytes)?;
            for e in &entries {
                if e.meta.name == name {
                    if e.meta.is_dir {
                        return Ok(Some(Vec::new()));
                    }
                    return zip::read_entry(bytes, e).map(Some);
                }
            }
            Ok(None)
        }
        Format::Tar => {
            let entries = tar::list(bytes)?;
            for e in &entries {
                if e.meta.name == name {
                    return tar::read_entry(bytes, e).map(Some);
                }
            }
            Ok(None)
        }
    }
}

/// Strip leading `./` segments (GNU tar's convention for archive roots).
/// Only ever applied to entry names; safe_join still vets the result.
fn strip_dot_slash(name: &str) -> &str {
    let mut n = name;
    while let Some(rest) = n.strip_prefix("./") {
        n = rest;
    }
    while let Some(rest) = n.strip_prefix(".\\") {
        n = rest;
    }
    n
}

fn extract_all(bytes: &[u8], fmt: Format, dest: &Path) -> AResult<u64> {
    let metas = list_entries(bytes, fmt)?;
    let mut count = 0u64;
    for m in &metas {
        let clean = strip_dot_slash(&m.name);
        if clean.is_empty() {
            // The archive root itself (e.g. GNU tar's "./" record).
            if m.is_dir {
                continue;
            }
            return crate::err(ERR_CORRUPT, "archive entry with an empty name");
        }
        let target = safe_join(dest, clean).ok_or((
            ERR_CORRUPT,
            format!("entry '{}' would escape the destination; refused", m.name),
        ))?;
        if m.is_dir {
            std::fs::create_dir_all(&target).map_err(|e| {
                (
                    ERR_PLATFORM,
                    format!("cannot create directory {}: {e}", target.display()),
                )
            })?;
            continue;
        }
        if let Some(data) = read_one(bytes, fmt, &m.name)? {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    (
                        ERR_PLATFORM,
                        format!("cannot create directory {}: {e}", parent.display()),
                    )
                })?;
            }
            std::fs::write(&target, &data).map_err(|e| {
                (
                    ERR_PLATFORM,
                    format!("cannot write {}: {e}", target.display()),
                )
            })?;
            count += 1;
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Version & errors
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn ak_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.1.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn ak_version_major() -> u32 {
    crate::VERSION_MAJOR
}

#[no_mangle]
pub extern "C" fn ak_version_minor() -> u32 {
    crate::VERSION_MINOR
}

#[no_mangle]
pub extern "C" fn ak_version_patch() -> u32 {
    crate::VERSION_PATCH
}

#[no_mangle]
pub extern "C" fn ak_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn ak_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0) as c_int
}

/// # Safety (caller contract): `p` is null or a string this library
/// returned and has not been freed yet. Documented in the header.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn ak_free_string(p: *mut c_char) {
    if !p.is_null() {
        // SAFETY: per the caller contract above.
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

// ---------------------------------------------------------------------------
// Read operations
// ---------------------------------------------------------------------------

/// JSON array of entries, or null on error.
#[no_mangle]
pub extern "C" fn ak_list_json(archive_utf8: *const c_char) -> *mut c_char {
    let run = guard(|| {
        let path = require_str(archive_utf8, "archive")?;
        let (bytes, fmt) = read_archive(&path)?;
        Ok(list_json(&list_entries(&bytes, fmt)?))
    });
    match run {
        Ok(json) => {
            clear_error();
            into_c_string(json)
        }
        Err((c, m)) => {
            set_error(c, &m);
            std::ptr::null_mut()
        }
    }
}

/// Verify the whole archive (structure + decompress + CRC for ZIP).
/// Returns the entry count, or -1 on error.
#[no_mangle]
pub extern "C" fn ak_test(archive_utf8: *const c_char) -> i64 {
    let run = guard(|| {
        let path = require_str(archive_utf8, "archive")?;
        let (bytes, fmt) = read_archive(&path)?;
        let n = match fmt {
            Format::Zip => zip::test(&bytes)?,
            Format::Tar => tar::test(&bytes)?,
        };
        Ok(n as i64)
    });
    match run {
        Ok(n) => {
            clear_error();
            n
        }
        Err((c, m)) => {
            set_error(c, &m);
            -1
        }
    }
}

/// Extract. `entry_utf8` null = extract all entries. Returns the number
/// of FILES written, or -1 on error. Any entry that would escape the
/// destination aborts the extraction with AK_ERR_CORRUPT.
#[no_mangle]
pub extern "C" fn ak_extract(
    archive_utf8: *const c_char,
    dest_dir_utf8: *const c_char,
    entry_utf8: *const c_char,
) -> i64 {
    let run = guard(|| {
        let path = require_str(archive_utf8, "archive")?;
        let dest = require_str(dest_dir_utf8, "dest_dir")?;
        let (bytes, fmt) = read_archive(&path)?;
        let dest_path = Path::new(&dest);
        if entry_utf8.is_null() {
            extract_all(&bytes, fmt, dest_path)
        } else {
            let name = require_str(entry_utf8, "entry")?;
            let metas = list_entries(&bytes, fmt)?;
            let meta = metas
                .iter()
                .find(|m| m.name == name)
                .ok_or((ERR_NOT_FOUND, format!("no entry named '{name}'")))?;
            if meta.is_dir {
                return Ok(0);
            }
            let target = safe_join(dest_path, &meta.name).ok_or((
                ERR_CORRUPT,
                format!(
                    "entry '{}' would escape the destination; refused",
                    meta.name
                ),
            ))?;
            let data = read_one(&bytes, fmt, &meta.name)?.unwrap_or_default();
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    (
                        ERR_PLATFORM,
                        format!("cannot create directory {}: {e}", parent.display()),
                    )
                })?;
            }
            std::fs::write(&target, &data).map_err(|e| {
                (
                    ERR_PLATFORM,
                    format!("cannot write {}: {e}", target.display()),
                )
            })?;
            Ok(1)
        }
    });
    match run {
        Ok(n) => {
            clear_error();
            n as i64
        }
        Err((c, m)) => {
            set_error(c, &m);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Create operations
// ---------------------------------------------------------------------------

fn collected_zip_entries(root: &str) -> AResult<Vec<NewEntry>> {
    let items = platform::collect(root)?;
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        if it.is_dir {
            out.push(NewEntry::dir(it.arcname, it.modified_unix));
        } else {
            let data = std::fs::read(&it.full_path).map_err(|e| {
                (
                    ERR_PLATFORM,
                    format!("cannot read {}: {e}", it.full_path.display()),
                )
            })?;
            out.push(NewEntry::file(it.arcname, data, it.modified_unix));
        }
    }
    Ok(out)
}

fn create_impl(archive: &str, root: &str, fmt: Format) -> AResult<i64> {
    match fmt {
        Format::Zip => {
            let entries = collected_zip_entries(root)?;
            let n = entries.len() as i64;
            std::fs::write(archive, zip::create(&entries))
                .map_err(|e| (ERR_PLATFORM, format!("cannot write '{archive}': {e}")))?;
            Ok(n)
        }
        Format::Tar => {
            let items = platform::collect(root)?;
            let mut entries = Vec::with_capacity(items.len());
            for it in items {
                let data = if it.is_dir {
                    Vec::new()
                } else {
                    std::fs::read(&it.full_path).map_err(|e| {
                        (
                            ERR_PLATFORM,
                            format!("cannot read {}: {e}", it.full_path.display()),
                        )
                    })?
                };
                entries.push(NewTarEntry {
                    name: it.arcname,
                    data,
                    modified_unix: it.modified_unix,
                    is_dir: it.is_dir,
                });
            }
            let n = entries.len() as i64;
            let bytes = tar::create(&entries)?;
            std::fs::write(archive, bytes)
                .map_err(|e| (ERR_PLATFORM, format!("cannot write '{archive}': {e}")))?;
            Ok(n)
        }
    }
}

/// Create a ZIP at `archive_utf8` from the folder `root_dir_utf8`.
/// Returns the number of entries archived, or -1 on error.
#[no_mangle]
pub extern "C" fn ak_create_zip(archive_utf8: *const c_char, root_dir_utf8: *const c_char) -> i64 {
    let run = guard(|| {
        let archive = require_str(archive_utf8, "archive")?;
        let root = require_str(root_dir_utf8, "root_dir")?;
        create_impl(&archive, &root, Format::Zip)
    });
    match run {
        Ok(n) => {
            clear_error();
            n
        }
        Err((c, m)) => {
            set_error(c, &m);
            -1
        }
    }
}

/// Create a TAR at `archive_utf8` from the folder `root_dir_utf8`.
/// Returns the number of entries archived, or -1 on error.
#[no_mangle]
pub extern "C" fn ak_create_tar(archive_utf8: *const c_char, root_dir_utf8: *const c_char) -> i64 {
    let run = guard(|| {
        let archive = require_str(archive_utf8, "archive")?;
        let root = require_str(root_dir_utf8, "root_dir")?;
        create_impl(&archive, &root, Format::Tar)
    });
    match run {
        Ok(n) => {
            clear_error();
            n
        }
        Err((c, m)) => {
            set_error(c, &m);
            -1
        }
    }
}

/// Append one file to an existing ZIP (rewrites the archive; existing
/// entries are preserved byte-for-byte in content). Returns AK_OK or an
/// error code.
#[no_mangle]
pub extern "C" fn ak_zip_append(
    archive_utf8: *const c_char,
    file_utf8: *const c_char,
    arcname_utf8: *const c_char,
) -> c_int {
    let run = guard(|| {
        let archive = require_str(archive_utf8, "archive")?;
        let file = require_str(file_utf8, "file")?;
        let arcname = require_str(arcname_utf8, "arcname")?;
        let (bytes, fmt) = read_archive(&archive)?;
        if fmt != Format::Zip {
            return crate::err(
                crate::ERR_NOT_SUPPORTED,
                "append is supported for ZIP archives only",
            );
        }
        let mut entries: Vec<NewEntry> = Vec::new();
        for e in zip::list(&bytes)? {
            if e.meta.is_dir {
                entries.push(NewEntry::dir(
                    e.meta.name.trim_end_matches('/'),
                    e.meta.modified_unix.unwrap_or(0),
                ));
            } else {
                let data = zip::read_entry(&bytes, &e)?;
                entries.push(NewEntry::file(
                    e.meta.name.clone(),
                    data,
                    e.meta.modified_unix.unwrap_or(0),
                ));
            }
        }
        let data = std::fs::read(&file)
            .map_err(|e| (ERR_NOT_FOUND, format!("cannot read '{file}': {e}")))?;
        let mtime = std::fs::metadata(&file)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        entries.push(NewEntry::file(arcname, data, mtime));
        std::fs::write(&archive, zip::create(&entries))
            .map_err(|e| (ERR_PLATFORM, format!("cannot write '{archive}': {e}")))?;
        Ok(())
    });
    match run {
        Ok(()) => {
            clear_error();
            AK_OK as c_int
        }
        Err((c, m)) => {
            set_error(c, &m);
            c as c_int
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn cstr(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn ffi_create_list_extract_cycle() {
        let base = std::env::temp_dir().join(format!("ak-ffi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), b"alpha content").unwrap();
        fs::write(
            src.join("sub/b.rs"),
            b"fn main() { /* lots of code code code */ }".repeat(10),
        )
        .unwrap();

        let zip_path = base.join("out.zip");
        let n = ak_create_zip(
            cstr(zip_path.to_str().unwrap()).as_ptr(),
            cstr(src.to_str().unwrap()).as_ptr(),
        );
        assert_eq!(n, 3, "a.txt, sub (dir), sub/b.rs");

        let list_ptr = ak_list_json(cstr(zip_path.to_str().unwrap()).as_ptr());
        assert!(!list_ptr.is_null());
        // SAFETY: pointer came from this module in this test.
        let json = unsafe { CStr::from_ptr(list_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        ak_free_string(list_ptr);
        assert!(json.contains("\"name\":\"a.txt\""), "{json}");
        assert!(json.contains("\"method\":\"deflate\""), "{json}");
        assert_eq!(ak_test(cstr(zip_path.to_str().unwrap()).as_ptr()), 3);

        let dest = base.join(" extracted");
        let written = ak_extract(
            cstr(zip_path.to_str().unwrap()).as_ptr(),
            cstr(dest.to_str().unwrap()).as_ptr(),
            std::ptr::null(),
        );
        assert_eq!(written, 2);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"alpha content");

        // TAR cycle
        let tar_path = base.join("out.tar");
        let n = ak_create_tar(
            cstr(tar_path.to_str().unwrap()).as_ptr(),
            cstr(src.to_str().unwrap()).as_ptr(),
        );
        assert_eq!(n, 3);
        assert_eq!(ak_test(cstr(tar_path.to_str().unwrap()).as_ptr()), 3);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ffi_errors() {
        assert_eq!(ak_test(cstr("/no/such/file.zip").as_ptr()), -1);
        assert_eq!(ak_last_error_code(), ERR_NOT_FOUND as c_int);
        assert!(ak_list_json(std::ptr::null()).is_null());
        assert_eq!(ak_last_error_code(), ERR_INVALID_ARG as c_int);
    }
}
