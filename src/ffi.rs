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

fn read_archive(path: &str) -> AResult<(Vec<u8>, Format, Listed)> {
    use std::io::Read;
    let file = std::fs::File::open(path)
        .map_err(|e| (ERR_NOT_FOUND, format!("cannot read '{path}': {e}")))?;
    let mut bytes = Vec::new();
    file.take(crate::MAX_ARCHIVE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| (ERR_PLATFORM, e.to_string()))?;
    if bytes.len() > crate::MAX_ARCHIVE_BYTES {
        return crate::err(ERR_CORRUPT, "archive exceeds 256 MiB input limit");
    }
    let fmt = detect_format(&bytes, path)?;
    let listed = list_archive(&bytes, fmt)?;
    let mut total = 0u64;
    for meta in listed.metas() {
        total = total
            .checked_add(meta.size)
            .ok_or((ERR_CORRUPT, "archive size overflow".into()))?;
        if meta.size > crate::MAX_ENTRY_BYTES as u64 || total > crate::MAX_TOTAL_BYTES {
            return crate::err(ERR_CORRUPT, "archive exceeds output budget");
        }
    }
    Ok((bytes, fmt, listed))
}

fn safe_directories(path: &Path) -> AResult<()> {
    let absolute = std::path::absolute(path).map_err(|e| (ERR_PLATFORM, e.to_string()))?;
    if absolute
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return crate::err(
            ERR_INVALID_ARG,
            "destination must not contain parent components",
        );
    }
    let chain: Vec<_> = absolute.ancestors().collect();
    for item in chain.into_iter().rev() {
        if !item.exists() {
            std::fs::create_dir(item).map_err(|e| {
                (
                    ERR_PLATFORM,
                    format!("cannot create {}: {e}", item.display()),
                )
            })?;
        }
        let meta = std::fs::symlink_metadata(item).map_err(|e| (ERR_PLATFORM, e.to_string()))?;
        #[cfg(windows)]
        let reparse = {
            use std::os::windows::fs::MetadataExt;
            meta.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let reparse = meta.file_type().is_symlink();
        if reparse || !meta.is_dir() {
            return crate::err(
                ERR_CORRUPT,
                format!(
                    "destination ancestor is not a plain directory: {}",
                    item.display()
                ),
            );
        }
    }
    Ok(())
}

/// Write one extracted file and restore its modified time. The time is
/// best-effort: the content is already on disk, so a filesystem or attribute
/// set that rejects the timestamp must not fail the extraction.
fn write_extracted(target: &Path, data: &[u8], mtime: Option<i64>) -> AResult<()> {
    use std::io::Write;
    if let Some(parent) = target.parent() {
        safe_directories(parent)?;
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|e| {
            (
                ERR_PLATFORM,
                format!(
                    "cannot create new file {} (an earlier entry or an existing file is \
                     never overwritten): {e}",
                    target.display()
                ),
            )
        })?;
    if let Err(e) = output.write_all(data) {
        // Never leave a truncated file behind: it would look like a
        // successful extraction to whatever runs next.
        drop(output);
        let removed = std::fs::remove_file(target);
        return crate::err(
            ERR_PLATFORM,
            match removed {
                Ok(()) => format!(
                    "write failed, partial file removed {}: {e}",
                    target.display()
                ),
                Err(_) => format!(
                    "write failed and the partial file could not be removed {}: {e}",
                    target.display()
                ),
            },
        );
    }
    // Close before touching attributes: Windows refuses SetFileTime on a
    // path whose handle is still open for writing.
    drop(output);
    if let Some(seconds) = mtime.filter(|&secs| secs > 0) {
        let _ = platform::set_mtime(target, seconds);
    }
    Ok(())
}

/// Key used to spot two archive entries that would land on the same file.
/// Windows paths are case-insensitive, so there the key is folded; on Unix
/// the same archive is legal and both files are written.
fn collision_key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}

/// Apply a recorded read-only attribute. Files get this right after their
/// content; directories only once every child exists, or the directory could
/// not be written into.
fn apply_read_only(path: &Path, read_only: bool) {
    if read_only {
        let _ = platform::set_read_only(path, true);
    }
}

/// Apply recorded directory times once every file has been written. Writing
/// children updates a parent's mtime, so directory times are set last (and
/// deepest-first) or the walk would undo them.
fn apply_directory_times(directory_times: Vec<(std::path::PathBuf, i64)>) {
    for (path, seconds) in directory_times.into_iter().rev() {
        let _ = platform::set_mtime(&path, seconds);
    }
}

/// An opened archive's entries, parsed once and reused for listing,
/// extraction and append. v0.1 re-parsed the archive for every entry it
/// extracted (`read_one` called `list` again per file), which made
/// extraction quadratic in the entry count; the parsed offsets are now
/// carried through instead.
enum Listed {
    Zip(Vec<zip::ZipEntry>),
    Tar(Vec<tar::TarEntry>),
}

impl Listed {
    fn len(&self) -> usize {
        match self {
            Listed::Zip(entries) => entries.len(),
            Listed::Tar(entries) => entries.len(),
        }
    }

    fn metas(&self) -> Vec<EntryMeta> {
        match self {
            Listed::Zip(entries) => entries.iter().map(|e| e.meta.clone()).collect(),
            Listed::Tar(entries) => entries.iter().map(|e| e.meta.clone()).collect(),
        }
    }

    fn meta_at(&self, index: usize) -> &EntryMeta {
        match self {
            Listed::Zip(entries) => &entries[index].meta,
            Listed::Tar(entries) => &entries[index].meta,
        }
    }

    /// Exact name match first. Directory entries are stored with a trailing
    /// `/` by ZIP convention and without one by some TAR writers, so a
    /// directory is also found when the caller's spelling differs only by
    /// that slash (files are always matched exactly).
    fn find(&self, name: &str) -> Option<usize> {
        if let Some(index) = (0..self.len()).position(|i| self.meta_at(i).name == name) {
            return Some(index);
        }
        let alternate = if name.ends_with('/') {
            name.trim_end_matches('/').to_string()
        } else {
            format!("{name}/")
        };
        (0..self.len()).position(|i| self.meta_at(i).is_dir && self.meta_at(i).name == alternate)
    }

    fn read(&self, bytes: &[u8], index: usize) -> AResult<Vec<u8>> {
        match self {
            Listed::Zip(entries) => zip::read_entry(bytes, &entries[index]),
            Listed::Tar(entries) => tar::read_entry(bytes, &entries[index]),
        }
    }
}

fn list_archive(bytes: &[u8], fmt: Format) -> AResult<Listed> {
    match fmt {
        Format::Zip => Ok(Listed::Zip(zip::list(bytes)?)),
        Format::Tar => Ok(Listed::Tar(tar::list(bytes)?)),
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

/// Match `name` against a folder `prefix` on component boundaries, so
/// "doc" never selects "docs/x". Returns the name's path *below* the
/// prefix ("" for the prefix entry itself).
fn strip_prefix_component<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = name.strip_prefix(prefix)?;
    if rest.is_empty() {
        return Some("");
    }
    rest.strip_prefix('/')
}

/// Normalize a folder prefix for matching: `\` separators become `/`, `./`
/// segments and any trailing `/` are removed.
fn normalize_prefix(prefix: &str) -> String {
    let slashed = prefix.replace('\\', "/");
    let trimmed = strip_dot_slash(&slashed).trim_end_matches('/');
    // "." and "./" both mean the archive root, not a folder named ".".
    if trimmed == "." {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// Extract the folder `prefix` and everything below it. The prefix itself
/// is stripped from the written paths, so `docs/api` lands its contents
/// directly in `dest` — the "extract this folder" behaviour archive tools
/// offer. Only entries that are actually selected are traversal-checked:
/// an unsafe entry elsewhere in the archive is never written and does not
/// abort the operation.
fn extract_prefix(bytes: &[u8], listed: &Listed, dest: &Path, prefix: &str) -> AResult<u64> {
    let prefix = normalize_prefix(prefix);
    if prefix.is_empty() {
        return extract_all(bytes, listed, dest);
    }
    // Reuse the extraction guard to validate the prefix itself: absolute
    // paths, drive-relative names, `..` and device names are all refused.
    if safe_join(dest, &prefix).is_none() {
        return crate::err(
            ERR_INVALID_ARG,
            format!("'{prefix}' is not a safe folder prefix"),
        );
    }
    let basename = prefix.rsplit('/').next().unwrap_or(&prefix).to_string();
    let mut count = 0u64;
    let mut directory_times: Vec<(std::path::PathBuf, i64)> = Vec::new();
    let mut directory_attributes: Vec<std::path::PathBuf> = Vec::new();
    let mut seen_files: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for index in 0..listed.len() {
        let meta = listed.meta_at(index);
        let slashed;
        let clean = if meta.name.contains('\\') {
            slashed = meta.name.replace('\\', "/");
            strip_dot_slash(&slashed)
        } else {
            strip_dot_slash(&meta.name)
        };
        let rest = match strip_prefix_component(clean, &prefix) {
            Some(rest) => rest,
            None => continue,
        };
        // The prefix entry itself: a directory contributes nothing, and a
        // file named exactly like the prefix keeps its own basename.
        let relative = if rest.is_empty() {
            if meta.is_dir {
                safe_directories(dest)?;
                continue;
            }
            basename.as_str()
        } else {
            rest
        };
        if relative.is_empty() {
            continue;
        }
        let target = safe_join(dest, relative).ok_or((
            ERR_CORRUPT,
            format!(
                "entry '{}' would escape the destination; refused",
                meta.name
            ),
        ))?;
        if meta.is_dir {
            safe_directories(&target)?;
            if let Some(seconds) = meta.modified_unix.filter(|&secs| secs > 0) {
                directory_times.push((target.clone(), seconds));
            }
            if meta.read_only {
                directory_attributes.push(target);
            }
            continue;
        }
        // Two entries writing one path is the archive's fault, not the
        // destination's, and the "existing file" error would blame the
        // wrong thing. Say which two entries collide instead (this also
        // catches case-only collisions on Windows).
        let key = collision_key(&target);
        if let Some(first) = seen_files.insert(key, meta.name.clone()) {
            return crate::err(
                ERR_CORRUPT,
                format!(
                    "archive has two entries that map to the same path ({} and {}); \
                     nothing further was extracted",
                    first, meta.name
                ),
            );
        }
        let data = listed.read(bytes, index)?;
        write_extracted(&target, &data, meta.modified_unix)?;
        apply_read_only(&target, meta.read_only);
        count += 1;
    }
    apply_directory_times(directory_times);
    for path in directory_attributes.into_iter().rev() {
        apply_read_only(&path, true);
    }
    Ok(count)
}

fn extract_all(bytes: &[u8], listed: &Listed, dest: &Path) -> AResult<u64> {
    let mut count = 0u64;
    let mut directory_times: Vec<(std::path::PathBuf, i64)> = Vec::new();
    let mut directory_attributes: Vec<std::path::PathBuf> = Vec::new();
    let mut seen_files: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for index in 0..listed.len() {
        let meta = listed.meta_at(index);
        let clean = strip_dot_slash(&meta.name);
        if clean.is_empty() {
            // The archive root itself (e.g. GNU tar's "./" record).
            if meta.is_dir {
                continue;
            }
            return crate::err(ERR_CORRUPT, "archive entry with an empty name");
        }
        let target = safe_join(dest, clean).ok_or((
            ERR_CORRUPT,
            format!(
                "entry '{}' would escape the destination; refused",
                meta.name
            ),
        ))?;
        if meta.is_dir {
            safe_directories(&target)?;
            if let Some(seconds) = meta.modified_unix.filter(|&secs| secs > 0) {
                directory_times.push((target.clone(), seconds));
            }
            if meta.read_only {
                directory_attributes.push(target);
            }
            continue;
        }
        // Two entries writing one path is the archive's fault, not the
        // destination's, and the "existing file" error would blame the
        // wrong thing. Say which two entries collide instead (this also
        // catches case-only collisions on Windows).
        let key = collision_key(&target);
        if let Some(first) = seen_files.insert(key, meta.name.clone()) {
            return crate::err(
                ERR_CORRUPT,
                format!(
                    "archive has two entries that map to the same path ({} and {}); \
                     nothing further was extracted",
                    first, meta.name
                ),
            );
        }
        let data = listed.read(bytes, index)?;
        write_extracted(&target, &data, meta.modified_unix)?;
        apply_read_only(&target, meta.read_only);
        count += 1;
    }
    apply_directory_times(directory_times);
    for path in directory_attributes.into_iter().rev() {
        apply_read_only(&path, true);
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Version & errors
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn ak_version() -> *const c_char {
    // Compile-time synced with Cargo.toml so the DLL cannot claim a
    // version the package does not have.
    static VERSION_C: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
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
        let (_, _, listed) = read_archive(&path)?;
        Ok(list_json(&listed.metas()))
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
        let (bytes, fmt, _) = read_archive(&path)?;
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
/// destination aborts the extraction with AK_ERR_CORRUPT. A named
/// directory extracts nothing and returns 0; its trailing `/` is optional.
#[no_mangle]
pub extern "C" fn ak_extract(
    archive_utf8: *const c_char,
    dest_dir_utf8: *const c_char,
    entry_utf8: *const c_char,
) -> i64 {
    let run = guard(|| {
        let path = require_str(archive_utf8, "archive")?;
        let dest = require_str(dest_dir_utf8, "dest_dir")?;
        let (bytes, _, listed) = read_archive(&path)?;
        let dest_path = Path::new(&dest);
        if entry_utf8.is_null() {
            return extract_all(&bytes, &listed, dest_path);
        }
        let name = require_str(entry_utf8, "entry")?;
        let index = listed
            .find(&name)
            .ok_or((ERR_NOT_FOUND, format!("no entry named '{name}'")))?;
        let meta = listed.meta_at(index);
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
        let data = listed.read(&bytes, index)?;
        write_extracted(&target, &data, meta.modified_unix)?;
        apply_read_only(&target, meta.read_only);
        Ok(1)
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

/// Extract one folder and everything below it. `prefix_utf8` is matched on
/// path component boundaries; the prefix itself is stripped from the
/// written paths. Returns the number of FILES written, or -1 on error.
#[no_mangle]
pub extern "C" fn ak_extract_prefix(
    archive_utf8: *const c_char,
    dest_dir_utf8: *const c_char,
    prefix_utf8: *const c_char,
) -> i64 {
    let run = guard(|| {
        let path = require_str(archive_utf8, "archive")?;
        let dest = require_str(dest_dir_utf8, "dest_dir")?;
        let prefix = require_str(prefix_utf8, "prefix")?;
        let (bytes, _, listed) = read_archive(&path)?;
        extract_prefix(&bytes, &listed, Path::new(&dest), &prefix)
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
        let mut entry = if it.is_dir {
            NewEntry::dir(it.arcname, it.modified_unix)
        } else {
            let data = std::fs::read(&it.full_path).map_err(|e| {
                (
                    ERR_PLATFORM,
                    format!("cannot read {}: {e}", it.full_path.display()),
                )
            })?;
            NewEntry::file(it.arcname, data, it.modified_unix)
        };
        entry.read_only = it.read_only;
        out.push(entry);
    }
    Ok(out)
}

fn create_impl(archive: &str, root: &str, fmt: Format) -> AResult<i64> {
    match fmt {
        Format::Zip => {
            let entries = collected_zip_entries(root)?;
            let n = entries.len() as i64;
            let bytes = zip::create(&entries)?;
            std::fs::write(archive, bytes)
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
                    read_only: it.read_only,
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
        let (bytes, fmt, listed) = read_archive(&archive)?;
        if fmt != Format::Zip {
            return crate::err(
                crate::ERR_NOT_SUPPORTED,
                "append is supported for ZIP archives only",
            );
        }
        let mut entries: Vec<NewEntry> = Vec::new();
        for index in 0..listed.len() {
            let meta = listed.meta_at(index);
            let mut entry = if meta.is_dir {
                NewEntry::dir(
                    meta.name.trim_end_matches('/'),
                    meta.modified_unix.unwrap_or(0),
                )
            } else {
                let data = listed.read(&bytes, index)?;
                NewEntry::file(meta.name.clone(), data, meta.modified_unix.unwrap_or(0))
            };
            entry.read_only = meta.read_only;
            entries.push(entry);
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
        let bytes = zip::create(&entries)?;
        std::fs::write(&archive, bytes)
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
    fn ffi_single_entry_extraction() {
        let base = std::env::temp_dir().join(format!("ak-one-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("b.txt"), b"beta").unwrap();
        let zip_path = base.join("one.zip");
        fs::write(
            &zip_path,
            zip::create(&[
                NewEntry::dir("sub", 0),
                NewEntry::file("a.txt", b"alpha".to_vec(), 0),
                NewEntry::file("b.txt", b"beta".to_vec(), 0),
            ])
            .unwrap(),
        )
        .unwrap();
        let archive = cstr(zip_path.to_str().unwrap());
        let dest = base.join("out");
        let dest_c = cstr(dest.to_str().unwrap());
        // One named entry: only that file is written.
        assert_eq!(
            ak_extract(archive.as_ptr(), dest_c.as_ptr(), cstr("b.txt").as_ptr()),
            1
        );
        assert_eq!(fs::read(dest.join("b.txt")).unwrap(), b"beta");
        assert!(!dest.join("a.txt").exists());
        // A directory entry extracts nothing but reports success.
        assert_eq!(
            ak_extract(archive.as_ptr(), dest_c.as_ptr(), cstr("sub").as_ptr()),
            0
        );
        // A name that is not in the archive is NOT_FOUND.
        assert_eq!(
            ak_extract(archive.as_ptr(), dest_c.as_ptr(), cstr("nope").as_ptr()),
            -1
        );
        assert_eq!(ak_last_error_code(), ERR_NOT_FOUND as c_int);
        // Names are matched exactly, not as prefixes.
        assert_eq!(
            ak_extract(archive.as_ptr(), dest_c.as_ptr(), cstr("a.tx").as_ptr()),
            -1
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ffi_tar_long_names_roundtrip() {
        // 40 + '/' + 70 = 111 bytes: over the single name field, so the
        // writer must use the ustar prefix split and the reader must
        // reassemble it.
        let base = std::env::temp_dir().join(format!("ak-long-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let dir = "d".repeat(40);
        let file = "f".repeat(70);
        let src = base.join("src");
        fs::create_dir_all(src.join(&dir)).unwrap();
        fs::write(src.join(&dir).join(&file), b"long tar payload").unwrap();
        let tar_path = base.join("long.tar");
        assert_eq!(
            ak_create_tar(
                cstr(tar_path.to_str().unwrap()).as_ptr(),
                cstr(src.to_str().unwrap()).as_ptr(),
            ),
            2
        );
        assert_eq!(ak_test(cstr(tar_path.to_str().unwrap()).as_ptr()), 2);
        let list_ptr = ak_list_json(cstr(tar_path.to_str().unwrap()).as_ptr());
        assert!(!list_ptr.is_null());
        // SAFETY: pointer came from this module in this test.
        let json = unsafe { CStr::from_ptr(list_ptr) }
            .to_str()
            .unwrap()
            .to_string();
        ak_free_string(list_ptr);
        assert!(json.contains(&format!("\"{dir}/{file}\"")), "{json}");
        let dest = base.join("out");
        assert_eq!(
            ak_extract(
                cstr(tar_path.to_str().unwrap()).as_ptr(),
                cstr(dest.to_str().unwrap()).as_ptr(),
                std::ptr::null(),
            ),
            1
        );
        assert_eq!(
            fs::read(dest.join(&dir).join(&file)).unwrap(),
            b"long tar payload"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ffi_extract_prefix_writes_the_folder_contents() {
        let base = std::env::temp_dir().join(format!("ak-prefix-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let zip_path = base.join("p.zip");
        fs::create_dir_all(&base).unwrap();
        fs::write(
            &zip_path,
            zip::create(&[
                NewEntry::dir("docs/api", 0),
                NewEntry::file("docs/api/a.txt", b"a".to_vec(), 0),
                NewEntry::file("docs/api/deep/b.txt", b"b".to_vec(), 0),
                NewEntry::file("docs/other/c.txt", b"c".to_vec(), 0),
                NewEntry::file("docsx/d.txt", b"d".to_vec(), 0),
                NewEntry::file("top.txt", b"t".to_vec(), 0),
            ])
            .unwrap(),
        )
        .unwrap();
        let archive = cstr(zip_path.to_str().unwrap());

        // Contents of the folder land directly in dest, prefix stripped.
        let dest = base.join("api");
        let dest_c = cstr(dest.to_str().unwrap());
        assert_eq!(
            ak_extract_prefix(archive.as_ptr(), dest_c.as_ptr(), cstr("docs/api").as_ptr()),
            2
        );
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"a");
        assert_eq!(fs::read(dest.join("deep").join("b.txt")).unwrap(), b"b");
        assert!(!dest.join("api").exists());
        assert!(!dest.join("other").exists());

        // Trailing slash and `./` are tolerated.
        let dest2 = base.join("trailing");
        assert_eq!(
            ak_extract_prefix(
                archive.as_ptr(),
                cstr(dest2.to_str().unwrap()).as_ptr(),
                cstr("./docs/api/").as_ptr()
            ),
            2
        );
        // Matching is per component: "doc" or "docs/a" select nothing.
        for miss in ["doc", "docs/a", "docs/api/deeper"] {
            let dest3 = base.join(format!("miss-{}", miss.replace('/', "_")));
            assert_eq!(
                ak_extract_prefix(
                    archive.as_ptr(),
                    cstr(dest3.to_str().unwrap()).as_ptr(),
                    cstr(miss).as_ptr()
                ),
                0,
                "{miss}"
            );
        }
        // A whole top-level folder: docs/api + docs/other + docsx are not
        // included, because "docsx" is a different component.
        let dest4 = base.join("docs");
        assert_eq!(
            ak_extract_prefix(
                archive.as_ptr(),
                cstr(dest4.to_str().unwrap()).as_ptr(),
                cstr("docs").as_ptr()
            ),
            3
        );
        assert_eq!(fs::read(dest4.join("other").join("c.txt")).unwrap(), b"c");
        assert!(!dest4.join("was-docsx").exists());
        // Asking for a file extracts just that file, under its basename.
        let dest5 = base.join("file");
        assert_eq!(
            ak_extract_prefix(
                archive.as_ptr(),
                cstr(dest5.to_str().unwrap()).as_ptr(),
                cstr("docs/other/c.txt").as_ptr()
            ),
            1
        );
        assert_eq!(fs::read(dest5.join("c.txt")).unwrap(), b"c");
        // "." and "./" mean the archive root, so they extract everything;
        // an empty prefix and "/" do the same. The destination names are
        // explicit labels, not derived from the prefix: Win32 strips a
        // trailing dot from a path component, so "root-." would silently
        // become "root-" and collide with the empty-prefix case.
        for (label, root_prefix) in [
            ("dot", "."),
            ("dot-slash", "./"),
            ("empty", ""),
            ("slash", "/"),
        ] {
            let dest_root = base.join(format!("root-{label}"));
            assert_eq!(
                ak_extract_prefix(
                    archive.as_ptr(),
                    cstr(dest_root.to_str().unwrap()).as_ptr(),
                    cstr(root_prefix).as_ptr()
                ),
                5, // every file in the archive: a, deep/b, other/c, docsx/d, top
                "{root_prefix:?}"
            );
            assert_eq!(fs::read(dest_root.join("top.txt")).unwrap(), b"t");
        }
        // Unsafe prefixes are refused rather than silently matching nothing.
        for bad in ["..", "../docs", "C:/docs", "/docs", "docs/../x"] {
            assert_eq!(
                ak_extract_prefix(archive.as_ptr(), dest_c.as_ptr(), cstr(bad).as_ptr()),
                -1,
                "{bad}"
            );
            assert_eq!(ak_last_error_code(), ERR_INVALID_ARG as c_int, "{bad}");
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ffi_extract_prefix_ignores_unsafe_entries_outside_it() {
        // A hostile entry elsewhere in the archive must not block extracting
        // a clean folder, and must never be written.
        let base = std::env::temp_dir().join(format!("ak-prefix-evil-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let zip_path = base.join("evil.zip");
        fs::write(
            &zip_path,
            zip::create(&[
                NewEntry::file("../escape.txt", b"nope".to_vec(), 0),
                NewEntry::file("good/keep.txt", b"keep".to_vec(), 0),
                NewEntry::file("good/deep/../traversal.txt", b"nope".to_vec(), 0),
            ])
            .unwrap(),
        )
        .unwrap();
        let dest = base.join("out");
        let n = ak_extract_prefix(
            cstr(zip_path.to_str().unwrap()).as_ptr(),
            cstr(dest.to_str().unwrap()).as_ptr(),
            cstr("good").as_ptr(),
        );
        // keep.txt is written; the traversal entry *inside* the prefix is
        // refused, which aborts the operation with CORRUPT.
        assert_eq!(n, -1);
        assert_eq!(ak_last_error_code(), ERR_CORRUPT as c_int);
        assert!(!base.join("escape.txt").exists());
        assert!(!dest.join("traversal.txt").exists());
        // Extracting everything still refuses the archive as a whole.
        assert_eq!(
            ak_extract(
                cstr(zip_path.to_str().unwrap()).as_ptr(),
                cstr(dest.to_str().unwrap()).as_ptr(),
                std::ptr::null()
            ),
            -1
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ffi_extraction_restores_timestamps() {
        // 2026-10-20 15:40:00 UTC, an even second so ZIP's 2-second DOS
        // resolution round-trips exactly. This runs the platform timestamp
        // path for real: utimensat on Unix, SetFileTime on Windows CI.
        const STAMP: i64 = 1_792_510_800;
        fn mtime_of(path: &std::path::Path) -> i64 {
            fs::metadata(path)
                .unwrap()
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        }
        let base = std::env::temp_dir().join(format!("ak-time-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let zip_path = base.join("t.zip");
        fs::write(
            &zip_path,
            zip::create(&[
                NewEntry::dir("dir", STAMP),
                NewEntry::file("dir/a.txt", b"alpha".to_vec(), STAMP),
                // ZIP cannot express "before 1980": DOS time clamps a zero
                // timestamp to 1980-01-01, and that is what extraction
                // restores — the archive's statement, not the clock.
                NewEntry::file("epoch.txt", b"beta".to_vec(), 0),
            ])
            .unwrap(),
        )
        .unwrap();
        let dest = base.join("out");
        assert_eq!(
            ak_extract(
                cstr(zip_path.to_str().unwrap()).as_ptr(),
                cstr(dest.to_str().unwrap()).as_ptr(),
                std::ptr::null()
            ),
            2
        );
        assert_eq!(mtime_of(&dest.join("dir").join("a.txt")), STAMP);
        // Directory times are applied after the children are written, so the
        // walk cannot leave the parent stamped with "now".
        assert_eq!(mtime_of(&dest.join("dir")), STAMP);
        assert_eq!(mtime_of(&dest.join("epoch.txt")), 315_532_800);
        // Single-entry extraction restores it too (and keeps the full
        // archive path, as documented for ak_extract).
        let single = base.join("single");
        assert_eq!(
            ak_extract(
                cstr(zip_path.to_str().unwrap()).as_ptr(),
                cstr(single.to_str().unwrap()).as_ptr(),
                cstr("dir/a.txt").as_ptr()
            ),
            1
        );
        assert_eq!(mtime_of(&single.join("dir").join("a.txt")), STAMP);
        // And TAR (second resolution, no DOS quantization).
        let tar_path = base.join("t.tar");
        let tar_bytes = tar::create(&[NewTarEntry {
            name: "b.txt".into(),
            data: b"payload".to_vec(),
            modified_unix: STAMP + 1,
            is_dir: false,
            read_only: false,
        }])
        .unwrap();
        fs::write(&tar_path, tar_bytes).unwrap();
        let tar_dest = base.join("tarout");
        assert_eq!(
            ak_extract(
                cstr(tar_path.to_str().unwrap()).as_ptr(),
                cstr(tar_dest.to_str().unwrap()).as_ptr(),
                std::ptr::null()
            ),
            1
        );
        assert_eq!(mtime_of(&tar_dest.join("b.txt")), STAMP + 1);
        // TAR *can* say zero (1970), which archive tools also use for "no
        // timestamp". That case is left alone rather than stamped 1970.
        let zero_tar = base.join("zero.tar");
        fs::write(
            &zero_tar,
            tar::create(&[NewTarEntry {
                name: "c.txt".into(),
                data: b"x".to_vec(),
                modified_unix: 0,
                is_dir: false,
                read_only: false,
            }])
            .unwrap(),
        )
        .unwrap();
        let zero_dest = base.join("zerotar");
        assert_eq!(
            ak_extract(
                cstr(zero_tar.to_str().unwrap()).as_ptr(),
                cstr(zero_dest.to_str().unwrap()).as_ptr(),
                std::ptr::null()
            ),
            1
        );
        assert!(
            mtime_of(&zero_dest.join("c.txt")) > 1_700_000_000,
            "a zero TAR timestamp is treated as unknown"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ffi_read_only_attribute_roundtrips() {
        // A read-only file must stay read-only after create + extract, in
        // both formats, or a restored backup silently changes permissions.
        fn make_read_only(path: &std::path::Path) {
            let mut perms = fs::metadata(path).unwrap().permissions();
            perms.set_readonly(true);
            fs::set_permissions(path, perms).unwrap();
        }
        fn make_writable(path: &std::path::Path) {
            let mut perms = fs::symlink_metadata(path).unwrap().permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            fs::set_permissions(path, perms).unwrap();
        }
        fn is_read_only(path: &std::path::Path) -> bool {
            fs::metadata(path).unwrap().permissions().readonly()
        }
        let base = std::env::temp_dir().join(format!("ak-ro-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let src = base.join("src");
        fs::create_dir_all(src.join("locked-dir")).unwrap();
        fs::write(src.join("locked.txt"), b"locked").unwrap();
        fs::write(src.join("free.txt"), b"free").unwrap();
        fs::write(src.join("locked-dir/inner.txt"), b"inner").unwrap();
        make_read_only(&src.join("locked.txt"));
        make_read_only(&src.join("locked-dir"));

        for format in [Format::Zip, Format::Tar] {
            let archive = base.join(format!("archive.{}", format.name()));
            let archive_c = cstr(archive.to_str().unwrap());
            let root_c = cstr(src.to_str().unwrap());
            let created = match format {
                Format::Zip => ak_create_zip(archive_c.as_ptr(), root_c.as_ptr()),
                Format::Tar => ak_create_tar(archive_c.as_ptr(), root_c.as_ptr()),
            };
            assert_eq!(created, 4, "{}", format.name());

            // The listing reports the attribute.
            let list_ptr = ak_list_json(archive_c.as_ptr());
            assert!(!list_ptr.is_null());
            // SAFETY: pointer came from this module in this test.
            let json = unsafe { CStr::from_ptr(list_ptr) }
                .to_str()
                .unwrap()
                .to_string();
            ak_free_string(list_ptr);
            assert!(
                json.contains(r#"{"name":"locked.txt","size":6"#)
                    && json.contains(r#""read_only":true"#),
                "{}: {json}",
                format.name()
            );
            assert!(
                json.contains(r#"{"name":"free.txt","size":4"#)
                    && json.contains(r#""read_only":false"#),
                "{}: {json}",
                format.name()
            );

            let dest = base.join(format!("out-{}", format.name()));
            assert_eq!(
                ak_extract(
                    archive_c.as_ptr(),
                    cstr(dest.to_str().unwrap()).as_ptr(),
                    std::ptr::null()
                ),
                3, // locked.txt, free.txt, locked-dir/inner.txt
                "{}",
                format.name()
            );
            assert!(
                is_read_only(&dest.join("locked.txt")),
                "{}: locked.txt lost its attribute",
                format.name()
            );
            assert!(
                !is_read_only(&dest.join("free.txt")),
                "{}: free.txt became read-only",
                format.name()
            );
            assert!(
                is_read_only(&dest.join("locked-dir")),
                "{}: locked-dir lost its attribute",
                format.name()
            );
            // Children were written before the directory was locked, so
            // extraction had to reach into it while it was still writable.
            assert_eq!(
                fs::read(dest.join("locked-dir").join("inner.txt")).unwrap(),
                b"inner"
            );
            // Leave the tree writable so the temp-directory cleanup works on
            // Windows, where read-only blocks deletion.
            make_writable(&dest.join("locked-dir").join("inner.txt"));
            make_writable(&dest.join("locked-dir"));
            make_writable(&dest.join("locked.txt"));
        }
        make_writable(&src.join("locked.txt"));
        make_writable(&src.join("locked-dir"));
        make_writable(&src.join("locked-dir").join("inner.txt"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ffi_duplicate_entries_are_reported_as_an_archive_fault() {
        // An archive with the same name twice: the second write cannot
        // create the file, and the error must say the archive is at fault
        // rather than blaming a pre-existing file.
        let base = std::env::temp_dir().join(format!("ak-dup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let zip_path = base.join("dup.zip");
        fs::write(
            &zip_path,
            zip::create(&[
                NewEntry::file("dup.txt", b"first".to_vec(), 0),
                NewEntry::file("dup.txt", b"second".to_vec(), 0),
            ])
            .unwrap(),
        )
        .unwrap();
        let dest = base.join("out");
        assert_eq!(
            ak_extract(
                cstr(zip_path.to_str().unwrap()).as_ptr(),
                cstr(dest.to_str().unwrap()).as_ptr(),
                std::ptr::null()
            ),
            -1
        );
        assert_eq!(ak_last_error_code(), ERR_CORRUPT as c_int);
        // SAFETY: the pointer is a thread-local C string owned by this module.
        let message = unsafe { CStr::from_ptr(ak_last_error()) }
            .to_str()
            .unwrap()
            .to_string();
        assert!(message.contains("two entries"), "{message}");
        assert!(message.contains("dup.txt"), "{message}");
        // The first entry's content is what landed, untouched.
        assert_eq!(fs::read(dest.join("dup.txt")).unwrap(), b"first");

        // Directories may legitimately be listed more than once.
        fs::write(
            &zip_path,
            zip::create(&[
                NewEntry::dir("d", 0),
                NewEntry::dir("d", 0),
                NewEntry::file("d/a.txt", b"a".to_vec(), 0),
            ])
            .unwrap(),
        )
        .unwrap();
        let dest2 = base.join("out2");
        assert_eq!(
            ak_extract(
                cstr(zip_path.to_str().unwrap()).as_ptr(),
                cstr(dest2.to_str().unwrap()).as_ptr(),
                std::ptr::null()
            ),
            1
        );

        // Case-only collisions only collide where the filesystem does.
        fs::write(
            &zip_path,
            zip::create(&[
                NewEntry::file("Case.txt", b"upper".to_vec(), 0),
                NewEntry::file("case.txt", b"lower".to_vec(), 0),
            ])
            .unwrap(),
        )
        .unwrap();
        let dest3 = base.join("out3");
        let result = ak_extract(
            cstr(zip_path.to_str().unwrap()).as_ptr(),
            cstr(dest3.to_str().unwrap()).as_ptr(),
            std::ptr::null(),
        );
        if cfg!(windows) {
            assert_eq!(result, -1, "case-insensitive target must refuse the second");
            assert_eq!(ak_last_error_code(), ERR_CORRUPT as c_int);
        } else {
            assert_eq!(result, 2, "case-sensitive target keeps both files");
            assert_eq!(fs::read(dest3.join("Case.txt")).unwrap(), b"upper");
            assert_eq!(fs::read(dest3.join("case.txt")).unwrap(), b"lower");
        }
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
