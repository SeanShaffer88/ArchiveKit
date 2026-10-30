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
