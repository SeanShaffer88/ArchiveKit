//! Platform layer: collecting a directory tree for create-from-folder.
//! Pure `std::fs` — ArchiveKit has no OS-specific APIs in v0.1; the
//! module exists to keep filesystem walking out of the format code.
//! Symlinks are never followed (loop safety; same rule as FastSearch).

use crate::{err, AResult, ERR_NOT_FOUND, ERR_PLATFORM};

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
    let mut stack = vec![root_path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue, // unreadable subdirectories are skipped
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
            let rel = path
                .strip_prefix(root_path)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let is_dir = ft.is_dir();
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
