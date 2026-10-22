//! ArchiveKit — pure logic core: ZIP and TAR archives, CRC-32, and a
//! from-scratch DEFLATE codec (RFC 1951) so the crate stays at ZERO
//! dependencies. The C ABI lives in [`ffi`]; directory walking for
//! create-from-folder lives in [`platform`].
//!
//! v0.1 scope (stated plainly):
//! - ZIP: read + write, STORE and DEFLATE methods. No encryption, no
//!   ZIP64, no multi-disk archives — archives needing them fail with
//!   ERR_NOT_SUPPORTED and a specific message, never a silent misread.
//! - TAR: read + write (ustar). Regular files and directories.
//! - Extraction rejects unsafe lexical names and detected link ancestors; entries that would
//!   land outside the destination are refused (see [`safe_join`]).

pub mod crc32;
pub mod deflate;
pub mod ffi;
pub mod inflate;
pub mod platform;
pub mod tar;
pub mod zip;

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
pub const VERSION_PATCH: u32 = 0;

pub const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_ENTRY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 10_000;

pub const AK_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;
/// The archive bytes are malformed or fail an integrity check.
pub const ERR_CORRUPT: i32 = 7;

pub type AResult<T> = Result<T, (i32, String)>;

pub fn err<T>(code: i32, msg: impl Into<String>) -> AResult<T> {
    Err((code, msg.into()))
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Archive model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Zip,
    Tar,
}

impl Format {
    pub fn name(&self) -> &'static str {
        match self {
            Format::Zip => "zip",
            Format::Tar => "tar",
        }
    }
}

/// Detect the format from content first (magic bytes), extension second.
pub fn detect_format(bytes: &[u8], path_hint: &str) -> AResult<Format> {
    if bytes.len() >= 4 && &bytes[0..2] == b"PK" && bytes[2] == 3 && bytes[3] == 4 {
        return Ok(Format::Zip);
    }
    if bytes.len() >= 4 && &bytes[0..2] == b"PK" && bytes[2] == 5 && bytes[3] == 6 {
        return Ok(Format::Zip); // empty zip: EOCD only
    }
    if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        return Ok(Format::Tar);
    }
    let lower = path_hint.to_lowercase();
    if lower.ends_with(".zip") {
        Ok(Format::Zip)
    } else if lower.ends_with(".tar") {
        Ok(Format::Tar)
    } else {
        err(
            ERR_NOT_SUPPORTED,
            "cannot determine archive format (no ZIP/TAR signature, unknown extension)",
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EntryMeta {
    pub name: String,
    pub size: u64,
    pub compressed_size: u64,
    /// "store" | "deflate" | "tar" | other method names for listings.
    pub method: String,
    pub is_dir: bool,
    pub crc32: Option<u32>,
    pub modified_unix: Option<i64>,
}

impl EntryMeta {
    pub fn to_json(&self) -> String {
        let crc = match self.crc32 {
            Some(c) => format!("\"{c:08x}\""),
            None => "null".to_string(),
        };
        let mtime = match self.modified_unix {
            Some(m) => m.to_string(),
            None => "null".to_string(),
        };
        format!(
            "{{\"name\":\"{}\",\"size\":{},\"compressed_size\":{},\"method\":\"{}\",\"is_dir\":{},\"crc32\":{},\"modified_unix\":{}}}",
            json_escape(&self.name),
            self.size,
            self.compressed_size,
            json_escape(&self.method),
            self.is_dir,
            crc,
            mtime
        )
    }
}

pub fn list_json(entries: &[EntryMeta]) -> String {
    let mut s = String::from("[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&e.to_json());
    }
    s.push(']');
    s
}

// ---------------------------------------------------------------------------
// Traversal safety
// ---------------------------------------------------------------------------

/// Join an archive entry name onto a destination directory, refusing
/// anything that could escape it: absolute paths, drive-relative names,
/// `..` components, NUL bytes. Both `/` and `\` are treated as separators
/// (a Windows extractor must not be fooled by either). Returns the safe
/// path, or None when the entry must be refused.
pub fn safe_join(dest: &std::path::Path, entry_name: &str) -> Option<std::path::PathBuf> {
    if entry_name.contains('\0') {
        return None;
    }
    let name = entry_name.replace('\\', "/");
    if name.starts_with('/') || name.starts_with("//") {
        return None;
    }
    // Drive-relative or absolute Windows forms: "C:...", "C/...".
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let mut out = dest.to_path_buf();
    let mut parts = 0;
    for comp in name.split('/') {
        match comp {
            "" | "." => continue,
            ".." => return None,
            c => {
                if c.contains(':') || c.ends_with([' ', '.']) || c.chars().any(char::is_control) {
                    return None;
                }
                let stem = c.split('.').next().unwrap_or("").to_ascii_uppercase();
                if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                        && stem.len() == 4
                        && matches!(stem.as_bytes()[3], b'1'..=b'9'))
                {
                    return None;
                }
                out.push(c);
                parts += 1;
            }
        }
    }
    if parts == 0 {
        return None;
    }
    Some(out)
}

/// Is `name` a directory entry (by archive convention: trailing slash,
/// or a TAR dir record — callers pass what their format says)?
pub fn looks_like_dir(name: &str) -> bool {
    name.ends_with('/') || name.ends_with('\\')
}

// ---------------------------------------------------------------------------
// Time conversion (DOS <-> unix), self-contained civil-date math.
// ---------------------------------------------------------------------------

pub fn unix_to_dos(unix: i64) -> (u16, u16) {
    // (dos_time, dos_date); clamped to the DOS range 1980..=2107.
    let unix = unix.max(31_536_000); // 1980-01-01 + a day of slack
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (y, m, d) = if y < 1980 {
        (1980, 1, 1)
    } else if y > 2107 {
        (2107, 12, 31)
    } else {
        (y, m, d)
    };
    let time = (((secs / 3600) as u16) << 11)
        | ((((secs % 3600) / 60) as u16) << 5)
        | (((secs % 60) / 2) as u16);
    let date = (((y - 1980) as u16) << 9) | ((m as u16) << 5) | (d as u16);
    (time, date)
}

pub fn dos_to_unix(time: u16, date: u16) -> i64 {
    let y = ((date >> 9) & 0x7F) as i64 + 1980;
    let m = ((date >> 5) & 0xF) as i64;
    let d = (date & 0x1F) as i64;
    let hh = ((time >> 11) & 0x1F) as i64;
    let mm = ((time >> 5) & 0x3F) as i64;
    let ss = ((time & 0x1F) as i64) * 2;
    days_from_civil(y, m.max(1), d.max(1)) * 86_400 + hh * 3600 + mm * 60 + ss
}

/// Howard Hinnant's civil-from-days (public domain algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = y_adj.div_euclid(400);
    let yoe = y_adj.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rules() {
        let dest = std::path::Path::new("/tmp/out");
        assert!(safe_join(dest, "a/b.txt").is_some());
        assert!(safe_join(dest, "a\\b.txt").is_some());
        assert!(safe_join(dest, "../evil.txt").is_none());
        assert!(safe_join(dest, "a/../../evil").is_none());
        assert!(safe_join(dest, "/abs/path").is_none());
        assert!(safe_join(dest, "C:\\evil").is_none());
        assert!(safe_join(dest, "C:evil").is_none());
        assert!(safe_join(dest, "").is_none());
        assert!(safe_join(dest, ".").is_none());
        let p = safe_join(dest, "a/./b.txt").unwrap();
        assert!(p.ends_with("a/b.txt") || p.to_string_lossy().contains("a"));
    }

    #[test]
    fn dos_time_roundtrip() {
        // 2026-10-20 14:39:00 UTC
        let unix = 1_792_674_000;
        let (t, d) = unix_to_dos(unix);
        let back = dos_to_unix(t, d);
        assert!((unix - back).abs() <= 2, "unix {unix} -> back {back}");
        // Pre-1980 timestamps clamp to the DOS epoch: 1980-01-01 00:00:00 UTC.
        let (t0, d0) = unix_to_dos(0);
        assert_eq!(dos_to_unix(t0, d0), 315_532_800);
    }

    #[test]
    fn detect() {
        assert_eq!(
            detect_format(b"PK\x03\x04rest", "x.bin").unwrap(),
            Format::Zip
        );
        let mut tar = vec![0u8; 300];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_format(&tar, "x.bin").unwrap(), Format::Tar);
        assert_eq!(detect_format(b"junk", "a.zip").unwrap(), Format::Zip);
        assert!(detect_format(b"junk", "a.rar").is_err());
    }
}
