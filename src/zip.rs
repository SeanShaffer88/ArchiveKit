//! ZIP format (APPNOTE basics): central-directory reader and writer.
//! Supported: STORE (0) and DEFLATE (8). Refused with ERR_NOT_SUPPORTED:
//! encryption, ZIP64, multi-disk, other methods. Structure problems and
//! CRC/size mismatches are ERR_CORRUPT.

use crate::crc32::crc32;
use crate::{
    dos_to_unix, err, unix_to_dos, AResult, EntryMeta, ERR_CORRUPT, ERR_INVALID_ARG,
    ERR_NOT_SUPPORTED,
};

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;

#[derive(Clone, Debug)]
pub struct ZipEntry {
    pub meta: EntryMeta,
    pub method_id: u16,
    /// Offset of this entry's local header in the archive.
    pub local_offset: u64,
}

fn u16le(b: &[u8], off: usize) -> AResult<u16> {
    if off + 2 > b.len() {
        return err(ERR_CORRUPT, "unexpected end of archive");
    }
    Ok(u16::from_le_bytes([b[off], b[off + 1]]))
}

fn u32le(b: &[u8], off: usize) -> AResult<u32> {
    if off + 4 > b.len() {
        return err(ERR_CORRUPT, "unexpected end of archive");
    }
    Ok(u32::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}

/// Find the End Of Central Directory record by scanning the tail
/// (comment can be up to 64 KiB).
fn find_eocd(bytes: &[u8]) -> AResult<usize> {
    if bytes.len() < 22 {
        return err(ERR_CORRUPT, "file too small to be a ZIP archive");
    }
    let start = bytes.len().saturating_sub(65_557);
    let mut i = bytes.len() - 22;
    loop {
        if u32le(bytes, i)? == SIG_EOCD {
            let comment_len = u16le(bytes, i + 20)? as usize;
            if i + 22 + comment_len == bytes.len() {
                return Ok(i);
            }
        }
        if i == start {
            break;
        }
        i -= 1;
    }
    err(ERR_CORRUPT, "end of central directory not found")
}

/// Read-only bit from a central-directory record. Unix-made archives
/// (host 3 = Unix, 19 = OS X) put a POSIX mode in the high half and the DOS
/// attribute byte in the low half; DOS/Windows-made archives only use the
/// low byte, where 0x01 is the read-only attribute.
fn decode_read_only(version_made_by: u16, external_attributes: u32) -> bool {
    let host = (version_made_by >> 8) & 0xFF;
    let unix_mode = (external_attributes >> 16) & 0xFFFF;
    if matches!(host, 3 | 19) && unix_mode != 0 {
        return unix_mode & 0o200 == 0;
    }
    external_attributes & 0x01 != 0
}

/// IBM code page 437 for bytes 0x80..=0xFF, the encoding APPNOTE 4.4.4
/// assigns to ZIP names that do not set the UTF-8 flag. Legacy Windows
/// tools (and DOS-era archives) store names this way; without this table a
/// name like "caf\x82.txt" came out as "caf\u{fffd}.txt".
const CP437_HIGH: [char; 128] = [
    '\u{00c7}', '\u{00fc}', '\u{00e9}', '\u{00e2}', '\u{00e4}', '\u{00e0}', '\u{00e5}', '\u{00e7}',
    '\u{00ea}', '\u{00eb}', '\u{00e8}', '\u{00ef}', '\u{00ee}', '\u{00ec}', '\u{00c4}', '\u{00c5}',
    '\u{00c9}', '\u{00e6}', '\u{00c6}', '\u{00f4}', '\u{00f6}', '\u{00f2}', '\u{00fb}', '\u{00f9}',
    '\u{00ff}', '\u{00d6}', '\u{00dc}', '\u{00a2}', '\u{00a3}', '\u{00a5}', '\u{20a7}', '\u{0192}',
    '\u{00e1}', '\u{00ed}', '\u{00f3}', '\u{00fa}', '\u{00f1}', '\u{00d1}', '\u{00aa}', '\u{00ba}',
    '\u{00bf}', '\u{2310}', '\u{00ac}', '\u{00bd}', '\u{00bc}', '\u{00a1}', '\u{00ab}', '\u{00bb}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255d}', '\u{255c}', '\u{255b}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252c}', '\u{251c}', '\u{2500}', '\u{253c}', '\u{255e}', '\u{255f}',
    '\u{255a}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256c}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256b}',
    '\u{256a}', '\u{2518}', '\u{250c}', '\u{2588}', '\u{2584}', '\u{258c}', '\u{2590}', '\u{2580}',
    '\u{03b1}', '\u{00df}', '\u{0393}', '\u{03c0}', '\u{03a3}', '\u{03c3}', '\u{00b5}', '\u{03c4}',
    '\u{03a6}', '\u{0398}', '\u{03a9}', '\u{03b4}', '\u{221e}', '\u{03c6}', '\u{03b5}', '\u{2229}',
    '\u{2261}', '\u{00b1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00f7}', '\u{2248}',
    '\u{00b0}', '\u{2219}', '\u{00b7}', '\u{221a}', '\u{207f}', '\u{00b2}', '\u{25a0}', '\u{00a0}',
];

fn decode_name(raw: &[u8], flags: u16) -> String {
    const UTF8_FLAG: u16 = 0x0800;
    if flags & UTF8_FLAG != 0 || raw.is_ascii() {
        return String::from_utf8_lossy(raw).into_owned();
    }
    // No UTF-8 flag but the bytes are valid UTF-8: some writers forget the
    // flag. Trusting the bytes beats mojibake in both directions, because
    // genuine CP437 high bytes are almost never valid UTF-8.
    if let Ok(text) = std::str::from_utf8(raw) {
        return text.to_string();
    }
    raw.iter()
        .map(|&b| {
            if b < 0x80 {
                b as char
            } else {
                CP437_HIGH[(b - 0x80) as usize]
            }
        })
        .collect()
}

/// Extra-field tags this reader interprets. Everything else in an extra
/// field is skipped, as before: extras are a hint box, not a contract.
const EXTRA_EXTENDED_TIMESTAMP: u16 = 0x5455;
const EXTRA_NTFS: u16 = 0x000a;
const EXTRA_UNICODE_PATH: u16 = 0x7075;

/// Walk an extra field and return the first record with `tag`. A record that
/// overruns the field ends the walk: the archive is what it is, and a broken
/// extra must not become an error when the entry itself is readable.
fn extra_record(extra: &[u8], tag: u16) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[off], extra[off + 1]]);
        let len = u16::from_le_bytes([extra[off + 2], extra[off + 3]]) as usize;
        let start = off + 4;
        let end = start.checked_add(len)?;
        if end > extra.len() {
            return None;
        }
        if id == tag {
            return Some(&extra[start..end]);
        }
        off = end;
    }
    None
}

/// 100 ns ticks since 1601-01-01 to Unix seconds. Only values that land in a
/// sane range survive; anything else means "no usable timestamp" and the DOS
/// field is used instead.
fn filetime_to_unix(ticks: u64) -> Option<i64> {
    const TICKS_PER_SEC: u64 = 10_000_000;
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = i64::try_from(ticks / TICKS_PER_SEC).ok()?;
    let unix = secs.checked_sub(EPOCH_DIFF_SECS)?;
    if (0..=253_402_300_799).contains(&unix) {
        Some(unix)
    } else {
        None
    }
}

/// The exact modification time when the writer recorded one. The DOS field
/// has 2-second resolution and cannot express dates outside 1980-2107, so
/// writers that care add 0x5455 (Unix seconds, Info-ZIP) or 0x000A (NTFS
/// FILETIME, Windows). Rounding a 2001 timestamp to the next even second, or
/// reporting 1980 for a 1975 file, is a wrong answer, not a rounding detail.
fn extra_mtime(extra: &[u8]) -> Option<i64> {
    if let Some(data) = extra_record(extra, EXTRA_EXTENDED_TIMESTAMP) {
        let flags = *data.first()?;
        if flags & 1 != 0 && data.len() >= 5 {
            let secs = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            if secs != 0 {
                return Some(i64::from(secs));
            }
        }
    }
    // NTFS: 4 reserved bytes, then tag/size pairs; tag 1 holds mtime, atime
    // and ctime as FILETIMEs.
    let ntfs = extra_record(extra, EXTRA_NTFS)?;
    let mut off = 4usize;
    while off + 4 <= ntfs.len() {
        let tag = u16::from_le_bytes([ntfs[off], ntfs[off + 1]]);
        let len = u16::from_le_bytes([ntfs[off + 2], ntfs[off + 3]]) as usize;
        let start = off + 4;
        if start.checked_add(len)? > ntfs.len() {
            return None;
        }
        if tag == 1 && len >= 8 {
            let ticks = u64::from_le_bytes(ntfs[start..start + 8].try_into().ok()?);
            return filetime_to_unix(ticks);
        }
        off = start + len;
    }
    None
}

/// 0x7075 carries the entry name as UTF-8 for writers whose name field is a
/// legacy code page. The CRC of the raw name guards against stale records; a
/// name that is empty or holds a NUL is refused, since neither can become a
/// path. Names stay untrusted input either way: `safe_join` still decides.
fn extra_unicode_name(extra: &[u8], raw_name: &[u8]) -> Option<String> {
    let data = extra_record(extra, EXTRA_UNICODE_PATH)?;
    if data.len() < 5 || data[0] != 1 {
        return None;
    }
    let recorded = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if recorded != crc32(raw_name) {
        return None;
    }
    let text = std::str::from_utf8(&data[5..]).ok()?;
    if text.is_empty() || text.contains('\0') {
        return None;
    }
    Some(text.to_string())
}

pub fn list(bytes: &[u8]) -> AResult<Vec<ZipEntry>> {
    let eocd = find_eocd(bytes)?;
    let disk = u16le(bytes, eocd + 4)?;
    let entries_this_disk = u16le(bytes, eocd + 8)?;
    let total_entries = u16le(bytes, eocd + 10)?;
    let cd_size = u32le(bytes, eocd + 12)?;
    let cd_offset_raw = u32le(bytes, eocd + 16)?;
    if disk != 0 {
        return err(
            ERR_NOT_SUPPORTED,
            "multi-disk ZIP archives are not supported",
        );
    }
    // 0xFFFF / 0xFFFFFFFF are ZIP64's "the real value lives elsewhere"
    // markers. Reading on would mis-locate the central directory, so say
    // what is wrong instead of reporting a corrupt archive.
    if entries_this_disk == 0xFFFF
        || total_entries == 0xFFFF
        || cd_size == 0xFFFF_FFFF
        || cd_offset_raw == 0xFFFF_FFFF
    {
        return err(
            ERR_NOT_SUPPORTED,
            "ZIP64 archives are not supported in v0.2 (entry count or offset overflows the classic format)",
        );
    }
    let total = total_entries as usize;
    let cd_offset = cd_offset_raw as usize;
    if total > crate::MAX_ENTRIES {
        return err(ERR_CORRUPT, "ZIP entry count exceeds limit");
    }
    // Self-extractors and installers prepend a stub, so the recorded offsets
    // are short by its size. The central directory always ends exactly where
    // the EOCD begins, which pins its real position; that is only trusted
    // when the signature is actually there, and the same shift is then
    // applied to every local header offset.
    let mut shift = 0i64;
    if u32le(bytes, cd_offset).unwrap_or(0) != SIG_CENTRAL {
        if let Some(actual) = eocd.checked_sub(cd_size as usize) {
            if actual + cd_size as usize == eocd && u32le(bytes, actual).unwrap_or(0) == SIG_CENTRAL
            {
                shift = actual as i64 - cd_offset as i64;
            }
        }
    }
    let mut entries = Vec::with_capacity(total);
    let mut off = (cd_offset as i64 + shift) as usize;
    for _ in 0..total {
        if u32le(bytes, off)? != SIG_CENTRAL {
            return err(ERR_CORRUPT, "bad central directory signature");
        }
        let flags = u16le(bytes, off + 8)?;
        let method = u16le(bytes, off + 10)?;
        let mtime = u16le(bytes, off + 12)?;
        let mdate = u16le(bytes, off + 14)?;
        let crc = u32le(bytes, off + 16)?;
        let comp = u32le(bytes, off + 20)?;
        let size = u32le(bytes, off + 24)?;
        let version_made_by = u16le(bytes, off + 4)?;
        let name_len = u16le(bytes, off + 28)? as usize;
        let extra_len = u16le(bytes, off + 30)? as usize;
        let comment_len = u16le(bytes, off + 32)? as usize;
        let external_attributes = u32le(bytes, off + 38)?;
        let local_offset = u32le(bytes, off + 42)?;
        if comp == 0xFFFF_FFFF || size == 0xFFFF_FFFF || local_offset == 0xFFFF_FFFF {
            return err(
                ERR_NOT_SUPPORTED,
                "ZIP64 entries are not supported (v0.2 writes and reads classic ZIP only)",
            );
        }
        if flags & 1 != 0 {
            return err(ERR_NOT_SUPPORTED, "encrypted ZIP entries are not supported");
        }
        let name_start = off + 46;
        if name_start + name_len + extra_len > bytes.len() {
            return err(ERR_CORRUPT, "central directory name overruns archive");
        }
        let raw_name = &bytes[name_start..name_start + name_len];
        let extra = &bytes[name_start + name_len..name_start + name_len + extra_len];
        let name =
            extra_unicode_name(extra, raw_name).unwrap_or_else(|| decode_name(raw_name, flags));
        // ZIP marks directories with a trailing `/`, but some writers only
        // set the DOS directory attribute (0x10) and leave the name bare.
        // Trusting the slash alone turned those into zero-byte files.
        let is_dir = name.ends_with('/') || external_attributes & 0x10 != 0;
        entries.push(ZipEntry {
            meta: EntryMeta {
                name,
                size: size as u64,
                compressed_size: comp as u64,
                method: match method {
                    0 => "store".to_string(),
                    8 => "deflate".to_string(),
                    m => format!("method-{m}"),
                },
                is_dir,
                crc32: Some(crc),
                modified_unix: Some(
                    extra_mtime(extra).unwrap_or_else(|| dos_to_unix(mtime, mdate)),
                ),
                kind: if is_dir {
                    crate::EntryKind::Dir
                } else {
                    crate::EntryKind::File
                },
                read_only: decode_read_only(version_made_by, external_attributes),
            },
            method_id: method,
            local_offset: u64::try_from(local_offset as i64 + shift).map_err(|_| {
                (
                    ERR_CORRUPT,
                    "entry offset points before the archive".to_string(),
                )
            })?,
        });
        off = name_start + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

/// Decompress + verify one entry's data.
pub fn read_entry(bytes: &[u8], entry: &ZipEntry) -> AResult<Vec<u8>> {
    if entry.meta.size > crate::MAX_ENTRY_BYTES as u64 {
        return err(
            ERR_CORRUPT,
            format!(
                "entry '{}' is {} bytes, over the {} MiB per-entry limit",
                entry.meta.name,
                entry.meta.size,
                crate::MAX_ENTRY_BYTES / (1024 * 1024)
            ),
        );
    }
    let off = entry.local_offset as usize;
    if u32le(bytes, off)? != SIG_LOCAL {
        return err(ERR_CORRUPT, "bad local header signature");
    }
    let name_len = u16le(bytes, off + 26)? as usize;
    let extra_len = u16le(bytes, off + 28)? as usize;
    let data_start = off + 30 + name_len + extra_len;
    let comp_size = entry.meta.compressed_size as usize;
    if data_start + comp_size > bytes.len() {
        return err(ERR_CORRUPT, "entry data overruns archive");
    }
    let raw = &bytes[data_start..data_start + comp_size];
    let data = match entry.method_id {
        0 => raw.to_vec(),
        8 => crate::inflate::inflate_limited(raw, entry.meta.size as usize)
            .map_err(|e| (ERR_CORRUPT, e))?,
        m => {
            return err(
                ERR_NOT_SUPPORTED,
                format!("ZIP compression method {m} is not supported (only store/deflate)"),
            )
        }
    };
    if data.len() as u64 != entry.meta.size {
        return err(
            ERR_CORRUPT,
            format!(
                "entry '{}' size mismatch: directory says {}, data is {}",
                entry.meta.name,
                entry.meta.size,
                data.len()
            ),
        );
    }
    if let Some(expected) = entry.meta.crc32 {
        let actual = crc32(&data);
        if actual != expected {
            return err(
                ERR_CORRUPT,
                format!(
                    "entry '{}' CRC mismatch: expected {expected:08x}, got {actual:08x}",
                    entry.meta.name
                ),
            );
        }
    }
    Ok(data)
}

/// Verify every entry (decompress + CRC). Returns the entry count.
pub fn test(bytes: &[u8]) -> AResult<usize> {
    let entries = list(bytes)?;
    for e in &entries {
        if !e.meta.is_dir {
            read_entry(bytes, e)?;
        }
    }
    Ok(entries.len())
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

pub struct NewEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub modified_unix: i64,
    /// Store without compression (small or incompressible data is chosen
    /// automatically anyway; this forces it).
    pub force_store: bool,
    /// Record the DOS read-only attribute for this entry.
    pub read_only: bool,
}

impl NewEntry {
    pub fn file(name: impl Into<String>, data: Vec<u8>, modified_unix: i64) -> Self {
        NewEntry {
            name: name.into(),
            data,
            modified_unix,
            force_store: false,
            read_only: false,
        }
    }
    pub fn dir(name: impl Into<String>, modified_unix: i64) -> Self {
        let mut n = name.into();
        if !n.ends_with('/') {
            n.push('/');
        }
        NewEntry {
            name: n,
            data: Vec::new(),
            modified_unix,
            force_store: true,
            read_only: false,
        }
    }
}

/// Write a classic ZIP (no ZIP64). Anything that needs ZIP64 — more than
/// 65,535 entries, a member or offset at or above 4 GiB — is refused with
/// ERR_NOT_SUPPORTED rather than written with wrapped counts.
pub fn create(entries: &[NewEntry]) -> AResult<Vec<u8>> {
    if entries.len() > u16::MAX as usize {
        return err(
            ERR_NOT_SUPPORTED,
            "more than 65,535 entries needs ZIP64, which is not written",
        );
    }
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for e in entries {
        if e.name.len() > u16::MAX as usize {
            return err(ERR_INVALID_ARG, "ZIP entry name exceeds 65,535 bytes");
        }
        if e.data.len() as u64 > u32::MAX as u64 {
            return err(
                ERR_NOT_SUPPORTED,
                format!("entry '{}' is 4 GiB or larger, which needs ZIP64", e.name),
            );
        }
        if out.len() as u64 > u32::MAX as u64 {
            return err(
                ERR_NOT_SUPPORTED,
                "archive exceeds 4 GiB, which needs ZIP64",
            );
        }
        let (time, date) = unix_to_dos(e.modified_unix);
        let crc = crc32(&e.data);
        let is_dir = e.name.ends_with('/');
        let compressed = if e.force_store || is_dir {
            e.data.clone()
        } else {
            crate::deflate::deflate(&e.data)
        };
        let (method, payload) = if !e.force_store && !is_dir && compressed.len() < e.data.len() {
            (8u16, compressed)
        } else {
            (0u16, e.data.clone())
        };
        let offset = out.len() as u32;
        let name = e.name.as_bytes();
        // Local header
        out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // flags: UTF-8 names
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&time.to_le_bytes());
        out.extend_from_slice(&date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(&payload);
        // Central directory record
        central.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&time.to_le_bytes());
        central.extend_from_slice(&date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        central.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
                                                        // DOS attribute byte: 0x10 marks a directory, 0x01 read-only.
        let attributes: u32 = if is_dir { 0x10 } else { 0 } | if e.read_only { 0x01 } else { 0 };
        central.extend_from_slice(&attributes.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    // The per-entry check fails fast, but the last entry can still push the
    // layout past 4 GiB; the offsets below are 32-bit.
    if out.len() as u64 > u32::MAX as u64 {
        return err(
            ERR_NOT_SUPPORTED,
            "archive exceeds 4 GiB, which needs ZIP64",
        );
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&SIG_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let count = entries.len() as u16;
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entries() -> Vec<NewEntry> {
        vec![
            NewEntry::dir("docs", 1_792_674_000),
            NewEntry::file(
                "docs/hello.txt",
                b"hello world, hello zip!".to_vec(),
                1_792_674_000,
            ),
            NewEntry::file(
                "big.txt",
                b"the quick brown fox jumps over the lazy dog. ".repeat(100),
                1_792_674_000,
            ),
            NewEntry::file("empty.bin", Vec::new(), 1_792_674_000),
        ]
    }

    /// Build a one-entry STORE archive with explicit extra fields, DOS time
    /// and date, and an optional prefix of foreign bytes, so the reader can
    /// be tested against byte sequences it never writes itself.
    fn hand_built_extras(
        name: &[u8],
        data: &[u8],
        extra: &[u8],
        dos_time: u16,
        dos_date: u16,
        prefix: &[u8],
    ) -> Vec<u8> {
        let crc = crc32(data);
        let mut out = Vec::new();
        out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // store
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(extra);
        out.extend_from_slice(data);
        // Offsets are recorded as if the prefix were not there, exactly like a
        // real self-extractor's stub.
        let cd_offset = out.len() as u32;
        let cd_start = out.len();
        out.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // store
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // local offset
        out.extend_from_slice(name);
        out.extend_from_slice(extra);
        let cd_size = (out.len() - cd_start) as u32;
        out.extend_from_slice(&SIG_EOCD.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        let mut archive = prefix.to_vec();
        archive.extend_from_slice(&out);
        archive
    }

    /// One extra-field record as it appears on disk: tag, length, payload.
    fn extra(tag: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn exact_times_come_from_extras() {
        // 2001-01-21T12:20:01Z: an odd second the DOS field cannot express,
        // so 0x5455 must win over the stored 2-second value.
        let mut payload = vec![1u8]; // flags: mtime present
        payload.extend_from_slice(&979_902_001u32.to_le_bytes());
        let stamp = extra(0x5455, &payload);
        let archive = hand_built_extras(b"a.txt", b"hi", &stamp, 0, 0x21, b"");
        let listed = list(&archive).unwrap();
        assert_eq!(listed[0].meta.modified_unix, Some(979_902_001));

        // A pre-1980 timestamp (DOS clamps to 1980) survives too.
        let mut old = vec![1u8];
        old.extend_from_slice(&100_000_000u32.to_le_bytes());
        let archive = hand_built_extras(b"a.txt", b"hi", &extra(0x5455, &old), 0, 0x21, b"");
        assert_eq!(
            list(&archive).unwrap()[0].meta.modified_unix,
            Some(100_000_000)
        );

        // Windows writes 0x000A: reserved word, then tag 1 with FILETIMEs.
        let mut ntfs = vec![0u8; 4];
        ntfs.extend_from_slice(&1u16.to_le_bytes());
        ntfs.extend_from_slice(&24u16.to_le_bytes());
        ntfs.extend_from_slice(&128_000_000_000_000_000u64.to_le_bytes());
        ntfs.extend_from_slice(&0u64.to_le_bytes());
        ntfs.extend_from_slice(&0u64.to_le_bytes());
        let archive = hand_built_extras(b"a.txt", b"hi", &extra(0x000a, &ntfs), 0, 0x21, b"");
        assert_eq!(
            list(&archive).unwrap()[0].meta.modified_unix,
            Some(1_155_526_400)
        );

        // Flags saying "no mtime" and a zero timestamp both fall back to DOS.
        let none = extra(0x5455, &[0u8, 0, 0, 0, 0]);
        let archive = hand_built_extras(b"a.txt", b"hi", &none, 0, 0x21, b"");
        assert_eq!(
            list(&archive).unwrap()[0].meta.modified_unix,
            Some(crate::dos_to_unix(0, 0x21))
        );
    }

    #[test]
    fn unicode_path_extra_wins_over_the_legacy_name() {
        // Java's zipfs and some 7-Zip settings write the name in a legacy code
        // page and put UTF-8 in 0x7075. CP437 alone turned this into `cafΘ`.
        let raw = b"caf\xe9.txt";
        let utf8 = "café.txt".as_bytes();
        let mut payload = vec![1u8]; // version
        payload.extend_from_slice(&crc32(raw).to_le_bytes());
        payload.extend_from_slice(utf8);
        let archive = hand_built_extras(raw, b"hi", &extra(0x7075, &payload), 0, 0x21, b"");
        assert_eq!(list(&archive).unwrap()[0].meta.name, "café.txt");

        // A stale record (wrong CRC) is ignored rather than trusted.
        let mut stale = vec![1u8];
        stale.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        stale.extend_from_slice(utf8);
        let archive = hand_built_extras(raw, b"hi", &extra(0x7075, &stale), 0, 0x21, b"");
        assert_ne!(list(&archive).unwrap()[0].meta.name, "café.txt");

        // A name that cannot become a path is refused, not passed on.
        let mut weird = vec![1u8];
        weird.extend_from_slice(&crc32(raw).to_le_bytes());
        weird.extend_from_slice(b"bad\0name.txt");
        let archive = hand_built_extras(raw, b"hi", &extra(0x7075, &weird), 0, 0x21, b"");
        assert_ne!(list(&archive).unwrap()[0].meta.name, "bad");
    }

    #[test]
    fn a_prepended_stub_does_not_hide_the_entries() {
        // Self-extractors and installers put their own bytes in front of a
        // normal archive, so every recorded offset is short. The central
        // directory still ends where the EOCD begins, which pins the shift.
        let plain = hand_built_extras(b"a.txt", b"payload", b"", 0, 0x21, b"");
        let mut stubbed = b"MZ\x90\x00stub!".repeat(11);
        let stub_len = stubbed.len();
        stubbed.extend_from_slice(&plain);
        let listed = list(&stubbed).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].meta.name, "a.txt");
        assert_eq!(read_entry(&stubbed, &listed[0]).unwrap(), b"payload");
        assert!(listed[0].local_offset >= stub_len as u64);

        // Without the signature right before the EOCD the shift is not
        // guessed: a genuinely broken offset stays an error.
        let mut broken = hand_built_extras(b"a.txt", b"payload", b"", 0, 0x21, b"");
        let eocd = broken.len() - 22;
        broken[eocd + 16..eocd + 20].copy_from_slice(&9999u32.to_le_bytes());
        assert!(list(&broken).is_err());
    }

    #[test]
    fn extra_field_walker_refuses_truncated_records() {
        // A record whose length runs past the field must not be read as if it
        // were whole, and must not panic.
        let truncated = [0x55u8, 0x54, 0xff, 0x00, 1, 2, 3];
        assert!(extra_record(&truncated, 0x5455).is_none());
        assert!(extra_record(&[], 0x5455).is_none());
        // A record with no payload is well-formed but useless.
        assert_eq!(extra_record(&extra(0x5455, &[]), 0x5455), Some(&[][..]));
        // FILETIME conversions outside the sane range are refused.
        assert_eq!(filetime_to_unix(0), None);
        assert_eq!(filetime_to_unix(u64::MAX), None);
        assert_eq!(filetime_to_unix(116_444_736_000_000_000), Some(0));
    }

    #[test]
    fn roundtrip() {
        let bytes = create(&sample_entries()).unwrap();
        let listed = list(&bytes).unwrap();
        assert_eq!(listed.len(), 4);
        assert!(listed[0].meta.is_dir);
        assert_eq!(listed[2].meta.method, "deflate"); // 4500 repetitive bytes
        assert_eq!(test(&bytes).unwrap(), 4);
        let data = read_entry(&bytes, &listed[1]).unwrap();
        assert_eq!(data, b"hello world, hello zip!");
        let big = read_entry(&bytes, &listed[2]).unwrap();
        assert_eq!(big.len(), 4500);
    }

    /// Hand-build a one-entry STORE archive so tests can emit byte
    /// sequences this crate never writes (foreign name encodings, data
    /// descriptors) rather than only reading back its own output.
    fn hand_built(name: &[u8], data: &[u8], flags: u16, descriptor: bool) -> Vec<u8> {
        hand_built_attrs(name, data, flags, descriptor, 0)
    }

    fn hand_built_attrs(
        name: &[u8],
        data: &[u8],
        flags: u16,
        descriptor: bool,
        attributes: u32,
    ) -> Vec<u8> {
        let crc = crc32(data);
        let (local_crc, local_comp, local_size) = if descriptor {
            (0, 0, 0) // sizes deferred to the trailing data descriptor
        } else {
            (crc, data.len() as u32, data.len() as u32)
        };
        let mut out = Vec::new();
        out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // store
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0x21u16.to_le_bytes()); // date
        out.extend_from_slice(&local_crc.to_le_bytes());
        out.extend_from_slice(&local_comp.to_le_bytes());
        out.extend_from_slice(&local_size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(data);
        if descriptor {
            out.extend_from_slice(&0x0807_4b50u32.to_le_bytes()); // data descriptor
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        }
        let cd_offset = out.len() as u32;
        let central_start = out.len();
        out.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x21u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&attributes.to_le_bytes()); // external attributes
        out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        out.extend_from_slice(name);
        let cd_size = out.len() - central_start;
        out.extend_from_slice(&SIG_EOCD.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(cd_size as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn directory_attribute_marks_directories_without_a_trailing_slash() {
        // Some writers emit "folder" with the DOS directory attribute and no
        // trailing slash; treating that as a file created a zero-byte file
        // instead of a directory.
        let bytes = hand_built_attrs(b"folder", b"", 0, false, 0x10);
        let listed = list(&bytes).unwrap();
        assert!(listed[0].meta.is_dir, "0x10 marks a directory");
        // The trailing-slash convention still works, and a plain file with
        // the archive bit is still a file.
        assert!(
            list(&hand_built(b"with-slash/", b"", 0, false)).unwrap()[0]
                .meta
                .is_dir
        );
        assert!(
            !list(&hand_built_attrs(b"plain.txt", b"x", 0, false, 0x20)).unwrap()[0]
                .meta
                .is_dir
        );
    }

    #[test]
    fn read_only_bit_decodes_for_dos_and_unix_hosts() {
        // DOS/Windows-made: low byte, bit 0 is the read-only attribute.
        assert!(decode_read_only(0x0014, 0x01));
        assert!(!decode_read_only(0x0014, 0x20)); // archive bit only
        assert!(decode_read_only(0x0014, 0x11)); // read-only directory
                                                 // Unix host (3) and OS X (19): a POSIX mode in the high half wins,
                                                 // because DOS tools set the low byte to 0 and would say "writable".
        assert!(decode_read_only(0x0314, 0o444u32 << 16));
        assert!(!decode_read_only(0x0314, 0o644u32 << 16));
        assert!(decode_read_only(0x1314, 0o555u32 << 16));
        // No mode recorded: fall back to the DOS byte rather than treating a
        // mode of 0 as read-only.
        assert!(!decode_read_only(0x0314, 0));
        // One we write ourselves: DOS host, plain file.
        assert!(!decode_read_only(0x0014, 0));
    }

    #[test]
    fn legacy_cp437_names_are_decoded() {
        // APPNOTE 4.4.4: without the UTF-8 flag, names are CP437. 0x82 is
        // 'é', so this is the DOS-era spelling of "café-pré.txt" and used
        // to surface as replacement characters.
        let bytes = hand_built(b"caf\x82-pr\x82.txt", b"legacy name", 0, false);
        let listed = list(&bytes).unwrap();
        assert_eq!(listed[0].meta.name, "café-pré.txt");
        assert_eq!(read_entry(&bytes, &listed[0]).unwrap(), b"legacy name");
        // Box-drawing characters are a different byte in CP437 than in
        // UTF-8, so this also pins the table beyond the Latin-1 range.
        let bytes = hand_built(b"\xc9\xcd\xbb.txt", b"x", 0, false);
        assert_eq!(list(&bytes).unwrap()[0].meta.name, "╔═╗.txt");
        // Writers that set the UTF-8 flag are read as UTF-8 and left alone.
        let bytes = hand_built("café-pré.txt".as_bytes(), b"x", 0x0800, false);
        assert_eq!(list(&bytes).unwrap()[0].meta.name, "café-pré.txt");
        // Valid UTF-8 *without* the flag: trust the bytes rather than
        // rendering real UTF-8 as CP437 mojibake.
        let bytes = hand_built("café-pré.txt".as_bytes(), b"x", 0, false);
        assert_eq!(list(&bytes).unwrap()[0].meta.name, "café-pré.txt");
    }

    #[test]
    fn data_descriptor_archives_are_read_from_the_central_directory() {
        // Streaming writers (flag bit 3) put zero sizes in the local header
        // and the real values in a trailing descriptor. Sizes come from the
        // central directory, so the local placeholder must not matter.
        let bytes = hand_built(b"streamed.txt", b"streamed payload", 0x0008, true);
        let listed = list(&bytes).unwrap();
        assert_eq!(listed[0].meta.size, 16);
        assert_eq!(listed[0].meta.compressed_size, 16);
        assert_eq!(read_entry(&bytes, &listed[0]).unwrap(), b"streamed payload");
        assert_eq!(test(&bytes).unwrap(), 1);
    }

    #[test]
    fn classic_entry_count_is_enforced() {
        // 65,535 entries fit the classic EOCD count; one more needs ZIP64,
        // which this writer does not emit. Refusing beats writing a count
        // that wraps to 0 and describes none of the entries.
        let many: Vec<NewEntry> = (0..=u16::MAX)
            .map(|i| NewEntry::file(format!("f{i}.txt"), Vec::new(), 0))
            .collect();
        assert_eq!(many.len(), u16::MAX as usize + 1);
        match create(&many) {
            Err((code, message)) => {
                assert_eq!(code, ERR_NOT_SUPPORTED);
                assert!(message.contains("ZIP64"), "{message}");
            }
            Ok(bytes) => panic!("wrote {} bytes for 65,536 entries", bytes.len()),
        }
    }

    #[test]
    fn zip64_markers_are_refused_not_misread() {
        // Start from a real archive, then flip the EOCD entry count to the
        // ZIP64 marker. This must be NOT_SUPPORTED, not a silent partial
        // listing or a spurious corruption report.
        let mut bytes = create(&sample_entries()).unwrap();
        let eocd = bytes.len() - 22;
        bytes[eocd + 10] = 0xFF;
        bytes[eocd + 11] = 0xFF;
        match list(&bytes) {
            Err((code, message)) => {
                assert_eq!(code, ERR_NOT_SUPPORTED, "{message}");
                assert!(message.contains("ZIP64"), "{message}");
            }
            Ok(listed) => panic!("ZIP64 marker accepted: {} entries", listed.len()),
        }
    }

    #[test]
    fn corruption_detected() {
        // Stored entry with known content: flipping a data byte MUST trip
        // the CRC check deterministically.
        let entries = vec![NewEntry {
            name: "plain.txt".into(),
            data: b"ABCDEFGH".repeat(20).to_vec(),
            modified_unix: 1_792_674_000,
            force_store: true,
            read_only: false,
        }];
        let mut bytes = create(&entries).unwrap();
        let pos = bytes
            .windows(8)
            .position(|w| w == b"ABCDEFGH")
            .expect("stored content present verbatim");
        bytes[pos + 3] ^= 0xFF;
        let listed = list(&bytes).unwrap();
        assert!(read_entry(&bytes, &listed[0]).is_err());
        assert!(test(&bytes).is_err());
        // Truncation.
        let bytes = create(&sample_entries()).unwrap();
        let short = &bytes[..bytes.len() - 10];
        assert!(list(short).is_err());
    }
}
