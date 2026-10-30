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
    let mut entries = Vec::with_capacity(total);
    let mut off = cd_offset;
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
        let name_len = u16le(bytes, off + 28)? as usize;
        let extra_len = u16le(bytes, off + 30)? as usize;
        let comment_len = u16le(bytes, off + 32)? as usize;
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
        if name_start + name_len > bytes.len() {
            return err(ERR_CORRUPT, "central directory name overruns archive");
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_start + name_len]).into_owned();
        let is_dir = name.ends_with('/');
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
                modified_unix: Some(dos_to_unix(mtime, mdate)),
            },
            method_id: method,
            local_offset: local_offset as u64,
        });
        off = name_start + name_len + extra_len + comment_len;
    }
    Ok(entries)
}

/// Decompress + verify one entry's data.
pub fn read_entry(bytes: &[u8], entry: &ZipEntry) -> AResult<Vec<u8>> {
    if entry.meta.size > crate::MAX_ENTRY_BYTES as u64 {
        return err(ERR_CORRUPT, "ZIP entry exceeds output limit");
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
}

impl NewEntry {
    pub fn file(name: impl Into<String>, data: Vec<u8>, modified_unix: i64) -> Self {
        NewEntry {
            name: name.into(),
            data,
            modified_unix,
            force_store: false,
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
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
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
