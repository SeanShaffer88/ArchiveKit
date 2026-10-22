//! TAR (ustar) reader and writer. 512-byte header blocks; names up to
//! 100 chars, or 155-char prefix + 100-char name. Octal numeric fields.
//! Supported typeflags: '0'/'\0' files, '5' directories. Other records
//! are listed and can be skipped on extract; reading their data errors.

use crate::{err, AResult, EntryMeta, ERR_CORRUPT, ERR_NOT_SUPPORTED};

pub struct TarEntry {
    pub meta: EntryMeta,
    /// Byte offset of the data blocks within the archive.
    pub data_offset: usize,
    pub typeflag: u8,
}

fn parse_octal(field: &[u8]) -> AResult<u64> {
    let s = std::str::from_utf8(field)
        .map_err(|_| (ERR_CORRUPT, "tar numeric field is not ASCII".to_string()))?;
    let s = s.trim_matches(['\0', ' ']);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| (ERR_CORRUPT, format!("bad tar octal field: {s:?}")))
}

fn read_str(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn header_checksum_ok(block: &[u8]) -> bool {
    if block.len() < 512 {
        return false;
    }
    let stored = match parse_octal(&block[148..156]) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut sum: u64 = 0;
    for (i, &b) in block.iter().take(512).enumerate() {
        sum += if (148..156).contains(&i) {
            b' ' as u64
        } else {
            b as u64
        };
    }
    sum == stored
}

pub fn list(bytes: &[u8]) -> AResult<Vec<TarEntry>> {
    let mut entries = Vec::new();
    let mut off = 0usize;
    while off + 512 <= bytes.len() {
        let block = &bytes[off..off + 512];
        if block.iter().all(|&b| b == 0) {
            break; // end-of-archive zero blocks
        }
        if !header_checksum_ok(block) {
            return err(
                ERR_CORRUPT,
                format!("tar header checksum fails at offset {off}"),
            );
        }
        if &block[257..262] != b"ustar" {
            return err(
                ERR_CORRUPT,
                format!("tar header at offset {off} is not ustar"),
            );
        }
        let name = read_str(&block[0..100]);
        let prefix = read_str(&block[345..500]);
        let full = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let size = parse_octal(&block[124..136])?;
        let mtime = parse_octal(&block[136..148])? as i64;
        let typeflag = block[156];
        let is_dir = typeflag == b'5' || full.ends_with('/');
        if size > crate::MAX_ENTRY_BYTES as u64 || entries.len() >= crate::MAX_ENTRIES {
            return err(ERR_CORRUPT, "TAR entry exceeds resource limits");
        }
        entries.push(TarEntry {
            meta: EntryMeta {
                name: full,
                size,
                compressed_size: size,
                method: "tar".to_string(),
                is_dir,
                crc32: None,
                modified_unix: Some(mtime),
            },
            data_offset: off + 512,
            typeflag,
        });
        let blocks = (size as usize).div_ceil(512);
        off = off
            .checked_add(512)
            .and_then(|n| blocks.checked_mul(512).and_then(|b| n.checked_add(b)))
            .ok_or((ERR_CORRUPT, "TAR length overflow".into()))?;
        if off > bytes.len() {
            return err(ERR_CORRUPT, "TAR entry data overruns archive");
        }
    }
    Ok(entries)
}

pub fn read_entry(bytes: &[u8], entry: &TarEntry) -> AResult<Vec<u8>> {
    match entry.typeflag {
        b'0' | 0 => {}
        b'5' => return Ok(Vec::new()),
        other => {
            return err(
                ERR_NOT_SUPPORTED,
                format!("tar entry type '{}' is not supported", other as char),
            )
        }
    }
    if entry.meta.size > crate::MAX_ENTRY_BYTES as u64 {
        return err(ERR_CORRUPT, "TAR entry exceeds output limit");
    }
    let end = entry
        .data_offset
        .checked_add(entry.meta.size as usize)
        .ok_or((ERR_CORRUPT, "TAR length overflow".into()))?;
    if end > bytes.len() {
        return err(ERR_CORRUPT, "tar entry data overruns archive");
    }
    Ok(bytes[entry.data_offset..end].to_vec())
}

pub fn test(bytes: &[u8]) -> AResult<usize> {
    let entries = list(bytes)?;
    for e in &entries {
        if e.typeflag == b'0' || e.typeflag == 0 {
            let data = read_entry(bytes, e)?;
            if data.len() as u64 != e.meta.size {
                return err(ERR_CORRUPT, "tar entry size mismatch");
            }
        }
    }
    Ok(entries.len())
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

pub struct NewTarEntry {
    pub name: String,
    pub data: Vec<u8>,
    pub modified_unix: i64,
    pub is_dir: bool,
}

fn write_octal(field: &mut [u8], value: u64) {
    let s = format!("{:0width$o}\0", value, width = field.len() - 1);
    field.copy_from_slice(s.as_bytes());
}

pub fn create(entries: &[NewTarEntry]) -> AResult<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    for e in entries {
        if e.name.len() > 100 {
            return err(
                ERR_NOT_SUPPORTED,
                format!(
                    "tar entry name exceeds 100 chars in v0.1 (prefix splitting is a roadmap item): {}",
                    e.name
                ),
            );
        }
        let mut header = [0u8; 512];
        header[..e.name.len()].copy_from_slice(e.name.as_bytes());
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        let size = if e.is_dir { 0 } else { e.data.len() as u64 };
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], e.modified_unix.max(0) as u64);
        header[156] = if e.is_dir { b'5' } else { b'0' };
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // Checksum: field treated as spaces while summing.
        for b in &mut header[148..156] {
            *b = b' ';
        }
        let sum: u64 = header.iter().map(|&b| b as u64).sum();
        let chk = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(chk.as_bytes());
        out.extend_from_slice(&header);
        if !e.is_dir {
            out.extend_from_slice(&e.data);
            let pad = (512 - (e.data.len() % 512)) % 512;
            out.extend(std::iter::repeat(0u8).take(pad));
        }
    }
    out.extend_from_slice(&[0u8; 1024]); // two zero blocks
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let entries = vec![
            NewTarEntry {
                name: "dir".into(),
                data: vec![],
                modified_unix: 1_792_674_000,
                is_dir: true,
            },
            NewTarEntry {
                name: "dir/file.txt".into(),
                data: b"tar contents here".to_vec(),
                modified_unix: 1_792_674_000,
                is_dir: false,
            },
            NewTarEntry {
                name: "big.bin".into(),
                data: vec![7u8; 1500],
                modified_unix: 1_792_674_000,
                is_dir: false,
            },
        ];
        let bytes = create(&entries).unwrap();
        let listed = list(&bytes).unwrap();
        assert_eq!(listed.len(), 3);
        assert!(listed[0].meta.is_dir);
        assert_eq!(listed[1].meta.size, 17);
        assert_eq!(test(&bytes).unwrap(), 3);
        assert_eq!(
            read_entry(&bytes, &listed[1]).unwrap(),
            b"tar contents here"
        );
        assert_eq!(read_entry(&bytes, &listed[2]).unwrap().len(), 1500);
    }
}
