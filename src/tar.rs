//! TAR (ustar) reader and writer. 512-byte header blocks.
//!
//! Read: ustar headers (155-byte prefix + 100-byte name), plus the two ways
//! real-world tars carry longer names — GNU `L` records and pax `x` extended
//! headers (`path=`, `size=`, `mtime=`). GNU tar writes `L` records and
//! Python/BSD tar write pax records, so both appear in ordinary downloads.
//! Metadata records are consumed as structure rather than listed as entries.
//!
//! Write: ustar only. Names up to 100 bytes go in the name field; longer
//! names are split on a `/` into prefix (≤155) + name (≤100). A name that
//! cannot be split that way is refused with ERR_NOT_SUPPORTED rather than
//! written as a truncated header (GNU `L` output is still a roadmap item).
//!
//! Supported typeflags: '0'/'\0' files, '5' directories. Other records are
//! listed and can be skipped on extract; reading their data errors.

use crate::{err, AResult, EntryMeta, ERR_CORRUPT, ERR_NOT_SUPPORTED};

/// Upper bound on a GNU long-name or pax extension record. Real paths are
/// capped at PATH_MAX (4096); anything much larger is a malformed archive.
const MAX_META_BYTES: u64 = 64 * 1024;

pub struct TarEntry {
    pub meta: EntryMeta,
    /// Byte offset of the data blocks within the archive.
    pub data_offset: usize,
    pub typeflag: u8,
}

fn parse_octal(field: &[u8]) -> AResult<u64> {
    let binary = field.first().is_some_and(|&first| first & 0x80 != 0);
    if binary {
        return err(
            ERR_NOT_SUPPORTED,
            "tar base-256 (GNU binary) numeric fields are not supported",
        );
    }
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

/// Metadata that the next real header inherits: GNU `L` long name, or a pax
/// `x` record set. Cleared once consumed so it cannot leak onto later files.
#[derive(Default)]
struct Pending {
    name: Option<String>,
    path: Option<String>,
    size: Option<u64>,
    mtime: Option<i64>,
}

/// Parse pax `"<len> <key>=<value>\n"` records. Unknown keys are ignored;
/// malformed lengths or missing newlines are refused so a corrupt extension
/// cannot silently shift every following entry.
fn apply_pax(pending: &mut Pending, data: &[u8]) -> AResult<()> {
    let mut i = 0usize;
    let total = data.len();
    while i < total {
        let rest = &data[i..];
        let space = match rest.iter().position(|&b| b == b' ') {
            Some(pos) => pos,
            None => break, // trailing NUL padding
        };
        let text = std::str::from_utf8(&rest[..space])
            .map_err(|_| (ERR_CORRUPT, "pax record length is not ASCII".to_string()))?;
        let record: usize = text
            .parse()
            .map_err(|_| (ERR_CORRUPT, "bad pax record length".to_string()))?;
        if record <= space || i + record > total {
            return err(ERR_CORRUPT, "pax record overruns its block");
        }
        let body = match data[i + space + 1..i + record].strip_suffix(b"\n") {
            Some(inner) => inner,
            None => return err(ERR_CORRUPT, "pax record is not newline terminated"),
        };
        let eq = match body.iter().position(|&b| b == b'=') {
            Some(pos) => pos,
            None => return err(ERR_CORRUPT, "pax record has no '='"),
        };
        let value = &body[eq + 1..];
        match &body[..eq] {
            b"path" => pending.path = Some(String::from_utf8_lossy(value).into_owned()),
            b"size" => {
                let text = std::str::from_utf8(value)
                    .map_err(|_| (ERR_CORRUPT, "bad pax size record".to_string()))?;
                pending.size = Some(
                    text.parse()
                        .map_err(|_| (ERR_CORRUPT, "bad pax size record".to_string()))?,
                );
            }
            b"mtime" => {
                let text = std::str::from_utf8(value).unwrap_or("");
                let seconds = text.split('.').next().unwrap_or_default();
                if let Ok(v) = seconds.parse::<i64>() {
                    pending.mtime = Some(v);
                }
            }
            _ => {}
        }
        i += record;
    }
    Ok(())
}

/// Offset just past `size` bytes of data starting at `data_offset`, rounded
/// up to whole 512-byte blocks. Checked: a declared size near u64::MAX must
/// be an error, not an overflow panic.
fn padded_end(data_offset: usize, size: u64) -> AResult<u64> {
    let blocks = size
        .div_ceil(512)
        .checked_mul(512)
        .ok_or((ERR_CORRUPT, "TAR length overflow".to_string()))?;
    (data_offset as u64)
        .checked_add(blocks)
        .ok_or((ERR_CORRUPT, "TAR length overflow".to_string()))
}

pub fn list(bytes: &[u8]) -> AResult<Vec<TarEntry>> {
    let mut entries = Vec::new();
    let mut off = 0usize;
    let mut pending = Pending::default();
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
        let header_size = parse_octal(&block[124..136])?;
        let typeflag = block[156];
        let data_offset = off + 512;
        let header_end = padded_end(data_offset, header_size)?;
        if header_end > bytes.len() as u64 {
            return err(ERR_CORRUPT, "TAR entry data overruns archive");
        }
        if matches!(typeflag, b'L' | b'K' | b'x' | b'X' | b'g') {
            if header_size > MAX_META_BYTES {
                return err(ERR_CORRUPT, "tar metadata record exceeds the size limit");
            }
            let data = &bytes[data_offset..data_offset + header_size as usize];
            match typeflag {
                b'L' => pending.name = Some(read_str(data)),
                b'x' | b'X' => apply_pax(&mut pending, data)?,
                // 'K' (long link name) and 'g' (global pax header) carry
                // nothing this library acts on.
                _ => {}
            }
            off = header_end as usize;
            continue;
        }
        let prefix = read_str(&block[345..500]);
        let mut name = read_str(&block[0..100]);
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        if let Some(override_path) = pending.path.as_ref() {
            name.clone_from(override_path);
        } else if let Some(override_name) = pending.name.as_ref() {
            name.clone_from(override_name);
        }
        let size = pending.size.unwrap_or(header_size);
        let mode = parse_octal(&block[100..108])?;
        let mut mtime = parse_octal(&block[136..148])? as i64;
        if let Some(override_mtime) = pending.mtime {
            mtime = override_mtime;
        }
        pending = Pending::default();
        let is_dir = typeflag == b'5' || name.ends_with('/');
        if size > crate::MAX_ENTRY_BYTES as u64 || entries.len() >= crate::MAX_ENTRIES {
            return err(ERR_CORRUPT, "TAR entry exceeds resource limits");
        }
        entries.push(TarEntry {
            meta: EntryMeta {
                name,
                size,
                compressed_size: size,
                method: "tar".to_string(),
                is_dir,
                crc32: None,
                modified_unix: Some(mtime),
                // A zero mode means "not recorded"; only a real mode with no
                // write bit at all counts as read-only.
                read_only: mode != 0 && mode & 0o200 == 0,
            },
            data_offset,
            typeflag,
        });
        // A pax size record can override a placeholder header field, so the
        // next header is located from the effective size, not the field.
        let end = padded_end(data_offset, size)?;
        if end > bytes.len() as u64 {
            return err(ERR_CORRUPT, "TAR entry data overruns archive");
        }
        off = end as usize;
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
    /// Record a mode without a write bit (0444 files, 0555 directories).
    pub read_only: bool,
}

/// Write an octal field with a trailing NUL, refusing values that would not
/// fit. v0.1 panicked on overflow here; a caller-supplied timestamp must
/// never take the library down, so it is an error now.
fn write_octal(field: &mut [u8], value: u64) -> AResult<()> {
    let digits = field.len() - 1;
    let max = if digits > 21 {
        u64::MAX
    } else {
        (1u64 << (3 * digits)) - 1
    };
    if value > max {
        return err(
            ERR_NOT_SUPPORTED,
            format!("tar numeric field cannot hold {value}"),
        );
    }
    let text = format!("{value:0digits$o}\0");
    field.copy_from_slice(text.as_bytes());
    Ok(())
}

/// Split an archive name into ustar `(prefix, name)` parts. Plain names use
/// the 100-byte field alone; longer ones need a `/` with at most 155 bytes
/// before it and at most 100 after it. Byte counts, not characters — the
/// fields are byte-limited, so a UTF-8 name can be well under 100 chars and
/// still not fit.
fn split_name(path: &str) -> AResult<(String, String)> {
    if path.len() <= 100 {
        return Ok((String::new(), path.to_string()));
    }
    let split = path.rmatch_indices('/').find(|&(idx, _)| {
        let prefix = &path[..idx];
        let rest = &path[idx + 1..];
        !prefix.is_empty() && !rest.is_empty() && prefix.len() <= 155 && rest.len() <= 100
    });
    match split {
        Some((idx, _)) => Ok((path[..idx].to_string(), path[idx + 1..].to_string())),
        None => err(
            ERR_NOT_SUPPORTED,
            format!(
                "tar entry name does not fit ustar's 155+100 byte prefix split \
                 (long-name records are a roadmap item): {path}"
            ),
        ),
    }
}

pub fn create(entries: &[NewTarEntry]) -> AResult<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    for e in entries {
        let (prefix, name) = split_name(&e.name)?;
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        if !prefix.is_empty() {
            header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        }
        let mode = match (e.is_dir, e.read_only) {
            (true, false) => 0o755,
            (true, true) => 0o555,
            (false, false) => 0o644,
            (false, true) => 0o444,
        };
        write_octal(&mut header[100..108], mode)?;
        write_octal(&mut header[108..116], 0)?;
        write_octal(&mut header[116..124], 0)?;
        let size = if e.is_dir { 0 } else { e.data.len() as u64 };
        write_octal(&mut header[124..136], size)?;
        write_octal(&mut header[136..148], e.modified_unix.max(0) as u64)?;
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
            out.resize(out.len() + pad, 0u8);
        }
    }
    out.extend_from_slice(&[0u8; 1024]); // two zero blocks
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, body: &[u8], is_dir: bool) -> NewTarEntry {
        NewTarEntry {
            name: name.to_string(),
            data: body.to_vec(),
            modified_unix: 1_792_674_000,
            is_dir,
            read_only: false,
        }
    }

    /// Build one ustar header the way a GNU/BSD tar would, so the reader can
    /// be tested against metadata records this crate never writes.
    fn raw_header(name: &[u8], size: u64, typeflag: u8) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name);
        write_octal(&mut header[100..108], 0o644).unwrap();
        write_octal(&mut header[108..116], 0).unwrap();
        write_octal(&mut header[116..124], 0).unwrap();
        write_octal(&mut header[124..136], size).unwrap();
        write_octal(&mut header[136..148], 1_792_674_000).unwrap();
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        for b in &mut header[148..156] {
            *b = b' ';
        }
        let sum: u64 = header.iter().map(|&b| b as u64).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        header
    }

    /// One pax record: "<len> <key>=<value>\n", where <len> counts every
    /// byte of the record including its own digits and the space.
    fn pax_record(line: &str) -> Vec<u8> {
        let body = format!("{line}\n");
        let mut digits = 1usize;
        loop {
            let total = body.len() + 1 + digits;
            let actual = total.to_string().len();
            if actual == digits {
                return format!("{total} {body}").into_bytes();
            }
            digits = actual;
        }
    }

    fn push_record(out: &mut Vec<u8>, header: [u8; 512], data: &[u8]) {
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        out.resize(out.len() + pad, 0u8);
    }

    #[test]
    fn roundtrip() {
        let entries = vec![
            entry("dir", b"", true),
            entry("dir/file.txt", b"tar contents here", false),
            entry("big.bin", &vec![7u8; 1500], false),
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

    #[test]
    fn long_names_use_the_prefix_field() {
        // 60 + 1 + 80 = 141 bytes: too long for the name field, easily
        // inside prefix (≤155) + name (≤100).
        let name = format!("{}/{}", "d".repeat(60), "f".repeat(80));
        let bytes = create(&[entry(&name, b"long name payload", false)]).unwrap();
        let listed = list(&bytes).unwrap();
        assert_eq!(listed[0].meta.name, name);
        assert_eq!(listed[0].meta.size, 17);
        assert_eq!(
            read_entry(&bytes, &listed[0]).unwrap(),
            b"long name payload"
        );
        // Exactly at the ustar maximum: 155 + '/' + 100.
        let edge = format!("{}/{}", "p".repeat(155), "n".repeat(100));
        let bytes = create(&[entry(&edge, b"edge", false)]).unwrap();
        assert_eq!(list(&bytes).unwrap()[0].meta.name, edge);
        // One byte over either field cannot be expressed in ustar.
        let over = format!("{}/{}", "p".repeat(155), "n".repeat(101));
        assert!(create(&[entry(&over, b"x", false)]).is_err());
        // No slash at all: nothing to split on, so it is refused, not cut.
        assert!(create(&[entry(&"z".repeat(200), b"x", false)]).is_err());
    }

    #[test]
    fn multibyte_names_are_measured_in_bytes() {
        // 50 x 'ü' is 100 bytes: exactly one name field, no prefix.
        let fits = "ü".repeat(50);
        let bytes = create(&[entry(&fits, b"a", false)]).unwrap();
        assert_eq!(list(&bytes).unwrap()[0].meta.name, fits);
        // 60 x 'é' is 120 bytes with no slash: unrepresentable, refused.
        assert!(create(&[entry(&"é".repeat(60), b"a", false)]).is_err());
        // With a slash it splits by byte count (120 bytes prefix + name).
        let split = format!("{}/tail.txt", "é".repeat(60));
        let bytes = create(&[entry(&split, b"a", false)]).unwrap();
        assert_eq!(list(&bytes).unwrap()[0].meta.name, split);
    }

    #[test]
    fn gnu_long_name_records_are_applied() {
        // GNU tar writes an 'L' record holding the real name, then a
        // truncated header. The entry must be listed once, under the full
        // name, and the 'L' record itself must not appear as a file.
        let long_name = format!("{}/{}", "g".repeat(80), "n".repeat(80));
        let mut bytes = Vec::new();
        push_record(
            &mut bytes,
            raw_header(b"././@LongLink", long_name.len() as u64 + 1, b'L'),
            format!("{long_name}\0").as_bytes(),
        );
        push_record(
            &mut bytes,
            raw_header(b"gggggggggggggggggg", 4, b'0'),
            b"body",
        );
        bytes.extend_from_slice(&[0u8; 1024]);
        let listed = list(&bytes).unwrap();
        assert_eq!(listed.len(), 1, "the 'L' metadata record is not an entry");
        assert_eq!(listed[0].meta.name, long_name);
        assert_eq!(read_entry(&bytes, &listed[0]).unwrap(), b"body");
    }

    #[test]
    fn pax_records_override_name_size_and_mtime() {
        let long_name = format!("{}/{}", "p".repeat(90), "x".repeat(90));
        let mut records = Vec::new();
        for line in [
            format!("path={long_name}"),
            "size=9".to_string(),
            "mtime=1600000000.123456789".to_string(),
            "SCHILY.dev=42".to_string(),
        ] {
            records.extend_from_slice(&pax_record(&line));
        }
        let mut bytes = Vec::new();
        push_record(
            &mut bytes,
            raw_header(b"./PaxHeaders/entry", records.len() as u64, b'x'),
            &records,
        );
        // Header size field is a placeholder; pax says 9 bytes.
        push_record(
            &mut bytes,
            raw_header(b"placeholder", 0, b'0'),
            b"nine byte",
        );
        bytes.extend_from_slice(&[0u8; 1024]);
        let listed = list(&bytes).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].meta.name, long_name);
        assert_eq!(listed[0].meta.size, 9);
        assert_eq!(listed[0].meta.modified_unix, Some(1_600_000_000));
        assert_eq!(read_entry(&bytes, &listed[0]).unwrap(), b"nine byte");
        assert_eq!(test(&bytes).unwrap(), 1);
    }

    #[test]
    fn modes_mark_read_only_entries() {
        // What the writer records for a read-only file and directory.
        let bytes = create(&[
            entry("free.txt", b"x", false),
            NewTarEntry {
                read_only: true,
                ..entry("locked.txt", b"y", false)
            },
            NewTarEntry {
                read_only: true,
                ..entry("locked-dir", b"", true)
            },
        ])
        .unwrap();
        let listed = list(&bytes).unwrap();
        assert!(!listed[0].meta.read_only, "0644 file is writable");
        assert!(listed[1].meta.read_only, "0444 file is read-only");
        assert!(listed[2].meta.read_only, "0555 directory is read-only");
        assert_eq!(&bytes[100..108], b"0000644\0");
        // A zero mode means "not recorded" and must not read as read-only.
        let mut header = raw_header(b"unknown.txt", 0, b'0');
        header[100..108].copy_from_slice(b"0000000\0");
        for b in &mut header[148..156] {
            *b = b' ';
        }
        let sum: u64 = header.iter().map(|&b| b as u64).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut archive = Vec::new();
        push_record(&mut archive, header, b"");
        archive.extend_from_slice(&[0u8; 1024]);
        assert!(!list(&archive).unwrap()[0].meta.read_only);
    }

    #[test]
    fn hostile_headers_error_instead_of_panicking() {
        // Timestamp beyond the 11-octal-digit field must be an error, not a
        // panic inside the writer.
        let mut bad = entry("f.txt", b"x", false);
        bad.modified_unix = i64::MAX;
        assert!(create(&[bad]).is_err());
        // Truncated and corrupt archives.
        let good = create(&[entry("f.txt", b"hello", false)]).unwrap();
        // Header present, data cut short: corrupt, not an empty archive.
        assert!(list(&good[..600]).is_err());
        let mut corrupt = good.clone();
        corrupt[0] = b'X';
        assert!(list(&corrupt).is_err());
        // A pax record whose length runs past its block.
        let mut bytes = Vec::new();
        push_record(&mut bytes, raw_header(b"pax", 12, b'x'), b"99 path=x\n\0\0");
        push_record(&mut bytes, raw_header(b"x", 0, b'0'), b"");
        bytes.extend_from_slice(&[0u8; 1024]);
        assert!(list(&bytes).is_err());
    }
}
