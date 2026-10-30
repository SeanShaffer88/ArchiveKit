use archive_kit::{deflate, inflate, safe_join, zip};
use std::{ffi::CString, fs, path::Path};
#[test]
fn output_budgets_apply_inside_blocks() {
    for data in [vec![b'a'; 4096], (0..=255).cycle().take(4096).collect()] {
        let stream = deflate::deflate(&data);
        assert_eq!(inflate::inflate_limited(&stream, data.len()).unwrap(), data);
        assert!(inflate::inflate_limited(&stream, data.len() - 1).is_err());
    }
    assert!(inflate::inflate_limited(&[1, 1, 0, 254, 255, 42], 0).is_err());
}
#[test]
fn windows_aliases_and_traversal_are_refused() {
    for name in [
        "../outside",
        "C:evil",
        "a:stream",
        "dir/NUL.txt",
        "LPT1",
        "CON",
        "a. ",
        "a\0b",
    ] {
        assert!(
            safe_join(Path::new("destination"), name).is_none(),
            "{name:?}"
        );
    }
}
#[test]
fn extraction_never_overwrites_and_refuses_junction_ancestors() {
    let root = std::env::temp_dir().join(format!("ak-audit-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let dest = root.join("dest");
    fs::create_dir_all(&dest).unwrap();
    let zip_path = root.join("input.zip");
    fs::write(
        &zip_path,
        zip::create(&[zip::NewEntry::file("keep.txt", b"new".to_vec(), 0)]).unwrap(),
    )
    .unwrap();
    fs::write(dest.join("keep.txt"), b"original").unwrap();
    let a = CString::new(zip_path.to_str().unwrap()).unwrap();
    let d = CString::new(dest.to_str().unwrap()).unwrap();
    assert_eq!(
        archive_kit::ffi::ak_extract(a.as_ptr(), d.as_ptr(), std::ptr::null()),
        -1
    );
    assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"original");
    #[cfg(windows)]
    {
        let outside = root.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let hop = dest.join("hop");
        let result = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&hop)
            .arg(&outside)
            .output()
            .unwrap();
        assert!(result.status.success(), "junction fixture creation failed");
        fs::write(
            &zip_path,
            zip::create(&[zip::NewEntry::file(
                "hop/escape.txt",
                b"blocked".to_vec(),
                0,
            )])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            archive_kit::ffi::ak_extract(a.as_ptr(), d.as_ptr(), std::ptr::null()),
            -1
        );
        assert!(!outside.join("escape.txt").exists());
        fs::remove_dir(&hop).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn bounded_malformed_corpus_returns_without_panics() {
    let mut seed = 0x12345678u32;
    for len in 0..256 {
        let data: Vec<u8> = (0..len)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                seed as u8
            })
            .collect();
        let _ = inflate::inflate_limited(&data, 1024);
        let _ = zip::list(&data);
        let _ = archive_kit::tar::list(&data);
    }
}

/// Patch a real header into a foreign one: set the typeflag and size, then
/// recompute the checksum the way tar does (sum with the field as spaces).
fn patch_header(block: &mut [u8; 512], typeflag: u8, size: u64) {
    block[156] = typeflag;
    let octal = format!("{size:011o}\0");
    block[124..136].copy_from_slice(octal.as_bytes());
    for b in &mut block[148..156] {
        *b = b' ';
    }
    let sum: u64 = block.iter().map(|&b| b as u64).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

#[test]
fn tar_metadata_record_parsers_never_panic() {
    // GNU 'L' and pax 'x' records are the two places where ArchiveKit trusts
    // a length field inside archive data. Feed both random payloads (and a
    // few hand-picked shapes) and require an error or a clean listing, never
    // a panic.
    let seed_tar = archive_kit::tar::create(&[archive_kit::tar::NewTarEntry {
        name: "seed.txt".into(),
        data: b"seed".to_vec(),
        modified_unix: 0,
        is_dir: false,
        read_only: false,
    }])
    .unwrap();
    let mut header = [0u8; 512];
    header.copy_from_slice(&seed_tar[..512]);

    let mut seed = 0x9E37_79B9u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for len in [0usize, 1, 2, 7, 64, 511, 512, 1024] {
        let payload: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        cases.push(payload);
    }
    // Shapes that exercise the record walker specifically.
    cases.push(b"5 path".to_vec()); // length then a space, no newline
    cases.push(b"999 path=x\n".to_vec()); // length overruns the block
    cases.push(b"9 path=\n".to_vec()); // empty value
    cases.push(b"0 \n".to_vec()); // zero-length record
    cases.push(b"20 path=x\n3 ab".to_vec()); // truncated second record
    cases.push(b"12 mtime=nope\n".to_vec()); // unparseable mtime is ignored
    cases.push(b"10 size=nope\n".to_vec()); // unparseable size must error

    for (index, payload) in cases.iter().enumerate() {
        for typeflag in *b"xXLK" {
            let mut archive = Vec::new();
            let mut meta = header;
            patch_header(&mut meta, typeflag, payload.len() as u64);
            archive.extend_from_slice(&meta);
            archive.extend_from_slice(payload);
            archive.resize(archive.len().next_multiple_of(512), 0);
            let mut entry = header;
            patch_header(&mut entry, b'0', 0);
            archive.extend_from_slice(&entry);
            archive.extend_from_slice(&[0u8; 1024]);
            match archive_kit::tar::list(&archive) {
                Ok(listed) => {
                    // A pax record that parsed must leave exactly one entry.
                    assert_eq!(listed.len(), 1, "case {index} type {typeflag}");
                }
                Err((code, message)) => {
                    assert!(code > 0, "case {index} type {typeflag}: {message}");
                    assert!(!message.is_empty());
                }
            }
        }
    }
}
