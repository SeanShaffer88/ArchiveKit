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
        zip::create(&[zip::NewEntry::file("keep.txt", b"new".to_vec(), 0)]),
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
            )]),
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
