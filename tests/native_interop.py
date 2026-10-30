"""Independent stdlib ZIP/TAR interop against a compiled DLL; synthetic files only.

Runs as part of Windows CI after `cargo build --release`:

    python tests/native_interop.py target/release/archive_kit.dll

Everything here is generated with Python's stdlib (zlib via zipfile, tarfile),
so it is an independent check of the DLL's bytes: dynamic-Huffman DEFLATE
streams are decoded by zlib, ustar headers by tarfile, and both 100-byte names
and GNU 'L' / pax 'x' long-name records are exercised in both directions.
"""
import ctypes
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import zipfile

lib = ctypes.CDLL(str(pathlib.Path(sys.argv[1]).resolve()))
lib.ak_test.restype = ctypes.c_int64
lib.ak_test.argtypes = [ctypes.c_char_p]
for name in ("ak_create_zip", "ak_create_tar"):
    fn = getattr(lib, name)
    fn.restype = ctypes.c_int64
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.ak_extract.restype = ctypes.c_int64
lib.ak_extract.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.ak_list_json.restype = ctypes.c_void_p
lib.ak_list_json.argtypes = [ctypes.c_char_p]
lib.ak_free_string.argtypes = [ctypes.c_void_p]
lib.ak_last_error.restype = ctypes.c_char_p
lib.ak_last_error_code.restype = ctypes.c_int


def listing(path):
    """ak_list_json as Python data, plus the entry names."""
    ptr = lib.ak_list_json(str(path).encode())
    assert ptr, f"list failed ({lib.ak_last_error_code()}): {lib.ak_last_error()!r}"
    raw = ctypes.string_at(ptr)
    lib.ak_free_string(ptr)
    entries = json.loads(raw)
    return entries, [e["name"] for e in entries]


def test(path):
    return lib.ak_test(str(path).encode())


def extract(path, dest, entry=None):
    name = entry.encode() if entry is not None else None
    return lib.ak_extract(str(path).encode(), str(dest).encode(), name)


payload = bytes(range(256)) * 16
long_name = "d" * 70 + "/" + "f" * 90 + ".bin"

with tempfile.TemporaryDirectory(prefix="archivekit-interop-") as folder:
    root = pathlib.Path(folder)

    # ---- Python writes ZIP (store + deflate) -> DLL reads/extracts -------------
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        arc = root / f"python-{method}.zip"
        with zipfile.ZipFile(arc, "w", compression=method) as z:
            z.writestr("café/data.bin", payload)
        assert test(arc) == 1
        dest = root / f"extract-{method}"
        assert extract(arc, dest) == 1
        assert (dest / "café" / "data.bin").read_bytes() == payload

    # ---- DLL writes ZIP -> Python/zlib reads ----------------------------------
    source = root / "source"
    source.mkdir()
    (source / "data.bin").write_bytes(payload)
    text = b"the quick brown fox jumps over the lazy dog. " * 4000
    (source / "text.txt").write_bytes(text)
    arc = root / "native.zip"
    assert lib.ak_create_zip(str(arc).encode(), str(source).encode()) == 2
    with zipfile.ZipFile(arc) as z:
        assert z.read("data.bin") == payload
        # 180 KB of repetitive text: only a working LZ77 + Huffman encoder
        # gets anywhere near this, and zlib is the decoder here.
        assert z.read("text.txt") == text
    assert test(arc) == 2
    assert arc.stat().st_size < len(text) // 20, arc.stat().st_size
    entries, names = listing(arc)
    assert names == ["data.bin", "text.txt"], names
    assert entries[1]["method"] == "deflate", entries[1]
    assert entries[1]["size"] == len(text), entries[1]

    # ---- single named entry extraction ---------------------------------------
    only = root / "only"
    assert extract(arc, only, "data.bin") == 1
    assert (only / "data.bin").read_bytes() == payload
    assert not (only / "text.txt").exists()
    missing = extract(arc, only, "nope.bin")
    assert missing == -1 and lib.ak_last_error_code() == 3  # AK_ERR_NOT_FOUND

    # ---- DLL writes TAR (prefix-split long name) -> tarfile reads -------------
    deep = root / "tarsrc" / ("a" * 60)
    deep.mkdir(parents=True)
    (deep / ("b" * 80 + ".txt")).write_bytes(b"tar long name payload")
    arc = root / "native.tar"
    assert lib.ak_create_tar(str(arc).encode(), str(source).encode()) == 2
    with tarfile.open(arc) as t:
        assert t.extractfile("data.bin").read() == payload
    assert test(arc) == 2
    long_arc = root / "long.tar"
    assert lib.ak_create_tar(str(long_arc).encode(), str(root / "tarsrc").encode()) == 2
    want = "a" * 60 + "/" + "b" * 80 + ".txt"
    with tarfile.open(long_arc) as t:
        assert t.extractfile(want).read() == b"tar long name payload"
    dest = root / "long-out"
    assert extract(long_arc, dest) == 1
    assert (dest / ("a" * 60) / ("b" * 80 + ".txt")).read_bytes() == b"tar long name payload"

    # ---- Python writes GNU and pax long-name TARs -> DLL reads/extracts -------
    for fmt, label in ((tarfile.GNU_FORMAT, "gnu"), (tarfile.PAX_FORMAT, "pax")):
        arc = root / f"{label}.tar"
        body = f"{label} long name".encode()
        with tarfile.open(arc, "w", format=fmt) as t:
            info = tarfile.TarInfo(long_name)
            info.size = len(body)
            t.addfile(info, io.BytesIO(body))
        assert test(arc) == 1, f"{label}: {lib.ak_last_error()!r}"
        _, names = listing(arc)
        assert names == [long_name], f"{label}: {names}"
        dest = root / f"{label}-out"
        assert extract(arc, dest) == 1
        assert (dest / ("d" * 70) / ("f" * 90 + ".bin")).read_bytes() == body

    # ---- ZIP64 markers: harmless extras are readable, real markers refuse ----
    # A ZIP64 extra field whose central directory still holds classic sizes
    # (what streaming writers emit) is readable: sizes come from the central
    # directory, so the extra field is just bytes we skip.
    zip64_extra = root / "zip64-extra.zip"
    with zipfile.ZipFile(zip64_extra, "w") as z:
        with z.open("big.bin", "w", force_zip64=True) as f:
            f.write(payload)
    assert test(zip64_extra) == 1, lib.ak_last_error()
    with zipfile.ZipFile(zip64_extra) as z:
        assert z.read("big.bin") == payload
    # A central directory carrying the 0xFFFFFFFF "value lives in ZIP64"
    # marker is refused with a specific message instead of being misread.
    patched = root / "zip64-marker.zip"
    data = bytearray((root / "native.zip").read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd > 0, "EOCD not found"
    cd_offset = int.from_bytes(data[eocd + 16:eocd + 20], "little")
    assert data[cd_offset:cd_offset + 4] == b"PK\x01\x02", "central directory not found"
    data[cd_offset + 20:cd_offset + 24] = b"\xff\xff\xff\xff"  # compressed size
    patched.write_bytes(bytes(data))
    assert test(patched) == -1
    assert lib.ak_last_error_code() == 2  # AK_ERR_NOT_SUPPORTED
    assert b"ZIP64" in lib.ak_last_error(), lib.ak_last_error()

    # ---- traversal is refused and nothing lands outside the destination -----
    evil = root / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../escape.txt", b"nope")
    dest = root / "safe" / "nested"
    dest.mkdir(parents=True)
    assert extract(evil, dest) == -1
    assert lib.ak_last_error_code() == 7  # AK_ERR_CORRUPT
    assert not (root / "escape.txt").exists()

print(
    "Native interop passed: Python ZIP store/deflate and GNU/pax TAR -> DLL; "
    "DLL ZIP (dynamic Huffman) and TAR (prefix split) -> Python; ZIP64 and "
    "traversal refusals verified"
)
