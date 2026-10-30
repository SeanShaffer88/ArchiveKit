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
import os
import pathlib
import struct
import sys
import tarfile
import tempfile
import zipfile
import zlib

lib = ctypes.CDLL(str(pathlib.Path(sys.argv[1]).resolve()))
lib.ak_test.restype = ctypes.c_int64
lib.ak_test.argtypes = [ctypes.c_char_p]
for name in ("ak_create_zip", "ak_create_tar"):
    fn = getattr(lib, name)
    fn.restype = ctypes.c_int64
    fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.ak_extract.restype = ctypes.c_int64
lib.ak_extract.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.ak_extract_prefix.restype = ctypes.c_int64
lib.ak_extract_prefix.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
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


def extract_prefix(path, dest, prefix):
    return lib.ak_extract_prefix(
        str(path).encode(), str(dest).encode(), prefix.encode()
    )


def one_entry_zip(name_bytes, payload, flags):
    """A minimal STORE archive with the name bytes exactly as given, so the
    test can emit encodings this library never writes."""
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flags, 0, 0, 0x21, crc,
        len(payload), len(payload), len(name_bytes), 0,
    ) + name_bytes + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, 0, 0, 0x21, crc,
        len(payload), len(payload), len(name_bytes), 0, 0, 0, 0, 0, 0,
    ) + name_bytes
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + eocd


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

    # ---- legacy CP437 names decode correctly (APPNOTE 4.4.4) ----------------
    # 0x82 is 'é' in CP437: the DOS-era spelling of "café-pré.txt". Without
    # the UTF-8 flag these bytes are CP437, not UTF-8.
    legacy = root / "legacy.zip"
    legacy.write_bytes(one_entry_zip(b"caf\x82-pr\x82.txt", b"legacy", 0))
    entries, names = listing(legacy)
    assert names == ["café-pré.txt"], names
    dest = root / "legacy-out"
    assert extract(legacy, dest) == 1
    assert (dest / "café-pré.txt").read_bytes() == b"legacy"
    # Flagged UTF-8 is read as UTF-8 and left alone.
    modern = root / "modern.zip"
    modern.write_bytes(one_entry_zip("café-pré.txt".encode(), b"modern", 0x0800))
    assert listing(modern)[1] == ["café-pré.txt"]

    # ---- streaming archives (data descriptors) are readable ----------------
    class Unseekable(io.RawIOBase):
        def __init__(self, handle):
            self.handle = handle

        def writable(self):
            return True

        def write(self, data):
            return self.handle.write(data)

        def seekable(self):
            return False

    streamed = root / "streamed.zip"
    streamed_payload = b"data descriptor payload" * 100
    with open(streamed, "wb") as raw:
        with zipfile.ZipFile(Unseekable(raw), "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("streamed.txt", streamed_payload)
    assert struct.unpack_from("<H", streamed.read_bytes(), 6)[0] & 0x8, "no descriptor bit"
    assert test(streamed) == 1, lib.ak_last_error()
    dest = root / "streamed-out"
    assert extract(streamed, dest) == 1
    assert (dest / "streamed.txt").read_bytes() == streamed_payload

    # ---- ak_extract_prefix extracts one folder, prefix stripped ------------
    tree = root / "tree.zip"
    with zipfile.ZipFile(tree, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("docs/api/a.txt", b"a")
        z.writestr("docs/api/deep/b.txt", b"b")
        z.writestr("docs/other/c.txt", b"c")
        z.writestr("docsx/d.txt", b"d")
        z.writestr("top.txt", b"t")
    dest = root / "api-out"
    assert extract_prefix(tree, dest, "docs/api") == 2
    assert (dest / "a.txt").read_bytes() == b"a"
    assert (dest / "deep" / "b.txt").read_bytes() == b"b"
    assert not (dest / "api").exists() and not (dest / "other").exists()
    # Component boundaries: "doc" and "docsx" select nothing.
    assert extract_prefix(tree, root / "miss1", "doc") == 0
    assert extract_prefix(tree, root / "miss2", "docs/api/deeper") == 0
    # Whole top-level folder, still excluding the look-alike "docsx".
    dest = root / "docs-out"
    assert extract_prefix(tree, dest, "docs/") == 3
    assert (dest / "other" / "c.txt").read_bytes() == b"c"
    # An unsafe prefix is an argument error, not a silent no-op.
    assert extract_prefix(tree, root / "bad", "../docs") == -1
    assert lib.ak_last_error_code() == 1  # AK_ERR_INVALID_ARG

    # ---- long TAR names on create use a GNU 'L' record --------------------
    # 306 bytes with no legal ustar prefix split: the old writer refused
    # these, which made tar creation fail on deep Windows trees.
    long_dir = "x" * 100 + "/" + "y" * 100
    long_src = root / "long-src"
    (long_src / long_dir).mkdir(parents=True)
    long_leaf = "z" * 100 + ".txt"
    (long_src / long_dir / long_leaf).write_bytes(b"deep path payload")
    long_arc = root / "long-names.tar"
    assert lib.ak_create_tar(str(long_arc).encode(), str(long_src).encode()) == 3
    assert b"././@LongLink" in long_arc.read_bytes(), "expected a GNU long-name record"
    expected_name = long_dir + "/" + long_leaf
    with tarfile.open(long_arc) as t:
        assert expected_name in t.getnames(), [len(n) for n in t.getnames()]
        assert t.extractfile(expected_name).read() == b"deep path payload"
    assert test(long_arc) == 3
    dest = root / "long-out"
    assert extract(long_arc, dest) == 1
    assert (dest / expected_name).read_bytes() == b"deep path payload"
    # Names that fit stay plain ustar: no long-name record in that archive.
    plain_arc = root / "plain-names.tar"
    assert lib.ak_create_tar(str(plain_arc).encode(), str(source).encode()) == 2
    assert b"././@LongLink" not in plain_arc.read_bytes()

    # ---- restored timestamps, in both directions ---------------------------
    stamped = root / "stamped.zip"
    with zipfile.ZipFile(stamped, "w", zipfile.ZIP_DEFLATED) as z:
        info = zipfile.ZipInfo("stamped.txt", date_time=(2026, 10, 20, 14, 20, 0))
        z.writestr(info, b"hello")
    dest = root / "stamped-out"
    assert extract(stamped, dest) == 1
    expected = 1792506000  # 2026-10-20T14:20:00Z
    assert int((dest / "stamped.txt").stat().st_mtime) == expected, (
        (dest / "stamped.txt").stat().st_mtime,
        expected,
    )
    # TAR carries whole seconds; a directory's time must survive the children
    # being written after it.
    timed = root / "timed"
    (timed / "sub").mkdir(parents=True)
    (timed / "sub" / "f.txt").write_bytes(b"x" * 10)
    for target in (timed / "sub" / "f.txt", timed / "sub"):
        os.utime(target, (expected, expected))
    arc = root / "timed.tar"
    assert lib.ak_create_tar(str(arc).encode(), str(timed).encode()) == 2
    dest = root / "timed-out"
    assert extract(arc, dest) == 1  # one file; directories are not counted
    assert int((dest / "sub" / "f.txt").stat().st_mtime) == expected
    assert int((dest / "sub").stat().st_mtime) == expected

    # ---- the read-only attribute survives create + extract -----------------
    locked_src = root / "locked-src"
    locked_src.mkdir()
    (locked_src / "locked.txt").write_bytes(b"locked")
    (locked_src / "free.txt").write_bytes(b"free")
    locked = locked_src / "locked.txt"
    locked.chmod(0o444)  # works on Windows too: makes the file read-only
    arc = root / "locked.zip"
    assert lib.ak_create_zip(str(arc).encode(), str(locked_src).encode()) == 2
    entries, _ = listing(arc)
    by_name = {e["name"]: e["read_only"] for e in entries}
    assert by_name == {"locked.txt": True, "free.txt": False}, by_name
    dest = root / "locked-out"
    assert extract(arc, dest) == 2
    assert not (dest / "locked.txt").stat().st_mode & 0o200, "locked.txt lost its mode"
    assert (dest / "free.txt").stat().st_mode & 0o200, "free.txt became read-only"
    # Also through TAR, which carries the mode field directly.
    arc = root / "locked.tar"
    assert lib.ak_create_tar(str(arc).encode(), str(locked_src).encode()) == 2
    entries, _ = listing(arc)
    assert {e["name"]: e["read_only"] for e in entries} == {
        "locked.txt": True,
        "free.txt": False,
    }
    # The attribute is restored from an archive we did not write, too.
    foreign = root / "foreign.tar"
    with tarfile.open(foreign, "w") as t:
        info = tarfile.TarInfo("from-python.txt")
        info.size = 4
        info.mode = 0o444
        t.addfile(info, io.BytesIO(b"py!!"))
    dest = root / "foreign-out"
    assert extract(foreign, dest) == 1
    assert not (dest / "from-python.txt").stat().st_mode & 0o200
    # Leave everything writable so the temp tree can be removed on Windows.
    for path in (dest / "foreign-open.txt", dest / "from-python.txt"):
        if path.exists():
            path.chmod(0o666)

    # ---- traversal is refused and nothing lands outside the destination -----
    evil = root / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../../escape.txt", b"nope")
    dest = root / "safe" / "nested"
    dest.mkdir(parents=True)
    assert extract(evil, dest) == -1
    assert lib.ak_last_error_code() == 7  # AK_ERR_CORRUPT
    assert not (root / "escape.txt").exists()

    # Windows refuses to delete read-only files; keep the temp tree removable.
    for path in sorted(root.rglob("*"), reverse=True):
        try:
            path.chmod(path.stat().st_mode | 0o600)
        except OSError:
            pass

print(
    "Native interop passed: Python ZIP store/deflate, streaming and legacy "
    "CP437 archives and GNU/pax TAR -> DLL; DLL ZIP (dynamic Huffman) and "
    "TAR (prefix split, GNU long names) -> Python; folder extraction, "
    "timestamp and read-only restoration, ZIP64 and traversal refusals "
    "verified"
)
