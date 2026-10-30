# ArchiveKit.dll

**Create, list, test, and extract ZIP and TAR archives — from any language that can call C, with zero dependencies.**

ArchiveKit is #3 in the Windows DLL Collection (after WinRecovery and
FastSearch). Archiving is the thing every small tool eventually needs and
nobody wants to re-implement: here it is once, behind one header, with
the DEFLATE codec built in — no external libraries to ship or license.

## Quick start (C)

```c
#include "archivekit.h"
ak_create_zip("backup.zip", "C:\\Users\\me\\Documents");   // archive a folder
char *entries = ak_list_json("backup.zip");               // JSON listing
ak_free_string(entries);
ak_test("backup.zip");                                    // verify: count or -1
ak_extract("backup.zip", "C:\\Restore", NULL);            // extract all
ak_extract("backup.zip", "C:\\Restore", "docs/report.txt"); // extract one
ak_extract_prefix("backup.zip", "C:\\Restore", "docs/api"); // extract a folder
ak_zip_append("backup.zip", "extra.log", "logs/extra.log");
```

## Design

- **Zero dependencies, codec included.** CRC-32 and DEFLATE (RFC 1951)
  are implemented in this repo. The decompressor handles stored, fixed-,
  and dynamic-Huffman blocks. Since v0.2 the compressor emits LZ77 tokens
  (32 KiB window, hash chains) in 1 MiB blocks and codes each block with
  dynamic Huffman codes, falling back to fixed codes for blocks that are
  cheaper that way. Code lengths are limited to 15 bits by rescaling
  frequencies, so no input needs code-count fixups.
- **Close to a real encoder, measured.** On this harness the ZIP member
  stream lands between parity and ~2% above Info-ZIP's `-6`/zlib's level 6:
  a 6 MB repetitive text file compressed to 18,398 bytes against 18,019
  (102%), a 16 MB mixed text/binary tree to 58,303 against 58,195 (100.2%),
  and a 45 KB text sample to 189 bytes against 195 (97%). v0.1's
  fixed-Huffman encoder needed 417 bytes for that last sample.
- **Extraction restores what the archive recorded.** Modified times are
  applied to files and to listed directories (via `utimensat`/`SetFileTime`,
  declared in `platform.rs` — still zero dependencies), and the read-only
  attribute round-trips: recorded on create, reported in the listing,
  re-applied on extract. Both use the same ordering rule, directories last,
  so writing children cannot undo a parent's time and a read-only directory
  can still be populated before it is locked.
- **Creating reports what it left out.** Symlinks are never followed (they can
  point anywhere) and unreadable directories are skipped, but neither is
  dropped in silence: `ak_last_warning()` names them after `ak_create_zip` /
  `ak_create_tar`, so an archive never quietly claims to be a full copy.
- **Appending never loses the archive's own note.** `ak_zip_append` keeps the
  ZIP archive comment, and refuses a name that is absolute, contains `..`, or
  already exists — appending is not a way to build an archive this library
  would then refuse to extract.
- **Old and wrapped archives get an answer, not a shrug.** TAR reads v7 (the
  pre-ustar format, recognised by its header checksum) as well as ustar, GNU
  and pax. A `.tar.gz`, `.tar.bz2`, `.xz`, `.zst`, 7z or RAR file is named as
  such — "this is gzip-compressed data, not an archive" — instead of being
  called an unknown format.
- **Sparse members are named, not written as stubs.** A GNU sparse entry
  (`S`) lists as `type: sparse`, is skipped on extraction and appears in
  `ak_last_warning()`, because its header describes only the bytes present:
  writing it as-is would leave a file with the right name and wrong contents.
- **Exact file times, not rounded ones.** ZIP's DOS field stores 2-second
  steps and nothing before 1980, so archives that record a real timestamp in an
  extra field (`0x5455` or NTFS `0x000A`) are read from there; the same goes for
  the UTF-8 name in `0x7075`, which some writers use to spell names the legacy
  code page cannot. Archives with a self-extractor stub in front are read too.
- **Tarballs with symlinks extract instead of failing.** Link and special-file
  entries are listed with their `type`, and extraction skips them and says so
  through `ak_last_warning()` — Windows cannot recreate them anyway, and one
  link used to abort the whole extraction of an otherwise ordinary archive.
- **Traversal-safe by construction.** Every extraction path is joined
  through a guard that refuses absolute paths, drive-relative names, and
  `..` escapes — archives are untrusted input.
- **Legacy names decode instead of turning into mojibake.** ZIP names are
  UTF-8 when flagged (or when the bytes are valid UTF-8), otherwise CP437 per
  APPNOTE 4.4.4 — so a DOS-era name stored as `caf` + byte 0x82 + `.txt`
  lists and extracts as `café.txt` instead of `caf?`.txt. Archives written by
  streaming tools (data descriptors, flag bit 3) read fine, because sizes
  come from the central directory.
- **Reads what the world actually writes.** ZIP store/deflate (directories
  detected from the trailing `/` *or* the DOS directory attribute), ustar TAR,
  and TAR long names carried the two ways they really are: GNU `L` records
  and pax `x` extended headers (`path`, `size`, `mtime`). Metadata records
  are consumed as structure, never listed as entries. On create, TAR names
  use the 100-byte field or a 155+100 byte ustar prefix split, and fall back
  to a GNU long-name record when neither fits — so deep Windows paths no
  longer fail to archive.
- **Bounded, and honest about it.** 256 MiB encoded input, 64 MiB per
  expanded entry, 512 MiB total declared output, 10,000 entries — the same
  budgets are enforced while *creating*, so an archive can never be written
  larger than it could be opened. ZIP: no encryption, no ZIP64, no
  multi-disk; those fail with AK_ERR_NOT_SUPPORTED and a specific message,
  never a silent misread (a classic ZIP's 16-bit entry count is why the
  create path refuses more than 65,535 entries rather than wrapping it).

## Verification status

- 58 tests: 53 unit tests plus 5 integration tests. CRC vectors;
  zlib-produced DEFLATE streams (embedded, byte-exact); deflate↔inflate
  roundtrips including incompressible data, window-edge data, block
  boundaries and multi-block streams; Huffman length limiting and
  code-length RLE reconstruction; ZIP/TAR roundtrips; CRC corruption and
  truncation; ZIP64 marker refusal; TAR prefix splitting, GNU `L` and pax
  record handling; legacy CP437 versus flagged-UTF-8 names; DOS-versus-Unix
  read-only decoding; data-descriptor archives; traversal and device-name
  refusals; exact times from extra fields, timestamps and the read-only
  attribute restored on extraction; prepended-stub archives;
  FFI create→list→test→extract cycles including single-entry and
  folder-prefix extraction.
- The codec is verified three ways: zlib-produced vectors embedded in
  inflate tests, deflate↔inflate roundtrips, and live interop against
  system zip/unzip/tar and Python's zipfile/tarfile. The dynamic-Huffman
  encoder is additionally anchored to byte-exact output from a line-by-line
  model whose streams were decoded by zlib, so a refactor cannot silently
  change the bytes it writes.
- Interop (run during development, and `tests/native_interop.py` runs in
  CI): archives from Python zipfile (store/deflate), Info-ZIP `zip -9`, GNU
  tar (ustar, `gnu`, `pax`) and Python tarfile extract correctly here;
  archives produced here pass `unzip -t`, Python zipfile and GNU tar
  verification, including long TAR names and multi-block DEFLATE streams.
- Windows CI (`windows-latest`) is the link + native-run gate: fmt, clippy,
  full test suite, release build, then the Python interop script against
  the built DLL.

## Build & gate

```sh
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
../windevkit/tools/gate.sh   # fmt, clippy host+windows, full tests
```

## License

MIT.

## Input review and reporting

Read the [bounded input and safety contract](docs/INPUT_REVIEW.md), including intentional refusals and remaining validation gaps. Report sensitive issues through the [security policy](SECURITY.md).
