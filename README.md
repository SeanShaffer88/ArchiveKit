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
- **Traversal-safe by construction.** Every extraction path is joined
  through a guard that refuses absolute paths, drive-relative names, and
  `..` escapes — archives are untrusted input.
- **Reads what the world actually writes.** ZIP store/deflate, ustar TAR,
  and TAR long names carried the two ways they really are: GNU `L` records
  and pax `x` extended headers (`path`, `size`, `mtime`). Metadata records
  are consumed as structure, never listed as entries. On create, TAR names
  use the 100-byte field or a 155+100 byte ustar prefix split.
- **Bounded, and honest about it.** 256 MiB encoded input, 64 MiB per
  expanded entry, 512 MiB total declared output, 10,000 entries — the same
  budgets are enforced while *creating*, so an archive can never be written
  larger than it could be opened. ZIP: no encryption, no ZIP64, no
  multi-disk; those fail with AK_ERR_NOT_SUPPORTED and a specific message,
  never a silent misread (a classic ZIP's 16-bit entry count is why the
  create path refuses more than 65,535 entries rather than wrapping it).

## Verification status

- 33 tests: 29 unit tests plus 4 integration tests. CRC vectors;
  zlib-produced DEFLATE streams (embedded, byte-exact); deflate↔inflate
  roundtrips including incompressible data, window-edge data, block
  boundaries and multi-block streams; Huffman length limiting and
  code-length RLE reconstruction; ZIP/TAR roundtrips; CRC corruption and
  truncation; ZIP64 marker refusal; TAR prefix splitting, GNU `L` and pax
  record handling; traversal and device-name refusals; FFI
  create→list→test→extract cycles including single-entry extraction.
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
