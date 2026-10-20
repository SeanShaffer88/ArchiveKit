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
ak_zip_append("backup.zip", "extra.log", "logs/extra.log");
```

## Design

- **Zero dependencies, codec included.** CRC-32 and DEFLATE (RFC 1951)
  are implemented in this repo: the decompressor handles stored, fixed-,
  and dynamic-Huffman blocks; the compressor emits fixed-Huffman streams
  with hash-chain LZ77.
- **Traversal-safe by construction.** Every extraction path is joined
  through a guard that refuses absolute paths, drive-relative names, and
  `..` escapes — archives are untrusted input.
- **Honest v0.1 scope.** ZIP: STORE + DEFLATE only — no encryption, no
  ZIP64, no multi-disk (those fail with AK_ERR_NOT_SUPPORTED and a
  specific message, never a silent misread). TAR: ustar files and
  directories, names up to 100 chars on create. Whole-archive-in-memory
  design; streaming is on the roadmap.

## Verification status

- 15 unit tests: CRC vectors, zlib-produced DEFLATE streams (embedded,
  byte-exact), deflate↔inflate roundtrips (including incompressible and
  window-edge data), ZIP/TAR roundtrips, CRC corruption detection,
  traversal-guard rules, FFI create→list→test→extract cycles.
- Interop (run during development): archives produced by Python zipfile
  and the system `zip` extract correctly here; archives produced here
  pass `unzip -t`, Python zipfile, and GNU tar verification.
- Windows CI (`windows-latest`) is the link + native-run gate.

## Build & gate

```sh
cargo test
../windevkit/tools/gate.sh   # fmt, clippy host+windows, full tests
```

## License

MIT.
