# ArchiveKit API — v0.1.0

Authoritative declaration: `../include/archivekit.h`.

## Operations

| Call | Returns |
|---|---|
| `ak_list_json(path)` | caller-owned JSON array of entries, NULL on error |
| `ak_test(path)` | entry count after full verification, -1 on error |
| `ak_extract(path, dest, NULL)` | files written extracting everything |
| `ak_extract(path, dest, "name")` | 1 extracting one entry (0 if it is a directory) |
| `ak_create_zip(path, root_dir)` | entries archived |
| `ak_create_tar(path, root_dir)` | entries archived |
| `ak_zip_append(path, file, arcname)` | AK_OK or AK_ERR_* |

Format is detected from content (ZIP signature / ustar magic), falling
back to the extension. Listing JSON per entry:
`{"name","size","compressed_size","method","is_dir","crc32","modified_unix"}`
— crc32 is a hex string for ZIP entries, null for TAR.

## Errors

AK_ERR_NOT_FOUND (missing file/entry), AK_ERR_NOT_SUPPORTED (encrypted,
ZIP64, multi-disk, unknown method, TAR name > 100 chars on create),
AK_ERR_CORRUPT (bad structure, checksum, CRC, size — or an entry that
would escape the extraction destination), AK_ERR_INVALID_ARG (null or
non-UTF-8 arguments). Details via `ak_last_error()` (thread-local).

## Honest limitations (v0.1)

- Whole-archive-in-memory design: create/extract read archives and file
  payloads fully into RAM. Fine for tool-scale archives; a streaming API
  is v0.3 roadmap.
- DEFLATE *compression* uses fixed Huffman codes: valid everywhere,
  typically ~10-20% larger than dynamic-Huffman encoders on text.
  Decompression handles all DEFLATE block types.
- `ak_zip_append` rewrites the archive (entries re-encoded); content is
  preserved, byte layout is not.
- Timestamps: ZIP stores DOS time (2-second resolution, 1980-2107).
