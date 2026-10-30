# ArchiveKit API — v0.2.0

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

Entry names are matched exactly. A directory is also found when the
caller writes its name with or without the trailing `/` that ZIP uses.

## Limits

Enforced on read **and** while creating, so the library never writes an
archive it could not open:

| Limit | Value | Constant |
|---|---|---|
| encoded archive size | 256 MiB | `MAX_ARCHIVE_BYTES` |
| one expanded entry | 64 MiB | `MAX_ENTRY_BYTES` |
| total declared output | 512 MiB | `MAX_TOTAL_BYTES` |
| entries | 10,000 | `MAX_ENTRIES` |

Exceeding a limit is an error, never a truncation. `ak_create_*` reports
`AK_ERR_NOT_SUPPORTED` with the limit named in `ak_last_error()`.

## Errors

AK_ERR_NOT_FOUND (missing file/entry), AK_ERR_NOT_SUPPORTED (encrypted,
ZIP64, multi-disk, unknown method, TAR base-256 numeric fields, a TAR name
that cannot be prefix-split, or a create that would exceed a limit),
AK_ERR_CORRUPT (bad structure, checksum, CRC, size — or an entry that
would escape the extraction destination), AK_ERR_INVALID_ARG (null or
non-UTF-8 arguments). Details via `ak_last_error()` (thread-local).

## Honest limitations (v0.2)

- Whole-archive-in-memory design: create/extract read archives and file
  payloads fully into RAM. Fine for tool-scale archives; a streaming API
  is v0.3 roadmap.
- DEFLATE compression is LZ77 + dynamic Huffman in 1 MiB blocks. That is
  within ~0-2% of zlib level 6 on the samples measured here, but it is not
  an optimal parser: expect a few percent behind `-9` on some inputs.
- `ak_zip_append` rewrites the archive (entries re-encoded); content is
  preserved, byte layout is not.
- TAR *writing* is ustar only: names must fit the 155+100 byte prefix
  split. Longer names are refused — GNU `L` output is roadmap. Reading
  handles GNU `L` and pax `x` records, so those archives extract fine.
- Timestamps: ZIP stores DOS time (2-second resolution, 1980-2107); TAR
  stores whole seconds. Extraction does not restore them yet (roadmap).
