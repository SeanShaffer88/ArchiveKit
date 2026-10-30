# ArchiveKit API — v0.2.0

Authoritative declaration: `../include/archivekit.h`.

## Operations

| Call | Returns |
|---|---|
| `ak_list_json(path)` | caller-owned JSON array of entries, NULL on error |
| `ak_test(path)` | entry count after full verification, -1 on error |
| `ak_extract(path, dest, NULL)` | files written extracting everything |
| `ak_extract(path, dest, "name")` | 1 extracting one entry (0 if it is a directory) |
| `ak_extract_prefix(path, dest, "folder")` | files written extracting that folder and everything below it (prefix stripped) |
| `ak_create_zip(path, root_dir)` | entries archived |
| `ak_create_tar(path, root_dir)` | entries archived |
| `ak_zip_append(path, file, arcname)` | AK_OK or AK_ERR_* |

Format is detected from content (ZIP signature / ustar magic), falling
back to the extension. Listing JSON per entry:
`{"name","size","compressed_size","method","is_dir","crc32","modified_unix","read_only","type"}`
— crc32 is a hex string for ZIP entries, null for TAR; read_only reflects the
DOS read-only attribute (ZIP) or a mode with no write bit (TAR); `type` is
`file`, `dir`, `symlink`, `hardlink` or `other`.

## Timestamps

`modified_unix` is the modification time the archive states, in Unix seconds.
For ZIP that means the exact value when the archive carries an extended
timestamp (`0x5455` or NTFS `0x000A`), falling back to the DOS field, whose
resolution is 2 seconds and whose range is 1980-2107; a zero DOS time is
reported as the DOS epoch because that is what the archive says. For TAR it is
the header's `mtime`, with pax overrides honoured, and `null` when the archive
records none.

Extraction restores those times best-effort. A TAR entry with no recorded time
is left alone; a failed attribute write never fails the extraction, since the
content is already on disk.

## What gets extracted

Regular files and directories are written. TAR entries of any other kind —
symbolic links, hard links, device nodes, FIFOs — are **skipped** and counted
in `ak_last_warning()`, because Windows cannot recreate them without privilege
and failing the whole extraction over one link made ordinary tarballs
unusable. The call still succeeds and returns the number of files written:

```c
int64_t n = ak_extract("linux.tar", "C:\\Restore", NULL);
if (n >= 0 && ak_last_warning()[0]) {
    printf("extracted %lld files; %s\\n", n, ak_last_warning());
}
```

Asking for such an entry *by name* is still an error (`AK_ERR_NOT_SUPPORTED`
with the link type in the message), because there is no partial result to
inspect. `ak_test` validates the whole archive including link entries.

Entry names are matched exactly. A directory is also found when the
caller writes its name with or without the trailing `/` that ZIP uses.

A ZIP entry counts as a directory when its name ends with `/` **or** when it
carries the DOS directory attribute (`0x10`) — some writers set only the
attribute, and those entries used to extract as empty files.

Two entries that would land on the same path abort the extraction with
`AK_ERR_CORRUPT` naming both of them, since that is the archive's fault rather
than a pre-existing file. On Windows the comparison is case-insensitive, so
`Case.txt` and `case.txt` collide there and are both kept on Unix. Duplicate
*directory* entries are tolerated, because listing a directory twice is
common and harmless.

## Names

Names are UTF-8 when the entry sets the UTF-8 flag (or when the bytes happen
to be valid UTF-8); otherwise they are decoded as legacy CP437, which is what
APPNOTE 4.4.4 assigns to unflagged names and what DOS-era Windows tools
wrote. The high half of CP437 is all non-ASCII printable characters, so this
decoding cannot introduce a path separator, drive colon or device name — the
traversal guard still sees exactly one place where separators can appear.

## Attributes

Only the read-only bit is carried. Create records it from the source file
(`Permissions::readonly()`, i.e. the owner write bit on Unix and the
attribute on Windows); extract re-applies it to files immediately and to
directories after their children exist, so a read-only directory can still be
populated. Full POSIX modes, ACLs and Windows hidden/system bits are not
preserved and are not applied.

## Timestamps

| archive | resolution | restored |
|---|---|---|
| ZIP | 2 s, 1980-2107 | yes (zero clamps to 1980) |
| TAR | 1 s | yes (zero = unknown, left alone) |

## Extracting a folder

`ak_extract_prefix` selects an entry when its name is the prefix or starts
with `prefix/` (component boundaries, `\` accepted as a separator), then
writes the remainder below it:

```
docs/api/a.txt        + prefix "docs/api"  ->  <dest>/a.txt
docs/api/deep/b.txt                         ->  <dest>/deep/b.txt
docs/other/c.txt                            ->  not selected
docsx/d.txt                                 ->  not selected ("docsx" != "docs")
```

Only selected entries are traversal-checked: a hostile entry elsewhere in the
archive is never written and does not abort the operation, while one inside
the selection aborts with `AK_ERR_CORRUPT`. An unsafe prefix (`..`, absolute,
drive-relative) is `AK_ERR_INVALID_ARG` rather than a silent no-op.

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
- TAR *writing* is ustar, with one exception: a name that cannot be
  expressed as a 155+100 byte prefix split is written as a GNU `L` record,
  which GNU tar, bsdtar, 7-Zip and Python's tarfile read (strict ustar-only
  readers will see the truncated name). Reading handles GNU `L` and pax `x`
  records. Long-name records are capped at 64 KiB, matching the reader.
- Attributes: only the read-only bit round-trips (see above).
- Timestamps: ZIP stores DOS time (2-second resolution, 1980-2107); TAR
  stores whole seconds. Extraction restores the archive's modified time on
  files and on listed directories (directories last, so writing children
  cannot undo them). ZIP cannot express a time before 1980, so a zero ZIP
  timestamp restores as 1980-01-01; a zero *TAR* timestamp is treated as
  "unknown" and left alone. Restoration is best-effort: the content has
  already been written, so a filesystem that rejects the timestamp does not
  fail the extraction. File permissions and other attributes are not
  restored.
