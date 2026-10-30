# ArchiveKit Roadmap

**v0.1** — ZIP (store/deflate) + TAR (ustar) create/list/test/extract behind
a C ABI, zero dependencies, hand-written DEFLATE codec, traversal-safe
extraction.

**v0.2 (this build)**
- Dynamic-Huffman DEFLATE compression: LZ77 tokens are coded per 1 MiB
  block with dynamic Huffman codes (fixed-Huffman per block when that is
  smaller). Measured within ~0-2% of zlib/Info-ZIP level 6 on text, prose,
  logs and mixed binary; v0.1's fixed-Huffman output was 10-20% larger.
- The read-only attribute round-trips: create records it (DOS attribute in
  ZIP, mode without a write bit in TAR), `ak_list_json` reports it, and
  extract re-applies it — directories last, so a read-only directory can
  still be populated first.
- Extraction restores the archive's modified times (files, and listed
  directories after their children are written) through `utimensat` on Unix
  and `SetFileTime` on Windows — declared in `platform.rs`, no new
  dependency. ZIP's zero time clamps to 1980; a zero TAR time is treated as
  unknown and left alone.
- New ABI call `ak_extract_prefix`: extract one folder with the prefix
  stripped from the written paths, matched on path component boundaries.
  Only selected entries are traversal-checked, so a hostile entry elsewhere
  in the archive cannot block a clean folder extraction.
- Legacy name decoding: unflagged ZIP names are CP437 per APPNOTE 4.4.4
  (UTF-8 when flagged, or when the bytes are valid UTF-8), so DOS-era names
  list and extract correctly instead of as replacement characters.
  Streaming archives (`data-descriptor`, flag bit 3) are verified readable.
- TAR long-name *output*: names that cannot be prefix-split are written as
  a GNU `L` record (capped at 64 KiB, the reader's metadata limit) instead of
  failing the whole archive. Names that fit stay plain ustar.
- TAR long names: ustar prefix split on create (155 + 100 bytes), GNU `L`
  records and pax `x` `path`/`size`/`mtime` records on read, with metadata
  records consumed as structure instead of listed as entries.
- Explicit ZIP64 refusal: classic-format overflow markers in the EOCD or a
  central-directory entry now produce AK_ERR_NOT_SUPPORTED instead of a
  mis-parse. ZIP64 *extras* that leave classic sizes intact stay readable.
- Create-side budgets: entry count, per-file size and total size are
  enforced while walking a folder, so an archive cannot be written that the
  library could not open (classic ZIP's 16-bit entry count would otherwise
  wrap silently).
- Extraction parses the archive once instead of once per entry (v0.1 was
  quadratic in entry count), removes partial files when a write fails, and
  finds a directory by name with or without its trailing `/`.
- TAR writer no longer panics on out-of-range timestamps; it reports them.
- ZIP extra fields are read for exact times (`0x5455` Unix seconds, `0x000A`
  NTFS FILETIME) and for the UTF-8 name in `0x7075`. Found by zipping a file
  with an odd-second mtime: the listing reported ...:02, and a 1975 file
  reported 1980. Other extra tags are still skipped.
- Archives with a self-extractor stub in front (prepended bytes, short recorded
  offsets) are located from the EOCD instead of failing on the first record.
- Per-entry budget errors name the entry and its size instead of saying only
  that the archive exceeded a budget.

**v0.3**
- ZIP64 *read* support for large archives, and `data-descriptor` archives
  whose sizes only appear in the trailing descriptor.
- Symlink and hardlink *creation* behind an explicit opt-in (creating links
  is a security decision, not just a format one). Reading already lists them
  with their `type`, and extraction skips them and reports the count through
  `ak_last_warning()`.
- Full permission restore: the read-only bit now round-trips, but complete
  POSIX modes (executable bits, group/other), ACLs and Windows hidden/system
  attributes are still not carried or applied.
- Streaming API for archives too large to hold in memory comfortably.

**Later**
- 7z read support evaluation (format complexity vs demand).
- Per-entry extract-to-memory API; progress callbacks and cancellation for
  big archives.
