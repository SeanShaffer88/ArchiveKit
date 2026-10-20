# ArchiveKit Roadmap

**v0.1 (this build)** — ZIP (store/deflate) + TAR (ustar) create/list/
test/extract behind a C ABI, zero dependencies, hand-written DEFLATE
codec, traversal-safe extraction.

**v0.2**
- ZIP64 read support (large archives), data-descriptor flag handling.
- TAR long names (ustar prefix split on create; GNU 'L' records on read).
- Dynamic-Huffman DEFLATE compression for better ratios (the decoder
  already supports it; the encoder is fixed-Huffman in v0.1).

**v0.3**
- Streaming API for archives too large to hold in memory comfortably.
- 7z read support evaluation (format complexity vs demand).

**Later**
- Per-entry extract-to-memory API; progress callbacks for big archives.
