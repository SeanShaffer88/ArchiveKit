# ArchiveKit — agent notes

- Zero dependencies is a design rule: the DEFLATE codec is written from RFC 1951 in src/inflate.rs + src/deflate.rs and CRC-32 is table-driven in src/crc32.rs. Do not add a compression dependency without a written justification.
- The codec is verified three ways: zlib-produced vectors embedded in inflate tests, deflate↔inflate roundtrips, and live interop against system zip/unzip/tar/Python zipfile (see README verification status). Keep all three when changing the codec.
- Format limits are contractual honesty, not bugs: ZIP = store/deflate only, no encryption/ZIP64/multi-disk (ERR_NOT_SUPPORTED with specifics); TAR write is ustar, so names beyond the 155+100 byte prefix split are refused (GNU 'L' output is roadmap; both 'L' and pax records are *read*).
- One parsed entry list per operation (src/ffi.rs `Listed`): listing, extraction and append all read it. Do not reintroduce per-entry re-parsing — that made extraction quadratic.
- Archives cannot be created larger than they can be read: platform::collect enforces the same entry/size budgets as the read path (classic ZIP's 16-bit entry count would otherwise wrap silently).
- Extraction must stay traversal-safe: all writes go through safe_join in lib.rs; archive entry names are untrusted input.
- Gate: WinDevKit tools/gate.sh. Check/clippy do not link — CI's real build is the link gate.
