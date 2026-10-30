# Input and extraction review

This file records what the library refuses, why, and what is still not
proven. Sections are dated; later sections describe later builds.

## October 21–22, 2026 (v0.1 hardening)

The C ABI is unchanged. New conservative refusals apply: 256 MiB encoded archive input, 64 MiB per expanded entry, 512 MiB total declared output and 10,000 entries. DEFLATE checks the budget before literal, stored-block and back-reference growth; ZIP uses the declared entry size as a tighter budget. TAR checks output size, padded offsets and input truncation before advancing.

Extraction creates new files exclusively and never overwrites existing files. Destination ancestors are checked with link-aware metadata; detected symlinks and Windows reparse points/junctions are refused. Common Windows device names, ADS colons, trailing-dot/space aliases and control characters are refused in archive names. Existing supported ZIP/TAR formats and upstream-independent codec implementations remain.

Limits: these metadata checks do not close adversarial replacement races. Use a fresh, quiescent extraction folder without untrusted concurrent writers. Extraction is not transactional: earlier files/directories can remain after failure; a failed write can leave a partial file named in the error. There is no cancellation API. Do not advertise this as a sandbox or as guaranteed containment against a hostile local filesystem actor. The archive-creation APIs are separate from these extraction safeguards.

Validation at that review, on Windows 11 Home build 26300 x64: 19 Debug and 19 Release tests (the suite has grown since); host and all-target Windows Clippy/check; Release DLL build. Tests exercised intra-block expansion boundaries, malformed bounded corpora, traversal/device/ADS names, overwrite refusal and a real standard-user junction pointing to another synthetic folder. The outside fixture remained unchanged. Python stdlib ZIP store/deflate input decoded through the compiled DLL; ZIP and TAR created by the DLL were independently read by Python. Existing zlib vectors and round-trip anchors remain intact.

`tests/native_interop.py` is part of Windows CI. The deterministic malformed corpus is bounded regression coverage, not coverage-guided fuzzing, a sanitizer run or a complete security audit. Native ARM64 and hostile race/resource-exhaustion scenarios need separate evidence. Release panic strategy is unwind so the existing FFI panic guard works for unwinding panics; it cannot recover from invalid caller pointers or allocator/process aborts.

## October 30, 2026 (v0.2)

No ABI change: same functions, same error codes, same header.

**New read paths, with their own bounds.** TAR now consumes GNU `L` long-name
records and pax `x`/`X` extended headers instead of listing them as entries.
A metadata record is capped at 64 KiB; GNU base-256 (binary) numeric fields
are refused with `AK_ERR_NOT_SUPPORTED` rather than read as octal; pax records
must declare a length that stays inside the record block and must be newline
terminated, and `size`/`mtime` must parse, or the archive is `AK_ERR_CORRUPT`.
A pax `size` override is used for both the reported entry size and the offset
of the following header, so a placeholder header field cannot desynchronise the
walk. Names from these records are subject to exactly the same extraction guard
as before (`safe_join`), i.e. a long name is not a way around traversal checks.

**ZIP64 is refused precisely.** The EOCD entry-count/offset/size overflow
markers, and per-entry `0xFFFFFFFF` size or offset markers, now produce
`AK_ERR_NOT_SUPPORTED` naming ZIP64. Previously such archives could be
mis-parsed as corrupt or partially listed. ZIP64 *extra fields* whose central
directory still carries classic sizes (what streaming writers emit) remain
readable, because sizes are taken from the central directory.

**Create paths now enforce the read budgets.** Entry count, per-file size and
total size are checked while walking the folder, and the ZIP writer refuses
more than 65,535 entries or a 4 GiB layout instead of writing a wrapped 16-bit
count or 32-bit offset. This closes a silent-corruption hole rather than a
security hole: the old writer produced an archive that described the wrong
number of entries. Symlinks are still never followed; unreadable
subdirectories are still skipped silently, which is a deliberate trade for
backup use and is called out here.

**Extraction changes.** The archive is parsed once per call instead of once
per entry (v0.1 re-parsed the central directory for every file it extracted).
A file that fails mid-write is removed instead of being left truncated, and
the error says whether removal succeeded. The remaining non-transactional
properties are unchanged: earlier entries stay on disk after a failure, and
existing files are never overwritten.

**What was verified for this change.** Locally on Linux x86_64, with rustc
1.88.0: 29 unit tests and 4 integration tests, `cargo fmt --all -- --check`,
`cargo clippy --all-targets -- -D warnings`, and the release cdylib. Interop
was re-run against Info-ZIP `zip`/`unzip`, GNU `tar` (ustar, `gnu`, `pax`) and
Python `zipfile`/`tarfile` in both directions, including long TAR names, a
5-10 MB multi-block DEFLATE stream, ZIP64 refusal and traversal refusal. The
dynamic-Huffman encoder was additionally checked against a line-by-line Python
model whose streams were decoded by zlib: 300 structural fuzz cases, 4,000
random frequency sets (no incomplete or over-long codes), and byte-exact
anchors now asserted in the Rust test suite.

**Name decoding and folder extraction (added to v0.2 before release).** ZIP
names are now decoded as UTF-8 when the entry sets the UTF-8 flag or when the
bytes are valid UTF-8, and as CP437 otherwise (APPNOTE 4.4.4). This cannot
widen the extraction surface: ASCII bytes pass through unchanged and every
CP437 high byte maps to a non-ASCII printable character (U+00A1 and above),
so decoding cannot introduce a `/` or `\` separator, a drive colon, a control
character or a device name. The traversal guard therefore still sees exactly
the separator set it did before. `ak_extract_prefix` selects entries on
component boundaries and strips the prefix; it traversal-checks only the
entries it writes, so an unsafe entry elsewhere in the archive is skipped
silently rather than aborting the call, while an unsafe entry *inside* the
selection aborts with `AK_ERR_CORRUPT`. An unsafe prefix itself is
`AK_ERR_INVALID_ARG`, not a silent no-op that reports zero files.

**Timestamp restoration.** Extraction now calls `utimensat` (Unix) or
`SetFileTime` (Windows) with the time each entry declared. The value is
validated before use: the Windows path converts to 100 ns ticks in `i128` and
refuses anything outside the FILETIME range instead of wrapping, and the Unix
path passes the seconds through unchanged. A zero TAR time is treated as
unknown and skipped; ZIP clamps pre-1980 times to the DOS epoch because the
format cannot express them. Restoration runs after the file handle is closed
(Windows refuses attribute writes on an open write handle) and failures are
deliberately swallowed, because the content is already on disk and a
read-only volume or a filesystem without timestamps must not turn a good
extraction into an error. This adds one more attribute write per entry, so an
entry name that resolves to a path the process may write but not re-attribute
now produces a file with the wrong (current) time rather than an error.

**Read-only attribute.** Create records whether a source file or directory is
read-only, `ak_list_json` reports it, and extraction re-applies it. Two
ordering rules keep it safe: a file is marked only after its content *and*
timestamp are written, and a directory is marked only after every child
exists, in reverse order, because a read-only directory can still be written
into on Unix but Windows will refuse new children. On Unix the owner write bit
is dropped from all three permission triads, so "read-only" means read-only
for every account rather than just the owner. Failures are ignored like
timestamp failures. The practical consequence worth knowing: extracting a
read-only tree and then trying to modify or delete it inside the same process
will fail until the attribute is cleared, exactly as it would for a real copy.
A zero TAR mode is treated as "not recorded" and does not make an entry
read-only.

**What is still not proven.** No new Windows-native adversarial run was made
for this change; Windows CI (fmt, clippy, test, release build, then
`tests/native_interop.py` against the built DLL) is the native gate, and the
v0.1 statements above are neither re-run nor retracted. The TAR pax/GNU
metadata parsers have not been fuzzed, only exercised against real archives
and hand-built malformed records. Long TAR names beyond the ustar prefix split
still cannot be *written*. Extraction remains a best-effort tool for
trustworthy local archives, not a containment boundary.
