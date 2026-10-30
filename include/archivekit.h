/*
 * ArchiveKit.dll — C ABI
 * =======================
 * Create, list, test, and extract ZIP and TAR archives. Self-contained:
 * the DEFLATE codec is built in, there are no dependencies.
 *
 * Conventions
 * -----------
 * - All strings are UTF-8, NUL-terminated.
 * - Functions returning char* transfer ownership; free with
 *   ak_free_string(). On failure they return NULL — see ak_last_error().
 * - Count functions return the count, or -1 on error.
 * - ak_zip_append returns AK_OK (0) or an AK_ERR_* code.
 *
 * v0.2 scope (honest)
 * -------------------
 * - ZIP: STORE + DEFLATE. No encryption, no ZIP64, no multi-disk;
 *   archives needing them fail with AK_ERR_NOT_SUPPORTED.
 * - Names: UTF-8 when the entry's UTF-8 flag is set (or the bytes are
 *   valid UTF-8); otherwise legacy CP437, which is what APPNOTE 4.4.4
 *   assigns to unflagged names.
 * - TAR: ustar, files + directories. On create, names use the 100-byte
 *   name field or a 155+100 byte prefix split; anything longer is written
 *   as a GNU 'L' long-name record (read by GNU tar, bsdtar, 7-Zip, Python).
 *   On read, GNU 'L' long names and pax 'x' path/size/mtime records are
 *   honoured (long link names are not).
 * - Extraction is traversal-safe: an entry that would land outside the
 *   destination directory aborts extraction with AK_ERR_CORRUPT.
 * - Extraction restores entry modified times and the read-only attribute
 *   (best effort; a filesystem that rejects them does not fail the call).
 *   Only the read-only bit is carried — not full modes, ACLs or hidden and
 *   system attributes.
 */

#ifndef ARCHIVEKIT_H
#define ARCHIVEKIT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(AK_BUILD)
#define AK_API __declspec(dllexport)
#elif defined(_WIN32)
#define AK_API __declspec(dllimport)
#else
#define AK_API
#endif

#define AK_OK                   0
#define AK_ERR_INVALID_ARG      1
#define AK_ERR_NOT_SUPPORTED    2
#define AK_ERR_NOT_FOUND        3
#define AK_ERR_ACCESS_DENIED    4
#define AK_ERR_PLATFORM         5
#define AK_ERR_INTERNAL         6
#define AK_ERR_CORRUPT          7

/* Version & errors ------------------------------------------------------- */
AK_API const char *ak_version(void);          /* static string; do NOT free */
AK_API uint32_t ak_version_major(void);
AK_API uint32_t ak_version_minor(void);
AK_API uint32_t ak_version_patch(void);
AK_API const char *ak_last_error(void);       /* thread-local; do NOT free */
AK_API int ak_last_error_code(void);
AK_API void ak_free_string(char *p);          /* frees ak_list_json results */

/* Read --------------------------------------------------------------------- */
/* JSON array: [{"name":"...","size":N,"compressed_size":N,"method":"deflate",
 * "is_dir":false,"crc32":"0d4a1185" (or null),"modified_unix":N (or null),
 * "read_only":false}]
 * Format is detected from content, falling back to the file extension. */
AK_API char *ak_list_json(const char *archive_utf8);
/* Verify structure + full decompression + CRC (ZIP). Returns entry count. */
AK_API int64_t ak_test(const char *archive_utf8);
/* Extract all (entry_utf8 == NULL) or one named entry into dest_dir.
 * Returns the number of FILES written. */
AK_API int64_t ak_extract(const char *archive_utf8, const char *dest_dir_utf8,
                          const char *entry_utf8);
/* Extract one folder and everything below it. prefix_utf8 is matched on
 * path component boundaries ("doc" does not select "docs/x") and the
 * prefix itself is stripped from the written paths, so the folder's
 * contents land directly in dest_dir. An empty prefix extracts all.
 * Returns the number of FILES written, or -1 on error. */
AK_API int64_t ak_extract_prefix(const char *archive_utf8, const char *dest_dir_utf8,
                                 const char *prefix_utf8);

/* Create --------------------------------------------------------------------- */
/* Archive the contents of root_dir. Returns the entry count. */
AK_API int64_t ak_create_zip(const char *archive_utf8, const char *root_dir_utf8);
AK_API int64_t ak_create_tar(const char *archive_utf8, const char *root_dir_utf8);
/* Append one file to an existing ZIP under arcname. AK_OK or AK_ERR_*. */
AK_API int ak_zip_append(const char *archive_utf8, const char *file_utf8,
                         const char *arcname_utf8);

#ifdef __cplusplus
}
#endif

#endif /* ARCHIVEKIT_H */
