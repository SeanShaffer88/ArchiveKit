/* ArchiveKit C example: list + test an archive. */
#include "archivekit.h"
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: example <archive>\n"); return 2; }
    char *json = ak_list_json(argv[1]);
    if (!json) { fprintf(stderr, "list failed (%d): %s\n", ak_last_error_code(), ak_last_error()); return 1; }
    printf("%s\n", json);
    ak_free_string(json);
    int64_t n = ak_test(argv[1]);
    printf("verified entries: %lld\n", (long long)n);
    return n < 0 ? 1 : 0;
}
