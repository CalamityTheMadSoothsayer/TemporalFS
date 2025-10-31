// prune.c — remove orphaned chunks and compact DB
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define DB_PATH "/home/s3v3red/Documents/.temporalfs/temporal.db"
#define CHUNK_DIR "/home/s3v3red/Documents/.temporalfs/chunks"

int prune_chunks(void) {
    sqlite3 *db;
    if (sqlite3_open(DB_PATH, &db)) {
        fprintf(stderr, "DB open: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    // Collect all referenced hashes
    const char *sql = "SELECT DISTINCT chunk_hash FROM version_chunks;";
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "Query error: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    char **referenced = NULL;
    size_t count = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *hash = (const char*)sqlite3_column_text(st, 0);
        if (!hash) continue;
        referenced = realloc(referenced, sizeof(char*) * (count + 1));
        referenced[count++] = strdup(hash);
    }
    sqlite3_finalize(st);

    printf("Scanning chunk directory for unreferenced data...\n");

    DIR *dir = opendir(CHUNK_DIR);
    if (!dir) { perror("opendir"); sqlite3_close(db); return 1; }

    size_t deleted = 0, kept = 0;
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.') continue;
        int found = 0;
        for (size_t i = 0; i < count; i++) {
            if (strcmp(ent->d_name, referenced[i]) == 0) { found = 1; break; }
        }
        if (!found) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", CHUNK_DIR, ent->d_name);
            if (unlink(path) == 0) {
                printf("Deleted orphan: %s\n", ent->d_name);
                deleted++;
            }
        } else kept++;
    }
    closedir(dir);

    printf("Kept %zu chunks, deleted %zu orphans.\n", kept, deleted);

    // Free memory
    for (size_t i = 0; i < count; i++) free(referenced[i]);
    free(referenced);

    // Compact DB
    sqlite3_exec(db, "VACUUM;", NULL, NULL, NULL);
    sqlite3_close(db);

    return 0;
}
