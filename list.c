// list.c — list all stored versions for a file
#include <stdio.h>
#include <sqlite3.h>
#include <time.h>
#include <string.h>

#define DB_PATH "/home/s3v3red/Documents/.temporalfs/temporal.db"

int list_versions(const char *path) {
    sqlite3 *db;
    if (sqlite3_open(DB_PATH, &db)) {
        fprintf(stderr, "DB open: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    const char *sql =
        "SELECT id, timestamp, hash, size FROM versions WHERE path=? ORDER BY id;";
    sqlite3_stmt *st;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);

        printf("Versions for: %s\n", path);
        printf("---------------------------------------------\n");
        printf("%-6s %-20s %-64s %s\n", "ID", "Date", "Hash", "Size");
        printf("---------------------------------------------\n");

        while (sqlite3_step(st) == SQLITE_ROW) {
            int id = sqlite3_column_int(st, 0);
            time_t ts = sqlite3_column_int64(st, 1);
            const char *hash = (const char*)sqlite3_column_text(st, 2);
            long size = sqlite3_column_int64(st, 3);

            char tbuf[32];
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&ts));
            printf("%-6d %-20s %-64s %ld\n", id, tbuf, hash, size);
        }

        sqlite3_finalize(st);
    } else {
        fprintf(stderr, "Query error: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_close(db);
    return 0;
}
