// FileWatcher.c — rolling-hash chunking + dedup + undo-compress
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include "buzhash_table.h"
#include "dbutils.h"
#include "verify.h"
#include "maintenance.h"
#include <signal.h>

#define BUF_LEN    (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

// replace #define paths with defaults
static const char *WATCH_DIR  = "/home/s3v3red/Documents";
static const char *META_DIR   = "/home/s3v3red/Documents/.temporalfs";
const char *CHUNK_DIR  = "/home/s3v3red/Documents/.temporalfs/chunks";
static const char *DB_PATH    = "/home/s3v3red/Documents/.temporalfs/temporal.db";

const char *CHUNK_DIR;  // exported for dbutils.c

static void init_paths_from_env() {
    const char *w = getenv("TEMPORALFS_WATCH");
    const char *m = getenv("TEMPORALFS_META");
    const char *c = getenv("TEMPORALFS_CHUNKS");
    const char *d = getenv("TEMPORALFS_DB");

    if (w) WATCH_DIR = w;
    if (m) META_DIR = m;
    if (c) CHUNK_DIR = c;
    if (d) DB_PATH = d;
}

// Content-defined chunking parameters
#define RH_WINDOW 64
#define AVG_SIZE  (1 << 20)
#define MIN_SIZE  (1 << 16)
#define MAX_SIZE  (1 << 23)
#define MASK      (AVG_SIZE - 1)

// --- Utility helpers ---

static inline unsigned int rol32(unsigned int x) { return (x << 1) | (x >> 31); }

static off_t file_size(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? st.st_size : -1;
}

// SHA-256 of full file
static void hash_file(const char* path, char out_hex[65], long* out_size) {
    *out_size = file_size(path);
    FILE* fp = fopen(path, "rb");
    if (!fp) { out_hex[0] = 0; return; }

    unsigned char buf[65536], h[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    size_t n;
    while ((n = fread(buf, 1, sizeof buf, fp)) > 0)
        SHA256_Update(&ctx, buf, n);

    fclose(fp);
    SHA256_Final(h, &ctx);
    for (int i = 0; i < 32; i++) sprintf(out_hex + 2*i, "%02x", h[i]);
    out_hex[64] = '\0';
}

// Chunk file based on rolling hash
static int chunk_file(sqlite3* db, const char* path, long version_id) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return 0;  // fail early if cannot open

    mkdir(META_DIR, 0755);
    mkdir(CHUNK_DIR, 0755);

    const size_t BUF = 65536;
    unsigned char *filebuf = malloc(BUF);
    unsigned char *chunkbuf = malloc(MAX_SIZE);
    if (!filebuf || !chunkbuf) {
        free(filebuf); free(chunkbuf);
        fclose(fp);
        return 0;
    }

    unsigned int h = 0;
    unsigned char win[RH_WINDOW] = {0};
    size_t chunk_len = 0, wpos = 0, wfill = 0;
    int seq = 0;
    int ok = 1;  // success flag

    size_t r;
    while ((r = fread(filebuf, 1, BUF, fp)) > 0) {
        for (size_t i = 0; i < r; i++) {
            unsigned char b = filebuf[i];
            chunkbuf[chunk_len++] = b;

            unsigned char old = win[wpos];
            win[wpos] = b;
            wpos = (wpos + 1) % RH_WINDOW;

            if (wfill < RH_WINDOW) {
                h = rol32(h) ^ BUZHASH_T[b];
                wfill++;
            } else {
                h = rol32(h) ^ BUZHASH_T[b] ^ BUZHASH_T[old];
            }

            if (chunk_len >= MIN_SIZE && ((h & MASK) == 0 || chunk_len >= MAX_SIZE)) {
                if (!flush_chunk(db, chunkbuf, chunk_len, version_id, &seq)) {
                    ok = 0;  // failure detected
                    break;
                }
                chunk_len = 0;
            }
        }
        if (!ok) break;
    }

    if (ok && chunk_len > 0) {
        if (!flush_chunk(db, chunkbuf, chunk_len, version_id, &seq))
            ok = 0;
    }

    free(filebuf);
    free(chunkbuf);
    fclose(fp);
    return ok;
}

#include <libgen.h>

static void ensure_path_exists(const char *prompt, const char **path_ref) {
    char input[PATH_MAX];
    struct stat st;

    // If path doesn't exist, ask user
    if (stat(*path_ref, &st) != 0) {
        printf("Default directory not found.\n");
        printf("Define %s: \"%s\" ", prompt, *path_ref);
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin)) {
            input[strcspn(input, "\n")] = 0;  // strip newline
            if (input[0] != '\0')
                *path_ref = strdup(input);
        }
    }

    // Attempt to create directory if it still doesn't exist
    if (mkdir(*path_ref, 0755) && errno != EEXIST) {
        perror("mkdir");
        exit(1);
    }
}

static volatile sig_atomic_t stop = 0;
static void handle_signal(int sig) { stop = 1; }
int fsync_dir(const char *dirpath);

// --- Main ---
int main(int argc, char *argv[]) {
    init_paths_from_env();

    ensure_path_exists("WATCH_DIR", &WATCH_DIR);
    ensure_path_exists("META_DIR", &META_DIR);
    ensure_path_exists("CHUNK_DIR", &CHUNK_DIR);

    // Ensure META and CHUNK directories exist before DB
    char db_parent[PATH_MAX];
    strcpy(db_parent, DB_PATH);
    dirname(db_parent);
    if (mkdir(db_parent, 0755) && errno != EEXIST) {
        perror("mkdir DB parent");
        exit(1);
    }

    sqlite3* db = init_db(DB_PATH);

    // remove orphaned chunks, we don't want to perform actions that could corrupt files.
    printf("Auto-pruning stale chunks...\n");
    prune_chunks();

        // --- Command-line interface handling ---
    if (argc < 2) goto start_watcher;

        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            puts("TemporalFS — rolling-hash deduplication and version tracking\n");
            puts("Usage:");
            puts("  FileWatcher                           Start inotify watcher on the target directory");
            puts("  FileWatcher --verify <file> [ver_id]  Verify recombined data matches recorded hash");
            puts("  FileWatcher --restore <file> <ver_id> Restore a previous version");
            puts("  FileWatcher --list <file>             List available versions");
            puts("  FileWatcher --purge                   Clear all database records");
            puts("  FileWatcher --clean                   Remove unreferenced chunks");
            puts("  FileWatcher --status                  Show summary of tracked files, versions, and chunks");
            puts("  FileWatcher --set-paths               Redefine directories interactively");
            puts("  FileWatcher -h, --help                Show this help message\n");

            puts("Path configuration:");
            puts("  Environment variables override defaults at startup:");
            puts("    TEMPORALFS_WATCH   → watched directory");
            puts("    TEMPORALFS_META    → metadata directory");
            puts("    TEMPORALFS_CHUNKS  → chunk storage directory");
            puts("    TEMPORALFS_DB      → SQLite database file path\n");

            puts("Example:");
            puts("  export TEMPORALFS_WATCH=/data");
            puts("  export TEMPORALFS_META=/data/.temporalfs");
            puts("  export TEMPORALFS_CHUNKS=/data/.temporalfs/chunks");
            puts("  export TEMPORALFS_DB=/data/.temporalfs/temporal.db\n");

            puts("Current configuration:");
            printf("  WATCH_DIR : %s\n", WATCH_DIR);
            printf("  META_DIR  : %s\n", META_DIR);
            printf("  CHUNK_DIR : %s\n", CHUNK_DIR);
            printf("  DB_PATH   : %s\n", DB_PATH);
            return 0;
        }

        if (!strcmp(argv[1], "--status")) {
            sqlite3_stmt *stmt;
            int files = 0, versions = 0, chunks = 0;
            long long total_size = 0;

            if (sqlite3_prepare_v2(db, "SELECT COUNT(DISTINCT path) FROM versions;", -1, &stmt, 0) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) files = sqlite3_column_int(stmt, 0);
                sqlite3_finalize(stmt);
            }

            if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM versions;", -1, &stmt, 0) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) versions = sqlite3_column_int(stmt, 0);
                sqlite3_finalize(stmt);
            }

            if (sqlite3_prepare_v2(db, "SELECT COUNT(*), SUM(size) FROM chunks;", -1, &stmt, 0) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    chunks = sqlite3_column_int(stmt, 0);
                    total_size = sqlite3_column_int64(stmt, 1);
                }
                sqlite3_finalize(stmt);
            }

            printf("Tracked files   : %d\n", files);
            printf("Stored versions : %d\n", versions);
            printf("Unique chunks   : %d\n", chunks);
            printf("Chunk storage   : %.2f MB\n", total_size / (1024.0 * 1024.0));
            return 0;
        }

        if (!strcmp(argv[1], "--clean")) {
            printf("Scanning for unreferenced chunks...\n");
            const char *sql =
                "DELETE FROM chunks "
                "WHERE id NOT IN (SELECT chunk_id FROM version_chunks);";
            char *errmsg = NULL;
            if (sqlite3_exec(db, sql, 0, 0, &errmsg) != SQLITE_OK) {
                fprintf(stderr, "SQLite error: %s\n", errmsg);
                sqlite3_free(errmsg);
            } else {
                printf("Orphaned chunks removed.\n");
            }
            return 0;
        }

        if (argc > 1 && !strcmp(argv[1], "--set-paths")) {
            char input[PATH_MAX];

            printf("Current WATCH_DIR: %s\nNew WATCH_DIR: ", WATCH_DIR);
            if (fgets(input, sizeof(input), stdin)) {
                input[strcspn(input, "\n")] = 0;
                if (input[0]) {
                    setenv("TEMPORALFS_WATCH", input, 1);
                    WATCH_DIR = strdup(input);
                }
            }

            printf("Current META_DIR: %s\nNew META_DIR: ", META_DIR);
            if (fgets(input, sizeof(input), stdin)) {
                input[strcspn(input, "\n")] = 0;
                if (input[0]) {
                    setenv("TEMPORALFS_META", input, 1);
                    META_DIR = strdup(input);
                }
            }

            printf("Current CHUNK_DIR: %s\nNew CHUNK_DIR: ", CHUNK_DIR);
            if (fgets(input, sizeof(input), stdin)) {
                input[strcspn(input, "\n")] = 0;
                if (input[0]) {
                    setenv("TEMPORALFS_CHUNKS", input, 1);
                    CHUNK_DIR = strdup(input);
                }
            }

            printf("Current DB_PATH: %s\nNew DB_PATH: ", DB_PATH);
            if (fgets(input, sizeof(input), stdin)) {
                input[strcspn(input, "\n")] = 0;
                if (input[0]) {
                    setenv("TEMPORALFS_DB", input, 1);
                    DB_PATH = strdup(input);
                }
            }

            printf("\nEnvironment variables updated.\n");
            printf("To persist them, run:\n\n");
            printf("export TEMPORALFS_WATCH=\"%s\"\n", WATCH_DIR);
            printf("export TEMPORALFS_META=\"%s\"\n", META_DIR);
            printf("export TEMPORALFS_CHUNKS=\"%s\"\n", CHUNK_DIR);
            printf("export TEMPORALFS_DB=\"%s\"\n\n", DB_PATH);
            printf("Then rerun FileWatcher.\n");

            return 0;
        }

        if (!strcmp(argv[1], "--purge")) {
        printf("⚠️  This will permanently delete all database records.\n");
        printf("Type 'YES' to confirm: ");

        char input[8];
        if (!fgets(input, sizeof(input), stdin)) {
            fprintf(stderr, "Input error.\n");
            return 1;
        }

        // Strip newline
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "YES") != 0) {
            printf("Purge cancelled.\n");
            return 0;
        }

        printf("Purging all database records...\n");
        sqlite3* purge_db;
        if (sqlite3_open(DB_PATH, &purge_db) == SQLITE_OK) {
            char *errmsg = NULL;
            const char *sql =
                "DELETE FROM version_chunks;"
                "DELETE FROM chunks;"
                "DELETE FROM versions;"
                "VACUUM;";
            if (sqlite3_exec(purge_db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
                fprintf(stderr, "SQLite error: %s\n", errmsg);
                sqlite3_free(errmsg);
            } else {
                printf("All records purged successfully.\n");
            }
            sqlite3_close(purge_db);
        } else {
            fprintf(stderr, "Unable to open database.\n");
        }
        return 0;
    }

    if (!strcmp(argv[1], "--verify")) {
        if (argc >= 3) {
            long version_id = (argc >= 4) ? atol(argv[3]) : -1;
            verify_stored(argv[2], version_id);
        } else {
            fprintf(stderr, "Usage: FileWatcher --verify <file> [version_id]\n");
        }
        return 0;
    }

    if (!strcmp(argv[1], "--restore")) {
        if (argc == 4) {
            long ver = atol(argv[3]);
            return restore_file(argv[2], ver);
        } else {
            fprintf(stderr, "Usage: FileWatcher --restore <file> <version_id>\n");
            return 1;
        }
    }

    if (!strcmp(argv[1], "--list")) {
        if (argc == 3)
            return list_versions(argv[2]);
        else {
            fprintf(stderr, "Usage: FileWatcher --list <file>\n");
            return 1;
        }
    }

    start_watcher:

    // suppress unused warnings
    (void)argc;
    (void)argv;

    // Ensure metadata directories exist
    if (mkdir(META_DIR, 0755) == 0) puts("META_DIR created");
    else if (errno == EEXIST) puts("META_DIR exists");
    else perror("mkdir META_DIR");

    if (mkdir(CHUNK_DIR, 0755) == 0) puts("CHUNK_DIR created");
    else if (errno == EEXIST) puts("CHUNK_DIR exists");
    else perror("mkdir CHUNK_DIR");

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        perror("inotify_init1");
        return 1;
    }

    int wd = inotify_add_watch(fd, WATCH_DIR, IN_CLOSE_WRITE);
    if (wd == -1) {
        perror("inotify_add_watch");
        close(fd);
        return 1;
    }

    printf("Watching %s for changes...\n", WATCH_DIR);
    fflush(stdout);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    char buf[BUF_LEN];
    for (; !stop; ) {
        ssize_t n = read(fd, buf, BUF_LEN);
        if (n <= 0) { usleep(100000); continue; }

        for (char* p = buf; p < buf + n; ) {
            struct inotify_event* ev = (struct inotify_event*)p;

            printf("Event: %s (mask=%u)\n", ev->name, ev->mask);
            fflush(stdout);

            if (ev->len > 0 && (ev->mask & IN_CLOSE_WRITE)) {
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "%s/%s", WATCH_DIR, ev->name);

                if (access(path, F_OK) != 0 || file_size(path) <= 0) {
                    p += sizeof(*ev) + ev->len; continue;
                }

                char file_hex[65];
                long fsize = 0;
                hash_file(path, file_hex, &fsize);
                if (!file_hex[0]) {
                    p += sizeof(*ev) + ev->len; continue;
                }

                int rc = sqlite3_exec(db, "BEGIN IMMEDIATE;", 0, 0, 0);
                if (rc != SQLITE_OK) {
                    fprintf(stderr, "BEGIN failed: %s\n", sqlite3_errmsg(db));
                    goto next_event;
                }

                long vid = log_version(db, path, file_hex, fsize);
                if (vid == -1) {
                    sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
                    printf("Skipped (duplicate/undo): %s\n", path);
                    goto next_event;
                }

                if (!chunk_file(db, path, vid)) {
                    sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
                    fprintf(stderr, "Chunking failed: %s\n", path);
                    goto next_event;
                }

                rc = sqlite3_exec(db, "COMMIT;", 0, 0, 0);
                if (rc != SQLITE_OK) {
                    fprintf(stderr, "COMMIT failed: %s\n", sqlite3_errmsg(db));
                    sqlite3_exec(db, "ROLLBACK;", 0, 0, 0);
                } else {
                    fsync_dir(CHUNK_DIR);
                    fsync_dir(META_DIR);
                    printf("Recorded: %s (%ld bytes)\n", path, fsize);
                }

                next_event:
                (void)0;
            }

            p += sizeof(*ev) + ev->len;
        }
    }

    printf("\nStopping watcher, closing DB...\n");
    sqlite3_close(db);
    close(fd);
    return stop ? 3 : 0;

}
