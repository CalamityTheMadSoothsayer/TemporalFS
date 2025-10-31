#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sqlite3.h>
#include "dbutils.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "codec.h"
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#define HASH_CACHE_TTL 2

// CHUNK_DIR is now provided by the main program (env-configurable)
extern const char *CHUNK_DIR;

typedef struct { char path[4096]; char hash[65]; time_t ts; } CacheEntry;
static CacheEntry last_rec = {"", "", 0};

/* ------- durability helpers ------- */

int fsync_dir(const char *dirpath) {
    int dfd = open(dirpath, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return -1;
    int r = fsync(dfd);
    close(dfd);
    return r;
}

static int safe_write_file_atomic(const char *dir, const char *final_name,
                                  const void *buf, size_t len)
{
    char tmp_template[PATH_MAX];
    snprintf(tmp_template, sizeof(tmp_template), "%s/.tmpchunk.XXXXXX", dir);

    int tfd = mkstemp(tmp_template);
    if (tfd < 0) return 0;

    const unsigned char *p = (const unsigned char *)buf;
    size_t rem = len;
    while (rem) {
        ssize_t w = write(tfd, p, rem);
        if (w < 0) { close(tfd); unlink(tmp_template); return 0; }
        rem -= (size_t)w; p += w;
    }

    if (fdatasync(tfd) != 0) { close(tfd); unlink(tmp_template); return 0; }
    if (close(tfd) != 0) { unlink(tmp_template); return 0; }

    char final_path[PATH_MAX];
    snprintf(final_path, sizeof(final_path), "%s/%s", dir, final_name);
    if (rename(tmp_template, final_path) != 0) { unlink(tmp_template); return 0; }

    // make directory entry durable
    (void)fsync_dir(dir);
    return 1;
}

/* ------- database init ------- */

sqlite3* init_db(const char *db_path) {
    sqlite3 *db;
    if (sqlite3_open(db_path, &db)) {
        fprintf(stderr, "DB open: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    const char *sql =
        // Safety & durability
        "PRAGMA journal_mode=WAL;"
        "PRAGMA synchronous=FULL;"
        "PRAGMA temp_store=MEMORY;"
        "PRAGMA locking_mode=NORMAL;"
        "PRAGMA foreign_keys=ON;"
        "PRAGMA mmap_size=268435456;"
        // Tables
        "CREATE TABLE IF NOT EXISTS versions ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " path TEXT NOT NULL,"
        " timestamp INTEGER,"
        " hash TEXT NOT NULL,"
        " size INTEGER);"
        "CREATE TABLE IF NOT EXISTS chunks ("
        " hash TEXT PRIMARY KEY,"
        " size INTEGER);"
        "CREATE TABLE IF NOT EXISTS version_chunks ("
        " version_id INTEGER,"
        " seq INTEGER,"
        " chunk_hash TEXT,"
        " FOREIGN KEY(version_id) REFERENCES versions(id) ON DELETE CASCADE,"
        " FOREIGN KEY(chunk_hash) REFERENCES chunks(hash));"
        // Indexes + view
        "CREATE INDEX IF NOT EXISTS idx_versions_path ON versions(path);"
        "CREATE INDEX IF NOT EXISTS idx_versions_hash ON versions(hash);"
        "CREATE INDEX IF NOT EXISTS idx_vchunks_vid ON version_chunks(version_id);"
        "CREATE VIEW IF NOT EXISTS vw_versions AS "
        "SELECT id, path, datetime(timestamp, 'unixepoch', 'localtime') AS time, hash, size "
        "FROM versions;";

    char *err = 0;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "DB init: %s\n", err);
        sqlite3_free(err);
    }

    return db;
}

/* ------- version logging ------- */

long log_version(sqlite3 *db, const char *path, const char *file_hash, long size) {
    time_t now = time(NULL);

    if (!strcmp(last_rec.path, path) &&
        !strcmp(last_rec.hash, file_hash) &&
        (now - last_rec.ts) < HASH_CACHE_TTL)
        return -1; // same file and hash too soon

    strcpy(last_rec.path, path);
    strcpy(last_rec.hash, file_hash);
    last_rec.ts = now;

    sqlite3_stmt *st;
    int existing_id = -1;

    if (sqlite3_prepare_v2(db,
        "SELECT id FROM versions WHERE path=? AND hash=? ORDER BY id DESC LIMIT 1;",
        -1, &st, NULL) == SQLITE_OK)
    {
        sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, file_hash, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)
            existing_id = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }

    if (existing_id != -1)
        return -1;

    long version_id = -1;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO versions(path,timestamp,hash,size) VALUES(?,?,?,?);",
        -1, &st, NULL) == SQLITE_OK)
    {
        sqlite3_bind_text(st, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, now);
        sqlite3_bind_text(st, 3, file_hash, -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 4, size);
        if (sqlite3_step(st) == SQLITE_DONE)
            version_id = (long)sqlite3_last_insert_rowid(db);
        sqlite3_finalize(st);
    }

    return version_id;
}

/* ------- chunk persistence ------- */

int ensure_chunk(sqlite3* db, const char* chunk_hash,
                 const unsigned char* data, size_t len)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", CHUNK_DIR, chunk_hash);

    // If file exists but size mismatches, treat as collision and fail
    struct stat st;
    if (stat(path, &st) == 0) {
        if (st.st_size != (off_t)len) {
            fprintf(stderr, "Hash collision detected for %s\n", chunk_hash);
            return 0;
        }
        // File exists with expected size: ensure DB row and return
        sqlite3_stmt *stchk;
        if (sqlite3_prepare_v2(db,
            "INSERT OR IGNORE INTO chunks(hash,size) VALUES(?,?);",
            -1, &stchk, NULL) == SQLITE_OK)
        {
            sqlite3_bind_text(stchk, 1, chunk_hash, -1, SQLITE_STATIC);
            sqlite3_bind_int64(stchk, 2, (sqlite3_int64)len);
            sqlite3_step(stchk);
            sqlite3_finalize(stchk);
        }
        return 1;
    }

    // Write new file atomically
    if (!safe_write_file_atomic(CHUNK_DIR, chunk_hash, data, len)) {
        perror("chunk atomic write");
        return 0;
    }

    // Record chunk in DB
    sqlite3_stmt *stins;
    if (sqlite3_prepare_v2(db,
        "INSERT OR IGNORE INTO chunks(hash,size) VALUES(?,?);",
        -1, &stins, NULL) == SQLITE_OK)
    {
        sqlite3_bind_text(stins, 1, chunk_hash, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stins, 2, (sqlite3_int64)len);
        sqlite3_step(stins);
        sqlite3_finalize(stins);
    }

    return 1;
}

void map_chunk(sqlite3* db, long version_id, int seq, const char* chunk_hash) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO version_chunks(version_id,seq,chunk_hash) VALUES(?,?,?);",
        -1, &st, NULL) == SQLITE_OK)
    {
        sqlite3_bind_int64(st, 1, version_id);
        sqlite3_bind_int(st, 2, seq);
        sqlite3_bind_text(st, 3, chunk_hash, -1, SQLITE_STATIC);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }
}

/* Store a chunk, map it to version. Returns 1 on success. */
int flush_chunk(sqlite3 *db, const unsigned char *data,
                size_t len, long version_id, int *seq)
{
    if (len == 0) return 1;  // nothing to do

    // 1) compress
    unsigned char *cdata = NULL; size_t clen = 0;
    if (compress_buffer(data, len, &cdata, &clen) != 0) return 0;

    // 2) encrypt
    char key_path[PATH_MAX], iv_path[PATH_MAX];
    snprintf(key_path, sizeof key_path, "%s/.temporalfs/key", getenv("HOME"));
    snprintf(iv_path, sizeof iv_path, "%s/.temporalfs/iv", getenv("HOME"));

    FILE *fk = fopen(key_path, "rb");
    FILE *fi = fopen(iv_path, "rb");
    if (!fk || !fi) {
        perror("key/iv");
        if (fk) fclose(fk);
        if (fi) fclose(fi);
        free(cdata);
        return 0;
    }

    unsigned char key[32], iv[16];
    if (fread(key,1,32,fk) != 32 || fread(iv,1,16,fi) != 16) {
        fprintf(stderr, "key/iv read short\n");
        fclose(fk); fclose(fi); free(cdata);
        return 0;
    }
    fclose(fk); fclose(fi);

    if (clen > INT_MAX) {
        fprintf(stderr,"chunk too large\n");
        free(cdata);
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(cdata); return 0; }

    int blk = EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char *edata = malloc((int)clen + blk);
    if (!edata) { EVP_CIPHER_CTX_free(ctx); free(cdata); return 0; }

    int out1 = 0, out2 = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, edata, &out1, cdata, (int)clen) != 1 ||
        EVP_EncryptFinal_ex(ctx, edata + out1, &out2) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(cdata); free(edata);
        return 0;
    }
    int total = out1 + out2;

    EVP_CIPHER_CTX_free(ctx);
    free(cdata);

    // 3) hash the encrypted data for content address
    unsigned char h_raw[32]; char h_hex[65];
    SHA256_CTX hctx;
    SHA256_Init(&hctx);
    SHA256_Update(&hctx, edata, total);
    SHA256_Final(h_raw, &hctx);
    for (int i = 0; i < 32; i++)
        sprintf(h_hex + 2*i, "%02x", h_raw[i]);
    h_hex[64] = '\0';

    // 4) ensure chunk persisted (atomic) and recorded
    if (!ensure_chunk(db, h_hex, edata, (size_t)total)) {
        free(edata);
        return 0;
    }

    // 5) link to version
    if (version_id > 0)
        map_chunk(db, version_id, (*seq)++, h_hex);

    free(edata);
    return 1;
}
