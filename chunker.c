#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include "buzhash_table.h"
#include "dbutils.h"
#include "chunker.h"

// Paths and constants
#define META_DIR   "/home/s3v3red/Documents/.temporalfs"
#define CHUNK_DIR  "/home/s3v3red/Documents/.temporalfs/chunks"
#define RH_WINDOW  64
#define AVG_SIZE   (1 << 20)
#define MIN_SIZE   (1 << 16)
#define MAX_SIZE   (1 << 23)
#define MASK       (AVG_SIZE - 1)

static inline unsigned int rol32(unsigned int x) { return (x << 1) | (x >> 31); }

// --- Helpers ---

void sha256_bytes(const unsigned char* data, size_t len, char out_hex[65]) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(h, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out_hex + 2*i, "%02x", h[i]);
    out_hex[64] = '\0';
}

off_t file_size(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 ? st.st_size : -1;
}

// --- File hashing (full SHA-256) ---

void hash_file(const char* path, char out_hex[65], long* out_size) {
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
    for (int i = 0; i < 32; i++)
        sprintf(out_hex + 2*i, "%02x", h[i]);
    out_hex[64] = '\0';
}

// --- Rolling-hash chunking ---

void chunk_file(sqlite3* db, const char* path, long version_id) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return;

    mkdir(META_DIR, 0755);
    mkdir(CHUNK_DIR, 0755);

    const size_t BUF = 65536;
    unsigned char *filebuf = malloc(BUF);
    unsigned char *chunkbuf = malloc(MAX_SIZE);
    unsigned int h = 0;
    unsigned char win[RH_WINDOW] = {0};
    size_t chunk_len = 0, wpos = 0, wfill = 0;
    int seq = 0;

    size_t r;
    while ((r = fread(filebuf, 1, BUF, fp)) > 0) {
        for (size_t i = 0; i < r; i++) {
            unsigned char b = filebuf[i];
            chunkbuf[chunk_len++] = b;

            unsigned char old = win[wpos];
            win[wpos] = b;
            wpos = (wpos + 1) % RH_WINDOW;
            if (wfill < RH_WINDOW) { h = rol32(h) ^ BUZHASH_T[b]; wfill++; }
            else { h = rol32(h) ^ BUZHASH_T[b] ^ BUZHASH_T[old]; }

            if (chunk_len >= MIN_SIZE && ((h & MASK) == 0 || chunk_len >= MAX_SIZE)) {
                flush_chunk(db, chunkbuf, chunk_len, version_id, &seq);
                chunk_len = 0;
            }
        }
    }
    if (chunk_len > 0)
        flush_chunk(db, chunkbuf, chunk_len, version_id, &seq);

    free(filebuf);
    free(chunkbuf);
    fclose(fp);
}
