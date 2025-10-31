// verify.c — verify stored data integrity
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "codec.h"

#define META_DIR  "/home/s3v3red/Documents/.temporalfs"
#define DB_PATH   "/home/s3v3red/Documents/.temporalfs/temporal.db"
#define CHUNK_DIR "/home/s3v3red/Documents/.temporalfs/chunks"

int verify_stored(const char *path, long version_id) {
    sqlite3 *db;
    if (sqlite3_open(DB_PATH, &db)) {
        fprintf(stderr, "DB open: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    // Resolve latest version if not specified
    if (version_id < 0) {
        sqlite3_stmt *vs;
        if (sqlite3_prepare_v2(db,
            "SELECT id FROM versions WHERE path=? ORDER BY id DESC LIMIT 1;",
            -1, &vs, NULL) == SQLITE_OK) {
            sqlite3_bind_text(vs, 1, path, -1, SQLITE_STATIC);
            if (sqlite3_step(vs) == SQLITE_ROW)
                version_id = sqlite3_column_int64(vs, 0);
            sqlite3_finalize(vs);
        }
    }

    if (version_id < 0) {
        fprintf(stderr, "No version found for %s\n", path);
        sqlite3_close(db);
        return 1;
    }

    // Get expected file hash
    char expected[65] = {0};
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db,
        "SELECT hash FROM versions WHERE id=?;", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, version_id);
        if (sqlite3_step(st) == SQLITE_ROW)
            strncpy(expected, (const char*)sqlite3_column_text(st, 0), 64);
        sqlite3_finalize(st);
    }
    if (!*expected) {
        fprintf(stderr, "Version %ld not found.\n", version_id);
        sqlite3_close(db);
        return 1;
    }

    // Prepare key/iv
    char key_path[4096], iv_path[4096];
    snprintf(key_path, sizeof key_path, "%s/.temporalfs/key", getenv("HOME"));
    snprintf(iv_path, sizeof iv_path, "%s/.temporalfs/iv", getenv("HOME"));
    FILE *fk = fopen(key_path, "rb");
    FILE *fi = fopen(iv_path, "rb");
    if (!fk || !fi) { perror("key/iv"); sqlite3_close(db); return 1; }
    unsigned char key[32], iv[16];
    fread(key,1,32,fk); fread(iv,1,16,fi);
    fclose(fk); fclose(fi);

    // Aggregate all chunks → decrypt + decompress + hash
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    if (sqlite3_prepare_v2(db,
        "SELECT chunk_hash FROM version_chunks WHERE version_id=? ORDER BY seq;",
        -1, &st, NULL) == SQLITE_OK)
    {
        sqlite3_bind_int64(st, 1, version_id);

        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *chunk_hash = (const char*)sqlite3_column_text(st, 0);
            char chunk_path[4096];
            snprintf(chunk_path, sizeof chunk_path, "%s/%s", CHUNK_DIR, chunk_hash);
            FILE *chunk = fopen(chunk_path, "rb");
            if (!chunk) { fprintf(stderr, "Missing chunk %s\n", chunk_hash); continue; }

            fseek(chunk, 0, SEEK_END);
            long sz = ftell(chunk);
            fseek(chunk, 0, SEEK_SET);
            unsigned char *edata = malloc(sz);
            fread(edata, 1, sz, chunk);
            fclose(chunk);

            // decrypt
            EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
            unsigned char *cdata = malloc(sz);
            int len_out = 0, total = 0;
            EVP_DecryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, key, iv);
            EVP_DecryptUpdate(ectx, cdata, &len_out, edata, sz);
            total = len_out;
            EVP_DecryptFinal_ex(ectx, cdata + len_out, &len_out);
            total += len_out;
            EVP_CIPHER_CTX_free(ectx);
            free(edata);

            // decompress
            unsigned char *rdata = NULL; size_t rlen = 0;
            if (decompress_buffer(cdata, total, &rdata, &rlen) != 0) {
                fprintf(stderr, "Decompress fail for %s\n", chunk_hash);
                free(cdata);
                continue;
            }
            free(cdata);

            SHA256_Update(&ctx, rdata, rlen);
            free(rdata);
        }
        sqlite3_finalize(st);
    }

    unsigned char final[SHA256_DIGEST_LENGTH];
    SHA256_Final(final, &ctx);
    char actual[65];
    for (int i = 0; i < 32; i++) sprintf(actual + 2*i, "%02x", final[i]);
    actual[64] = '\0';

    printf("Expected: %s\n", expected);
    printf("Actual:   %s\n", actual);
    printf(strcmp(expected, actual) == 0 ? "MATCH ✅\n" : "MISMATCH ❌\n");

    sqlite3_close(db);
    return 0;
}
