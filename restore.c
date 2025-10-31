// restore.c — rebuild file from stored chunks
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <limits.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "codec.h"

#define META_DIR  "/home/s3v3red/Documents/.temporalfs"
#define DB_PATH   "/home/s3v3red/Documents/.temporalfs/temporal.db"
#define CHUNK_DIR "/home/s3v3red/Documents/.temporalfs/chunks"

int restore_file(const char *path, long version_id) {
    sqlite3 *db;
    if (sqlite3_open(DB_PATH, &db)) {
        fprintf(stderr, "DB open: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    // Get expected file hash
    char expected[65] = {0};
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, "SELECT hash FROM versions WHERE id=?;", -1, &st, NULL) == SQLITE_OK) {
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

    // Open output file
    char outpath[PATH_MAX];
    snprintf(outpath, sizeof(outpath), "%s.restore", path);
    FILE *out = fopen(outpath, "wb");
    if (!out) {
        perror("restore open");
        sqlite3_close(db);
        return 1;
    }

    // Get and concatenate all chunks
    if (sqlite3_prepare_v2(db, "SELECT chunk_hash FROM version_chunks WHERE version_id=? ORDER BY seq;", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(st, 1, version_id);
        SHA256_CTX hashctx;
        SHA256_Init(&hashctx);


        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *chunk_hash = (const char*)sqlite3_column_text(st, 0);
            char chunk_path[PATH_MAX];
            snprintf(chunk_path,sizeof(chunk_path),"%s/%s",CHUNK_DIR,chunk_hash);
            FILE *chunk=fopen(chunk_path,"rb");
            if(!chunk){fprintf(stderr,"Missing chunk %s\n",chunk_hash);continue;}

            // --- read encrypted data ---
            fseek(chunk,0,SEEK_END);
            long sz=ftell(chunk);
            fseek(chunk,0,SEEK_SET);
            unsigned char *edata=malloc(sz);
            fread(edata,1,sz,chunk);
            fclose(chunk);

            // --- decrypt ---
            char key_path[PATH_MAX], iv_path[PATH_MAX];
            snprintf(key_path, sizeof key_path, "%s/.temporalfs/key", getenv("HOME"));
            snprintf(iv_path, sizeof iv_path, "%s/.temporalfs/iv", getenv("HOME"));

            FILE *fk = fopen(key_path, "rb");
            FILE *fi = fopen(iv_path, "rb");
            if (!fk || !fi) { perror("key/iv"); free(edata); if (fk) fclose(fk); if (fi) fclose(fi); continue; }
            unsigned char key[32], iv[16];
            if (fread(key,1,32,fk) != 32 || fread(iv,1,16,fi) != 16) {
                fprintf(stderr,"key/iv read short\n");
                free(edata); fclose(fk); fclose(fi); continue;
            }
            fclose(fk); fclose(fi);

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) { free(edata); continue; }

            if (sz > INT_MAX) { fprintf(stderr,"chunk too large\n"); EVP_CIPHER_CTX_free(ctx); free(edata); continue; }
            int in_len = (int)sz;

            unsigned char *cdata = malloc(in_len);   // decrypted compressed bytes
            if (!cdata) { EVP_CIPHER_CTX_free(ctx); free(edata); continue; }

            int out1 = 0, out2 = 0;
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ||
                EVP_DecryptUpdate(ctx, cdata, &out1, edata, in_len) != 1 ||
                EVP_DecryptFinal_ex(ctx, cdata + out1, &out2) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                free(edata);
                free(cdata);
                fprintf(stderr, "decrypt failed for chunk %s\n", chunk_hash);
                continue;
            }
            int total = out1 + out2;

            EVP_CIPHER_CTX_free(ctx);
            free(edata);

            // --- decompress ---
            unsigned char *rdata = NULL; size_t rlen = 0;
            if (decompress_buffer(cdata, total, &rdata, &rlen) != 0) { free(cdata); continue; }
            free(cdata);

            fwrite(rdata, 1, rlen, out);
            SHA256_Update(&hashctx, rdata, rlen);
            free(rdata);
        }

        sqlite3_finalize(st);

        unsigned char final[SHA256_DIGEST_LENGTH];
        SHA256_Final(final, &hashctx);
        char actual[65];
        for (int i = 0; i < 32; i++) sprintf(actual + 2*i, "%02x", final[i]);
        actual[64] = '\0';

        printf("Expected: %s\n", expected);
        printf("Actual:   %s\n", actual);
        printf(strcmp(expected, actual) == 0 ? "MATCH ✅\n" : "MISMATCH ❌\n");

        if (strcmp(expected, actual) == 0) {
            sqlite3_stmt *del1, *del2;

            // find path of restored version
            char pathbuf[PATH_MAX] = {0};
            if (sqlite3_prepare_v2(db, "SELECT path FROM versions WHERE id=?;", -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(st, 1, version_id);
                if (sqlite3_step(st) == SQLITE_ROW)
                    strncpy(pathbuf, (const char*)sqlite3_column_text(st, 0), sizeof(pathbuf)-1);
                sqlite3_finalize(st);
            }

            // delete newer versions
            if (*pathbuf) {
                sqlite3_prepare_v2(db,
                    "DELETE FROM version_chunks WHERE version_id IN "
                    "(SELECT id FROM versions WHERE path=? AND id>=?);",
                    -1, &del1, NULL);
                sqlite3_bind_text(del1, 1, pathbuf, -1, SQLITE_STATIC);
                sqlite3_bind_int64(del1, 2, version_id);
                sqlite3_step(del1);
                sqlite3_finalize(del1);

                sqlite3_prepare_v2(db,
                    "DELETE FROM versions WHERE path=? AND id>=?;",
                    -1, &del2, NULL);
                sqlite3_bind_text(del2, 1, pathbuf, -1, SQLITE_STATIC);
                sqlite3_bind_int64(del2, 2, version_id);
                sqlite3_step(del2);
                sqlite3_finalize(del2);
            }

            printf("Cleaned newer versions for %s\n", pathbuf);
        }
    }


    fclose(out);
    sqlite3_close(db);
    return 0;
}
