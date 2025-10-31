#ifndef CHUNKER_H
#define CHUNKER_H

#include <sqlite3.h>
#include <stddef.h>
#include <stdio.h>

// Hashing and chunking interface
void sha256_bytes(const unsigned char *data, size_t len, char out_hex[65]);
off_t file_size(const char *path);
void hash_file(const char *path, char out_hex[65], long *out_size);
void chunk_file(sqlite3 *db, const char *path, long version_id);

#endif