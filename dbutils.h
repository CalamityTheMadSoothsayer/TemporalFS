#ifndef DB_UTILS_H
#define DB_UTILS_H
#include <sqlite3.h>
#include <stddef.h>

sqlite3* init_db(const char *db_path);
long log_version(sqlite3 *db, const char *path, const char *file_hash, long size);
int ensure_chunk(sqlite3* db, const char* chunk_hash, const unsigned char* data, size_t len);
void map_chunk(sqlite3* db, long version_id, int seq, const char* chunk_hash);
int flush_chunk(sqlite3 *db, const unsigned char *data, size_t len, long version_id, int *seq);

#endif