#ifndef MAINTENANCE_H
#define MAINTENANCE_H
    int restore_file(const char *path, long version_id);
    int list_versions(const char *path);
    int prune_chunks(void);
#endif