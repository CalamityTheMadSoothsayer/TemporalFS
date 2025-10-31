#ifndef VERIFY_H
#define VERIFY_H

// Verifies stored chunks for a specific file version directly from the database
int verify_stored(const char *path, long version_id);

#endif
