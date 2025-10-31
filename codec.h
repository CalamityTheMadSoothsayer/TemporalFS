#ifndef CODEC_H
#define CODEC_H
#include <stddef.h>

int compress_buffer(const unsigned char *input, size_t in_len,
                    unsigned char **out, size_t *out_len);
int decompress_buffer(const unsigned char *input, size_t in_len,
                      unsigned char **out, size_t *out_len);
int encrypt_buffer(const unsigned char *input, size_t in_len,
                   unsigned char **out, size_t *out_len,
                   const unsigned char *key, const unsigned char *iv);
int decrypt_buffer(const unsigned char *input, size_t in_len,
                   unsigned char **out, size_t *out_len,
                   const unsigned char *key, const unsigned char *iv);

#endif
