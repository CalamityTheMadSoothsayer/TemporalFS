#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Compress a memory buffer
int compress_buffer(const unsigned char *input, size_t in_len,
                    unsigned char **out, size_t *out_len) {
    uLongf bound = compressBound(in_len);
    *out = malloc(bound);
    if (!*out) return -1;

    if (compress2(*out, &bound, input, in_len, Z_BEST_COMPRESSION) != Z_OK) {
        free(*out);
        return -1;
    }

    *out_len = bound;
    return 0;
}

// Decompress a memory buffer
int decompress_buffer(const unsigned char *input, size_t in_len,
                      unsigned char **out, size_t *out_len) {
    uLongf alloc = in_len * 4; // start guess
    *out = malloc(alloc);
    if (!*out) return -1;

    int res = uncompress(*out, &alloc, input, in_len);
    if (res == Z_BUF_ERROR) {  // output too small → resize and retry
        free(*out);
        alloc = in_len * 10;
        *out = malloc(alloc);
        if (!*out) return -1;
        res = uncompress(*out, &alloc, input, in_len);
    }

    if (res != Z_OK) {
        free(*out);
        return -1;
    }

    *out_len = alloc;
    return 0;
}

// Encrypt buffer with AES-256-CBC
int encrypt_buffer(const unsigned char *input, size_t in_len,
                   unsigned char **out, size_t *out_len,
                   const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, ciphertext_len;
    *out = malloc(in_len + EVP_MAX_BLOCK_LENGTH);
    if (!*out) { EVP_CIPHER_CTX_free(ctx); return -1; }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, *out, &len, input, in_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, *out + len, &len);
    ciphertext_len += len;

    *out_len = ciphertext_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Decrypt buffer with AES-256-CBC
int decrypt_buffer(const unsigned char *input, size_t in_len,
                   unsigned char **out, size_t *out_len,
                   const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len, plaintext_len;
    *out = malloc(in_len);
    if (!*out) { EVP_CIPHER_CTX_free(ctx); return -1; }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, *out, &len, input, in_len);
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, *out + len, &len) <= 0) {
        free(*out);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    *out_len = plaintext_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}