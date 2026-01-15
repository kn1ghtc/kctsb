/**
 * @file blake2.h
 * @brief BLAKE2 hash function implementation header
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * BLAKE2 is a cryptographic hash function designed as an improvement over BLAKE.
 * This implementation supports BLAKE2b (512-bit) and BLAKE2s (256-bit).
 * 
 * Reference: RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
 */

#ifndef KCTSB_BLAKE2_H
#define KCTSB_BLAKE2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BLAKE2b constants */
#define BLAKE2B_BLOCKBYTES  128
#define BLAKE2B_OUTBYTES    64
#define BLAKE2B_KEYBYTES    64

/* BLAKE2s constants */
#define BLAKE2S_BLOCKBYTES  64
#define BLAKE2S_OUTBYTES    32
#define BLAKE2S_KEYBYTES    32

/**
 * @brief BLAKE2b context structure
 */
typedef struct {
    uint64_t h[8];                      /**< State */
    uint64_t t[2];                      /**< Counter */
    uint64_t f[2];                      /**< Finalization flags */
    uint8_t  buf[BLAKE2B_BLOCKBYTES];   /**< Buffer */
    size_t   buflen;                    /**< Buffer length */
    size_t   outlen;                    /**< Output length */
} blake2b_ctx_t;

/**
 * @brief BLAKE2s context structure
 */
typedef struct {
    uint32_t h[8];                      /**< State */
    uint32_t t[2];                      /**< Counter */
    uint32_t f[2];                      /**< Finalization flags */
    uint8_t  buf[BLAKE2S_BLOCKBYTES];   /**< Buffer */
    size_t   buflen;                    /**< Buffer length */
    size_t   outlen;                    /**< Output length */
} blake2s_ctx_t;

/* BLAKE2b API */

/**
 * @brief Initialize BLAKE2b context
 * @param ctx Context to initialize
 * @param outlen Desired output length (1-64 bytes)
 * @return 0 on success, -1 on error
 */
int blake2b_init(blake2b_ctx_t *ctx, size_t outlen);

/**
 * @brief Initialize BLAKE2b with a key
 * @param ctx Context to initialize
 * @param outlen Desired output length (1-64 bytes)
 * @param key Key data
 * @param keylen Key length (0-64 bytes)
 * @return 0 on success, -1 on error
 */
int blake2b_init_key(blake2b_ctx_t *ctx, size_t outlen, const void *key, size_t keylen);

/**
 * @brief Update BLAKE2b with more data
 * @param ctx Initialized context
 * @param in Input data
 * @param inlen Input length
 * @return 0 on success, -1 on error
 */
int blake2b_update(blake2b_ctx_t *ctx, const void *in, size_t inlen);

/**
 * @brief Finalize BLAKE2b and output hash
 * @param ctx Context
 * @param out Output buffer
 * @param outlen Output length
 * @return 0 on success, -1 on error
 */
int blake2b_final(blake2b_ctx_t *ctx, void *out, size_t outlen);

/**
 * @brief One-shot BLAKE2b hash
 * @param out Output buffer
 * @param outlen Desired output length
 * @param in Input data
 * @param inlen Input length
 * @param key Optional key (NULL for no key)
 * @param keylen Key length
 * @return 0 on success, -1 on error
 */
int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen);

/* BLAKE2s API */

/**
 * @brief Initialize BLAKE2s context
 * @param ctx Context to initialize
 * @param outlen Desired output length (1-32 bytes)
 * @return 0 on success, -1 on error
 */
int blake2s_init(blake2s_ctx_t *ctx, size_t outlen);

/**
 * @brief Initialize BLAKE2s with a key
 * @param ctx Context to initialize
 * @param outlen Desired output length (1-32 bytes)
 * @param key Key data
 * @param keylen Key length (0-32 bytes)
 * @return 0 on success, -1 on error
 */
int blake2s_init_key(blake2s_ctx_t *ctx, size_t outlen, const void *key, size_t keylen);

/**
 * @brief Update BLAKE2s with more data
 * @param ctx Initialized context
 * @param in Input data
 * @param inlen Input length
 * @return 0 on success, -1 on error
 */
int blake2s_update(blake2s_ctx_t *ctx, const void *in, size_t inlen);

/**
 * @brief Finalize BLAKE2s and output hash
 * @param ctx Context
 * @param out Output buffer
 * @param outlen Output length
 * @return 0 on success, -1 on error
 */
int blake2s_final(blake2s_ctx_t *ctx, void *out, size_t outlen);

/**
 * @brief One-shot BLAKE2s hash
 * @param out Output buffer
 * @param outlen Desired output length
 * @param in Input data
 * @param inlen Input length
 * @param key Optional key (NULL for no key)
 * @param keylen Key length
 * @return 0 on success, -1 on error
 */
int blake2s(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_BLAKE2_H */
