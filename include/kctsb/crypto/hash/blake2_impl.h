/**
 * @file blake2_impl.h
 * @brief BLAKE2 hash function implementation header (for internal/test use)
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * BLAKE2 is a cryptographic hash function designed as an improvement over BLAKE.
 * This implementation supports BLAKE2b (512-bit) and BLAKE2s (256-bit).
 * 
 * Reference: RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
 * 
 * NOTE: Internal implementation types and functions. For public API, use kctsb/crypto/blake.h
 *       The internal functions are prefixed with kctsb_ to avoid symbol conflicts with SEAL.
 */

#ifndef KCTSB_BLAKE2_IMPL_H
#define KCTSB_BLAKE2_IMPL_H

#include <stdint.h>
#include <stddef.h>
#include "kctsb/crypto/blake.h"

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

/* Type aliases for compatibility */
typedef kctsb_blake2b_ctx_t blake2b_ctx_t;
typedef kctsb_blake2s_ctx_t blake2s_ctx_t;

/* Extended keyed initialization - requires internal implementation */
KCTSB_API int kctsb_blake2b_init_key_extended(kctsb_blake2b_ctx_t *ctx, size_t outlen, 
                                               const void *key, size_t keylen);

/* ============================================================================
 * Inline wrapper functions for BLAKE2b (avoiding SEAL symbol conflict)
 * ============================================================================ */

static inline int blake2b_init(blake2b_ctx_t *ctx, size_t outlen) {
    kctsb_blake2b_init(ctx, outlen);
    return 0;
}

static inline int blake2b_init_key(blake2b_ctx_t *ctx, size_t outlen, 
                                    const void *key, size_t keylen) {
    return kctsb_blake2b_init_key_extended(ctx, outlen, key, keylen);
}

static inline int blake2b_update(blake2b_ctx_t *ctx, const void *in, size_t inlen) {
    kctsb_blake2b_update(ctx, (const uint8_t*)in, inlen);
    return 0;
}

static inline int blake2b_final(blake2b_ctx_t *ctx, void *out, size_t outlen) {
    (void)outlen;  /* Ignored, ctx->outlen is used */
    kctsb_blake2b_final(ctx, (uint8_t*)out);
    return 0;
}

static inline int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
                          const void *key, size_t keylen) {
    (void)key;
    (void)keylen;
    kctsb_blake2b((const uint8_t*)in, inlen, (uint8_t*)out, outlen);
    return 0;
}

/* ============================================================================
 * BLAKE2s API wrappers (public implementation)
 * ============================================================================ */

static inline int blake2s_init(blake2s_ctx_t *ctx, size_t outlen) {
    kctsb_blake2s_init(ctx, outlen);
    return 0;
}

static inline int blake2s_update(blake2s_ctx_t *ctx, const void *in, size_t inlen) {
    kctsb_blake2s_update(ctx, (const uint8_t*)in, inlen);
    return 0;
}

static inline int blake2s_final(blake2s_ctx_t *ctx, void *out, size_t outlen) {
    (void)outlen;
    kctsb_blake2s_final(ctx, (uint8_t*)out);
    return 0;
}

static inline int blake2s(void *out, size_t outlen, const void *in, size_t inlen,
                          const void *key, size_t keylen) {
    (void)key;
    (void)keylen;
    kctsb_blake2s((const uint8_t*)in, inlen, (uint8_t*)out, outlen);
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_BLAKE2_IMPL_H */
