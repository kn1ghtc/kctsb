/**
 * @file blake2.h
 * @brief BLAKE2 Hash Algorithm - Public C API
 *
 * RFC 7693 compliant BLAKE2b implementation.
 * Features:
 * - BLAKE2b (64-bit optimized, up to 64 bytes output)
 * - Keyed hashing (MAC) support
 * - SIMD acceleration on supported CPUs
 *
 * @note BLAKE2s has been removed. Use BLAKE2b exclusively.
 *
 * @author knightc
 * @version 3.4.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_BLAKE2_H
#define KCTSB_CRYPTO_BLAKE2_H

#include "kctsb/core/common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants (BLAKE2b only)
// ============================================================================

/** BLAKE2b maximum output size in bytes */
#define KCTSB_BLAKE2B_OUTBYTES 64

/** BLAKE2b block size in bytes */
#define KCTSB_BLAKE2B_BLOCKBYTES 128

/** BLAKE2b maximum key size in bytes */
#define KCTSB_BLAKE2B_KEYBYTES 64

// ============================================================================
// Types (with guard for kctsb_api.h inclusion)
// ============================================================================

/**
 * @brief BLAKE2b context structure
 */
#ifndef KCTSB_BLAKE2B_CTX_DEFINED
#define KCTSB_BLAKE2B_CTX_DEFINED
typedef struct kctsb_blake2b_ctx_s {
    uint64_t h[8];              /**< Hash state */
    uint64_t t[2];              /**< Total bytes counter */
    uint64_t f[2];              /**< Finalization flags */
    uint8_t buf[128];           /**< Block buffer */
    size_t buflen;              /**< Current buffer length */
    size_t outlen;              /**< Output length */
} kctsb_blake2b_ctx_t;
#endif

// ============================================================================
// BLAKE2b C API Functions
// ============================================================================

/**
 * @brief Initialize BLAKE2b context
 * @param ctx Context to initialize
 * @param outlen Output length in bytes (1-64)
 */
KCTSB_API void kctsb_blake2b_init(kctsb_blake2b_ctx_t* ctx, size_t outlen);

/**
 * @brief Initialize BLAKE2b context with key (for MAC)
 * @param ctx Context to initialize
 * @param outlen Output length in bytes (1-64)
 * @param key Key data
 * @param keylen Key length in bytes (1-64)
 */
KCTSB_API void kctsb_blake2b_init_key(kctsb_blake2b_ctx_t* ctx, size_t outlen,
                                       const uint8_t* key, size_t keylen);

/**
 * @brief Update BLAKE2b context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length in bytes
 */
KCTSB_API void kctsb_blake2b_update(kctsb_blake2b_ctx_t* ctx,
                                     const uint8_t* data, size_t len);

/**
 * @brief Finalize BLAKE2b and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest Output buffer (outlen bytes)
 */
KCTSB_API void kctsb_blake2b_final(kctsb_blake2b_ctx_t* ctx,
                                    uint8_t* digest);

/**
 * @brief Compute BLAKE2b hash in one call
 * @param data Input data
 * @param len Input length in bytes
 * @param digest Output buffer
 * @param outlen Output length in bytes (1-64)
 */
KCTSB_API void kctsb_blake2b(const uint8_t* data, size_t len,
                              uint8_t* digest, size_t outlen);

/**
 * @brief Securely clear BLAKE2b context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_blake2b_clear(kctsb_blake2b_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_BLAKE2_H
