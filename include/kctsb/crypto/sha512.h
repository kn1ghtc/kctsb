/**
 * @file sha512.h
 * @brief SHA-512 Hash Algorithm - Public C API
 *
 * FIPS 180-4 compliant SHA-512 implementation.
 * Features:
 * - Incremental hashing API (init/update/final)
 * - One-shot API for convenience
 * - Multi-block processing for large data optimization
 *
 * Note: SHA-384 support removed in v3.4.1. Use SHA-256 or SHA-512.
 *
 * @author knightc
 * @version 3.4.1
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_SHA512_H
#define KCTSB_CRYPTO_SHA512_H

#include "kctsb/core/common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

/** SHA-512 digest size in bytes */
#define KCTSB_SHA512_DIGEST_SIZE 64

/** SHA-512 block size in bytes */
#define KCTSB_SHA512_BLOCK_SIZE 128

// ============================================================================
// Types
// ============================================================================

/**
 * @brief SHA-512 context structure
 */
typedef struct kctsb_sha512_ctx_s {
    uint64_t state[8];          /**< Hash state */
    uint64_t count[2];          /**< Total bytes processed (128-bit) */
    uint8_t buffer[128];        /**< Block buffer */
    size_t buflen;              /**< Current buffer length */
} kctsb_sha512_ctx_t;

// ============================================================================
// SHA-512 C API Functions
// ============================================================================

/**
 * @brief Initialize SHA-512 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sha512_init(kctsb_sha512_ctx_t* ctx);

/**
 * @brief Update SHA-512 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length in bytes
 */
KCTSB_API void kctsb_sha512_update(kctsb_sha512_ctx_t* ctx,
                                    const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-512 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest Output buffer (64 bytes)
 */
KCTSB_API void kctsb_sha512_final(kctsb_sha512_ctx_t* ctx,
                                   uint8_t digest[KCTSB_SHA512_DIGEST_SIZE]);

/**
 * @brief Compute SHA-512 hash in one call
 * @param data Input data
 * @param len Input length in bytes
 * @param digest Output buffer (64 bytes)
 */
KCTSB_API void kctsb_sha512(const uint8_t* data, size_t len,
                             uint8_t digest[KCTSB_SHA512_DIGEST_SIZE]);

/**
 * @brief Securely clear SHA-512 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha512_clear(kctsb_sha512_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_SHA512_H
