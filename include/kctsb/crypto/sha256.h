/**
 * @file sha256.h
 * @brief SHA-256 Hash Algorithm - Public C API
 *
 * FIPS 180-4 compliant SHA-256 implementation with hardware acceleration.
 * Features:
 * - SHA-NI hardware acceleration on supported CPUs
 * - Incremental hashing API (init/update/final)
 * - One-shot API for convenience
 *
 * @author knightc
 * @version 3.4.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_SHA256_H
#define KCTSB_CRYPTO_SHA256_H

#include "kctsb/core/common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

/** SHA-256 digest size in bytes */
#define KCTSB_SHA256_DIGEST_SIZE 32

/** SHA-256 block size in bytes */
#define KCTSB_SHA256_BLOCK_SIZE 64

// ============================================================================
// Types
// ============================================================================

/**
 * @brief SHA-256 context structure
 */
typedef struct kctsb_sha256_ctx_s {
    uint32_t state[8];          /**< Hash state */
    uint64_t count;             /**< Total bytes processed */
    uint8_t buffer[64];         /**< Block buffer */
    size_t buflen;              /**< Current buffer length */
} kctsb_sha256_ctx_t;

// ============================================================================
// C API Functions
// ============================================================================

/**
 * @brief Initialize SHA-256 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sha256_init(kctsb_sha256_ctx_t* ctx);

/**
 * @brief Update SHA-256 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length in bytes
 */
KCTSB_API void kctsb_sha256_update(kctsb_sha256_ctx_t* ctx,
                                    const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-256 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest Output buffer (32 bytes)
 */
KCTSB_API void kctsb_sha256_final(kctsb_sha256_ctx_t* ctx,
                                   uint8_t digest[KCTSB_SHA256_DIGEST_SIZE]);

/**
 * @brief Compute SHA-256 hash in one call
 * @param data Input data
 * @param len Input length in bytes
 * @param digest Output buffer (32 bytes)
 */
KCTSB_API void kctsb_sha256(const uint8_t* data, size_t len,
                             uint8_t digest[KCTSB_SHA256_DIGEST_SIZE]);

/**
 * @brief Securely clear SHA-256 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha256_clear(kctsb_sha256_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_SHA256_H
