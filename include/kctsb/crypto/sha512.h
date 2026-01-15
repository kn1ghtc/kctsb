/**
 * @file sha512.h
 * @brief SHA-512/384 Hash Algorithm - Public C API
 *
 * FIPS 180-4 compliant SHA-512 and SHA-384 implementation.
 * Features:
 * - Incremental hashing API (init/update/final)
 * - One-shot API for convenience
 * - SHA-384 variant support (uses same core)
 *
 * @author knightc
 * @version 3.4.0
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

/** SHA-384 digest size in bytes */
#define KCTSB_SHA384_DIGEST_SIZE 48

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

/** SHA-384 uses same context as SHA-512 */
typedef kctsb_sha512_ctx_t kctsb_sha384_ctx_t;

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

// ============================================================================
// SHA-384 C API Functions
// ============================================================================

/**
 * @brief Initialize SHA-384 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sha384_init(kctsb_sha384_ctx_t* ctx);

/**
 * @brief Update SHA-384 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length in bytes
 */
KCTSB_API void kctsb_sha384_update(kctsb_sha384_ctx_t* ctx,
                                    const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-384 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest Output buffer (48 bytes)
 */
KCTSB_API void kctsb_sha384_final(kctsb_sha384_ctx_t* ctx,
                                   uint8_t digest[KCTSB_SHA384_DIGEST_SIZE]);

/**
 * @brief Compute SHA-384 hash in one call
 * @param data Input data
 * @param len Input length in bytes
 * @param digest Output buffer (48 bytes)
 */
KCTSB_API void kctsb_sha384(const uint8_t* data, size_t len,
                             uint8_t digest[KCTSB_SHA384_DIGEST_SIZE]);

/**
 * @brief Securely clear SHA-384 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha384_clear(kctsb_sha384_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_SHA512_H
