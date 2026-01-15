/**
 * @file blake2.h
 * @brief BLAKE2 Hash Algorithm - Public C API
 *
 * RFC 7693 compliant BLAKE2b and BLAKE2s implementation.
 * Features:
 * - BLAKE2b (64-bit optimized, up to 64 bytes output)
 * - BLAKE2s (32-bit optimized, up to 32 bytes output)
 * - Keyed hashing (MAC) support
 * - SIMD acceleration on supported CPUs
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
// Constants
// ============================================================================

/** BLAKE2b maximum output size in bytes */
#define KCTSB_BLAKE2B_OUTBYTES 64

/** BLAKE2b block size in bytes */
#define KCTSB_BLAKE2B_BLOCKBYTES 128

/** BLAKE2b maximum key size in bytes */
#define KCTSB_BLAKE2B_KEYBYTES 64

/** BLAKE2s maximum output size in bytes */
#define KCTSB_BLAKE2S_OUTBYTES 32

/** BLAKE2s block size in bytes */
#define KCTSB_BLAKE2S_BLOCKBYTES 64

/** BLAKE2s maximum key size in bytes */
#define KCTSB_BLAKE2S_KEYBYTES 32

// ============================================================================
// Types
// ============================================================================

/**
 * @brief BLAKE2b context structure
 */
typedef struct kctsb_blake2b_ctx_s {
    uint64_t h[8];              /**< Hash state */
    uint64_t t[2];              /**< Total bytes counter */
    uint64_t f[2];              /**< Finalization flags */
    uint8_t buf[128];           /**< Block buffer */
    size_t buflen;              /**< Current buffer length */
    size_t outlen;              /**< Output length */
} kctsb_blake2b_ctx_t;

/**
 * @brief BLAKE2s context structure
 */
typedef struct kctsb_blake2s_ctx_s {
    uint32_t h[8];              /**< Hash state */
    uint32_t t[2];              /**< Total bytes counter */
    uint32_t f[2];              /**< Finalization flags */
    uint8_t buf[64];            /**< Block buffer */
    size_t buflen;              /**< Current buffer length */
    size_t outlen;              /**< Output length */
} kctsb_blake2s_ctx_t;

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

// ============================================================================
// BLAKE2s C API Functions
// ============================================================================

/**
 * @brief Initialize BLAKE2s context
 * @param ctx Context to initialize
 * @param outlen Output length in bytes (1-32)
 */
KCTSB_API void kctsb_blake2s_init(kctsb_blake2s_ctx_t* ctx, size_t outlen);

/**
 * @brief Initialize BLAKE2s context with key (for MAC)
 * @param ctx Context to initialize
 * @param outlen Output length in bytes (1-32)
 * @param key Key data
 * @param keylen Key length in bytes (1-32)
 */
KCTSB_API void kctsb_blake2s_init_key(kctsb_blake2s_ctx_t* ctx, size_t outlen,
                                       const uint8_t* key, size_t keylen);

/**
 * @brief Update BLAKE2s context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length in bytes
 */
KCTSB_API void kctsb_blake2s_update(kctsb_blake2s_ctx_t* ctx,
                                     const uint8_t* data, size_t len);

/**
 * @brief Finalize BLAKE2s and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest Output buffer (outlen bytes)
 */
KCTSB_API void kctsb_blake2s_final(kctsb_blake2s_ctx_t* ctx,
                                    uint8_t* digest);

/**
 * @brief Compute BLAKE2s hash in one call
 * @param data Input data
 * @param len Input length in bytes
 * @param digest Output buffer
 * @param outlen Output length in bytes (1-32)
 */
KCTSB_API void kctsb_blake2s(const uint8_t* data, size_t len,
                              uint8_t* digest, size_t outlen);

/**
 * @brief Securely clear BLAKE2s context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_blake2s_clear(kctsb_blake2s_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_BLAKE2_H
