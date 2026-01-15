/**
 * @file sha3.h
 * @brief SHA3 (Keccak) Hash Algorithm - Public C API
 *
 * FIPS 202 compliant SHA3 implementation with AVX2 acceleration.
 * Features:
 * - SHA3-224/256/384/512 hash functions
 * - SHAKE128/256 extendable output functions
 * - AVX2 SIMD acceleration on supported CPUs
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_SHA3_H
#define KCTSB_CRYPTO_SHA3_H

#include "kctsb/core/common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

/** SHA3-256 digest size in bytes */
#define KCTSB_SHA3_256_DIGEST_SIZE 32

/** SHA3-512 digest size in bytes */
#define KCTSB_SHA3_512_DIGEST_SIZE 64

/** SHA3-224 digest size in bytes */
#define KCTSB_SHA3_224_DIGEST_SIZE 28

/** SHA3-384 digest size in bytes */
#define KCTSB_SHA3_384_DIGEST_SIZE 48

/** Keccak state size in bytes (1600 bits) */
#define KCTSB_KECCAK_STATE_SIZE 200

// ============================================================================
// Types
// ============================================================================

/**
 * @brief SHA3/Keccak context structure
 */
typedef struct kctsb_sha3_ctx_s {
    alignas(32) uint64_t state[25];  /**< Keccak state (1600 bits) */
    size_t rate;                      /**< Rate in bytes */
    size_t capacity;                  /**< Capacity in bytes */
    size_t absorbed;                  /**< Bytes absorbed in current block */
    uint8_t suffix;                   /**< Domain separation suffix */
    size_t digest_size;               /**< Output digest size */
} kctsb_sha3_ctx_t;

// ============================================================================
// SHA3-256 C API Functions
// ============================================================================

/**
 * @brief Initialize SHA3-256 context
 * @param ctx Context to initialize
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256_init(kctsb_sha3_ctx_t* ctx);

/**
 * @brief Update SHA3-256 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length in bytes
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256_update(kctsb_sha3_ctx_t* ctx,
                                               const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA3-256 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest Output buffer (32 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256_final(kctsb_sha3_ctx_t* ctx,
                                              uint8_t digest[KCTSB_SHA3_256_DIGEST_SIZE]);

/**
 * @brief Compute SHA3-256 hash in one call
 * @param data Input data
 * @param len Input length in bytes
 * @param digest Output buffer (32 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256(const uint8_t* data, size_t len,
                                        uint8_t digest[KCTSB_SHA3_256_DIGEST_SIZE]);

// ============================================================================
// SHA3-512 C API Functions
// ============================================================================

/**
 * @brief Initialize SHA3-512 context
 * @param ctx Context to initialize
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_512_init(kctsb_sha3_ctx_t* ctx);

/**
 * @brief Update SHA3-512 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length in bytes
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_512_update(kctsb_sha3_ctx_t* ctx,
                                               const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA3-512 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest Output buffer (64 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_512_final(kctsb_sha3_ctx_t* ctx,
                                              uint8_t digest[KCTSB_SHA3_512_DIGEST_SIZE]);

/**
 * @brief Compute SHA3-512 hash in one call
 * @param data Input data
 * @param len Input length in bytes
 * @param digest Output buffer (64 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_512(const uint8_t* data, size_t len,
                                        uint8_t digest[KCTSB_SHA3_512_DIGEST_SIZE]);

// ============================================================================
// SHAKE Extendable Output Functions
// ============================================================================

/**
 * @brief Compute SHAKE128 with specified output length
 * @param data Input data
 * @param len Input length in bytes
 * @param output Output buffer
 * @param output_len Desired output length in bytes
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_shake128(const uint8_t* data, size_t len,
                                        uint8_t* output, size_t output_len);

/**
 * @brief Compute SHAKE256 with specified output length
 * @param data Input data
 * @param len Input length in bytes
 * @param output Output buffer
 * @param output_len Desired output length in bytes
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_shake256(const uint8_t* data, size_t len,
                                        uint8_t* output, size_t output_len);

/**
 * @brief Securely clear SHA3 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha3_clear(kctsb_sha3_ctx_t* ctx);

// ============================================================================
// Legacy compatibility (FIPS 202 names)
// ============================================================================

/** Legacy function name for compatibility */
#define FIPS202_SHA3_256(data, len, digest) kctsb_sha3_256(data, len, digest)
#define FIPS202_SHA3_512(data, len, digest) kctsb_sha3_512(data, len, digest)

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_SHA3_H
