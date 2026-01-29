/**
 * @file whitebox_aes.h
 * @brief Chow White-box AES-128 Implementation
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * Single-file Chow et al. white-box AES (SAC 2002):
 * - T-box lookup tables encoding SubBytes + MixColumns + RoundKey
 * - OpenSSL-style optimization for performance
 * - Educational implementation demonstrating white-box concepts
 * 
 * Security Notice:
 * This implementation provides basic white-box protection but is vulnerable to:
 * - Statistical analysis attacks (needs external encodings)
 * - Differential Computation Analysis (DCA)
 * - Affine equivalence attacks
 * 
 * For production use, add:
 * - Input/output bijective encodings
 * - External encodings between rounds
 * - Random mixing bijections
 */

#ifndef KCTSB_WHITEBOX_AES_H
#define KCTSB_WHITEBOX_AES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief White-box AES context structure (opaque)
 * 
 * Internal C++ implementation is hidden via void pointer.
 * Actual T-boxes and round keys are managed in chow_whitebox_aes.cpp.
 */
typedef struct {
    void* internal_ctx;    /**< Pointer to C++ ChowAESContext */
    int initialized;       /**< Initialization flag */
} wbox_aes_ctx_t;

/**
 * @brief Initialize white-box AES context with 128-bit key
 * @param ctx White-box context to initialize (must be non-NULL)
 * @param key 16-byte AES-128 key
 * @return 0 on success, negative on error
 */
int wbox_aes_init(wbox_aes_ctx_t *ctx, const uint8_t key[16]);

/**
 * @brief Encrypt a single 16-byte block using white-box T-boxes
 * @param ctx Initialized white-box context
 * @param input 16-byte plaintext block
 * @param output 16-byte ciphertext block
 * @return 0 on success, negative on error
 */
int wbox_aes_encrypt(wbox_aes_ctx_t *ctx, const uint8_t input[16], uint8_t output[16]);

/**
 * @brief Cleanup white-box AES context
 * @param ctx Context to cleanup
 */
void wbox_aes_cleanup(wbox_aes_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif  // KCTSB_WHITEBOX_AES_H
