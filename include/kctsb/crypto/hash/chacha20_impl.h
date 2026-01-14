/**
 * @file chacha20.h
 * @brief ChaCha20 stream cipher implementation header
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * ChaCha20 is a high-speed stream cipher designed by Daniel J. Bernstein.
 * Reference: RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols
 */

#ifndef KCTSB_CHACHA20_H
#define KCTSB_CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA20_KEYSIZE    32
#define CHACHA20_NONCESIZE  12
#define CHACHA20_BLOCKSIZE  64

/**
 * @brief ChaCha20 context structure
 */
typedef struct {
    uint32_t state[16];     /**< Internal state */
    uint8_t keystream[64];  /**< Keystream buffer */
    size_t available;       /**< Available bytes in keystream */
    uint32_t counter;       /**< Block counter */
} chacha20_ctx_t;

/**
 * @brief Initialize ChaCha20 context
 * @param ctx Context to initialize
 * @param key 256-bit key
 * @param nonce 96-bit nonce
 * @param counter Initial counter value (usually 0 or 1)
 * @return 0 on success, -1 on error
 */
int chacha20_init(chacha20_ctx_t *ctx, const uint8_t key[32], 
                  const uint8_t nonce[12], uint32_t counter);

/**
 * @brief Encrypt/decrypt data with ChaCha20
 * @param ctx Initialized context
 * @param in Input data
 * @param out Output data (can be same as input)
 * @param len Data length
 * @return 0 on success, -1 on error
 */
int chacha20_crypt(chacha20_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len);

/**
 * @brief Generate keystream block
 * @param ctx Initialized context
 * @param out 64-byte output buffer
 */
void chacha20_block(chacha20_ctx_t *ctx, uint8_t out[64]);

/**
 * @brief One-shot ChaCha20 encryption/decryption
 * @param key 256-bit key
 * @param nonce 96-bit nonce
 * @param counter Initial counter
 * @param in Input data
 * @param out Output data
 * @param len Data length
 * @return 0 on success, -1 on error
 */
int chacha20(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
             const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_CHACHA20_H */
