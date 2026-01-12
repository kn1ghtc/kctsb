/**
 * @file whitebox_aes.h
 * @brief White-box AES implementation header
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * This is a simplified white-box AES implementation for educational purposes.
 * White-box cryptography aims to protect cryptographic keys in untrusted environments
 * by embedding the key into lookup tables.
 * 
 * Note: This implementation does not include full protection against all known attacks.
 */

#ifndef KCTSB_WHITEBOX_AES_H
#define KCTSB_WHITEBOX_AES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Type definitions */
typedef uint8_t u8;
typedef uint32_t u32;

/**
 * @brief White-box AES context structure
 */
typedef struct {
    u8 TBoxes[10][16][256];      /**< T-Box lookup tables */
    u32 TyiBoxes[9][16][256];    /**< Tyi-Box lookup tables */
    u32 TyiTables[4][256];       /**< Tyi multiplication tables */
    u8 xorTable[9][96][16][16];  /**< XOR tables for obfuscation */
    int initialized;             /**< Initialization flag */
} wbox_aes_ctx_t;

/**
 * @brief Initialize white-box AES context with a key
 * @param ctx White-box context to initialize
 * @param key 128-bit AES key
 * @return 0 on success, negative on error
 */
int wbox_aes_init(wbox_aes_ctx_t *ctx, const u8 key[16]);

/**
 * @brief Encrypt a single 16-byte block using white-box AES
 * @param ctx Initialized white-box context
 * @param input 16-byte plaintext block
 * @param output 16-byte ciphertext block
 * @return 0 on success, negative on error
 */
int wbox_aes_encrypt(const wbox_aes_ctx_t *ctx, const u8 input[16], u8 output[16]);

/**
 * @brief Clean up white-box AES context
 * @param ctx Context to clean up
 */
void wbox_aes_cleanup(wbox_aes_ctx_t *ctx);

/**
 * @brief Generate white-box tables from a key (internal use)
 * @param ctx Context to store generated tables
 * @param key 128-bit AES key
 */
void wbox_generate_tables(wbox_aes_ctx_t *ctx, const u8 key[16]);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_WHITEBOX_AES_H */
