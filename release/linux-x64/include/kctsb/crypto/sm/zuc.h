/**
 * @file zuc.h
 * @brief ZUC Stream Cipher - GB/T 33133
 *
 * ZUC is a Chinese stream cipher standardized for 4G/5G mobile security.
 * Provides EEA3 (confidentiality) and EIA3 (integrity) algorithms.
 *
 * C++ Core + C ABI Architecture (v3.4.0)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_ZUC_H
#define KCTSB_CRYPTO_ZUC_H

#include "kctsb/core/common.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief ZUC context structure
 */
typedef struct {
    void* internal;
} kctsb_zuc_ctx_t;

/**
 * @brief Initialize ZUC stream cipher
 * @param ctx Context to initialize
 * @param key 128-bit key (16 bytes)
 * @param iv 128-bit IV (16 bytes)
 */
KCTSB_API void kctsb_zuc_init(kctsb_zuc_ctx_t* ctx, const uint8_t key[16], const uint8_t iv[16]);

/**
 * @brief Generate ZUC keystream
 * @param ctx Initialized context
 * @param keystream Output buffer for 32-bit keystream words
 * @param len Number of 32-bit words to generate
 */
KCTSB_API void kctsb_zuc_generate(kctsb_zuc_ctx_t* ctx, uint32_t* keystream, size_t len);

/**
 * @brief Free ZUC context
 * @param ctx Context to free
 */
KCTSB_API void kctsb_zuc_free(kctsb_zuc_ctx_t* ctx);

/**
 * @brief ZUC-based Confidentiality Algorithm (128-EEA3)
 * @param ck 128-bit confidentiality key
 * @param count 32-bit COUNT
 * @param bearer 5-bit BEARER
 * @param direction 1-bit DIRECTION
 * @param ibs Input bit stream (as 32-bit words)
 * @param length Bit length of IBS
 * @param obs Output bit stream (as 32-bit words)
 */
KCTSB_API void kctsb_zuc_eea3(const uint8_t ck[16], uint32_t count, uint8_t bearer,
                              uint8_t direction, const uint32_t* ibs, int length, uint32_t* obs);

/**
 * @brief ZUC-based Integrity Algorithm (128-EIA3)
 * @param ik 128-bit integrity key
 * @param count 32-bit COUNT
 * @param bearer 5-bit BEARER
 * @param direction 1-bit DIRECTION
 * @param message Input message (as 32-bit words)
 * @param length Bit length of message
 * @return 32-bit MAC
 */
KCTSB_API uint32_t kctsb_zuc_eia3(const uint8_t ik[16], uint32_t count, uint8_t bearer,
                                  uint8_t direction, const uint32_t* message, int length);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_ZUC_H
