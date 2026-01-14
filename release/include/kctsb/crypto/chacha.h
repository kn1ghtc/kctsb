/**
 * @file chacha.h
 * @brief ChaCha20 stream cipher
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_CHACHA_H
#define KCTSB_CRYPTO_CHACHA_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[16];
} kctsb_chacha20_ctx_t;

KCTSB_API void kctsb_chacha20_init(kctsb_chacha20_ctx_t* ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);
KCTSB_API void kctsb_chacha20_crypt(kctsb_chacha20_ctx_t* ctx, const uint8_t* in, size_t len, uint8_t* out);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_CHACHA_H
