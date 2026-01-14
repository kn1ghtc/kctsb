/**
 * @file mac.h
 * @brief Message Authentication Code algorithms
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_MAC_H
#define KCTSB_CRYPTO_MAC_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

// HMAC-SHA256
typedef struct {
    void* internal;
} kctsb_hmac_ctx_t;

KCTSB_API void kctsb_hmac_sha256_init(kctsb_hmac_ctx_t* ctx, const uint8_t* key, size_t key_len);
KCTSB_API void kctsb_hmac_sha256_update(kctsb_hmac_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_hmac_sha256_final(kctsb_hmac_ctx_t* ctx, uint8_t mac[32]);
KCTSB_API void kctsb_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t mac[32]);

// CMAC-AES
KCTSB_API void kctsb_cmac_aes(const uint8_t key[16], const uint8_t* data, size_t len, uint8_t mac[16]);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_MAC_H
