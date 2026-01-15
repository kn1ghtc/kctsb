/**
 * @file mac.h
 * @brief Message Authentication Code Algorithms
 *
 * Provides HMAC, CMAC, and GMAC for message authentication.
 *
 * C++ Core + C ABI Architecture (v3.4.0)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_MAC_H
#define KCTSB_CRYPTO_MAC_H

#include "kctsb/core/common.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// HMAC-SHA256 (RFC 2104, FIPS 198-1)
// ============================================================================

typedef struct {
    void* internal;
} kctsb_hmac_ctx_t;

KCTSB_API void kctsb_hmac_sha256_init(kctsb_hmac_ctx_t* ctx, const uint8_t* key, size_t key_len);
KCTSB_API void kctsb_hmac_sha256_update(kctsb_hmac_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_hmac_sha256_final(kctsb_hmac_ctx_t* ctx, uint8_t mac[32]);
KCTSB_API void kctsb_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t mac[32]);

// ============================================================================
// HMAC-SHA512 (RFC 2104, FIPS 198-1)
// ============================================================================

typedef struct {
    void* internal;
} kctsb_hmac512_ctx_t;

KCTSB_API void kctsb_hmac_sha512_init(kctsb_hmac512_ctx_t* ctx, const uint8_t* key, size_t key_len);
KCTSB_API void kctsb_hmac_sha512_update(kctsb_hmac512_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_hmac_sha512_final(kctsb_hmac512_ctx_t* ctx, uint8_t mac[64]);
KCTSB_API void kctsb_hmac_sha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t mac[64]);

// ============================================================================
// CMAC-AES (NIST SP 800-38B)
// ============================================================================

typedef struct {
    void* internal;
} kctsb_cmac_ctx_t;

KCTSB_API void kctsb_cmac_aes_init(kctsb_cmac_ctx_t* ctx, const uint8_t key[16]);
KCTSB_API void kctsb_cmac_aes_update(kctsb_cmac_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_cmac_aes_final(kctsb_cmac_ctx_t* ctx, uint8_t mac[16]);
KCTSB_API void kctsb_cmac_aes(const uint8_t key[16], const uint8_t* data, size_t len, uint8_t mac[16]);

// ============================================================================
// GMAC (NIST SP 800-38D)
// ============================================================================

typedef struct {
    void* internal;
} kctsb_gmac_ctx_t;

KCTSB_API void kctsb_gmac_init(kctsb_gmac_ctx_t* ctx, const uint8_t key[16], const uint8_t* iv, size_t iv_len);
KCTSB_API void kctsb_gmac_update(kctsb_gmac_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_gmac_final(kctsb_gmac_ctx_t* ctx, uint8_t tag[16]);
KCTSB_API void kctsb_gmac(const uint8_t key[16], const uint8_t* iv, size_t iv_len,
                          const uint8_t* aad, size_t aad_len, uint8_t tag[16]);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_MAC_H
