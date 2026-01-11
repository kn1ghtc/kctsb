/**
 * @file blake.h
 * @brief BLAKE hash function
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_BLAKE_H
#define KCTSB_CRYPTO_BLAKE_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[128];
    size_t buflen;
    size_t outlen;
} kctsb_blake2b_ctx_t;

KCTSB_API void kctsb_blake2b_init(kctsb_blake2b_ctx_t* ctx, size_t outlen);
KCTSB_API void kctsb_blake2b_update(kctsb_blake2b_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_blake2b_final(kctsb_blake2b_ctx_t* ctx, uint8_t* out);
KCTSB_API void kctsb_blake2b(const uint8_t* data, size_t len, uint8_t* out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_BLAKE_H
