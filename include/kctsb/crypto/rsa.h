/**
 * @file rsa.h
 * @brief RSA public-key cryptosystem
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_RSA_H
#define KCTSB_CRYPTO_RSA_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// RSA key structure (placeholder - requires big integer library)
typedef struct {
    void* internal;
    int key_bits;
} kctsb_rsa_key_t;

KCTSB_API kctsb_error_t kctsb_rsa_generate_keypair(kctsb_rsa_key_t* key, int bits);
KCTSB_API kctsb_error_t kctsb_rsa_encrypt(const kctsb_rsa_key_t* key, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);
KCTSB_API kctsb_error_t kctsb_rsa_decrypt(const kctsb_rsa_key_t* key, const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);
KCTSB_API void kctsb_rsa_free(kctsb_rsa_key_t* key);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_RSA_H
