/**
 * @file ecc.h
 * @brief Elliptic Curve Cryptography
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_ECC_H
#define KCTSB_CRYPTO_ECC_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void* internal;
    int curve_id;
} kctsb_ecc_key_t;

// Supported curves (256-bit only)
#define KCTSB_ECC_SECP256K1 0
#define KCTSB_ECC_SECP256R1 1  // P-256
#define KCTSB_ECC_SM2       4  // Chinese National Standard

KCTSB_API kctsb_error_t kctsb_ecc_generate_keypair(kctsb_ecc_key_t* key, int curve);
KCTSB_API kctsb_error_t kctsb_ecdh_compute_shared(const kctsb_ecc_key_t* priv, const kctsb_ecc_key_t* pub, uint8_t* shared, size_t* len);
KCTSB_API kctsb_error_t kctsb_ecdsa_sign(const kctsb_ecc_key_t* key, const uint8_t* hash, size_t hash_len, uint8_t* sig, size_t* sig_len);
KCTSB_API kctsb_error_t kctsb_ecdsa_verify(const kctsb_ecc_key_t* key, const uint8_t* hash, size_t hash_len, const uint8_t* sig, size_t sig_len);
KCTSB_API void kctsb_ecc_free(kctsb_ecc_key_t* key);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CRYPTO_ECC_H
