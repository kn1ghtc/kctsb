/**
 * @file fe.h
 * @brief Format-Preserving Encryption
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_ADVANCED_FE_H
#define KCTSB_ADVANCED_FE_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void* internal;
} kctsb_fpe_ctx_t;

// FF1 mode (NIST SP 800-38G)
KCTSB_API kctsb_error_t kctsb_fpe_ff1_encrypt(const uint8_t key[32], const uint8_t* tweak, size_t tweak_len, const char* plaintext, size_t radix, char* ciphertext);
KCTSB_API kctsb_error_t kctsb_fpe_ff1_decrypt(const uint8_t key[32], const uint8_t* tweak, size_t tweak_len, const char* ciphertext, size_t radix, char* plaintext);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_ADVANCED_FE_H
