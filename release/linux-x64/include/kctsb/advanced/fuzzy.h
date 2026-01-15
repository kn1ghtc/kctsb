/**
 * @file fuzzy.h
 * @brief Fuzzy Extractor for secure key generation from noisy data
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_ADVANCED_FUZZY_H
#define KCTSB_ADVANCED_FUZZY_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void* internal;
} kctsb_fuzzy_ctx_t;

KCTSB_API kctsb_error_t kctsb_fuzzy_generate(kctsb_fuzzy_ctx_t* ctx, const uint8_t* biometric, size_t len, uint8_t* key, size_t key_len, uint8_t* helper, size_t* helper_len);
KCTSB_API kctsb_error_t kctsb_fuzzy_reproduce(const uint8_t* biometric, size_t len, const uint8_t* helper, size_t helper_len, uint8_t* key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_ADVANCED_FUZZY_H
