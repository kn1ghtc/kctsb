/**
 * @file common.h
 * @brief Common mathematical utilities
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_MATH_COMMON_H
#define KCTSB_MATH_COMMON_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

// GCD and extended GCD
KCTSB_API uint64_t kctsb_gcd(uint64_t a, uint64_t b);
KCTSB_API uint64_t kctsb_lcm(uint64_t a, uint64_t b);
KCTSB_API int64_t kctsb_extended_gcd(int64_t a, int64_t b, int64_t* x, int64_t* y);

// Modular arithmetic
KCTSB_API uint64_t kctsb_mod_add(uint64_t a, uint64_t b, uint64_t mod);
KCTSB_API uint64_t kctsb_mod_sub(uint64_t a, uint64_t b, uint64_t mod);
KCTSB_API uint64_t kctsb_mod_mul(uint64_t a, uint64_t b, uint64_t mod);
KCTSB_API uint64_t kctsb_mod_pow(uint64_t base, uint64_t exp, uint64_t mod);
KCTSB_API uint64_t kctsb_mod_inv(uint64_t a, uint64_t mod);

// Primality testing
KCTSB_API int kctsb_is_prime(uint64_t n);
KCTSB_API int kctsb_miller_rabin(uint64_t n, int iterations);

// Chinese Remainder Theorem
KCTSB_API uint64_t kctsb_crt(const uint64_t* remainders, const uint64_t* moduli, size_t count);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_MATH_COMMON_H
