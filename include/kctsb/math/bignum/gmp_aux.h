/**
 * @file gmp_aux.h
 * @brief GMP auxiliary functions for bignum integration
 *
 * This header provides the interface between bignum and GMP.
 * It replaces bignum's auto-generated gmp_aux.h.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_gmp_aux__H
#define KCTSB_gmp_aux__H

#include <gmp.h>

// Verify GMP version (bignum requires GMP 5.0.0+)
#if __GNU_MP_VERSION < 5
#error "GMP version 5.0.0 or later required"
#endif

// ============================================================================
// GMP Type Definitions
// ============================================================================

// mp_limb_t is the fundamental limb type in GMP
// This should match the platform word size

#if GMP_LIMB_BITS == 64
    #define KCTSB_BITS_PER_LIMB_T 64
#else
    #define KCTSB_BITS_PER_LIMB_T 32
#endif

// ============================================================================
// bignum ZZ to GMP mpz Conversion Macros
// ============================================================================

// These macros provide zero-copy access to the internal GMP representation
// of bignum big integers. They are used internally by bignum's lip.cpp.

// Get pointer to limb array (for reading)
#define KCTSB_IsGmpSingle(p) ((p)->_mp_alloc <= 1)

// Direct access to mpz internals (use with caution)
#define KCTSB_IsGmpZero(p) ((p)->_mp_size == 0)
#define KCTSB_IsGmpPos(p) ((p)->_mp_size > 0)
#define KCTSB_IsGmpNeg(p) ((p)->_mp_size < 0)
#define KCTSB_IsGmpOne(p) ((p)->_mp_size == 1 && (p)->_mp_d[0] == 1)

// Get absolute size (number of limbs)
#define KCTSB_IsGmpAbsSize(p) (((p)->_mp_size >= 0) ? (p)->_mp_size : -(p)->_mp_size)

// ============================================================================
// bignum FFT Primes (for FFT-based multiplication)
// ============================================================================

// These primes are used for NTT (Number Theoretic Transform)
// They must satisfy: p = 1 (mod 2^k) for sufficient k

// FFT prime selection based on limb size
#if KCTSB_BITS_PER_LIMB_T == 64
    // 64-bit FFT primes (62-bit primes with good 2-adic order)
    #define KCTSB_FFT_PRIME_1 0x3FFFFFFFFFFFFC21ULL  // 2^62 - 991
    #define KCTSB_FFT_PRIME_2 0x3FFFFFFFFFFFFC45ULL  // 2^62 - 955
    #define KCTSB_FFT_PRIME_3 0x3FFFFFFFFFFFFC61ULL  // 2^62 - 927
#else
    // 32-bit FFT primes (30-bit primes)
    #define KCTSB_FFT_PRIME_1 0x3FFFFF01UL  // 2^30 - 255
    #define KCTSB_FFT_PRIME_2 0x3FFFFF21UL  // 2^30 - 223
    #define KCTSB_FFT_PRIME_3 0x3FFFFF41UL  // 2^30 - 191
#endif

#endif // KCTSB_gmp_aux__H
