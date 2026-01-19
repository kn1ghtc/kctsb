/**
 * @file mach_desc.h
 * @brief Machine description header - compile-time platform detection
 * 
 * This file replaces NTL's configure-generated mach_desc.h with
 * compile-time detection that works across Windows/Linux/macOS.
 * 
 * Key constants defined:
 * - KCTSB_BITS_PER_LONG: sizeof(long) in bits (32 on Windows x64 LLP64)
 * - KCTSB_BITS_PER_INT: sizeof(int) in bits
 * - KCTSB_BITS_PER_SIZE_T: sizeof(size_t) in bits
 * - KCTSB_ZZ_NBITS: Internal ZZ representation bits (matches GMP when GMP_LIP)
 * - KCTSB_ZZ_FRADIX: Floating-point radix constant
 * 
 * @note NTL compatibility aliases are provided via NTL_* macros.
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MACH_DESC_H
#define KCTSB_MACH_DESC_H

// Include base config first for platform detection
#include <kctsb/math/bignum/kctsb_bignum_config.h>

// ============================================================================
// CRITICAL: Windows LLP64 Data Model
// ============================================================================
// On Windows x64, sizeof(long) = 4 bytes (32-bit), NOT 64-bit!
// This is different from Linux/macOS LP64 where long is 64-bit.
// The bignum code uses 'long' type directly, so KCTSB_BITS_PER_LONG
// MUST match the actual sizeof(long) on the platform.

// These should already be defined in kctsb_bignum_config.h, but provide fallbacks:

#ifndef KCTSB_BITS_PER_LONG
    #if defined(_WIN32) || defined(_WIN64)
        // Windows LLP64: long is always 32-bit
        #define KCTSB_BITS_PER_LONG 32
    #elif defined(__LP64__) || defined(__x86_64__) || defined(__aarch64__)
        // Unix LP64: long is 64-bit on 64-bit platforms
        #define KCTSB_BITS_PER_LONG 64
    #else
        // Default 32-bit
        #define KCTSB_BITS_PER_LONG 32
    #endif
#endif

#ifndef KCTSB_BITS_PER_INT
    #define KCTSB_BITS_PER_INT 32
#endif

#ifndef KCTSB_BITS_PER_SIZE_T
    #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
        #define KCTSB_BITS_PER_SIZE_T 64
    #else
        #define KCTSB_BITS_PER_SIZE_T 32
    #endif
#endif

// ============================================================================
// ZZ Internal Representation
// ============================================================================
// When using GMP (KCTSB_GMP_LIP), KCTSB_ZZ_NBITS must match GMP_NUMB_BITS.
// GMP uses full limb width without nail bits:
// - 64-bit platforms: 64-bit limbs → ZZ_NBITS = 64
// - 32-bit platforms: 32-bit limbs → ZZ_NBITS = 32
//
// When NOT using GMP (native bignum), NTL uses 2 bits less for overflow:
// - 64-bit: 60 bits (KCTSB_BITS_PER_LONG - 4 on 64-bit with space for carry)
// - 32-bit: 30 bits (KCTSB_BITS_PER_LONG - 2 on 32-bit)

#ifndef KCTSB_ZZ_NBITS
    #ifdef KCTSB_GMP_LIP
        // GMP mode: use full limb width (no nail bits)
        // GMP limb size is typically 64-bit on 64-bit platforms regardless of long size
        #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
            #define KCTSB_ZZ_NBITS 64
        #else
            #define KCTSB_ZZ_NBITS 32
        #endif
    #else
        // Native mode: use KCTSB_BITS_PER_LONG - overhead
        #if KCTSB_BITS_PER_LONG == 64
            #define KCTSB_ZZ_NBITS 60
        #else
            #define KCTSB_ZZ_NBITS 30
        #endif
    #endif
#endif

// ZZ radix as floating-point (used in RR, xdouble, etc.)
#ifndef KCTSB_ZZ_FRADIX
    #if KCTSB_ZZ_NBITS <= 30
        #define KCTSB_ZZ_FRADIX ((double)(1UL << KCTSB_ZZ_NBITS))
    #elif KCTSB_ZZ_NBITS <= 60
        // For 60-bit, we need to be careful about overflow
        #define KCTSB_ZZ_FRADIX (1152921504606846976.0) // 2^60
    #else
        // For 64-bit, use 2^64
        #define KCTSB_ZZ_FRADIX (18446744073709551616.0) // 2^64
    #endif
#endif

// Wide radix (same as FRADIX in most cases)
#ifndef KCTSB_ZZ_WIDE_FRADIX
    #define KCTSB_ZZ_WIDE_FRADIX KCTSB_ZZ_FRADIX
#endif

// ============================================================================
// Numeric Limits (int and long type bounds)
// ============================================================================

#include <climits>

#ifndef KCTSB_MAX_INT
    #define KCTSB_MAX_INT INT_MAX
#endif

#ifndef KCTSB_MIN_INT
    #define KCTSB_MIN_INT INT_MIN
#endif

#ifndef KCTSB_MAX_LONG
    #define KCTSB_MAX_LONG LONG_MAX
#endif

#ifndef KCTSB_MIN_LONG
    #define KCTSB_MIN_LONG LONG_MIN
#endif

// NTL compatibility
#ifndef NTL_MAX_INT
    #define NTL_MAX_INT KCTSB_MAX_INT
#endif

#ifndef NTL_MIN_INT
    #define NTL_MIN_INT KCTSB_MIN_INT
#endif

#ifndef NTL_MAX_LONG
    #define NTL_MAX_LONG KCTSB_MAX_LONG
#endif

#ifndef NTL_MIN_LONG
    #define NTL_MIN_LONG KCTSB_MIN_LONG
#endif

// ============================================================================
// Double Precision Configuration
// ============================================================================

#ifndef KCTSB_DOUBLE_PRECISION
    #define KCTSB_DOUBLE_PRECISION 53
#endif

#ifndef KCTSB_FDOUBLE_PRECISION
    #define KCTSB_FDOUBLE_PRECISION ((double)(KCTSB_DOUBLE_PRECISION))
#endif

// ============================================================================
// NTL Compatibility Aliases
// ============================================================================
// These allow NTL-originated code to work without modification.

#ifndef NTL_BITS_PER_LONG
    #define NTL_BITS_PER_LONG KCTSB_BITS_PER_LONG
#endif

#ifndef NTL_BITS_PER_INT
    #define NTL_BITS_PER_INT KCTSB_BITS_PER_INT
#endif

#ifndef NTL_BITS_PER_SIZE_T
    #define NTL_BITS_PER_SIZE_T KCTSB_BITS_PER_SIZE_T
#endif

#ifndef NTL_ZZ_NBITS
    #define NTL_ZZ_NBITS KCTSB_ZZ_NBITS
#endif

#ifndef NTL_ZZ_FRADIX
    #define NTL_ZZ_FRADIX KCTSB_ZZ_FRADIX
#endif

#ifndef NTL_ZZ_WIDE_FRADIX
    #define NTL_ZZ_WIDE_FRADIX KCTSB_ZZ_WIDE_FRADIX
#endif

#ifndef NTL_DOUBLE_PRECISION
    #define NTL_DOUBLE_PRECISION KCTSB_DOUBLE_PRECISION
#endif

#ifndef NTL_FDOUBLE_PRECISION
    #define NTL_FDOUBLE_PRECISION KCTSB_FDOUBLE_PRECISION
#endif

// ============================================================================
// Validation
// ============================================================================
// Static assertion to ensure configuration is sane

#if defined(__cplusplus) && __cplusplus >= 201103L
    static_assert(KCTSB_BITS_PER_LONG == 32 || KCTSB_BITS_PER_LONG == 64,
                  "KCTSB_BITS_PER_LONG must be 32 or 64");
    static_assert(KCTSB_ZZ_NBITS >= 30 && KCTSB_ZZ_NBITS <= 64,
                  "KCTSB_ZZ_NBITS must be between 30 and 64");
#endif

#endif // KCTSB_MACH_DESC_H
