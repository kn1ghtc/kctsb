/**
 * @file mach_desc.h
 * @brief Machine description for NTL in kctsb
 *
 * This replaces NTL's configure-generated mach_desc.h with
 * compile-time detection suitable for kctsb's build system.
 * Uses #ifndef guards to avoid conflicts with NTL's own definitions.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef NTL_mach_desc__H
#define NTL_mach_desc__H

#include <cstdint>
#include <climits>
#include <cstddef>

// ============================================================================
// Platform Detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #ifndef NTL_WINPACK
    #define NTL_WINPACK 1
    #endif
#endif

// ============================================================================
// Architecture Detection and Type Sizes
// ============================================================================

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
    // 64-bit platform
    #ifndef NTL_BITS_PER_LONG
    #define NTL_BITS_PER_LONG 64
    #endif
    #ifndef NTL_BITS_PER_INT
    #define NTL_BITS_PER_INT 32
    #endif
    #ifndef NTL_ARITH_RIGHT_SHIFT
    #define NTL_ARITH_RIGHT_SHIFT 1
    #endif
    #ifndef NTL_DOUBLE_PRECISION
    #define NTL_DOUBLE_PRECISION 53
    #endif
#elif defined(__i386__) || defined(_M_IX86)
    // 32-bit platform
    #ifndef NTL_BITS_PER_LONG
    #define NTL_BITS_PER_LONG 32
    #endif
    #ifndef NTL_BITS_PER_INT
    #define NTL_BITS_PER_INT 32
    #endif
    #ifndef NTL_ARITH_RIGHT_SHIFT
    #define NTL_ARITH_RIGHT_SHIFT 1
    #endif
    #ifndef NTL_DOUBLE_PRECISION
    #define NTL_DOUBLE_PRECISION 53
    #endif
#else
    // Unknown platform - assume 64-bit
    #ifndef NTL_BITS_PER_LONG
    #define NTL_BITS_PER_LONG 64
    #endif
    #ifndef NTL_BITS_PER_INT
    #define NTL_BITS_PER_INT 32
    #endif
    #ifndef NTL_ARITH_RIGHT_SHIFT
    #define NTL_ARITH_RIGHT_SHIFT 1
    #endif
    #ifndef NTL_DOUBLE_PRECISION
    #define NTL_DOUBLE_PRECISION 53
    #endif
#endif

#ifndef NTL_BITS_PER_SIZE_T
#define NTL_BITS_PER_SIZE_T NTL_BITS_PER_LONG
#endif

// ============================================================================
// GMP Limb Configuration
// ============================================================================

#ifndef NTL_BITS_PER_LIMB_T
#define NTL_BITS_PER_LIMB_T NTL_BITS_PER_LONG
#endif

// ============================================================================
// NTL ZZ Configuration
// ============================================================================

#ifndef NTL_ZZ_NBITS
#if NTL_BITS_PER_LONG == 64
    #define NTL_ZZ_NBITS 60
#else
    #define NTL_ZZ_NBITS 30
#endif
#endif

#ifndef NTL_NBITS_MAX
#define NTL_NBITS_MAX ((NTL_BITS_PER_LONG) - 2)
#endif

#ifndef NTL_ZZ_FRADIX
#define NTL_ZZ_FRADIX ((double)(1UL << NTL_ZZ_NBITS))
#endif

#ifndef NTL_ZZ_WIDE_FRADIX
#define NTL_ZZ_WIDE_FRADIX NTL_ZZ_FRADIX
#endif

// ============================================================================
// Numeric Limits
// ============================================================================

#ifndef NTL_ULONG_MAX
#define NTL_ULONG_MAX ULONG_MAX
#endif

#ifndef NTL_LONG_MAX
#define NTL_LONG_MAX LONG_MAX
#endif

#ifndef NTL_LONG_MIN
#define NTL_LONG_MIN LONG_MIN
#endif

#ifndef NTL_INT_MAX
#define NTL_INT_MAX INT_MAX
#endif

#ifndef NTL_INT_MIN
#define NTL_INT_MIN INT_MIN
#endif

#ifndef NTL_MIN_INT
#define NTL_MIN_INT INT_MIN
#endif

#ifndef NTL_UINT_MAX
#define NTL_UINT_MAX UINT_MAX
#endif

// ============================================================================
// Pointer size
// ============================================================================

#ifndef NTL_BITS_PER_POINTER
#define NTL_BITS_PER_POINTER NTL_BITS_PER_LONG
#endif

// ============================================================================
// Max allocation block (memory management)
// ============================================================================

#ifndef NTL_MAX_ALLOC_BLOCK
#define NTL_MAX_ALLOC_BLOCK 40000
#endif

#ifndef NTL_RELEASE_THRESH
#define NTL_RELEASE_THRESH 128
#endif

// ============================================================================
// FFT Configuration
// ============================================================================

#ifndef NTL_FFT_THRESH
#define NTL_FFT_THRESH 16
#endif

#ifndef NTL_FFT_BIGTAB_THRESH
#define NTL_FFT_BIGTAB_THRESH 4096
#endif

#endif // NTL_mach_desc__H
