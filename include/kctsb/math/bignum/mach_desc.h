/**
 * @file mach_desc.h
 * @brief Machine description for kctsb bignum module
 *
 * This provides compile-time platform detection for the bignum module.
 * 
 * CRITICAL: Windows LLP64 Data Model Handling
 * - Windows x64: sizeof(long) = 4 bytes (32-bit)
 * - Linux/macOS x64 (LP64): sizeof(long) = 8 bytes (64-bit)
 * 
 * The bignum module uses NTL_BITS_PER_LONG to determine word size.
 * On Windows x64, we MUST set this to 32 to match actual long size,
 * or use NTL_USE_LONGLONG to switch to 64-bit long long operations.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_BIGNUM_MACH_DESC_H
#define KCTSB_BIGNUM_MACH_DESC_H

// Include kctsb platform definitions first
#include <kctsb/math/bignum/platform.h>

// ============================================================================
// Platform Detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #ifndef NTL_WINPACK
    #define NTL_WINPACK 1
    #endif
#endif

// ============================================================================
// Type Size Detection - Handle Windows LLP64 Data Model
// ============================================================================
// 
// IMPORTANT: NTL_BITS_PER_LONG MUST match the actual sizeof(long) on the platform
// because NTL code uses `long` type directly for arithmetic operations.
// 
// On Windows x64 (LLP64): sizeof(long) = 4 bytes (32-bit)
// On Linux/macOS x64 (LP64): sizeof(long) = 8 bytes (64-bit)
//
// Strategy for Windows LLP64:
// - Set NTL_BITS_PER_LONG to 32 (matches actual long size)
// - Use NTL_ZZ_NBITS = 30 (32-bit word operations)
// - Enable NTL_HAVE_LL_TYPE for double-word arithmetic
// - Use GMP backend for efficient big integer operations
//
// This means Windows builds will use 32-bit single-precision arithmetic
// (slightly slower) but still have efficient GMP-backed ZZ operations.

#if defined(_WIN32) || defined(_WIN64)
    // Windows LLP64: long is ALWAYS 32-bit
    #ifndef NTL_BITS_PER_LONG
    #define NTL_BITS_PER_LONG 32
    #endif
    // Enable long long for double-word arithmetic
    #ifndef NTL_HAVE_LL_TYPE
    #define NTL_HAVE_LL_TYPE 1
    #endif
    #ifndef NTL_WINPACK
    #define NTL_WINPACK 1
    #endif
#elif defined(__LP64__) || defined(__x86_64__) || defined(__aarch64__) || defined(_M_ARM64)
    // Unix-like 64-bit (LP64): long is 64-bit
    #ifndef NTL_BITS_PER_LONG
    #define NTL_BITS_PER_LONG 64
    #endif
    #ifndef NTL_HAVE_LL_TYPE
    #define NTL_HAVE_LL_TYPE 1
    #endif
#elif defined(__i386__) || defined(_M_IX86)
    // 32-bit platforms
    #ifndef NTL_BITS_PER_LONG
    #define NTL_BITS_PER_LONG 32
    #endif
#else
    // Fallback: detect at compile time
    #ifndef NTL_BITS_PER_LONG
        #if ULONG_MAX == 0xFFFFFFFFUL
            #define NTL_BITS_PER_LONG 32
        #elif ULONG_MAX == 0xFFFFFFFFFFFFFFFFUL
            #define NTL_BITS_PER_LONG 64
        #else
            #error "Cannot determine NTL_BITS_PER_LONG"
        #endif
    #endif
#endif

// NTL_BITS_PER_INT is always 32 on modern platforms
#ifndef NTL_BITS_PER_INT
#define NTL_BITS_PER_INT 32
#endif

#ifndef NTL_ARITH_RIGHT_SHIFT
#define NTL_ARITH_RIGHT_SHIFT 1
#endif

#ifndef NTL_DOUBLE_PRECISION
#define NTL_DOUBLE_PRECISION 53
#endif

// SIZE_T bits - always match pointer size, not long size
#ifndef NTL_BITS_PER_SIZE_T
    #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
        #define NTL_BITS_PER_SIZE_T 64
    #else
        #define NTL_BITS_PER_SIZE_T 32
    #endif
#endif

// ============================================================================
// GMP Limb Configuration - Always 64-bit on 64-bit platforms
// ============================================================================

#ifndef NTL_BITS_PER_LIMB_T
    #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
        #define NTL_BITS_PER_LIMB_T 64
    #else
        #define NTL_BITS_PER_LIMB_T 32
    #endif
#endif

// ============================================================================
// ZZ Configuration - Match NTL_BITS_PER_LONG
// ============================================================================
// NTL_ZZ_NBITS defines the number of bits used per word in ZZ operations.
// It MUST be <= NTL_BITS_PER_LONG - 2 to avoid overflow.

#if NTL_BITS_PER_LONG >= 64
    // 64-bit long: use 60 bits per word
    #ifndef NTL_ZZ_NBITS
    #define NTL_ZZ_NBITS 60
    #endif
    #ifndef NTL_NBITS_MAX
    #define NTL_NBITS_MAX 62
    #endif
#else
    // 32-bit long (including Windows LLP64): use 30 bits per word
    #ifndef NTL_ZZ_NBITS
    #define NTL_ZZ_NBITS 30
    #endif
    #ifndef NTL_NBITS_MAX
    #define NTL_NBITS_MAX 30
    #endif
#endif

// Use 64-bit unsigned for ZZ_FRADIX calculation
// Note: With NTL_ZZ_NBITS <= 30 on Windows, 1UL << 30 is safe for 32-bit long
#ifndef NTL_ZZ_FRADIX
#define NTL_ZZ_FRADIX ((double)(1UL << NTL_ZZ_NBITS))
#endif

#ifndef NTL_ZZ_WIDE_FRADIX
#define NTL_ZZ_WIDE_FRADIX NTL_ZZ_FRADIX
#endif

// ============================================================================
// Numeric Limits - Use platform-appropriate values
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

// Alias: NTL_MAX_INT is sometimes used in code
#ifndef NTL_MAX_INT
#define NTL_MAX_INT INT_MAX
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
// kctsb 64-bit word limits (platform-independent)
// These are for 64-bit arithmetic on ALL platforms including Windows LLP64
// ============================================================================

#ifndef KCTSB_WORD_MAX
#define KCTSB_WORD_MAX INT64_MAX
#endif

#ifndef KCTSB_UWORD_MAX
#define KCTSB_UWORD_MAX UINT64_MAX
#endif

// ============================================================================
// Pointer size - Always match actual pointer size
// ============================================================================

#ifndef NTL_BITS_PER_POINTER
    #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
        #define NTL_BITS_PER_POINTER 64
    #else
        #define NTL_BITS_PER_POINTER 32
    #endif
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

#endif // KCTSB_BIGNUM_MACH_DESC_H
