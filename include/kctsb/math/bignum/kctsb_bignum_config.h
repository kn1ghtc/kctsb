/**
 * @file kctsb_kctsb_config.h
 * @brief kctsb-specific bignum configuration
 * 
 * This header provides bignum configuration for kctsb integration.
 * It replaces bignum's configure-generated headers with compile-time
 * detection that matches kctsb's build system.
 *
 * All macros use #ifndef guards to avoid redefinition conflicts
 * with bignum's original headers.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_KCTSB_CONFIG_H
#define KCTSB_KCTSB_CONFIG_H

// ============================================================================
// Platform Detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #ifndef KCTSB_WINPACK
        #define KCTSB_WINPACK 1
    #endif
    #ifndef KCTSB_PLATFORM_WINDOWS
        #define KCTSB_PLATFORM_WINDOWS 1
    #endif
#elif defined(__APPLE__)
    #ifndef KCTSB_PLATFORM_MACOS
        #define KCTSB_PLATFORM_MACOS 1
    #endif
#elif defined(__linux__)
    #ifndef KCTSB_PLATFORM_LINUX
        #define KCTSB_PLATFORM_LINUX 1
    #endif
#endif

// ============================================================================
// Compiler Detection
// ============================================================================

#if defined(_MSC_VER)
    #ifndef KCTSB_COMPILER_MSVC
        #define KCTSB_COMPILER_MSVC 1
    #endif
#elif defined(__GNUC__)
    #ifndef KCTSB_COMPILER_GCC
        #define KCTSB_COMPILER_GCC 1
    #endif
#elif defined(__clang__)
    #ifndef KCTSB_COMPILER_CLANG
        #define KCTSB_COMPILER_CLANG 1
    #endif
#endif

// ============================================================================
// Architecture Detection
// ============================================================================
// CRITICAL: Windows LLP64 Data Model
// ------------------------------------
// On Windows x64, sizeof(long) = 4 bytes (32-bit), NOT 64-bit!
// The bignum code uses `long` type directly, so KCTSB_BITS_PER_LONG
// MUST match the actual sizeof(long) on the platform.
//
// We use KCTSB_PLATFORM_WORD_BITS for the "algorithmic word size"
// and KCTSB_BITS_PER_LONG for the actual C `long` type size.

#if defined(__x86_64__) || defined(_M_X64)
    #ifndef KCTSB_ARCH_X64
        #define KCTSB_ARCH_X64 1
    #endif
    // Windows x64: long is 32-bit (LLP64 data model)
    #if defined(_WIN32) || defined(_WIN64)
        #ifndef KCTSB_BITS_PER_LONG
            #define KCTSB_BITS_PER_LONG 32
        #endif
        // Force legacy mode - avoid 64-bit long assumptions
        #ifndef KCTSB_LEGACY_SP_MULMOD
            #define KCTSB_LEGACY_SP_MULMOD 1
        #endif
    #else
        // Unix x64: long is 64-bit (LP64 data model)
        #ifndef KCTSB_BITS_PER_LONG
            #define KCTSB_BITS_PER_LONG 64
        #endif
    #endif
    #ifndef KCTSB_BITS_PER_INT
        #define KCTSB_BITS_PER_INT 32
    #endif
#elif defined(__i386__) || defined(_M_IX86)
    #ifndef KCTSB_ARCH_X86
        #define KCTSB_ARCH_X86 1
    #endif
    #ifndef KCTSB_BITS_PER_LONG
        #define KCTSB_BITS_PER_LONG 32
    #endif
    #ifndef KCTSB_BITS_PER_INT
        #define KCTSB_BITS_PER_INT 32
    #endif
    #ifndef KCTSB_LEGACY_SP_MULMOD
        #define KCTSB_LEGACY_SP_MULMOD 1
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64)
    #ifndef KCTSB_ARCH_ARM64
        #define KCTSB_ARCH_ARM64 1
    #endif
    // ARM64 Windows also uses LLP64
    #if defined(_WIN32) || defined(_WIN64)
        #ifndef KCTSB_BITS_PER_LONG
            #define KCTSB_BITS_PER_LONG 32
        #endif
        #ifndef KCTSB_LEGACY_SP_MULMOD
            #define KCTSB_LEGACY_SP_MULMOD 1
        #endif
    #else
        #ifndef KCTSB_BITS_PER_LONG
            #define KCTSB_BITS_PER_LONG 64
        #endif
    #endif
    #ifndef KCTSB_BITS_PER_INT
        #define KCTSB_BITS_PER_INT 32
    #endif
#endif

// SIZE_T bits - always match pointer size on 64-bit platforms
#ifndef KCTSB_BITS_PER_SIZE_T
    #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
        #define KCTSB_BITS_PER_SIZE_T 64
    #else
        #define KCTSB_BITS_PER_SIZE_T 32
    #endif
#endif

// ============================================================================
// GMP Integration (Required)
// ============================================================================

// Force GMP usage - we do not use bignum's internal big integer implementation
#ifndef KCTSB_GMP_LIP
    #define KCTSB_GMP_LIP 1
#endif

// GMP limb configuration
// Note: KCTSB_BITS_PER_LIMB_T should match GMP's mp_limb_t size
// On Windows x64 (LLP64): long=32bit, but GMP uses 64-bit limbs
// The actual value is set in gmp_aux.h based on GMP_LIMB_BITS
// Here we only provide a fallback if GMP headers haven't been included yet
#ifndef KCTSB_BITS_PER_LIMB_T
    // Fallback: assume 64-bit on 64-bit platforms, 32-bit otherwise
    #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
        #define KCTSB_BITS_PER_LIMB_T 64
    #else
        #define KCTSB_BITS_PER_LIMB_T 32
    #endif
#endif

// ZZ internal representation bits
// CRITICAL: When using GMP backend (KCTSB_GMP_LIP), this MUST match GMP_NUMB_BITS!
// GMP typically uses full limb width (no nail bits), so:
// - 64-bit: KCTSB_ZZ_NBITS = 64
// - 32-bit: KCTSB_ZZ_NBITS = 32
// This is now set correctly in mach_desc.h based on KCTSB_GMP_LIP flag.
// The fallback here is only used if mach_desc.h hasn't been included.
#ifndef KCTSB_ZZ_NBITS
    #if KCTSB_BITS_PER_LIMB_T == 64
        #ifdef KCTSB_GMP_LIP
            #define KCTSB_ZZ_NBITS 64
        #else
            #define KCTSB_ZZ_NBITS 60
        #endif
    #else
        #ifdef KCTSB_GMP_LIP
            #define KCTSB_ZZ_NBITS 32
        #else
            #define KCTSB_ZZ_NBITS 30
        #endif
    #endif
#endif

#ifndef KCTSB_ZZ_FRADIX
    #define KCTSB_ZZ_FRADIX ((double)(1UL << KCTSB_ZZ_NBITS))
#endif

#ifndef KCTSB_ZZ_WIDE_FRADIX
    #define KCTSB_ZZ_WIDE_FRADIX ((double)(1UL << KCTSB_ZZ_NBITS))
#endif

// ============================================================================
// Numeric Limits (long type bounds)
// ============================================================================

#ifndef KCTSB_MAX_LONG
    #define KCTSB_MAX_LONG LONG_MAX
#endif

#ifndef KCTSB_MIN_LONG
    #define KCTSB_MIN_LONG LONG_MIN
#endif

// ============================================================================
// Floating Point Configuration
// ============================================================================

#ifndef KCTSB_DOUBLE_PRECISION
    #define KCTSB_DOUBLE_PRECISION 53
#endif

#ifndef KCTSB_FDOUBLE_PRECISION
    #define KCTSB_FDOUBLE_PRECISION ((double)(KCTSB_DOUBLE_PRECISION))
#endif

// Quad-precision floating point split constant
// Used in quad_float.cpp for double-double arithmetic
// The value 134217729.0 = 2^27 + 1 is standard for IEEE 754 double splitting
#ifndef KCTSB_QUAD_FLOAT_SPLIT
    #define KCTSB_QUAD_FLOAT_SPLIT (134217729.0)
#endif

// ============================================================================
// gf2x Library (Optional - enabled via CMake)
// ============================================================================

#ifdef KCTSB_HAS_GF2X
    #ifndef KCTSB_GF2X_LIB
        #define KCTSB_GF2X_LIB 1
    #endif
#endif

// ============================================================================
// C++ Standard
// ============================================================================

// kctsb requires C++17
#ifndef KCTSB_STD_CXX17
    #define KCTSB_STD_CXX17 1
#endif
#ifndef KCTSB_STD_CXX14
    #define KCTSB_STD_CXX14 1
#endif
#ifndef KCTSB_STD_CXX11
    #define KCTSB_STD_CXX11 1
#endif

// ============================================================================
// Threading Configuration
// ============================================================================

#ifndef KCTSB_THREADS
    #define KCTSB_THREADS 1
#endif

#ifndef KCTSB_THREAD_BOOST
    #define KCTSB_THREAD_BOOST 1
#endif

// ============================================================================
// Exception Handling
// ============================================================================

#ifndef KCTSB_EXCEPTIONS
    #define KCTSB_EXCEPTIONS 1
#endif

// ============================================================================
// Hardware Acceleration (auto-detected by compiler)
// ============================================================================

// These are detected via compiler intrinsics and __GNUC__ macros
// See bignum's ALL_FEATURES.h for details

#ifndef KCTSB_HAVE_LL_TYPE
    #define KCTSB_HAVE_LL_TYPE 1
#endif

#ifndef KCTSB_HAVE_BUILTIN_CLZL
    #if defined(__GNUC__) || defined(__clang__)
        #define KCTSB_HAVE_BUILTIN_CLZL 1
    #endif
#endif

#ifndef KCTSB_HAVE_ALIGNED_ARRAY
    #define KCTSB_HAVE_ALIGNED_ARRAY 1
#endif

#ifndef KCTSB_HAVE_COPY_TRAITS1
    #define KCTSB_HAVE_COPY_TRAITS1 1
#endif

#ifndef KCTSB_HAVE_COPY_TRAITS2
    #define KCTSB_HAVE_COPY_TRAITS2 1
#endif

#ifndef KCTSB_HAVE_CHRONO_TIME
    #define KCTSB_HAVE_CHRONO_TIME 1
#endif

// ============================================================================
// Performance Tuning
// ============================================================================

#ifndef KCTSB_FFT_THRESH
    #define KCTSB_FFT_THRESH 16
#endif

#ifndef KCTSB_FFT_BIGTAB_THRESH
    #define KCTSB_FFT_BIGTAB_THRESH 4096
#endif

#ifndef KCTSB_NBITS_MAX
    #define KCTSB_NBITS_MAX ((KCTSB_BITS_PER_LONG) - 2)
#endif

#ifndef KCTSB_MAX_ALLOC_BLOCK
    #define KCTSB_MAX_ALLOC_BLOCK 40000
#endif

#ifndef KCTSB_RELEASE_THRESH
    #define KCTSB_RELEASE_THRESH 128
#endif

// ============================================================================
// Type Definitions
// ============================================================================

#ifndef KCTSB_LL_TYPE
    #if KCTSB_BITS_PER_LONG == 64
        #ifdef __GNUC__
            #define KCTSB_LL_TYPE __int128_t
            #define KCTSB_ULL_TYPE __uint128_t
        #elif defined(_MSC_VER)
            #define KCTSB_LL_TYPE __int128
            #define KCTSB_ULL_TYPE unsigned __int128
        #endif
    #else
        #define KCTSB_LL_TYPE long long
        #define KCTSB_ULL_TYPE unsigned long long
    #endif
#endif

// ============================================================================
// Bit Manipulation Code Macros for GF2 Operations
// ============================================================================
// These define the bit reversal and multiplication code used in GF2X and vec_GF2.
// The code depends on KCTSB_BITS_PER_LONG (word size).
// Note: These macros reference local variables (revtab, a, hhi, llo) that must
// be defined in the calling function.

#if KCTSB_BITS_PER_LONG == 64

// 64-bit bit reversal using byte table lookup (uses local 'revtab' table)
#ifndef KCTSB_BB_REV_CODE
#define KCTSB_BB_REV_CODE \
   ((((unsigned long)revtab[a & 255UL]) << 56) | \
    (((unsigned long)revtab[(a >> 8) & 255UL]) << 48) | \
    (((unsigned long)revtab[(a >> 16) & 255UL]) << 40) | \
    (((unsigned long)revtab[(a >> 24) & 255UL]) << 32) | \
    (((unsigned long)revtab[(a >> 32) & 255UL]) << 24) | \
    (((unsigned long)revtab[(a >> 40) & 255UL]) << 16) | \
    (((unsigned long)revtab[(a >> 48) & 255UL]) << 8) | \
    (((unsigned long)revtab[(a >> 56) & 255UL])))
#endif

#ifndef KCTSB_BB_SQR_CODE
#define KCTSB_BB_SQR_CODE \
   hi = sqrtab[(a >> 56) & 255] | (sqrtab[(a >> 48) & 255] << 16) | \
        (sqrtab[(a >> 40) & 255] << 32) | (sqrtab[(a >> 32) & 255] << 48); \
   lo = sqrtab[a & 255] | (sqrtab[(a >> 8) & 255] << 16) | \
        (sqrtab[(a >> 16) & 255] << 32) | (sqrtab[(a >> 24) & 255] << 48);
#endif

#ifndef KCTSB_BB_MUL1_BITS
#define KCTSB_BB_MUL1_BITS 4
#endif

// Polynomial multiplication macros - using table-based approach
// Note: When KCTSB_GF2X_LIB or KCTSB_HAVE_PCLMUL is defined, these are not used
#ifndef KCTSB_BB_MUL_CODE0
#define KCTSB_BB_MUL_CODE0
#endif

#ifndef KCTSB_BB_MUL_CODE1
#define KCTSB_BB_MUL_CODE1
#endif

#ifndef KCTSB_BB_MUL_CODE2
#define KCTSB_BB_MUL_CODE2
#endif

// Short and half multiply code - empty stubs (gf2x library handles these)
#ifndef KCTSB_SHORT_BB_MUL_CODE1
#define KCTSB_SHORT_BB_MUL_CODE1
#endif

#ifndef KCTSB_HALF_BB_MUL_CODE0
#define KCTSB_HALF_BB_MUL_CODE0
#endif

#else // 32-bit

// 32-bit bit reversal
#ifndef KCTSB_BB_REV_CODE
#define KCTSB_BB_REV_CODE \
   ((((unsigned long)revtab[a & 255UL]) << 24) | \
    (((unsigned long)revtab[(a >> 8) & 255UL]) << 16) | \
    (((unsigned long)revtab[(a >> 16) & 255UL]) << 8) | \
    (((unsigned long)revtab[(a >> 24) & 255UL])))
#endif

#ifndef KCTSB_BB_SQR_CODE
#define KCTSB_BB_SQR_CODE \
   hi = sqrtab[(a >> 24) & 255] | (sqrtab[(a >> 16) & 255] << 16); \
   lo = sqrtab[a & 255] | (sqrtab[(a >> 8) & 255] << 16);
#endif

#ifndef KCTSB_BB_MUL1_BITS
#define KCTSB_BB_MUL1_BITS 4
#endif

#ifndef KCTSB_BB_MUL_CODE0
#define KCTSB_BB_MUL_CODE0
#endif

#ifndef KCTSB_BB_MUL_CODE1
#define KCTSB_BB_MUL_CODE1
#endif

#ifndef KCTSB_BB_MUL_CODE2
#define KCTSB_BB_MUL_CODE2
#endif

// Short and half multiply code - empty stubs (gf2x library handles these)
#ifndef KCTSB_SHORT_BB_MUL_CODE1
#define KCTSB_SHORT_BB_MUL_CODE1
#endif

#ifndef KCTSB_HALF_BB_MUL_CODE0
#define KCTSB_HALF_BB_MUL_CODE0
#endif

#endif // KCTSB_BITS_PER_LONG

#endif // KCTSB_KCTSB_CONFIG_H
