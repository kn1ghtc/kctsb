/**
 * @file ALL_FEATURES.h
 * @brief Feature detection and compatibility header
 * 
 * This file replaces NTL's configure-generated ALL_FEATURES.h.
 * All feature detection is done at compile-time based on
 * compiler/platform detection.
 *
 * Removed features (NTL configure-time):
 * - HAVE_AVX, HAVE_FMA, HAVE_PCLMUL, etc. (now auto-detected)
 * - HAVE_KMA, HAVE_COPY_TRAITS, etc. (integrated into kctsb_bignum_config.h)
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_ALL_FEATURES_H
#define KCTSB_ALL_FEATURES_H

// All feature definitions come from kctsb_bignum_config.h
// which provides compile-time detection without configure step

// ============================================================================
// SIMD Feature Detection (auto-detected by compiler)
// ============================================================================

#if defined(__AES__) || defined(_MSC_VER)
    #ifndef KCTSB_HAVE_AES
        #define KCTSB_HAVE_AES 1
    #endif
    #ifndef NTL_HAVE_AES
        #define NTL_HAVE_AES 1
    #endif
#endif

#if defined(__PCLMUL__) || defined(_MSC_VER)
    #ifndef KCTSB_HAVE_PCLMUL
        #define KCTSB_HAVE_PCLMUL 1
    #endif
    #ifndef NTL_HAVE_PCLMUL
        #define NTL_HAVE_PCLMUL 1
    #endif
#endif

#if defined(__AVX__)
    #ifndef KCTSB_HAVE_AVX
        #define KCTSB_HAVE_AVX 1
    #endif
    #ifndef NTL_HAVE_AVX
        #define NTL_HAVE_AVX 1
    #endif
#endif

#if defined(__AVX2__)
    #ifndef KCTSB_HAVE_AVX2
        #define KCTSB_HAVE_AVX2 1
    #endif
    #ifndef NTL_HAVE_AVX2
        #define NTL_HAVE_AVX2 1
    #endif
#endif

#if defined(__FMA__)
    #ifndef KCTSB_HAVE_FMA
        #define KCTSB_HAVE_FMA 1
    #endif
    #ifndef NTL_HAVE_FMA
        #define NTL_HAVE_FMA 1
    #endif
#endif

#if defined(__AVX512F__)
    #ifndef KCTSB_HAVE_AVX512F
        #define KCTSB_HAVE_AVX512F 1
    #endif
    #ifndef NTL_HAVE_AVX512F
        #define NTL_HAVE_AVX512F 1
    #endif
#endif

// ARM NEON
#if defined(__ARM_NEON) || defined(__aarch64__)
    #ifndef KCTSB_HAVE_NEON
        #define KCTSB_HAVE_NEON 1
    #endif
#endif

// ============================================================================
// Compiler Intrinsics Detection
// ============================================================================

#if defined(__GNUC__) || defined(__clang__)
    #ifndef KCTSB_HAVE_BUILTIN_CLZL
        #define KCTSB_HAVE_BUILTIN_CLZL 1
    #endif
    #ifndef NTL_HAVE_BUILTIN_CLZL
        #define NTL_HAVE_BUILTIN_CLZL 1
    #endif
#endif

// ============================================================================
// Long Long Type Support
// ============================================================================

// Modern compilers always support long long
#ifndef KCTSB_HAVE_LL_TYPE
    #define KCTSB_HAVE_LL_TYPE 1
#endif
#ifndef NTL_HAVE_LL_TYPE
    #define NTL_HAVE_LL_TYPE 1
#endif

// ============================================================================
// Aligned Array Support (C++11+)
// ============================================================================

#if __cplusplus >= 201103L
    #ifndef KCTSB_HAVE_ALIGNED_ARRAY
        #define KCTSB_HAVE_ALIGNED_ARRAY 1
    #endif
    #ifndef NTL_HAVE_ALIGNED_ARRAY
        #define NTL_HAVE_ALIGNED_ARRAY 1
    #endif
#endif

// ============================================================================
// Copy Traits (C++11+ type traits)
// ============================================================================

#if __cplusplus >= 201103L
    #ifndef KCTSB_HAVE_COPY_TRAITS1
        #define KCTSB_HAVE_COPY_TRAITS1 1
    #endif
    #ifndef KCTSB_HAVE_COPY_TRAITS2
        #define KCTSB_HAVE_COPY_TRAITS2 1
    #endif
    #ifndef NTL_HAVE_COPY_TRAITS1
        #define NTL_HAVE_COPY_TRAITS1 1
    #endif
    #ifndef NTL_HAVE_COPY_TRAITS2
        #define NTL_HAVE_COPY_TRAITS2 1
    #endif
#endif

// ============================================================================
// Chrono Time (C++11+)
// ============================================================================

#if __cplusplus >= 201103L
    #ifndef KCTSB_HAVE_CHRONO_TIME
        #define KCTSB_HAVE_CHRONO_TIME 1
    #endif
    #ifndef NTL_HAVE_CHRONO_TIME
        #define NTL_HAVE_CHRONO_TIME 1
    #endif
#endif

// ============================================================================
// POSIX Thread Support
// ============================================================================

#if defined(_POSIX_THREADS) || defined(_WIN32)
    #ifndef KCTSB_HAVE_PTHREADS
        #define KCTSB_HAVE_PTHREADS 1
    #endif
#endif

// ============================================================================
// KMA (Kernel Memory Allocation) - typically not available
// ============================================================================
// This was an NTL optimization that's not commonly used
// #define KCTSB_HAVE_KMA 1

// ============================================================================
// NTL Compatibility - Ensure NTL_* versions exist
// ============================================================================

// These are already defined above with #ifndef guards
// Just verify the pattern is consistent

#endif // KCTSB_ALL_FEATURES_H
