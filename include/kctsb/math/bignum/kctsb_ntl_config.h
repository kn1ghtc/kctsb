/**
 * @file kctsb_ntl_config.h
 * @brief kctsb-specific NTL configuration
 * 
 * This header provides NTL configuration for kctsb integration.
 * It replaces NTL's configure-generated headers with compile-time
 * detection that matches kctsb's build system.
 *
 * All macros use #ifndef guards to avoid redefinition conflicts
 * with NTL's original headers.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_NTL_CONFIG_H
#define KCTSB_NTL_CONFIG_H

// ============================================================================
// Platform Detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #ifndef NTL_WINPACK
        #define NTL_WINPACK 1
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

#if defined(__x86_64__) || defined(_M_X64)
    #ifndef KCTSB_ARCH_X64
        #define KCTSB_ARCH_X64 1
    #endif
    #ifndef NTL_BITS_PER_LONG
        #define NTL_BITS_PER_LONG 64
    #endif
    #ifndef NTL_BITS_PER_INT
        #define NTL_BITS_PER_INT 32
    #endif
#elif defined(__i386__) || defined(_M_IX86)
    #ifndef KCTSB_ARCH_X86
        #define KCTSB_ARCH_X86 1
    #endif
    #ifndef NTL_BITS_PER_LONG
        #define NTL_BITS_PER_LONG 32
    #endif
    #ifndef NTL_BITS_PER_INT
        #define NTL_BITS_PER_INT 32
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64)
    #ifndef KCTSB_ARCH_ARM64
        #define KCTSB_ARCH_ARM64 1
    #endif
    #ifndef NTL_BITS_PER_LONG
        #define NTL_BITS_PER_LONG 64
    #endif
    #ifndef NTL_BITS_PER_INT
        #define NTL_BITS_PER_INT 32
    #endif
#endif

#ifndef NTL_BITS_PER_SIZE_T
    // sizeof() cannot be used in #if preprocessor, so use architecture-based value
    #if NTL_BITS_PER_LONG == 64
        #define NTL_BITS_PER_SIZE_T 64
    #else
        #define NTL_BITS_PER_SIZE_T 32
    #endif
#endif

// ============================================================================
// GMP Integration (Required)
// ============================================================================

// Force GMP usage - we do not use NTL's internal big integer implementation
#ifndef NTL_GMP_LIP
    #define NTL_GMP_LIP 1
#endif

// GMP limb configuration
#ifndef NTL_BITS_PER_LIMB_T
    #if NTL_BITS_PER_LONG == 64
        #define NTL_BITS_PER_LIMB_T 64
    #else
        #define NTL_BITS_PER_LIMB_T 32
    #endif
#endif

#ifndef NTL_ZZ_NBITS
    #if NTL_BITS_PER_LONG == 64
        #define NTL_ZZ_NBITS 60
    #else
        #define NTL_ZZ_NBITS 30
    #endif
#endif

#ifndef NTL_ZZ_FRADIX
    #define NTL_ZZ_FRADIX ((double)(1UL << NTL_ZZ_NBITS))
#endif

#ifndef NTL_ZZ_WIDE_FRADIX
    #define NTL_ZZ_WIDE_FRADIX ((double)(1UL << NTL_ZZ_NBITS))
#endif

// ============================================================================
// gf2x Library (Optional - enabled via CMake)
// ============================================================================

#ifdef KCTSB_HAS_GF2X
    #ifndef NTL_GF2X_LIB
        #define NTL_GF2X_LIB 1
    #endif
#endif

// ============================================================================
// C++ Standard
// ============================================================================

// kctsb requires C++17
#ifndef NTL_STD_CXX17
    #define NTL_STD_CXX17 1
#endif
#ifndef NTL_STD_CXX14
    #define NTL_STD_CXX14 1
#endif
#ifndef NTL_STD_CXX11
    #define NTL_STD_CXX11 1
#endif

// ============================================================================
// Threading Configuration
// ============================================================================

#ifndef NTL_THREADS
    #define NTL_THREADS 1
#endif

#ifndef NTL_THREAD_BOOST
    #define NTL_THREAD_BOOST 1
#endif

// ============================================================================
// Exception Handling
// ============================================================================

#ifndef NTL_EXCEPTIONS
    #define NTL_EXCEPTIONS 1
#endif

// ============================================================================
// Hardware Acceleration (auto-detected by compiler)
// ============================================================================

// These are detected via compiler intrinsics and __GNUC__ macros
// See NTL's ALL_FEATURES.h for details

#ifndef NTL_HAVE_LL_TYPE
    #define NTL_HAVE_LL_TYPE 1
#endif

#ifndef NTL_HAVE_BUILTIN_CLZL
    #if defined(__GNUC__) || defined(__clang__)
        #define NTL_HAVE_BUILTIN_CLZL 1
    #endif
#endif

#ifndef NTL_HAVE_ALIGNED_ARRAY
    #define NTL_HAVE_ALIGNED_ARRAY 1
#endif

#ifndef NTL_HAVE_COPY_TRAITS1
    #define NTL_HAVE_COPY_TRAITS1 1
#endif

#ifndef NTL_HAVE_COPY_TRAITS2
    #define NTL_HAVE_COPY_TRAITS2 1
#endif

#ifndef NTL_HAVE_CHRONO_TIME
    #define NTL_HAVE_CHRONO_TIME 1
#endif

// ============================================================================
// Performance Tuning
// ============================================================================

#ifndef NTL_FFT_THRESH
    #define NTL_FFT_THRESH 16
#endif

#ifndef NTL_FFT_BIGTAB_THRESH
    #define NTL_FFT_BIGTAB_THRESH 4096
#endif

#ifndef NTL_NBITS_MAX
    #define NTL_NBITS_MAX ((NTL_BITS_PER_LONG) - 2)
#endif

#ifndef NTL_MAX_ALLOC_BLOCK
    #define NTL_MAX_ALLOC_BLOCK 40000
#endif

#ifndef NTL_RELEASE_THRESH
    #define NTL_RELEASE_THRESH 128
#endif

// ============================================================================
// Type Definitions
// ============================================================================

#ifndef NTL_LL_TYPE
    #if NTL_BITS_PER_LONG == 64
        #ifdef __GNUC__
            #define NTL_LL_TYPE __int128_t
            #define NTL_ULL_TYPE __uint128_t
        #elif defined(_MSC_VER)
            #define NTL_LL_TYPE __int128
            #define NTL_ULL_TYPE unsigned __int128
        #endif
    #else
        #define NTL_LL_TYPE long long
        #define NTL_ULL_TYPE unsigned long long
    #endif
#endif

#endif // KCTSB_NTL_CONFIG_H
