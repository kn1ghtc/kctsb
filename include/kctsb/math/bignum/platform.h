/**
 * @file platform.h
 * @brief kctsb Platform-independent type definitions for bignum module
 *
 * This file resolves the Windows LLP64 vs Unix LP64 data model differences:
 * - Windows x64: sizeof(long) = 4, sizeof(long long) = 8
 * - Linux/macOS x64: sizeof(long) = 8, sizeof(long long) = 8
 *
 * We define kctsb_long_t as a platform-independent 64-bit signed type
 * to be used throughout the bignum module, replacing bignum's long dependencies.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_BIGNUM_PLATFORM_H
#define KCTSB_BIGNUM_PLATFORM_H

#include <cstdint>
#include <cstddef>
#include <climits>

// ============================================================================
// Platform Detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #define KCTSB_PLATFORM_WINDOWS 1
#elif defined(__linux__)
    #define KCTSB_PLATFORM_LINUX 1
#elif defined(__APPLE__)
    #define KCTSB_PLATFORM_MACOS 1
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
    #define KCTSB_ARCH_64BIT 1
#else
    #define KCTSB_ARCH_32BIT 1
#endif

// ============================================================================
// Unified Integer Types for Bignum
// ============================================================================
// These types provide consistent semantics across all platforms.
// Using int64_t/uint64_t ensures 64-bit width on both LLP64 (Windows)
// and LP64 (Linux/macOS) data models.

namespace kctsb {

/**
 * @brief Platform-independent signed word type (always 64-bit on 64-bit platforms)
 * Replaces bignum's 'long' which has different sizes on different platforms.
 */
#ifdef KCTSB_ARCH_64BIT
using word_t = std::int64_t;
using uword_t = std::uint64_t;
constexpr int BITS_PER_WORD = 64;
#else
using word_t = std::int32_t;
using uword_t = std::uint32_t;
constexpr int BITS_PER_WORD = 32;
#endif

/**
 * @brief Platform-independent double-word type for overflow handling
 */
#ifdef KCTSB_ARCH_64BIT
    #if defined(__GNUC__) || defined(__clang__)
        using dword_t = __int128_t;
        using udword_t = __uint128_t;
        #define KCTSB_HAS_INT128 1
    #elif defined(_MSC_VER)
        // MSVC doesn't have native 128-bit types, use software emulation
        #define KCTSB_NO_INT128 1
    #endif
#else
using dword_t = std::int64_t;
using udword_t = std::uint64_t;
#endif

// Type aliases for backward compatibility with bignum-style code
using zz_limb_t = uword_t;  // Limb type for big integers (replaces mp_limb_t)

} // namespace kctsb

// ============================================================================
// C-compatible type definitions (for extern "C" interfaces)
// ============================================================================

typedef std::int64_t kctsb_slong;    // Signed 64-bit (replaces long on LP64)
typedef std::uint64_t kctsb_ulong;   // Unsigned 64-bit
typedef std::int32_t kctsb_sint;     // Signed 32-bit
typedef std::uint32_t kctsb_uint;    // Unsigned 32-bit

// ============================================================================
// bignum Compatibility Macros (to be phased out)
// ============================================================================
// These macros provide source-level compatibility with existing code
// while ensuring correct bit widths across platforms.

// Always use 64 bits for word operations on 64-bit platforms
#ifdef KCTSB_ARCH_64BIT
    #define KCTSB_BITS_PER_WORD 64
    #define KCTSB_WORD_MAX INT64_MAX
    #define KCTSB_WORD_MIN INT64_MIN
    #define KCTSB_UWORD_MAX UINT64_MAX
#else
    #define KCTSB_BITS_PER_WORD 32
    #define KCTSB_WORD_MAX INT32_MAX
    #define KCTSB_WORD_MIN INT32_MIN
    #define KCTSB_UWORD_MAX UINT32_MAX
#endif

// For sizeof expressions
#define KCTSB_SIZEOF_WORD (KCTSB_BITS_PER_WORD / 8)

// Pointer size (same across LLP64 and LP64 for 64-bit platforms)
#ifdef KCTSB_ARCH_64BIT
    #define KCTSB_BITS_PER_POINTER 64
#else
    #define KCTSB_BITS_PER_POINTER 32
#endif

// size_t bits - use compile-time constant, not sizeof()
// Note: sizeof() cannot be used in #if preprocessor directives
#ifndef KCTSB_BITS_PER_SIZE_T
    #ifdef KCTSB_ARCH_64BIT
        #define KCTSB_BITS_PER_SIZE_T 64
    #else
        #define KCTSB_BITS_PER_SIZE_T 32
    #endif
#endif

// ============================================================================
// Compile-time assertions
// ============================================================================

static_assert(sizeof(kctsb::word_t) * CHAR_BIT == KCTSB_BITS_PER_WORD,
              "word_t size mismatch");
static_assert(sizeof(kctsb::uword_t) * CHAR_BIT == KCTSB_BITS_PER_WORD,
              "uword_t size mismatch");

#ifdef KCTSB_ARCH_64BIT
static_assert(sizeof(kctsb_slong) == 8, "kctsb_slong must be 64-bit");
static_assert(sizeof(kctsb_ulong) == 8, "kctsb_ulong must be 64-bit");
#endif

#endif // KCTSB_BIGNUM_PLATFORM_H
