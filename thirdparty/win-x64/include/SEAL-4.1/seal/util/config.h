// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
// 
// Generated configuration for SEAL 4.1 (MinGW-w64/GCC)
// This is a manually created config for kctsb benchmark integration

#pragma once

#define SEAL_VERSION "4.1.2"
#define SEAL_VERSION_MAJOR 4
#define SEAL_VERSION_MINOR 1
#define SEAL_VERSION_PATCH 2

// C++17 features - enabled for modern compilers
#define SEAL_USE_STD_BYTE
#define SEAL_USE_ALIGNED_ALLOC
#define SEAL_USE_SHARED_MUTEX
#define SEAL_USE_IF_CONSTEXPR
#define SEAL_USE_MAYBE_UNUSED
#define SEAL_USE_NODISCARD
#define SEAL_USE_STD_FOR_EACH_N

// Security settings
#define SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
// #define SEAL_USE_GAUSSIAN_NOISE  // Use uniform noise for performance
#define SEAL_DEFAULT_PRNG SEAL_DEFAULT_PRNG_BLAKE2XB
#define SEAL_AVOID_BRANCHING

// Intrinsics - MinGW-w64/GCC on Windows
#define SEAL_USE_INTRIN
// #define SEAL_USE__UMUL128  // MSVC only
// #define SEAL_USE__BITSCANREVERSE64  // MSVC only
#define SEAL_USE___BUILTIN_CLZLL
#define SEAL_USE___INT128
// #define SEAL_USE__ADDCARRY_U64  // MSVC only
// #define SEAL_USE__SUBBORROW_U64  // MSVC only

// Zero memory functions
// #define SEAL_USE_EXPLICIT_BZERO  // Not available on Windows
// #define SEAL_USE_EXPLICIT_MEMSET  // glibc only
// #define SEAL_USE_MEMSET_S  // Optional

// Third-party dependencies - disabled for minimal build
// #define SEAL_USE_MSGSL
// #define SEAL_USE_ZLIB
// #define SEAL_USE_ZSTD
// #define SEAL_USE_INTEL_HEXL  // Requires Intel HEXL library
