/**
 * @file config.h
 * @brief bignum configuration for kctsb integration
 *
 * This is a kctsb-specific replacement for bignum's auto-generated config.h.
 * All configuration is handled by kctsb_bignum_config.h with compile-time detection.
 *
 * All macros use #ifndef guards to avoid redefinition conflicts
 * with bignum's original headers.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_config__H
#define KCTSB_config__H

// Include kctsb's unified bignum configuration
#include "kctsb_bignum_config.h"

// ============================================================================
// GMP Configuration (Required)
// ============================================================================

// bignum uses GMP for big integer arithmetic
#ifndef KCTSB_GMP_LIP
#define KCTSB_GMP_LIP
#endif

// ============================================================================
// gf2x Configuration (Optional - enabled via CMake)
// ============================================================================

// bignum uses gf2x for GF(2) polynomial multiplication if available
// This is defined by CMake when gf2x library is found
#ifdef KCTSB_HAS_GF2X
#ifndef KCTSB_GF2X_LIB
#define KCTSB_GF2X_LIB
#endif
#endif

// ============================================================================
// Threading Configuration
// ============================================================================

// Enable thread support (using C++11 threads, not pthreads)
#ifndef KCTSB_THREADS
#define KCTSB_THREADS
#endif

// Use standard C++11 thread-local storage
#ifndef KCTSB_THREAD_BOOST
#define KCTSB_THREAD_BOOST
#endif

// ============================================================================
// C++ Standard Configuration
// ============================================================================

// kctsb requires C++17
#ifndef KCTSB_STD_CXX17
#define KCTSB_STD_CXX17
#endif
#ifndef KCTSB_STD_CXX14
#define KCTSB_STD_CXX14
#endif
#ifndef KCTSB_STD_CXX11
#define KCTSB_STD_CXX11
#endif

// ============================================================================
// Exception Handling
// ============================================================================

// Enable exceptions (kctsb uses C++ internally)
#ifndef KCTSB_EXCEPTIONS
#define KCTSB_EXCEPTIONS
#endif

// ============================================================================
// Safe Vectors (bounds checking)
// ============================================================================

// Enable safe vectors in debug mode
#ifdef KCTSB_DEBUG
#ifndef KCTSB_SAFE_VECTORS
#define KCTSB_SAFE_VECTORS
#endif
#endif

// ============================================================================
// Performance Tuning
// ============================================================================

// FFT threshold values (optimized for modern CPUs)
#ifndef KCTSB_FFT_THRESH
#define KCTSB_FFT_THRESH 16
#endif
#ifndef KCTSB_FFT_BIGTAB_THRESH
#define KCTSB_FFT_BIGTAB_THRESH 4096
#endif

// ============================================================================
// Numeric Limits (for 64-bit platforms)
// ============================================================================

// These are set in kctsb_kctsb_config.h based on platform detection

#endif // KCTSB_config__H
