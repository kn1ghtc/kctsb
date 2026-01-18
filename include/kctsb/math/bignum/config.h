/**
 * @file config.h
 * @brief NTL configuration for kctsb integration
 *
 * This is a kctsb-specific replacement for NTL's auto-generated config.h.
 * All configuration is handled by kctsb_ntl_config.h with compile-time detection.
 *
 * All macros use #ifndef guards to avoid redefinition conflicts
 * with NTL's original headers.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef NTL_config__H
#define NTL_config__H

// Include kctsb's unified NTL configuration
#include "kctsb_ntl_config.h"

// ============================================================================
// GMP Configuration (Required)
// ============================================================================

// NTL uses GMP for big integer arithmetic
#ifndef NTL_GMP_LIP
#define NTL_GMP_LIP
#endif

// ============================================================================
// gf2x Configuration (Optional - enabled via CMake)
// ============================================================================

// NTL uses gf2x for GF(2) polynomial multiplication if available
// This is defined by CMake when gf2x library is found
#ifdef KCTSB_HAS_GF2X
#ifndef NTL_GF2X_LIB
#define NTL_GF2X_LIB
#endif
#endif

// ============================================================================
// Threading Configuration
// ============================================================================

// Enable thread support (using C++11 threads, not pthreads)
#ifndef NTL_THREADS
#define NTL_THREADS
#endif

// Use standard C++11 thread-local storage
#ifndef NTL_THREAD_BOOST
#define NTL_THREAD_BOOST
#endif

// ============================================================================
// C++ Standard Configuration
// ============================================================================

// kctsb requires C++17
#ifndef NTL_STD_CXX17
#define NTL_STD_CXX17
#endif
#ifndef NTL_STD_CXX14
#define NTL_STD_CXX14
#endif
#ifndef NTL_STD_CXX11
#define NTL_STD_CXX11
#endif

// ============================================================================
// Exception Handling
// ============================================================================

// Enable exceptions (kctsb uses C++ internally)
#ifndef NTL_EXCEPTIONS
#define NTL_EXCEPTIONS
#endif

// ============================================================================
// Safe Vectors (bounds checking)
// ============================================================================

// Enable safe vectors in debug mode
#ifdef KCTSB_DEBUG
#ifndef NTL_SAFE_VECTORS
#define NTL_SAFE_VECTORS
#endif
#endif

// ============================================================================
// Performance Tuning
// ============================================================================

// FFT threshold values (optimized for modern CPUs)
#ifndef NTL_FFT_THRESH
#define NTL_FFT_THRESH 16
#endif
#ifndef NTL_FFT_BIGTAB_THRESH
#define NTL_FFT_BIGTAB_THRESH 4096
#endif

// ============================================================================
// Numeric Limits (for 64-bit platforms)
// ============================================================================

// These are set in kctsb_ntl_config.h based on platform detection

#endif // NTL_config__H
