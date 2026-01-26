/**
 * @file bignum.h
 * @brief Self-Contained Bignum Module for kctsb v5.0
 * 
 * Unified header for arbitrary-precision arithmetic.
 * 
 * v5.0 Architecture:
 * - ZZ: Arbitrary-precision integers (replaces NTL::ZZ)
 * - ZZ_p: Integers modulo prime p (replaces NTL::ZZ_p)
 * - vec_ZZ: Vector of ZZ elements
 * - vec_ZZ_p: Vector of ZZ_p elements
 * - mat_ZZ: Matrix of ZZ elements (for crypto applications)
 * 
 * v5.1: Removed unused headers (GF2*, LLL, Factoring) to reduce compile time
 * 
 * All functionality is now self-contained with no external dependencies.
 * 
 * @example
 * @code
 * #include <kctsb/math/bignum.h>
 * 
 * kctsb::ZZ a = kctsb::ZZ::from_hex("123456789ABCDEF");
 * kctsb::ZZ b(42);
 * kctsb::ZZ c = a + b;
 * @endcode
 * 
 * @author knightc
 * @version 5.1.0 - Streamlined, unused headers removed
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_BIGNUM_MODULE_H
#define KCTSB_MATH_BIGNUM_MODULE_H

// Core ZZ implementation (arbitrary-precision integers)
#include "ZZ.h"

// Modular arithmetic (required for ECC/RSA/SM2)
#include "ZZ_p.h"

// Vector types (required for crypto operations)
#include "vec_ZZ.h"
#include "vec_ZZ_p.h"

// Polynomial types (required for FHE) - optional
#ifdef KCTSB_HAS_FHE
#include "ZZ_pX.h"
#endif

#endif // KCTSB_MATH_BIGNUM_MODULE_H
