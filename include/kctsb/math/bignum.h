/**
 * @file bignum.h
 * @brief Self-Contained Bignum Module for kctsb v5.0
 * 
 * Unified header for arbitrary-precision arithmetic.
 * 
 * v5.0 Architecture:
 * - ZZ: Arbitrary-precision integers (replaces NTL::ZZ)
 * - ZZ_p: Integers modulo prime p (replaces NTL::ZZ_p)
 * - ZZX: Polynomials over integers (replaces NTL::ZZX)
 * - ZZ_pX: Polynomials over Z/pZ (replaces NTL::ZZ_pX)
 * - GF2X: Polynomials over GF(2)
 * - mat_ZZ: Matrix of ZZ elements
 * - LLL: Lattice reduction
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
 * @version 5.0.0 - Self-contained, NTL removed
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_BIGNUM_MODULE_H
#define KCTSB_MATH_BIGNUM_MODULE_H

// Core ZZ implementation
#include "bignum/ZZ.h"

// Modular arithmetic
#include "bignum/ZZ_p.h"

// Polynomial arithmetic
#include "bignum/ZZX.h"
#include "bignum/ZZXFactoring.h"
#include "bignum/ZZ_pX.h"
#include "bignum/ZZ_pXFactoring.h"

// Binary field polynomials
#include "bignum/GF2X.h"
#include "bignum/mat_GF2.h"

// Vector types
#include "bignum/vec_ZZ.h"
#include "bignum/vec_ZZ_p.h"

// Matrix and vector types
#include "bignum/mat_ZZ.h"

// Lattice reduction
#include "bignum/LLL.h"

#endif // KCTSB_MATH_BIGNUM_MODULE_H
