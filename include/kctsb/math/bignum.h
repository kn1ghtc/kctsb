/**
 * @file bignum.h
 * @brief High-precision arithmetic module for kctsb
 *
 * This header provides the unified interface for kctsb's high-precision
 * mathematics library. All types are defined in the kctsb namespace.
 *
 * Features:
 * - Arbitrary-precision integers (ZZ)
 * - Modular arithmetic (ZZ_p, lzz_p)
 * - Finite fields (GF2, GF2E)
 * - Polynomials (ZZX, GF2X, etc.)
 * - Linear algebra (matrices, vectors)
 * - Lattice algorithms (LLL, HNF)
 * - FFT operations
 *
 * @example
 * @code
 * #include <kctsb/math/bignum.h>
 * 
 * kctsb::ZZ a, b, c;
 * a = kctsb::conv<kctsb::ZZ>("123456789012345678901234567890");
 * b = 42;
 * c = a + b;
 * @endcode
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_BIGNUM_MODULE_H
#define KCTSB_MATH_BIGNUM_MODULE_H

#include "bignum/ntl.h"

#endif // KCTSB_MATH_BIGNUM_MODULE_H
