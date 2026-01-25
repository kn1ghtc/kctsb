/**
 * @file math.h
 * @brief Unified mathematical utilities header for kctsb library
 * 
 * This header provides compatibility with legacy opentsb code and exposes
 * all mathematical functions including bignum-based high precision arithmetic.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_MATH_MATH_H
#define KCTSB_MATH_MATH_H

// Include core common definitions
#include "kctsb/core/common.h"

// Include C-style math functions
#include "kctsb/math/common.h"
#include "kctsb/math/polynomials.h"
#include "kctsb/math/vector.h"

#ifdef __cplusplus

// bignum support for high-precision arithmetic
#ifdef KCTSB_HAS_BIGNUM_MODULES
#include <kctsb/math/bignum/ZZ.h>
#include <kctsb/math/bignum/ZZX.h>
#include <kctsb/math/bignum/GF2X.h>
#include <kctsb/math/bignum/vec_ZZ.h>
#include <kctsb/math/bignum/mat_ZZ.h>
#include <kctsb/math/bignum/mat_GF2.h>
#include <kctsb/math/bignum/mat_GF2E.h>
#include <kctsb/math/bignum/mat_ZZ_p.h>
#include <vector>

namespace kctsb {
namespace math {

/**
 * @brief Compute LCM of two bignum big integers
 * @param result Output LCM
 * @param x First operand
 * @param y Second operand
 */
void lcm(kctsb::ZZ& result, const kctsb::ZZ& x, const kctsb::ZZ& y);

/**
 * @brief Compute LCM or GCD of a vector of bignum big integers
 * @param v Input vector
 * @param mode 1 for LCM, 2 for GCD
 * @return Vector of intermediate results
 */
kctsb::vec_ZZ lcm_gcd_vec(const kctsb::vec_ZZ& v, int mode);

/**
 * @brief Compute LCM or GCD of multiple numbers to single result
 * @param v Input vector
 * @param mode 1 for LCM, 2 for GCD
 * @param endlen Output length (will be 1)
 * @return Vector with single result
 */
kctsb::vec_ZZ lcm_gcd_vec(const kctsb::vec_ZZ& v, int mode, long endlen);

/**
 * @brief Convert C-style array to bignum vector
 * @param arr Input array
 * @param v Output vector
 * @param len Array length
 */
void array_to_vec(const kctsb::ZZ arr[], kctsb::vec_ZZ& v, long len);
void array_to_vec(const int arr[], kctsb::vec_ZZ& v, long len);
void array_to_vec(const long arr[], kctsb::vec_ZZ& v, long len);

/**
 * @brief Polynomial reduction modulo prime
 * @param f Input polynomial
 * @param mod Modulus polynomial
 * @param p Prime modulus
 * @return Reduced polynomial
 */
kctsb::ZZX poly_reduce_mod(const kctsb::ZZX& f, const kctsb::ZZX& mod, const kctsb::ZZ& p);

} // namespace math
} // namespace kctsb

#endif // KCTSB_HAS_BIGNUM_MODULES

#endif // __cplusplus

#endif // KCTSB_MATH_MATH_H
