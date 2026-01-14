/**
 * @file math.h
 * @brief Unified mathematical utilities header for kctsb library
 * 
 * This header provides compatibility with legacy opentsb code and exposes
 * all mathematical functions including NTL-based high precision arithmetic.
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

// NTL support for high-precision arithmetic
#ifdef KCTSB_HAS_NTL
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>
#include <NTL/vec_ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_GF2.h>
#include <NTL/mat_GF2E.h>
#include <NTL/mat_ZZ_p.h>
#include <vector>

namespace kctsb {
namespace math {

/**
 * @brief Compute LCM of two NTL big integers
 * @param result Output LCM
 * @param x First operand
 * @param y Second operand
 */
void lcm(NTL::ZZ& result, const NTL::ZZ& x, const NTL::ZZ& y);

/**
 * @brief Compute LCM or GCD of a vector of NTL big integers
 * @param v Input vector
 * @param mode 1 for LCM, 2 for GCD
 * @return Vector of intermediate results
 */
NTL::vec_ZZ lcm_gcd_vec(const NTL::vec_ZZ& v, int mode);

/**
 * @brief Compute LCM or GCD of multiple numbers to single result
 * @param v Input vector
 * @param mode 1 for LCM, 2 for GCD
 * @param endlen Output length (will be 1)
 * @return Vector with single result
 */
NTL::vec_ZZ lcm_gcd_vec(const NTL::vec_ZZ& v, int mode, long endlen);

/**
 * @brief Convert C-style array to NTL vector
 * @param arr Input array
 * @param v Output vector
 * @param len Array length
 */
void array_to_vec(const NTL::ZZ arr[], NTL::vec_ZZ& v, long len);
void array_to_vec(const int arr[], NTL::vec_ZZ& v, long len);
void array_to_vec(const long arr[], NTL::vec_ZZ& v, long len);

/**
 * @brief Polynomial reduction modulo prime
 * @param f Input polynomial
 * @param mod Modulus polynomial
 * @param p Prime modulus
 * @return Reduced polynomial
 */
NTL::ZZX poly_reduce_mod(const NTL::ZZX& f, const NTL::ZZX& mod, const NTL::ZZ& p);

} // namespace math
} // namespace kctsb

// Legacy global function declarations for backward compatibility
void lcm(NTL::ZZ& k, const NTL::ZZ& x, const NTL::ZZ& y);
NTL::vec_ZZ lcm_gcd_vec(const NTL::vec_ZZ& v, int typemode);
NTL::vec_ZZ lcm_gcd_vec(const NTL::vec_ZZ& v, int typemode, long endleng);
void array_to_vec(const NTL::ZZ arr[], NTL::vec_ZZ& v, long len);
void array_to_vec(const int arr[], NTL::vec_ZZ& v, long len);
void array_to_vec(const long arr[], NTL::vec_ZZ& v, long len);

// Matrix conversion utilities
void array2_to_mat(const std::vector<std::vector<NTL::ZZ>> arr, NTL::mat_ZZ& v);
void array2_to_mat(const std::vector<std::vector<int>> arr, NTL::mat_ZZ& v);
void array2_to_mat(const std::vector<std::vector<int>> arr, NTL::mat_GF2& v);
void array2_to_mat(const std::vector<std::vector<NTL::ZZ>> arr, NTL::mat_GF2& v);
void array2_to_mat(const std::vector<std::vector<NTL::GF2>> arr, NTL::mat_GF2& v);
void array2_to_mat(const std::vector<std::vector<int>> arr, NTL::mat_GF2E& v);
void array2_to_mat(const std::vector<std::vector<int>> arr, NTL::mat_ZZ_p& v);

#endif // KCTSB_HAS_NTL

#endif // __cplusplus

#endif // KCTSB_MATH_MATH_H
