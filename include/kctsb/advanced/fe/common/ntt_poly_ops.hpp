/**
 * @file ntt_poly_ops.hpp
 * @brief NTT-Accelerated Polynomial Operations for BGV Integration
 * 
 * Provides high-level polynomial operations using NTT acceleration.
 * Bridges between ZZ_pX (NTL-style) and native uint64_t NTT operations.
 * 
 * This module enables gradual migration from schoolbook to NTT multiplication
 * in BGV without requiring full architecture rewrite.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#ifndef KCTSB_ADVANCED_FE_COMMON_NTT_POLY_OPS_HPP
#define KCTSB_ADVANCED_FE_COMMON_NTT_POLY_OPS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

#include "kctsb/advanced/fe/common/ntt.hpp"

namespace kctsb {
namespace fhe {
namespace ntt {

// ============================================================================
// High-Performance Polynomial Operations
// ============================================================================

/**
 * @brief Multiply two polynomials using NTT (negacyclic convolution)
 * 
 * Computes c = a * b mod (x^n + 1, q) in O(n log n) time.
 * This is the core operation for BGV/BFV/CKKS polynomial rings.
 * 
 * Requirements:
 * - q must be NTT-friendly: q = 1 (mod 2n)
 * - a and b must have exactly n coefficients
 * - All coefficients must be < q
 * 
 * @param a First polynomial (n coefficients)
 * @param b Second polynomial (n coefficients)
 * @param n Polynomial degree (power of 2)
 * @param q NTT-friendly modulus
 * @return Product polynomial (n coefficients)
 */
std::vector<uint64_t> multiply_poly_ntt(
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    size_t n,
    uint64_t q);

/**
 * @brief In-place polynomial multiplication
 * 
 * Result stored in first operand.
 */
void multiply_poly_ntt_inplace(
    std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q);

/**
 * @brief Add two polynomials coefficient-wise modulo q
 */
void add_poly_mod(
    std::vector<uint64_t>& result,
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q);

/**
 * @brief Subtract two polynomials coefficient-wise modulo q
 */
void sub_poly_mod(
    std::vector<uint64_t>& result,
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q);

/**
 * @brief Negate polynomial coefficients modulo q
 */
void negate_poly_mod(
    std::vector<uint64_t>& poly,
    uint64_t q);

/**
 * @brief Multiply polynomial by scalar modulo q
 */
void scalar_mul_poly_mod(
    std::vector<uint64_t>& poly,
    uint64_t scalar,
    uint64_t q);

// ============================================================================
// Batch Operations (Multiple Moduli - RNS)
// ============================================================================

/**
 * @brief Multiply polynomials across multiple moduli (RNS style)
 * 
 * For each modulus q_i in the list, computes:
 *   result[i] = a[i] * b[i] mod (x^n + 1, q_i)
 * 
 * @param a Vector of polynomial coefficient arrays (one per modulus)
 * @param b Vector of polynomial coefficient arrays (one per modulus)
 * @param n Polynomial degree
 * @param moduli List of NTT-friendly moduli
 * @return Product polynomials for each modulus
 */
std::vector<std::vector<uint64_t>> multiply_poly_ntt_rns(
    const std::vector<std::vector<uint64_t>>& a,
    const std::vector<std::vector<uint64_t>>& b,
    size_t n,
    const std::vector<uint64_t>& moduli);

// ============================================================================
// Conversion Utilities
// ============================================================================

/**
 * @brief Convert coefficient polynomial to NTT form
 * 
 * @param coeffs Coefficient representation (input/output)
 * @param n Polynomial degree
 * @param q Modulus
 */
void to_ntt_form(
    std::vector<uint64_t>& coeffs,
    size_t n,
    uint64_t q);

/**
 * @brief Convert NTT form back to coefficient representation
 */
void from_ntt_form(
    std::vector<uint64_t>& ntt_vals,
    size_t n,
    uint64_t q);

/**
 * @brief Check if a modulus is suitable for NTT with given degree
 */
inline bool is_ntt_compatible(uint64_t q, size_t n) {
    return is_ntt_prime(q, n);
}

}  // namespace ntt
}  // namespace fhe
}  // namespace kctsb

#endif  // KCTSB_ADVANCED_FE_COMMON_NTT_POLY_OPS_HPP
