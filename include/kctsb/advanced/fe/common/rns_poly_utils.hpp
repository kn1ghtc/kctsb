/**
 * @file rns_poly_utils.hpp
 * @brief RNS Polynomial Utility Functions
 * 
 * Helper functions for RNSPoly operations including arithmetic,
 * sampling, and CRT reconstruction.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.10.0
 * @since Phase 4c optimization
 */

#ifndef KCTSB_FHE_RNS_POLY_UTILS_HPP
#define KCTSB_FHE_RNS_POLY_UTILS_HPP

#include "rns_poly.hpp"
#include <random>
#include <vector>
#include <cstdint>

namespace kctsb {
namespace fhe {

// ============================================================================
// Arithmetic Operations
// ============================================================================

/**
 * @brief Add two RNS polynomials and return result
 * @param a First polynomial
 * @param b Second polynomial
 * @return Result polynomial (same NTT form as inputs)
 */
RNSPoly poly_add(const RNSPoly& a, const RNSPoly& b);

/**
 * @brief Add polynomial b to a (in-place)
 * @param a Target polynomial (modified)
 * @param b Source polynomial
 */
void poly_add_inplace(RNSPoly& a, const RNSPoly& b);

/**
 * @brief Subtract polynomial b from a (in-place)
 * @param a Target polynomial (modified)
 * @param b Source polynomial
 */
void poly_sub_inplace(RNSPoly& a, const RNSPoly& b);

/**
 * @brief Negate polynomial (in-place)
 * @param poly Polynomial to negate
 */
void poly_negate_inplace(RNSPoly& poly);

/**
 * @brief Multiply polynomial by scalar (in-place)
 * @param poly Target polynomial
 * @param scalar Scalar multiplier
 */
void poly_multiply_scalar_inplace(RNSPoly& poly, uint64_t scalar);

// ============================================================================
// Sampling Functions
// ============================================================================

/**
 * @brief Sample uniform random polynomial in [0, q_i) for each level
 * @param out Output polynomial (must be pre-allocated with context)
 * @param rng Random number generator
 */
void sample_uniform_rns(RNSPoly* out, std::mt19937_64& rng);

/**
 * @brief Sample ternary polynomial from {-1, 0, 1} distribution
 * @param out Output polynomial (coefficient form)
 * @param rng Random number generator
 * @note Output is in coefficient form, caller should NTT if needed
 */
void sample_ternary_rns(RNSPoly* out, std::mt19937_64& rng);

/**
 * @brief Sample polynomial from discrete Gaussian distribution
 * @param out Output polynomial (coefficient form)
 * @param rng Random number generator
 * @param sigma Standard deviation (typically 3.2)
 * @note Output is in coefficient form, caller should NTT if needed
 */
void sample_gaussian_rns(RNSPoly* out, std::mt19937_64& rng, double sigma);

// ============================================================================
// CRT Reconstruction
// ============================================================================

/**
 * @brief Reconstruct integer coefficients from RNS representation using CRT
 * @param poly RNS polynomial in coefficient form
 * @param out Output coefficient vector (must be pre-allocated with size n)
 * @note Input polynomial must NOT be in NTT form
 */
void crt_reconstruct_rns(const RNSPoly& poly, std::vector<uint64_t>& out);

/**
 * @brief Reduce x modulo modulus to [0, modulus)
 * 
 * @param x Input value
 * @param modulus Modulus value
 * @return x mod modulus
 */
uint64_t balance_mod(uint64_t x, uint64_t modulus);

/**
 * @brief CRT reconstruction returning full __int128 precision
 * 
 * Same as crt_reconstruct_rns but returns __int128 values to
 * preserve full precision for BGV scaling calculations.
 * 
 * @param poly RNS polynomial in coefficient form
 * @param out Output coefficient vector with __int128 precision
 * @note Input polynomial must NOT be in NTT form
 */
void crt_reconstruct_rns_128(const RNSPoly& poly, std::vector<__int128>& out);

/**
 * @brief Compute product of all RNS moduli Q = q_0 * q_1 * ... * q_{L-1}
 * 
 * @param context RNS context
 * @return Product Q as __int128
 */
__int128 compute_Q_product(const RNSContext* context);

} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_RNS_POLY_UTILS_HPP
