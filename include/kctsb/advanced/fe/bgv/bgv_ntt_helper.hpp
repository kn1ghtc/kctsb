/**
 * @file bgv_ntt_helper.hpp
 * @brief BGV-NTT Integration Helper Functions
 * 
 * Provides conversion utilities between BGV's ZZ_pX polynomials and 
 * NTT's uint64_t coefficient vectors for accelerated polynomial multiplication.
 * 
 * This bridge layer enables gradual migration from schoolbook O(n²) to NTT O(n log n).
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#ifndef KCTSB_ADVANCED_FE_BGV_NTT_HELPER_HPP
#define KCTSB_ADVANCED_FE_BGV_NTT_HELPER_HPP

#include "kctsb/advanced/fe/bgv/bgv_types.hpp"
#include "kctsb/advanced/fe/common/ntt_poly_ops.hpp"
#include <vector>
#include <cstdint>

namespace kctsb {
namespace fhe {
namespace bgv {

/**
 * @brief Check if parameters support NTT acceleration
 * 
 * NTT acceleration is available when:
 * 1. n is a power of 2
 * 2. All RNS primes are NTT-friendly (= 1 mod 2n)
 * 
 * @param n Ring degree
 * @param primes RNS primes
 * @return true if NTT can be used
 */
inline bool can_use_ntt(uint64_t n, const std::vector<uint64_t>& primes) {
    // Check n is power of 2
    if (n == 0 || (n & (n - 1)) != 0) {
        return false;
    }
    
    // Check all primes are NTT-friendly
    for (uint64_t q : primes) {
        if (!ntt::is_ntt_prime(q, n)) {
            return false;
        }
    }
    
    return !primes.empty();
}

/**
 * @brief Convert ZZ_pX polynomial to uint64_t coefficient vector
 * 
 * Extracts coefficients from ZZ_pX format to uint64_t vector.
 * Assumes all coefficients fit in 64 bits (which is true for RNS representation).
 * 
 * @param poly Input polynomial in ZZ_pX format
 * @param n Target size (padded with zeros if smaller)
 * @return Coefficient vector of size n
 */
inline std::vector<uint64_t> zz_px_to_uint64(const ZZ_pX& poly, size_t n) {
    std::vector<uint64_t> result(n, 0);
    
    long degree = deg(poly);
    for (long i = 0; i <= degree && static_cast<size_t>(i) < n; ++i) {
        ZZ_p c = coeff(poly, i);
        ZZ z = rep(c);  // Get representative
        
        // Convert to uint64_t (assumes it fits)
        if (IsZero(z)) {
            result[i] = 0;
        } else {
            result[i] = to_ulong(z);
        }
    }
    
    return result;
}

/**
 * @brief Convert uint64_t coefficient vector to ZZ_pX polynomial
 * 
 * Reconstructs ZZ_pX polynomial from uint64_t coefficients.
 * Must call ZZ_p::init() with appropriate modulus before calling.
 * 
 * @param coeffs Coefficient vector
 * @return Polynomial in ZZ_pX format
 */
inline ZZ_pX uint64_to_zz_px(const std::vector<uint64_t>& coeffs) {
    ZZ_pX result;
    clear(result);
    
    for (size_t i = 0; i < coeffs.size(); ++i) {
        if (coeffs[i] != 0) {
            SetCoeff(result, static_cast<long>(i), conv<ZZ_p>(to_ZZ(coeffs[i])));
        }
    }
    
    return result;
}

/**
 * @brief Multiply two ZZ_pX polynomials using NTT acceleration
 * 
 * Uses NTT for O(n log n) multiplication in ring R_q = Z_q[x]/(x^n + 1).
 * This is the negacyclic convolution needed for power-of-2 cyclotomic rings.
 * 
 * @param a First polynomial
 * @param b Second polynomial
 * @param n Ring degree (must be power of 2)
 * @param q Modulus (must be NTT-friendly)
 * @return Product a * b mod (x^n + 1) mod q
 */
inline ZZ_pX multiply_ntt(const ZZ_pX& a, const ZZ_pX& b, size_t n, uint64_t q) {
    // Convert to uint64_t vectors
    auto a_vec = zz_px_to_uint64(a, n);
    auto b_vec = zz_px_to_uint64(b, n);
    
    // NTT multiply
    auto result_vec = ntt::multiply_poly_ntt(a_vec, b_vec, n, q);
    
    // Set modulus context and convert back
    ZZ_p::init(to_ZZ(q));
    return uint64_to_zz_px(result_vec);
}

/**
 * @brief Multiply polynomials using RNS-NTT acceleration
 * 
 * Performs multiplication using RNS decomposition with NTT for each prime.
 * Results are computed mod each prime and can be recombined via CRT if needed.
 * 
 * For BGV evaluator, we keep results in RNS form throughout computations
 * and only recombine when necessary (e.g., for decryption or modulus switching).
 * 
 * @param a First polynomial (in coefficient form mod q_i)
 * @param b Second polynomial (in coefficient form mod q_i)
 * @param n Ring degree
 * @param primes RNS prime moduli
 * @return Product polynomials, one per prime level
 */
inline std::vector<ZZ_pX> multiply_rns_ntt(
    const ZZ_pX& a,
    const ZZ_pX& b,
    size_t n,
    const std::vector<uint64_t>& primes)
{
    std::vector<ZZ_pX> results;
    results.reserve(primes.size());
    
    for (uint64_t q : primes) {
        // Set modulus context
        ZZ_p::init(to_ZZ(q));
        
        // Convert, multiply, convert back
        auto a_vec = zz_px_to_uint64(a, n);
        auto b_vec = zz_px_to_uint64(b, n);
        auto result_vec = ntt::multiply_poly_ntt(a_vec, b_vec, n, q);
        
        results.push_back(uint64_to_zz_px(result_vec));
    }
    
    return results;
}

/**
 * @brief Reduce polynomial coefficients modulo a prime
 * 
 * Useful when converting from large modulus to RNS representation.
 * 
 * @param poly Input polynomial (coefficients as ZZ)
 * @param q Target modulus
 * @return Polynomial with coefficients reduced mod q
 */
inline std::vector<uint64_t> reduce_to_prime(const ZZ_pX& poly, size_t n, uint64_t q) {
    std::vector<uint64_t> result(n, 0);
    
    long degree = deg(poly);
    for (long i = 0; i <= degree && static_cast<size_t>(i) < n; ++i) {
        ZZ_p c = coeff(poly, i);
        ZZ z = rep(c);
        
        // Reduce mod q
        ZZ reduced = z % to_ZZ(q);
        if (IsZero(reduced)) {
            result[i] = 0;
        } else {
            result[i] = to_ulong(reduced);
        }
    }
    
    return result;
}

/**
 * @brief CRT reconstruction of a coefficient from RNS representation
 * 
 * Given residues r_0, r_1, ..., r_{k-1} where r_i = x mod q_i,
 * reconstruct x mod Q where Q = q_0 * q_1 * ... * q_{k-1}.
 * 
 * Uses the formula: x = sum_i (r_i * Q_i * (Q_i^{-1} mod q_i)) mod Q
 * where Q_i = Q / q_i.
 * 
 * @param residues Residues [r_0, r_1, ..., r_{k-1}]
 * @param primes Moduli [q_0, q_1, ..., q_{k-1}]
 * @return Reconstructed value mod Q
 */
inline ZZ crt_reconstruct(
    const std::vector<uint64_t>& residues,
    const std::vector<uint64_t>& primes)
{
    if (residues.size() != primes.size()) {
        throw std::invalid_argument("Residues and primes size mismatch");
    }
    
    size_t k = primes.size();
    
    // Compute Q = prod(q_i)
    ZZ Q = conv<ZZ>(1);
    for (uint64_t q : primes) {
        Q *= to_ZZ(q);
    }
    
    // CRT reconstruction
    ZZ result = conv<ZZ>(0);
    for (size_t i = 0; i < k; ++i) {
        ZZ q_i = to_ZZ(primes[i]);
        ZZ Q_i = Q / q_i;                    // Q_i = Q / q_i
        ZZ Q_i_inv = InvMod(Q_i % q_i, q_i); // Q_i^{-1} mod q_i
        
        ZZ term = to_ZZ(residues[i]) * Q_i * Q_i_inv;
        result += term;
    }
    
    return result % Q;
}

/**
 * @brief CRT reconstruct polynomial from RNS representation
 * 
 * Reconstructs a polynomial mod Q from its RNS components mod each q_i.
 * 
 * @param rns_polys Polynomials in RNS representation [poly mod q_0, poly mod q_1, ...]
 * @param n Ring degree
 * @param primes RNS primes
 * @param Q Full modulus (product of primes)
 * @return Polynomial with coefficients mod Q
 */
inline ZZ_pX crt_reconstruct_poly(
    const std::vector<std::vector<uint64_t>>& rns_polys,
    size_t n,
    const std::vector<uint64_t>& primes,
    const ZZ& Q)
{
    // Set modulus context to full Q
    ZZ_p::init(Q);
    
    ZZ_pX result;
    clear(result);
    
    for (size_t j = 0; j < n; ++j) {
        // Collect residues for coefficient j
        std::vector<uint64_t> residues(primes.size());
        for (size_t i = 0; i < primes.size(); ++i) {
            residues[i] = rns_polys[i][j];
        }
        
        // CRT reconstruct coefficient j
        ZZ coef = crt_reconstruct(residues, primes);
        if (!IsZero(coef)) {
            SetCoeff(result, static_cast<long>(j), conv<ZZ_p>(coef));
        }
    }
    
    return result;
}

/**
 * @brief Full RNS-NTT multiplication with CRT reconstruction
 * 
 * Performs complete multiplication pipeline:
 * 1. Decompose inputs into RNS representation
 * 2. For each RNS level, perform NTT multiplication
 * 3. CRT reconstruct the result back to full modulus
 * 
 * This is the correct approach for BGV when q = prod(q_i).
 * 
 * @param a First polynomial (under full q modulus context)
 * @param b Second polynomial (under full q modulus context)
 * @param n Ring degree
 * @param primes RNS primes where q = prod(primes)
 * @param Q Full modulus q
 * @return Product a * b mod (x^n + 1) mod Q
 */
inline ZZ_pX multiply_rns_ntt_crt(
    const ZZ_pX& a,
    const ZZ_pX& b,
    size_t n,
    const std::vector<uint64_t>& primes,
    const ZZ& Q)
{
    size_t k = primes.size();
    
    // Step 1: Decompose polynomials into RNS representation
    std::vector<std::vector<uint64_t>> a_rns(k), b_rns(k);
    for (size_t i = 0; i < k; ++i) {
        a_rns[i] = reduce_to_prime(a, n, primes[i]);
        b_rns[i] = reduce_to_prime(b, n, primes[i]);
    }
    
    // Step 2: NTT multiply in each RNS level
    std::vector<std::vector<uint64_t>> result_rns(k);
    for (size_t i = 0; i < k; ++i) {
        result_rns[i] = ntt::multiply_poly_ntt(a_rns[i], b_rns[i], n, primes[i]);
    }
    
    // Step 3: CRT reconstruct back to full modulus
    return crt_reconstruct_poly(result_rns, n, primes, Q);
}

}  // namespace bgv
}  // namespace fhe
}  // namespace kctsb

#endif // KCTSB_ADVANCED_FE_BGV_NTT_HELPER_HPP
