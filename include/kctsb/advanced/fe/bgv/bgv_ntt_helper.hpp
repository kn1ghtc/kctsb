/**
 * @file bgv_ntt_helper.hpp
 * @brief BGV-NTT Integration Helper Functions (Pure RNS Version)
 * 
 * Provides NTT-related utility functions for the Pure RNS BGV implementation.
 * Uses native kctsb bignum module (no external NTL dependency).
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.12.0
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
 * @brief Multiply two coefficient vectors using NTT
 * 
 * Pure RNS version without NTL dependency.
 * Uses NTT for O(n log n) multiplication in ring R_q = Z_q[x]/(x^n + 1).
 * 
 * @param a First coefficient vector
 * @param b Second coefficient vector
 * @param n Ring degree (must be power of 2)
 * @param q Modulus (must be NTT-friendly)
 * @return Product a * b mod (x^n + 1) mod q
 */
inline std::vector<uint64_t> multiply_ntt_pure(
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    size_t n,
    uint64_t q)
{
    return ntt::multiply_poly_ntt(a, b, n, q);
}

/**
 * @brief Multiply polynomials using RNS-NTT (Pure RNS version)
 * 
 * Performs multiplication using RNS decomposition with NTT for each prime.
 * Results are kept in RNS form for efficiency.
 * 
 * @param a_rns First polynomial in RNS form [coeffs_mod_q0, coeffs_mod_q1, ...]
 * @param b_rns Second polynomial in RNS form
 * @param n Ring degree
 * @param primes RNS prime moduli
 * @return Product polynomials in RNS form
 */
inline std::vector<std::vector<uint64_t>> multiply_rns_ntt_pure(
    const std::vector<std::vector<uint64_t>>& a_rns,
    const std::vector<std::vector<uint64_t>>& b_rns,
    size_t n,
    const std::vector<uint64_t>& primes)
{
    if (a_rns.size() != primes.size() || b_rns.size() != primes.size()) {
        throw std::invalid_argument("RNS representation size mismatch");
    }
    
    std::vector<std::vector<uint64_t>> results;
    results.reserve(primes.size());
    
    for (size_t i = 0; i < primes.size(); ++i) {
        auto result = ntt::multiply_poly_ntt(a_rns[i], b_rns[i], n, primes[i]);
        results.push_back(std::move(result));
    }
    
    return results;
}

/**
 * @brief CRT reconstruction using __int128 for precision
 * 
 * Reconstructs a coefficient from RNS representation to full integer.
 * Uses __int128 for intermediate computations to handle large products.
 * 
 * @param residues Residues [r_0, r_1, ..., r_{k-1}]
 * @param primes Moduli [q_0, q_1, ..., q_{k-1}]
 * @param Q_hat_i_inv Precomputed (Q / q_i)^{-1} mod q_i for each prime
 * @return Reconstructed value (may need reduction mod Q)
 */
inline __int128 crt_reconstruct_int128(
    const std::vector<uint64_t>& residues,
    const std::vector<uint64_t>& primes,
    const std::vector<uint64_t>& Q_hat_i_inv)
{
    __int128 result = 0;
    __int128 Q = 1;
    
    // Compute Q = prod(q_i)
    for (uint64_t q : primes) {
        Q *= static_cast<__int128>(q);
    }
    
    // CRT reconstruction
    for (size_t i = 0; i < primes.size(); ++i) {
        __int128 Q_i = Q / static_cast<__int128>(primes[i]);
        __int128 term = (static_cast<__int128>(residues[i]) * Q_hat_i_inv[i]) % primes[i];
        term = (term * Q_i) % Q;
        result = (result + term) % Q;
    }
    
    return result;
}

}  // namespace bgv
}  // namespace fhe
}  // namespace kctsb

#endif // KCTSB_ADVANCED_FE_BGV_NTT_HELPER_HPP
