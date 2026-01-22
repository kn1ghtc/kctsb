/**
 * @file ntt_poly_ops.cpp
 * @brief NTT-Accelerated Polynomial Operations Implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#include "kctsb/advanced/fe/common/ntt_poly_ops.hpp"
#include <algorithm>
#include <stdexcept>

namespace kctsb {
namespace fhe {
namespace ntt {

// ============================================================================
// High-Performance Polynomial Operations
// ============================================================================

std::vector<uint64_t> multiply_poly_ntt(
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    size_t n,
    uint64_t q)
{
    if (a.size() != n || b.size() != n) {
        throw std::invalid_argument("Polynomial size must match degree n");
    }
    
    if (!is_ntt_prime(q, n)) {
        throw std::invalid_argument("Modulus is not NTT-friendly for degree n");
    }
    
    // Use negacyclic NTT for x^n + 1 ring
    return poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
}

void multiply_poly_ntt_inplace(
    std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q)
{
    size_t n = a.size();
    
    if (b.size() != n) {
        throw std::invalid_argument("Polynomial sizes must match");
    }
    
    if (!is_ntt_prime(q, n)) {
        throw std::invalid_argument("Modulus is not NTT-friendly");
    }
    
    poly_multiply_negacyclic_ntt_inplace(a.data(), b.data(), n, q);
}

void add_poly_mod(
    std::vector<uint64_t>& result,
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q)
{
    size_t n = a.size();
    
    if (b.size() != n) {
        throw std::invalid_argument("Polynomial sizes must match");
    }
    
    result.resize(n);
    
    for (size_t i = 0; i < n; ++i) {
        result[i] = add_mod(a[i], b[i], q);
    }
}

void sub_poly_mod(
    std::vector<uint64_t>& result,
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q)
{
    size_t n = a.size();
    
    if (b.size() != n) {
        throw std::invalid_argument("Polynomial sizes must match");
    }
    
    result.resize(n);
    
    for (size_t i = 0; i < n; ++i) {
        result[i] = sub_mod(a[i], b[i], q);
    }
}

void negate_poly_mod(
    std::vector<uint64_t>& poly,
    uint64_t q)
{
    for (auto& coeff : poly) {
        if (coeff != 0) {
            coeff = q - coeff;
        }
    }
}

void scalar_mul_poly_mod(
    std::vector<uint64_t>& poly,
    uint64_t scalar,
    uint64_t q)
{
    for (auto& coeff : poly) {
        coeff = mul_mod_slow(coeff, scalar, q);
    }
}

// ============================================================================
// Batch Operations (RNS)
// ============================================================================

std::vector<std::vector<uint64_t>> multiply_poly_ntt_rns(
    const std::vector<std::vector<uint64_t>>& a,
    const std::vector<std::vector<uint64_t>>& b,
    size_t n,
    const std::vector<uint64_t>& moduli)
{
    size_t num_levels = moduli.size();
    
    if (a.size() != num_levels || b.size() != num_levels) {
        throw std::invalid_argument("Number of polynomial levels must match moduli count");
    }
    
    std::vector<std::vector<uint64_t>> result(num_levels);
    
    for (size_t level = 0; level < num_levels; ++level) {
        result[level] = multiply_poly_ntt(a[level], b[level], n, moduli[level]);
    }
    
    return result;
}

// ============================================================================
// Conversion Utilities
// ============================================================================

void to_ntt_form(
    std::vector<uint64_t>& coeffs,
    size_t n,
    uint64_t q)
{
    if (coeffs.size() != n) {
        throw std::invalid_argument("Coefficient count must match degree");
    }
    
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    ntt.forward_negacyclic(coeffs.data());
}

void from_ntt_form(
    std::vector<uint64_t>& ntt_vals,
    size_t n,
    uint64_t q)
{
    if (ntt_vals.size() != n) {
        throw std::invalid_argument("NTT value count must match degree");
    }
    
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    ntt.inverse_negacyclic(ntt_vals.data());
}

}  // namespace ntt
}  // namespace fhe
}  // namespace kctsb
