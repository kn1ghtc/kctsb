/**
 * @file ntt_poly_ops.cpp
 * @brief NTT-Accelerated Polynomial Operations Implementation
 * 
 * Updated to use Harvey NTT implementation for Phase 4b optimization.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.9.1
 */

#include "kctsb/advanced/fe/common/ntt_poly_ops.hpp"
#include "kctsb/advanced/fe/common/ntt_harvey.hpp"
#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <mutex>

namespace kctsb {
namespace fhe {
namespace ntt {

// ============================================================================
// NTT Tables Cache for ntt_poly_ops
// ============================================================================

namespace {

/**
 * @brief Thread-safe cache for NTT tables
 * 
 * Uses hash map for O(1) lookup by (n, q) pair.
 */
class NTTTablesCache {
public:
    static NTTTablesCache& instance() {
        static NTTTablesCache cache;
        return cache;
    }
    
    /**
     * @brief Get or create NTT tables for given parameters
     */
    const NTTTables& get(size_t n, uint64_t q) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        uint64_t key = make_key(n, q);
        auto it = tables_.find(key);
        if (it != tables_.end()) {
            return *it->second;
        }
        
        // Compute log2(n)
        int log_n = 0;
        size_t temp = n;
        while (temp > 1) {
            temp >>= 1;
            ++log_n;
        }
        
        auto tables = std::make_unique<NTTTables>(log_n, Modulus(q));
        const NTTTables& ref = *tables;
        tables_[key] = std::move(tables);
        return ref;
    }
    
private:
    static uint64_t make_key(size_t n, uint64_t q) {
        return (static_cast<uint64_t>(n) << 48) ^ q;
    }
    
    std::mutex mutex_;
    std::unordered_map<uint64_t, std::unique_ptr<NTTTables>> tables_;
};

} // anonymous namespace

// ============================================================================
// High-Performance Polynomial Operations (Harvey NTT)
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
    
    // Get or create Harvey NTT tables
    const NTTTables& tables = NTTTablesCache::instance().get(n, q);
    const Modulus& mod = tables.modulus();
    
    // Copy inputs (NTT is in-place)
    std::vector<uint64_t> a_ntt(a);
    std::vector<uint64_t> b_ntt(b);
    
    // Forward NTT using Harvey algorithm
    ntt_negacyclic_harvey(a_ntt.data(), tables);
    ntt_negacyclic_harvey(b_ntt.data(), tables);
    
    // Point-wise multiplication with modular reduction
    std::vector<uint64_t> c_ntt(n);
    for (size_t i = 0; i < n; ++i) {
        c_ntt[i] = multiply_uint_mod(a_ntt[i], b_ntt[i], mod);
    }
    
    // Inverse NTT using Harvey algorithm (includes n^{-1} scaling)
    inverse_ntt_negacyclic_harvey(c_ntt.data(), tables);
    
    return c_ntt;
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
    
    // Get or create Harvey NTT tables
    const NTTTables& tables = NTTTablesCache::instance().get(n, q);
    const Modulus& mod = tables.modulus();
    
    // Copy b (need to preserve original)
    std::vector<uint64_t> b_ntt(b);
    
    // Forward NTT using Harvey algorithm
    ntt_negacyclic_harvey(a.data(), tables);
    ntt_negacyclic_harvey(b_ntt.data(), tables);
    
    // Point-wise multiplication
    for (size_t i = 0; i < n; ++i) {
        a[i] = multiply_uint_mod(a[i], b_ntt[i], mod);
    }
    
    // Inverse NTT using Harvey algorithm
    inverse_ntt_negacyclic_harvey(a.data(), tables);
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
    
    Modulus mod(q);
    for (size_t i = 0; i < n; ++i) {
        result[i] = add_uint_mod(a[i], b[i], mod);
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
    
    Modulus mod(q);
    for (size_t i = 0; i < n; ++i) {
        result[i] = sub_uint_mod(a[i], b[i], mod);
    }
}

void negate_poly_mod(
    std::vector<uint64_t>& poly,
    uint64_t q)
{
    Modulus mod(q);
    for (auto& coeff : poly) {
        coeff = negate_uint_mod(coeff, mod);
    }
}

void scalar_mul_poly_mod(
    std::vector<uint64_t>& poly,
    uint64_t scalar,
    uint64_t q)
{
    Modulus mod(q);
    MultiplyUIntModOperand operand;
    operand.set(scalar, mod);
    
    for (auto& coeff : poly) {
        coeff = multiply_uint_mod(coeff, operand, mod);
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
// Conversion Utilities (Harvey NTT)
// ============================================================================

void to_ntt_form(
    std::vector<uint64_t>& coeffs,
    size_t n,
    uint64_t q)
{
    if (coeffs.size() != n) {
        throw std::invalid_argument("Coefficient count must match degree");
    }
    
    const NTTTables& tables = NTTTablesCache::instance().get(n, q);
    ntt_negacyclic_harvey(coeffs.data(), tables);
}

void from_ntt_form(
    std::vector<uint64_t>& ntt_vals,
    size_t n,
    uint64_t q)
{
    if (ntt_vals.size() != n) {
        throw std::invalid_argument("NTT value count must match degree");
    }
    
    const NTTTables& tables = NTTTablesCache::instance().get(n, q);
    inverse_ntt_negacyclic_harvey(ntt_vals.data(), tables);
}

}  // namespace ntt
}  // namespace fhe
}  // namespace kctsb
