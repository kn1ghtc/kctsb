/**
 * @file rns.cpp
 * @brief Residue Number System (RNS) Implementation
 * 
 * Implements RNS polynomial representation and base conversion for FHE.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#include "kctsb/advanced/fe/common/rns.hpp"
#include <stdexcept>
#include <cstring>
#include <algorithm>

namespace kctsb {
namespace fhe {
namespace rns {

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief GCD using Euclidean algorithm
 */
static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

bool are_coprime(const std::vector<uint64_t>& moduli) {
    for (size_t i = 0; i < moduli.size(); ++i) {
        for (size_t j = i + 1; j < moduli.size(); ++j) {
            if (gcd(moduli[i], moduli[j]) != 1) {
                return false;
            }
        }
    }
    return true;
}

/**
 * @brief Simple primality test
 */
static bool is_prime(uint64_t n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

std::vector<uint64_t> generate_ntt_primes(
    size_t count, 
    size_t bit_size, 
    size_t poly_degree)
{
    std::vector<uint64_t> primes;
    primes.reserve(count);
    
    // Start near 2^bit_size
    uint64_t start = (1ULL << bit_size) - 1;
    
    // q = 1 (mod 2n) means q = 2n*k + 1 for some k
    uint64_t two_n = static_cast<uint64_t>(poly_degree) * 2;
    
    // Find starting k
    uint64_t k = start / two_n;
    
    while (primes.size() < count) {
        uint64_t q = k * two_n + 1;
        
        // Check bit size bounds
        if (q >= (1ULL << (bit_size + 1))) {
            // Went too high, go down
            if (k == 0) break;
            --k;
            continue;
        }
        
        if (q < (1ULL << (bit_size - 1))) {
            // Too low, we're done with this bit_size
            break;
        }
        
        // Check primality and NTT-friendliness
        if (is_prime(q) && ntt::is_ntt_prime(q, poly_degree)) {
            // Check coprimality with existing primes
            bool coprime = true;
            for (auto p : primes) {
                if (gcd(p, q) != 1) {
                    coprime = false;
                    break;
                }
            }
            
            if (coprime) {
                primes.push_back(q);
            }
        }
        
        if (k == 0) break;
        --k;
    }
    
    if (primes.size() < count) {
        throw std::runtime_error("Could not find enough NTT-friendly primes");
    }
    
    return primes;
}

// ============================================================================
// RNSBase Implementation
// ============================================================================

RNSBase::RNSBase(const std::vector<uint64_t>& moduli, size_t poly_degree)
    : poly_degree_(poly_degree)
    , moduli_(moduli)
{
    if (moduli.empty()) {
        throw std::invalid_argument("RNS base must have at least one modulus");
    }
    
    if (poly_degree == 0 || (poly_degree & (poly_degree - 1)) != 0) {
        throw std::invalid_argument("Polynomial degree must be a power of 2");
    }
    
    if (!are_coprime(moduli)) {
        throw std::invalid_argument("RNS moduli must be pairwise coprime");
    }
    
    // Validate each modulus is NTT-friendly
    for (auto q : moduli) {
        if (!ntt::is_ntt_prime(q, poly_degree)) {
            throw std::invalid_argument("All moduli must be NTT-friendly");
        }
    }
    
    // Initialize Barrett constants
    barrett_.reserve(moduli.size());
    for (auto q : moduli) {
        barrett_.emplace_back(q);
    }
    
    // Compute Q_i = Q / q_i (as product of other moduli)
    // For large products, we compute Q_i mod q_j directly
    size_t k = moduli.size();
    
    // q_hat_inv_mod_qi[i] = (Q / q_i)^(-1) mod q_i
    q_hat_inv_mod_qi_.resize(k);
    
    for (size_t i = 0; i < k; ++i) {
        // Compute Q_i mod q_i by multiplying all other moduli
        uint64_t q_hat_mod_qi = 1;
        for (size_t j = 0; j < k; ++j) {
            if (i != j) {
                q_hat_mod_qi = ntt::mul_mod_slow(q_hat_mod_qi, moduli[j] % moduli[i], moduli[i]);
            }
        }
        
        // Compute inverse: q_hat_inv = q_hat^(-1) mod q_i
        q_hat_inv_mod_qi_[i] = ntt::inv_mod(q_hat_mod_qi, moduli[i]);
    }
    
    // q_hat_mod_qj[i * k + j] = Q_i mod q_j
    q_hat_mod_qj_.resize(k * k);
    
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = 0; j < k; ++j) {
            // Q_i = product of all moduli except q_i
            uint64_t q_hat_mod_qj = 1;
            for (size_t m = 0; m < k; ++m) {
                if (m != i) {
                    q_hat_mod_qj = ntt::mul_mod_slow(
                        q_hat_mod_qj, moduli[m] % moduli[j], moduli[j]);
                }
            }
            q_hat_mod_qj_[i * k + j] = q_hat_mod_qj;
        }
    }
}

const ntt::NTTTable& RNSBase::ntt_table(size_t i) const {
    return ntt::NTTTableCache::instance().get(poly_degree_, moduli_[i]);
}

// ============================================================================
// RNSPoly Implementation
// ============================================================================

RNSPoly::RNSPoly(const RNSBase& base)
    : base_(base)
    , coeffs_(base.size())
    , is_ntt_(false)
{
    for (size_t i = 0; i < base.size(); ++i) {
        coeffs_[i].resize(base.poly_degree(), 0);
    }
}

RNSPoly::RNSPoly(const RNSBase& base, 
                 const std::vector<std::vector<uint64_t>>& coeffs)
    : base_(base)
    , coeffs_(coeffs)
    , is_ntt_(false)
{
    if (coeffs.size() != base.size()) {
        throw std::invalid_argument("Coefficient levels must match RNS base size");
    }
    
    for (size_t i = 0; i < coeffs.size(); ++i) {
        if (coeffs[i].size() != base.poly_degree()) {
            throw std::invalid_argument("Coefficient count must match polynomial degree");
        }
    }
}

RNSPoly::RNSPoly(const RNSPoly& other)
    : base_(other.base_)
    , coeffs_(other.coeffs_)
    , is_ntt_(other.is_ntt_)
{
}

RNSPoly::RNSPoly(RNSPoly&& other) noexcept
    : base_(other.base_)
    , coeffs_(std::move(other.coeffs_))
    , is_ntt_(other.is_ntt_)
{
}

RNSPoly& RNSPoly::operator=(const RNSPoly& other) {
    if (this != &other) {
        // Check base compatibility
        if (&base_ != &other.base_) {
            throw std::invalid_argument("Cannot assign polynomials with different bases");
        }
        coeffs_ = other.coeffs_;
        is_ntt_ = other.is_ntt_;
    }
    return *this;
}

RNSPoly& RNSPoly::operator=(RNSPoly&& other) noexcept {
    if (this != &other) {
        // Note: base_ is a reference, cannot be reassigned
        coeffs_ = std::move(other.coeffs_);
        is_ntt_ = other.is_ntt_;
    }
    return *this;
}

void RNSPoly::to_ntt() {
    if (is_ntt_) return;
    
    for (size_t level = 0; level < base_.size(); ++level) {
        base_.ntt_table(level).forward_negacyclic(coeffs_[level].data());
    }
    
    is_ntt_ = true;
}

void RNSPoly::from_ntt() {
    if (!is_ntt_) return;
    
    for (size_t level = 0; level < base_.size(); ++level) {
        base_.ntt_table(level).inverse_negacyclic(coeffs_[level].data());
    }
    
    is_ntt_ = false;
}

void RNSPoly::set_zero() {
    for (auto& level_coeffs : coeffs_) {
        std::fill(level_coeffs.begin(), level_coeffs.end(), 0);
    }
}

void RNSPoly::negate() {
    for (size_t level = 0; level < base_.size(); ++level) {
        uint64_t q = base_.modulus(level);
        for (size_t i = 0; i < base_.poly_degree(); ++i) {
            if (coeffs_[level][i] != 0) {
                coeffs_[level][i] = q - coeffs_[level][i];
            }
        }
    }
}

RNSPoly& RNSPoly::operator+=(const RNSPoly& other) {
    if (&base_ != &other.base_) {
        throw std::invalid_argument("Polynomials must have the same RNS base");
    }
    
    if (is_ntt_ != other.is_ntt_) {
        throw std::invalid_argument("Polynomials must be in the same form (NTT or coefficient)");
    }
    
    for (size_t level = 0; level < base_.size(); ++level) {
        uint64_t q = base_.modulus(level);
        for (size_t i = 0; i < base_.poly_degree(); ++i) {
            coeffs_[level][i] = ntt::add_mod(
                coeffs_[level][i], other.coeffs_[level][i], q);
        }
    }
    
    return *this;
}

RNSPoly& RNSPoly::operator-=(const RNSPoly& other) {
    if (&base_ != &other.base_) {
        throw std::invalid_argument("Polynomials must have the same RNS base");
    }
    
    if (is_ntt_ != other.is_ntt_) {
        throw std::invalid_argument("Polynomials must be in the same form");
    }
    
    for (size_t level = 0; level < base_.size(); ++level) {
        uint64_t q = base_.modulus(level);
        for (size_t i = 0; i < base_.poly_degree(); ++i) {
            coeffs_[level][i] = ntt::sub_mod(
                coeffs_[level][i], other.coeffs_[level][i], q);
        }
    }
    
    return *this;
}

RNSPoly& RNSPoly::operator*=(const RNSPoly& other) {
    if (&base_ != &other.base_) {
        throw std::invalid_argument("Polynomials must have the same RNS base");
    }
    
    if (!is_ntt_ || !other.is_ntt_) {
        throw std::invalid_argument("Both polynomials must be in NTT form for multiplication");
    }
    
    // Element-wise multiplication in NTT domain with Barrett reduction
    // Optimized v4.9.0: Uses Barrett constants for ~2x faster modular multiplication
    for (size_t level = 0; level < base_.size(); ++level) {
        const ntt::BarrettConstants& bc = base_.barrett(level);
        for (size_t i = 0; i < base_.poly_degree(); ++i) {
            coeffs_[level][i] = ntt::mul_mod_barrett(
                coeffs_[level][i], other.coeffs_[level][i], bc);
        }
    }
    
    return *this;
}

// ============================================================================
// Binary Operators
// ============================================================================

RNSPoly operator+(const RNSPoly& a, const RNSPoly& b) {
    RNSPoly result(a);
    result += b;
    return result;
}

RNSPoly operator-(const RNSPoly& a, const RNSPoly& b) {
    RNSPoly result(a);
    result -= b;
    return result;
}

RNSPoly operator*(const RNSPoly& a, const RNSPoly& b) {
    RNSPoly result(a);
    result *= b;
    return result;
}

// ============================================================================
// RNSBaseConverter Implementation
// ============================================================================

RNSBaseConverter::RNSBaseConverter(const RNSBase& from_base, const RNSBase& to_base)
    : from_base_(from_base)
    , to_base_(to_base)
{
    // Precompute conversion matrix
    // For each (from_level, to_level), we need Q_{from_level} mod q_{to_level}
    size_t from_size = from_base.size();
    size_t to_size = to_base.size();
    
    conversion_matrix_.resize(from_size);
    
    for (size_t i = 0; i < from_size; ++i) {
        conversion_matrix_[i].resize(to_size);
        
        for (size_t j = 0; j < to_size; ++j) {
            // Compute Q_i mod q_j where Q_i = product of all from_base moduli except i
            uint64_t q_j = to_base.modulus(j);
            uint64_t q_hat_mod_qj = 1;
            
            for (size_t m = 0; m < from_size; ++m) {
                if (m != i) {
                    q_hat_mod_qj = ntt::mul_mod_slow(
                        q_hat_mod_qj, 
                        from_base.modulus(m) % q_j, 
                        q_j);
                }
            }
            
            conversion_matrix_[i][j] = q_hat_mod_qj;
        }
    }
}

void RNSBaseConverter::convert(const RNSPoly& input, RNSPoly& output) const {
    if (&input.base() != &from_base_) {
        throw std::invalid_argument("Input polynomial must use source base");
    }
    
    if (&output.base() != &to_base_) {
        throw std::invalid_argument("Output polynomial must use target base");
    }
    
    if (input.is_ntt()) {
        throw std::invalid_argument("Input must be in coefficient form for base conversion");
    }
    
    size_t n = from_base_.poly_degree();
    size_t from_size = from_base_.size();
    size_t to_size = to_base_.size();
    
    output.set_zero();
    
    // For each coefficient position
    for (size_t coeff_idx = 0; coeff_idx < n; ++coeff_idx) {
        // For each target modulus
        for (size_t j = 0; j < to_size; ++j) {
            const ntt::BarrettConstants& bc_j = to_base_.barrett(j);
            uint64_t sum = 0;
            
            // Sum over source moduli: sum = Σ (a_i * Q_i^(-1) mod q_i) * Q_i mod q_j
            for (size_t i = 0; i < from_size; ++i) {
                uint64_t a_i = input[i][coeff_idx];
                uint64_t q_hat_inv = from_base_.q_hat_inv(i);
                const ntt::BarrettConstants& bc_i = from_base_.barrett(i);
                
                // Compute (a_i * Q_i^(-1)) mod q_i with Barrett reduction
                uint64_t term = ntt::mul_mod_barrett(a_i, q_hat_inv, bc_i);
                
                // Multiply by Q_i mod q_j with Barrett reduction
                uint64_t q_hat_mod_qj = conversion_matrix_[i][j];
                term = ntt::mul_mod_barrett(term, q_hat_mod_qj, bc_j);
                
                // Add to sum
                sum = ntt::add_mod(sum, term, bc_j.q);
            }
            
            output[j][coeff_idx] = sum;
        }
    }
}

}  // namespace rns
}  // namespace fhe
}  // namespace kctsb
