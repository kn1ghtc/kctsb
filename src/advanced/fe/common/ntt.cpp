/**
 * @file ntt.cpp
 * @brief Number Theoretic Transform Implementation
 * 
 * Implements Cooley-Tukey NTT algorithm with:
 * - Barrett reduction for efficient modular multiplication
 * - Bit-reversal permutation for in-place operation
 * - Precomputed root of unity tables
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#include "kctsb/advanced/fe/common/ntt.hpp"
#include <stdexcept>
#include <cstring>

namespace kctsb {
namespace fhe {
namespace ntt {

// ============================================================================
// Barrett Reduction Constants
// ============================================================================

BarrettConstants::BarrettConstants(uint64_t modulus)
    : q(modulus)
    , mu(0)
{
    if (modulus == 0) {
        throw std::invalid_argument("Modulus cannot be zero");
    }
    if (modulus >= (1ULL << 62)) {
        throw std::invalid_argument("Modulus must be < 2^62 for safe Barrett reduction");
    }
    
    // Compute mu = floor(2^64 / q)
    // We compute this as (2^64 - 1) / q + adjustment
    // Since 2^64 doesn't fit in uint64_t, we use a different approach
    mu = static_cast<uint64_t>(static_cast<__uint128_t>(1ULL << 63) * 2 / modulus);
}

// ============================================================================
// Modular Arithmetic
// ============================================================================

uint64_t mul_mod_barrett(uint64_t a, uint64_t b, const BarrettConstants& bc) {
    // For correctness, we use the slow method for now
    // TODO: Implement proper Barrett reduction
    return mul_mod_slow(a, b, bc.q);
}

uint64_t mul_mod_slow(uint64_t a, uint64_t b, uint64_t q) {
    __uint128_t product = static_cast<__uint128_t>(a) * b;
    return static_cast<uint64_t>(product % q);
}

uint64_t pow_mod(uint64_t base, uint64_t exp, uint64_t q) {
    if (q == 1) return 0;
    
    uint64_t result = 1;
    base = base % q;
    
    while (exp > 0) {
        if (exp & 1) {
            result = mul_mod_slow(result, base, q);
        }
        exp >>= 1;
        base = mul_mod_slow(base, base, q);
    }
    
    return result;
}

uint64_t inv_mod(uint64_t a, uint64_t q) {
    if (a == 0) {
        throw std::invalid_argument("Cannot compute inverse of zero");
    }
    
    // Extended Euclidean Algorithm
    int64_t t = 0, new_t = 1;
    uint64_t r = q, new_r = a;
    
    while (new_r != 0) {
        uint64_t quotient = r / new_r;
        
        int64_t tmp_t = t - static_cast<int64_t>(quotient) * new_t;
        t = new_t;
        new_t = tmp_t;
        
        uint64_t tmp_r = r - quotient * new_r;
        r = new_r;
        new_r = tmp_r;
    }
    
    if (r != 1) {
        throw std::invalid_argument("Modular inverse does not exist (gcd != 1)");
    }
    
    return (t < 0) ? static_cast<uint64_t>(t + static_cast<int64_t>(q)) : static_cast<uint64_t>(t);
}

// ============================================================================
// Primitive Root Finding
// ============================================================================

/**
 * @brief Simple primality test (trial division)
 * @note For production, use Miller-Rabin
 */
static bool is_prime_simple(uint64_t n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

bool is_ntt_prime(uint64_t q, size_t n) {
    if (!is_prime_simple(q)) return false;
    
    // Check q = 1 (mod 2n)
    uint64_t two_n = static_cast<uint64_t>(n) * 2;
    return (q % two_n) == 1;
}

/**
 * @brief Find prime factors of n (for primitive root test)
 */
static std::vector<uint64_t> prime_factors(uint64_t n) {
    std::vector<uint64_t> factors;
    
    // Factor out 2s
    while (n % 2 == 0) {
        if (factors.empty() || factors.back() != 2) {
            factors.push_back(2);
        }
        n /= 2;
    }
    
    // Odd factors
    for (uint64_t i = 3; i * i <= n; i += 2) {
        while (n % i == 0) {
            if (factors.empty() || factors.back() != i) {
                factors.push_back(i);
            }
            n /= i;
        }
    }
    
    if (n > 1) {
        factors.push_back(n);
    }
    
    return factors;
}

uint64_t find_primitive_root(uint64_t q, size_t n) {
    // We need a primitive 2n-th root of unity
    // This means finding g such that g^(2n) = 1 and g^k != 1 for k < 2n
    
    // The multiplicative group Z_q* has order q-1
    // We need 2n | (q-1), which is guaranteed by is_ntt_prime
    
    uint64_t order = q - 1;
    uint64_t two_n = static_cast<uint64_t>(n) * 2;
    
    if (order % two_n != 0) {
        throw std::invalid_argument("q is not NTT-friendly for this n");
    }
    
    // Find a generator of Z_q*
    auto factors = prime_factors(order);
    
    for (uint64_t g = 2; g < q; ++g) {
        bool is_generator = true;
        
        for (uint64_t p : factors) {
            if (pow_mod(g, order / p, q) == 1) {
                is_generator = false;
                break;
            }
        }
        
        if (is_generator) {
            // g is a generator of Z_q*
            // The 2n-th primitive root is g^((q-1)/(2n))
            return pow_mod(g, order / two_n, q);
        }
    }
    
    throw std::runtime_error("Failed to find primitive root");
}

// ============================================================================
// NTT Table
// ============================================================================

/**
 * @brief Count trailing zeros (log2 for power of 2)
 */
static size_t count_trailing_zeros(size_t n) {
    size_t count = 0;
    while ((n & 1) == 0) {
        n >>= 1;
        ++count;
    }
    return count;
}

/**
 * @brief Bit-reverse an integer with given bit width
 */
static size_t bit_reverse(size_t x, size_t bits) {
    size_t result = 0;
    for (size_t i = 0; i < bits; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

void NTTTable::bit_reverse_permute(uint64_t* data, size_t n) {
    size_t log_n = count_trailing_zeros(n);
    
    for (size_t i = 0; i < n; ++i) {
        size_t j = bit_reverse(i, log_n);
        if (i < j) {
            std::swap(data[i], data[j]);
        }
    }
}

NTTTable::NTTTable(size_t n, uint64_t q)
    : n_(n)
    , q_(q)
    , n_inv_(0)
    , barrett_(q)
    , roots_(n)
    , inv_roots_(n)
    , psi_powers_(n)
    , inv_psi_powers_(n)
{
    // Validate n is power of 2
    if (n == 0 || (n & (n - 1)) != 0) {
        throw std::invalid_argument("n must be a power of 2");
    }
    
    // Validate q is NTT-friendly
    if (!is_ntt_prime(q, n)) {
        throw std::invalid_argument("q is not an NTT-friendly prime for n");
    }
    
    // Compute n^(-1) mod q
    n_inv_ = inv_mod(n, q);
    
    // Find primitive 2n-th root of unity (ψ)
    uint64_t psi = find_primitive_root(q, n);  // ψ^(2n) = 1
    uint64_t psi_inv = inv_mod(psi, q);
    
    // ω = ψ² is the n-th root of unity
    uint64_t omega = mul_mod_slow(psi, psi, q);
    uint64_t omega_inv = inv_mod(omega, q);
    
    // Precompute ω powers for cyclic NTT
    roots_[0] = 1;
    inv_roots_[0] = 1;
    for (size_t i = 1; i < n; ++i) {
        roots_[i] = mul_mod_slow(roots_[i - 1], omega, q);
        inv_roots_[i] = mul_mod_slow(inv_roots_[i - 1], omega_inv, q);
    }
    
    // Precompute ψ powers for negacyclic twist
    psi_powers_[0] = 1;
    inv_psi_powers_[0] = 1;
    for (size_t i = 1; i < n; ++i) {
        psi_powers_[i] = mul_mod_slow(psi_powers_[i - 1], psi, q);
        inv_psi_powers_[i] = mul_mod_slow(inv_psi_powers_[i - 1], psi_inv, q);
    }
}

void NTTTable::forward(uint64_t* data) const {
    // Cooley-Tukey iterative NTT (decimation-in-time)
    // Standard algorithm: bit-reversal at INPUT, then butterflies
    
    // Step 1: Bit-reversal permutation at the beginning (DIT input reordering)
    bit_reverse_permute(data, n_);
    
    // Step 2: Iterative butterfly operations
    // len = half-size of current FFT block, starts at 1 and doubles each stage
    for (size_t len = 1; len <= n_ / 2; len <<= 1) {
        // step = stride between consecutive uses of same twiddle factor
        size_t step = n_ / (2 * len);
        
        for (size_t i = 0; i < n_; i += 2 * len) {
            for (size_t j = 0; j < len; ++j) {
                size_t w_idx = j * step;
                uint64_t u = data[i + j];
                uint64_t v = mul_mod_slow(data[i + j + len], roots_[w_idx], q_);
                
                // Butterfly: (u, v) -> (u + v, u - v)
                data[i + j] = add_mod(u, v, q_);
                data[i + j + len] = sub_mod(u, v, q_);
            }
        }
    }
}

void NTTTable::inverse(uint64_t* data) const {
    // Gentleman-Sande iterative iNTT (decimation-in-frequency)
    // Standard algorithm: butterflies then bit-reversal at OUTPUT
    
    // Step 1: Iterative inverse butterfly operations
    for (size_t len = n_ / 2; len >= 1; len >>= 1) {
        size_t step = n_ / (2 * len);
        
        for (size_t i = 0; i < n_; i += 2 * len) {
            for (size_t j = 0; j < len; ++j) {
                size_t w_idx = j * step;
                uint64_t u = data[i + j];
                uint64_t v = data[i + j + len];
                
                // Inverse butterfly: (u, v) -> (u + v, (u - v) * w_inv)
                data[i + j] = add_mod(u, v, q_);
                uint64_t diff = sub_mod(u, v, q_);
                data[i + j + len] = mul_mod_slow(diff, inv_roots_[w_idx], q_);
            }
        }
    }
    
    // Step 2: Bit-reversal permutation at the end (DIF output reordering)
    bit_reverse_permute(data, n_);
    
    // Step 3: Final scaling by n^(-1)
    for (size_t i = 0; i < n_; ++i) {
        data[i] = mul_mod_slow(data[i], n_inv_, q_);
    }
}

void NTTTable::forward_negacyclic(uint64_t* data) const {
    // Negacyclic NTT for x^n + 1 ring
    // Step 1: Twist - multiply by ψ^i to convert x^n + 1 to x^n - 1
    for (size_t i = 0; i < n_; ++i) {
        data[i] = mul_mod_slow(data[i], psi_powers_[i], q_);
    }
    
    // Step 2: Standard cyclic NTT
    forward(data);
}

void NTTTable::inverse_negacyclic(uint64_t* data) const {
    // Inverse negacyclic NTT
    // Step 1: Standard cyclic iNTT
    inverse(data);
    
    // Step 2: Untwist - multiply by ψ^(-i)
    for (size_t i = 0; i < n_; ++i) {
        data[i] = mul_mod_slow(data[i], inv_psi_powers_[i], q_);
    }
}

// ============================================================================
// NTT Table Cache
// ============================================================================

NTTTableCache& NTTTableCache::instance() {
    static NTTTableCache cache;
    return cache;
}

const NTTTable& NTTTableCache::get(size_t n, uint64_t q) {
    // Linear search for now (few tables expected)
    for (const auto& table : tables_) {
        if (table->degree() == n && table->modulus() == q) {
            return *table;
        }
    }
    
    // Create new table
    tables_.push_back(std::make_unique<NTTTable>(n, q));
    return *tables_.back();
}

void NTTTableCache::clear() {
    tables_.clear();
}

// ============================================================================
// High-Level Polynomial Operations
// ============================================================================

std::vector<uint64_t> poly_multiply_ntt(
    const uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q)
{
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    
    // Copy inputs (NTT is in-place)
    std::vector<uint64_t> a_ntt(a, a + n);
    std::vector<uint64_t> b_ntt(b, b + n);
    
    // Forward NTT
    ntt.forward(a_ntt.data());
    ntt.forward(b_ntt.data());
    
    // Point-wise multiplication
    std::vector<uint64_t> c_ntt(n);
    for (size_t i = 0; i < n; ++i) {
        c_ntt[i] = mul_mod_slow(a_ntt[i], b_ntt[i], q);
    }
    
    // Inverse NTT
    ntt.inverse(c_ntt.data());
    
    return c_ntt;
}

void poly_multiply_ntt_inplace(
    uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q)
{
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    
    // Copy b (need to preserve original)
    std::vector<uint64_t> b_ntt(b, b + n);
    
    // Forward NTT on both
    ntt.forward(a);
    ntt.forward(b_ntt.data());
    
    // Point-wise multiplication
    for (size_t i = 0; i < n; ++i) {
        a[i] = mul_mod_slow(a[i], b_ntt[i], q);
    }
    
    // Inverse NTT
    ntt.inverse(a);
}

std::vector<uint64_t> poly_multiply_negacyclic_ntt(
    const uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q)
{
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    
    // Copy inputs (NTT is in-place)
    std::vector<uint64_t> a_ntt(a, a + n);
    std::vector<uint64_t> b_ntt(b, b + n);
    
    // Forward negacyclic NTT (includes twist)
    ntt.forward_negacyclic(a_ntt.data());
    ntt.forward_negacyclic(b_ntt.data());
    
    // Point-wise multiplication
    std::vector<uint64_t> c_ntt(n);
    for (size_t i = 0; i < n; ++i) {
        c_ntt[i] = mul_mod_slow(a_ntt[i], b_ntt[i], q);
    }
    
    // Inverse negacyclic NTT (includes untwist)
    ntt.inverse_negacyclic(c_ntt.data());
    
    return c_ntt;
}

void poly_multiply_negacyclic_ntt_inplace(
    uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q)
{
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    
    // Copy b (need to preserve original)
    std::vector<uint64_t> b_ntt(b, b + n);
    
    // Forward negacyclic NTT on both
    ntt.forward_negacyclic(a);
    ntt.forward_negacyclic(b_ntt.data());
    
    // Point-wise multiplication
    for (size_t i = 0; i < n; ++i) {
        a[i] = mul_mod_slow(a[i], b_ntt[i], q);
    }
    
    // Inverse negacyclic NTT
    ntt.inverse_negacyclic(a);
}

}  // namespace ntt
}  // namespace fhe
}  // namespace kctsb
