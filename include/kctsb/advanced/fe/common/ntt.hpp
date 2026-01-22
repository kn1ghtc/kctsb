/**
 * @file ntt.hpp
 * @brief Number Theoretic Transform (NTT) for Polynomial Multiplication
 * 
 * This module provides O(n log n) polynomial multiplication using NTT,
 * replacing the O(n²) schoolbook multiplication in BGV/BFV/CKKS schemes.
 * 
 * Implements:
 * - Cooley-Tukey FFT algorithm with NTT primes
 * - Barrett reduction for modular arithmetic
 * - AVX2 vectorization for 4x parallel uint64_t operations
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#ifndef KCTSB_ADVANCED_FE_COMMON_NTT_HPP
#define KCTSB_ADVANCED_FE_COMMON_NTT_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

// Detect AVX2 support
#if defined(__AVX2__) && defined(__x86_64__)
    #define KCTSB_HAS_AVX2 1
    #include <immintrin.h>
#endif

namespace kctsb {
namespace fhe {
namespace ntt {

// ============================================================================
// Modular Arithmetic (Barrett Reduction)
// ============================================================================

/**
 * @brief Precomputed constants for Barrett reduction
 * 
 * Barrett reduction computes a mod q without division:
 *   a mod q ≈ a - q * floor(a * mu / 2^k)
 * where mu = floor(2^k / q), k = 2 * bit_width(q)
 */
struct BarrettConstants {
    uint64_t q;           ///< Modulus
    uint64_t mu;          ///< Barrett constant: floor(2^64 / q)
    
    /**
     * @brief Initialize Barrett constants for modulus q
     * @param modulus Prime modulus (must be < 2^62 for safe arithmetic)
     */
    explicit BarrettConstants(uint64_t modulus);
};

/**
 * @brief Modular addition with single conditional subtraction
 * @param a First operand (must be < q)
 * @param b Second operand (must be < q)
 * @param q Modulus
 * @return (a + b) mod q
 */
inline uint64_t add_mod(uint64_t a, uint64_t b, uint64_t q) {
    uint64_t sum = a + b;
    return (sum >= q) ? (sum - q) : sum;
}

/**
 * @brief Modular subtraction with single conditional addition
 * @param a First operand (must be < q)
 * @param b Second operand (must be < q)
 * @param q Modulus
 * @return (a - b) mod q
 */
inline uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t q) {
    uint64_t diff = a - b;
    return (a < b) ? (diff + q) : diff;
}

/**
 * @brief Modular multiplication using Barrett reduction
 * @param a First operand (must be < q)
 * @param b Second operand (must be < q)
 * @param bc Barrett constants for modulus q
 * @return (a * b) mod q
 */
uint64_t mul_mod_barrett(uint64_t a, uint64_t b, const BarrettConstants& bc);

/**
 * @brief Modular multiplication (simple version, slower)
 * @param a First operand
 * @param b Second operand
 * @param q Modulus
 * @return (a * b) mod q
 */
uint64_t mul_mod_slow(uint64_t a, uint64_t b, uint64_t q);

/**
 * @brief Modular exponentiation using square-and-multiply
 * @param base Base value
 * @param exp Exponent
 * @param q Modulus
 * @return base^exp mod q
 */
uint64_t pow_mod(uint64_t base, uint64_t exp, uint64_t q);

/**
 * @brief Compute modular inverse using extended Euclidean algorithm
 * @param a Value to invert (must be coprime with q)
 * @param q Modulus
 * @return a^(-1) mod q
 * @throws std::invalid_argument if gcd(a, q) != 1
 */
uint64_t inv_mod(uint64_t a, uint64_t q);

// ============================================================================
// AVX2 Vectorized Operations (4x parallel uint64_t)
// ============================================================================

#ifdef KCTSB_HAS_AVX2

/**
 * @brief AVX2 vectorized modular addition (4 elements in parallel)
 * @param a First operand (4 x uint64_t, each < q)
 * @param b Second operand (4 x uint64_t, each < q)
 * @param q Modulus (broadcasted)
 * @return (a + b) mod q for each lane
 */
inline __m256i add_mod_avx2(__m256i a, __m256i b, __m256i q) {
    __m256i sum = _mm256_add_epi64(a, b);
    // Create mask: sum >= q
    __m256i mask = _mm256_or_si256(
        _mm256_cmpgt_epi64(sum, q),
        _mm256_cmpeq_epi64(sum, q)
    );
    // Subtract q if sum >= q
    __m256i diff = _mm256_sub_epi64(sum, q);
    return _mm256_blendv_epi8(sum, diff, mask);
}

/**
 * @brief AVX2 vectorized modular subtraction (4 elements in parallel)
 * @param a First operand (4 x uint64_t, each < q)
 * @param b Second operand (4 x uint64_t, each < q)
 * @param q Modulus (broadcasted)
 * @return (a - b) mod q for each lane
 */
inline __m256i sub_mod_avx2(__m256i a, __m256i b, __m256i q) {
    __m256i diff = _mm256_sub_epi64(a, b);
    // Create mask: a < b (need to add q)
    __m256i mask = _mm256_cmpgt_epi64(b, a);
    // Add q if a < b
    __m256i sum = _mm256_add_epi64(diff, q);
    return _mm256_blendv_epi8(diff, sum, mask);
}

/**
 * @brief AVX2 vectorized modular multiplication (4 elements in parallel)
 * 
 * Uses Barrett reduction approximation for fast modular multiplication.
 * Note: This is a simplified version that works for moduli < 2^32.
 * For larger moduli, fall back to scalar mul_mod_barrett.
 * 
 * @param a First operand (4 x uint64_t, each < q)
 * @param b Second operand (4 x uint64_t, each < q)
 * @param q Modulus (broadcasted)
 * @param mu Barrett constant (broadcasted)
 * @return (a * b) mod q for each lane
 */
__m256i mul_mod_avx2(__m256i a, __m256i b, __m256i q, __m256i mu);

#endif  // KCTSB_HAS_AVX2

// ============================================================================
// Primitive Root Finding
// ============================================================================

/**
 * @brief Check if q is an NTT-friendly prime
 * 
 * An NTT prime q satisfies:
 * - q is prime
 * - q = 1 (mod 2n) for the required polynomial degree n
 * 
 * @param q Candidate modulus
 * @param n Required polynomial degree (power of 2)
 * @return true if q is NTT-friendly for degree n
 */
bool is_ntt_prime(uint64_t q, size_t n);

/**
 * @brief Find a primitive 2n-th root of unity modulo q
 * 
 * Returns ω such that:
 * - ω^(2n) ≡ 1 (mod q)
 * - ω^k ≢ 1 (mod q) for 0 < k < 2n
 * 
 * @param q Prime modulus (must satisfy q = 1 (mod 2n))
 * @param n Polynomial degree (power of 2)
 * @return Primitive 2n-th root of unity
 * @throws std::invalid_argument if no such root exists
 */
uint64_t find_primitive_root(uint64_t q, size_t n);

// ============================================================================
// NTT Table (Precomputed Roots of Unity)
// ============================================================================

/**
 * @brief NTT precomputation table for a specific (n, q) pair
 * 
 * Stores:
 * - Powers of the n-th root of unity: ω^0, ω^1, ..., ω^(n-1)
 * - Powers of the inverse root for iNTT
 * - n^(-1) mod q for final scaling
 * 
 * Thread-safe: immutable after construction
 */
class NTTTable {
public:
    /**
     * @brief Construct NTT table for polynomial degree n and modulus q
     * @param n Polynomial degree (must be power of 2)
     * @param q Prime modulus (must satisfy q = 1 (mod 2n))
     * @throws std::invalid_argument if parameters are invalid
     */
    NTTTable(size_t n, uint64_t q);
    
    /**
     * @brief Forward NTT (Cooley-Tukey, decimation-in-time)
     * 
     * Transforms coefficient representation to evaluation representation.
     * In-place operation: input is overwritten with output.
     * 
     * Complexity: O(n log n)
     * 
     * @param data Input/output array of n coefficients (each < q)
     */
    void forward(uint64_t* data) const;
    
    /**
     * @brief Inverse NTT (Gentleman-Sande, decimation-in-frequency)
     * 
     * Transforms evaluation representation back to coefficient representation.
     * In-place operation with final scaling by n^(-1).
     * 
     * Complexity: O(n log n)
     * 
     * @param data Input/output array of n evaluations (each < q)
     */
    void inverse(uint64_t* data) const;
    
    // Accessors
    size_t degree() const { return n_; }
    uint64_t modulus() const { return q_; }
    uint64_t n_inverse() const { return n_inv_; }
    const BarrettConstants& barrett() const { return barrett_; }
    
    /**
     * @brief Get forward root of unity power
     * @param idx Index in [0, n)
     * @return ω^(bit_reverse(idx)) for forward NTT
     */
    uint64_t root(size_t idx) const { return roots_[idx]; }
    
    /**
     * @brief Get inverse root of unity power
     * @param idx Index in [0, n)
     * @return ω^(-bit_reverse(idx)) for inverse NTT
     */
    uint64_t inv_root(size_t idx) const { return inv_roots_[idx]; }
    
    /**
     * @brief Get psi (2n-th root of unity) power for negacyclic NTT
     * @param idx Index in [0, n)
     * @return ψ^idx where ψ^(2n) = 1
     */
    uint64_t psi(size_t idx) const { return psi_powers_[idx]; }
    
    /**
     * @brief Get inverse psi power for negacyclic iNTT
     * @param idx Index in [0, n)
     * @return ψ^(-idx)
     */
    uint64_t inv_psi(size_t idx) const { return inv_psi_powers_[idx]; }
    
    /**
     * @brief Forward negacyclic NTT for x^n + 1 ring
     * 
     * Computes NTT in the ring Z_q[x]/(x^n + 1).
     * Uses twisting: a'[i] = a[i] * ψ^i, then standard NTT.
     * 
     * @param data Input/output array of n coefficients
     */
    void forward_negacyclic(uint64_t* data) const;
    
    /**
     * @brief Inverse negacyclic NTT for x^n + 1 ring
     * 
     * Inverse of forward_negacyclic.
     * Uses standard iNTT, then untwisting: a[i] = a'[i] * ψ^(-i).
     * 
     * @param data Input/output array of n evaluations
     */
    void inverse_negacyclic(uint64_t* data) const;
    
#ifdef KCTSB_HAS_AVX2
    /**
     * @brief AVX2-accelerated forward NTT
     * 
     * Uses AVX2 SIMD for 4x parallel butterfly operations.
     * Falls back to scalar for n < 8 or non-aligned data.
     * 
     * @param data Input/output array (must be 32-byte aligned for best performance)
     */
    void forward_avx2(uint64_t* data) const;
    
    /**
     * @brief AVX2-accelerated inverse NTT
     * @param data Input/output array
     */
    void inverse_avx2(uint64_t* data) const;
    
    /**
     * @brief AVX2-accelerated negacyclic forward NTT
     * @param data Input/output array
     */
    void forward_negacyclic_avx2(uint64_t* data) const;
    
    /**
     * @brief AVX2-accelerated negacyclic inverse NTT
     * @param data Input/output array
     */
    void inverse_negacyclic_avx2(uint64_t* data) const;
#endif  // KCTSB_HAS_AVX2

private:
    size_t n_;                       ///< Polynomial degree
    uint64_t q_;                     ///< Modulus
    uint64_t n_inv_;                 ///< n^(-1) mod q
    BarrettConstants barrett_;       ///< Barrett reduction constants
    std::vector<uint64_t> roots_;    ///< Forward roots (ω powers)
    std::vector<uint64_t> inv_roots_;///< Inverse roots (ω^(-1) powers)
    std::vector<uint64_t> psi_powers_;    ///< ψ^i for negacyclic twist
    std::vector<uint64_t> inv_psi_powers_;///< ψ^(-i) for negacyclic untwist
    
    /// Bit-reversal permutation for NTT
    static void bit_reverse_permute(uint64_t* data, size_t n);
};

// ============================================================================
// NTT Table Cache (Singleton)
// ============================================================================

/**
 * @brief Cached NTT tables for common parameter sets
 * 
 * Avoids recomputing root of unity tables for frequently used (n, q) pairs.
 * Thread-safe singleton.
 */
class NTTTableCache {
public:
    static NTTTableCache& instance();
    
    /**
     * @brief Get or create NTT table for given parameters
     * @param n Polynomial degree
     * @param q Modulus
     * @return Reference to cached NTT table
     */
    const NTTTable& get(size_t n, uint64_t q);
    
    /// Clear all cached tables (for testing)
    void clear();
    
private:
    NTTTableCache() = default;
    
    std::vector<std::unique_ptr<NTTTable>> tables_;
    // TODO: Add mutex for thread safety
};

// ============================================================================
// High-Level Polynomial Operations
// ============================================================================

/**
 * @brief Polynomial multiplication using NTT (cyclic convolution)
 * 
 * Computes c = a * b mod (x^n - 1, q) in O(n log n) time.
 * 
 * @param a First polynomial coefficients (n elements, each < q)
 * @param b Second polynomial coefficients (n elements, each < q)
 * @param n Polynomial degree
 * @param q Modulus
 * @return Result polynomial coefficients (n elements)
 */
std::vector<uint64_t> poly_multiply_ntt(
    const uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q);

/**
 * @brief In-place polynomial multiplication using NTT (cyclic)
 * 
 * Result is stored in first operand.
 * 
 * @param a First polynomial (input/output)
 * @param b Second polynomial (input only)
 * @param n Polynomial degree
 * @param q Modulus
 */
void poly_multiply_ntt_inplace(
    uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q);

/**
 * @brief Negacyclic polynomial multiplication for BGV/BFV/CKKS
 * 
 * Computes c = a * b mod (x^n + 1, q) in O(n log n) time.
 * This is the main multiplication used in lattice-based FHE.
 * 
 * @param a First polynomial coefficients (n elements, each < q)
 * @param b Second polynomial coefficients (n elements, each < q)
 * @param n Polynomial degree (must be power of 2)
 * @param q Modulus (must be NTT-friendly: q = 1 (mod 2n))
 * @return Result polynomial coefficients (n elements)
 */
std::vector<uint64_t> poly_multiply_negacyclic_ntt(
    const uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q);

/**
 * @brief In-place negacyclic polynomial multiplication
 * 
 * Result is stored in first operand.
 * 
 * @param a First polynomial (input/output)
 * @param b Second polynomial (input only)
 * @param n Polynomial degree
 * @param q Modulus
 */
void poly_multiply_negacyclic_ntt_inplace(
    uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q);

#ifdef KCTSB_HAS_AVX2

/**
 * @brief AVX2-accelerated negacyclic polynomial multiplication
 * 
 * Uses AVX2 SIMD for both NTT and pointwise multiplication.
 * Best performance for n >= 8 and 32-byte aligned data.
 * 
 * @param a First polynomial coefficients
 * @param b Second polynomial coefficients  
 * @param n Polynomial degree (power of 2)
 * @param q Modulus
 * @return Result polynomial
 */
std::vector<uint64_t> poly_multiply_negacyclic_ntt_avx2(
    const uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q);

/**
 * @brief AVX2-accelerated in-place negacyclic multiplication
 * @param a First polynomial (input/output)
 * @param b Second polynomial (input only)
 * @param n Polynomial degree
 * @param q Modulus
 */
void poly_multiply_negacyclic_ntt_inplace_avx2(
    uint64_t* a,
    const uint64_t* b,
    size_t n,
    uint64_t q);

#endif  // KCTSB_HAS_AVX2

}  // namespace ntt
}  // namespace fhe
}  // namespace kctsb

#endif  // KCTSB_ADVANCED_FE_COMMON_NTT_HPP
