/**
 * @file ntt_harvey.hpp
 * @brief Harvey NTT Implementation with Lazy Reduction
 * 
 * Implements the Harvey NTT algorithm used by SEAL:
 * - Precomputed twiddle factors with quotients
 * - Lazy reduction to minimize modular operations
 * - Negacyclic convolution for R_q = Z_q[x]/(x^n + 1)
 * 
 * Reference:
 * - David Harvey, "Faster arithmetic for number-theoretic transforms" (2014)
 * - Patrick Longa, Michael Naehrig, "Speeding up the Number Theoretic Transform" (2016)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.9.1
 * @since Phase 4b optimization
 */

#ifndef KCTSB_ADVANCED_FE_COMMON_NTT_HARVEY_HPP
#define KCTSB_ADVANCED_FE_COMMON_NTT_HARVEY_HPP

#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include <vector>
#include <memory>
#include <cstring>

#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace kctsb {
namespace fhe {

// ============================================================================
// NTT Tables with Precomputed Twiddle Factors
// ============================================================================

/**
 * @brief Precomputed NTT tables for a specific (n, q) pair
 * 
 * Stores:
 * - Root of unity powers in bit-reversed order
 * - Inverse root powers for inverse NTT
 * - All values as MultiplyUIntModOperand for fast multiplication
 */
class NTTTables {
public:
    /**
     * @brief Construct NTT tables for given parameters
     * @param log_n Log2 of polynomial degree (n = 2^log_n)
     * @param modulus NTT-friendly prime modulus
     * @throws std::invalid_argument if modulus doesn't support NTT for this n
     */
    NTTTables(int log_n, const Modulus& modulus);
    
    /**
     * @brief Move constructor
     */
    NTTTables(NTTTables&& other) noexcept = default;
    
    /**
     * @brief Copy constructor
     */
    NTTTables(const NTTTables& other);
    
    // ======== Accessors ========
    
    /**
     * @brief Get primitive root of unity
     */
    inline uint64_t root() const noexcept { return root_; }
    
    /**
     * @brief Get coefficient count (n)
     */
    inline size_t coeff_count() const noexcept { return coeff_count_; }
    
    /**
     * @brief Get log2(n)
     */
    inline int coeff_count_power() const noexcept { return coeff_count_power_; }
    
    /**
     * @brief Get modulus
     */
    inline const Modulus& modulus() const noexcept { return modulus_; }
    
    /**
     * @brief Get root powers array (bit-reversed order)
     */
    inline const MultiplyUIntModOperand* root_powers() const noexcept {
        return root_powers_.data();
    }
    
    /**
     * @brief Get inverse root powers array
     */
    inline const MultiplyUIntModOperand* inv_root_powers() const noexcept {
        return inv_root_powers_.data();
    }
    
    /**
     * @brief Get n^{-1} mod q for inverse NTT scaling
     */
    inline const MultiplyUIntModOperand& inv_degree_modulo() const noexcept {
        return inv_degree_modulo_;
    }
    
    /**
     * @brief Get 2*q for lazy reduction guard
     */
    inline uint64_t two_times_modulus() const noexcept {
        return two_times_modulus_;
    }

private:
    void initialize();
    
    /**
     * @brief Find primitive 2n-th root of unity
     */
    uint64_t find_minimal_primitive_root() const;
    
    /**
     * @brief Bit-reverse an index
     */
    static size_t bit_reverse(size_t x, int bits);
    
    int coeff_count_power_;                            // log2(n)
    size_t coeff_count_;                               // n
    Modulus modulus_;                                  // q
    uint64_t root_;                                    // primitive 2n-th root
    uint64_t inv_root_;                                // root^{-1}
    uint64_t two_times_modulus_;                       // 2*q
    
    std::vector<MultiplyUIntModOperand> root_powers_;     // w^0, w^1, ..., w^{n-1} (bit-reversed)
    std::vector<MultiplyUIntModOperand> inv_root_powers_; // w^{-0}, w^{-1}, ..., w^{-(n-1)}
    MultiplyUIntModOperand inv_degree_modulo_;            // n^{-1} mod q
};

// ============================================================================
// Harvey NTT Core Functions
// ============================================================================

/**
 * @brief Forward NTT with lazy reduction (Harvey algorithm)
 * 
 * Computes NTT in-place using Cooley-Tukey decimation-in-time.
 * Results are in [0, 2q) for lazy reduction variant.
 * 
 * @param[in,out] operand Coefficient array of size n
 * @param tables Precomputed NTT tables
 */
void ntt_negacyclic_harvey_lazy(uint64_t* operand, const NTTTables& tables);

/**
 * @brief Forward NTT with full reduction
 * 
 * Like ntt_negacyclic_harvey_lazy but ensures results are in [0, q).
 */
void ntt_negacyclic_harvey(uint64_t* operand, const NTTTables& tables);

/**
 * @brief Inverse NTT with lazy reduction (Harvey algorithm)
 * 
 * Computes inverse NTT in-place using Gentleman-Sande decimation-in-frequency.
 * Includes scaling by n^{-1}.
 */
void inverse_ntt_negacyclic_harvey_lazy(uint64_t* operand, const NTTTables& tables);

/**
 * @brief Inverse NTT with full reduction
 */
void inverse_ntt_negacyclic_harvey(uint64_t* operand, const NTTTables& tables);

// ============================================================================
// Multi-RNS NTT Operations
// ============================================================================

/**
 * @brief Apply forward NTT to each RNS component
 * 
 * @param operand Pointer to RNS polynomial data [k][n]
 * @param coeff_modulus_size Number of RNS levels (k)
 * @param tables Array of NTT tables, one per level
 */
inline void ntt_negacyclic_harvey(uint64_t* operand, size_t coeff_modulus_size,
                                   const NTTTables* tables) {
    for (size_t i = 0; i < coeff_modulus_size; ++i) {
        size_t n = tables[i].coeff_count();
        ntt_negacyclic_harvey(operand + i * n, tables[i]);
    }
}

/**
 * @brief Apply inverse NTT to each RNS component
 */
inline void inverse_ntt_negacyclic_harvey(uint64_t* operand, size_t coeff_modulus_size,
                                           const NTTTables* tables) {
    for (size_t i = 0; i < coeff_modulus_size; ++i) {
        size_t n = tables[i].coeff_count();
        inverse_ntt_negacyclic_harvey(operand + i * n, tables[i]);
    }
}

// ============================================================================
// AVX2 Accelerated NTT (optional)
// ============================================================================

#ifdef __AVX2__

/**
 * @brief AVX2-accelerated forward NTT
 * 
 * Uses 256-bit SIMD to process 4 butterflies in parallel.
 * Falls back to scalar for small sizes.
 */
void ntt_negacyclic_harvey_avx2(uint64_t* operand, const NTTTables& tables);

/**
 * @brief AVX2-accelerated inverse NTT
 */
void inverse_ntt_negacyclic_harvey_avx2(uint64_t* operand, const NTTTables& tables);

#endif // __AVX2__

// ============================================================================
// AVX-512 Accelerated NTT (optional, v4.13.0+)
// ============================================================================

#if defined(__AVX512F__) && defined(__AVX512VL__)

/**
 * @brief AVX-512-accelerated forward NTT
 * 
 * Uses 512-bit SIMD to process 8 butterflies in parallel.
 * Provides ~2x speedup over AVX2 for n >= 4096.
 * 
 * @param[in,out] operand Coefficient array of size n
 * @param tables Precomputed NTT tables
 */
void ntt_negacyclic_harvey_avx512(uint64_t* operand, const NTTTables& tables);

/**
 * @brief AVX-512-accelerated inverse NTT
 */
void inverse_ntt_negacyclic_harvey_avx512(uint64_t* operand, const NTTTables& tables);

#endif // __AVX512F__ && __AVX512VL__

// ============================================================================
// NTT Tables Factory
// ============================================================================

/**
 * @brief Create NTT tables for multiple moduli
 * @param coeff_count_power log2(n)
 * @param moduli Vector of NTT-friendly primes
 * @return Vector of NTT tables
 */
std::vector<NTTTables> create_ntt_tables(int coeff_count_power,
                                          const std::vector<Modulus>& moduli);

/**
 * @brief Check if a prime is NTT-friendly for given n
 * @param q Prime to check
 * @param n Polynomial degree
 * @return true if q ≡ 1 (mod 2n) and q is prime
 */
bool is_ntt_prime(uint64_t q, size_t n);

/**
 * @brief Generate NTT-friendly primes
 * @param bit_size Desired bit size of primes
 * @param n Polynomial degree
 * @param count Number of primes to generate
 * @return Vector of NTT-friendly primes
 */
std::vector<uint64_t> generate_ntt_primes(int bit_size, size_t n, size_t count);

} // namespace fhe
} // namespace kctsb

#endif // KCTSB_ADVANCED_FE_COMMON_NTT_HARVEY_HPP
