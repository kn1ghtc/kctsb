/**
 * @file rns.hpp
 * @brief Residue Number System (RNS) for Large Modulus Operations
 * 
 * RNS representation splits large integers across multiple small moduli,
 * enabling efficient modular arithmetic without multiprecision operations.
 * 
 * Key features:
 * - CRT-based integer reconstruction
 * - Fast base conversion (BEHZ algorithm)
 * - Integration with NTT for polynomial operations
 * 
 * Used in BGV/BFV/CKKS for handling large ciphertext moduli (q ≈ 2^200+).
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#ifndef KCTSB_ADVANCED_FE_COMMON_RNS_HPP
#define KCTSB_ADVANCED_FE_COMMON_RNS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <stdexcept>

#include "kctsb/advanced/fe/common/ntt.hpp"

namespace kctsb {
namespace fhe {
namespace rns {

// ============================================================================
// RNS Base (Collection of Co-Prime Moduli)
// ============================================================================

/**
 * @brief Precomputed values for an RNS base
 * 
 * Stores moduli and precomputed CRT-related constants:
 * - Product of all moduli: Q = q_0 * q_1 * ... * q_{k-1}
 * - Partial products: Q_i = Q / q_i
 * - Modular inverses: Q_i^(-1) mod q_i
 */
class RNSBase {
public:
    /**
     * @brief Construct RNS base from list of coprime moduli
     * @param moduli List of pairwise coprime moduli (each < 2^62)
     * @param poly_degree Polynomial degree (power of 2, for NTT compatibility)
     * @throws std::invalid_argument if moduli are not coprime or not NTT-friendly
     */
    RNSBase(const std::vector<uint64_t>& moduli, size_t poly_degree);
    
    /**
     * @brief Number of moduli in this base
     */
    size_t size() const { return moduli_.size(); }
    
    /**
     * @brief Get the i-th modulus
     */
    uint64_t modulus(size_t i) const { return moduli_[i]; }
    
    /**
     * @brief Get all moduli
     */
    const std::vector<uint64_t>& moduli() const { return moduli_; }
    
    /**
     * @brief Get polynomial degree
     */
    size_t poly_degree() const { return poly_degree_; }
    
    /**
     * @brief Get Barrett constants for i-th modulus
     */
    const ntt::BarrettConstants& barrett(size_t i) const { return barrett_[i]; }
    
    /**
     * @brief Get NTT table for i-th modulus
     */
    const ntt::NTTTable& ntt_table(size_t i) const;
    
    /**
     * @brief Get Q_i^(-1) mod q_i for CRT reconstruction
     */
    uint64_t q_hat_inv(size_t i) const { return q_hat_inv_mod_qi_[i]; }
    
    /**
     * @brief Get Q_i mod q_j for base conversion
     */
    uint64_t q_hat_mod_qj(size_t i, size_t j) const { 
        return q_hat_mod_qj_[i * moduli_.size() + j]; 
    }

private:
    size_t poly_degree_;                           ///< Polynomial degree n
    std::vector<uint64_t> moduli_;                 ///< q_0, q_1, ..., q_{k-1}
    std::vector<ntt::BarrettConstants> barrett_;   ///< Barrett constants per modulus
    std::vector<uint64_t> q_hat_inv_mod_qi_;       ///< Q_i^(-1) mod q_i
    std::vector<uint64_t> q_hat_mod_qj_;           ///< Q_i mod q_j (flattened 2D)
};

// ============================================================================
// RNS Polynomial (Multi-Modulus Representation)
// ============================================================================

/**
 * @brief Polynomial in RNS representation
 * 
 * Stores coefficients modulo each prime in the RNS base.
 * Supports both coefficient and NTT (evaluation) forms.
 * 
 * Memory layout: coeffs_[level][coeff_idx] where:
 * - level ∈ [0, num_moduli)
 * - coeff_idx ∈ [0, poly_degree)
 */
class RNSPoly {
public:
    /**
     * @brief Construct zero polynomial
     * @param base RNS base (defines moduli and degree)
     */
    explicit RNSPoly(const RNSBase& base);
    
    /**
     * @brief Construct from coefficient representation
     * @param base RNS base
     * @param coeffs Coefficient vector (one per level)
     */
    RNSPoly(const RNSBase& base, 
            const std::vector<std::vector<uint64_t>>& coeffs);
    
    /**
     * @brief Copy constructor
     */
    RNSPoly(const RNSPoly& other);
    
    /**
     * @brief Move constructor
     */
    RNSPoly(RNSPoly&& other) noexcept;
    
    /**
     * @brief Copy assignment
     */
    RNSPoly& operator=(const RNSPoly& other);
    
    /**
     * @brief Move assignment
     */
    RNSPoly& operator=(RNSPoly&& other) noexcept;
    
    // ========================================================================
    // NTT Form Conversion
    // ========================================================================
    
    /**
     * @brief Convert to NTT (evaluation) form
     * 
     * Applies forward NTT to each RNS component.
     * After conversion, pointwise multiplication becomes valid.
     */
    void to_ntt();
    
    /**
     * @brief Convert from NTT to coefficient form
     * 
     * Applies inverse NTT to each RNS component.
     */
    void from_ntt();
    
    /**
     * @brief Check if polynomial is in NTT form
     */
    bool is_ntt() const { return is_ntt_; }
    
    // ========================================================================
    // Element Access
    // ========================================================================
    
    /**
     * @brief Access coefficients at given level (mutable)
     * @param level RNS level index
     * @return Pointer to coefficient array for this level
     */
    uint64_t* operator[](size_t level) { return coeffs_[level].data(); }
    
    /**
     * @brief Access coefficients at given level (const)
     */
    const uint64_t* operator[](size_t level) const { return coeffs_[level].data(); }
    
    /**
     * @brief Get coefficient vector at given level
     */
    std::vector<uint64_t>& level(size_t idx) { return coeffs_[idx]; }
    
    /**
     * @brief Get coefficient vector at given level (const)
     */
    const std::vector<uint64_t>& level(size_t idx) const { return coeffs_[idx]; }
    
    /**
     * @brief Get number of RNS levels
     */
    size_t num_levels() const { return coeffs_.size(); }
    
    /**
     * @brief Get polynomial degree
     */
    size_t degree() const { return base_.poly_degree(); }
    
    /**
     * @brief Get underlying RNS base
     */
    const RNSBase& base() const { return base_; }
    
    // ========================================================================
    // Arithmetic Operations (In-Place)
    // ========================================================================
    
    /**
     * @brief Add another polynomial (element-wise mod each q_i)
     * @param other Polynomial to add (must have same base)
     * @return Reference to this
     */
    RNSPoly& operator+=(const RNSPoly& other);
    
    /**
     * @brief Subtract another polynomial
     */
    RNSPoly& operator-=(const RNSPoly& other);
    
    /**
     * @brief Multiply by another polynomial
     * @note Both polynomials must be in NTT form
     * @param other Polynomial to multiply (must have same base, NTT form)
     * @return Reference to this
     */
    RNSPoly& operator*=(const RNSPoly& other);
    
    /**
     * @brief Negate all coefficients
     */
    void negate();
    
    /**
     * @brief Set all coefficients to zero
     */
    void set_zero();

private:
    const RNSBase& base_;                          ///< Reference to RNS base
    std::vector<std::vector<uint64_t>> coeffs_;    ///< [level][coeff_idx]
    bool is_ntt_;                                  ///< True if in NTT form
};

// ============================================================================
// Binary Arithmetic Operators
// ============================================================================

/**
 * @brief Add two RNS polynomials
 */
RNSPoly operator+(const RNSPoly& a, const RNSPoly& b);

/**
 * @brief Subtract two RNS polynomials
 */
RNSPoly operator-(const RNSPoly& a, const RNSPoly& b);

/**
 * @brief Multiply two RNS polynomials (must be in NTT form)
 */
RNSPoly operator*(const RNSPoly& a, const RNSPoly& b);

// ============================================================================
// RNS Base Conversion
// ============================================================================

/**
 * @brief Fast base converter using BEHZ algorithm
 * 
 * Converts polynomials between two RNS bases efficiently.
 * Used for modulus switching and BFV/BGV scaling operations.
 */
class RNSBaseConverter {
public:
    /**
     * @brief Construct converter between two bases
     * @param from_base Source RNS base
     * @param to_base Target RNS base
     */
    RNSBaseConverter(const RNSBase& from_base, const RNSBase& to_base);
    
    /**
     * @brief Convert polynomial from source to target base
     * @param input Polynomial in source base representation
     * @param output Polynomial in target base representation (output)
     */
    void convert(const RNSPoly& input, RNSPoly& output) const;
    
private:
    const RNSBase& from_base_;
    const RNSBase& to_base_;
    
    // Precomputed conversion matrices
    std::vector<std::vector<uint64_t>> conversion_matrix_;  ///< [from_level][to_level]
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Generate a list of NTT-friendly primes for RNS
 * 
 * Each prime q satisfies:
 * - q is prime
 * - q = 1 (mod 2n) for NTT compatibility
 * - q is approximately bit_size bits
 * 
 * @param count Number of primes to generate
 * @param bit_size Approximate bit size of each prime (e.g., 60)
 * @param poly_degree Polynomial degree n (power of 2)
 * @return Vector of NTT-friendly primes
 */
std::vector<uint64_t> generate_ntt_primes(
    size_t count, 
    size_t bit_size, 
    size_t poly_degree);

/**
 * @brief Check if all moduli are pairwise coprime
 */
bool are_coprime(const std::vector<uint64_t>& moduli);

}  // namespace rns
}  // namespace fhe
}  // namespace kctsb

#endif  // KCTSB_ADVANCED_FE_COMMON_RNS_HPP
