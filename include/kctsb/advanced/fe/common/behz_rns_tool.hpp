/**
 * @file behz_rns_tool.hpp
 * @brief BEHZ RNS Tool for Industrial-Grade BFV/BGV Multiplication
 * 
 * Implements the Bajard-Eynard-Hasan-Zucca (BEHZ) 2016 algorithm for high-performance
 * RNS-based homomorphic encryption operations. This is the same algorithm used by
 * Microsoft SEAL for BFV ciphertext multiplication.
 * 
 * The BEHZ method solves the fundamental RNS problem: computing round(c * t / Q) where
 * c is only available in RNS form. It uses an auxiliary modulus base B to extend
 * computations and perform Montgomery-style reduction.
 * 
 * Key components:
 * - RNSBase: Manages a set of coprime moduli with CRT precomputation
 * - BaseConverter: Fast approximate and exact base conversion between RNS bases
 * - BEHZRNSTool: Complete BEHZ machinery for BFV multiplication rescaling
 * 
 * Performance targets (n=8192):
 * - Fast base conversion: O(L * n) with SIMD optimization
 * - Multiply + Relin: < 15ms (competitive with SEAL's ~18ms)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.11.1
 * @since Phase 4d - Industrial FHE performance
 */

#ifndef KCTSB_ADVANCED_FE_COMMON_BEHZ_RNS_TOOL_HPP
#define KCTSB_ADVANCED_FE_COMMON_BEHZ_RNS_TOOL_HPP

#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include "kctsb/advanced/fe/common/ntt.hpp"
#include <vector>
#include <memory>
#include <cstdint>

namespace kctsb {
namespace fhe {

// Forward declarations
class RNSContext;
namespace ntt {
class NTTTable;
}

// ============================================================================
// RNSBase: Manages a set of coprime moduli with CRT precomputation
// ============================================================================

/**
 * @brief Represents a base of coprime moduli for RNS representation
 * 
 * Precomputes all values needed for CRT operations:
 * - Q = product of all moduli
 * - Q_i = Q / q_i (punctured products)
 * - q_i^{-1} mod q_i (CRT reconstruction coefficients)
 */
class RNSBase {
public:
    /**
     * @brief Construct RNSBase from vector of moduli
     * @param primes Vector of coprime primes
     */
    explicit RNSBase(const std::vector<Modulus>& primes);
    
    /**
     * @brief Construct RNSBase from RNSContext (convenience)
     */
    explicit RNSBase(const RNSContext* ctx);
    
    /**
     * @brief Default constructor for empty base
     */
    RNSBase() = default;
    
    /**
     * @brief Get number of moduli in base
     */
    size_t size() const noexcept { return primes_.size(); }
    
    /**
     * @brief Get modulus at index
     */
    const Modulus& operator[](size_t idx) const { return primes_[idx]; }
    
    /**
     * @brief Get all moduli
     */
    const std::vector<Modulus>& primes() const noexcept { return primes_; }
    
    /**
     * @brief Get punctured product Q/q_i for each modulus
     * 
     * Returns Q_i = Q / q_i as multi-precision integers (L x L uint64_t)
     */
    const std::vector<std::vector<uint64_t>>& punctured_products() const noexcept {
        return punctured_products_;
    }
    
    /**
     * @brief Get (Q/q_i)^{-1} mod q_i for CRT reconstruction
     */
    const std::vector<MultiplyUIntModOperand>& inv_punctured_mod_base() const noexcept {
        return inv_punctured_mod_base_;
    }
    
    /**
     * @brief Get Q mod q_i for each modulus (used in various computations)
     */
    uint64_t prod_mod(size_t idx) const { return prod_mod_primes_[idx]; }
    
    /**
     * @brief Extend this base with an additional modulus
     * @param new_mod The new modulus to add
     * @return New RNSBase with the additional modulus
     */
    RNSBase extend(const Modulus& new_mod) const;
    
private:
    void initialize();
    
    std::vector<Modulus> primes_;
    std::vector<std::vector<uint64_t>> punctured_products_;  // Q/q_i as L-word integers
    std::vector<MultiplyUIntModOperand> inv_punctured_mod_base_;  // (Q/q_i)^{-1} mod q_i
    std::vector<uint64_t> prod_mod_primes_;  // Q mod q_i
};

// ============================================================================
// BaseConverter: Fast conversion between RNS bases
// ============================================================================

/**
 * @brief Performs fast base conversion between two RNS bases
 * 
 * Given a value x in base {q_0, ..., q_{k-1}} (input base), computes
 * x mod {p_0, ..., p_{m-1}} (output base).
 * 
 * Two methods:
 * 1. fast_convert: Approximate (may have error ~1), O(k * m) per coefficient
 * 2. exact_convert: Exact conversion using Shenoy-Kumaresan correction
 * 
 * The fast_convert is sufficient for intermediate BFV computations;
 * exact_convert is needed only for final decryption.
 */
class BaseConverter {
public:
    /**
     * @brief Construct converter from input base to output base
     * @param ibase Input RNS base
     * @param obase Output RNS base
     */
    BaseConverter(const RNSBase& ibase, const RNSBase& obase);
    
    /**
     * @brief Default constructor
     */
    BaseConverter() = default;
    
    /**
     * @brief Fast (approximate) base conversion for polynomial
     * 
     * Computes output[i] = sum_j (input[j] * hat_q_j mod p_i) for each coefficient
     * where hat_q_j = (Q/q_j) * (Q/q_j)^{-1} mod q_j
     * 
     * @param input Input polynomial in RNS form (ibase.size() x coeff_count)
     * @param output Output polynomial in RNS form (obase.size() x coeff_count)
     * @param coeff_count Number of polynomial coefficients
     */
    void fast_convert_array(const uint64_t* input, uint64_t* output, 
                            size_t coeff_count) const;
    
    /**
     * @brief Exact base conversion with Shenoy-Kumaresan correction
     * 
     * For exact conversion, we track the v values and apply correction.
     * Used in BFV decryption.
     * 
     * @param input Input polynomial in RNS form
     * @param output Output polynomial (single modulus result)
     * @param coeff_count Number of polynomial coefficients
     */
    void exact_convert_array(const uint64_t* input, uint64_t* output,
                             size_t coeff_count) const;
    
    /**
     * @brief Get input base
     */
    const RNSBase& ibase() const noexcept { return ibase_; }
    
    /**
     * @brief Get output base
     */
    const RNSBase& obase() const noexcept { return obase_; }
    
private:
    RNSBase ibase_;
    RNSBase obase_;
    
    // base_change_matrix_[j][i] = (Q/q_i) mod p_j
    // For computing: sum over i of (x_i * hat_q_i) mod p_j
    std::vector<std::vector<uint64_t>> base_change_matrix_;
};

// ============================================================================
// BEHZRNSTool: Complete BEHZ machinery for BFV multiplication
// ============================================================================

/**
 * @brief BEHZ RNS Tool for BFV ciphertext multiplication
 * 
 * Implements the Bajard-Eynard-Hasan-Zucca algorithm for computing
 * round(c * t / Q) in RNS without CRT reconstruction.
 * 
 * Key insight: Use auxiliary base B with similar size to Q, and modulus m_tilde.
 * The algorithm:
 * 1. Extend tensor product to base B ∪ {m_tilde} via fastbconv_m_tilde
 * 2. Montgomery-style reduction (sm_mrq) to get result in Bsk
 * 3. Fast floor division via fast_floor to get final RNS result
 * 
 * Bases used:
 * - Q = {q_0, ..., q_{L-1}}: Original ciphertext modulus
 * - B = {b_0, ..., b_{L-1}}: Auxiliary base (same size as Q)
 * - m_sk: Special modulus for Shenoy-Kumaresan correction
 * - m_tilde = 2^32: Montgomery-style auxiliary modulus
 * - Bsk = B ∪ {m_sk}: Extended auxiliary base
 */
class BEHZRNSTool {
public:
    /**
     * @brief Construct BEHZ tool for given parameters
     * @param n Polynomial degree (must be power of 2)
     * @param q_base The main modulus base Q
     * @param t Plaintext modulus
     */
    BEHZRNSTool(size_t n, const RNSBase& q_base, uint64_t t);
    
    /**
     * @brief Default constructor
     */
    BEHZRNSTool() = default;
    
    // ========================================================================
    // BEHZ Core Operations
    // ========================================================================
    
    /**
     * @brief Fast base conversion Q → Bsk ∪ {m_tilde}
     * 
     * First step of BEHZ: extend input to auxiliary base.
     * Multiplies input by m_tilde for Montgomery reduction.
     * 
     * @param input Input in base Q (L * n values)
     * @param output Output in base Bsk ∪ {m_tilde} ((L+2) * n values)
     */
    void fastbconv_m_tilde(const uint64_t* input, uint64_t* output) const;
    
    /**
     * @brief Shenoy-Kumaresan Montgomery reduction in Bsk
     * 
     * Computes (input + q * r_{m_tilde}) / m_tilde in base Bsk
     * where r_{m_tilde} = -input * q^{-1} mod m_tilde
     * 
     * @param input Input in base Bsk ∪ {m_tilde}
     * @param output Output in base Bsk
     */
    void sm_mrq(const uint64_t* input, uint64_t* output) const;
    
    /**
     * @brief Fast floor: compute floor(input / Q) in base Bsk
     * 
     * Given input in Q ∪ Bsk, computes floor(input / Q) in Bsk.
     * Uses fast conversion Q → Bsk and Shenoy-Kumaresan correction.
     * 
     * @param input Input in base Q ∪ Bsk ((2L+1) * n values)
     * @param output Output in base Bsk ((L+1) * n values)
     */
    void fast_floor(const uint64_t* input, uint64_t* output) const;
    
    /**
     * @brief Fast conversion Bsk → Q (Shenoy-Kumaresan)
     * 
     * Final step: convert from auxiliary base back to Q.
     * 
     * @param input Input in base Bsk
     * @param output Output in base Q
     */
    void fastbconv_sk(const uint64_t* input, uint64_t* output) const;
    
    // ========================================================================
    // BFV Multiplication Rescaling
    // ========================================================================
    
    /**
     * @brief Compute round(c * t / Q) for BFV ciphertext multiplication
     * 
     * This is the complete BEHZ rescaling operation:
     * 1. Multiply input by t: c' = c * t (in Q)
     * 2. Extend to auxiliary base: c' in Q ∪ Bsk via fastbconv_m_tilde + sm_mrq
     * 3. Fast floor: floor(c' / Q) in Bsk
     * 4. Convert back: result in Q via fastbconv_sk
     * 
     * @param input Input polynomial in base Q (tensor product component)
     * @param output Output polynomial in base Q (rescaled result)
     */
    void multiply_and_rescale(const uint64_t* input, uint64_t* output) const;
    
    // ========================================================================
    // Modulus Switching (for BGV/BFV level reduction)
    // ========================================================================
    
    /**
     * @brief Divide and round by last modulus q_{L-1}
     * 
     * Computes round(input / q_{L-1}) for modulus switching.
     * Input: L-level polynomial
     * Output: (L-1)-level polynomial
     * 
     * @param input Input polynomial in base Q
     * @param output Output polynomial in base Q' (one fewer modulus)
     */
    void divide_and_round_q_last_inplace(uint64_t* data) const;
    
    // ========================================================================
    // Decryption Scaling
    // ========================================================================
    
    /**
     * @brief BFV decryption scaling: compute round(c * t / Q) mod t
     * 
     * Optimized for single plaintext modulus output.
     * Uses {t, gamma} base trick for exact rounding.
     * 
     * @param input Input polynomial in base Q
     * @param output Output plaintext (single value per coefficient)
     */
    void decrypt_scale_and_round(const uint64_t* input, uint64_t* output) const;
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    size_t n() const noexcept { return n_; }
    size_t q_size() const noexcept { return q_base_.size(); }
    size_t bsk_size() const noexcept { return bsk_base_.size(); }
    uint64_t t() const noexcept { return t_; }
    const RNSBase& q_base() const noexcept { return q_base_; }
    const RNSBase& b_base() const noexcept { return b_base_; }
    const RNSBase& bsk_base() const noexcept { return bsk_base_; }
    
private:
    void initialize();
    
    // Configuration
    size_t n_;              // Polynomial degree
    uint64_t t_;            // Plaintext modulus
    
    // RNS Bases
    RNSBase q_base_;        // Main modulus base Q
    RNSBase b_base_;        // Auxiliary base B
    RNSBase bsk_base_;      // B ∪ {m_sk}
    RNSBase bsk_m_tilde_;   // Bsk ∪ {m_tilde}
    
    // Special moduli
    Modulus m_sk_;          // Special modulus for SK correction
    Modulus m_tilde_;       // Montgomery auxiliary (2^32)
    Modulus gamma_;         // For t-gamma decryption trick
    
    // Base converters
    std::unique_ptr<BaseConverter> q_to_bsk_conv_;
    std::unique_ptr<BaseConverter> q_to_m_tilde_conv_;
    std::unique_ptr<BaseConverter> b_to_q_conv_;
    std::unique_ptr<BaseConverter> b_to_m_sk_conv_;
    std::unique_ptr<BaseConverter> q_to_t_conv_;
    std::unique_ptr<BaseConverter> q_to_t_gamma_conv_;
    
    // Precomputed values
    std::vector<uint64_t> prod_B_mod_q_;           // prod(B) mod q_i
    std::vector<MultiplyUIntModOperand> inv_prod_q_mod_Bsk_;  // Q^{-1} mod each Bsk modulus
    MultiplyUIntModOperand inv_prod_B_mod_m_sk_;   // B^{-1} mod m_sk
    std::vector<MultiplyUIntModOperand> inv_m_tilde_mod_Bsk_;  // m_tilde^{-1} mod Bsk
    MultiplyUIntModOperand neg_inv_prod_q_mod_m_tilde_;  // -Q^{-1} mod m_tilde
    std::vector<uint64_t> prod_q_mod_Bsk_;         // Q mod each Bsk modulus
    MultiplyUIntModOperand inv_gamma_mod_t_;       // gamma^{-1} mod t
    std::vector<MultiplyUIntModOperand> prod_t_gamma_mod_q_;  // (t * gamma) mod q_i
    std::vector<MultiplyUIntModOperand> neg_inv_q_mod_t_gamma_;  // -Q^{-1} mod {t, gamma}
    std::vector<MultiplyUIntModOperand> inv_q_last_mod_q_;  // q_{L-1}^{-1} mod q_i
    
    // Rounding correction: Q/2 mod q_i (for converting floor to round)
    std::vector<uint64_t> half_q_mod_q_;           // (Q/2) mod q_i for rounding
    std::vector<uint64_t> half_q_mod_Bsk_;         // (Q/2) mod Bsk[i] for rounding
    
    // NTT tables for Bsk base
    std::vector<std::unique_ptr<ntt::NTTTable>> bsk_ntt_tables_;
};

} // namespace fhe
} // namespace kctsb

#endif // KCTSB_ADVANCED_FE_COMMON_BEHZ_RNS_TOOL_HPP
