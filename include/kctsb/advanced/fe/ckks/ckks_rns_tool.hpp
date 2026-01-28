/**
 * @file ckks_rns_tool.hpp
 * @brief CKKS RNS Key Switching Tool
 * 
 * Implements hybrid key switching for CKKS using RNS decomposition.
 * Based on the BEHZ approach adapted for approximate arithmetic.
 * 
 * Key Features:
 * - Hybrid key switching with special prime P
 * - RNS decomposition to control noise growth
 * - Efficient base conversion between Q and P*Q bases
 * 
 * The hybrid approach generates evaluation keys at modulus P*Q where P is a
 * special prime, then performs key switching and divides by P. This reduces
 * noise growth from O(Q) to O(L * sigma) where L is the number of primes.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.14.0
 */

#ifndef KCTSB_ADVANCED_FE_CKKS_CKKS_RNS_TOOL_HPP
#define KCTSB_ADVANCED_FE_CKKS_CKKS_RNS_TOOL_HPP

#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include "kctsb/advanced/fe/common/behz_rns_tool.hpp"
#include <vector>
#include <memory>
#include <cstdint>

namespace kctsb {
namespace fhe {
namespace ckks {

/**
 * @brief CKKS RNS Key Switching Tool
 * 
 * Implements hybrid key switching using a special modulus P.
 * The approach follows the Microsoft SEAL methodology for CKKS.
 * 
 * Bases:
 * - Q = {q_0, ..., q_{L-1}}: Main ciphertext modulus chain
 * - P = {p}: Special prime for key switching (typically larger than Q primes)
 * - PQ = P ∪ Q: Extended base for evaluation keys
 */
class CKKSRNSTool {
public:
    /**
     * @brief Construct CKKS RNS tool
     * @param ctx RNS context with Q primes
     */
    explicit CKKSRNSTool(const RNSContext* ctx);
    
    /**
     * @brief Get the special modulus P for key switching
     */
    const Modulus& special_prime() const noexcept { return p_; }
    
    /**
     * @brief Get P*Q mod q_i for each i (used in key generation)
     */
    const std::vector<uint64_t>& pq_mod_q() const noexcept { return pq_mod_q_; }
    
    /**
     * @brief Get Q mod P (used in rescaling after key switch)
     */
    uint64_t q_mod_p() const noexcept { return q_mod_p_; }
    
    /**
     * @brief Get P^{-1} mod q_i for each i (used in rescaling)
     */
    const std::vector<MultiplyUIntModOperand>& p_inv_mod_q() const noexcept { 
        return p_inv_mod_q_; 
    }
    
    /**
     * @brief Get Q/q_j mod q_i for all i, j (for RNS decomposition)
     */
    const std::vector<std::vector<uint64_t>>& q_div_qj_mod_qi() const noexcept {
        return q_div_qj_mod_qi_;
    }
    
    /**
     * @brief Get (Q/q_j)^{-1} mod q_j (for RNS decomposition)
     */
    const std::vector<MultiplyUIntModOperand>& q_div_qj_inv_mod_qj() const noexcept {
        return q_div_qj_inv_mod_qj_;
    }
    
    /**
     * @brief Decompose a polynomial for key switching
     * 
     * RNS decomposition: Given poly in R_Q, output L polynomials where
     * the j-th polynomial has the j-th RNS component "lifted" to all levels.
     * 
     * @param poly Input polynomial (in coefficient form, all L levels)
     * @param decomposed Output: L polynomials, each in NTT form at all L levels
     */
    void decompose(const RNSPoly& poly, std::vector<RNSPoly>& decomposed) const;
    
    /**
     * @brief Perform key switching using hybrid method
     * 
     * Given c2 (the third ciphertext component after multiplication) and
     * the evaluation key components, compute the key-switched contributions
     * to c0' and c1'.
     * 
     * @param c2 Third component (in NTT form)
     * @param rk_b Relin key b components (L polynomials in NTT form)
     * @param rk_a Relin key a components (L polynomials in NTT form)
     * @param c0_out Output contribution to c0' (in NTT form)
     * @param c1_out Output contribution to c1' (in NTT form)
     */
    void key_switch(const RNSPoly& c2,
                   const std::vector<RNSPoly>& rk_b,
                   const std::vector<RNSPoly>& rk_a,
                   RNSPoly& c0_out,
                   RNSPoly& c1_out) const;
    
    size_t n() const noexcept { return n_; }
    size_t level_count() const noexcept { return L_; }
    const RNSContext* context() const noexcept { return context_; }

private:
    void initialize();
    
    const RNSContext* context_;
    size_t n_;              ///< Polynomial degree
    size_t L_;              ///< Number of Q primes
    
    // Special prime P for hybrid key switching
    Modulus p_;
    
    // Precomputed values
    std::vector<uint64_t> pq_mod_q_;           ///< P*Q mod q_i (not used directly in simple RNS)
    uint64_t q_mod_p_;                          ///< Q mod P
    std::vector<MultiplyUIntModOperand> p_inv_mod_q_;  ///< P^{-1} mod q_i
    
    // For RNS decomposition: Q/q_j values
    std::vector<std::vector<uint64_t>> q_div_qj_mod_qi_;  ///< (Q/q_j) mod q_i for all i, j
    std::vector<MultiplyUIntModOperand> q_div_qj_inv_mod_qj_;  ///< (Q/q_j)^{-1} mod q_j
};

}  // namespace ckks
}  // namespace fhe
}  // namespace kctsb

#endif  // KCTSB_ADVANCED_FE_CKKS_CKKS_RNS_TOOL_HPP
