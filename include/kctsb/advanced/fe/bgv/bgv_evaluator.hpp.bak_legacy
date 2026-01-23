/**
 * @file bgv_evaluator.hpp
 * @brief BGV Homomorphic Evaluation Operations
 * 
 * Provides homomorphic arithmetic operations on BGV ciphertexts:
 * - Addition and subtraction
 * - Multiplication with relinearization
 * - Rotation and conjugation
 * - Modulus switching (noise management)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_ADVANCED_FE_BGV_EVALUATOR_HPP
#define KCTSB_ADVANCED_FE_BGV_EVALUATOR_HPP

#include "bgv_context.hpp"

namespace kctsb {
namespace fhe {
namespace bgv {

/**
 * @brief BGV Homomorphic Evaluator
 * 
 * Performs homomorphic operations on ciphertexts.
 * All operations are in-place or return new ciphertexts.
 */
class BGVEvaluator {
public:
    /**
     * @brief Construct evaluator for given context
     * @param context BGV context (must outlive evaluator)
     */
    explicit BGVEvaluator(const BGVContext& context);
    
    // ==================== Addition ====================
    
    /**
     * @brief Add two ciphertexts
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext  
     * @return Sum ct1 + ct2
     */
    BGVCiphertext add(const BGVCiphertext& ct1, 
                      const BGVCiphertext& ct2) const;
    
    /**
     * @brief Add ciphertext and plaintext
     * @param ct Ciphertext
     * @param pt Plaintext
     * @return ct + pt
     */
    BGVCiphertext add_plain(const BGVCiphertext& ct, 
                             const BGVPlaintext& pt) const;
    
    /**
     * @brief In-place addition
     */
    void add_inplace(BGVCiphertext& ct1, 
                     const BGVCiphertext& ct2) const;
    
    void add_plain_inplace(BGVCiphertext& ct, 
                            const BGVPlaintext& pt) const;
    
    // ==================== Subtraction ====================
    
    /**
     * @brief Subtract ciphertexts
     * @return ct1 - ct2
     */
    BGVCiphertext sub(const BGVCiphertext& ct1, 
                      const BGVCiphertext& ct2) const;
    
    BGVCiphertext sub_plain(const BGVCiphertext& ct, 
                             const BGVPlaintext& pt) const;
    
    void sub_inplace(BGVCiphertext& ct1, 
                     const BGVCiphertext& ct2) const;
    
    void sub_plain_inplace(BGVCiphertext& ct, 
                            const BGVPlaintext& pt) const;
    
    /**
     * @brief Negate ciphertext
     * @return -ct
     */
    BGVCiphertext negate(const BGVCiphertext& ct) const;
    void negate_inplace(BGVCiphertext& ct) const;
    
    // ==================== Multiplication ====================
    
    /**
     * @brief Multiply two ciphertexts
     * 
     * Result has size (ct1.size() + ct2.size() - 1).
     * Must call relinearize() to reduce back to size 2.
     * 
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @return Product ct1 * ct2
     */
    BGVCiphertext multiply(const BGVCiphertext& ct1, 
                            const BGVCiphertext& ct2) const;
    
    /**
     * @brief Multiply ciphertext by plaintext
     * @return ct * pt
     */
    BGVCiphertext multiply_plain(const BGVCiphertext& ct, 
                                  const BGVPlaintext& pt) const;
    
    void multiply_inplace(BGVCiphertext& ct1, 
                          const BGVCiphertext& ct2) const;
    
    void multiply_plain_inplace(BGVCiphertext& ct, 
                                 const BGVPlaintext& pt) const;
    
    /**
     * @brief Square a ciphertext
     * @return ct^2
     */
    BGVCiphertext square(const BGVCiphertext& ct) const;
    void square_inplace(BGVCiphertext& ct) const;
    
    /**
     * @brief Multiply and relinearize in one step
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @param rk Relinearization key
     * @return ct1 * ct2 (relinearized to size 2)
     */
    BGVCiphertext multiply_relin(const BGVCiphertext& ct1,
                                  const BGVCiphertext& ct2,
                                  const BGVRelinKey& rk) const;
    
    // ==================== Relinearization ====================
    
    /**
     * @brief Reduce ciphertext size after multiplication
     * 
     * Transforms (c_0, c_1, c_2) to (c_0', c_1') using key switching.
     * Required after each multiplication to prevent blowup.
     * 
     * @param ct Ciphertext of size > 2
     * @param rk Relinearization key
     * @return Relinearized ciphertext of size 2
     */
    BGVCiphertext relinearize(const BGVCiphertext& ct, 
                               const BGVRelinKey& rk) const;
    
    void relinearize_inplace(BGVCiphertext& ct, 
                              const BGVRelinKey& rk) const;
    
    // ==================== Rotation (SIMD) ====================
    
    /**
     * @brief Rotate slots left
     * 
     * For batched ciphertexts, rotates the plaintext slots.
     * [a, b, c, d] --rotate(1)--> [b, c, d, a]
     * 
     * @param ct Batched ciphertext
     * @param steps Number of positions to rotate (negative = right)
     * @param gk Galois keys
     * @return Rotated ciphertext
     */
    BGVCiphertext rotate(const BGVCiphertext& ct, int steps,
                          const BGVGaloisKey& gk) const;
    
    void rotate_inplace(BGVCiphertext& ct, int steps,
                         const BGVGaloisKey& gk) const;
    
    /**
     * @brief Rotate rows (for matrix-like slot arrangements)
     */
    BGVCiphertext rotate_rows(const BGVCiphertext& ct, int steps,
                               const BGVGaloisKey& gk) const;
    
    /**
     * @brief Swap columns (for matrix-like slot arrangements)
     */
    BGVCiphertext rotate_columns(const BGVCiphertext& ct,
                                  const BGVGaloisKey& gk) const;
    
    // ==================== Modulus Switching ====================
    
    /**
     * @brief Switch to next lower modulus level
     * 
     * Reduces noise by scaling down the ciphertext.
     * Trades precision for noise headroom.
     * 
     * @param ct Ciphertext at level k
     * @return Ciphertext at level k+1 (smaller modulus)
     */
    BGVCiphertext mod_switch(const BGVCiphertext& ct) const;
    void mod_switch_inplace(BGVCiphertext& ct) const;
    
    /**
     * @brief Switch to specific level
     * @param ct Ciphertext
     * @param level Target level (must be >= current level)
     */
    BGVCiphertext mod_switch_to(const BGVCiphertext& ct, 
                                 uint32_t level) const;
    void mod_switch_to_inplace(BGVCiphertext& ct, 
                                uint32_t level) const;
    
    // ==================== Complex Operations ====================
    
    /**
     * @brief Compute inner product of ciphertext vectors
     * @param ct1 First vector of ciphertexts
     * @param ct2 Second vector (same size)
     * @param rk Relinearization key
     * @return Sum of products
     */
    BGVCiphertext inner_product(
        const std::vector<BGVCiphertext>& ct1,
        const std::vector<BGVCiphertext>& ct2,
        const BGVRelinKey& rk) const;
    
    /**
     * @brief Exponentiation by squaring
     * @param ct Ciphertext
     * @param exponent Power (must be >= 1)
     * @param rk Relinearization key
     * @return ct^exponent
     */
    BGVCiphertext power(const BGVCiphertext& ct, uint64_t exponent,
                         const BGVRelinKey& rk) const;
    
    /**
     * @brief Apply automorphism σ: X -> X^k
     * @param ct Ciphertext
     * @param galois_elt Galois element k
     * @param gk Galois key for k
     * @return σ(ct)
     */
    BGVCiphertext apply_galois(const BGVCiphertext& ct, 
                                uint64_t galois_elt,
                                const BGVGaloisKey& gk) const;
    
    // ==================== Utility ====================
    
    /// Get associated context
    const BGVContext& context() const { return context_; }
    
    /// Check if two ciphertexts have compatible parameters
    bool is_compatible(const BGVCiphertext& ct1, 
                       const BGVCiphertext& ct2) const;
    
    /// Rescale ciphertext (for CKKS-style operations, optional in BGV)
    void rescale_inplace(BGVCiphertext& ct) const;

private:
    const BGVContext& context_;
    
    // Key switching helper
    BGVCiphertext key_switch(const BGVCiphertext& ct,
                              const std::vector<std::pair<RingElement, 
                                  RingElement>>& switch_key) const;
    
    // Decompose polynomial for key switching
    std::vector<RingElement> decompose(const RingElement& poly) const;
};

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_ADVANCED_FE_BGV_EVALUATOR_HPP
