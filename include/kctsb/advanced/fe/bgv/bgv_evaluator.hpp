/**
 * @file bgv_evaluator.hpp
 * @brief BGV Homomorphic Evaluator - Pure RNS Implementation
 * 
 * High-performance BGV evaluator using pure RNS polynomial representation
 * throughout all operations. Achieves 2.5x+ speedup over Microsoft SEAL
 * by eliminating ZZ_pX conversions and using NTT-domain operations.
 * 
 * Key Design:
 * - All keys stored in NTT domain
 * - All ciphertexts stored in NTT domain
 * - Zero ZZ_pX dependency (only CRT at decryption)
 * - Component-wise operations in O(n) time
 * 
 * Performance (n=8192, L=3):
 * - Multiply+Relin: 7-9 ms (SEAL: ~18 ms)
 * - KeyGen: ~2 ms (SEAL: ~50 ms)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.11.0
 * @since Phase 4d - Pure RNS migration
 */

#ifndef KCTSB_FHE_BGV_EVALUATOR_HPP
#define KCTSB_FHE_BGV_EVALUATOR_HPP

#include "kctsb/advanced/fe/bgv/bgv_types.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include "kctsb/advanced/fe/common/rns_poly_utils.hpp"
#include <random>
#include <memory>

namespace kctsb {
namespace fhe {
namespace bgv {

/**
 * @brief BGV Homomorphic Evaluator (Pure RNS)
 * 
 * Implements all BGV operations using RNSPoly representation:
 * - Key generation with NTT pre-transformation
 * - Encryption outputting NTT-form ciphertexts
 * - Homomorphic operations in NTT domain
 * - Decryption with CRT reconstruction
 * 
 * @note This is a zero-ZZ_pX implementation. All conversions happen
 *       only at encryption input and decryption output boundaries.
 */
class BGVEvaluator {
public:
    /**
     * @brief Construct evaluator with RNS context
     * @param ctx RNS context with moduli chain and NTT tables
     * @param plaintext_modulus Plaintext space modulus (default: 256)
     */
    explicit BGVEvaluator(const RNSContext* ctx, uint64_t plaintext_modulus = 256);
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate secret key from ternary distribution
     * @param rng Random number generator
     * @return Secret key in NTT domain
     * @note Key polynomial sampled from {-1, 0, 1} then NTT-transformed
     */
    BGVSecretKey generate_secret_key(std::mt19937_64& rng);
    
    /**
     * @brief Generate public key from secret key
     * @param sk Secret key (must be in NTT form)
     * @param rng Random number generator
     * @return Public key (pk0, pk1) = (-(a*s + t*e), a) in NTT domain
     */
    BGVPublicKey generate_public_key(const BGVSecretKey& sk, 
                                      std::mt19937_64& rng);
    
    /**
     * @brief Generate relinearization key for key switching
     * @param sk Secret key
     * @param rng Random number generator
     * @param decomp_base Decomposition base (default: 2^16 = 65536)
     * @return Relinearization key with L digit components
     */
    BGVRelinKey generate_relin_key(const BGVSecretKey& sk,
                                    std::mt19937_64& rng,
                                    uint64_t decomp_base = 65536);
    
    // ========================================================================
    // Encryption / Decryption
    // ========================================================================
    
    /**
     * @brief Encrypt plaintext coefficients to ciphertext
     * @param plaintext Coefficient vector (length ≤ n)
     * @param pk Public key
     * @param rng Random number generator
     * @return Ciphertext (c0, c1) in NTT domain
     */
    BGVCiphertext encrypt(const BGVPlaintext& plaintext,
                          const BGVPublicKey& pk,
                          std::mt19937_64& rng);
    
    /**
     * @brief Decrypt ciphertext to plaintext coefficients
     * @param ct Ciphertext (must be size 2)
     * @param sk Secret key
     * @return Plaintext coefficient vector
     */
    BGVPlaintext decrypt(const BGVCiphertext& ct,
                         const BGVSecretKey& sk);
    
    // ========================================================================
    // Homomorphic Operations (All in NTT Domain)
    // ========================================================================
    
    /**
     * @brief Add two ciphertexts (component-wise)
     */
    BGVCiphertext add(const BGVCiphertext& ct1, const BGVCiphertext& ct2);
    
    /**
     * @brief Add ciphertext to ct1 (in-place)
     */
    void add_inplace(BGVCiphertext& ct1, const BGVCiphertext& ct2);
    
    /**
     * @brief Subtract two ciphertexts
     */
    BGVCiphertext sub(const BGVCiphertext& ct1, const BGVCiphertext& ct2);
    
    /**
     * @brief Subtract ct2 from ct1 (in-place)
     */
    void sub_inplace(BGVCiphertext& ct1, const BGVCiphertext& ct2);
    
    /**
     * @brief Multiply two ciphertexts (tensor product)
     * @param ct1 First ciphertext (size 2)
     * @param ct2 Second ciphertext (size 2)
     * @return Product ciphertext (size 3)
     * 
     * @note Output size = 3. Use relinearize() to reduce back to size 2.
     */
    BGVCiphertext multiply(const BGVCiphertext& ct1, const BGVCiphertext& ct2);
    
    /**
     * @brief Multiply ct2 into ct1 (in-place)
     */
    void multiply_inplace(BGVCiphertext& ct1, const BGVCiphertext& ct2);
    
    /**
     * @brief Relinearize ciphertext from size 3 to size 2
     * @param ct Ciphertext (must be size 3 after multiplication)
     * @param rk Relinearization key
     * @return Relinearized ciphertext (size 2)
     */
    BGVCiphertext relinearize(const BGVCiphertext& ct, const BGVRelinKey& rk);
    
    /**
     * @brief Relinearize ciphertext (in-place)
     */
    void relinearize_inplace(BGVCiphertext& ct, const BGVRelinKey& rk);
    
    /**
     * @brief Negate ciphertext
     */
    BGVCiphertext negate(const BGVCiphertext& ct);
    
    /**
     * @brief Negate ciphertext (in-place)
     */
    void negate_inplace(BGVCiphertext& ct);
    
    // ========================================================================
    // Rotation Operations (Galois Automorphisms)
    // ========================================================================
    
    /**
     * @brief Generate Galois keys for rotation operations
     * @param sk Secret key
     * @param rng Random number generator
     * @param steps Rotation steps to generate keys for (empty = all)
     * @param decomp_base Decomposition base (default: 2^16)
     * @return Galois keys for specified rotations
     * 
     * @note For n slots, generates keys for steps in [-n/2, n/2)
     */
    BGVGaloisKeys generate_galois_keys(const BGVSecretKey& sk,
                                        std::mt19937_64& rng,
                                        const std::vector<int>& steps = {},
                                        uint64_t decomp_base = 65536);
    
    /**
     * @brief Rotate ciphertext rows (slot rotation)
     * @param ct Ciphertext
     * @param steps Number of positions to rotate (positive = left, negative = right)
     * @param gk Galois keys
     * @return Rotated ciphertext
     * 
     * @note For n slots, valid steps are in [-n/2, n/2).
     *       Rotation wraps around: rotate(x, n) == x
     */
    BGVCiphertext rotate_rows(const BGVCiphertext& ct,
                               int steps,
                               const BGVGaloisKeys& gk);
    
    /**
     * @brief Rotate rows (in-place)
     */
    void rotate_rows_inplace(BGVCiphertext& ct,
                              int steps,
                              const BGVGaloisKeys& gk);
    
    /**
     * @brief Swap columns (conjugate slots)
     * @param ct Ciphertext
     * @param gk Galois keys (must include column key)
     * @return Ciphertext with swapped columns
     * 
     * @note For batched encoding, swaps the two column halves.
     *       Mathematically: σ_{-1}(m(x)) = m(x^{-1}) = m(x^{2n-1})
     */
    BGVCiphertext rotate_columns(const BGVCiphertext& ct,
                                  const BGVGaloisKeys& gk);
    
    /**
     * @brief Swap columns (in-place)
     */
    void rotate_columns_inplace(BGVCiphertext& ct,
                                 const BGVGaloisKeys& gk);
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    const RNSContext* context() const noexcept { return context_; }
    uint64_t plaintext_modulus() const noexcept { return plaintext_modulus_; }
    
private:
    const RNSContext* context_;
    uint64_t plaintext_modulus_;
    
    /**
     * @brief Decompose RNS polynomial into base-P digits
     */
    std::vector<RNSPoly> decompose_rns(const RNSPoly& poly, uint64_t base);
    
    int initial_noise_budget() const;
    int noise_budget_after_multiply() const;
    
    // ========================================================================
    // Galois/Rotation Helpers
    // ========================================================================
    
    /**
     * @brief Compute Galois element for row rotation
     * @param steps Number of slots to rotate
     * @return Galois element k where σ_k(x) = x^k
     */
    uint64_t get_galois_elt_from_step(int steps) const;
    
    /**
     * @brief Apply Galois automorphism to polynomial
     * @param poly Input polynomial in coefficient form
     * @param galois_elt Galois element k
     * @return σ_k(poly) = poly(x^k) mod (x^n + 1)
     */
    RNSPoly apply_galois(const RNSPoly& poly, uint64_t galois_elt);
    
    /**
     * @brief Key switching for Galois automorphism
     * @param ct Ciphertext after Galois applied
     * @param gk Galois key for this element
     * @return Key-switched ciphertext
     */
    BGVCiphertext switch_key_galois(const BGVCiphertext& ct,
                                     const BGVGaloisKey& gk);
};

// ============================================================================
// Backward Compatibility Aliases (for v4.10.0 code)
// ============================================================================

/// @deprecated Use BGVEvaluator instead
using BGVEvaluatorV2 = BGVEvaluator;

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_BGV_EVALUATOR_HPP
