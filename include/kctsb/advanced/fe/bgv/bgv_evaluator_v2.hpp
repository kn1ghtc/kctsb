/**
 * @file bgv_evaluator_v2.hpp
 * @brief BGV EvaluatorV2 - Pure RNS Implementation
 * 
 * High-performance BGV evaluator using pure RNS polynomial representation
 * throughout all operations. Achieves 50x+ speedup by eliminating ZZ_pX
 * conversions that dominated v4.6.0 performance.
 * 
 * Key Design:
 * - All keys stored in NTT domain
 * - All ciphertexts stored in NTT domain
 * - Zero ZZ_pX dependency (only CRT at decryption)
 * - Component-wise operations in O(n) time
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.10.0
 * @since Phase 4c optimization
 */

#ifndef KCTSB_FHE_BGV_EVALUATOR_V2_HPP
#define KCTSB_FHE_BGV_EVALUATOR_V2_HPP

#include "kctsb/advanced/fe/bgv/bgv_types_v2.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include "kctsb/advanced/fe/common/rns_poly_utils.hpp"
#include <random>
#include <memory>

namespace kctsb {
namespace fhe {
namespace bgv {

/**
 * @brief BGV Homomorphic Evaluator V2 (Pure RNS)
 * 
 * Implements all BGV operations using RNSPoly representation:
 * - Key generation with NTT pre-transformation
 * - Encryption outputting NTT-form ciphertexts
 * - Homomorphic operations in NTT domain
 * - Decryption with CRT reconstruction
 * 
 * Performance Targets (n=8192):
 * - Encrypt: < 50 ms (vs 3494 ms in v4.6.0)
 * - Multiply: < 20 ms (vs 1335 ms in v4.6.0)
 * - Multiply+Relin: < 30 ms (vs 9650 ms in v4.6.0)
 * 
 * @note This is a zero-ZZ_pX implementation. All conversions happen
 *       only at encryption input and decryption output boundaries.
 */
class BGVEvaluatorV2 {
public:
    /**
     * @brief Construct evaluator with RNS context
     * @param ctx RNS context with moduli chain and NTT tables
     * @param plaintext_modulus Plaintext space modulus (default: 256)
     */
    explicit BGVEvaluatorV2(const RNSContext* ctx, uint64_t plaintext_modulus = 256);
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate secret key from ternary distribution
     * @param rng Random number generator
     * @return Secret key in NTT domain
     * @note Key polynomial sampled from {-1, 0, 1} then NTT-transformed
     */
    BGVSecretKeyV2 generate_secret_key(std::mt19937_64& rng);
    
    /**
     * @brief Generate public key from secret key
     * @param sk Secret key (must be in NTT form)
     * @param rng Random number generator
     * @return Public key (pk0, pk1) = (-(a*s + e), a) in NTT domain
     */
    BGVPublicKeyV2 generate_public_key(const BGVSecretKeyV2& sk, 
                                        std::mt19937_64& rng);
    
    /**
     * @brief Generate relinearization key for key switching
     * @param sk Secret key
     * @param rng Random number generator
     * @param decomp_base Decomposition base (default: 2^16 = 65536)
     * @return Relinearization key with L digit components
     */
    BGVRelinKeyV2 generate_relin_key(const BGVSecretKeyV2& sk,
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
     * 
     * @note Output ciphertext is in NTT form and ready for homomorphic ops
     */
    BGVCiphertextV2 encrypt(const BGVPlaintextV2& plaintext,
                             const BGVPublicKeyV2& pk,
                             std::mt19937_64& rng);
    
    /**
     * @brief Decrypt ciphertext to plaintext coefficients
     * @param ct Ciphertext (must be size 2)
     * @param sk Secret key
     * @return Plaintext coefficient vector
     * 
     * @note Uses CRT reconstruction to recover ZZ coefficients,
     *       then reduces modulo plaintext_modulus_
     */
    BGVPlaintextV2 decrypt(const BGVCiphertextV2& ct,
                           const BGVSecretKeyV2& sk);
    
    // ========================================================================
    // Homomorphic Operations (All in NTT Domain)
    // ========================================================================
    
    /**
     * @brief Add two ciphertexts (component-wise)
     * @param ct1 First ciphertext
     * @param ct2 Second ciphertext
     * @return Sum ciphertext
     */
    BGVCiphertextV2 add(const BGVCiphertextV2& ct1, 
                         const BGVCiphertextV2& ct2);
    
    /**
     * @brief Add ciphertext to ct1 (in-place)
     */
    void add_inplace(BGVCiphertextV2& ct1, const BGVCiphertextV2& ct2);
    
    /**
     * @brief Subtract two ciphertexts
     */
    BGVCiphertextV2 sub(const BGVCiphertextV2& ct1,
                         const BGVCiphertextV2& ct2);
    
    /**
     * @brief Subtract ct2 from ct1 (in-place)
     */
    void sub_inplace(BGVCiphertextV2& ct1, const BGVCiphertextV2& ct2);
    
    /**
     * @brief Multiply two ciphertexts (tensor product)
     * @param ct1 First ciphertext (size 2)
     * @param ct2 Second ciphertext (size 2)
     * @return Product ciphertext (size 3)
     * 
     * @note Output size = 3: (c0*d0, c0*d1 + c1*d0, c1*d1)
     *       Use relinearize() to reduce back to size 2
     */
    BGVCiphertextV2 multiply(const BGVCiphertextV2& ct1,
                              const BGVCiphertextV2& ct2);
    
    /**
     * @brief Multiply ct2 into ct1 (in-place)
     */
    void multiply_inplace(BGVCiphertextV2& ct1, const BGVCiphertextV2& ct2);
    
    /**
     * @brief Relinearize ciphertext from size 3 to size 2
     * @param ct Ciphertext (must be size 3 after multiplication)
     * @param rk Relinearization key
     * @return Relinearized ciphertext (size 2)
     */
    BGVCiphertextV2 relinearize(const BGVCiphertextV2& ct,
                                 const BGVRelinKeyV2& rk);
    
    /**
     * @brief Relinearize ciphertext (in-place)
     */
    void relinearize_inplace(BGVCiphertextV2& ct, const BGVRelinKeyV2& rk);
    
    /**
     * @brief Negate ciphertext
     */
    BGVCiphertextV2 negate(const BGVCiphertextV2& ct);
    
    /**
     * @brief Negate ciphertext (in-place)
     */
    void negate_inplace(BGVCiphertextV2& ct);
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    const RNSContext* context() const noexcept { return context_; }
    uint64_t plaintext_modulus() const noexcept { return plaintext_modulus_; }
    
private:
    const RNSContext* context_;
    uint64_t plaintext_modulus_;
    
    // ========================================================================
    // Internal Helpers
    // ========================================================================
    
    /**
     * @brief Decompose RNS polynomial into base-P digits
     * @param poly Input polynomial (NTT domain)
     * @param base Decomposition base P (typically 2^16 or 2^20)
     * @return Vector of digit polynomials in NTT domain
     * 
     * @note Used for relinearization key switching
     */
    std::vector<RNSPoly> decompose_rns(const RNSPoly& poly, uint64_t base);
    
    /**
     * @brief Estimate initial noise budget in fresh ciphertext
     * @return Noise budget in bits
     */
    int initial_noise_budget() const;
    
    /**
     * @brief Estimate noise budget consumed by one multiplication
     * @return Noise budget decrease in bits
     */
    int noise_budget_after_multiply() const;
};

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_BGV_EVALUATOR_V2_HPP
