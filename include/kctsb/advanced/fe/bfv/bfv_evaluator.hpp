/**
 * @file bfv_evaluator.hpp
 * @brief BFV Homomorphic Evaluator - Pure RNS Implementation
 * 
 * High-performance BFV evaluator using pure RNS polynomial representation.
 * BFV is a scale-invariant FHE scheme: plaintext is scaled by Δ = floor(Q/t)
 * during encoding, and multiplication preserves this scaling automatically.
 * 
 * Key Design:
 * - All keys stored in NTT domain
 * - All ciphertexts stored in NTT domain
 * - BFV-specific scaling: m → Δ·m at encoding, round(t·m/Q) at decoding
 * - Zero ZZ_pX dependency in hot path
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

#ifndef KCTSB_FHE_BFV_EVALUATOR_HPP
#define KCTSB_FHE_BFV_EVALUATOR_HPP

#include "kctsb/advanced/fe/bfv/bfv_types.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include "kctsb/advanced/fe/common/rns_poly_utils.hpp"
#include "kctsb/advanced/fe/common/behz_rns_tool.hpp"
#include <random>
#include <memory>

namespace kctsb {
namespace fhe {
namespace bfv {

/**
 * @brief BFV Homomorphic Evaluator (Pure RNS)
 * 
 * Implements all BFV operations using RNSPoly representation:
 * - Key generation with NTT pre-transformation
 * - Encryption with Δ-scaling: c = pk*u + e + Δ·m
 * - Homomorphic operations in NTT domain
 * - Decryption with scaling: round(t·(c0+c1*s)/Q)
 * 
 * @note BFV plaintext encoding uses Δ = floor(Q/t) scaling factor.
 */
class BFVEvaluator {
public:
    /**
     * @brief Construct evaluator with RNS context
     * @param ctx RNS context with moduli chain and NTT tables
     * @param plaintext_modulus Plaintext space modulus (default: 256)
     */
    explicit BFVEvaluator(const RNSContext* ctx, uint64_t plaintext_modulus = 256);
    
    // ========================================================================
    // Key Generation (Same as BGV)
    // ========================================================================
    
    /**
     * @brief Generate secret key from ternary distribution
     * @param rng Random number generator
     * @return Secret key in NTT domain
     */
    BFVSecretKey generate_secret_key(std::mt19937_64& rng);
    
    /**
     * @brief Generate public key from secret key
     * @param sk Secret key (must be in NTT form)
     * @param rng Random number generator
     * @return Public key (pk0, pk1) = (-(a*s + e), a) in NTT domain
     * @note BFV public key uses e directly, not t*e like BGV
     */
    BFVPublicKey generate_public_key(const BFVSecretKey& sk, 
                                      std::mt19937_64& rng);
    
    /**
     * @brief Generate relinearization key for key switching
     * @param sk Secret key
     * @param rng Random number generator
     * @param decomp_base Decomposition base (default: 2^16 = 65536)
     * @return Relinearization key with L digit components
     */
    BFVRelinKey generate_relin_key(const BFVSecretKey& sk,
                                    std::mt19937_64& rng,
                                    uint64_t decomp_base = 65536);
    
    // ========================================================================
    // Encryption / Decryption (BFV-specific scaling)
    // ========================================================================
    
    /**
     * @brief Encrypt plaintext coefficients to ciphertext
     * @param plaintext Coefficient vector (length ≤ n)
     * @param pk Public key
     * @param rng Random number generator
     * @return Ciphertext (c0, c1) in NTT domain
     * 
     * @note BFV encryption: c = (pk0*u + e0 + Δ·m, pk1*u + e1)
     *       where Δ = floor(Q/t) is the scaling factor
     */
    BFVCiphertext encrypt(const BFVPlaintext& plaintext,
                          const BFVPublicKey& pk,
                          std::mt19937_64& rng);
    
    /**
     * @brief Decrypt ciphertext to plaintext coefficients
     * @param ct Ciphertext (must be size 2)
     * @param sk Secret key
     * @return Plaintext coefficient vector
     * 
     * @note BFV decryption: m = round((t/Q) · (c0 + c1·s)) mod t
     */
    BFVPlaintext decrypt(const BFVCiphertext& ct,
                         const BFVSecretKey& sk);
    
    // ========================================================================
    // Homomorphic Operations (All in NTT Domain)
    // ========================================================================
    
    /**
     * @brief Add two ciphertexts (component-wise)
     */
    BFVCiphertext add(const BFVCiphertext& ct1, const BFVCiphertext& ct2);
    
    /**
     * @brief Add ciphertext to ct1 (in-place)
     */
    void add_inplace(BFVCiphertext& ct1, const BFVCiphertext& ct2);
    
    /**
     * @brief Subtract two ciphertexts
     */
    BFVCiphertext sub(const BFVCiphertext& ct1, const BFVCiphertext& ct2);
    
    /**
     * @brief Subtract ct2 from ct1 (in-place)
     */
    void sub_inplace(BFVCiphertext& ct1, const BFVCiphertext& ct2);
    
    /**
     * @brief Multiply two ciphertexts (tensor product)
     * @param ct1 First ciphertext (size 2)
     * @param ct2 Second ciphertext (size 2)
     * @return Product ciphertext (size 3)
     * 
     * @note BFV multiplication requires scaling adjustment (unlike BGV).
     *       The result contains an extra Δ factor that is removed by
     *       the invariant decryption formula.
     */
    BFVCiphertext multiply(const BFVCiphertext& ct1, const BFVCiphertext& ct2);
    
    /**
     * @brief Multiply ct2 into ct1 (in-place)
     */
    void multiply_inplace(BFVCiphertext& ct1, const BFVCiphertext& ct2);
    
    /**
     * @brief Relinearize ciphertext from size 3 to size 2
     * @param ct Ciphertext (must be size 3 after multiplication)
     * @param rk Relinearization key
     * @return Relinearized ciphertext (size 2)
     */
    BFVCiphertext relinearize(const BFVCiphertext& ct, const BFVRelinKey& rk);
    
    /**
     * @brief Relinearize ciphertext (in-place)
     */
    void relinearize_inplace(BFVCiphertext& ct, const BFVRelinKey& rk);
    
    /**
     * @brief Negate ciphertext
     */
    BFVCiphertext negate(const BFVCiphertext& ct);
    
    /**
     * @brief Negate ciphertext (in-place)
     */
    void negate_inplace(BFVCiphertext& ct);
    
    // ========================================================================
    // BFV-Specific Operations
    // ========================================================================
    
    /**
     * @brief Add plaintext to ciphertext
     * @param ct Ciphertext
     * @param pt Plaintext (will be Δ-scaled)
     * @return ct + Δ·pt
     */
    BFVCiphertext add_plain(const BFVCiphertext& ct, const BFVPlaintext& pt);
    
    /**
     * @brief Multiply ciphertext by plaintext
     * @param ct Ciphertext
     * @param pt Plaintext
     * @return ct * pt
     */
    BFVCiphertext multiply_plain(const BFVCiphertext& ct, const BFVPlaintext& pt);
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    const RNSContext* context() const noexcept { return context_; }
    uint64_t plaintext_modulus() const noexcept { return plaintext_modulus_; }
    
    /**
     * @brief Get the BFV scaling factor Δ = floor(Q/t)
     * @return Scaling factor per RNS component
     * @note Returns vector of Δ_i = floor(q_i/t) for each RNS modulus
     */
    std::vector<uint64_t> get_delta() const;
    
    /**
     * @brief Initialize BEHZ tool for ciphertext multiplication
     * @note Call this before first multiply operation
     */
    void init_behz_tool();
    
    /**
     * @brief Check if BEHZ tool is initialized
     */
    bool has_behz_tool() const noexcept { return behz_tool_ != nullptr; }
    
private:
    const RNSContext* context_;
    uint64_t plaintext_modulus_;
    std::unique_ptr<BEHZRNSTool> behz_tool_;  ///< BEHZ tool for multiplication rescaling
    
    /**
     * @brief Decompose RNS polynomial into base-P digits
     */
    std::vector<RNSPoly> decompose_rns(const RNSPoly& poly, uint64_t base);
    
    /**
     * @brief Scale plaintext by Δ and convert to RNSPoly
     * @param pt Plaintext coefficients
     * @return Δ·pt as RNSPoly in coefficient form
     */
    RNSPoly scale_plaintext(const BFVPlaintext& pt);
    
    int initial_noise_budget() const;
    int noise_budget_after_multiply() const;
};

} // namespace bfv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_BFV_EVALUATOR_HPP
