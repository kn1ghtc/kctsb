/**
 * @file ckks.hpp
 * @brief CKKS (Cheon-Kim-Kim-Song) Approximate Homomorphic Encryption Scheme
 * 
 * CKKS enables computation on encrypted floating-point numbers with controlled
 * approximation error. It is the primary scheme for ML inference and statistical
 * computation on encrypted data.
 * 
 * Key differences from BGV/BFV:
 * - Encoding: complex vectors → polynomial via canonical embedding (FFT)
 * - Messages are approximate: decryption returns m + e where |e| is small
 * - Scale management: multiply causes scale² → need rescale to restore
 * 
 * @note This implementation reuses BGV infrastructure for cryptographic core.
 * @note Phase 3 uses O(N²) DFT for correctness; Phase 4 will optimize to FFT.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_ADVANCED_FE_CKKS_CKKS_HPP
#define KCTSB_ADVANCED_FE_CKKS_CKKS_HPP

#include "kctsb/advanced/fe/bgv/bgv.hpp"
#include <complex>
#include <vector>
#include <memory>
#include <cmath>

namespace kctsb::fhe::ckks {

// ============================================================================
// Type Aliases - Reuse BGV types for cryptographic core
// ============================================================================

using SecretKey = bgv::BGVSecretKey;
using PublicKey = bgv::BGVPublicKey;
using RelinKey = bgv::BGVRelinKey;
using RingElement = bgv::RingElement;
using ZZ = kctsb::ZZ;
using ZZ_p = kctsb::ZZ_p;
using ZZ_pX = kctsb::ZZ_pX;

// Complex number type
using Complex = std::complex<double>;

// Forward declarations
class CKKSContext;
class CKKSEncoder;
class CKKSEvaluator;
class CKKSPlaintext;
class CKKSCiphertext;

// ============================================================================
// CKKS Parameters
// ============================================================================

/**
 * @brief CKKS encryption parameters
 * 
 * CKKS uses the same ring structure as BGV (R_q = Z_q[X]/(X^n+1))
 * but encodes complex vectors via canonical embedding.
 */
struct CKKSParams {
    // Ring parameters
    uint64_t m = 0;             ///< Cyclotomic index (2*n)
    size_t n = 0;               ///< Polynomial degree (must be power of 2)
    ZZ q;                       ///< Initial ciphertext modulus
    std::vector<uint64_t> primes;  ///< RNS modulus chain for rescaling
    size_t L = 0;               ///< Modulus chain depth (max multiply depth)
    
    // CKKS-specific
    double log_scale = 40.0;    ///< log2 of scale factor (default 2^40)
    double sigma = 3.2;         ///< Error distribution std dev
    bgv::SecurityLevel security = bgv::SecurityLevel::NONE;
    
    /**
     * @brief Compute scale factor Δ = 2^log_scale
     * @return The CKKS scale factor as double
     */
    double scale() const { 
        return std::pow(2.0, log_scale); 
    }
    
    /**
     * @brief Compute scale factor as ZZ
     * @return The CKKS scale factor as big integer
     */
    ZZ scale_zz() const;
    
    /**
     * @brief Number of message slots (complex numbers)
     * @return N/2 slots for N-degree polynomial
     */
    size_t slot_count() const { return n / 2; }
    
    /**
     * @brief Convert to BGV parameters (for key generation)
     * @return Equivalent BGV parameters
     */
    bgv::BGVParams to_bgv_params() const;
    
    /**
     * @brief Validate parameters
     * @return true if parameters are valid
     */
    bool validate() const;
};

/**
 * @brief Standard CKKS parameter sets
 */
struct StandardParams {
    /**
     * @brief Toy parameters for testing (n=256)
     * @note NOT cryptographically secure!
     */
    static CKKSParams TOY_PARAMS();
    
    /**
     * @brief 128-bit security, depth 3 (n=4096)
     */
    static CKKSParams SECURITY_128_DEPTH_3();
    
    /**
     * @brief 128-bit security, depth 5 (n=8192)
     * @note Industry standard for SEAL comparison
     */
    static CKKSParams SECURITY_128();
};

// ============================================================================
// CKKS Plaintext
// ============================================================================

/**
 * @brief CKKS plaintext with scale tracking
 */
class CKKSPlaintext {
public:
    CKKSPlaintext() = default;
    explicit CKKSPlaintext(double scale, size_t level = SIZE_MAX) 
        : scale_(scale), level_(level) {}
    
    // Polynomial access
    ZZ_pX& data() { return poly_; }
    const ZZ_pX& data() const { return poly_; }
    
    // Scale access
    double scale() const { return scale_; }
    void set_scale(double s) { scale_ = s; }
    
    // Level access (SIZE_MAX means full modulus q_L)
    size_t level() const { return level_; }
    void set_level(size_t l) { level_ = l; }
    
    // Coefficient access
    long degree() const;
    void set_coeff(long i, const ZZ_p& c);
    ZZ_p coeff(long i) const;
    
private:
    ZZ_pX poly_;
    double scale_ = 1.0;
    size_t level_ = SIZE_MAX;  // SIZE_MAX = use q_L (full modulus)
};

// ============================================================================
// CKKS Ciphertext
// ============================================================================

/**
 * @brief CKKS ciphertext with level and scale tracking
 */
class CKKSCiphertext {
public:
    CKKSCiphertext() = default;
    CKKSCiphertext(size_t level, double scale) 
        : level_(level), scale_(scale) {}
    
    // Component access (c0, c1, ...)
    std::vector<RingElement>& components() { return components_; }
    const std::vector<RingElement>& components() const { return components_; }
    
    size_t size() const { return components_.size(); }
    
    RingElement& operator[](size_t i) { return components_[i]; }
    const RingElement& operator[](size_t i) const { return components_[i]; }
    
    void push_back(const RingElement& elem) { components_.push_back(elem); }
    
    // Level access (decreases after rescale)
    size_t level() const { return level_; }
    void set_level(size_t l) { level_ = l; }
    
    // Scale access (doubles after multiply, halves after rescale)
    double scale() const { return scale_; }
    void set_scale(double s) { scale_ = s; }
    
    // Check if more multiplications are possible
    bool can_multiply() const { return level_ > 0; }
    
private:
    std::vector<RingElement> components_;
    size_t level_ = 0;
    double scale_ = 1.0;
};

// ============================================================================
// CKKS Context
// ============================================================================

/**
 * @brief CKKS encryption context
 * 
 * Manages parameters, key generation, encryption and decryption.
 * Internally delegates to BGV context for cryptographic operations.
 */
class CKKSContext {
public:
    /**
     * @brief Construct CKKS context from parameters
     * @param params CKKS encryption parameters
     */
    explicit CKKSContext(const CKKSParams& params);
    
    // Key generation
    SecretKey generate_secret_key();
    PublicKey generate_public_key(const SecretKey& sk);
    RelinKey generate_relin_key(const SecretKey& sk);
    
    // Encryption/Decryption
    CKKSCiphertext encrypt(const PublicKey& pk, const CKKSPlaintext& pt);
    CKKSCiphertext encrypt_symmetric(const SecretKey& sk, const CKKSPlaintext& pt);
    CKKSPlaintext decrypt(const SecretKey& sk, const CKKSCiphertext& ct);
    
    // Parameter access
    const CKKSParams& params() const { return params_; }
    size_t ring_degree() const { return params_.n; }
    size_t slot_count() const { return params_.slot_count(); }
    double scale() const { return params_.scale(); }
    size_t max_level() const { return params_.L; }
    
    // Access modulus at given level
    ZZ modulus_at_level(size_t level) const;
    
    // Access internal BGV context
    const bgv::BGVContext& bgv_context() const { return *bgv_ctx_; }

private:
    CKKSParams params_;
    std::unique_ptr<bgv::BGVContext> bgv_ctx_;
    std::vector<ZZ> modulus_chain_;  // q_L, q_{L-1}, ..., q_0
    
    void init_modulus_chain();
};

// ============================================================================
// CKKS Encoder
// ============================================================================

/**
 * @brief CKKS encoder for complex/real values
 * 
 * Uses canonical embedding (FFT) to encode N/2 complex values
 * into a polynomial of degree N.
 * 
 * @note Phase 3 uses O(N²) DFT for correctness verification.
 */
class CKKSEncoder {
public:
    /**
     * @brief Construct encoder from context
     * @param ctx CKKS context
     */
    explicit CKKSEncoder(const CKKSContext& ctx);
    
    /**
     * @brief Encode complex vector to plaintext
     * @param values N/2 complex values
     * @param scale Scale factor (default: context scale)
     * @return Encoded plaintext polynomial
     */
    CKKSPlaintext encode(const std::vector<Complex>& values, 
                         double scale = 0.0);
    
    /**
     * @brief Encode real vector to plaintext
     * @param values N/2 real values
     * @param scale Scale factor
     * @return Encoded plaintext polynomial
     */
    CKKSPlaintext encode_real(const std::vector<double>& values,
                              double scale = 0.0);
    
    /**
     * @brief Encode single real value to all slots
     * @param value Real value
     * @param scale Scale factor
     * @return Encoded plaintext polynomial
     */
    CKKSPlaintext encode_single(double value, double scale = 0.0);
    
    /**
     * @brief Decode plaintext to complex vector
     * @param pt Encoded plaintext
     * @return N/2 complex values
     */
    std::vector<Complex> decode(const CKKSPlaintext& pt);
    
    /**
     * @brief Decode plaintext to real vector (takes real part)
     * @param pt Encoded plaintext
     * @return N/2 real values
     */
    std::vector<double> decode_real(const CKKSPlaintext& pt);
    
    /**
     * @brief Number of slots
     */
    size_t slot_count() const { return ctx_.slot_count(); }

private:
    const CKKSContext& ctx_;
    size_t n_;              // Polynomial degree
    size_t slots_;          // N/2 slots
    std::vector<Complex> roots_;  // Precomputed roots of unity
    
    /**
     * @brief Precompute roots of unity for DFT
     */
    void precompute_roots();
    
    /**
     * @brief Forward DFT (encode direction)
     * @param values N values in the embedding
     * @return N coefficients
     */
    std::vector<Complex> inverse_dft(const std::vector<Complex>& values);
    
    /**
     * @brief Inverse DFT (decode direction)
     * @param coeffs N coefficients
     * @return N values in the embedding
     */
    std::vector<Complex> forward_dft(const std::vector<Complex>& coeffs);
};

// ============================================================================
// CKKS Evaluator
// ============================================================================

/**
 * @brief CKKS homomorphic operations
 */
class CKKSEvaluator {
public:
    /**
     * @brief Construct evaluator from context
     * @param ctx CKKS context
     */
    explicit CKKSEvaluator(const CKKSContext& ctx);
    
    // ========== Addition ==========
    
    /**
     * @brief Add two ciphertexts
     * @note Scales must match
     */
    CKKSCiphertext add(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2);
    
    /**
     * @brief Add plaintext to ciphertext
     */
    CKKSCiphertext add_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt);
    
    // ========== Subtraction ==========
    
    /**
     * @brief Subtract two ciphertexts
     */
    CKKSCiphertext sub(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2);
    
    // ========== Multiplication ==========
    
    /**
     * @brief Multiply two ciphertexts
     * @note Result scale = scale1 * scale2
     * @note Result size = size1 + size2 - 1 (needs relinearization)
     */
    CKKSCiphertext multiply(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2);
    
    /**
     * @brief Multiply ciphertext by plaintext
     */
    CKKSCiphertext multiply_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt);
    
    // ========== Rescale ==========
    
    /**
     * @brief Rescale ciphertext after multiplication
     * 
     * Divides all coefficients by prime p_l and reduces modulus.
     * This restores scale from Δ² back to ~Δ.
     * 
     * @param ct Ciphertext to rescale
     * @return Rescaled ciphertext with reduced level
     */
    CKKSCiphertext rescale(const CKKSCiphertext& ct);
    
    // ========== Relinearization ==========
    
    /**
     * @brief Relinearize ciphertext (reduce size from 3 to 2)
     * @param ct Size-3 ciphertext from multiplication
     * @param rk Relinearization key
     * @return Size-2 ciphertext
     */
    CKKSCiphertext relinearize(const CKKSCiphertext& ct, const RelinKey& rk);
    
    // ========== Combined Operations ==========
    
    /**
     * @brief Multiply, relinearize, and rescale
     * @note Most common operation for deep circuits
     */
    CKKSCiphertext multiply_relin_rescale(const CKKSCiphertext& ct1,
                                           const CKKSCiphertext& ct2,
                                           const RelinKey& rk);
    
    // ========== Level/Scale Management ==========
    
    /**
     * @brief Mod switch without rescaling (noise reduction)
     */
    CKKSCiphertext mod_switch(const CKKSCiphertext& ct);
    
    /**
     * @brief Check if two ciphertexts have matching scales
     */
    bool scales_match(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2,
                      double tolerance = 1e-6) const;

private:
    const CKKSContext& ctx_;
    std::unique_ptr<bgv::BGVEvaluator> bgv_eval_;
    
    /**
     * @brief Convert CKKSCiphertext to BGV format
     */
    bgv::BGVCiphertext to_bgv_ct(const CKKSCiphertext& ct) const;
    
    /**
     * @brief Convert BGV ciphertext to CKKS format
     */
    CKKSCiphertext from_bgv_ct(const bgv::BGVCiphertext& ct, 
                                size_t level, double scale) const;
};

}  // namespace kctsb::fhe::ckks

#endif  // KCTSB_ADVANCED_FE_CKKS_CKKS_HPP
