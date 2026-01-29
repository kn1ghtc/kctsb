/**
 * @file ckks_evaluator.hpp
 * @brief CKKS Evaluator - Pure RNS Implementation
 *
 * High-performance CKKS evaluator using pure RNS polynomial representation.
 * CKKS enables approximate homomorphic computation on real/complex numbers.
 *
 * Key Features:
 * - Pure RNS architecture (no NTL dependency for operations)
 * - FFT-based canonical embedding for encode/decode
 * - Scale management with automatic rescaling
 * - Compatible with BGV/BFV infrastructure
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.13.0
 */

#ifndef KCTSB_ADVANCED_FE_CKKS_CKKS_EVALUATOR_HPP
#define KCTSB_ADVANCED_FE_CKKS_CKKS_EVALUATOR_HPP

#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include "kctsb/advanced/fe/common/ntt.hpp"
#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include "kctsb/advanced/fe/ckks/ckks_rns_tool.hpp"
#include <complex>
#include <memory>
#include <vector>
#include <random>
#include <cmath>

namespace kctsb {
namespace fhe {
namespace ckks {

using Complex = std::complex<double>;
constexpr double PI = 3.14159265358979323846;

// ============================================================================
// CKKS Parameters
// ============================================================================

/**
 * @brief CKKS encryption parameters
 */
struct CKKSParams {
    size_t n = 4096;           ///< Ring dimension (power of 2)
    size_t L = 3;              ///< Number of modulus levels
    double log_scale = 40.0;   ///< Log2 of scaling factor
    double sigma = 3.2;        ///< Error standard deviation
    uint64_t special_prime = 0; ///< Special prime for key switching (optional)
    
    /// Get scaling factor as double
    double scale() const { return std::pow(2.0, log_scale); }
    
    /// Number of slots (n/2 for CKKS)
    size_t slot_count() const { return n / 2; }
    
    /// Validate parameters
    bool validate() const {
        if (n == 0 || (n & (n - 1)) != 0) return false;
        if (L == 0) return false;
        if (log_scale <= 0.0 || log_scale > 60.0) return false;
        return true;
    }
};

// ============================================================================
// CKKS Plaintext (RNS representation)
// ============================================================================

/**
 * @brief CKKS plaintext in RNS representation
 */
class CKKSPlaintext {
public:
    CKKSPlaintext() = default;
    explicit CKKSPlaintext(const RNSContext* ctx, double scale = 0.0)
        : data_(ctx), scale_(scale), level_(ctx ? ctx->level_count() - 1 : 0) {}
    
    /// Get underlying RNS polynomial
    RNSPoly& data() { return data_; }
    const RNSPoly& data() const { return data_; }
    
    /// Scale factor
    double scale() const { return scale_; }
    void set_scale(double s) { scale_ = s; }
    
    /// Level
    size_t level() const { return level_; }
    void set_level(size_t l) { level_ = l; }
    
    /// Check if in NTT form
    bool is_ntt_form() const { return data_.is_ntt_form(); }
    
private:
    RNSPoly data_;
    double scale_ = 0.0;
    size_t level_ = 0;
};

// ============================================================================
// CKKS Ciphertext (two RNS polynomials)
// ============================================================================

/**
 * @brief CKKS ciphertext: (c0, c1, [c2]) where m ≈ c0 + c1*s [+ c2*s^2]
 * 
 * After multiplication, ciphertext has 3 components. Relinearization
 * converts it back to 2 components.
 */
class CKKSCiphertext {
public:
    CKKSCiphertext() = default;
    explicit CKKSCiphertext(const RNSContext* ctx, double scale = 0.0)
        : c0_(ctx), c1_(ctx), c2_(), scale_(scale), level_(ctx ? ctx->level_count() - 1 : 0), size_(2), context_(ctx) {}
    
    /// Access components
    RNSPoly& c0() { return c0_; }
    RNSPoly& c1() { return c1_; }
    RNSPoly& c2() { return c2_; }
    const RNSPoly& c0() const { return c0_; }
    const RNSPoly& c1() const { return c1_; }
    const RNSPoly& c2() const { return c2_; }
    
    /// Scale and level
    double scale() const { return scale_; }
    void set_scale(double s) { scale_ = s; }
    size_t level() const { return level_; }
    void set_level(size_t l) { level_ = l; }
    
    /// Check if in NTT form
    bool is_ntt_form() const { return c0_.is_ntt_form() && c1_.is_ntt_form(); }
    
    /// Size (2 for standard, 3 after multiplication before relinearization)
    size_t size() const { return size_; }
    void set_size(size_t s) { 
        size_ = s; 
        if (s >= 3 && context_) {
            c2_ = RNSPoly(context_);
        }
    }
    
private:
    RNSPoly c0_, c1_, c2_;
    double scale_ = 0.0;
    size_t level_ = 0;
    size_t size_ = 2;
    const RNSContext* context_ = nullptr;
};

// ============================================================================
// CKKS Keys
// ============================================================================

/**
 * @brief CKKS secret key: s ∈ R (ternary)
 */
struct CKKSSecretKey {
    RNSPoly s;
    bool is_ntt_form = false;
};

/**
 * @brief CKKS public key: (b, a) where b = -a*s + e
 */
struct CKKSPublicKey {
    RNSPoly b;  ///< b = -a*s + e
    RNSPoly a;  ///< random uniform
    bool is_ntt_form = false;
};

/**
 * @brief CKKS relinearization key with RNS decomposition
 * 
 * Uses RNS decomposition for key switching to control noise growth.
 * For each RNS prime q_j, stores a key component (b_j, a_j) where:
 *   b_j = -a_j * s + e_j + (Q/q_j) * s^2 mod Q
 * 
 * The RNS decomposition reduces noise from O(Q) to O(L * sqrt(n) * sigma)
 * where L is the number of primes and sigma is error std deviation.
 */
struct CKKSRelinKey {
    /// Key b components: rk_b[j] where b_j = -a_j*s + e_j + (Q/q_j) * s^2
    std::vector<RNSPoly> rk_b;
    
    /// Key a components: rk_a[j] (random uniform polynomials)
    std::vector<RNSPoly> rk_a;
    
    bool is_ntt_form = false;
};

// ============================================================================
// CKKS Encoder (FFT-based canonical embedding)
// ============================================================================

/**
 * @brief CKKS encoder using canonical embedding
 * 
 * Encodes complex vectors to polynomials and vice versa.
 * Uses FFT for efficient encoding/decoding.
 */
class CKKSEncoder {
public:
    explicit CKKSEncoder(const RNSContext* ctx, double default_scale = 0.0);
    
    /**
     * @brief Encode complex vector to plaintext
     * @param values Input complex values (max n/2 elements)
     * @param scale Scaling factor (0 = use default)
     * @return Encoded plaintext
     */
    CKKSPlaintext encode(const std::vector<Complex>& values, double scale = 0.0);
    
    /**
     * @brief Encode real vector to plaintext
     */
    CKKSPlaintext encode_real(const std::vector<double>& values, double scale = 0.0);
    
    /**
     * @brief Encode single real value
     */
    CKKSPlaintext encode_single(double value, double scale = 0.0);
    
    /**
     * @brief Decode plaintext to complex vector
     */
    std::vector<Complex> decode(const CKKSPlaintext& pt);
    
    /**
     * @brief Decode plaintext to real vector
     */
    std::vector<double> decode_real(const CKKSPlaintext& pt);
    
    /// Number of slots
    size_t slot_count() const { return slots_; }

private:
    const RNSContext* context_;
    size_t n_;              ///< Ring dimension
    size_t slots_;          ///< Number of slots (n/2)
    double default_scale_;
    
    std::vector<Complex> roots_;       ///< Precomputed roots of unity
    std::vector<Complex> roots_inv_;   ///< Inverse roots
    
    void precompute_roots();
    
    /// FFT operations
    void fft_forward(std::vector<Complex>& values);
    void fft_inverse(std::vector<Complex>& values);
    
    /// Bit-reversal permutation
    void bit_reverse_permute(std::vector<Complex>& values);
};

// ============================================================================
// CKKS Evaluator (Pure RNS)
// ============================================================================

/**
 * @brief CKKS evaluator with pure RNS operations
 * 
 * Provides all CKKS operations:
 * - Key generation (secret, public, relin)
 * - Encryption/Decryption
 * - Homomorphic add/sub/multiply
 * - Rescale for scale management
 */
class CKKSEvaluator {
public:
    /**
     * @brief Constructor
     * @param ctx RNS context
     * @param default_scale Default scaling factor
     */
    explicit CKKSEvaluator(const RNSContext* ctx, double default_scale = 0.0);
    
    // ========== Key Generation ==========
    
    /**
     * @brief Generate secret key (ternary distribution)
     */
    CKKSSecretKey generate_secret_key(std::mt19937_64& rng);
    
    /**
     * @brief Generate public key from secret key
     */
    CKKSPublicKey generate_public_key(const CKKSSecretKey& sk, std::mt19937_64& rng);
    
    /**
     * @brief Generate relinearization key
     */
    CKKSRelinKey generate_relin_key(const CKKSSecretKey& sk, std::mt19937_64& rng);
    
    // ========== Encryption/Decryption ==========
    
    /**
     * @brief Encrypt plaintext using public key
     */
    CKKSCiphertext encrypt(const CKKSPublicKey& pk, const CKKSPlaintext& pt,
                           std::mt19937_64& rng);
    
    /**
     * @brief Encrypt plaintext using secret key (symmetric)
     */
    CKKSCiphertext encrypt_symmetric(const CKKSSecretKey& sk, const CKKSPlaintext& pt,
                                      std::mt19937_64& rng);
    
    /**
     * @brief Decrypt ciphertext using secret key
     */
    CKKSPlaintext decrypt(const CKKSSecretKey& sk, const CKKSCiphertext& ct);
    
    // ========== Homomorphic Operations ==========
    
    /**
     * @brief Add two ciphertexts
     */
    CKKSCiphertext add(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2);
    
    /**
     * @brief Subtract ciphertexts
     */
    CKKSCiphertext sub(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2);
    
    /**
     * @brief Add plaintext to ciphertext
     */
    CKKSCiphertext add_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt);
    
    /**
     * @brief Multiply two ciphertexts (degree 2 result)
     */
    CKKSCiphertext multiply(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2);
    
    /**
     * @brief Multiply ciphertext by plaintext
     */
    CKKSCiphertext multiply_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt);
    
    /**
     * @brief Relinearize degree-2 ciphertext to degree-1
     */
    CKKSCiphertext relinearize(const CKKSCiphertext& ct, const CKKSRelinKey& rk);
    
    /**
     * @brief Rescale to reduce scale (divide by prime)
     */
    CKKSCiphertext rescale(const CKKSCiphertext& ct);
    
    /**
     * @brief Rescale ciphertext in-place (modifies input)
     * @param ct Ciphertext to rescale (modified in place)
     */
    void rescale_inplace(CKKSCiphertext& ct);
    
    /**
     * @brief Add two ciphertexts in-place (ct1 += ct2)
     * @param ct1 Target ciphertext (modified)
     * @param ct2 Source ciphertext to add
     */
    void add_inplace(CKKSCiphertext& ct1, const CKKSCiphertext& ct2);
    
    /**
     * @brief Multiply + relinearize + rescale (common operation)
     */
    CKKSCiphertext multiply_relin_rescale(const CKKSCiphertext& ct1,
                                           const CKKSCiphertext& ct2,
                                           const CKKSRelinKey& rk);
    
    // ========== Utilities ==========
    
    /// Check if scales approximately match
    bool scales_match(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2,
                      double tolerance = 0.01) const;
    
    /// Get encoder
    CKKSEncoder& encoder() { return *encoder_; }
    
    /// Get RNS context
    const RNSContext* context() const { return context_; }

private:
    const RNSContext* context_;
    double default_scale_;
    std::unique_ptr<CKKSEncoder> encoder_;
    std::unique_ptr<CKKSRNSTool> rns_tool_;  ///< RNS key switching tool
    
    /// Sample from ternary distribution {-1, 0, 1}
    void sample_ternary_rns(RNSPoly* poly, std::mt19937_64& rng);
    
    /// Sample from discrete Gaussian approximation
    void sample_error_rns(RNSPoly* poly, double sigma, std::mt19937_64& rng);
    
    /// Sample uniform random polynomial
    void sample_uniform_rns(RNSPoly* poly, std::mt19937_64& rng);
};

// ============================================================================
// Standard Parameter Sets
// ============================================================================

namespace StandardParams {

/**
 * @brief Toy parameters for testing (NOT SECURE)
 */
inline CKKSParams TOY_PARAMS() {
    CKKSParams p;
    p.n = 256;
    p.L = 2;
    p.log_scale = 20.0;
    p.sigma = 3.2;
    return p;
}

/**
 * @brief 128-bit security with 3 levels
 */
inline CKKSParams SECURITY_128_DEPTH_3() {
    CKKSParams p;
    p.n = 4096;
    p.L = 3;
    p.log_scale = 40.0;
    p.sigma = 3.2;
    return p;
}

/**
 * @brief 128-bit security with 5 levels (recommended)
 */
inline CKKSParams SECURITY_128() {
    CKKSParams p;
    p.n = 8192;
    p.L = 5;
    p.log_scale = 40.0;
    p.sigma = 3.2;
    return p;
}

/**
 * @brief High depth computation (8 levels)
 */
inline CKKSParams SECURITY_128_DEPTH_8() {
    CKKSParams p;
    p.n = 16384;
    p.L = 8;
    p.log_scale = 45.0;
    p.sigma = 3.2;
    return p;
}

}  // namespace StandardParams

}  // namespace ckks
}  // namespace fhe
}  // namespace kctsb

#endif  // KCTSB_ADVANCED_FE_CKKS_CKKS_EVALUATOR_HPP
