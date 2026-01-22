/**
 * @file bgv_context.hpp
 * @brief BGV Scheme Context and Key Management
 * 
 * The BGVContext is the central manager for BGV scheme parameters, keys,
 * and cryptographic operations. It initializes the polynomial ring
 * and provides key generation, encryption, decryption interfaces.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * 
 * @security v4.6.0: Added ModulusGuard and context versioning to prevent
 *           global state pollution (Chapter 6 lessons from troubleshooting).
 */

#ifndef KCTSB_ADVANCED_FE_BGV_CONTEXT_HPP
#define KCTSB_ADVANCED_FE_BGV_CONTEXT_HPP

#include "bgv_types.hpp"
#include <random>
#include <functional>
#include <map>
#include <atomic>

namespace kctsb {
namespace fhe {
namespace bgv {

// Forward declaration
class BGVContext;

/**
 * @brief RAII guard for NTL modulus context protection
 * 
 * Saves the current ZZ_p modulus on construction and restores it on destruction.
 * This prevents "modulus pollution" when switching between different BGV contexts
 * or when BGV operations are called from code with different modulus expectations.
 * 
 * @security v4.6.0: Implements Chapter 6.1 recommendation - explicit modulus protection
 * 
 * Usage:
 * @code
 * void some_bgv_operation() {
 *     ModulusGuard guard(ciphertext_modulus_);  // Saves current, sets new
 *     // ... operations using ciphertext_modulus_ ...
 * }  // guard destructor restores original modulus
 * @endcode
 */
class ModulusGuard {
public:
    /**
     * @brief Construct guard with specific modulus
     * @param q New modulus to set (must be > 1)
     */
    explicit ModulusGuard(const ZZ& q);
    
    /**
     * @brief Destructor - restores original modulus
     */
    ~ModulusGuard();
    
    // Non-copyable, non-movable (RAII semantics)
    ModulusGuard(const ModulusGuard&) = delete;
    ModulusGuard& operator=(const ModulusGuard&) = delete;
    ModulusGuard(ModulusGuard&&) = delete;
    ModulusGuard& operator=(ModulusGuard&&) = delete;

private:
    ZZ_pBak backup_;  ///< Saved modulus state
};

/**
 * @brief BGV Secret Key
 * 
 * The secret key is a polynomial s ∈ R with small coefficients
 * (typically ternary: coefficients in {-1, 0, 1}).
 * 
 * IMPORTANT: Coefficients are stored as ZZ (not ZZ_p) to avoid
 * dependency on NTL's global modulus state.
 * 
 * @security v4.6.0: Added context-aware power caching with version validation
 */
class BGVSecretKey {
public:
    BGVSecretKey() = default;
    
    /// Access secret polynomial (use with caution - modulus-dependent)
    const RingElement& data() const { return s_; }
    
    /// Get coefficient as ZZ (modulus-independent)
    const ZZ& coeff(size_t i) const;
    
    /// Get all coefficients
    const std::vector<ZZ>& coefficients() const { return coeffs_; }
    
    /// Polynomial degree
    long degree() const;
    
    /**
     * @brief Get power of secret key s^k (with context version validation)
     * @param k Power exponent
     * @param ctx_version Context version for cache validation
     * @return Reference to cached s^k
     * 
     * @security v4.6.0: Cache is invalidated if context version changes
     *           (Chapter 6.3 recommendation)
     */
    const RingElement& power(size_t k, uint64_t ctx_version = 0) const;
    
    /**
     * @brief Invalidate cached power computations
     * 
     * Call this when switching contexts or when the modulus changes.
     * @security v4.6.0: Part of cache invalidation mechanism
     */
    void invalidate_power_cache() const;
    
    /// Serialize (CAUTION: contains secret material)
    std::vector<uint8_t> serialize() const;
    static BGVSecretKey deserialize(const std::vector<uint8_t>& data);
    
    /// Secure destruction
    ~BGVSecretKey();

private:
    RingElement s_;                        ///< Secret polynomial (for backward compat)
    std::vector<ZZ> coeffs_;               ///< Modulus-independent coefficients
    mutable std::vector<RingElement> powers_;  ///< Cached powers s^k
    mutable uint64_t cached_ctx_version_ = 0;  ///< Context version for cache validation
    
    friend class BGVContext;
};

/**
 * @brief BGV Public Key
 * 
 * The public key is a pair (b, a) where:
 * - a is uniform random in R_q
 * - b = -a*s + t*e for small error e
 * 
 * Encryption: c = (b*u + t*e_1 + m, a*u + t*e_2)
 */
class BGVPublicKey {
public:
    BGVPublicKey() = default;
    
    /// Public key components (b, a)
    const RingElement& b() const { return b_; }
    const RingElement& a() const { return a_; }
    
    /// Serialization
    std::vector<uint8_t> serialize() const;
    static BGVPublicKey deserialize(const std::vector<uint8_t>& data);
    
    /// Size in bytes
    size_t byte_size() const;

private:
    RingElement b_;  ///< First component
    RingElement a_;  ///< Second component
    
    friend class BGVContext;
};

/**
 * @brief Relinearization Key
 * 
 * Used to reduce ciphertext size after multiplication.
 * Key switching from s^2 to s.
 */
class BGVRelinKey {
public:
    BGVRelinKey() = default;
    
    /// Access key components
    const std::vector<std::pair<RingElement, RingElement>>& data() const {
        return key_components_;
    }
    
    /// Serialization
    std::vector<uint8_t> serialize() const;
    static BGVRelinKey deserialize(const std::vector<uint8_t>& data);

private:
    // Key switching components for each decomposition digit
    std::vector<std::pair<RingElement, RingElement>> key_components_;
    
    friend class BGVContext;
};

/**
 * @brief Galois Keys (for rotation operations)
 * 
 * Enables automorphism operations X -> X^k for slot rotations.
 */
class BGVGaloisKey {
public:
    BGVGaloisKey() = default;
    
    /// Get key for specific automorphism
    const std::vector<std::pair<RingElement, RingElement>>& 
        get_key(uint64_t galois_elt) const;
    
    /// Check if automorphism is available
    bool has_key(uint64_t galois_elt) const;

private:
    // Map from Galois element to key switching key
    std::map<uint64_t, std::vector<std::pair<RingElement, RingElement>>> keys_;
    
    friend class BGVContext;
};

/**
 * @brief BGV Scheme Context
 * 
 * Central class for managing the BGV homomorphic encryption scheme.
 * Responsible for:
 * - Parameter validation and storage
 * - Key generation (secret, public, relinearization, Galois)
 * - Encryption and decryption
 * - Ring arithmetic setup
 * 
 * @security v4.6.0: Added context versioning for cache invalidation
 *           (Chapter 6.3 recommendation). Each context instance has a unique
 *           version number that increases monotonically across all contexts.
 */
class BGVContext {
public:
    /**
     * @brief Construct context from parameters
     * @param params BGV scheme parameters
     * @throws std::invalid_argument if parameters are invalid
     */
    explicit BGVContext(const BGVParams& params);
    
    /// Destructor (secure cleanup)
    ~BGVContext();
    
    // Non-copyable, movable
    BGVContext(const BGVContext&) = delete;
    BGVContext& operator=(const BGVContext&) = delete;
    BGVContext(BGVContext&&) noexcept;
    BGVContext& operator=(BGVContext&&) noexcept;
    
    // ==================== Parameter Access ====================
    
    /// Get parameters
    const BGVParams& params() const { return params_; }
    
    /// Ring degree n = φ(m)
    uint64_t ring_degree() const { return params_.n; }
    
    /// Plaintext modulus t
    uint64_t plaintext_modulus() const { return params_.t; }
    
    /// Ciphertext modulus q at level k
    ZZ ciphertext_modulus(uint32_t level = 0) const;
    
    /// Number of slots for batching
    uint64_t slot_count() const { return params_.slot_count(); }
    
    // ==================== Key Generation ====================
    
    /**
     * @brief Generate new secret key
     * @return Generated secret key
     */
    BGVSecretKey generate_secret_key();
    
    /**
     * @brief Generate public key from secret key
     * @param sk Secret key
     * @return Generated public key
     */
    BGVPublicKey generate_public_key(const BGVSecretKey& sk);
    
    /**
     * @brief Generate relinearization key
     * @param sk Secret key
     * @return Relinearization key for multiplication
     */
    BGVRelinKey generate_relin_key(const BGVSecretKey& sk);
    
    /**
     * @brief Generate Galois keys for rotation
     * @param sk Secret key
     * @param steps Rotation steps to support (empty = all)
     * @return Galois key set
     */
    BGVGaloisKey generate_galois_keys(const BGVSecretKey& sk,
                                       const std::vector<int>& steps = {});
    
    // ==================== Encryption/Decryption ====================
    
    /**
     * @brief Encrypt plaintext
     * @param pk Public key
     * @param pt Plaintext to encrypt
     * @return Ciphertext
     */
    BGVCiphertext encrypt(const BGVPublicKey& pk, const BGVPlaintext& pt);
    
    /**
     * @brief Decrypt ciphertext
     * @param sk Secret key
     * @param ct Ciphertext to decrypt
     * @return Decrypted plaintext
     */
    BGVPlaintext decrypt(const BGVSecretKey& sk, const BGVCiphertext& ct);
    
    /**
     * @brief Symmetric encryption (faster, uses secret key)
     * @param sk Secret key
     * @param pt Plaintext
     * @return Ciphertext
     */
    BGVCiphertext encrypt_symmetric(const BGVSecretKey& sk, 
                                     const BGVPlaintext& pt);
    
    /**
     * @brief Encrypt zero (useful for homomorphic operations)
     * @param pk Public key
     * @return Encryption of zero polynomial
     */
    BGVCiphertext encrypt_zero(const BGVPublicKey& pk);
    
    // ==================== Noise Management ====================
    
    /**
     * @brief Estimate remaining noise budget
     * @param sk Secret key (for exact measurement)
     * @param ct Ciphertext
     * @return Noise budget in bits
     */
    double noise_budget(const BGVSecretKey& sk, const BGVCiphertext& ct);
    
    /**
     * @brief Check if ciphertext can be decrypted correctly
     * @param sk Secret key
     * @param ct Ciphertext
     * @return true if noise is within bounds
     */
    bool is_valid(const BGVSecretKey& sk, const BGVCiphertext& ct);
    
    // ==================== Context Version Control ====================
    
    /**
     * @brief Get unique context version number
     * @return Monotonically increasing version number
     * 
     * @security v4.6.0: Used for cache invalidation (Chapter 6.3)
     */
    uint64_t version() const { return version_; }
    
    /**
     * @brief Get the ciphertext modulus for this context
     * @return Current ciphertext modulus q
     */
    const ZZ& modulus() const;
    
    // ==================== Ring Operations ====================
    
    /**
     * @brief Sample uniform random polynomial
     * @return Random element in R_q
     */
    RingElement sample_uniform();
    
    /**
     * @brief Sample error polynomial (discrete Gaussian)
     * @return Small polynomial with Gaussian coefficients
     */
    RingElement sample_error();
    
    /**
     * @brief Sample ternary polynomial (coefficients in {-1,0,1})
     * @param hamming_weight Number of non-zero coefficients (0 = random)
     * @return Ternary polynomial
     */
    RingElement sample_ternary(uint32_t hamming_weight = 0);
    
    /**
     * @brief Compute cyclotomic polynomial Φ_m(X)
     * @return Cyclotomic polynomial coefficients
     */
    const ZZ_pX& cyclotomic() const { return cyclotomic_; }
    
    // ==================== Serialization ====================
    
    /// Serialize context (parameters only, not keys)
    std::vector<uint8_t> serialize() const;
    
    /// Deserialize context
    static std::unique_ptr<BGVContext> deserialize(
        const std::vector<uint8_t>& data);

private:
    BGVParams params_;
    ZZ_pX cyclotomic_;      ///< Φ_m(X)
    uint64_t version_;      ///< Unique context version for cache invalidation
    
    /// Global version counter (monotonically increasing)
    static std::atomic<uint64_t> global_version_counter_;
    
    // RNS components for each level
    struct LevelContext {
        ZZ q;               ///< Modulus at this level
        ZZ_pX cyclotomic;   ///< Φ_m(X) mod q
        // NTT tables (if using NTT)
    };
    std::vector<LevelContext> levels_;
    
    // Random number generation
    std::mt19937_64 rng_;
    
    // Initialization
    void initialize_ring();
    void initialize_levels();
    ZZ_pX compute_cyclotomic(uint64_t m);
};

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_ADVANCED_FE_BGV_CONTEXT_HPP
