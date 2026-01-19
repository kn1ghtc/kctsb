/**
 * @file bgv_types.hpp
 * @brief BGV Homomorphic Encryption Scheme - Type Definitions
 * 
 * Core type definitions for the Brakerski-Gentry-Vaikuntanathan (BGV) scheme.
 * This is a native implementation using kctsb's bignum library (NTL-based).
 * 
 * References:
 * - Brakerski, Gentry, Vaikuntanathan: "(Leveled) Fully Homomorphic Encryption 
 *   without Bootstrapping" (ITCS 2012)
 * - Fan, Vercauteren: "Somewhat Practical Fully Homomorphic Encryption" (IACR 2012)
 * - Smart, Vercauteren: "Fully Homomorphic SIMD Operations" (DCC 2014)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_ADVANCED_FE_BGV_TYPES_HPP
#define KCTSB_ADVANCED_FE_BGV_TYPES_HPP

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <limits>
#include <cmath>

// kctsb bignum types (NTL-compatible API)
#include "kctsb/math/bignum/ZZ.h"
#include "kctsb/math/bignum/ZZ_p.h"
#include "kctsb/math/bignum/ZZ_pX.h"
#include "kctsb/math/bignum/ZZ_pE.h"
#include "kctsb/math/bignum/ZZ_pEX.h"
#include "kctsb/math/bignum/vec_ZZ.h"
#include "kctsb/math/bignum/vec_ZZ_p.h"
#include "kctsb/math/bignum/vec_ZZ_pE.h"
#include "kctsb/math/bignum/mat_ZZ.h"

namespace kctsb {
namespace fhe {
namespace bgv {

// Use kctsb namespace types (compatible with NTL API)
using kctsb::ZZ;
using kctsb::ZZ_p;
using kctsb::ZZ_pX;
using kctsb::ZZ_pE;
using kctsb::ZZ_pEX;
using kctsb::vec_ZZ;
using kctsb::vec_ZZ_p;
using kctsb::vec_ZZ_pE;
using kctsb::mat_ZZ;
using kctsb::conv;
using kctsb::IsZero;
using kctsb::IsOne;
using kctsb::SetCoeff;
using kctsb::coeff;
using kctsb::deg;
using kctsb::rem;
using kctsb::power;
using kctsb::clear;
using kctsb::ProbPrime;
using kctsb::to_ulong;
using kctsb::to_long;
using kctsb::to_double;

// Helper functions for uint64_t conversion (LLP64 compatibility)
inline ZZ to_ZZ(uint64_t val) {
    // Handle uint64_t on LLP64 (Windows) where unsigned long is 32-bit
    if (val <= static_cast<uint64_t>(std::numeric_limits<unsigned long>::max())) {
        return conv<ZZ>(static_cast<unsigned long>(val));
    }
    // For larger values, construct from two 32-bit parts
    ZZ result = conv<ZZ>(static_cast<unsigned long>(val >> 32));
    result <<= 32;
    result += conv<ZZ>(static_cast<unsigned long>(val & 0xFFFFFFFFULL));
    return result;
}

inline double to_dbl(uint64_t val) {
    return static_cast<double>(val);
}

// Forward declarations
class BGVContext;
class BGVSecretKey;
class BGVPublicKey;
class BGVRelinKey;
class BGVGaloisKey;
class BGVCiphertext;
class BGVPlaintext;
class BGVEncoder;
class BGVEvaluator;

/**
 * @brief Security level enumeration
 * 
 * Defines post-quantum security levels based on LWE hardness estimates.
 * Higher levels require larger parameters and are slower.
 */
enum class SecurityLevel {
    NONE = 0,           ///< No security guarantee (for testing only)
    CLASSICAL_128 = 1,  ///< 128-bit classical security
    CLASSICAL_192 = 2,  ///< 192-bit classical security  
    CLASSICAL_256 = 3,  ///< 256-bit classical security
    QUANTUM_128 = 4,    ///< 128-bit post-quantum security
    QUANTUM_192 = 5,    ///< 192-bit post-quantum security
    QUANTUM_256 = 6     ///< 256-bit post-quantum security
};

/**
 * @brief BGV scheme parameters
 * 
 * Configures the polynomial ring R_q = Z_q[X]/(Φ_m(X)) for the BGV scheme.
 * 
 * Notation:
 * - m: cyclotomic ring index (Φ_m(X) is the m-th cyclotomic polynomial)
 * - n: polynomial degree = φ(m)
 * - q: ciphertext modulus (product of primes in RNS decomposition)
 * - t: plaintext modulus
 * - L: number of modulus levels (determines multiplicative depth)
 */
struct BGVParams {
    // Ring parameters
    uint64_t m = 0;              ///< Cyclotomic index (determines n = φ(m))
    uint64_t n = 0;              ///< Polynomial degree = φ(m)
    
    // Moduli
    ZZ q;                        ///< Ciphertext modulus
    uint64_t t = 0;              ///< Plaintext modulus (typically small prime)
    
    // RNS decomposition (for faster modular arithmetic)
    std::vector<uint64_t> primes;  ///< List of NTT-friendly primes q = q_1 * ... * q_L
    uint32_t L = 0;                ///< Number of levels (primes)
    
    // Error distribution
    double sigma = 3.2;          ///< Standard deviation for discrete Gaussian
    uint32_t hamming_weight = 0; ///< Hamming weight for secret key (0 = dense)
    
    // Security
    SecurityLevel security = SecurityLevel::CLASSICAL_128;
    
    /**
     * @brief Get the slot count for batching (SIMD)
     * @return Number of plaintext slots = n / ord_t(m)
     */
    uint64_t slot_count() const;
    
    /**
     * @brief Calculate noise budget in bits
     * @return Maximum noise before decryption fails
     */
    double initial_noise_budget() const;
    
    /**
     * @brief Validate parameter consistency
     * @return true if parameters are valid
     */
    bool validate() const;
    
    /**
     * @brief Create standard parameters for given security and depth
     * @param security Target security level
     * @param mult_depth Required multiplicative depth
     * @param t Plaintext modulus
     * @return Configured parameters
     */
    static BGVParams create_standard(SecurityLevel security, 
                                      uint32_t mult_depth,
                                      uint64_t t = 65537);
};

/**
 * @brief Standard parameter sets
 * 
 * Pre-defined parameter sets for common use cases.
 * Based on HElib and SEAL standard parameters.
 */
namespace StandardParams {
    /// Small parameters for testing (INSECURE)
    BGVParams TOY_PARAMS();
    
    /// 128-bit security, depth 3
    BGVParams SECURITY_128_DEPTH_3();
    
    /// 128-bit security, depth 5  
    BGVParams SECURITY_128_DEPTH_5();
    
    /// 192-bit security, depth 5
    BGVParams SECURITY_192_DEPTH_5();
}

/**
 * @brief Polynomial element in R_q
 * 
 * Represents a polynomial in the ring Z_q[X]/(Φ_m(X)).
 * Stored in coefficient representation (power basis).
 */
class RingElement {
public:
    RingElement() = default;
    explicit RingElement(const ZZ_pX& poly);
    RingElement(const RingElement& other) = default;
    RingElement(RingElement&& other) noexcept = default;
    RingElement& operator=(const RingElement& other) = default;
    RingElement& operator=(RingElement&& other) noexcept = default;
    
    /// Access underlying polynomial
    const ZZ_pX& poly() const { return poly_; }
    ZZ_pX& poly() { return poly_; }
    
    /// Coefficient access
    ZZ_p coeff(long i) const;
    void set_coeff(long i, const ZZ_p& val);
    
    /// Degree
    long degree() const;
    
    /// Ring operations
    RingElement operator+(const RingElement& other) const;
    RingElement operator-(const RingElement& other) const;
    RingElement operator*(const RingElement& other) const;
    RingElement operator-() const;
    
    RingElement& operator+=(const RingElement& other);
    RingElement& operator-=(const RingElement& other);
    RingElement& operator*=(const RingElement& other);
    
    /// Scalar operations
    RingElement operator*(const ZZ_p& scalar) const;
    RingElement& operator*=(const ZZ_p& scalar);
    
    /// Comparison
    bool operator==(const RingElement& other) const;
    bool operator!=(const RingElement& other) const { return !(*this == other); }
    
    /// Utility
    bool is_zero() const;
    void clear();
    
    /// Modular reduction (reduce coefficients mod new modulus)
    RingElement reduce_mod(const ZZ& new_mod) const;
    
    /// NTT transform (for faster multiplication)
    void to_ntt();
    void from_ntt();
    bool is_ntt() const { return is_ntt_; }

private:
    ZZ_pX poly_;           ///< Coefficient representation
    bool is_ntt_ = false;  ///< True if in NTT domain
    
    friend class BGVContext;
};

/**
 * @brief BGV Plaintext
 * 
 * Represents a plaintext element in the ring R_t = Z_t[X]/(Φ_m(X)).
 * Can encode:
 * - Single integers (coefficient encoding)
 * - Vectors of integers (SIMD/batching with CRT)
 */
class BGVPlaintext {
public:
    BGVPlaintext() = default;
    explicit BGVPlaintext(const RingElement& elem);
    explicit BGVPlaintext(uint64_t value);
    explicit BGVPlaintext(const std::vector<int64_t>& values);
    
    /// Access encoded polynomial
    const RingElement& data() const { return data_; }
    RingElement& data() { return data_; }
    
    /// Check if SIMD encoded
    bool is_batched() const { return is_batched_; }
    
    /// Get slot values (after decoding)
    std::vector<int64_t> decode_slots() const;
    
    /// Get single value (coefficient 0)
    int64_t decode_single() const;

private:
    RingElement data_;
    bool is_batched_ = false;
    
    friend class BGVEncoder;
};

/**
 * @brief BGV Ciphertext
 * 
 * A ciphertext is a vector of ring elements (c_0, c_1, ..., c_k) where k >= 1.
 * Fresh ciphertexts have k=1 (two elements).
 * After multiplication, k increases (requires relinearization).
 * 
 * Decryption: m = [c_0 + c_1*s + c_2*s^2 + ...]_t
 */
class BGVCiphertext {
public:
    BGVCiphertext() = default;
    
    /// Number of polynomial components
    size_t size() const { return polys_.size(); }
    
    /// Access components
    const RingElement& operator[](size_t i) const { return polys_[i]; }
    RingElement& operator[](size_t i) { return polys_[i]; }
    
    /// Add new component
    void push_back(const RingElement& elem);
    void push_back(RingElement&& elem);
    
    /// Current modulus level
    uint32_t level() const { return level_; }
    void set_level(uint32_t lvl) { level_ = lvl; }
    
    /// Noise budget estimate (in bits)
    double noise_budget() const { return noise_budget_; }
    void set_noise_budget(double budget) { noise_budget_ = budget; }
    
    /// Serialization
    std::vector<uint8_t> serialize() const;
    static BGVCiphertext deserialize(const std::vector<uint8_t>& data);
    
    /// Size in bytes
    size_t byte_size() const;

private:
    std::vector<RingElement> polys_;
    uint32_t level_ = 0;
    double noise_budget_ = 0.0;
    
    friend class BGVContext;
    friend class BGVEvaluator;
};

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_ADVANCED_FE_BGV_TYPES_HPP
