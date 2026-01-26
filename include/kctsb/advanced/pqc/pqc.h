/**
 * @file pqc.h
 * @brief Post-Quantum Cryptography Interface - NIST Standards
 * 
 * Implements NIST PQC standardized algorithms:
 * - ML-KEM (Kyber) - Key Encapsulation Mechanism
 * - ML-DSA (Dilithium) - Digital Signature Algorithm
 * 
 * Security Levels:
 * - Level 1 (128-bit): Kyber512, Dilithium2
 * - Level 3 (192-bit): Kyber768, Dilithium3
 * - Level 5 (256-bit): Kyber1024, Dilithium5
 * 
 * Based on:
 * - FIPS 203 (ML-KEM)
 * - FIPS 204 (ML-DSA)
 * - Lattice-based cryptography (Module-LWE, Module-SIS)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_PQC_H
#define KCTSB_CRYPTO_PQC_H

#include <vector>
#include <cstdint>
#include <array>

namespace kctsb {
namespace pqc {

// ============================================================================
// Common Constants
// ============================================================================

constexpr size_t KYBER_N = 256;           // Polynomial degree
constexpr uint32_t KYBER_Q = 3329;        // Modulus q

constexpr size_t DILITHIUM_N = 256;       // Polynomial degree
constexpr uint32_t DILITHIUM_Q = 8380417; // Modulus q (2^23 - 2^13 + 1)

// ============================================================================
// Kyber Parameter Sets
// ============================================================================

/**
 * @brief Kyber security level
 */
enum class KyberLevel {
    KYBER512 = 2,   ///< k=2, 128-bit security (Level 1)
    KYBER768 = 3,   ///< k=3, 192-bit security (Level 3)
    KYBER1024 = 4   ///< k=4, 256-bit security (Level 5)
};

/**
 * @brief Kyber parameter set
 */
struct KyberParams {
    size_t k;           ///< Module rank
    size_t eta1;        ///< CBD parameter for secret
    size_t eta2;        ///< CBD parameter for noise
    size_t du;          ///< Bits for u compression
    size_t dv;          ///< Bits for v compression
    
    // Sizes in bytes
    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
    
    static KyberParams get(KyberLevel level);
};

// ============================================================================
// Kyber Data Structures
// ============================================================================

/**
 * @brief Kyber polynomial (Z_q[X]/(X^256 + 1))
 */
struct KyberPoly {
    std::array<int16_t, KYBER_N> coeffs;
    
    KyberPoly& operator+=(const KyberPoly& other);
    KyberPoly& operator-=(const KyberPoly& other);
    KyberPoly operator+(const KyberPoly& other) const;
    KyberPoly operator-(const KyberPoly& other) const;
    
    void reduce();  // Barrett reduction mod q
    void ntt();     // Number Theoretic Transform
    void inv_ntt(); // Inverse NTT
};

/**
 * @brief Kyber polynomial vector
 */
struct KyberPolyVec {
    std::vector<KyberPoly> polys;
    
    explicit KyberPolyVec(size_t k) : polys(k) {}
    
    KyberPolyVec& operator+=(const KyberPolyVec& other);
    void ntt();
    void inv_ntt();
    void reduce();
};

/**
 * @brief Kyber public key
 */
struct KyberPublicKey {
    std::vector<uint8_t> data;
    
    size_t size() const { return data.size(); }
    const uint8_t* bytes() const { return data.data(); }
};

/**
 * @brief Kyber secret key
 */
struct KyberSecretKey {
    std::vector<uint8_t> data;
    
    size_t size() const { return data.size(); }
    const uint8_t* bytes() const { return data.data(); }
    
    void clear();  // Secure zeroing
};

/**
 * @brief Kyber key pair
 */
struct KyberKeyPair {
    KyberPublicKey public_key;
    KyberSecretKey secret_key;
};

/**
 * @brief Kyber ciphertext
 */
struct KyberCiphertext {
    std::vector<uint8_t> data;
    
    size_t size() const { return data.size(); }
    const uint8_t* bytes() const { return data.data(); }
};

// ============================================================================
// Kyber KEM (ML-KEM)
// ============================================================================

/**
 * @brief Kyber Key Encapsulation Mechanism
 */
class Kyber {
public:
    /**
     * @brief Construct with security level
     * @param level Security level (KYBER512, KYBER768, KYBER1024)
     */
    explicit Kyber(KyberLevel level = KyberLevel::KYBER768);
    
    /**
     * @brief Get current parameters
     */
    const KyberParams& get_params() const { return params_; }
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate key pair
     * @return Key pair (public key, secret key)
     */
    KyberKeyPair keygen() const;
    
    // ========================================================================
    // Encapsulation/Decapsulation
    // ========================================================================
    
    /**
     * @brief Encapsulate: generate shared secret and ciphertext
     * @param public_key Recipient's public key
     * @param shared_secret Output: shared secret (32 bytes)
     * @return Ciphertext
     */
    KyberCiphertext encaps(const KyberPublicKey& public_key,
                           std::array<uint8_t, 32>& shared_secret) const;
    
    /**
     * @brief Decapsulate: recover shared secret from ciphertext
     * @param secret_key Recipient's secret key
     * @param ciphertext Ciphertext from encaps
     * @param shared_secret Output: shared secret (32 bytes)
     * @return true if decapsulation successful
     */
    bool decaps(const KyberSecretKey& secret_key,
                const KyberCiphertext& ciphertext,
                std::array<uint8_t, 32>& shared_secret) const;

private:
    KyberLevel level_;
    KyberParams params_;
    
    // Internal functions
    void gen_matrix(std::vector<std::vector<KyberPoly>>& A,
                    const uint8_t seed[32], bool transposed) const;
    void sample_noise(KyberPolyVec& r, const uint8_t seed[32], uint8_t nonce) const;
    void pack_pk(std::vector<uint8_t>& out, const KyberPolyVec& pk,
                 const uint8_t seed[32]) const;
    void unpack_pk(KyberPolyVec& pk, uint8_t seed[32],
                   const std::vector<uint8_t>& data) const;
};

// ============================================================================
// Dilithium Parameter Sets
// ============================================================================

/**
 * @brief Dilithium security level
 */
enum class DilithiumLevel {
    DILITHIUM2 = 2,   ///< Level 2, 128-bit security
    DILITHIUM3 = 3,   ///< Level 3, 192-bit security
    DILITHIUM5 = 5    ///< Level 5, 256-bit security
};

/**
 * @brief Dilithium parameter set
 */
struct DilithiumParams {
    size_t k;           ///< Rows in matrix A
    size_t l;           ///< Columns in matrix A
    size_t eta;         ///< Secret key coefficient bound
    size_t tau;         ///< Number of +/-1 in c
    size_t beta;        ///< = tau * eta
    size_t gamma1;      ///< y coefficient range
    size_t gamma2;      ///< Low-order rounding range
    size_t omega;       ///< Hint weight bound
    
    // Sizes in bytes
    size_t public_key_size;
    size_t secret_key_size;
    size_t signature_size;
    
    static DilithiumParams get(DilithiumLevel level);
};

// ============================================================================
// Dilithium Data Structures
// ============================================================================

/**
 * @brief Dilithium polynomial (Z_q[X]/(X^256 + 1))
 */
struct DilithiumPoly {
    std::array<int32_t, DILITHIUM_N> coeffs;
    
    DilithiumPoly& operator+=(const DilithiumPoly& other);
    DilithiumPoly& operator-=(const DilithiumPoly& other);
    DilithiumPoly operator+(const DilithiumPoly& other) const;
    DilithiumPoly operator-(const DilithiumPoly& other) const;
    
    void reduce();  // Reduction mod q
    void ntt();     // Number Theoretic Transform
    void inv_ntt(); // Inverse NTT
};

/**
 * @brief Dilithium polynomial vector
 */
struct DilithiumPolyVec {
    std::vector<DilithiumPoly> polys;
    
    explicit DilithiumPolyVec(size_t n) : polys(n) {}
    
    DilithiumPolyVec& operator+=(const DilithiumPolyVec& other);
    DilithiumPolyVec& operator-=(const DilithiumPolyVec& other);
    void ntt();
    void inv_ntt();
    void reduce();
};

/**
 * @brief Dilithium public key
 */
struct DilithiumPublicKey {
    std::vector<uint8_t> data;
    
    size_t size() const { return data.size(); }
    const uint8_t* bytes() const { return data.data(); }
};

/**
 * @brief Dilithium secret key
 */
struct DilithiumSecretKey {
    std::vector<uint8_t> data;
    
    size_t size() const { return data.size(); }
    const uint8_t* bytes() const { return data.data(); }
    
    void clear();  // Secure zeroing
};

/**
 * @brief Dilithium key pair
 */
struct DilithiumKeyPair {
    DilithiumPublicKey public_key;
    DilithiumSecretKey secret_key;
};

/**
 * @brief Dilithium signature
 */
struct DilithiumSignature {
    std::vector<uint8_t> data;
    
    size_t size() const { return data.size(); }
    const uint8_t* bytes() const { return data.data(); }
};

// ============================================================================
// Dilithium Signature (ML-DSA)
// ============================================================================

/**
 * @brief Dilithium Digital Signature Algorithm
 */
class Dilithium {
public:
    /**
     * @brief Construct with security level
     * @param level Security level (DILITHIUM2, DILITHIUM3, DILITHIUM5)
     */
    explicit Dilithium(DilithiumLevel level = DilithiumLevel::DILITHIUM3);
    
    /**
     * @brief Get current parameters
     */
    const DilithiumParams& get_params() const { return params_; }
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate key pair
     * @return Key pair (public key, secret key)
     */
    DilithiumKeyPair keygen() const;
    
    // ========================================================================
    // Signing and Verification
    // ========================================================================
    
    /**
     * @brief Sign a message
     * @param secret_key Signer's secret key
     * @param message Message to sign
     * @param message_len Message length
     * @return Signature
     */
    DilithiumSignature sign(const DilithiumSecretKey& secret_key,
                            const uint8_t* message, size_t message_len) const;
    
    /**
     * @brief Verify a signature
     * @param public_key Signer's public key
     * @param signature Signature to verify
     * @param message Message that was signed
     * @param message_len Message length
     * @return true if signature is valid
     */
    bool verify(const DilithiumPublicKey& public_key,
                const DilithiumSignature& signature,
                const uint8_t* message, size_t message_len) const;

    /**
     * @brief Get the security level
     * @return Current Dilithium security level
     */
    DilithiumLevel get_level() const { return level_; }

private:
    DilithiumLevel level_;
    DilithiumParams params_;
    
    // Internal functions
    void expand_matrix(std::vector<std::vector<DilithiumPoly>>& A,
                       const uint8_t rho[32]) const;
    void sample_s(DilithiumPolyVec& s, const uint8_t rhoprime[64]) const;
    DilithiumPoly challenge(const uint8_t mu[64], size_t tau) const;
};

// ============================================================================
// High-Level API Functions
// ============================================================================

/**
 * @brief Generate Kyber key pair
 * @param level Security level
 * @return Key pair
 */
KyberKeyPair kyber_keygen(KyberLevel level = KyberLevel::KYBER768);

/**
 * @brief Kyber encapsulation
 * @param pk Recipient's public key
 * @param level Security level
 * @return Pair of (ciphertext, shared_secret)
 */
std::pair<KyberCiphertext, std::array<uint8_t, 32>>
kyber_encaps(const KyberPublicKey& pk, KyberLevel level = KyberLevel::KYBER768);

/**
 * @brief Kyber decapsulation
 * @param sk Recipient's secret key
 * @param ct Ciphertext
 * @param level Security level
 * @return Shared secret
 */
std::array<uint8_t, 32> kyber_decaps(const KyberSecretKey& sk,
                                      const KyberCiphertext& ct,
                                      KyberLevel level = KyberLevel::KYBER768);

/**
 * @brief Generate Dilithium key pair
 * @param level Security level
 * @return Key pair
 */
DilithiumKeyPair dilithium_keygen(DilithiumLevel level = DilithiumLevel::DILITHIUM3);

/**
 * @brief Dilithium sign
 * @param sk Signer's secret key
 * @param message Message to sign
 * @param message_len Message length
 * @param level Security level
 * @return Signature
 */
DilithiumSignature dilithium_sign(const DilithiumSecretKey& sk,
                                   const uint8_t* message, size_t message_len,
                                   DilithiumLevel level = DilithiumLevel::DILITHIUM3);

/**
 * @brief Dilithium verify
 * @param pk Signer's public key
 * @param sig Signature
 * @param message Message
 * @param message_len Message length
 * @param level Security level
 * @return true if valid
 */
bool dilithium_verify(const DilithiumPublicKey& pk,
                      const DilithiumSignature& sig,
                      const uint8_t* message, size_t message_len,
                      DilithiumLevel level = DilithiumLevel::DILITHIUM3);

} // namespace pqc
} // namespace kctsb

#endif // KCTSB_CRYPTO_PQC_H
