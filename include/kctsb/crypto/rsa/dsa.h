/**
 * @file dsa.h
 * @brief Digital Signature Algorithm (DSA) Interface - NTL Backend
 * 
 * Provides complete DSA signature functionality:
 * - FIPS 186-4 compliant implementation
 * - Parameter generation (2048/3072-bit)
 * - Key generation
 * - Signature creation and verification
 * 
 * Security Features:
 * - RFC 6979 deterministic k generation (optional)
 * - Protection against fault attacks
 * - Strict parameter validation
 * 
 * Supported Key Sizes (FIPS 186-4):
 * - DSA-2048/224: L=2048, N=224
 * - DSA-2048/256: L=2048, N=256 (recommended)
 * - DSA-3072/256: L=3072, N=256
 * 
 * Usage Example:
 * @code
 *   DSA dsa(DSAKeySize::DSA_2048_256);
 *   auto keypair = dsa.generate_keypair();
 *   
 *   uint8_t hash[32] = {...};  // SHA-256 hash of message
 *   auto signature = dsa.sign(hash, 32, keypair.private_key);
 *   
 *   bool valid = dsa.verify(hash, 32, signature, keypair.public_key);
 * @endcode
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_RSA_DSA_H
#define KCTSB_CRYPTO_RSA_DSA_H

#include <vector>
#include <cstdint>
#include <string>
#include <NTL/ZZ.h>

using NTL::ZZ;
using NTL::conv;
using NTL::PowerMod;
using NTL::InvMod;
using NTL::ProbPrime;
using NTL::NumBytes;
using NTL::NumBits;
using NTL::BytesFromZZ;
using NTL::ZZFromBytes;

namespace kctsb {
namespace dsa {

// ============================================================================
// Enumerations and Types
// ============================================================================

/**
 * @brief DSA key size options (FIPS 186-4)
 * 
 * L = bit length of p
 * N = bit length of q
 */
enum class DSAKeySize {
    DSA_2048_224,   ///< L=2048, N=224 (legacy)
    DSA_2048_256,   ///< L=2048, N=256 (recommended)
    DSA_3072_256    ///< L=3072, N=256 (high security)
};

// ============================================================================
// Data Structures
// ============================================================================

/**
 * @brief DSA domain parameters
 */
struct DSAParams {
    ZZ p;           ///< Prime modulus (L bits)
    ZZ q;           ///< Prime divisor of (p-1) (N bits)
    ZZ g;           ///< Generator of order q subgroup
    size_t L;       ///< Bit length of p
    size_t N;       ///< Bit length of q
    
    /**
     * @brief Validate parameters
     * @return true if parameters are valid per FIPS 186-4
     */
    bool is_valid() const;
};

/**
 * @brief DSA key pair structure
 */
struct DSAKeyPair {
    DSAParams params;   ///< Domain parameters
    ZZ private_key;     ///< Private key x (1 < x < q)
    ZZ public_key;      ///< Public key y = g^x mod p
    
    /**
     * @brief Export public key as bytes
     * @return Public key in big-endian format
     */
    std::vector<uint8_t> export_public_key() const;
    
    /**
     * @brief Export private key as bytes (use with caution)
     * @return Private key in big-endian format
     */
    std::vector<uint8_t> export_private_key() const;
    
    /**
     * @brief Securely clear private key
     */
    void clear();
};

/**
 * @brief DSA signature structure
 */
struct DSASignature {
    ZZ r;   ///< Signature component r
    ZZ s;   ///< Signature component s
    
    /**
     * @brief Convert signature to bytes
     * @return Signature as byte array
     */
    std::vector<uint8_t> to_bytes() const;
    
    /**
     * @brief Create signature from bytes
     * @param data Signature data
     * @param len Data length
     * @return DSASignature
     * @throws std::invalid_argument if format is invalid
     */
    static DSASignature from_bytes(const uint8_t* data, size_t len);
};

// ============================================================================
// DSA Class
// ============================================================================

/**
 * @brief Digital Signature Algorithm class
 * 
 * Implements FIPS 186-4 compliant DSA
 */
class DSA {
public:
    /**
     * @brief Construct with standard key size
     * @param key_size DSA key size
     */
    explicit DSA(DSAKeySize key_size = DSAKeySize::DSA_2048_256);
    
    /**
     * @brief Construct with custom parameters
     * @param params DSA parameters
     * @throws std::invalid_argument if parameters are invalid
     */
    explicit DSA(const DSAParams& params);
    
    /**
     * @brief Get current parameters
     * @return Reference to DSA parameters
     */
    const DSAParams& get_params() const { return params_; }
    
    // ========================================================================
    // Parameter Generation
    // ========================================================================
    
    /**
     * @brief Generate DSA parameters
     * @param key_size Desired key size
     * @return Generated parameters
     */
    static DSAParams generate_params(DSAKeySize key_size);
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate a new DSA key pair
     * @return Newly generated key pair
     */
    DSAKeyPair generate_keypair() const;
    
    /**
     * @brief Create key pair from existing private key
     * @param private_key Private key value
     * @return Key pair with computed public key
     * @throws std::invalid_argument if private key is invalid
     */
    DSAKeyPair keypair_from_private(const ZZ& private_key) const;
    
    // ========================================================================
    // Signing and Verification
    // ========================================================================
    
    /**
     * @brief Sign a message hash
     * @param message_hash Hash of message to sign
     * @param hash_len Length of hash
     * @param private_key Signer's private key
     * @param use_rfc6979 Use deterministic k (RFC 6979)
     * @return DSA signature (r, s)
     */
    DSASignature sign(const uint8_t* message_hash, size_t hash_len,
                      const ZZ& private_key, bool use_rfc6979 = true) const;
    
    /**
     * @brief Verify a DSA signature
     * @param message_hash Hash of message
     * @param hash_len Length of hash
     * @param signature Signature to verify
     * @param public_key Signer's public key
     * @return true if signature is valid
     */
    bool verify(const uint8_t* message_hash, size_t hash_len,
                const DSASignature& signature, const ZZ& public_key) const;

private:
    DSAParams params_;  ///< DSA parameters
};

// ============================================================================
// High-Level API Functions
// ============================================================================

/**
 * @brief Generate DSA key pair
 * @param key_size DSA key size
 * @return Generated key pair with parameters
 */
DSAKeyPair dsa_generate_keypair(DSAKeySize key_size = DSAKeySize::DSA_2048_256);

/**
 * @brief Sign message hash with DSA
 * @param keypair Signer's key pair
 * @param message_hash Hash of message
 * @param hash_len Length of hash
 * @return DSA signature
 */
DSASignature dsa_sign(const DSAKeyPair& keypair,
                      const uint8_t* message_hash, size_t hash_len);

/**
 * @brief Verify DSA signature
 * @param keypair Key pair containing public key and parameters
 * @param message_hash Hash of message
 * @param hash_len Length of hash
 * @param signature Signature to verify
 * @return true if signature is valid
 */
bool dsa_verify(const DSAKeyPair& keypair,
                const uint8_t* message_hash, size_t hash_len,
                const DSASignature& signature);

} // namespace dsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_DSA_H
