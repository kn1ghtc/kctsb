/**
 * @file dh.h
 * @brief Diffie-Hellman Key Exchange Interface - Bignum Backend
 * 
 * Provides complete DH key exchange functionality:
 * - Standard MODP groups (RFC 3526 / RFC 7919)
 * - Key generation and validation
 * - Shared secret computation
 * 
 * Security Features:
 * - Safe prime groups (p = 2q + 1)
 * - Subgroup confinement validation
 * - Protection against small subgroup attacks
 * 
 * Supported Groups:
 * - MODP-2048 (128-bit security, RFC 3526 Group 14)
 * - MODP-3072 (128-bit security, RFC 3526 Group 15)
 * - MODP-4096 (192-bit security, RFC 3526 Group 16)
 * 
 * Usage Example:
 * @code
 *   DH alice(DHGroupType::MODP_2048);
 *   DH bob(DHGroupType::MODP_2048);
 *   
 *   auto alice_keypair = alice.generate_keypair();
 *   auto bob_keypair = bob.generate_keypair();
 *   
 *   auto alice_secret = alice.compute_shared_secret(alice_keypair, bob_keypair.public_key);
 *   auto bob_secret = bob.compute_shared_secret(bob_keypair, alice_keypair.public_key);
 *   // alice_secret == bob_secret
 * @endcode
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_RSA_DH_H
#define KCTSB_CRYPTO_RSA_DH_H

#include <vector>
#include <cstdint>
#include <string>
#include <kctsb/math/bignum/ZZ.h>

using kctsb::ZZ;
using kctsb::conv;
using kctsb::PowerMod;
using kctsb::ProbPrime;
using kctsb::NumBytes;
using kctsb::BytesFromZZ;
using kctsb::ZZFromBytes;
using kctsb::IsZero;

namespace kctsb {
namespace dh {

// ============================================================================
// Enumerations and Types
// ============================================================================

/**
 * @brief Standard DH group types
 * 
 * Groups follow RFC 3526 (MODP groups for IKE) and RFC 7919 (TLS FFDHE)
 */
enum class DHGroupType {
    MODP_2048 = 14,  ///< RFC 3526 Group 14 - 2048-bit MODP (112-bit security)
    MODP_3072 = 15,  ///< RFC 3526 Group 15 - 3072-bit MODP (128-bit security)
    MODP_4096 = 16   ///< RFC 3526 Group 16 - 4096-bit MODP (152-bit security)
};

// ============================================================================
// Data Structures
// ============================================================================

/**
 * @brief DH parameters structure
 */
struct DHParams {
    ZZ p;               ///< Prime modulus
    ZZ g;               ///< Generator
    ZZ q;               ///< Order of subgroup (optional, for safe primes q = (p-1)/2)
    size_t bits;        ///< Bit length of prime
    std::string name;   ///< Parameter set name
    
    /**
     * @brief Validate parameters
     * @return true if parameters are valid
     */
    bool is_valid() const;
};

/**
 * @brief DH key pair structure
 */
struct DHKeyPair {
    ZZ private_key;     ///< Private key x (random)
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
     * @brief Securely clear key material
     */
    void clear();
};

// ============================================================================
// Standard Group Parameter Getters
// ============================================================================

/**
 * @brief Get MODP-2048 parameters (RFC 3526 Group 14)
 * @return DHParams for 2048-bit MODP group
 */
DHParams get_modp_2048();

/**
 * @brief Get MODP-3072 parameters (RFC 3526 Group 15)
 * @return DHParams for 3072-bit MODP group
 */
DHParams get_modp_3072();

/**
 * @brief Get MODP-4096 parameters (RFC 3526 Group 16)
 * @return DHParams for 4096-bit MODP group
 */
DHParams get_modp_4096();

// ============================================================================
// DH Class
// ============================================================================

/**
 * @brief Diffie-Hellman Key Exchange class
 * 
 * Implements finite field DH (FFDH) with standard groups
 */
class DH {
public:
    /**
     * @brief Default constructor (uses MODP-2048)
     */
    DH();
    
    /**
     * @brief Construct with standard group
     * @param group_type DH group type
     */
    explicit DH(DHGroupType group_type);
    
    /**
     * @brief Construct with custom parameters
     * @param params DH parameters
     * @throws std::invalid_argument if parameters are invalid
     */
    explicit DH(const DHParams& params);
    
    /**
     * @brief Get current parameters
     * @return Reference to DH parameters
     */
    const DHParams& get_params() const { return params_; }
    
    /**
     * @brief Get prime bit size
     * @return Bit length of prime modulus
     */
    size_t get_prime_bits() const { return params_.bits; }
    
    /**
     * @brief Get prime byte size
     * @return Byte length of prime modulus
     */
    size_t get_prime_size() const;
    
    /**
     * @brief Get shared secret byte size
     * @return Expected length of shared secret
     */
    size_t get_shared_secret_size() const;
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate a new DH key pair
     * @return Newly generated key pair
     * 
     * Private key is randomly generated in range [2, q-1] (or [2, p-2])
     * Public key is computed as g^x mod p
     */
    DHKeyPair generate_keypair() const;
    
    /**
     * @brief Create key pair from existing private key
     * @param private_key Private key value
     * @return Key pair with computed public key
     * @throws std::invalid_argument if private key is invalid
     */
    DHKeyPair keypair_from_private(const ZZ& private_key) const;
    
    /**
     * @brief Import public key from bytes
     * @param data Public key data
     * @param len Data length
     * @return Public key as ZZ
     * @throws std::invalid_argument if public key is invalid
     */
    ZZ import_public_key(const uint8_t* data, size_t len) const;
    
    /**
     * @brief Import private key from bytes and compute key pair
     * @param data Private key data
     * @param len Data length
     * @return Complete key pair
     */
    DHKeyPair import_private_key(const uint8_t* data, size_t len) const;
    
    // ========================================================================
    // Key Exchange
    // ========================================================================
    
    /**
     * @brief Compute shared secret
     * @param private_key Our private key
     * @param peer_public_key Peer's public key
     * @return Shared secret bytes
     * @throws std::invalid_argument if peer's public key is invalid
     * @throws std::runtime_error if computation results in weak secret
     */
    std::vector<uint8_t> compute_shared_secret(const ZZ& private_key,
                                               const ZZ& peer_public_key) const;
    
    /**
     * @brief Compute shared secret using key pair
     * @param keypair Our key pair
     * @param peer_public_key Peer's public key
     * @return Shared secret bytes
     */
    std::vector<uint8_t> compute_shared_secret(const DHKeyPair& keypair,
                                               const ZZ& peer_public_key) const;
    
    /**
     * @brief Compute shared secret from raw bytes
     * @param private_key Our private key bytes
     * @param priv_len Private key length
     * @param peer_public Peer's public key bytes
     * @param pub_len Public key length
     * @return Shared secret bytes
     */
    std::vector<uint8_t> compute_shared_secret(const uint8_t* private_key, size_t priv_len,
                                               const uint8_t* peer_public, size_t pub_len) const;
    
    // ========================================================================
    // Validation
    // ========================================================================
    
    /**
     * @brief Validate a public key
     * @param public_key Public key to validate
     * @return true if public key is valid
     * 
     * Checks:
     * - Key is in range [2, p-2]
     * - Key is in correct subgroup (for safe primes)
     */
    bool validate_public_key(const ZZ& public_key) const;

private:
    DHParams params_;   ///< DH parameters
};

// ============================================================================
// High-Level API Functions
// ============================================================================

/**
 * @brief Generate DH key pair
 * @param group_type DH group type
 * @return Generated key pair
 */
DHKeyPair dh_generate_keypair(DHGroupType group_type = DHGroupType::MODP_2048);

/**
 * @brief Compute DH shared secret
 * @param group_type DH group type
 * @param private_key Our private key
 * @param priv_len Private key length
 * @param peer_public_key Peer's public key
 * @param pub_len Public key length
 * @return Shared secret bytes
 */
std::vector<uint8_t> dh_shared_secret(DHGroupType group_type,
                                      const uint8_t* private_key, size_t priv_len,
                                      const uint8_t* peer_public_key, size_t pub_len);

} // namespace dh
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_DH_H
