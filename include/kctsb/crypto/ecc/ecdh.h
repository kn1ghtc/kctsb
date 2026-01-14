/**
 * @file ecdh.h
 * @brief ECDH (Elliptic Curve Diffie-Hellman) Key Exchange Header
 * 
 * Complete ECDH implementation for secure key exchange.
 * Features:
 * - Static and ephemeral key exchange modes
 * - X-only key exchange (Curve25519-style)
 * - Key derivation function (KDF) integration
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_ECDH_H
#define KCTSB_CRYPTO_ECDH_H

#include "kctsb/crypto/ecc/ecc_curve.h"
#include <vector>
#include <cstdint>
#include <string>
#include <memory>

namespace kctsb {
namespace ecc {

/**
 * @brief ECDH Key Pair
 */
struct ECDHKeyPair {
    ZZ private_key;           // Private scalar d
    JacobianPoint public_key; // Public point Q = d*G
    
    ECDHKeyPair() = default;
    ECDHKeyPair(const ZZ& d, const JacobianPoint& Q) 
        : private_key(d), public_key(Q) {}
    
    /**
     * @brief Export public key to bytes
     */
    std::vector<uint8_t> export_public_key(const ECCurve& curve) const;
    
    /**
     * @brief Export private key to bytes
     */
    std::vector<uint8_t> export_private_key(size_t field_size) const;
    
    /**
     * @brief Clear sensitive data
     */
    void clear();
};

/**
 * @brief ECDH Implementation Class
 */
class ECDH {
public:
    /**
     * @brief Construct ECDH with specified curve
     */
    explicit ECDH(const ECCurve& curve);
    
    /**
     * @brief Construct ECDH with curve type
     */
    explicit ECDH(CurveType curve_type);
    
    /**
     * @brief Construct ECDH with curve name
     */
    explicit ECDH(const std::string& curve_name);
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate new ECDH key pair
     * @return Generated key pair
     */
    ECDHKeyPair generate_keypair() const;
    
    /**
     * @brief Derive key pair from private key
     * @param private_key Private scalar d
     * @return Key pair with computed public key
     */
    ECDHKeyPair keypair_from_private(const ZZ& private_key) const;
    
    /**
     * @brief Import public key from bytes
     * @param data Public key bytes
     * @param len Length of data
     * @return Public key point
     */
    JacobianPoint import_public_key(const uint8_t* data, size_t len) const;
    
    /**
     * @brief Import private key from bytes
     * @param data Private key bytes
     * @param len Length of data
     * @return Complete key pair
     */
    ECDHKeyPair import_private_key(const uint8_t* data, size_t len) const;
    
    // ========================================================================
    // Key Exchange
    // ========================================================================
    
    /**
     * @brief Compute shared secret
     * 
     * Computes the ECDH shared point: S = d_A * Q_B
     * Returns the x-coordinate of the shared point as the raw shared secret.
     * 
     * @param private_key Our private key (d_A)
     * @param peer_public_key Peer's public key (Q_B)
     * @return Raw shared secret (x-coordinate)
     */
    std::vector<uint8_t> compute_shared_secret(
        const ZZ& private_key,
        const JacobianPoint& peer_public_key) const;
    
    /**
     * @brief Compute shared secret from key pair
     * @param our_keypair Our key pair
     * @param peer_public_key Peer's public key
     * @return Raw shared secret
     */
    std::vector<uint8_t> compute_shared_secret(
        const ECDHKeyPair& our_keypair,
        const JacobianPoint& peer_public_key) const;
    
    /**
     * @brief Compute shared secret from bytes
     * @param private_key_bytes Our private key bytes
     * @param private_key_len Private key length
     * @param peer_public_bytes Peer's public key bytes
     * @param peer_public_len Public key length
     * @return Raw shared secret
     */
    std::vector<uint8_t> compute_shared_secret(
        const uint8_t* private_key_bytes, size_t private_key_len,
        const uint8_t* peer_public_bytes, size_t peer_public_len) const;
    
    // ========================================================================
    // Key Derivation
    // ========================================================================
    
    /**
     * @brief Derive symmetric key from shared secret using HKDF
     * 
     * Uses HKDF-SHA256 for key derivation:
     * 1. Extract: PRK = HMAC-SHA256(salt, shared_secret)
     * 2. Expand: key_material = HKDF-Expand(PRK, info, length)
     * 
     * @param shared_secret Raw shared secret from compute_shared_secret()
     * @param salt Optional salt (can be empty)
     * @param info Optional context info (can be empty)
     * @param key_length Desired key length in bytes
     * @return Derived key material
     */
    std::vector<uint8_t> derive_key(
        const std::vector<uint8_t>& shared_secret,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info,
        size_t key_length) const;
    
    /**
     * @brief Derive key with default salt
     */
    std::vector<uint8_t> derive_key(
        const std::vector<uint8_t>& shared_secret,
        size_t key_length) const;
    
    // ========================================================================
    // One-Step Key Exchange
    // ========================================================================
    
    /**
     * @brief Complete ECDH key exchange and derivation in one step
     * 
     * @param private_key Our private key
     * @param peer_public_key Peer's public key
     * @param salt Optional salt for HKDF
     * @param info Optional info for HKDF
     * @param key_length Desired key length
     * @return Derived symmetric key
     */
    std::vector<uint8_t> exchange_and_derive(
        const ZZ& private_key,
        const JacobianPoint& peer_public_key,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info,
        size_t key_length) const;
    
    // ========================================================================
    // Utilities
    // ========================================================================
    
    /**
     * @brief Get the underlying curve
     */
    const ECCurve& get_curve() const { return curve_; }
    
    /**
     * @brief Get field size in bytes
     */
    size_t get_field_size() const;
    
    /**
     * @brief Get shared secret size in bytes
     */
    size_t get_shared_secret_size() const;
    
    /**
     * @brief Validate peer's public key
     * 
     * Checks:
     * 1. Point is on curve
     * 2. Point is not at infinity
     * 3. Point is in the correct subgroup
     * 
     * @param peer_public_key Public key to validate
     * @return true if valid for ECDH
     */
    bool validate_public_key(const JacobianPoint& peer_public_key) const;
    
private:
    ECCurve curve_;
    
    /**
     * @brief HKDF-Extract
     */
    std::vector<uint8_t> hkdf_extract(
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& ikm) const;
    
    /**
     * @brief HKDF-Expand
     */
    std::vector<uint8_t> hkdf_expand(
        const std::vector<uint8_t>& prk,
        const std::vector<uint8_t>& info,
        size_t length) const;
    
    /**
     * @brief HMAC-SHA256
     */
    std::vector<uint8_t> hmac_sha256(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data) const;
};

/**
 * @brief ECIES (Elliptic Curve Integrated Encryption Scheme) Parameters
 */
struct ECIESParams {
    size_t mac_key_length = 32;      // MAC key length
    size_t enc_key_length = 32;      // Encryption key length  
    bool use_point_compression = false;
    std::string kdf_algorithm = "HKDF-SHA256";
    std::string mac_algorithm = "HMAC-SHA256";
    std::string cipher_algorithm = "AES-256-GCM";
};

// ============================================================================
// High-Level API Functions
// ============================================================================

/**
 * @brief Generate ECDH key pair
 */
ECDHKeyPair ecdh_generate_keypair(CurveType curve_type);

/**
 * @brief Compute shared secret
 */
std::vector<uint8_t> ecdh_shared_secret(
    CurveType curve_type,
    const uint8_t* private_key, size_t private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_len);

/**
 * @brief Complete key agreement with key derivation
 */
std::vector<uint8_t> ecdh_key_agreement(
    CurveType curve_type,
    const uint8_t* private_key, size_t private_key_len,
    const uint8_t* peer_public_key, size_t peer_public_len,
    size_t derived_key_length);

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_CRYPTO_ECDH_H
