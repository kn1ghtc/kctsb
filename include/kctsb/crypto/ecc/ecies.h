/**
 * @file ecies.h
 * @brief ECIES (Elliptic Curve Integrated Encryption Scheme) Header
 * 
 * Complete ECIES implementation following SEC 1 v2.0 and IEEE 1363a.
 * Features:
 * - Hybrid encryption (ECDH + symmetric cipher)
 * - Authenticated encryption (AES-GCM)
 * - Flexible KDF and MAC options
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_ECIES_H
#define KCTSB_CRYPTO_ECIES_H

#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/crypto/ecc/ecdh.h"
#include <vector>
#include <cstdint>
#include <string>
#include <memory>

namespace kctsb {
namespace ecc {
namespace internal {

/**
 * @brief ECIES Configuration Parameters
 */
struct ECIESConfig {
    size_t enc_key_len = 32;         // Symmetric key length (bytes)
    size_t mac_key_len = 32;         // MAC key length (bytes)
    size_t nonce_len = 12;           // Nonce/IV length (bytes)
    size_t tag_len = 16;             // Authentication tag length (bytes)
    bool compress_public_key = false; // Use compressed public key format
    std::string cipher = "AES-256-GCM";
    std::string kdf = "HKDF-SHA256";
    std::string mac = "HMAC-SHA256";
};

/**
 * @brief ECIES Ciphertext structure
 */
struct ECIESCiphertext {
    std::vector<uint8_t> ephemeral_public_key;  // R = r*G
    std::vector<uint8_t> ciphertext;            // Encrypted message
    std::vector<uint8_t> tag;                   // Authentication tag
    std::vector<uint8_t> nonce;                 // Nonce/IV (if not using GCM)
    
    /**
     * @brief Serialize to bytes
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * @brief Deserialize from bytes
     */
    static ECIESCiphertext deserialize(const uint8_t* data, size_t len, 
                                       size_t pub_key_len, size_t tag_len);
};

/**
 * @brief ECIES Implementation Class
 */
class ECIES {
public:
    /**
     * @brief Construct ECIES with curve and default config
     */
    explicit ECIES(const ECCurve& curve);
    
    /**
     * @brief Construct ECIES with curve type and default config
     */
    explicit ECIES(CurveType curve_type);
    
    /**
     * @brief Construct ECIES with curve and custom config
     */
    ECIES(const ECCurve& curve, const ECIESConfig& config);
    
    /**
     * @brief Construct ECIES with curve type and custom config
     */
    ECIES(CurveType curve_type, const ECIESConfig& config);
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate ECIES key pair
     */
    ECDHKeyPair generate_keypair() const;
    
    /**
     * @brief Import public key from bytes
     */
    JacobianPoint import_public_key(const uint8_t* data, size_t len) const;
    
    /**
     * @brief Import private key from bytes
     */
    ECDHKeyPair import_private_key(const uint8_t* data, size_t len) const;
    
    // ========================================================================
    // Encryption
    // ========================================================================
    
    /**
     * @brief Encrypt a message
     * 
     * ECIES encryption:
     * 1. Generate ephemeral key pair (r, R = r*G)
     * 2. Compute shared secret: S = r * Q_recipient
     * 3. Derive keys: (enc_key, mac_key) = KDF(S)
     * 4. Encrypt: ciphertext = AES-GCM(enc_key, plaintext)
     * 
     * @param plaintext Message to encrypt
     * @param plaintext_len Length of plaintext
     * @param recipient_public_key Recipient's public key
     * @param shared_info Optional shared info for KDF
     * @return ECIES ciphertext structure
     */
    ECIESCiphertext encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const JacobianPoint& recipient_public_key,
        const std::vector<uint8_t>& shared_info = {}) const;
    
    /**
     * @brief Encrypt with public key bytes
     */
    ECIESCiphertext encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* recipient_public_key, size_t pub_len,
        const std::vector<uint8_t>& shared_info = {}) const;
    
    /**
     * @brief Encrypt and serialize to single byte array
     */
    std::vector<uint8_t> encrypt_to_bytes(
        const uint8_t* plaintext, size_t plaintext_len,
        const JacobianPoint& recipient_public_key,
        const std::vector<uint8_t>& shared_info = {}) const;
    
    // ========================================================================
    // Decryption
    // ========================================================================
    
    /**
     * @brief Decrypt ECIES ciphertext
     * 
     * ECIES decryption:
     * 1. Compute shared secret: S = d * R (ephemeral public key)
     * 2. Derive keys: (enc_key, mac_key) = KDF(S)
     * 3. Decrypt and verify: plaintext = AES-GCM-Dec(enc_key, ciphertext, tag)
     * 
     * @param ciphertext ECIES ciphertext structure
     * @param private_key Recipient's private key
     * @param shared_info Optional shared info for KDF (must match encryption)
     * @return Decrypted plaintext
     */
    std::vector<uint8_t> decrypt(
        const ECIESCiphertext& ciphertext,
        const ZZ& private_key,
        const std::vector<uint8_t>& shared_info = {}) const;
    
    /**
     * @brief Decrypt with key pair
     */
    std::vector<uint8_t> decrypt(
        const ECIESCiphertext& ciphertext,
        const ECDHKeyPair& keypair,
        const std::vector<uint8_t>& shared_info = {}) const;
    
    /**
     * @brief Decrypt from serialized bytes
     */
    std::vector<uint8_t> decrypt_from_bytes(
        const uint8_t* data, size_t len,
        const ZZ& private_key,
        const std::vector<uint8_t>& shared_info = {}) const;
    
    // ========================================================================
    // Utilities
    // ========================================================================
    
    /**
     * @brief Get the underlying curve
     */
    const ECCurve& get_curve() const { return curve_; }
    
    /**
     * @brief Get the configuration
     */
    const ECIESConfig& get_config() const { return config_; }
    
    /**
     * @brief Get overhead size (ephemeral key + tag)
     */
    size_t get_overhead_size() const;
    
    /**
     * @brief Get maximum plaintext size for given ciphertext size
     */
    size_t get_max_plaintext_size(size_t ciphertext_size) const;
    
private:
    ECCurve curve_;
    ECIESConfig config_;
    ECDH ecdh_;
    
    /**
     * @brief Derive encryption and MAC keys from shared secret
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_keys(
        const std::vector<uint8_t>& shared_secret,
        const std::vector<uint8_t>& shared_info) const;
    
    /**
     * @brief AES-GCM encryption
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> aes_gcm_encrypt(
        const uint8_t* plaintext, size_t plaintext_len,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& aad) const;
    
    /**
     * @brief AES-GCM decryption
     */
    std::vector<uint8_t> aes_gcm_decrypt(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& aad) const;
    
    /**
     * @brief Generate random nonce
     */
    std::vector<uint8_t> generate_nonce() const;
};

// ============================================================================
// High-Level API Functions
// ============================================================================

/**
 * @brief Encrypt data using ECIES
 */
std::vector<uint8_t> ecies_encrypt(
    CurveType curve_type,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* recipient_public_key, size_t pub_len);

/**
 * @brief Decrypt ECIES ciphertext
 */
std::vector<uint8_t> ecies_decrypt(
    CurveType curve_type,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* private_key, size_t key_len);

} // namespace internal
} // namespace ecc
} // namespace kctsb

#endif // KCTSB_CRYPTO_ECIES_H
