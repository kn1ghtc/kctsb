/**
 * @file ecdsa.h
 * @brief ECDSA (Elliptic Curve Digital Signature Algorithm) Header
 * 
 * Complete ECDSA implementation following FIPS 186-4 and RFC 6979.
 * Features:
 * - Deterministic signature generation (RFC 6979)
 * - Constant-time operations to prevent timing attacks
 * - Support for all standard curves
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_ECDSA_H
#define KCTSB_CRYPTO_ECDSA_H

#include "kctsb/crypto/ecc/ecc_curve.h"
#include <vector>
#include <cstdint>
#include <string>

namespace kctsb {
namespace ecc {

/**
 * @brief ECDSA Signature (r, s) pair
 */
struct ECDSASignature {
    ZZ r;
    ZZ s;
    
    ECDSASignature() = default;
    ECDSASignature(const ZZ& r_, const ZZ& s_) : r(r_), s(s_) {}
    
    /**
     * @brief Check if signature is valid format (0 < r, s < n)
     */
    bool is_valid(const ZZ& n) const;
    
    /**
     * @brief Serialize to DER format
     */
    std::vector<uint8_t> to_der() const;
    
    /**
     * @brief Parse from DER format
     */
    static ECDSASignature from_der(const uint8_t* data, size_t len);
    
    /**
     * @brief Serialize to fixed-size format (r || s)
     * @param out Output buffer (must be 2 * field_size bytes)
     * @param field_size Size of each coordinate in bytes
     */
    void to_fixed(uint8_t* out, size_t field_size) const;
    
    /**
     * @brief Parse from fixed-size format
     */
    static ECDSASignature from_fixed(const uint8_t* data, size_t field_size);
};

/**
 * @brief ECDSA Key Pair
 */
struct ECDSAKeyPair {
    ZZ private_key;       // d: private scalar
    JacobianPoint public_key;  // Q: public point (Q = d*G)
    
    ECDSAKeyPair() = default;
    ECDSAKeyPair(const ZZ& d, const JacobianPoint& Q) 
        : private_key(d), public_key(Q) {}
    
    /**
     * @brief Check if key pair is valid
     */
    bool is_valid(const ECCurve& curve) const;
    
    /**
     * @brief Export public key to bytes (uncompressed format)
     */
    std::vector<uint8_t> export_public_key(const ECCurve& curve) const;
    
    /**
     * @brief Export private key to bytes
     */
    std::vector<uint8_t> export_private_key(size_t field_size) const;
};

/**
 * @brief ECDSA Implementation Class
 */
class ECDSA {
public:
    /**
     * @brief Construct ECDSA with specified curve
     */
    explicit ECDSA(const ECCurve& curve);
    
    /**
     * @brief Construct ECDSA with curve type
     */
    explicit ECDSA(CurveType curve_type);
    
    /**
     * @brief Construct ECDSA with curve name
     */
    explicit ECDSA(const std::string& curve_name);
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate new ECDSA key pair
     * @return Generated key pair
     */
    ECDSAKeyPair generate_keypair() const;
    
    /**
     * @brief Derive public key from private key
     * @param private_key Private scalar d
     * @return Key pair with computed public key
     */
    ECDSAKeyPair keypair_from_private(const ZZ& private_key) const;
    
    /**
     * @brief Import public key from bytes
     * @param data Public key bytes (uncompressed format)
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
    ECDSAKeyPair import_private_key(const uint8_t* data, size_t len) const;
    
    // ========================================================================
    // Signing
    // ========================================================================
    
    /**
     * @brief Sign a message hash
     * 
     * Uses deterministic k generation per RFC 6979.
     * 
     * @param message_hash Hash of the message (e.g., SHA-256)
     * @param hash_len Length of hash
     * @param private_key Signer's private key
     * @return ECDSA signature (r, s)
     */
    ECDSASignature sign(const uint8_t* message_hash, size_t hash_len,
                       const ZZ& private_key) const;
    
    /**
     * @brief Sign a message hash (ZZ version)
     */
    ECDSASignature sign(const ZZ& e, const ZZ& private_key) const;
    
    /**
     * @brief Sign with explicit k value (for testing only)
     * @warning Do NOT use in production - k must be random/deterministic
     */
    ECDSASignature sign_with_k(const ZZ& e, const ZZ& private_key, const ZZ& k) const;
    
    // ========================================================================
    // Verification
    // ========================================================================
    
    /**
     * @brief Verify an ECDSA signature
     * 
     * @param message_hash Hash of the message
     * @param hash_len Length of hash
     * @param signature Signature to verify
     * @param public_key Signer's public key
     * @return true if signature is valid
     */
    bool verify(const uint8_t* message_hash, size_t hash_len,
               const ECDSASignature& signature,
               const JacobianPoint& public_key) const;
    
    /**
     * @brief Verify an ECDSA signature (ZZ version)
     */
    bool verify(const ZZ& e, const ECDSASignature& signature,
               const JacobianPoint& public_key) const;
    
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
     * @brief Get signature size in bytes (DER format max)
     */
    size_t get_signature_size_der() const;
    
    /**
     * @brief Get signature size in bytes (fixed format)
     */
    size_t get_signature_size_fixed() const;
    
private:
    ECCurve curve_;
    
    /**
     * @brief RFC 6979 deterministic k generation
     */
    ZZ generate_k_rfc6979(const ZZ& e, const ZZ& private_key) const;
    
    /**
     * @brief Generate random k value
     */
    ZZ generate_k_random() const;
    
    /**
     * @brief Convert hash bytes to integer
     */
    ZZ bits2int(const uint8_t* data, size_t len) const;
    
    /**
     * @brief HMAC-DRBG for RFC 6979
     */
    void hmac_drbg(const uint8_t* entropy, size_t entropy_len,
                   const uint8_t* nonce, size_t nonce_len,
                   uint8_t* output, size_t output_len) const;
};

/**
 * @brief High-level signing function
 */
std::vector<uint8_t> ecdsa_sign(const ECCurve& curve,
                                const uint8_t* message_hash, size_t hash_len,
                                const uint8_t* private_key, size_t key_len);

/**
 * @brief High-level verification function
 */
bool ecdsa_verify(const ECCurve& curve,
                  const uint8_t* message_hash, size_t hash_len,
                  const uint8_t* signature, size_t sig_len,
                  const uint8_t* public_key, size_t pub_len);

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_CRYPTO_ECDSA_H
