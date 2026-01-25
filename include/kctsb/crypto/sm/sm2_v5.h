/**
 * @file sm2_v5.h
 * @brief Self-Contained SM2 Cryptography v5.0
 * 
 * Complete SM2 implementation following GM/T 0003-2012 standard.
 * Implementation references GMssl project for standards compliance.
 * No external dependencies (NTL, GMP removed).
 * 
 * Features:
 * - SM2 Digital Signature (SM2DSA) with SM3 hash
 * - SM2 Key Exchange Protocol
 * - SM2 Public Key Encryption (SM2PKE)
 * - ZA hash calculation for user identity
 * 
 * Reference Implementation:
 * - GmSSL: https://github.com/guanzhi/GmSSL
 * - GM/T 0003.1-2012: SM2 Elliptic Curve Signature Algorithm
 * - GM/T 0003.2-2012: SM2 Key Exchange Protocol
 * - GM/T 0003.3-2012: SM2 Public Key Encryption
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_SM2_V5_H
#define KCTSB_CRYPTO_SM2_V5_H

#include "kctsb/core/fe256.h"
#include "kctsb/crypto/ecc/ecc_v5.h"
#include <array>
#include <vector>
#include <string>
#include <cstdint>

namespace kctsb {
namespace sm {

// ============================================================================
// SM2 Curve (from ECC v5)
// ============================================================================

/**
 * @brief Get SM2 curve reference
 */
inline const ecc::CurveParamsV5& sm2_curve() {
    return ecc::sm2_params();
}

// ============================================================================
// SM2 Key Pair
// ============================================================================

/**
 * @brief SM2 Private Key
 */
struct SM2PrivateKeyV5 {
    Fe256 d;    ///< Private key scalar (0 < d < n)
    
    /**
     * @brief Generate random private key
     */
    void generate();
    
    /**
     * @brief Import from bytes (32 bytes, big-endian)
     */
    void from_bytes(const uint8_t* data);
    
    /**
     * @brief Export to bytes
     */
    void to_bytes(uint8_t* data) const;
    
    /**
     * @brief Get corresponding public key
     */
    void get_public_key(ecc::AffinePointV5* pub) const;
    
    /**
     * @brief Clear sensitive key material
     */
    void clear() { d.zero(); }
};

/**
 * @brief SM2 Public Key
 */
struct SM2PublicKeyV5 {
    ecc::AffinePointV5 Q;   ///< Public key point (Q = d*G)
    
    /**
     * @brief Import from uncompressed format (04 || x || y, 65 bytes)
     */
    void from_bytes(const uint8_t* data);
    
    /**
     * @brief Export to uncompressed format
     */
    void to_bytes(uint8_t* data) const;
    
    /**
     * @brief Import from compressed format (02/03 || x, 33 bytes)
     */
    void from_compressed(const uint8_t* data);
    
    /**
     * @brief Export to compressed format
     */
    void to_compressed(uint8_t* data) const;
    
    /**
     * @brief Validate public key is on curve
     */
    bool is_valid() const;
};

// ============================================================================
// SM2 Digital Signature (SM2DSA)
// ============================================================================

/**
 * @brief SM2 Signature (r, s)
 */
struct SM2SignatureV5 {
    Fe256 r;
    Fe256 s;
    
    /**
     * @brief Serialize to DER format
     */
    std::vector<uint8_t> to_der() const;
    
    /**
     * @brief Parse from DER format
     */
    static SM2SignatureV5 from_der(const uint8_t* data, size_t len);
    
    /**
     * @brief Serialize to raw format (r || s, 64 bytes)
     */
    std::array<uint8_t, 64> to_raw() const;
    
    /**
     * @brief Parse from raw format
     */
    static SM2SignatureV5 from_raw(const uint8_t* data);
};

/**
 * @brief Compute ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
 * 
 * @param user_id User identity string (default: "1234567812345678")
 * @param pub_key User's public key
 * @param za Output: 32-byte ZA hash
 */
void sm2_compute_za(const uint8_t* user_id, size_t user_id_len,
                    const SM2PublicKeyV5& pub_key,
                    uint8_t za[32]);

/**
 * @brief Compute ZA with default ID
 */
void sm2_compute_za_default(const SM2PublicKeyV5& pub_key, uint8_t za[32]);

/**
 * @brief SM2 Digital Signature Algorithm
 * 
 * Usage:
 *   1. Compute ZA for signer
 *   2. Compute e = SM3(ZA || M)
 *   3. Sign e with private key
 *   4. Verify signature with public key
 */
class SM2SignerV5 {
public:
    SM2SignerV5();
    
    /**
     * @brief Sign message hash (e = SM3(ZA || M))
     * @param e 32-byte message hash
     * @param priv Private key
     * @param sig Output signature
     */
    void sign(const uint8_t e[32], const SM2PrivateKeyV5& priv,
              SM2SignatureV5* sig);
    
    /**
     * @brief Sign message directly (computes ZA and e internally)
     * @param msg Message to sign
     * @param msg_len Message length
     * @param priv Private key
     * @param user_id User ID for ZA computation
     * @param user_id_len User ID length
     * @param sig Output signature
     */
    void sign_message(const uint8_t* msg, size_t msg_len,
                      const SM2PrivateKeyV5& priv,
                      const uint8_t* user_id, size_t user_id_len,
                      SM2SignatureV5* sig);
    
    /**
     * @brief Verify signature
     * @param e 32-byte message hash
     * @param pub Public key
     * @param sig Signature to verify
     * @return true if signature is valid
     */
    bool verify(const uint8_t e[32], const SM2PublicKeyV5& pub,
                const SM2SignatureV5& sig);
    
    /**
     * @brief Verify message signature directly
     */
    bool verify_message(const uint8_t* msg, size_t msg_len,
                        const SM2PublicKeyV5& pub,
                        const uint8_t* user_id, size_t user_id_len,
                        const SM2SignatureV5& sig);

private:
    ecc::ECCurveV5 curve_;
};

// ============================================================================
// SM2 Key Exchange Protocol
// ============================================================================

/**
 * @brief SM2 Key Exchange Context
 * 
 * Implements GM/T 0003.2-2012 key exchange protocol.
 * Both parties exchange ephemeral keys and derive shared secret.
 */
class SM2KeyExchangeV5 {
public:
    /**
     * @brief Construct key exchange context
     * @param is_initiator true if this party initiates the exchange
     */
    explicit SM2KeyExchangeV5(bool is_initiator);
    
    /**
     * @brief Generate ephemeral key pair
     * @param ephemeral_pub Output: ephemeral public key (65 bytes)
     */
    void generate_ephemeral(uint8_t ephemeral_pub[65]);
    
    /**
     * @brief Compute shared key
     * @param my_priv My static private key
     * @param my_pub My static public key
     * @param my_id My user ID
     * @param my_id_len My user ID length
     * @param their_pub Their static public key
     * @param their_ephemeral Their ephemeral public key
     * @param their_id Their user ID
     * @param their_id_len Their user ID length
     * @param shared_key Output: derived shared key
     * @param key_len Desired key length (bytes)
     */
    void compute_key(const SM2PrivateKeyV5& my_priv,
                     const SM2PublicKeyV5& my_pub,
                     const uint8_t* my_id, size_t my_id_len,
                     const SM2PublicKeyV5& their_pub,
                     const uint8_t* their_ephemeral,
                     const uint8_t* their_id, size_t their_id_len,
                     uint8_t* shared_key, size_t key_len);
    
private:
    ecc::ECCurveV5 curve_;
    bool is_initiator_;
    Fe256 ephemeral_priv_;
    ecc::AffinePointV5 ephemeral_pub_;
};

// ============================================================================
// SM2 Public Key Encryption (SM2PKE)
// ============================================================================

/**
 * @brief SM2 Public Key Encryption
 * 
 * Implements GM/T 0003.3-2012 encryption scheme.
 * Output format: C1 || C3 || C2
 *   C1 = ephemeral public key (65 bytes, uncompressed)
 *   C3 = SM3 hash (32 bytes)
 *   C2 = encrypted message (same length as plaintext)
 */
class SM2EncryptorV5 {
public:
    SM2EncryptorV5();
    
    /**
     * @brief Encrypt message
     * @param plaintext Message to encrypt
     * @param plaintext_len Message length
     * @param pub Recipient's public key
     * @param ciphertext Output: ciphertext buffer
     * @param ciphertext_len Output: ciphertext length
     * @return true on success
     * 
     * @note ciphertext must have at least (97 + plaintext_len) bytes
     */
    bool encrypt(const uint8_t* plaintext, size_t plaintext_len,
                 const SM2PublicKeyV5& pub,
                 uint8_t* ciphertext, size_t* ciphertext_len);
    
    /**
     * @brief Decrypt message
     * @param ciphertext Ciphertext to decrypt
     * @param ciphertext_len Ciphertext length
     * @param priv Recipient's private key
     * @param plaintext Output: plaintext buffer
     * @param plaintext_len Output: plaintext length
     * @return true on success
     */
    bool decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                 const SM2PrivateKeyV5& priv,
                 uint8_t* plaintext, size_t* plaintext_len);

private:
    ecc::ECCurveV5 curve_;
    
    /**
     * @brief Key Derivation Function (KDF) per GM/T 0003
     */
    void kdf(const uint8_t* z, size_t z_len,
             uint8_t* key, size_t key_len);
};

// ============================================================================
// High-Level API
// ============================================================================

/**
 * @brief Generate SM2 key pair
 */
void sm2_keygen(uint8_t private_key[32], uint8_t public_key[65]);

/**
 * @brief SM2 sign message
 * @param msg Message to sign
 * @param msg_len Message length
 * @param private_key 32-byte private key
 * @param user_id User ID (use nullptr for default "1234567812345678")
 * @param user_id_len User ID length
 * @param signature Output: 64-byte signature (r || s)
 */
void sm2_sign(const uint8_t* msg, size_t msg_len,
              const uint8_t private_key[32],
              const uint8_t* user_id, size_t user_id_len,
              uint8_t signature[64]);

/**
 * @brief SM2 verify signature
 * @return true if signature is valid
 */
bool sm2_verify(const uint8_t* msg, size_t msg_len,
                const uint8_t public_key[65],
                const uint8_t* user_id, size_t user_id_len,
                const uint8_t signature[64]);

/**
 * @brief SM2 encrypt message
 * @return Ciphertext as vector (C1 || C3 || C2 format)
 */
std::vector<uint8_t> sm2_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                                  const uint8_t public_key[65]);

/**
 * @brief SM2 decrypt message
 * @return Plaintext as vector
 */
std::vector<uint8_t> sm2_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                                  const uint8_t private_key[32]);

} // namespace sm
} // namespace kctsb

#endif // KCTSB_CRYPTO_SM2_V5_H
