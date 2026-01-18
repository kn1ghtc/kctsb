/**
 * @file rsa.h
 * @brief RSA Cryptosystem Header - NTL Implementation
 * 
 * Complete RSA implementation following:
 * - PKCS#1 v2.2 (RSA Cryptography Specifications)
 * - RFC 8017 (PKCS#1: RSA Cryptography Specifications)
 * 
 * Features:
 * - Key sizes: 2048, 3072, 4096 bits
 * - OAEP padding for encryption (RSAES-OAEP)
 * - PSS padding for signatures (RSASSA-PSS)
 * - PKCS#1 v1.5 for compatibility
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_H
#define KCTSB_CRYPTO_RSA_H

#include <NTL/ZZ.h>
#include <vector>
#include <cstdint>
#include <string>
#include <memory>

namespace kctsb {
namespace rsa {

using kctsb::ZZ;

/**
 * @brief RSA Key Size options
 */
enum class RSAKeySize : int {
    RSA_2048 = 2048,
    RSA_3072 = 3072,
    RSA_4096 = 4096
};

/**
 * @brief RSA Public Key
 */
struct RSAPublicKey {
    ZZ n;      // Modulus
    ZZ e;      // Public exponent
    int bits;  // Key size in bits
    
    RSAPublicKey() : bits(0) {}
    RSAPublicKey(const ZZ& n_, const ZZ& e_, int bits_) : n(n_), e(e_), bits(bits_) {}
    
    /**
     * @brief Check if key is valid
     */
    bool is_valid() const;
    
    /**
     * @brief Export to DER format (SubjectPublicKeyInfo)
     */
    std::vector<uint8_t> to_der() const;
    
    /**
     * @brief Export to PEM format
     */
    std::string to_pem() const;
    
    /**
     * @brief Import from DER format
     */
    static RSAPublicKey from_der(const uint8_t* data, size_t len);
    
    /**
     * @brief Import from PEM format
     */
    static RSAPublicKey from_pem(const std::string& pem);
};

/**
 * @brief RSA Private Key (CRT representation)
 */
struct RSAPrivateKey {
    ZZ n;      // Modulus
    ZZ e;      // Public exponent
    ZZ d;      // Private exponent
    ZZ p;      // First prime factor
    ZZ q;      // Second prime factor
    ZZ dp;     // d mod (p-1)
    ZZ dq;     // d mod (q-1)
    ZZ qinv;   // q^(-1) mod p
    int bits;  // Key size in bits
    
    RSAPrivateKey() : bits(0) {}
    
    /**
     * @brief Check if key is valid
     */
    bool is_valid() const;
    
    /**
     * @brief Get public key from private key
     */
    RSAPublicKey get_public_key() const;
    
    /**
     * @brief Export to DER format (PKCS#1 RSAPrivateKey)
     */
    std::vector<uint8_t> to_der() const;
    
    /**
     * @brief Export to PEM format
     */
    std::string to_pem() const;
    
    /**
     * @brief Import from DER format
     */
    static RSAPrivateKey from_der(const uint8_t* data, size_t len);
    
    /**
     * @brief Clear sensitive data
     */
    void clear();
};

/**
 * @brief RSA Key Pair
 */
struct RSAKeyPair {
    RSAPublicKey public_key;
    RSAPrivateKey private_key;
};

/**
 * @brief OAEP Parameters
 */
struct OAEPParams {
    std::string hash_algorithm = "SHA-256";  // Hash for OAEP
    std::string mgf_algorithm = "MGF1";      // Mask generation function
    std::vector<uint8_t> label;              // Optional label (default empty)
};

/**
 * @brief PSS Parameters
 */
struct PSSParams {
    std::string hash_algorithm = "SHA-256";  // Hash for PSS
    std::string mgf_algorithm = "MGF1";      // Mask generation function
    size_t salt_length = 32;                 // Salt length (default = hash length)
};

/**
 * @brief RSA Implementation Class
 */
class RSA {
public:
    /**
     * @brief Construct RSA with default 2048-bit key size
     */
    RSA();
    
    /**
     * @brief Construct RSA with specified key size
     */
    explicit RSA(RSAKeySize key_size);
    
    /**
     * @brief Construct RSA with existing key pair
     */
    explicit RSA(const RSAKeyPair& keypair);
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate new RSA key pair
     * @param key_size Key size (2048, 3072, or 4096 bits)
     * @param e Public exponent (default 65537)
     * @return Generated key pair
     */
    static RSAKeyPair generate_keypair(RSAKeySize key_size = RSAKeySize::RSA_2048,
                                       const ZZ& e = ZZ(65537));
    
    /**
     * @brief Generate key pair with custom bit size
     */
    static RSAKeyPair generate_keypair(int bits, const ZZ& e = ZZ(65537));
    
    // ========================================================================
    // RSAES-OAEP Encryption
    // ========================================================================
    
    /**
     * @brief Encrypt using RSAES-OAEP
     * 
     * @param plaintext Message to encrypt
     * @param plaintext_len Length of message
     * @param public_key Recipient's public key
     * @param params OAEP parameters (optional)
     * @return Ciphertext
     */
    static std::vector<uint8_t> encrypt_oaep(
        const uint8_t* plaintext, size_t plaintext_len,
        const RSAPublicKey& public_key,
        const OAEPParams& params = OAEPParams());
    
    /**
     * @brief Decrypt using RSAES-OAEP
     */
    static std::vector<uint8_t> decrypt_oaep(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const RSAPrivateKey& private_key,
        const OAEPParams& params = OAEPParams());
    
    // ========================================================================
    // RSAES-PKCS1-v1_5 Encryption (for compatibility)
    // ========================================================================
    
    /**
     * @brief Encrypt using RSAES-PKCS1-v1_5
     * @warning Use OAEP for new applications
     */
    static std::vector<uint8_t> encrypt_pkcs1(
        const uint8_t* plaintext, size_t plaintext_len,
        const RSAPublicKey& public_key);
    
    /**
     * @brief Decrypt using RSAES-PKCS1-v1_5
     */
    static std::vector<uint8_t> decrypt_pkcs1(
        const uint8_t* ciphertext, size_t ciphertext_len,
        const RSAPrivateKey& private_key);
    
    // ========================================================================
    // RSASSA-PSS Signatures
    // ========================================================================
    
    /**
     * @brief Sign using RSASSA-PSS
     * 
     * @param message_hash Hash of the message
     * @param hash_len Length of hash
     * @param private_key Signer's private key
     * @param params PSS parameters (optional)
     * @return Signature
     */
    static std::vector<uint8_t> sign_pss(
        const uint8_t* message_hash, size_t hash_len,
        const RSAPrivateKey& private_key,
        const PSSParams& params = PSSParams());
    
    /**
     * @brief Verify RSASSA-PSS signature
     */
    static bool verify_pss(
        const uint8_t* message_hash, size_t hash_len,
        const uint8_t* signature, size_t sig_len,
        const RSAPublicKey& public_key,
        const PSSParams& params = PSSParams());
    
    // ========================================================================
    // RSASSA-PKCS1-v1_5 Signatures (for compatibility)
    // ========================================================================
    
    /**
     * @brief Sign using RSASSA-PKCS1-v1_5
     */
    static std::vector<uint8_t> sign_pkcs1(
        const uint8_t* message_hash, size_t hash_len,
        const RSAPrivateKey& private_key,
        const std::string& hash_algorithm = "SHA-256");
    
    /**
     * @brief Verify RSASSA-PKCS1-v1_5 signature
     */
    static bool verify_pkcs1(
        const uint8_t* message_hash, size_t hash_len,
        const uint8_t* signature, size_t sig_len,
        const RSAPublicKey& public_key,
        const std::string& hash_algorithm = "SHA-256");
    
    // ========================================================================
    // Raw RSA Operations
    // ========================================================================
    
    /**
     * @brief Raw RSA encryption (RSAEP)
     * @param m Message integer (0 <= m < n)
     * @param public_key Public key
     * @return Ciphertext integer
     */
    static ZZ rsaep(const ZZ& m, const RSAPublicKey& public_key);
    
    /**
     * @brief Raw RSA decryption (RSADP)
     * @param c Ciphertext integer
     * @param private_key Private key
     * @return Message integer
     */
    static ZZ rsadp(const ZZ& c, const RSAPrivateKey& private_key);
    
    /**
     * @brief Raw RSA signature (RSASP1)
     */
    static ZZ rsasp1(const ZZ& m, const RSAPrivateKey& private_key);
    
    /**
     * @brief Raw RSA verification (RSAVP1)
     */
    static ZZ rsavp1(const ZZ& s, const RSAPublicKey& public_key);
    
private:
    RSAKeySize key_size_;
    RSAKeyPair keypair_;
    
    /**
     * @brief MGF1 mask generation function
     */
    static std::vector<uint8_t> mgf1(const uint8_t* seed, size_t seed_len,
                                     size_t mask_len,
                                     const std::string& hash_algorithm);
    
    /**
     * @brief EME-OAEP encoding
     */
    static std::vector<uint8_t> eme_oaep_encode(
        const uint8_t* message, size_t message_len,
        size_t k, const OAEPParams& params);
    
    /**
     * @brief EME-OAEP decoding
     */
    static std::vector<uint8_t> eme_oaep_decode(
        const uint8_t* encoded, size_t encoded_len,
        const OAEPParams& params);
    
    /**
     * @brief EMSA-PSS encoding
     */
    static std::vector<uint8_t> emsa_pss_encode(
        const uint8_t* message_hash, size_t hash_len,
        size_t em_bits, const PSSParams& params);
    
    /**
     * @brief EMSA-PSS verification
     */
    static bool emsa_pss_verify(
        const uint8_t* message_hash, size_t hash_len,
        const uint8_t* em, size_t em_len,
        size_t em_bits, const PSSParams& params);
    
    /**
     * @brief I2OSP (Integer to Octet String Primitive)
     */
    static std::vector<uint8_t> i2osp(const ZZ& x, size_t x_len);
    
    /**
     * @brief OS2IP (Octet String to Integer Primitive)
     */
    static ZZ os2ip(const uint8_t* x, size_t x_len);
    
    /**
     * @brief Generate random prime
     */
    static ZZ generate_prime(int bits);
    
    /**
     * @brief Compute CRT parameters
     */
    static void compute_crt_params(RSAPrivateKey& key);
    
    /**
     * @brief CRT-based private key operation
     */
    static ZZ rsadp_crt(const ZZ& c, const RSAPrivateKey& key);
};

// ============================================================================
// High-Level API Functions
// ============================================================================

/**
 * @brief Generate RSA key pair
 */
RSAKeyPair rsa_generate_keypair(int bits = 2048);

/**
 * @brief RSA-OAEP encrypt
 */
std::vector<uint8_t> rsa_encrypt(
    const uint8_t* plaintext, size_t plaintext_len,
    const RSAPublicKey& public_key);

/**
 * @brief RSA-OAEP decrypt
 */
std::vector<uint8_t> rsa_decrypt(
    const uint8_t* ciphertext, size_t ciphertext_len,
    const RSAPrivateKey& private_key);

/**
 * @brief RSA-PSS sign
 */
std::vector<uint8_t> rsa_sign(
    const uint8_t* message_hash, size_t hash_len,
    const RSAPrivateKey& private_key);

/**
 * @brief RSA-PSS verify
 */
bool rsa_verify(
    const uint8_t* message_hash, size_t hash_len,
    const uint8_t* signature, size_t sig_len,
    const RSAPublicKey& public_key);

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_H
