/**
 * @file rsa_v5.h
 * @brief RSA Cryptosystem Header - Self-Contained v5.0 Implementation
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
 * - Self-contained: NO external dependencies (NTL, GMP removed)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_V5_H
#define KCTSB_CRYPTO_RSA_V5_H

#include "kctsb/core/bigint.h"
#include "kctsb/crypto/sha256.h"
#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <array>

namespace kctsb {
namespace rsa {

// ============================================================================
// RSA Key Types
// ============================================================================

/**
 * @brief RSA Key Size options
 */
enum class RSAKeySize : int {
    RSA_2048 = 2048,
    RSA_3072 = 3072,
    RSA_4096 = 4096
};

/**
 * @brief RSA Public Key (v5.0 self-contained)
 * @tparam BITS Key size in bits (2048, 3072, or 4096)
 */
template<size_t BITS = 2048>
struct RSAPublicKeyV5 {
    static_assert(BITS == 2048 || BITS == 3072 || BITS == 4096,
                  "RSA key size must be 2048, 3072, or 4096 bits");
    
    BigInt<BITS> n;      ///< Modulus
    BigInt<BITS> e;      ///< Public exponent (typically 65537)
    
    /**
     * @brief Default constructor - creates invalid key
     */
    RSAPublicKeyV5() = default;
    
    /**
     * @brief Construct from modulus and exponent
     */
    RSAPublicKeyV5(const BigInt<BITS>& n_, const BigInt<BITS>& e_)
        : n(n_), e(e_) {}
    
    /**
     * @brief Check if key is valid
     * @return true if key parameters are valid
     */
    bool is_valid() const {
        if (n.is_zero() || !n.is_odd()) return false;
        if (e < BigInt<BITS>(3) || e >= n || !e.is_odd()) return false;
        return true;
    }
    
    /**
     * @brief Get key size in bits
     */
    constexpr size_t key_bits() const { return BITS; }
    
    /**
     * @brief Get key size in bytes
     */
    constexpr size_t key_bytes() const { return BITS / 8; }
    
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
    static RSAPublicKeyV5 from_der(const uint8_t* data, size_t len);
};

/**
 * @brief RSA Private Key with CRT representation (v5.0 self-contained)
 * @tparam BITS Key size in bits (2048, 3072, or 4096)
 */
template<size_t BITS = 2048>
struct RSAPrivateKeyV5 {
    static_assert(BITS == 2048 || BITS == 3072 || BITS == 4096,
                  "RSA key size must be 2048, 3072, or 4096 bits");
    
    // Half-size for prime factors
    static constexpr size_t HALF_BITS = BITS / 2;
    
    BigInt<BITS> n;            ///< Modulus (n = p * q)
    BigInt<BITS> e;            ///< Public exponent
    BigInt<BITS> d;            ///< Private exponent
    BigInt<HALF_BITS + 64> p;  ///< First prime factor (with margin)
    BigInt<HALF_BITS + 64> q;  ///< Second prime factor (with margin)
    BigInt<HALF_BITS + 64> dp; ///< d mod (p-1) for CRT
    BigInt<HALF_BITS + 64> dq; ///< d mod (q-1) for CRT
    BigInt<HALF_BITS + 64> qinv; ///< q^(-1) mod p for CRT
    
    /**
     * @brief Default constructor
     */
    RSAPrivateKeyV5() = default;
    
    /**
     * @brief Check if key is valid
     */
    bool is_valid() const {
        if (n.is_zero() || !n.is_odd()) return false;
        if (d.is_zero() || d >= n) return false;
        // Additional checks could verify n = p * q, etc.
        return true;
    }
    
    /**
     * @brief Get public key from private key
     */
    RSAPublicKeyV5<BITS> get_public_key() const {
        return RSAPublicKeyV5<BITS>(n, e);
    }
    
    /**
     * @brief Securely clear all sensitive data
     */
    void clear() {
        n.secure_zero();
        e.secure_zero();
        d.secure_zero();
        p.secure_zero();
        q.secure_zero();
        dp.secure_zero();
        dq.secure_zero();
        qinv.secure_zero();
    }
    
    /**
     * @brief Destructor - securely clears sensitive data
     */
    ~RSAPrivateKeyV5() {
        clear();
    }
    
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
    static RSAPrivateKeyV5 from_der(const uint8_t* data, size_t len);
};

/**
 * @brief RSA Key Pair
 */
template<size_t BITS = 2048>
struct RSAKeyPairV5 {
    RSAPublicKeyV5<BITS> public_key;
    RSAPrivateKeyV5<BITS> private_key;
};

// ============================================================================
// Padding Parameters
// ============================================================================

/**
 * @brief OAEP Parameters for RSAES-OAEP
 */
struct OAEPParamsV5 {
    enum class HashAlgorithm {
        SHA256,
        SHA384,
        SHA512
    };
    
    HashAlgorithm hash = HashAlgorithm::SHA256;
    std::vector<uint8_t> label;  ///< Optional label (default empty)
    
    /**
     * @brief Get hash output length in bytes
     */
    size_t hash_length() const {
        switch (hash) {
            case HashAlgorithm::SHA256: return 32;
            case HashAlgorithm::SHA384: return 48;
            case HashAlgorithm::SHA512: return 64;
            default: return 32;
        }
    }
};

/**
 * @brief PSS Parameters for RSASSA-PSS
 */
struct PSSParamsV5 {
    enum class HashAlgorithm {
        SHA256,
        SHA384,
        SHA512
    };
    
    HashAlgorithm hash = HashAlgorithm::SHA256;
    size_t salt_length = 32;  ///< Salt length (default = hash length)
    
    /**
     * @brief Get hash output length in bytes
     */
    size_t hash_length() const {
        switch (hash) {
            case HashAlgorithm::SHA256: return 32;
            case HashAlgorithm::SHA384: return 48;
            case HashAlgorithm::SHA512: return 64;
            default: return 32;
        }
    }
};

// ============================================================================
// RSA Core Operations Class
// ============================================================================

/**
 * @brief RSA Implementation Class (v5.0 Self-Contained)
 * @tparam BITS Key size in bits
 */
template<size_t BITS = 2048>
class RSAV5 {
public:
    using PublicKey = RSAPublicKeyV5<BITS>;
    using PrivateKey = RSAPrivateKeyV5<BITS>;
    using KeyPair = RSAKeyPairV5<BITS>;
    using Int = BigInt<BITS>;
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate new RSA key pair
     * @param e Public exponent (default 65537)
     * @return Generated key pair
     */
    static KeyPair generate_keypair(uint64_t e = 65537);
    
    // ========================================================================
    // Core RSA Primitives
    // ========================================================================
    
    /**
     * @brief RSA Encryption Primitive (RSAEP)
     * @param m Message representative (0 <= m < n)
     * @param k Public key
     * @return Ciphertext representative c = m^e mod n
     */
    static Int rsaep(const Int& m, const PublicKey& k);
    
    /**
     * @brief RSA Decryption Primitive (RSADP)
     * @param c Ciphertext representative (0 <= c < n)
     * @param k Private key
     * @return Message representative m = c^d mod n
     */
    static Int rsadp(const Int& c, const PrivateKey& k);
    
    /**
     * @brief RSA Decryption Primitive with CRT (4x faster)
     */
    static Int rsadp_crt(const Int& c, const PrivateKey& k);
    
    /**
     * @brief RSA Signature Primitive (RSASP1)
     */
    static Int rsasp1(const Int& m, const PrivateKey& k) { return rsadp(m, k); }
    
    /**
     * @brief RSA Verification Primitive (RSAVP1)
     */
    static Int rsavp1(const Int& s, const PublicKey& k) { return rsaep(s, k); }
    
    // ========================================================================
    // Byte Conversion (I2OSP / OS2IP)
    // ========================================================================
    
    /**
     * @brief Integer to Octet String Primitive
     * @param x Non-negative integer
     * @param len Intended length of output
     * @return Octet string of length len
     */
    static std::vector<uint8_t> i2osp(const Int& x, size_t len);
    
    /**
     * @brief Octet String to Integer Primitive
     * @param x Octet string
     * @param len Length of octet string
     * @return Non-negative integer
     */
    static Int os2ip(const uint8_t* x, size_t len);
    
    // ========================================================================
    // RSAES-OAEP Encryption
    // ========================================================================
    
    /**
     * @brief Encrypt using RSAES-OAEP
     * @param plaintext Message to encrypt
     * @param len Length of message
     * @param k Public key
     * @param params OAEP parameters
     * @return Ciphertext
     */
    static std::vector<uint8_t> encrypt_oaep(
        const uint8_t* plaintext, size_t len,
        const PublicKey& k,
        const OAEPParamsV5& params = OAEPParamsV5());
    
    /**
     * @brief Decrypt using RSAES-OAEP
     * @param ciphertext Ciphertext to decrypt
     * @param len Length of ciphertext
     * @param k Private key
     * @param params OAEP parameters
     * @return Decrypted message
     */
    static std::vector<uint8_t> decrypt_oaep(
        const uint8_t* ciphertext, size_t len,
        const PrivateKey& k,
        const OAEPParamsV5& params = OAEPParamsV5());
    
    // ========================================================================
    // RSAES-PKCS1-v1_5 (Legacy)
    // ========================================================================
    
    /**
     * @brief Encrypt using RSAES-PKCS1-v1_5
     */
    static std::vector<uint8_t> encrypt_pkcs1(
        const uint8_t* plaintext, size_t len,
        const PublicKey& k);
    
    /**
     * @brief Decrypt using RSAES-PKCS1-v1_5
     */
    static std::vector<uint8_t> decrypt_pkcs1(
        const uint8_t* ciphertext, size_t len,
        const PrivateKey& k);
    
    // ========================================================================
    // RSASSA-PSS Signatures
    // ========================================================================
    
    /**
     * @brief Sign message hash using RSASSA-PSS
     * @param mHash Message hash
     * @param hlen Hash length
     * @param k Private key
     * @param params PSS parameters
     * @return Signature
     */
    static std::vector<uint8_t> sign_pss(
        const uint8_t* mHash, size_t hlen,
        const PrivateKey& k,
        const PSSParamsV5& params = PSSParamsV5());
    
    /**
     * @brief Verify signature using RSASSA-PSS
     * @param mHash Message hash
     * @param hlen Hash length
     * @param sig Signature
     * @param sigLen Signature length
     * @param k Public key
     * @param params PSS parameters
     * @return true if signature is valid
     */
    static bool verify_pss(
        const uint8_t* mHash, size_t hlen,
        const uint8_t* sig, size_t sigLen,
        const PublicKey& k,
        const PSSParamsV5& params = PSSParamsV5());
    
    // ========================================================================
    // RSASSA-PKCS1-v1_5 (Legacy)
    // ========================================================================
    
    /**
     * @brief Sign using RSASSA-PKCS1-v1_5
     */
    static std::vector<uint8_t> sign_pkcs1(
        const uint8_t* mHash, size_t hlen,
        const PrivateKey& k);
    
    /**
     * @brief Verify using RSASSA-PKCS1-v1_5
     */
    static bool verify_pkcs1(
        const uint8_t* mHash, size_t hlen,
        const uint8_t* sig, size_t sigLen,
        const PublicKey& k);
    
private:
    // ========================================================================
    // Internal Functions
    // ========================================================================
    
    /**
     * @brief MGF1 Mask Generation Function
     */
    static std::vector<uint8_t> mgf1(
        const uint8_t* seed, size_t seedLen,
        size_t maskLen,
        OAEPParamsV5::HashAlgorithm hash);
    
    /**
     * @brief EME-OAEP Encoding
     */
    static std::vector<uint8_t> eme_oaep_encode(
        const uint8_t* msg, size_t msgLen,
        size_t k,
        const OAEPParamsV5& params);
    
    /**
     * @brief EME-OAEP Decoding
     */
    static std::vector<uint8_t> eme_oaep_decode(
        const uint8_t* em, size_t emLen,
        const OAEPParamsV5& params);
    
    /**
     * @brief EMSA-PSS Encoding
     */
    static std::vector<uint8_t> emsa_pss_encode(
        const uint8_t* mHash, size_t hlen,
        size_t emBits,
        const PSSParamsV5& params);
    
    /**
     * @brief EMSA-PSS Verification
     */
    static bool emsa_pss_verify(
        const uint8_t* mHash, size_t hlen,
        const uint8_t* em, size_t emLen,
        size_t emBits,
        const PSSParamsV5& params);
};

// ============================================================================
// Type Aliases
// ============================================================================

using RSA2048 = RSAV5<2048>;
using RSA3072 = RSAV5<3072>;
using RSA4096 = RSAV5<4096>;

using RSAPublicKey2048 = RSAPublicKeyV5<2048>;
using RSAPublicKey4096 = RSAPublicKeyV5<4096>;
using RSAPrivateKey2048 = RSAPrivateKeyV5<2048>;
using RSAPrivateKey4096 = RSAPrivateKeyV5<4096>;

// ============================================================================
// High-Level API (Convenience Functions)
// ============================================================================

/**
 * @brief Generate RSA-2048 key pair
 */
inline RSAKeyPairV5<2048> rsa2048_generate_keypair() {
    return RSA2048::generate_keypair();
}

/**
 * @brief Generate RSA-4096 key pair
 */
inline RSAKeyPairV5<4096> rsa4096_generate_keypair() {
    return RSA4096::generate_keypair();
}

/**
 * @brief RSA-2048 OAEP encryption
 */
inline std::vector<uint8_t> rsa2048_encrypt(
    const uint8_t* plaintext, size_t len,
    const RSAPublicKeyV5<2048>& key) {
    return RSA2048::encrypt_oaep(plaintext, len, key);
}

/**
 * @brief RSA-2048 OAEP decryption
 */
inline std::vector<uint8_t> rsa2048_decrypt(
    const uint8_t* ciphertext, size_t len,
    const RSAPrivateKeyV5<2048>& key) {
    return RSA2048::decrypt_oaep(ciphertext, len, key);
}

/**
 * @brief RSA-2048 PSS sign
 */
inline std::vector<uint8_t> rsa2048_sign(
    const uint8_t* hash, size_t hlen,
    const RSAPrivateKeyV5<2048>& key) {
    return RSA2048::sign_pss(hash, hlen, key);
}

/**
 * @brief RSA-2048 PSS verify
 */
inline bool rsa2048_verify(
    const uint8_t* hash, size_t hlen,
    const uint8_t* sig, size_t sigLen,
    const RSAPublicKeyV5<2048>& key) {
    return RSA2048::verify_pss(hash, hlen, sig, sigLen, key);
}

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_V5_H
