/**
 * @file rsa_types.h
 * @brief RSA Core Type Definitions
 * 
 * Defines core RSA data structures:
 * - RSAKeySize enum (2048/3072/4096 bits)
 * - RSAPublicKey template (n, e, DER/PEM export)
 * - RSAPrivateKey template (CRT representation)
 * - RSAKeyPair template
 * - OAEPParams, PSSParams
 * 
 * @note Header-only template implementation
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_TYPES_H
#define KCTSB_CRYPTO_RSA_TYPES_H

#include "kctsb/core/bigint.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>

namespace kctsb {
namespace rsa {

// ============================================================================
// RSA Key Size Enum
// ============================================================================

/**
 * @brief Supported RSA key sizes
 */
enum class RSAKeySize : int {
    RSA_2048 = 2048,  ///< 2048-bit RSA (minimum recommended)
    RSA_3072 = 3072,  ///< 3072-bit RSA (medium security)
    RSA_4096 = 4096   ///< 4096-bit RSA (high security)
};

// ============================================================================
// RSA Public Key
// ============================================================================

/**
 * @brief RSA Public Key
 * @tparam BITS Key size in bits (2048, 3072, or 4096)
 */
template<size_t BITS = 2048>
struct RSAPublicKey {
    static_assert(BITS == 2048 || BITS == 3072 || BITS == 4096,
                  "RSA key size must be 2048, 3072, or 4096 bits");
    
    BigInt<BITS> n;  ///< Modulus (n = p * q)
    BigInt<BITS> e;  ///< Public exponent (typically 65537 = 0x10001)
    
    /**
     * @brief Default constructor
     */
    RSAPublicKey() = default;
    
    /**
     * @brief Constructor with modulus and exponent
     * @param n_ Modulus
     * @param e_ Public exponent
     */
    RSAPublicKey(const BigInt<BITS>& n_, const BigInt<BITS>& e_)
        : n(n_), e(e_) {}
    
    /**
     * @brief Validate key structure
     * @return true if key is structurally valid
     */
    bool is_valid() const {
        if (n.is_zero() || !n.is_odd()) return false;
        if (e < BigInt<BITS>(3) || e >= n || !e.is_odd()) return false;
        return true;
    }
    
    /**
     * @brief Get key size in bits
     */
    static constexpr size_t key_bits() { return BITS; }
    
    /**
     * @brief Get key size in bytes
     */
    static constexpr size_t key_bytes() { return BITS / 8; }
    
    /**
     * @brief Export public key to DER format
     * @return DER-encoded public key (SEQUENCE { n INTEGER, e INTEGER })
     */
    std::vector<uint8_t> to_der() const {
        auto n_bytes = n.to_bytes();
        auto e_bytes = e.to_bytes();
        
        // Remove leading zeros from e (typically 65537 = 0x010001)
        size_t e_start = 0;
        while (e_start < e_bytes.size() - 1 && e_bytes[e_start] == 0) {
            e_start++;
        }
        std::vector<uint8_t> e_trimmed(
            e_bytes.begin() + static_cast<std::ptrdiff_t>(e_start),
            e_bytes.end()
        );
        
        // Calculate content length
        size_t content_len = 2 + n_bytes.size() + (n_bytes[0] & 0x80 ? 1 : 0) +
                             2 + e_trimmed.size() + (e_trimmed[0] & 0x80 ? 1 : 0);
        
        std::vector<uint8_t> result;
        result.reserve(content_len + 4);
        
        // SEQUENCE tag
        result.push_back(0x30);
        
        // Length encoding (DER rules)
        if (content_len < 128) {
            result.push_back(static_cast<uint8_t>(content_len));
        } else if (content_len < 256) {
            result.push_back(0x81);
            result.push_back(static_cast<uint8_t>(content_len));
        } else {
            result.push_back(0x82);
            result.push_back(static_cast<uint8_t>(content_len >> 8));
            result.push_back(static_cast<uint8_t>(content_len));
        }
        
        // n INTEGER
        result.push_back(0x02);
        size_t n_len = n_bytes.size() + (n_bytes[0] & 0x80 ? 1 : 0);
        if (n_len < 128) {
            result.push_back(static_cast<uint8_t>(n_len));
        } else if (n_len < 256) {
            result.push_back(0x81);
            result.push_back(static_cast<uint8_t>(n_len));
        } else {
            result.push_back(0x82);
            result.push_back(static_cast<uint8_t>(n_len >> 8));
            result.push_back(static_cast<uint8_t>(n_len));
        }
        if (n_bytes[0] & 0x80) result.push_back(0x00);
        result.insert(result.end(), n_bytes.begin(), n_bytes.end());
        
        // e INTEGER
        result.push_back(0x02);
        size_t e_len = e_trimmed.size() + (e_trimmed[0] & 0x80 ? 1 : 0);
        result.push_back(static_cast<uint8_t>(e_len));
        if (e_trimmed[0] & 0x80) result.push_back(0x00);
        result.insert(result.end(), e_trimmed.begin(), e_trimmed.end());
        
        return result;
    }
    
    /**
     * @brief Export public key to PEM format
     * @return PEM-encoded public key
     */
    std::string to_pem() const {
        auto der = to_der();
        static const char* b64_table = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string encoded;
        encoded.reserve(((der.size() + 2) / 3) * 4);
        
        // Base64 encoding
        for (size_t i = 0; i < der.size(); i += 3) {
            uint32_t triplet = (static_cast<uint32_t>(der[i]) << 16) | 
                               (i + 1 < der.size() ? static_cast<uint32_t>(der[i + 1]) << 8 : 0) |
                               (i + 2 < der.size() ? static_cast<uint32_t>(der[i + 2]) : 0);
            
            encoded += b64_table[(triplet >> 18) & 0x3F];
            encoded += b64_table[(triplet >> 12) & 0x3F];
            encoded += (i + 1 < der.size()) ? b64_table[(triplet >> 6) & 0x3F] : '=';
            encoded += (i + 2 < der.size()) ? b64_table[triplet & 0x3F] : '=';
        }
        
        // Format as PEM (64 chars per line)
        std::string result = "-----BEGIN RSA PUBLIC KEY-----\n";
        for (size_t i = 0; i < encoded.size(); i += 64) {
            result += encoded.substr(i, 64) + "\n";
        }
        result += "-----END RSA PUBLIC KEY-----\n";
        
        return result;
    }
};

// ============================================================================
// RSA Private Key
// ============================================================================

/**
 * @brief RSA Private Key with CRT (Chinese Remainder Theorem) representation
 * @tparam BITS Key size in bits
 * 
 * Stores CRT parameters for faster decryption:
 * - Standard: d mod n
 * - CRT: dp = d mod (p-1), dq = d mod (q-1), qinv = q^(-1) mod p
 */
template<size_t BITS = 2048>
struct RSAPrivateKey {
    static_assert(BITS == 2048 || BITS == 3072 || BITS == 4096,
                  "RSA key size must be 2048, 3072, or 4096 bits");
    
    static constexpr size_t HALF_BITS = BITS / 2;
    
    BigInt<BITS> n;              ///< Modulus (n = p * q)
    BigInt<BITS> e;              ///< Public exponent
    BigInt<BITS> d;              ///< Private exponent (d = e^(-1) mod λ(n))
    BigInt<HALF_BITS + 64> p;    ///< First prime factor
    BigInt<HALF_BITS + 64> q;    ///< Second prime factor
    BigInt<HALF_BITS + 64> dp;   ///< d mod (p-1) for CRT
    BigInt<HALF_BITS + 64> dq;   ///< d mod (q-1) for CRT
    BigInt<HALF_BITS + 64> qinv; ///< q^(-1) mod p for CRT
    
    /**
     * @brief Default constructor
     */
    RSAPrivateKey() = default;
    
    /**
     * @brief Validate key structure
     * @return true if key is structurally valid
     */
    bool is_valid() const {
        if (n.is_zero() || !n.is_odd()) return false;
        if (d.is_zero() || d >= n) return false;
        if (p.is_zero() || q.is_zero()) return false;
        return true;
    }
    
    /**
     * @brief Extract public key from private key
     * @return Corresponding public key
     */
    RSAPublicKey<BITS> get_public_key() const {
        return RSAPublicKey<BITS>(n, e);
    }
    
    /**
     * @brief Securely zero all key material
     * @warning Call before destroying key to prevent memory leaks
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
     * @brief Destructor with secure clearing
     */
    ~RSAPrivateKey() {
        clear();
    }
};

// ============================================================================
// RSA Key Pair
// ============================================================================

/**
 * @brief RSA Public/Private Key Pair
 * @tparam BITS Key size in bits
 */
template<size_t BITS = 2048>
struct RSAKeyPair {
    RSAPublicKey<BITS> public_key;    ///< Public key component
    RSAPrivateKey<BITS> private_key;  ///< Private key component (sensitive!)
    
    /**
     * @brief Validate both keys
     */
    bool is_valid() const {
        return public_key.is_valid() && private_key.is_valid();
    }
};

// ============================================================================
// Padding Parameters
// ============================================================================

/**
 * @brief OAEP Padding Parameters (RSAES-OAEP)
 */
struct OAEPParams {
    /**
     * @brief Supported hash algorithms for OAEP
     */
    enum class HashAlgorithm {
        SHA256,  ///< SHA-256 (32 bytes)
        SHA384,  ///< SHA-384 (48 bytes)
        SHA512   ///< SHA-512 (64 bytes)
    };
    
    HashAlgorithm hash = HashAlgorithm::SHA256;  ///< Hash function
    std::vector<uint8_t> label;                   ///< Optional label (default: empty)
    
    /**
     * @brief Get hash output length
     * @return Hash length in bytes
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
 * @brief PSS Padding Parameters (RSASSA-PSS)
 */
struct PSSParams {
    /**
     * @brief Supported hash algorithms for PSS
     */
    enum class HashAlgorithm {
        SHA256,  ///< SHA-256 (32 bytes)
        SHA384,  ///< SHA-384 (48 bytes)
        SHA512   ///< SHA-512 (64 bytes)
    };
    
    HashAlgorithm hash = HashAlgorithm::SHA256;  ///< Hash function
    size_t salt_length = 32;                      ///< Salt length (default: 32 bytes)
    
    /**
     * @brief Get hash output length
     * @return Hash length in bytes
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
// Type Aliases for Common Key Sizes
// ============================================================================

using RSAPublicKey2048 = RSAPublicKey<2048>;
using RSAPublicKey3072 = RSAPublicKey<3072>;
using RSAPublicKey4096 = RSAPublicKey<4096>;

using RSAPrivateKey2048 = RSAPrivateKey<2048>;
using RSAPrivateKey3072 = RSAPrivateKey<3072>;
using RSAPrivateKey4096 = RSAPrivateKey<4096>;

using RSAKeyPair2048 = RSAKeyPair<2048>;
using RSAKeyPair3072 = RSAKeyPair<3072>;
using RSAKeyPair4096 = RSAKeyPair<4096>;

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_TYPES_H
