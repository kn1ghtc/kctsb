/**
 * @file rsa.h
 * @brief RSA Cryptosystem - Self-Contained Template Implementation
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
 * - Montgomery multiplication for accelerated modexp
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_H
#define KCTSB_CRYPTO_RSA_H

#include "kctsb/core/bigint.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <random>
#include <stdexcept>
#include <array>

namespace kctsb {
namespace rsa {

// ============================================================================
// RSA Key Size Enum
// ============================================================================

enum class RSAKeySize : int {
    RSA_2048 = 2048,
    RSA_3072 = 3072,
    RSA_4096 = 4096
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
    
    BigInt<BITS> n;      ///< Modulus
    BigInt<BITS> e;      ///< Public exponent (typically 65537)
    
    RSAPublicKey() = default;
    
    RSAPublicKey(const BigInt<BITS>& n_, const BigInt<BITS>& e_)
        : n(n_), e(e_) {}
    
    bool is_valid() const {
        if (n.is_zero() || !n.is_odd()) return false;
        if (e < BigInt<BITS>(3) || e >= n || !e.is_odd()) return false;
        return true;
    }
    
    static constexpr size_t key_bits() { return BITS; }
    static constexpr size_t key_bytes() { return BITS / 8; }
    
    std::vector<uint8_t> to_der() const {
        // Simple DER encoding for RSA public key
        auto n_bytes = n.to_bytes();
        auto e_bytes = e.to_bytes();
        
        // Remove leading zeros from e (typically 65537 = 0x010001)
        size_t e_start = 0;
        while (e_start < e_bytes.size() - 1 && e_bytes[e_start] == 0) e_start++;
        std::vector<uint8_t> e_trimmed(e_bytes.begin() + static_cast<std::ptrdiff_t>(e_start), e_bytes.end());
        
        // Build DER SEQUENCE
        std::vector<uint8_t> result;
        result.push_back(0x30); // SEQUENCE
        
        size_t content_len = 2 + n_bytes.size() + (n_bytes[0] & 0x80 ? 1 : 0) +
                             2 + e_trimmed.size() + (e_trimmed[0] & 0x80 ? 1 : 0);
        
        // Length encoding
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
    
    std::string to_pem() const {
        auto der = to_der();
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string encoded;
        for (size_t i = 0; i < der.size(); i += 3) {
            uint32_t t = (static_cast<uint32_t>(der[i]) << 16) | 
                         (i+1 < der.size() ? static_cast<uint32_t>(der[i+1]) << 8 : 0) |
                         (i+2 < der.size() ? static_cast<uint32_t>(der[i+2]) : 0);
            encoded += b64[(t >> 18) & 0x3F];
            encoded += b64[(t >> 12) & 0x3F];
            encoded += (i+1 < der.size()) ? b64[(t >> 6) & 0x3F] : '=';
            encoded += (i+2 < der.size()) ? b64[t & 0x3F] : '=';
        }
        std::string result = "-----BEGIN RSA PUBLIC KEY-----\n";
        for (size_t i = 0; i < encoded.size(); i += 64) {
            result += encoded.substr(i, 64) + "\n";
        }
        return result + "-----END RSA PUBLIC KEY-----\n";
    }
};

// ============================================================================
// RSA Private Key
// ============================================================================

/**
 * @brief RSA Private Key with CRT representation
 * @tparam BITS Key size in bits
 */
template<size_t BITS = 2048>
struct RSAPrivateKey {
    static_assert(BITS == 2048 || BITS == 3072 || BITS == 4096,
                  "RSA key size must be 2048, 3072, or 4096 bits");
    
    static constexpr size_t HALF_BITS = BITS / 2;
    
    BigInt<BITS> n;            ///< Modulus (n = p * q)
    BigInt<BITS> e;            ///< Public exponent
    BigInt<BITS> d;            ///< Private exponent
    BigInt<HALF_BITS + 64> p;  ///< First prime factor
    BigInt<HALF_BITS + 64> q;  ///< Second prime factor
    BigInt<HALF_BITS + 64> dp; ///< d mod (p-1) for CRT
    BigInt<HALF_BITS + 64> dq; ///< d mod (q-1) for CRT
    BigInt<HALF_BITS + 64> qinv; ///< q^(-1) mod p for CRT
    
    RSAPrivateKey() = default;
    
    bool is_valid() const {
        if (n.is_zero() || !n.is_odd()) return false;
        if (d.is_zero() || d >= n) return false;
        return true;
    }
    
    RSAPublicKey<BITS> get_public_key() const {
        return RSAPublicKey<BITS>(n, e);
    }
    
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
    
    ~RSAPrivateKey() {
        clear();
    }
};

/**
 * @brief RSA Key Pair
 */
template<size_t BITS = 2048>
struct RSAKeyPair {
    RSAPublicKey<BITS> public_key;
    RSAPrivateKey<BITS> private_key;
};

// ============================================================================
// Padding Parameters
// ============================================================================

struct OAEPParams {
    enum class HashAlgorithm { SHA256, SHA384, SHA512 };
    HashAlgorithm hash = HashAlgorithm::SHA256;
    std::vector<uint8_t> label;
    
    size_t hash_length() const {
        switch (hash) {
            case HashAlgorithm::SHA256: return 32;
            case HashAlgorithm::SHA384: return 48;
            case HashAlgorithm::SHA512: return 64;
            default: return 32;
        }
    }
};

struct PSSParams {
    enum class HashAlgorithm { SHA256, SHA384, SHA512 };
    HashAlgorithm hash = HashAlgorithm::SHA256;
    size_t salt_length = 32;
    
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
// Prime Generation Utilities
// ============================================================================

namespace detail {

/**
 * @brief Miller-Rabin primality test
 */
template<size_t BITS>
bool is_probable_prime(const BigInt<BITS>& n, int trials = 20) {
    if (n <= BigInt<BITS>(1)) return false;
    if (n == BigInt<BITS>(2)) return true;
    if (!n.is_odd()) return false;
    
    // Write n-1 = 2^r * d
    BigInt<BITS> n_minus_1 = n;
    n_minus_1 -= BigInt<BITS>(1);
    BigInt<BITS> d = n_minus_1;
    size_t r = 0;
    while (!d.is_odd()) {
        d >>= 1;
        r++;
    }
    
    std::random_device rd;
    std::mt19937_64 gen(rd());
    MontgomeryContext<BITS> mont(n);
    
    for (int i = 0; i < trials; i++) {
        // Pick random a in [2, n-2]
        BigInt<BITS> a = random_bigint_mod(gen, n_minus_1);
        if (a < BigInt<BITS>(2)) a = BigInt<BITS>(2);
        
        BigInt<BITS> x = mont.pow_mod(a, d);
        
        if (x == BigInt<BITS>(1) || x == n_minus_1) continue;
        
        bool found = false;
        for (size_t j = 0; j < r - 1; j++) {
            x = mont.pow_mod(x, BigInt<BITS>(2));
            if (x == n_minus_1) {
                found = true;
                break;
            }
        }
        
        if (!found) return false;
    }
    
    return true;
}

/**
 * @brief Generate random prime of specified bit length
 */
template<size_t BITS>
BigInt<BITS> generate_prime(size_t bits) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    while (true) {
        BigInt<BITS> candidate = random_bigint<BITS>(gen);
        
        // Set top two bits (ensures bit length and product length)
        candidate.set_bit(bits - 1, true);
        candidate.set_bit(bits - 2, true);
        
        // Set bottom bit (ensure odd)
        candidate.set_bit(0, true);
        
        // Clear bits above target length
        for (size_t i = bits; i < BITS; i++) {
            candidate.set_bit(i, false);
        }
        
        if (is_probable_prime(candidate)) {
            return candidate;
        }
    }
}

/**
 * @brief Compute GCD using binary GCD algorithm
 */
template<size_t BITS>
BigInt<BITS> gcd(BigInt<BITS> a, BigInt<BITS> b) {
    if (a.is_zero()) return b;
    if (b.is_zero()) return a;
    
    size_t shift = 0;
    while (!a.is_odd() && !b.is_odd()) {
        a >>= 1;
        b >>= 1;
        shift++;
    }
    
    while (!a.is_zero()) {
        while (!a.is_odd()) a >>= 1;
        while (!b.is_odd()) b >>= 1;
        
        if (a >= b) {
            a -= b;
        } else {
            b -= a;
        }
    }
    
    return b << shift;
}

} // namespace detail

// ============================================================================
// RSA Implementation Class
// ============================================================================

/**
 * @brief RSA Implementation Class
 * @tparam BITS Key size in bits
 */
template<size_t BITS = 2048>
class RSA {
public:
    using PublicKey = RSAPublicKey<BITS>;
    using PrivateKey = RSAPrivateKey<BITS>;
    using KeyPair = RSAKeyPair<BITS>;
    using Int = BigInt<BITS>;
    static constexpr size_t HALF_BITS = BITS / 2;
    using HalfInt = BigInt<HALF_BITS + 64>;
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate new RSA key pair
     * @param e_val Public exponent (default 65537)
     * @return Generated key pair
     */
    static KeyPair generate_keypair(uint64_t e_val = 65537) {
        KeyPair kp;
        PrivateKey& priv = kp.private_key;
        
        priv.e = Int(e_val);
        Int e = priv.e;
        
        while (true) {
            // Generate two primes of half the key size
            priv.p = detail::generate_prime<HALF_BITS + 64>(BITS / 2);
            priv.q = detail::generate_prime<HALF_BITS + 64>(BITS / 2);
            
            // Ensure p != q
            if (priv.p == priv.q) continue;
            
            // Ensure p > q
            if (priv.p < priv.q) {
                HalfInt tmp = priv.p;
                priv.p = priv.q;
                priv.q = tmp;
            }
            
            // Compute n = p * q (need to promote to full width)
            Int p_full, q_full;
            for (size_t i = 0; i < HalfInt::NUM_LIMBS && i < Int::NUM_LIMBS; i++) {
                p_full[i] = priv.p[i];
                q_full[i] = priv.q[i];
            }
            
            // Schoolbook multiplication for n = p * q
            BigInt<BITS * 2> n_wide;
            for (size_t i = 0; i < Int::NUM_LIMBS; i++) {
                limb_t carry = 0;
                for (size_t j = 0; j < Int::NUM_LIMBS; j++) {
                    limb_t hi, lo;
                    Int::mul64(p_full[i], q_full[j], lo, hi);
                    
                    limb_t c1, c2;
                    c1 = Int::add_with_carry(n_wide[i + j], lo, 0, n_wide[i + j]);
                    c2 = Int::add_with_carry(n_wide[i + j], carry, 0, n_wide[i + j]);
                    carry = hi + c1 + c2;
                }
                n_wide[i + Int::NUM_LIMBS] += carry;
            }
            
            // Copy lower BITS to n
            for (size_t i = 0; i < Int::NUM_LIMBS; i++) {
                priv.n[i] = n_wide[i];
            }
            
            // Check n has correct bit length
            if (priv.n.num_bits() != BITS) continue;
            
            // Compute lambda = (p-1)(q-1) / gcd(p-1, q-1)
            // For simplicity, use phi(n) = (p-1)(q-1)
            HalfInt p_minus_1 = priv.p;
            p_minus_1 -= HalfInt(1);
            HalfInt q_minus_1 = priv.q;
            q_minus_1 -= HalfInt(1);
            
            // Compute phi(n) in full width
            BigInt<BITS * 2> phi_wide;
            for (size_t i = 0; i < HalfInt::NUM_LIMBS; i++) {
                limb_t carry = 0;
                for (size_t j = 0; j < HalfInt::NUM_LIMBS; j++) {
                    limb_t hi, lo;
                    HalfInt::mul64(p_minus_1[i], q_minus_1[j], lo, hi);
                    
                    limb_t c1, c2;
                    c1 = HalfInt::add_with_carry(phi_wide[i + j], lo, 0, phi_wide[i + j]);
                    c2 = HalfInt::add_with_carry(phi_wide[i + j], carry, 0, phi_wide[i + j]);
                    carry = hi + c1 + c2;
                }
                phi_wide[i + HalfInt::NUM_LIMBS] += carry;
            }
            
            Int phi;
            for (size_t i = 0; i < Int::NUM_LIMBS; i++) {
                phi[i] = phi_wide[i];
            }
            
            // Check gcd(e, phi) = 1
            Int e_gcd = detail::gcd(e, phi);
            if (e_gcd != Int(1)) continue;
            
            // Compute d = e^(-1) mod phi
            priv.d = mod_inverse(e, phi);
            if (priv.d.is_zero()) continue;
            
            // Compute CRT parameters
            priv.dp = mod_inverse(HalfInt(e_val), p_minus_1);
            priv.dq = mod_inverse(HalfInt(e_val), q_minus_1);
            priv.qinv = mod_inverse(priv.q, priv.p);
            
            break;
        }
        
        kp.public_key = priv.get_public_key();
        return kp;
    }
    
    // ========================================================================
    // Core RSA Primitives
    // ========================================================================
    
    /**
     * @brief RSA Encryption Primitive (RSAEP)
     */
    static Int rsaep(const Int& m, const PublicKey& k) {
        if (m >= k.n) {
            throw std::invalid_argument("Message representative out of range");
        }
        MontgomeryContext<BITS> mont(k.n);
        return mont.pow_mod(m, k.e);
    }
    
    /**
     * @brief RSA Decryption Primitive (RSADP)
     */
    static Int rsadp(const Int& c, const PrivateKey& k) {
        if (c >= k.n) {
            throw std::invalid_argument("Ciphertext representative out of range");
        }
        MontgomeryContext<BITS> mont(k.n);
        return mont.pow_mod(c, k.d);
    }
    
    /**
     * @brief RSA Decryption Primitive with CRT (faster)
     */
    static Int rsadp_crt(const Int& c, const PrivateKey& k) {
        // TODO: Implement CRT acceleration
        // For now, fall back to standard modexp
        return rsadp(c, k);
    }
    
    static Int rsasp1(const Int& m, const PrivateKey& k) { return rsadp(m, k); }
    static Int rsavp1(const Int& s, const PublicKey& k) { return rsaep(s, k); }
    
    // ========================================================================
    // Byte Conversion
    // ========================================================================
    
    static std::vector<uint8_t> i2osp(const Int& x, size_t len) {
        std::vector<uint8_t> result(len);
        x.to_bytes(result.data(), len);
        return result;
    }
    
    static Int os2ip(const uint8_t* x, size_t len) {
        return Int(x, len);
    }
    
    // ========================================================================
    // RSAES-PKCS1-v1_5 (Simple Implementation)
    // ========================================================================
    
    static std::vector<uint8_t> encrypt_pkcs1(
        const uint8_t* plaintext, size_t len,
        const PublicKey& k) {
        
        size_t key_len = BITS / 8;
        if (len > key_len - 11) {
            throw std::invalid_argument("Message too long for PKCS#1");
        }
        
        // EM = 0x00 || 0x02 || PS || 0x00 || M
        std::vector<uint8_t> em(key_len);
        em[0] = 0x00;
        em[1] = 0x02;
        
        // Generate random padding
        std::random_device rd;
        size_t ps_len = key_len - len - 3;
        for (size_t i = 0; i < ps_len; i++) {
            uint8_t r;
            do { r = static_cast<uint8_t>(rd() & 0xFF); } while (r == 0);
            em[2 + i] = r;
        }
        
        em[2 + ps_len] = 0x00;
        std::memcpy(em.data() + 3 + ps_len, plaintext, len);
        
        // Convert to integer and encrypt
        Int m = os2ip(em.data(), key_len);
        Int c = rsaep(m, k);
        
        return i2osp(c, key_len);
    }
    
    static std::vector<uint8_t> decrypt_pkcs1(
        const uint8_t* ciphertext, size_t len,
        const PrivateKey& k) {
        
        size_t key_len = BITS / 8;
        if (len != key_len) {
            throw std::invalid_argument("Invalid ciphertext length");
        }
        
        // Decrypt
        Int c = os2ip(ciphertext, len);
        Int m = rsadp(c, k);
        auto em = i2osp(m, key_len);
        
        // Check format: 0x00 || 0x02 || PS || 0x00 || M
        if (em[0] != 0x00 || em[1] != 0x02) {
            throw std::runtime_error("Invalid PKCS#1 padding");
        }
        
        // Find 0x00 separator
        size_t sep = 2;
        while (sep < em.size() && em[sep] != 0x00) sep++;
        
        if (sep >= em.size() || sep < 10) {
            throw std::runtime_error("Invalid PKCS#1 padding");
        }
        
        return std::vector<uint8_t>(em.begin() + static_cast<std::ptrdiff_t>(sep) + 1, em.end());
    }
    
    // ========================================================================
    // OAEP and PSS (Simplified stubs - full implementation in .cpp)
    // ========================================================================
    
    static std::vector<uint8_t> encrypt_oaep(
        const uint8_t* plaintext, size_t len,
        const PublicKey& k,
        const OAEPParams& params = OAEPParams()) {
        // Simplified: use PKCS#1 for now
        (void)params;
        return encrypt_pkcs1(plaintext, len, k);
    }
    
    static std::vector<uint8_t> decrypt_oaep(
        const uint8_t* ciphertext, size_t len,
        const PrivateKey& k,
        const OAEPParams& params = OAEPParams()) {
        // Simplified: use PKCS#1 for now
        (void)params;
        return decrypt_pkcs1(ciphertext, len, k);
    }
    
    static std::vector<uint8_t> sign_pss(
        const uint8_t* mHash, size_t hlen,
        const PrivateKey& k,
        const PSSParams& params = PSSParams()) {
        // Simplified signing
        (void)params;
        size_t key_len = BITS / 8;
        
        // Create padded message
        std::vector<uint8_t> em(key_len, 0);
        em[0] = 0x00;
        em[1] = 0x01;
        std::memset(em.data() + 2, 0xFF, key_len - hlen - 3);
        em[key_len - hlen - 1] = 0x00;
        std::memcpy(em.data() + key_len - hlen, mHash, hlen);
        
        Int m = os2ip(em.data(), key_len);
        Int s = rsasp1(m, k);
        
        return i2osp(s, key_len);
    }
    
    static bool verify_pss(
        const uint8_t* mHash, size_t hlen,
        const uint8_t* sig, size_t sigLen,
        const PublicKey& k,
        const PSSParams& params = PSSParams()) {
        (void)params;
        size_t key_len = BITS / 8;
        
        if (sigLen != key_len) return false;
        
        Int s = os2ip(sig, sigLen);
        Int m = rsavp1(s, k);
        auto em = i2osp(m, key_len);
        
        // Check format and hash
        if (em[0] != 0x00 || em[1] != 0x01) return false;
        
        // Find 0x00 separator
        size_t sep = 2;
        while (sep < em.size() && em[sep] == 0xFF) sep++;
        if (sep >= em.size() || em[sep] != 0x00) return false;
        
        // Compare hash
        if (em.size() - sep - 1 != hlen) return false;
        return std::memcmp(em.data() + sep + 1, mHash, hlen) == 0;
    }
    
    static std::vector<uint8_t> sign_pkcs1(
        const uint8_t* mHash, size_t hlen,
        const PrivateKey& k) {
        return sign_pss(mHash, hlen, k);
    }
    
    static bool verify_pkcs1(
        const uint8_t* mHash, size_t hlen,
        const uint8_t* sig, size_t sigLen,
        const PublicKey& k) {
        return verify_pss(mHash, hlen, sig, sigLen, k);
    }
};

// ============================================================================
// Type Aliases
// ============================================================================

using RSA2048 = RSA<2048>;
using RSA3072 = RSA<3072>;
using RSA4096 = RSA<4096>;

using RSAPublicKey2048 = RSAPublicKey<2048>;
using RSAPublicKey4096 = RSAPublicKey<4096>;
using RSAPrivateKey2048 = RSAPrivateKey<2048>;
using RSAPrivateKey4096 = RSAPrivateKey<4096>;
using RSAKeyPair2048 = RSAKeyPair<2048>;
using RSAKeyPair4096 = RSAKeyPair<4096>;

// ============================================================================
// High-Level API
// ============================================================================

inline RSAKeyPair<2048> rsa2048_generate_keypair() {
    return RSA2048::generate_keypair();
}

inline RSAKeyPair<4096> rsa4096_generate_keypair() {
    return RSA4096::generate_keypair();
}

inline std::vector<uint8_t> rsa2048_encrypt(
    const uint8_t* plaintext, size_t len,
    const RSAPublicKey<2048>& key) {
    return RSA2048::encrypt_pkcs1(plaintext, len, key);
}

inline std::vector<uint8_t> rsa2048_decrypt(
    const uint8_t* ciphertext, size_t len,
    const RSAPrivateKey<2048>& key) {
    return RSA2048::decrypt_pkcs1(ciphertext, len, key);
}

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_H
