/**
 * @file rsa.h
 * @brief RSA Cryptosystem - Unified API Header
 * 
 * Modular RSA implementation following RFC 8017 (PKCS#1 v2.2):
 * - Key sizes: 2048, 3072, 4096 bits
 * - RSAES-OAEP encryption (recommended)
 * - RSASSA-PSS signatures (recommended)
 * - PKCS#1 v1.5 compatibility mode
 * - Self-contained: NO external dependencies
 * - Montgomery multiplication for accelerated modexp
 * 
 * Architecture (v5.0.0 - Modular Refactor):
 * - rsa_types.h: Core data structures (header-only templates)
 * - rsa_keygen.h/cpp: Key generation with Miller-Rabin
 * - rsa_padding.h/cpp: OAEP/PSS/PKCS1 padding schemes
 * - rsa_encrypt.h/cpp: Encryption/decryption operations
 * - rsa_sign.h/cpp: Signature generation/verification
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_H
#define KCTSB_CRYPTO_RSA_H

// Include all RSA submodules
#include "kctsb/crypto/rsa/rsa_types.h"
#include "kctsb/crypto/rsa/rsa_keygen.h"
#include "kctsb/crypto/rsa/rsa_padding.h"
#include "kctsb/crypto/rsa/rsa_encrypt.h"
#include "kctsb/crypto/rsa/rsa_sign.h"

namespace kctsb {
namespace rsa {

// ============================================================================
// Unified RSA Implementation Class
// ============================================================================

/**
 * @brief RSA Unified API Wrapper
 * @tparam BITS Key size in bits (2048, 3072, or 4096)
 * 
 * Provides a convenient class-based interface to all RSA operations.
 * For performance-critical code, use the individual functions directly.
 */
template<size_t BITS = 2048>
class RSA {
public:
    using PublicKey = RSAPublicKey<BITS>;
    using PrivateKey = RSAPrivateKey<BITS>;
    using KeyPair = RSAKeyPair<BITS>;
    using Int = BigInt<BITS>;
    
    // ========================================================================
    // Key Generation
    // ========================================================================
    
    /**
     * @brief Generate new RSA key pair
     * @param e_val Public exponent (default: 65537)
     * @return Generated key pair
     */
    static KeyPair generate_keypair(uint64_t e_val = 65537) {
        return rsa::generate_keypair<BITS>(e_val);
    }
    
    // ========================================================================
    // Encryption/Decryption
    // ========================================================================
    
    /**
     * @brief Encrypt with RSAES-OAEP (recommended)
     */
    static std::vector<uint8_t> encrypt_oaep(
        const uint8_t* plaintext, size_t len,
        const PublicKey& k,
        const OAEPParams& params = OAEPParams()
    ) {
        return rsa::encrypt_oaep<BITS>(plaintext, len, k, params);
    }
    
    /**
     * @brief Decrypt with RSAES-OAEP
     */
    static std::vector<uint8_t> decrypt_oaep(
        const uint8_t* ciphertext, size_t len,
        const PrivateKey& k,
        const OAEPParams& params = OAEPParams()
    ) {
        return rsa::decrypt_oaep<BITS>(ciphertext, len, k, params);
    }
    
    /**
     * @brief Encrypt with RSAES-PKCS1-v1_5 (legacy)
     */
    static std::vector<uint8_t> encrypt_pkcs1(
        const uint8_t* plaintext, size_t len,
        const PublicKey& k
    ) {
        return rsa::encrypt_pkcs1<BITS>(plaintext, len, k);
    }
    
    /**
     * @brief Decrypt with RSAES-PKCS1-v1_5
     */
    static std::vector<uint8_t> decrypt_pkcs1(
        const uint8_t* ciphertext, size_t len,
        const PrivateKey& k
    ) {
        return rsa::decrypt_pkcs1<BITS>(ciphertext, len, k);
    }
    
    // ========================================================================
    // Signature/Verification
    // ========================================================================
    
    /**
     * @brief Sign with RSASSA-PSS (recommended)
     */
    static std::vector<uint8_t> sign_pss(
        const uint8_t* mHash, size_t hlen,
        const PrivateKey& k,
        const PSSParams& params = PSSParams()
    ) {
        return rsa::sign_pss<BITS>(mHash, hlen, k, params);
    }
    
    /**
     * @brief Verify with RSASSA-PSS
     */
    static bool verify_pss(
        const uint8_t* mHash, size_t hlen,
        const uint8_t* sig, size_t sigLen,
        const PublicKey& k,
        const PSSParams& params = PSSParams()
    ) {
        return rsa::verify_pss<BITS>(mHash, hlen, sig, sigLen, k, params);
    }
    
    /**
     * @brief Sign with RSASSA-PKCS1-v1_5 (legacy)
     */
    static std::vector<uint8_t> sign_pkcs1(
        const uint8_t* mHash, size_t hlen,
        const PrivateKey& k
    ) {
        return rsa::sign_pkcs1<BITS>(mHash, hlen, k);
    }
    
    /**
     * @brief Verify with RSASSA-PKCS1-v1_5
     */
    static bool verify_pkcs1(
        const uint8_t* mHash, size_t hlen,
        const uint8_t* sig, size_t sigLen,
        const PublicKey& k
    ) {
        return rsa::verify_pkcs1<BITS>(mHash, hlen, sig, sigLen, k);
    }
    
    // ========================================================================
    // Low-Level Primitives
    // ========================================================================
    
    static Int rsaep(const Int& m, const PublicKey& k) {
        return rsa::rsaep<BITS>(m, k);
    }
    
    static Int rsadp(const Int& c, const PrivateKey& k) {
        return rsa::rsadp<BITS>(c, k);
    }
    
    static Int rsasp1(const Int& m, const PrivateKey& k) {
        return rsa::rsasp1<BITS>(m, k);
    }
    
    static Int rsavp1(const Int& s, const PublicKey& k) {
        return rsa::rsavp1<BITS>(s, k);
    }
    
    // ========================================================================
    // Byte Conversion Utilities
    // ========================================================================
    
    static std::vector<uint8_t> i2osp(const Int& x, size_t len) {
        return rsa::i2osp<BITS>(x, len);
    }
    
    static Int os2ip(const uint8_t* x, size_t len) {
        return rsa::os2ip<BITS>(x, len);
    }
};

// ============================================================================
// Type Aliases for Common Key Sizes
// ============================================================================

using RSA2048 = RSA<2048>;
using RSA3072 = RSA<3072>;
using RSA4096 = RSA<4096>;

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_H
