/**
 * @file rsa_encrypt.h
 * @brief RSA Encryption/Decryption Operations
 * 
 * Implements RSA encryption primitives and schemes:
 * - RSAEP/RSADP (raw RSA primitives)
 * - RSAES-OAEP (recommended for encryption)
 * - RSAES-PKCS1-v1_5 (legacy compatibility)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_ENCRYPT_H
#define KCTSB_CRYPTO_RSA_ENCRYPT_H

#include "kctsb/crypto/rsa/rsa_types.h"
#include "kctsb/core/bigint.h"
#include <vector>
#include <cstdint>

namespace kctsb {
namespace rsa {

// ============================================================================
// RSA Encryption Primitives (RSAEP/RSADP)
// ============================================================================

/**
 * @brief RSA Encryption Primitive (RSAEP)
 * @tparam BITS Key size in bits
 * @param m Message representative (0 <= m < n)
 * @param k Public key
 * @return Ciphertext representative c = m^e mod n
 * @throws std::invalid_argument if m >= n
 */
template<size_t BITS>
BigInt<BITS> rsaep(const BigInt<BITS>& m, const RSAPublicKey<BITS>& k);

/**
 * @brief RSA Decryption Primitive (RSADP)
 * @tparam BITS Key size in bits
 * @param c Ciphertext representative (0 <= c < n)
 * @param k Private key
 * @return Message representative m = c^d mod n
 * @throws std::invalid_argument if c >= n
 */
template<size_t BITS>
BigInt<BITS> rsadp(const BigInt<BITS>& c, const RSAPrivateKey<BITS>& k);

/**
 * @brief RSA Decryption Primitive with CRT optimization
 * @tparam BITS Key size in bits
 * @param c Ciphertext representative
 * @param k Private key (with CRT parameters)
 * @return Message representative m
 * 
 * @details Uses Chinese Remainder Theorem for ~4x speedup:
 * - m1 = c^dp mod p
 * - m2 = c^dq mod q
 * - h = qinv * (m1 - m2) mod p
 * - m = m2 + h * q
 */
template<size_t BITS>
BigInt<BITS> rsadp_crt(const BigInt<BITS>& c, const RSAPrivateKey<BITS>& k);

// ============================================================================
// Byte Conversion Utilities
// ============================================================================

/**
 * @brief Integer-to-Octet-String Primitive (I2OSP)
 * @param x Integer to convert
 * @param len Output length in bytes
 * @return Byte representation
 */
template<size_t BITS>
std::vector<uint8_t> i2osp(const BigInt<BITS>& x, size_t len);

/**
 * @brief Octet-String-to-Integer Primitive (OS2IP)
 * @param x Byte array
 * @param len Array length
 * @return BigInt representation
 */
template<size_t BITS>
BigInt<BITS> os2ip(const uint8_t* x, size_t len);

// ============================================================================
// RSAES-OAEP (Recommended)
// ============================================================================

/**
 * @brief RSAES-OAEP encryption (RFC 8017 Section 7.1)
 * @tparam BITS Key size in bits
 * @param plaintext Message to encrypt
 * @param len Message length in bytes
 * @param k Public key
 * @param params OAEP parameters
 * @return Ciphertext
 * @throws std::invalid_argument if message too long
 */
template<size_t BITS>
std::vector<uint8_t> encrypt_oaep(
    const uint8_t* plaintext,
    size_t len,
    const RSAPublicKey<BITS>& k,
    const OAEPParams& params = OAEPParams()
);

/**
 * @brief RSAES-OAEP decryption (RFC 8017 Section 7.1)
 * @tparam BITS Key size in bits
 * @param ciphertext Encrypted message
 * @param len Ciphertext length
 * @param k Private key
 * @param params OAEP parameters
 * @return Decrypted message
 * @throws std::runtime_error if decryption fails
 */
template<size_t BITS>
std::vector<uint8_t> decrypt_oaep(
    const uint8_t* ciphertext,
    size_t len,
    const RSAPrivateKey<BITS>& k,
    const OAEPParams& params = OAEPParams()
);

// ============================================================================
// RSAES-PKCS1-v1_5 (Legacy)
// ============================================================================

/**
 * @brief RSAES-PKCS1-v1_5 encryption (RFC 8017 Section 7.2)
 * @tparam BITS Key size in bits
 * @param plaintext Message to encrypt
 * @param len Message length
 * @param k Public key
 * @return Ciphertext
 */
template<size_t BITS>
std::vector<uint8_t> encrypt_pkcs1(
    const uint8_t* plaintext,
    size_t len,
    const RSAPublicKey<BITS>& k
);

/**
 * @brief RSAES-PKCS1-v1_5 decryption (RFC 8017 Section 7.2)
 * @tparam BITS Key size in bits
 * @param ciphertext Encrypted message
 * @param len Ciphertext length
 * @param k Private key
 * @return Decrypted message
 */
template<size_t BITS>
std::vector<uint8_t> decrypt_pkcs1(
    const uint8_t* ciphertext,
    size_t len,
    const RSAPrivateKey<BITS>& k
);

// ============================================================================
// Explicit Template Instantiations (declared here, defined in .cpp)
// ============================================================================

extern template BigInt<2048> rsaep<2048>(const BigInt<2048>&, const RSAPublicKey<2048>&);
extern template BigInt<3072> rsaep<3072>(const BigInt<3072>&, const RSAPublicKey<3072>&);
extern template BigInt<4096> rsaep<4096>(const BigInt<4096>&, const RSAPublicKey<4096>&);

extern template BigInt<2048> rsadp<2048>(const BigInt<2048>&, const RSAPrivateKey<2048>&);
extern template BigInt<3072> rsadp<3072>(const BigInt<3072>&, const RSAPrivateKey<3072>&);
extern template BigInt<4096> rsadp<4096>(const BigInt<4096>&, const RSAPrivateKey<4096>&);

extern template BigInt<2048> rsadp_crt<2048>(const BigInt<2048>&, const RSAPrivateKey<2048>&);
extern template BigInt<3072> rsadp_crt<3072>(const BigInt<3072>&, const RSAPrivateKey<3072>&);
extern template BigInt<4096> rsadp_crt<4096>(const BigInt<4096>&, const RSAPrivateKey<4096>&);

extern template std::vector<uint8_t> encrypt_oaep<2048>(const uint8_t*, size_t, const RSAPublicKey<2048>&, const OAEPParams&);
extern template std::vector<uint8_t> encrypt_oaep<3072>(const uint8_t*, size_t, const RSAPublicKey<3072>&, const OAEPParams&);
extern template std::vector<uint8_t> encrypt_oaep<4096>(const uint8_t*, size_t, const RSAPublicKey<4096>&, const OAEPParams&);

extern template std::vector<uint8_t> decrypt_oaep<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&, const OAEPParams&);
extern template std::vector<uint8_t> decrypt_oaep<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&, const OAEPParams&);
extern template std::vector<uint8_t> decrypt_oaep<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&, const OAEPParams&);

extern template std::vector<uint8_t> encrypt_pkcs1<2048>(const uint8_t*, size_t, const RSAPublicKey<2048>&);
extern template std::vector<uint8_t> encrypt_pkcs1<3072>(const uint8_t*, size_t, const RSAPublicKey<3072>&);
extern template std::vector<uint8_t> encrypt_pkcs1<4096>(const uint8_t*, size_t, const RSAPublicKey<4096>&);

extern template std::vector<uint8_t> decrypt_pkcs1<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&);
extern template std::vector<uint8_t> decrypt_pkcs1<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&);
extern template std::vector<uint8_t> decrypt_pkcs1<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&);

// ============================================================================
// High-Level API
// ============================================================================

/**
 * @brief Encrypt message with RSA-2048-OAEP
 */
inline std::vector<uint8_t> rsa2048_encrypt(
    const uint8_t* plaintext,
    size_t len,
    const RSAPublicKey<2048>& key
) {
    return encrypt_oaep<2048>(plaintext, len, key);
}

/**
 * @brief Decrypt message with RSA-2048-OAEP
 */
inline std::vector<uint8_t> rsa2048_decrypt(
    const uint8_t* ciphertext,
    size_t len,
    const RSAPrivateKey<2048>& key
) {
    return decrypt_oaep<2048>(ciphertext, len, key);
}

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_ENCRYPT_H
