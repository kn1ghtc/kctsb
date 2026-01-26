/**
 * @file rsa_encrypt.cpp
 * @brief RSA Encryption/Decryption Implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/rsa/rsa_encrypt.h"
#include "kctsb/crypto/rsa/rsa_padding.h"
#include <stdexcept>

namespace kctsb {
namespace rsa {

// ============================================================================
// RSA Encryption Primitives
// ============================================================================

template<size_t BITS>
BigInt<BITS> rsaep(const BigInt<BITS>& m, const RSAPublicKey<BITS>& k) {
    if (m >= k.n) {
        throw std::invalid_argument("Message representative out of range");
    }
    MontgomeryContext<BITS> mont(k.n);
    return mont.pow_mod(m, k.e);
}

template<size_t BITS>
BigInt<BITS> rsadp(const BigInt<BITS>& c, const RSAPrivateKey<BITS>& k) {
    if (c >= k.n) {
        throw std::invalid_argument("Ciphertext representative out of range");
    }
    MontgomeryContext<BITS> mont(k.n);
    return mont.pow_mod(c, k.d);
}

template<size_t BITS>
BigInt<BITS> rsadp_crt(const BigInt<BITS>& c, const RSAPrivateKey<BITS>& k) {
    // TODO: Implement CRT optimization
    // For now, fall back to standard modexp
    return rsadp(c, k);
}

// ============================================================================
// Byte Conversion
// ============================================================================

template<size_t BITS>
std::vector<uint8_t> i2osp(const BigInt<BITS>& x, size_t len) {
    std::vector<uint8_t> result(len);
    x.to_bytes(result.data(), len);
    return result;
}

template<size_t BITS>
BigInt<BITS> os2ip(const uint8_t* x, size_t len) {
    return BigInt<BITS>(x, len);
}

// ============================================================================
// RSAES-OAEP
// ============================================================================

template<size_t BITS>
std::vector<uint8_t> encrypt_oaep(
    const uint8_t* plaintext,
    size_t len,
    const RSAPublicKey<BITS>& k,
    const OAEPParams& params
) {
    size_t key_len = BITS / 8;
    
    // Encode message
    auto em = eme_oaep_encode(plaintext, len, key_len, params);
    
    // Convert to integer and encrypt
    BigInt<BITS> m = os2ip<BITS>(em.data(), key_len);
    BigInt<BITS> c = rsaep(m, k);
    
    return i2osp(c, key_len);
}

template<size_t BITS>
std::vector<uint8_t> decrypt_oaep(
    const uint8_t* ciphertext,
    size_t len,
    const RSAPrivateKey<BITS>& k,
    const OAEPParams& params
) {
    size_t key_len = BITS / 8;
    
    if (len != key_len) {
        throw std::invalid_argument("Invalid ciphertext length");
    }
    
    // Decrypt
    BigInt<BITS> c = os2ip<BITS>(ciphertext, len);
    BigInt<BITS> m = rsadp(c, k);
    auto em = i2osp(m, key_len);
    
    // Decode message
    return eme_oaep_decode(em.data(), key_len, params);
}

// ============================================================================
// RSAES-PKCS1-v1_5
// ============================================================================

template<size_t BITS>
std::vector<uint8_t> encrypt_pkcs1(
    const uint8_t* plaintext,
    size_t len,
    const RSAPublicKey<BITS>& k
) {
    size_t key_len = BITS / 8;
    
    // Encode message
    auto em = eme_pkcs1_encode(plaintext, len, key_len);
    
    // Convert to integer and encrypt
    BigInt<BITS> m = os2ip<BITS>(em.data(), key_len);
    BigInt<BITS> c = rsaep(m, k);
    
    return i2osp(c, key_len);
}

template<size_t BITS>
std::vector<uint8_t> decrypt_pkcs1(
    const uint8_t* ciphertext,
    size_t len,
    const RSAPrivateKey<BITS>& k
) {
    size_t key_len = BITS / 8;
    
    if (len != key_len) {
        throw std::invalid_argument("Invalid ciphertext length");
    }
    
    // Decrypt
    BigInt<BITS> c = os2ip<BITS>(ciphertext, len);
    BigInt<BITS> m = rsadp(c, k);
    auto em = i2osp(m, key_len);
    
    // Decode message
    return eme_pkcs1_decode(em.data(), key_len);
}

// ============================================================================
// Explicit Template Instantiations
// ============================================================================

template BigInt<2048> rsaep<2048>(const BigInt<2048>&, const RSAPublicKey<2048>&);
template BigInt<3072> rsaep<3072>(const BigInt<3072>&, const RSAPublicKey<3072>&);
template BigInt<4096> rsaep<4096>(const BigInt<4096>&, const RSAPublicKey<4096>&);

template BigInt<2048> rsadp<2048>(const BigInt<2048>&, const RSAPrivateKey<2048>&);
template BigInt<3072> rsadp<3072>(const BigInt<3072>&, const RSAPrivateKey<3072>&);
template BigInt<4096> rsadp<4096>(const BigInt<4096>&, const RSAPrivateKey<4096>&);

template BigInt<2048> os2ip<2048>(const uint8_t*, size_t);
template BigInt<3072> os2ip<3072>(const uint8_t*, size_t);
template BigInt<4096> os2ip<4096>(const uint8_t*, size_t);

template std::vector<uint8_t> i2osp<2048>(const BigInt<2048>&, size_t);
template std::vector<uint8_t> i2osp<3072>(const BigInt<3072>&, size_t);
template std::vector<uint8_t> i2osp<4096>(const BigInt<4096>&, size_t);

template BigInt<2048> rsadp_crt<2048>(const BigInt<2048>&, const RSAPrivateKey<2048>&);
template BigInt<3072> rsadp_crt<3072>(const BigInt<3072>&, const RSAPrivateKey<3072>&);
template BigInt<4096> rsadp_crt<4096>(const BigInt<4096>&, const RSAPrivateKey<4096>&);

template std::vector<uint8_t> encrypt_oaep<2048>(const uint8_t*, size_t, const RSAPublicKey<2048>&, const OAEPParams&);
template std::vector<uint8_t> encrypt_oaep<3072>(const uint8_t*, size_t, const RSAPublicKey<3072>&, const OAEPParams&);
template std::vector<uint8_t> encrypt_oaep<4096>(const uint8_t*, size_t, const RSAPublicKey<4096>&, const OAEPParams&);

template std::vector<uint8_t> decrypt_oaep<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&, const OAEPParams&);
template std::vector<uint8_t> decrypt_oaep<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&, const OAEPParams&);
template std::vector<uint8_t> decrypt_oaep<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&, const OAEPParams&);

template std::vector<uint8_t> encrypt_pkcs1<2048>(const uint8_t*, size_t, const RSAPublicKey<2048>&);
template std::vector<uint8_t> encrypt_pkcs1<3072>(const uint8_t*, size_t, const RSAPublicKey<3072>&);
template std::vector<uint8_t> encrypt_pkcs1<4096>(const uint8_t*, size_t, const RSAPublicKey<4096>&);

template std::vector<uint8_t> decrypt_pkcs1<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&);
template std::vector<uint8_t> decrypt_pkcs1<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&);
template std::vector<uint8_t> decrypt_pkcs1<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&);

} // namespace rsa
} // namespace kctsb
