/**
 * @file rsa_sign.cpp
 * @brief RSA Signature Implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/rsa/rsa_sign.h"
#include "kctsb/crypto/rsa/rsa_encrypt.h" // For i2osp, os2ip
#include "kctsb/crypto/rsa/rsa_padding.h"
#include <stdexcept>

namespace kctsb {
namespace rsa {

// ============================================================================
// RSA Signature Primitives
// ============================================================================

template<size_t BITS>
BigInt<BITS> rsasp1(const BigInt<BITS>& m, const RSAPrivateKey<BITS>& k) {
    if (m >= k.n) {
        throw std::invalid_argument("Message representative out of range");
    }
    MontgomeryContext<BITS> mont(k.n);
    return mont.pow_mod(m, k.d);
}

template<size_t BITS>
BigInt<BITS> rsavp1(const BigInt<BITS>& s, const RSAPublicKey<BITS>& k) {
    if (s >= k.n) {
        throw std::invalid_argument("Signature representative out of range");
    }
    MontgomeryContext<BITS> mont(k.n);
    return mont.pow_mod(s, k.e);
}

// ============================================================================
// RSASSA-PSS
// ============================================================================

template<size_t BITS>
std::vector<uint8_t> sign_pss(
    const uint8_t* mHash,
    size_t hlen,
    const RSAPrivateKey<BITS>& k,
    const PSSParams& params
) {
    size_t key_len = BITS / 8;
    size_t em_bits = BITS - 1; // modBits - 1
    
    // Encode message
    auto em = emsa_pss_encode(mHash, hlen, em_bits, params);
    
    // Convert to integer and sign
    BigInt<BITS> m = os2ip<BITS>(em.data(), em.size());
    BigInt<BITS> s = rsasp1(m, k);
    
    return i2osp(s, key_len);
}

template<size_t BITS>
bool verify_pss(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* sig,
    size_t sigLen,
    const RSAPublicKey<BITS>& k,
    const PSSParams& params
) {
    size_t key_len = BITS / 8;
    
    if (sigLen != key_len) {
        return false;
    }
    
    // Verify signature
    BigInt<BITS> s = os2ip<BITS>(sig, sigLen);
    
    // Catch exception if signature is invalid
    try {
        BigInt<BITS> m = rsavp1(s, k);
        auto em = i2osp(m, key_len);
        
        size_t em_bits = BITS - 1;
        return emsa_pss_verify(mHash, hlen, em.data(), em_bits, params);
    } catch (...) {
        return false;
    }
}

// ============================================================================
// RSASSA-PKCS1-v1_5
// ============================================================================

template<size_t BITS>
std::vector<uint8_t> sign_pkcs1(
    const uint8_t* mHash,
    size_t hlen,
    const RSAPrivateKey<BITS>& k
) {
    size_t key_len = BITS / 8;
    
    // Encode message
    auto em = emsa_pkcs1_encode(mHash, hlen, key_len);
    
    // Convert to integer and sign
    BigInt<BITS> m = os2ip<BITS>(em.data(), key_len);
    BigInt<BITS> s = rsasp1(m, k);
    
    return i2osp(s, key_len);
}

template<size_t BITS>
bool verify_pkcs1(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* sig,
    size_t sigLen,
    const RSAPublicKey<BITS>& k
) {
    size_t key_len = BITS / 8;
    
    if (sigLen != key_len) {
        return false;
    }
    
    try {
        BigInt<BITS> s = os2ip<BITS>(sig, sigLen);
        BigInt<BITS> m = rsavp1(s, k);
        auto em = i2osp(m, key_len);
        
        return emsa_pkcs1_verify(mHash, hlen, em.data(), key_len);
    } catch (...) {
        return false;
    }
}

// ============================================================================
// Explicit Template Instantiations
// ============================================================================

template BigInt<2048> rsasp1<2048>(const BigInt<2048>&, const RSAPrivateKey<2048>&);
template BigInt<3072> rsasp1<3072>(const BigInt<3072>&, const RSAPrivateKey<3072>&);
template BigInt<4096> rsasp1<4096>(const BigInt<4096>&, const RSAPrivateKey<4096>&);

template BigInt<2048> rsavp1<2048>(const BigInt<2048>&, const RSAPublicKey<2048>&);
template BigInt<3072> rsavp1<3072>(const BigInt<3072>&, const RSAPublicKey<3072>&);
template BigInt<4096> rsavp1<4096>(const BigInt<4096>&, const RSAPublicKey<4096>&);

template std::vector<uint8_t> sign_pss<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&, const PSSParams&);
template std::vector<uint8_t> sign_pss<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&, const PSSParams&);
template std::vector<uint8_t> sign_pss<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&, const PSSParams&);

template bool verify_pss<2048>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<2048>&, const PSSParams&);
template bool verify_pss<3072>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<3072>&, const PSSParams&);
template bool verify_pss<4096>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<4096>&, const PSSParams&);

template std::vector<uint8_t> sign_pkcs1<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&);
template std::vector<uint8_t> sign_pkcs1<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&);
template std::vector<uint8_t> sign_pkcs1<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&);

template bool verify_pkcs1<2048>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<2048>&);
template bool verify_pkcs1<3072>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<3072>&);
template bool verify_pkcs1<4096>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<4096>&);

} // namespace rsa
} // namespace kctsb
