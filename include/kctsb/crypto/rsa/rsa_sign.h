/**
 * @file rsa_sign.h
 * @brief RSA Signature Operations
 * 
 * Implements RSA signature primitives and schemes:
 * - RSASP1/RSAVP1 (raw RSA signature primitives)
 * - RSASSA-PSS (recommended for signatures)
 * - RSASSA-PKCS1-v1_5 (legacy compatibility)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_SIGN_H
#define KCTSB_CRYPTO_RSA_SIGN_H

#include "kctsb/crypto/rsa/rsa_types.h"
#include "kctsb/core/bigint.h"
#include <vector>
#include <cstdint>

namespace kctsb {
namespace rsa {

// ============================================================================
// RSA Signature Primitives (RSASP1/RSAVP1)
// ============================================================================

/**
 * @brief RSA Signature Primitive (RSASP1)
 * @tparam BITS Key size in bits
 * @param m Message representative (0 <= m < n)
 * @param k Private key
 * @return Signature representative s = m^d mod n
 * @throws std::invalid_argument if m >= n
 */
template<size_t BITS>
BigInt<BITS> rsasp1(const BigInt<BITS>& m, const RSAPrivateKey<BITS>& k);

/**
 * @brief RSA Verification Primitive (RSAVP1)
 * @tparam BITS Key size in bits
 * @param s Signature representative (0 <= s < n)
 * @param k Public key
 * @return Message representative m = s^e mod n
 * @throws std::invalid_argument if s >= n
 */
template<size_t BITS>
BigInt<BITS> rsavp1(const BigInt<BITS>& s, const RSAPublicKey<BITS>& k);

// ============================================================================
// RSASSA-PSS (Recommended)
// ============================================================================

/**
 * @brief RSASSA-PSS signature generation (RFC 8017 Section 8.1)
 * @tparam BITS Key size in bits
 * @param mHash Message hash (pre-computed)
 * @param hlen Hash length in bytes
 * @param k Private key
 * @param params PSS parameters
 * @return Signature
 * @throws std::invalid_argument if hash length invalid
 */
template<size_t BITS>
std::vector<uint8_t> sign_pss(
    const uint8_t* mHash,
    size_t hlen,
    const RSAPrivateKey<BITS>& k,
    const PSSParams& params = PSSParams()
);

/**
 * @brief RSASSA-PSS signature verification (RFC 8017 Section 8.1)
 * @tparam BITS Key size in bits
 * @param mHash Message hash
 * @param hlen Hash length
 * @param sig Signature to verify
 * @param sigLen Signature length
 * @param k Public key
 * @param params PSS parameters
 * @return true if signature is valid
 */
template<size_t BITS>
bool verify_pss(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* sig,
    size_t sigLen,
    const RSAPublicKey<BITS>& k,
    const PSSParams& params = PSSParams()
);

// ============================================================================
// RSASSA-PKCS1-v1_5 (Legacy)
// ============================================================================

/**
 * @brief RSASSA-PKCS1-v1_5 signature generation (RFC 8017 Section 8.2)
 * @tparam BITS Key size in bits
 * @param mHash Message hash
 * @param hlen Hash length
 * @param k Private key
 * @return Signature
 */
template<size_t BITS>
std::vector<uint8_t> sign_pkcs1(
    const uint8_t* mHash,
    size_t hlen,
    const RSAPrivateKey<BITS>& k
);

/**
 * @brief RSASSA-PKCS1-v1_5 signature verification (RFC 8017 Section 8.2)
 * @tparam BITS Key size in bits
 * @param mHash Message hash
 * @param hlen Hash length
 * @param sig Signature
 * @param sigLen Signature length
 * @param k Public key
 * @return true if signature is valid
 */
template<size_t BITS>
bool verify_pkcs1(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* sig,
    size_t sigLen,
    const RSAPublicKey<BITS>& k
);

// ============================================================================
// Explicit Template Instantiations (declared here, defined in .cpp)
// ============================================================================

extern template BigInt<2048> rsasp1<2048>(const BigInt<2048>&, const RSAPrivateKey<2048>&);
extern template BigInt<3072> rsasp1<3072>(const BigInt<3072>&, const RSAPrivateKey<3072>&);
extern template BigInt<4096> rsasp1<4096>(const BigInt<4096>&, const RSAPrivateKey<4096>&);

extern template BigInt<2048> rsavp1<2048>(const BigInt<2048>&, const RSAPublicKey<2048>&);
extern template BigInt<3072> rsavp1<3072>(const BigInt<3072>&, const RSAPublicKey<3072>&);
extern template BigInt<4096> rsavp1<4096>(const BigInt<4096>&, const RSAPublicKey<4096>&);

extern template std::vector<uint8_t> sign_pss<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&, const PSSParams&);
extern template std::vector<uint8_t> sign_pss<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&, const PSSParams&);
extern template std::vector<uint8_t> sign_pss<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&, const PSSParams&);

extern template bool verify_pss<2048>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<2048>&, const PSSParams&);
extern template bool verify_pss<3072>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<3072>&, const PSSParams&);
extern template bool verify_pss<4096>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<4096>&, const PSSParams&);

extern template std::vector<uint8_t> sign_pkcs1<2048>(const uint8_t*, size_t, const RSAPrivateKey<2048>&);
extern template std::vector<uint8_t> sign_pkcs1<3072>(const uint8_t*, size_t, const RSAPrivateKey<3072>&);
extern template std::vector<uint8_t> sign_pkcs1<4096>(const uint8_t*, size_t, const RSAPrivateKey<4096>&);

extern template bool verify_pkcs1<2048>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<2048>&);
extern template bool verify_pkcs1<3072>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<3072>&);
extern template bool verify_pkcs1<4096>(const uint8_t*, size_t, const uint8_t*, size_t, const RSAPublicKey<4096>&);

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_SIGN_H
