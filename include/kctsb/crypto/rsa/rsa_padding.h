/**
 * @file rsa_padding.h
 * @brief RSA Padding Schemes (OAEP, PSS)
 * 
 * Implements:
 * - EME-OAEP encoding/decoding (RSAES-OAEP)
 * - EMSA-PSS encoding/verification (RSASSA-PSS)
 * - MGF1 mask generation function
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_PADDING_H
#define KCTSB_CRYPTO_RSA_PADDING_H

#include "kctsb/crypto/rsa/rsa_types.h"
#include <vector>
#include <cstdint>

namespace kctsb {
namespace rsa {

// ============================================================================
// MGF1 (Mask Generation Function)
// ============================================================================

/**
 * @brief MGF1 mask generation function (RFC 8017 Appendix B.2.1)
 * @param seed Input seed
 * @param seed_len Seed length in bytes
 * @param mask_len Desired mask length in bytes
 * @param params OAEP parameters (specifies hash function)
 * @return Generated mask
 */
std::vector<uint8_t> mgf1(
    const uint8_t* seed,
    size_t seed_len,
    size_t mask_len,
    const OAEPParams& params
);

// ============================================================================
// EME-OAEP Encoding/Decoding
// ============================================================================

/**
 * @brief EME-OAEP encoding operation (RFC 8017 Section 7.1.1)
 * @param message Message to encode
 * @param msg_len Message length in bytes
 * @param em_len Encoded message length (key_bytes)
 * @param params OAEP parameters
 * @return Encoded message EM
 * @throws std::invalid_argument if message too long
 */
std::vector<uint8_t> eme_oaep_encode(
    const uint8_t* message,
    size_t msg_len,
    size_t em_len,
    const OAEPParams& params = OAEPParams()
);

/**
 * @brief EME-OAEP decoding operation (RFC 8017 Section 7.1.2)
 * @param em Encoded message
 * @param em_len Encoded message length
 * @param params OAEP parameters
 * @return Decoded message
 * @throws std::runtime_error if decoding fails
 */
std::vector<uint8_t> eme_oaep_decode(
    const uint8_t* em,
    size_t em_len,
    const OAEPParams& params = OAEPParams()
);

// ============================================================================
// EMSA-PSS Encoding/Verification
// ============================================================================

/**
 * @brief EMSA-PSS encoding operation (RFC 8017 Section 9.1.1)
 * @param mHash Message hash
 * @param hlen Hash length in bytes
 * @param em_bits Maximal bit length of encoded message (modBits - 1)
 * @param params PSS parameters
 * @return Encoded message EM
 * @throws std::invalid_argument if encoding fails
 */
std::vector<uint8_t> emsa_pss_encode(
    const uint8_t* mHash,
    size_t hlen,
    size_t em_bits,
    const PSSParams& params = PSSParams()
);

/**
 * @brief EMSA-PSS verification operation (RFC 8017 Section 9.1.2)
 * @param mHash Message hash
 * @param hlen Hash length in bytes
 * @param em Encoded message
 * @param em_bits Maximal bit length of encoded message
 * @param params PSS parameters
 * @return true if verification succeeds
 */
bool emsa_pss_verify(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* em,
    size_t em_bits,
    const PSSParams& params = PSSParams()
);

// ============================================================================
// PKCS#1 v1.5 Padding (for compatibility)
// ============================================================================

/**
 * @brief RSAES-PKCS1-v1_5 encoding (RFC 8017 Section 7.2.1)
 * @param message Message to encode
 * @param msg_len Message length
 * @param em_len Encoded message length (key_bytes)
 * @return Encoded message EM
 * @throws std::invalid_argument if message too long
 */
std::vector<uint8_t> eme_pkcs1_encode(
    const uint8_t* message,
    size_t msg_len,
    size_t em_len
);

/**
 * @brief RSAES-PKCS1-v1_5 decoding (RFC 8017 Section 7.2.2)
 * @param em Encoded message
 * @param em_len Encoded message length
 * @return Decoded message
 * @throws std::runtime_error if decoding fails
 */
std::vector<uint8_t> eme_pkcs1_decode(
    const uint8_t* em,
    size_t em_len
);

/**
 * @brief EMSA-PKCS1-v1_5 encoding for signatures (RFC 8017 Section 9.2)
 * @param mHash Message hash
 * @param hlen Hash length
 * @param em_len Encoded message length (key_bytes)
 * @return Encoded message EM
 */
std::vector<uint8_t> emsa_pkcs1_encode(
    const uint8_t* mHash,
    size_t hlen,
    size_t em_len
);

/**
 * @brief EMSA-PKCS1-v1_5 verification
 * @param mHash Message hash
 * @param hlen Hash length
 * @param em Encoded message
 * @param em_len Encoded message length
 * @return true if verification succeeds
 */
bool emsa_pkcs1_verify(
    const uint8_t* mHash,
    size_t hlen,
    const uint8_t* em,
    size_t em_len
);

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_PADDING_H
