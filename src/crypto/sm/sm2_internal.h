/**
 * @file sm2_internal.h
 * @brief SM2 Internal Shared Definitions
 * 
 * Shared definitions for SM2 module split files:
 * - sm2_curve.cpp: Curve parameters and context
 * - sm2_utils.cpp: Utility functions
 * - sm2_keygen.cpp: Key generation
 * - sm2_sign.cpp: Digital signature
 * - sm2_encrypt.cpp: Public key encryption
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_SM2_INTERNAL_H
#define KCTSB_SM2_INTERNAL_H

#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"
#include "kctsb/core/common.h"

#include <kctsb/math/bignum/ZZ.h>
#include <kctsb/math/bignum/ZZ_p.h>

#include <cstring>
#include <array>
#include <vector>
#include <stdexcept>

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

// ============================================================================
// Constants
// ============================================================================

namespace kctsb::internal::sm2 {

// Field size in bytes (256-bit = 32 bytes)
constexpr size_t FIELD_SIZE = 32;

// SM2 signature and encryption constants
constexpr size_t SIGNATURE_SIZE = 64;  // r (32) + s (32)
constexpr size_t MAX_HASH_SIZE = 32;   // SM3 output

// ============================================================================
// SM2 Context (defined in sm2_curve.cpp)
// ============================================================================

/**
 * @brief SM2 internal context for curve operations
 * Singleton instance with cached curve parameters
 */
class SM2Context {
public:
    SM2Context() : curve_(ecc::internal::CurveType::SM2) {
        // Cache curve parameters
        n_ = curve_.get_order();
        p_ = curve_.get_prime();
        bit_size_ = curve_.get_bit_size();
    }
    
    /**
     * @brief Get singleton instance
     */
    static SM2Context& instance() {
        static SM2Context ctx;
        return ctx;
    }
    
    const ecc::internal::ECCurve& curve() const { return curve_; }
    const ZZ& n() const { return n_; }
    const ZZ& p() const { return p_; }
    int bit_size() const { return bit_size_; }
    
private:
    ecc::internal::ECCurve curve_;
    ZZ n_;
    ZZ p_;
    int bit_size_;
};

// ============================================================================
// Utility Functions (defined in sm2_utils.cpp)
// ============================================================================

/**
 * @brief Convert byte array to bignum ZZ (big-endian)
 */
ZZ bytes_to_zz(const uint8_t* data, size_t len);

/**
 * @brief Convert bignum ZZ to byte array (big-endian, fixed length)
 */
void zz_to_bytes(const ZZ& z, uint8_t* out, size_t len);

/**
 * @brief Compute Z value for SM2 (user identification hash)
 * Z = SM3(ENTL || user_id || a || b || Gx || Gy || Px || Py)
 */
kctsb_error_t compute_z_value(
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* public_key,
    uint8_t z_value[32]
);

/**
 * @brief Generate random k for signature (must be in [1, n-1])
 */
kctsb_error_t generate_random_k(ZZ& k, const ZZ& n);

// ============================================================================
// Key Generation (defined in sm2_keygen.cpp)
// ============================================================================

/**
 * @brief Generate SM2 key pair
 */
kctsb_error_t generate_keypair_internal(kctsb_sm2_keypair_t* keypair);

// ============================================================================
// Digital Signature (defined in sm2_sign.cpp)
// ============================================================================

/**
 * @brief SM2 digital signature (internal)
 */
kctsb_error_t sign_internal(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
);

/**
 * @brief SM2 signature verification (internal)
 */
kctsb_error_t verify_internal(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
);

// ============================================================================
// Public Key Encryption (defined in sm2_encrypt.cpp)
// ============================================================================

/**
 * @brief Key Derivation Function (KDF) - SM3 based
 */
kctsb_error_t sm2_kdf(
    const uint8_t* z,
    size_t z_len,
    size_t klen,
    uint8_t* key
);

/**
 * @brief SM2 public key encryption (internal)
 */
kctsb_error_t encrypt_internal(
    const uint8_t public_key[64],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
);

/**
 * @brief SM2 private key decryption (internal)
 */
kctsb_error_t decrypt_internal(
    const uint8_t private_key[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
);

// ============================================================================
// Self Test (defined in sm2_keygen.cpp or separate file)
// ============================================================================

/**
 * @brief SM2 self test with standard test vectors
 */
kctsb_error_t self_test_internal();

}  // namespace kctsb::internal::sm2

#endif  // KCTSB_SM2_INTERNAL_H
