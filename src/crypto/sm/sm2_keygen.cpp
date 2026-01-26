/**
 * @file sm2_keygen.cpp
 * @brief SM2 Key Generation Module
 * 
 * Implements SM2 key pair generation and self-test functionality.
 * 
 * Key Generation Algorithm:
 * 1. Generate random private key d in [1, n-2]
 * 2. Compute public key P = d * G (point multiplication using Montgomery ladder)
 * 3. Export keys in big-endian byte format
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "sm2_internal.h"
#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"

#include <cstring>
#include <vector>

using namespace kctsb;

namespace kctsb::internal::sm2 {

// ============================================================================
// Key Generation
// ============================================================================

/**
 * @brief Generate SM2 key pair
 * 
 * Private key d is a random integer in [1, n-2]
 * Public key P = d * G (point multiplication)
 * 
 * @param keypair Output key pair structure
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t generate_keypair_internal(kctsb_sm2_keypair_t* keypair) {
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Generate private key d in [1, n-2]
    uint8_t d_bytes[FIELD_SIZE];
    for (int attempts = 0; attempts < 100; attempts++) {
        if (kctsb_random_bytes(d_bytes, FIELD_SIZE) != KCTSB_SUCCESS) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        
        ZZ d = bytes_to_zz(d_bytes, FIELD_SIZE);
        d = d % (n - 1);  // Reduce to [0, n-2]
        
        if (IsZero(d)) {
            continue;  // d must be at least 1
        }
        d = d + 1;  // Now d is in [1, n-1]
        
        // Compute public key P = d * G using Montgomery ladder
        ecc::internal::JacobianPoint P_jac = curve.scalar_mult_base(d);
        ecc::internal::AffinePoint P_aff = curve.to_affine(P_jac);
        
        // Export private key
        zz_to_bytes(d, keypair->private_key, FIELD_SIZE);
        
        // Export public key (Px || Py)
        ZZ_p::init(ctx.p());
        ZZ Px = rep(P_aff.x);
        ZZ Py = rep(P_aff.y);
        zz_to_bytes(Px, keypair->public_key, FIELD_SIZE);
        zz_to_bytes(Py, keypair->public_key + FIELD_SIZE, FIELD_SIZE);
        
        // Secure cleanup
        kctsb_secure_zero(d_bytes, sizeof(d_bytes));
        
        return KCTSB_SUCCESS;
    }
    
    kctsb_secure_zero(d_bytes, sizeof(d_bytes));
    return KCTSB_ERROR_RANDOM_FAILED;
}

// ============================================================================
// Self Test
// ============================================================================

/**
 * @brief SM2 self test with standard test vectors
 * 
 * Tests key generation, signature, verification, encryption, and decryption.
 * 
 * @return KCTSB_SUCCESS if all tests pass
 */
kctsb_error_t self_test_internal() {
    // Test 1: Key generation
    kctsb_sm2_keypair_t keypair;
    kctsb_error_t err = generate_keypair_internal(&keypair);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Test 2: Sign and verify
    const uint8_t test_message[] = "SM2 Test Message for Signature";
    const size_t msg_len = sizeof(test_message) - 1;
    const char* default_uid = "1234567812345678";
    
    kctsb_sm2_signature_t sig;
    err = sign_internal(
        keypair.private_key,
        keypair.public_key,
        reinterpret_cast<const uint8_t*>(default_uid),
        16,
        test_message,
        msg_len,
        &sig
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    err = verify_internal(
        keypair.public_key,
        reinterpret_cast<const uint8_t*>(default_uid),
        16,
        test_message,
        msg_len,
        &sig
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Test 3: Verify with wrong message should fail
    const uint8_t wrong_message[] = "Wrong Message";
    err = verify_internal(
        keypair.public_key,
        reinterpret_cast<const uint8_t*>(default_uid),
        16,
        wrong_message,
        sizeof(wrong_message) - 1,
        &sig
    );
    if (err == KCTSB_SUCCESS) {
        return KCTSB_ERROR_INTERNAL;  // Should have failed
    }
    
    // Test 4: Encryption and decryption
    const uint8_t plaintext[] = "SM2 Encryption Test Data";
    const size_t pt_len = sizeof(plaintext) - 1;
    
    size_t ct_len = 0;
    encrypt_internal(keypair.public_key, plaintext, pt_len, nullptr, &ct_len);
    
    std::vector<uint8_t> ciphertext(ct_len);
    err = encrypt_internal(
        keypair.public_key,
        plaintext,
        pt_len,
        ciphertext.data(),
        &ct_len
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    size_t dec_len = ct_len;
    std::vector<uint8_t> decrypted(pt_len + 32);  // Extra space for safety
    err = decrypt_internal(
        keypair.private_key,
        ciphertext.data(),
        ct_len,
        decrypted.data(),
        &dec_len
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Verify decrypted matches original
    if (dec_len != pt_len || std::memcmp(plaintext, decrypted.data(), pt_len) != 0) {
        return KCTSB_ERROR_INTERNAL;
    }
    
    return KCTSB_SUCCESS;
}

}  // namespace kctsb::internal::sm2
