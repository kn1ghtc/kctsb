/**
 * @file sm2_api.cpp
 * @brief SM2 C API and C++ Class Implementation
 * 
 * Provides:
 * - C API (extern "C" functions) for interoperability
 * - C++ class wrappers (SM2KeyPair, SM2) for modern C++ usage
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
#include <stdexcept>

using namespace kctsb;

// ============================================================================
// C API Implementation (extern "C")
// ============================================================================

extern "C" {

kctsb_error_t kctsb_sm2_generate_keypair(kctsb_sm2_keypair_t* keypair) {
    if (keypair == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    return kctsb::internal::sm2::generate_keypair_internal(keypair);
}

kctsb_error_t kctsb_sm2_sign(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
) {
    if (private_key == nullptr || public_key == nullptr || 
        message == nullptr || signature == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Use default user ID if not provided
    const uint8_t* uid = user_id;
    size_t uid_len = user_id_len;
    const char* default_uid = "1234567812345678";
    if (uid == nullptr || uid_len == 0) {
        uid = reinterpret_cast<const uint8_t*>(default_uid);
        uid_len = 16;
    }
    
    return kctsb::internal::sm2::sign_internal(
        private_key, public_key, uid, uid_len,
        message, message_len, signature
    );
}

kctsb_error_t kctsb_sm2_verify(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
) {
    if (public_key == nullptr || message == nullptr || signature == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    const uint8_t* uid = user_id;
    size_t uid_len = user_id_len;
    const char* default_uid = "1234567812345678";
    if (uid == nullptr || uid_len == 0) {
        uid = reinterpret_cast<const uint8_t*>(default_uid);
        uid_len = 16;
    }
    
    return kctsb::internal::sm2::verify_internal(
        public_key, uid, uid_len, message, message_len, signature
    );
}

kctsb_error_t kctsb_sm2_encrypt(
    const uint8_t public_key[64],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
) {
    if (public_key == nullptr || plaintext == nullptr || ciphertext_len == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (plaintext_len == 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    return kctsb::internal::sm2::encrypt_internal(
        public_key, plaintext, plaintext_len, ciphertext, ciphertext_len
    );
}

kctsb_error_t kctsb_sm2_decrypt(
    const uint8_t private_key[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
) {
    if (private_key == nullptr || ciphertext == nullptr || plaintext_len == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    return kctsb::internal::sm2::decrypt_internal(
        private_key, ciphertext, ciphertext_len, plaintext, plaintext_len
    );
}

kctsb_error_t kctsb_sm2_self_test(void) {
    return kctsb::internal::sm2::self_test_internal();
}

}  // extern "C"

// ============================================================================
// C++ Class Implementation
// ============================================================================

namespace kctsb {

// ============================================================================
// SM2KeyPair Implementation
// ============================================================================

SM2KeyPair::SM2KeyPair() {
    std::memset(&keypair_, 0, sizeof(keypair_));
}

SM2KeyPair::SM2KeyPair(const ByteVec& privateKey) {
    if (privateKey.size() != KCTSB_SM2_PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("Invalid SM2 private key size");
    }
    
    std::memcpy(keypair_.private_key, privateKey.data(), KCTSB_SM2_PRIVATE_KEY_SIZE);
    
    // Derive public key from private key (using Montgomery ladder)
    auto& ctx = internal::sm2::SM2Context::instance();
    const auto& curve = ctx.curve();
    
    kctsb::ZZ d = internal::sm2::bytes_to_zz(keypair_.private_key, KCTSB_SM2_PRIVATE_KEY_SIZE);
    ecc::internal::JacobianPoint P_jac = curve.scalar_mult_base(d);
    ecc::internal::AffinePoint P_aff = curve.to_affine(P_jac);
    
    kctsb::ZZ_p::init(ctx.p());
    kctsb::ZZ Px = IsZero(P_aff.x) ? kctsb::ZZ(0) : rep(P_aff.x);
    kctsb::ZZ Py = IsZero(P_aff.y) ? kctsb::ZZ(0) : rep(P_aff.y);
    
    internal::sm2::zz_to_bytes(Px, keypair_.public_key, internal::sm2::FIELD_SIZE);
    internal::sm2::zz_to_bytes(Py, keypair_.public_key + internal::sm2::FIELD_SIZE, 
                               internal::sm2::FIELD_SIZE);
}

SM2KeyPair SM2KeyPair::generate() {
    SM2KeyPair kp;
    kctsb_error_t err = kctsb_sm2_generate_keypair(&kp.keypair_);
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 key generation failed");
    }
    return kp;
}

ByteVec SM2KeyPair::getPrivateKey() const {
    return ByteVec(keypair_.private_key, 
                   keypair_.private_key + KCTSB_SM2_PRIVATE_KEY_SIZE);
}

ByteVec SM2KeyPair::getPublicKey() const {
    return ByteVec(keypair_.public_key, 
                   keypair_.public_key + KCTSB_SM2_PUBLIC_KEY_SIZE);
}

// ============================================================================
// SM2 Class Static Methods
// ============================================================================

ByteVec SM2::sign(
    const SM2KeyPair& keypair,
    const ByteVec& message,
    const std::string& userId
) {
    kctsb_sm2_signature_t sig;
    ByteVec priv = keypair.getPrivateKey();
    ByteVec pub = keypair.getPublicKey();
    
    kctsb_error_t err = kctsb_sm2_sign(
        priv.data(),
        pub.data(),
        reinterpret_cast<const uint8_t*>(userId.data()),
        userId.size(),
        message.data(),
        message.size(),
        &sig
    );
    
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 signing failed");
    }
    
    ByteVec result(KCTSB_SM2_SIGNATURE_SIZE);
    std::memcpy(result.data(), sig.r, 32);
    std::memcpy(result.data() + 32, sig.s, 32);
    return result;
}

bool SM2::verify(
    const ByteVec& publicKey,
    const ByteVec& message,
    const ByteVec& signature,
    const std::string& userId
) {
    if (publicKey.size() != KCTSB_SM2_PUBLIC_KEY_SIZE ||
        signature.size() != KCTSB_SM2_SIGNATURE_SIZE) {
        return false;
    }
    
    kctsb_sm2_signature_t sig;
    std::memcpy(sig.r, signature.data(), 32);
    std::memcpy(sig.s, signature.data() + 32, 32);
    
    kctsb_error_t err = kctsb_sm2_verify(
        publicKey.data(),
        reinterpret_cast<const uint8_t*>(userId.data()),
        userId.size(),
        message.data(),
        message.size(),
        &sig
    );
    
    return err == KCTSB_SUCCESS;
}

ByteVec SM2::encrypt(const ByteVec& publicKey, const ByteVec& plaintext) {
    if (publicKey.size() != KCTSB_SM2_PUBLIC_KEY_SIZE) {
        throw std::invalid_argument("Invalid public key size");
    }
    
    // Get required output size
    size_t ct_len = 0;
    kctsb_sm2_encrypt(publicKey.data(), plaintext.data(), plaintext.size(), 
                      nullptr, &ct_len);
    
    ByteVec ciphertext(ct_len);
    kctsb_error_t err = kctsb_sm2_encrypt(
        publicKey.data(),
        plaintext.data(),
        plaintext.size(),
        ciphertext.data(),
        &ct_len
    );
    
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 encryption failed");
    }
    
    ciphertext.resize(ct_len);
    return ciphertext;
}

ByteVec SM2::decrypt(const ByteVec& privateKey, const ByteVec& ciphertext) {
    if (privateKey.size() != KCTSB_SM2_PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("Invalid private key size");
    }
    
    // Get required output size
    size_t pt_len = 0;
    kctsb_sm2_decrypt(privateKey.data(), ciphertext.data(), ciphertext.size(),
                      nullptr, &pt_len);
    
    ByteVec plaintext(pt_len);
    kctsb_error_t err = kctsb_sm2_decrypt(
        privateKey.data(),
        ciphertext.data(),
        ciphertext.size(),
        plaintext.data(),
        &pt_len
    );
    
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 decryption failed");
    }
    
    plaintext.resize(pt_len);
    return plaintext;
}

}  // namespace kctsb
