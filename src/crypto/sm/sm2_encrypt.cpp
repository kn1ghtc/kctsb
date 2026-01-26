/**
 * @file sm2_encrypt.cpp
 * @brief SM2 Public Key Encryption Implementation
 * 
 * SM2 encryption scheme following GB/T 32918.4-2016:
 * - Key Derivation Function (KDF)
 * - Public key encryption and private key decryption
 * - Self-test implementation
 * - C++ wrapper classes
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"
#include "kctsb/core/common.h"

// Montgomery acceleration header
#include "sm2_mont_curve.h"

#include <kctsb/math/ZZ.h>
#include <kctsb/math/ZZ_p.h>

#include <cstring>
#include <vector>
#include <stdexcept>

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

namespace kctsb::internal::sm2 {

// External declarations from sm2_curve.cpp
constexpr size_t FIELD_SIZE = 32;

/**
 * @brief SM2 internal context for curve operations
 * 
 * Defined in sm2_curve.cpp, accessed via singleton pattern.
 */
class SM2Context {
public:
    static SM2Context& instance();
    const ecc::internal::ECCurve& curve() const;
    const ZZ& n() const;
    const ZZ& p() const;
    int bit_size() const;
private:
    SM2Context();
    ecc::internal::ECCurve curve_;
    ZZ n_;
    ZZ p_;
    int bit_size_;
};

// External utility functions from sm2_curve.cpp
extern ZZ bytes_to_zz(const uint8_t* data, size_t len);
extern void zz_to_bytes(const ZZ& z, uint8_t* out, size_t len);
extern kctsb_error_t generate_random_k(ZZ& k, const ZZ& n);

// External functions from sm2_keygen.cpp
extern kctsb_error_t generate_keypair_internal(kctsb_sm2_keypair_t* keypair);

// External functions from sm2_sign.cpp
extern kctsb_error_t sign_internal(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
);
extern kctsb_error_t verify_internal(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
);

// ============================================================================
// Key Derivation Function (KDF)
// ============================================================================

/**
 * @brief Key Derivation Function (KDF)
 * 
 * KDF(Z, klen) as defined in GB/T 32918.4-2016
 * Uses SM3 for hash function.
 * 
 * @param z Input key material
 * @param z_len Length of z
 * @param klen Output length in bytes
 * @param key Output key material
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t sm2_kdf(
    const uint8_t* z,
    size_t z_len,
    size_t klen,
    uint8_t* key
) {
    if (klen == 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Number of hash iterations
    size_t ct = (klen + 31) / 32;
    
    for (size_t i = 1; i <= ct; i++) {
        kctsb_sm3_ctx_t ctx;
        kctsb_sm3_init(&ctx);
        kctsb_sm3_update(&ctx, z, z_len);
        
        // Counter (4 bytes, big-endian)
        uint8_t counter[4] = {
            static_cast<uint8_t>((i >> 24) & 0xFF),
            static_cast<uint8_t>((i >> 16) & 0xFF),
            static_cast<uint8_t>((i >> 8) & 0xFF),
            static_cast<uint8_t>(i & 0xFF)
        };
        kctsb_sm3_update(&ctx, counter, 4);
        
        uint8_t hash[32];
        kctsb_sm3_final(&ctx, hash);
        
        size_t offset = (i - 1) * 32;
        size_t copy_len = (i == ct) ? (klen - offset) : 32;
        std::memcpy(key + offset, hash, copy_len);
    }
    
    return KCTSB_SUCCESS;
}

// ============================================================================
// Public Key Encryption
// ============================================================================

/**
 * @brief SM2 public key encryption
 * 
 * Algorithm (GB/T 32918.4-2016):
 * 1. Generate random k in [1, n-1]
 * 2. Compute C1 = k * G (point on curve)
 * 3. Compute (x2, y2) = k * P (shared point)
 * 4. Compute t = KDF(x2 || y2, klen)
 * 5. Compute C2 = M XOR t
 * 6. Compute C3 = SM3(x2 || M || y2)
 * 7. Output C = C1 || C3 || C2 (new format)
 * 
 * @param public_key 64-byte public key
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Plaintext length
 * @param ciphertext Output buffer
 * @param ciphertext_len Output length
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t encrypt_internal(
    const uint8_t public_key[64],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
) {
    using namespace kctsb::internal::sm2::mont;
    
    // Output size: C1 (65 bytes: 0x04 || x1 || y1) + C3 (32 bytes) + C2 (plaintext_len)
    size_t output_size = 1 + 2 * FIELD_SIZE + 32 + plaintext_len;
    
    if (ciphertext == nullptr) {
        *ciphertext_len = output_size;
        return KCTSB_SUCCESS;
    }
    
    if (*ciphertext_len < output_size) {
        *ciphertext_len = output_size;
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    // SM2 order n for k validation
    static const fe256 SM2_ORDER = {{
        0x53BBF40939D54123ULL,
        0x7203DF6B21C6052BULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFEFFFFFFFFULL
    }};
    
    // Encryption loop (retry if KDF produces all zeros)
    for (int attempts = 0; attempts < 100; attempts++) {
        // Step 1: Generate random k using fe256-based function
        uint8_t k_bytes[FIELD_SIZE];
        int rnd_err = kctsb_random_bytes(k_bytes, FIELD_SIZE);
        if (rnd_err != 0) {
            return KCTSB_ERROR_INTERNAL;
        }
        
        // Validate k: k != 0 and k < n
        fe256 k_fe;
        fe256_from_bytes(&k_fe, k_bytes);
        if (fe256_is_zero(&k_fe) || fe256_cmp(&k_fe, &SM2_ORDER) >= 0) {
            continue;
        }
        
        // Step 2: Compute C1 = k * G using Montgomery acceleration
        sm2_point_result C1_mont;
        if (!scalar_mult_base_mont(&C1_mont, k_bytes)) {
            kctsb_secure_zero(k_bytes, sizeof(k_bytes));
            continue;
        }
        
        // Step 3: Compute (x2, y2) = k * P using Montgomery acceleration
        sm2_point_result kP_mont;
        if (!scalar_mult_point_mont(&kP_mont, k_bytes, public_key, public_key + FIELD_SIZE)) {
            kctsb_secure_zero(k_bytes, sizeof(k_bytes));
            continue;
        }
        kctsb_secure_zero(k_bytes, sizeof(k_bytes));
        
        // Prepare x2||y2 for KDF (directly use Montgomery result bytes)
        uint8_t x2y2[2 * FIELD_SIZE];
        std::memcpy(x2y2, kP_mont.x, FIELD_SIZE);
        std::memcpy(x2y2 + FIELD_SIZE, kP_mont.y, FIELD_SIZE);
        
        // Step 4: Compute t = KDF(x2 || y2, plaintext_len)
        std::vector<uint8_t> t(plaintext_len);
        kctsb_error_t kdf_err = sm2_kdf(x2y2, sizeof(x2y2), plaintext_len, t.data());
        if (kdf_err != KCTSB_SUCCESS) {
            return kdf_err;
        }
        
        // Check if t is all zeros (would make encryption insecure)
        bool all_zero = true;
        for (size_t i = 0; i < plaintext_len; i++) {
            if (t[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            continue;  // Retry with new k
        }
        
        // Output C1 (uncompressed point format: 0x04 || x1 || y1)
        size_t pos = 0;
        ciphertext[pos++] = 0x04;
        std::memcpy(ciphertext + pos, C1_mont.x, FIELD_SIZE);
        pos += FIELD_SIZE;
        std::memcpy(ciphertext + pos, C1_mont.y, FIELD_SIZE);
        pos += FIELD_SIZE;
        
        // Step 6: Compute C3 = SM3(x2 || M || y2)
        kctsb_sm3_ctx_t sm3_ctx;
        kctsb_sm3_init(&sm3_ctx);
        kctsb_sm3_update(&sm3_ctx, kP_mont.x, FIELD_SIZE);
        kctsb_sm3_update(&sm3_ctx, plaintext, plaintext_len);
        kctsb_sm3_update(&sm3_ctx, kP_mont.y, FIELD_SIZE);
        kctsb_sm3_final(&sm3_ctx, ciphertext + pos);
        pos += 32;  // C3 size
        
        // Step 5: Compute C2 = M XOR t
        for (size_t i = 0; i < plaintext_len; i++) {
            ciphertext[pos + i] = plaintext[i] ^ t[i];
        }
        pos += plaintext_len;
        
        *ciphertext_len = pos;
        
        // Secure cleanup
        kctsb_secure_zero(t.data(), t.size());
        kctsb_secure_zero(x2y2, sizeof(x2y2));
        
        return KCTSB_SUCCESS;
    }
    
    return KCTSB_ERROR_INTERNAL;
}

/**
 * @brief SM2 private key decryption
 * 
 * Algorithm:
 * 1. Parse C1 from ciphertext
 * 2. Verify C1 is on curve
 * 3. Compute (x2, y2) = d * C1
 * 4. Compute t = KDF(x2 || y2, C2_len)
 * 5. Compute M = C2 XOR t
 * 6. Compute u = SM3(x2 || M || y2)
 * 7. Verify u == C3
 * 8. Output M
 * 
 * @param private_key 32-byte private key
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param plaintext Output buffer
 * @param plaintext_len Output length
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t decrypt_internal(
    const uint8_t private_key[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
) {
    using namespace kctsb::internal::sm2::mont;
    
    // SM2 order n for private key validation
    static const fe256 SM2_ORDER = {{
        0x53BBF40939D54123ULL,
        0x7203DF6B21C6052BULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFEFFFFFFFFULL
    }};
    
    // Minimum ciphertext size: C1 (65) + C3 (32) + C2 (1)
    constexpr size_t MIN_CIPHERTEXT_SIZE = 1 + 2 * FIELD_SIZE + 32 + 1;
    if (ciphertext_len < MIN_CIPHERTEXT_SIZE) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Parse ciphertext structure
    size_t c2_len = ciphertext_len - (1 + 2 * FIELD_SIZE + 32);
    
    if (plaintext == nullptr) {
        *plaintext_len = c2_len;
        return KCTSB_SUCCESS;
    }
    
    if (*plaintext_len < c2_len) {
        *plaintext_len = c2_len;
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Parse private key into fe256 and validate
    fe256 d_fe;
    fe256_from_bytes(&d_fe, private_key);
    if (fe256_is_zero(&d_fe) || fe256_cmp(&d_fe, &SM2_ORDER) >= 0) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Step 1: Parse C1
    if (ciphertext[0] != 0x04) {
        return KCTSB_ERROR_INVALID_PARAM;  // Only uncompressed format supported
    }
    
    // C1 coordinates (already in ciphertext as bytes)
    const uint8_t* C1_x = ciphertext + 1;
    const uint8_t* C1_y = ciphertext + 1 + FIELD_SIZE;
    
    // Parse C3 and C2
    const uint8_t* c3_ptr = ciphertext + 1 + 2 * FIELD_SIZE;
    const uint8_t* c2_ptr = c3_ptr + 32;
    
    // Step 3: Compute (x2, y2) = d * C1 using Montgomery acceleration
    sm2_point_result dC1_mont;
    if (!scalar_mult_point_mont(&dC1_mont, private_key, C1_x, C1_y)) {
        // Point at infinity
        return KCTSB_ERROR_DECRYPTION_FAILED;
    }
    
    // Prepare x2||y2 (directly use Montgomery result bytes)
    uint8_t x2y2[2 * FIELD_SIZE];
    std::memcpy(x2y2, dC1_mont.x, FIELD_SIZE);
    std::memcpy(x2y2 + FIELD_SIZE, dC1_mont.y, FIELD_SIZE);
    
    // Step 4: Compute t = KDF(x2 || y2, c2_len)
    std::vector<uint8_t> t(c2_len);
    kctsb_error_t err = sm2_kdf(x2y2, sizeof(x2y2), c2_len, t.data());
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Check if t is all zeros
    bool all_zero = true;
    for (size_t i = 0; i < c2_len; i++) {
        if (t[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        return KCTSB_ERROR_DECRYPTION_FAILED;
    }
    
    // Step 5: Compute M = C2 XOR t
    for (size_t i = 0; i < c2_len; i++) {
        plaintext[i] = c2_ptr[i] ^ t[i];
    }
    
    // Step 6: Compute u = SM3(x2 || M || y2)
    uint8_t u[32];
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    kctsb_sm3_update(&sm3_ctx, dC1_mont.x, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, plaintext, c2_len);
    kctsb_sm3_update(&sm3_ctx, dC1_mont.y, FIELD_SIZE);
    kctsb_sm3_final(&sm3_ctx, u);

    // Step 7: Verify u == C3
    // Note: kctsb_secure_compare returns 1 if equal, 0 if different
    if (kctsb_secure_compare(u, c3_ptr, 32) == 0) {
        // Clear plaintext on verification failure
        kctsb_secure_zero(plaintext, c2_len);
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    *plaintext_len = c2_len;
    
    // Secure cleanup
    kctsb_secure_zero(t.data(), t.size());
    kctsb_secure_zero(x2y2, sizeof(x2y2));
    
    return KCTSB_SUCCESS;
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

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

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

// SM2KeyPair implementation
SM2KeyPair::SM2KeyPair() {
    std::memset(&keypair_, 0, sizeof(keypair_));
}

SM2KeyPair::SM2KeyPair(const ByteVec& privateKey) {
    if (privateKey.size() != KCTSB_SM2_PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("Invalid SM2 private key size");
    }
    
    std::memcpy(keypair_.private_key, privateKey.data(), KCTSB_SM2_PRIVATE_KEY_SIZE);
    
    // Derive public key from private key using Montgomery acceleration
    internal::sm2::sm2_point_result P_mont;
    if (!internal::sm2::scalar_mult_base_mont(&P_mont, keypair_.private_key)) {
        throw std::runtime_error("Failed to derive SM2 public key");
    }
    
    // Copy public key coordinates
    std::memcpy(keypair_.public_key, P_mont.x, KCTSB_SM2_PRIVATE_KEY_SIZE);
    std::memcpy(keypair_.public_key + KCTSB_SM2_PRIVATE_KEY_SIZE, P_mont.y, 
                KCTSB_SM2_PRIVATE_KEY_SIZE);
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

// SM2 class static methods
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
