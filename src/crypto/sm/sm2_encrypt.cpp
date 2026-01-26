/**
 * @file sm2_encrypt.cpp
 * @brief SM2 Public Key Encryption Module
 * 
 * Implements SM2 public key encryption as specified in 
 * GB/T 32918.4-2016 Chinese National Standard.
 * 
 * Encryption Algorithm:
 * 1. Generate random k in [1, n-1]
 * 2. Compute C1 = k * G (point on curve)
 * 3. Compute (x2, y2) = k * P (shared point)
 * 4. Compute t = KDF(x2 || y2, klen)
 * 5. Compute C2 = M XOR t
 * 6. Compute C3 = SM3(x2 || M || y2)
 * 7. Output C = C1 || C3 || C2 (new format)
 * 
 * Decryption Algorithm:
 * 1. Parse C1 from ciphertext
 * 2. Verify C1 is on curve
 * 3. Compute (x2, y2) = d * C1
 * 4. Compute t = KDF(x2 || y2, C2_len)
 * 5. Compute M = C2 XOR t
 * 6. Compute u = SM3(x2 || M || y2)
 * 7. Verify u == C3
 * 8. Output M
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
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
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
    
    // Parse public key
    ZZ Px = bytes_to_zz(public_key, FIELD_SIZE);
    ZZ Py = bytes_to_zz(public_key + FIELD_SIZE, FIELD_SIZE);
    
    ZZ_p::init(ctx.p());
    ecc::internal::AffinePoint P_aff{ZZ_p(Px), ZZ_p(Py)};
    ecc::internal::JacobianPoint P_jac = curve.to_jacobian(P_aff);
    
    // Validate public key
    if (!curve.is_on_curve(P_jac)) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Encryption loop (retry if KDF produces all zeros)
    for (int attempts = 0; attempts < 100; attempts++) {
        // Step 1: Generate random k
        ZZ k;
        kctsb_error_t err = generate_random_k(k, n);
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        // Step 2: Compute C1 = k * G (using Montgomery ladder)
        ecc::internal::JacobianPoint C1_jac = curve.scalar_mult_base(k);
        ecc::internal::AffinePoint C1_aff = curve.to_affine(C1_jac);
        
        // Extract ZZ values immediately after to_affine (ZZ_p context still valid)
        ZZ x1 = rep(C1_aff.x);
        ZZ y1 = rep(C1_aff.y);
        
        // Step 3: Compute (x2, y2) = k * P (using Montgomery ladder)
        ecc::internal::JacobianPoint kP = curve.scalar_mult(k, P_jac);
        if (kP.is_infinity()) {
            continue;  // Retry with new k
        }
        ecc::internal::AffinePoint kP_aff = curve.to_affine(kP);
        
        // Extract ZZ values immediately after to_affine (ZZ_p context still valid)
        ZZ x2 = rep(kP_aff.x);
        ZZ y2 = rep(kP_aff.y);
        
        // Prepare x2||y2 for KDF
        std::vector<uint8_t> x2y2(2 * FIELD_SIZE);
        zz_to_bytes(x2, x2y2.data(), FIELD_SIZE);
        zz_to_bytes(y2, x2y2.data() + FIELD_SIZE, FIELD_SIZE);
        
        // Step 4: Compute t = KDF(x2 || y2, plaintext_len)
        std::vector<uint8_t> t(plaintext_len);
        err = sm2_kdf(x2y2.data(), x2y2.size(), plaintext_len, t.data());
        if (err != KCTSB_SUCCESS) {
            return err;
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
        zz_to_bytes(x1, ciphertext + pos, FIELD_SIZE);
        pos += FIELD_SIZE;
        zz_to_bytes(y1, ciphertext + pos, FIELD_SIZE);
        pos += FIELD_SIZE;
        
        // Step 6: Compute C3 = SM3(x2 || M || y2)
        kctsb_sm3_ctx_t sm3_ctx;
        kctsb_sm3_init(&sm3_ctx);
        
        uint8_t x2_bytes[FIELD_SIZE], y2_bytes[FIELD_SIZE];
        zz_to_bytes(x2, x2_bytes, FIELD_SIZE);
        zz_to_bytes(y2, y2_bytes, FIELD_SIZE);
        
        kctsb_sm3_update(&sm3_ctx, x2_bytes, FIELD_SIZE);
        kctsb_sm3_update(&sm3_ctx, plaintext, plaintext_len);
        kctsb_sm3_update(&sm3_ctx, y2_bytes, FIELD_SIZE);
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
        kctsb_secure_zero(x2y2.data(), x2y2.size());
        
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
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
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
    
    // Parse private key
    ZZ d = bytes_to_zz(private_key, FIELD_SIZE);
    if (IsZero(d) || d >= n - 1) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Step 1: Parse C1
    if (ciphertext[0] != 0x04) {
        return KCTSB_ERROR_INVALID_PARAM;  // Only uncompressed format supported
    }
    
    ZZ x1 = bytes_to_zz(ciphertext + 1, FIELD_SIZE);
    ZZ y1 = bytes_to_zz(ciphertext + 1 + FIELD_SIZE, FIELD_SIZE);
    
    ZZ_p::init(ctx.p());
    ecc::internal::AffinePoint C1_aff{ZZ_p(x1), ZZ_p(y1)};
    ecc::internal::JacobianPoint C1_jac = curve.to_jacobian(C1_aff);
    
    // Step 2: Verify C1 is on curve
    if (!curve.is_on_curve(C1_jac)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Parse C3 and C2
    const uint8_t* c3_ptr = ciphertext + 1 + 2 * FIELD_SIZE;
    const uint8_t* c2_ptr = c3_ptr + 32;
    
    // Step 3: Compute (x2, y2) = d * C1 (using Montgomery ladder)
    ecc::internal::JacobianPoint dC1 = curve.scalar_mult(d, C1_jac);
    if (dC1.is_infinity()) {
        return KCTSB_ERROR_DECRYPTION_FAILED;
    }
    ecc::internal::AffinePoint dC1_aff = curve.to_affine(dC1);
    
    // Extract ZZ values immediately after to_affine (ZZ_p context still valid)
    ZZ x2 = rep(dC1_aff.x);
    ZZ y2 = rep(dC1_aff.y);
    
    // Prepare x2||y2
    uint8_t x2_bytes[FIELD_SIZE], y2_bytes[FIELD_SIZE];
    zz_to_bytes(x2, x2_bytes, FIELD_SIZE);
    zz_to_bytes(y2, y2_bytes, FIELD_SIZE);
    
    std::vector<uint8_t> x2y2(2 * FIELD_SIZE);
    std::memcpy(x2y2.data(), x2_bytes, FIELD_SIZE);
    std::memcpy(x2y2.data() + FIELD_SIZE, y2_bytes, FIELD_SIZE);
    
    // Step 4: Compute t = KDF(x2 || y2, c2_len)
    std::vector<uint8_t> t(c2_len);
    kctsb_error_t err = sm2_kdf(x2y2.data(), x2y2.size(), c2_len, t.data());
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
    kctsb_sm3_update(&sm3_ctx, x2_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, plaintext, c2_len);
    kctsb_sm3_update(&sm3_ctx, y2_bytes, FIELD_SIZE);
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
    kctsb_secure_zero(x2y2.data(), x2y2.size());
    
    return KCTSB_SUCCESS;
}

}  // namespace kctsb::internal::sm2
