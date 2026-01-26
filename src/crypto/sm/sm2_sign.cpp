/**
 * @file sm2_sign.cpp
 * @brief SM2 Digital Signature Implementation
 * 
 * SM2 digital signature (SM2DSA) following GB/T 32918.2-2016:
 * - ZA hash computation (user identification)
 * - Signature generation and verification
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/crypto/sm/sm2_mont.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"
#include "kctsb/core/common.h"

// Montgomery acceleration header
#include "sm2_mont_curve.h"

#include <kctsb/math/ZZ.h>
#include <kctsb/math/ZZ_p.h>

#include <cstring>
#include <vector>

// Enable debug output for SM2 verification failures
// #define KCTSB_DEBUG_SM2 1  // Disabled - SM2 signature verification now works correctly
#ifdef KCTSB_DEBUG_SM2
#include <iostream>
#endif

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

/**
 * @brief Generate random scalar k in [1, n-1] using fe256
 * 
 * This is a faster alternative to generate_random_k that avoids ZZ.
 * Uses rejection sampling to ensure uniform distribution.
 * 
 * @param[out] k_bytes Output scalar (32 bytes, big-endian)
 * @return KCTSB_SUCCESS or error code
 */
static kctsb_error_t generate_random_k_fe256(uint8_t k_bytes[32]) {
    using namespace kctsb::internal::sm2::mont;
    
    // SM2 order n
    static const fe256 SM2_ORDER = {{
        0x53BBF40939D54123ULL,
        0x7203DF6B21C6052BULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFEFFFFFFFFULL
    }};
    
    // Maximum tries to avoid infinite loop
    for (int tries = 0; tries < 128; tries++) {
        // Generate random bytes
        if (kctsb_random_bytes(k_bytes, 32) != KCTSB_SUCCESS) {
            return KCTSB_ERROR_INTERNAL;
        }
        
        // Check if k is in valid range [1, n-1]
        // First check if k = 0
        bool is_zero = true;
        for (int i = 0; i < 32; i++) {
            if (k_bytes[i] != 0) {
                is_zero = false;
                break;
            }
        }
        if (is_zero) continue;
        
        // Convert to fe256 for comparison
        fe256 k_fe;
        fe256_from_bytes(&k_fe, k_bytes);
        
        // Check if k < n
        if (fe256_cmp(&k_fe, &SM2_ORDER) >= 0) {
            continue;  // k >= n, reject
        }
        
        return KCTSB_SUCCESS;
    }
    
    return KCTSB_ERROR_INTERNAL;
}

// ============================================================================
// Z Value Computation
// ============================================================================

/**
 * @brief Compute Z value for SM2 (user identification hash)
 * 
 * Z = SM3(ENTL || user_id || a || b || Gx || Gy || Px || Py)
 * where ENTL is the bit length of user_id (16 bits, big-endian)
 * 
 * @param user_id User identification bytes
 * @param user_id_len Length of user_id
 * @param public_key Public key (64 bytes: Px || Py)
 * @param z_value Output Z value (32 bytes)
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t compute_z_value(
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* public_key,
    uint8_t z_value[32]
) {
    // Get curve parameters
    ecc::internal::CurveParams params = ecc::internal::get_sm2_params();
    
    // Compute ENTL (bit length of user_id, max 8192 bits = 1024 bytes)
    if (user_id_len > 1024) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    uint16_t entl = static_cast<uint16_t>(user_id_len * 8);
    
    // Prepare Z input
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    
    // ENTL (2 bytes, big-endian)
    uint8_t entl_bytes[2] = {
        static_cast<uint8_t>(entl >> 8),
        static_cast<uint8_t>(entl & 0xFF)
    };
    kctsb_sm3_update(&sm3_ctx, entl_bytes, 2);
    
    // User ID
    kctsb_sm3_update(&sm3_ctx, user_id, user_id_len);
    
    // Curve parameter a (32 bytes)
    uint8_t a_bytes[FIELD_SIZE];
    zz_to_bytes(params.a, a_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, a_bytes, FIELD_SIZE);
    
    // Curve parameter b (32 bytes)
    uint8_t b_bytes[FIELD_SIZE];
    zz_to_bytes(params.b, b_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, b_bytes, FIELD_SIZE);
    
    // Generator Gx (32 bytes)
    uint8_t gx_bytes[FIELD_SIZE];
    zz_to_bytes(params.Gx, gx_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, gx_bytes, FIELD_SIZE);
    
    // Generator Gy (32 bytes)
    uint8_t gy_bytes[FIELD_SIZE];
    zz_to_bytes(params.Gy, gy_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, gy_bytes, FIELD_SIZE);
    
    // Public key Px (32 bytes)
    kctsb_sm3_update(&sm3_ctx, public_key, FIELD_SIZE);
    
    // Public key Py (32 bytes)
    kctsb_sm3_update(&sm3_ctx, public_key + FIELD_SIZE, FIELD_SIZE);
    
    kctsb_sm3_final(&sm3_ctx, z_value);
    
    return KCTSB_SUCCESS;
}

// ============================================================================
// Digital Signature (SM2DSA)
// ============================================================================

/**
 * @brief SM2 digital signature
 * 
 * Algorithm (GB/T 32918.2-2016):
 * 1. Compute e = SM3(Z || M)
 * 2. Generate random k in [1, n-1]
 * 3. Compute point (x1, y1) = k * G
 * 4. Compute r = (e + x1) mod n
 * 5. If r = 0 or r + k = n, go to step 2
 * 6. Compute s = ((1 + d)^-1 * (k - r*d)) mod n
 * 7. If s = 0, go to step 2
 * 8. Output signature (r, s)
 * 
 * This version uses fe256 operations for all scalar arithmetic.
 * 
 * @param private_key 32-byte private key
 * @param public_key 64-byte public key
 * @param user_id User ID for Z value computation
 * @param user_id_len Length of user_id
 * @param message Message to sign
 * @param message_len Message length
 * @param signature Output signature (r, s)
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t sign_internal(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
) {
    using namespace kctsb::internal::sm2::mont;
    
    // SM2 order n for validation
    static const fe256 SM2_ORDER = {{
        0x53BBF40939D54123ULL,
        0x7203DF6B21C6052BULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFEFFFFFFFFULL
    }};
    
    // Parse private key into fe256
    fe256 d_fe;
    fe256_from_bytes(&d_fe, private_key);
    
    // Validate private key range (should be in [1, n-2])
    // Check d != 0
    if (fe256_is_zero(&d_fe)) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Check d < n - 1 (approximately, full check would require n-1 constant)
    if (fe256_cmp(&d_fe, &SM2_ORDER) >= 0) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Step 1: Compute Z value
    uint8_t z_value[32];
    kctsb_error_t err = compute_z_value(user_id, user_id_len, public_key, z_value);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Compute e = SM3(Z || M)
    uint8_t e_hash[32];
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    kctsb_sm3_update(&sm3_ctx, z_value, 32);
    kctsb_sm3_update(&sm3_ctx, message, message_len);
    kctsb_sm3_final(&sm3_ctx, e_hash);
    
    // Convert e to fe256
    fe256 e_fe;
    fe256_from_bytes(&e_fe, e_hash);
    
    // Precompute (1 + d)^-1 mod n using fe256 operations
    fe256 one = {{1, 0, 0, 0}};
    fe256 d_plus_1_fe;
    fe256_modn_add(&d_plus_1_fe, &d_fe, &one);
    
    fe256 d_plus_1_inv_fe;
    fe256_modn_inv(&d_plus_1_inv_fe, &d_plus_1_fe);
    
    fe256 r_fe, s_fe;
    
    // Signature generation loop
    for (int attempts = 0; attempts < 100; attempts++) {
        // Step 2: Generate random k using fe256-based function
        uint8_t k_bytes[FIELD_SIZE];
        err = generate_random_k_fe256(k_bytes);
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        // Step 3: Compute (x1, y1) = k * G using Montgomery acceleration
        sm2_point_result kG_mont;
        if (!scalar_mult_base_mont(&kG_mont, k_bytes)) {
            kctsb_secure_zero(k_bytes, sizeof(k_bytes));
            continue;
        }
        
        // Convert x1 to fe256
        fe256 x1_fe;
        fe256_from_bytes(&x1_fe, kG_mont.x);
        
        // Step 4: Compute r = (e + x1) mod n using fe256
        fe256_modn_add(&r_fe, &e_fe, &x1_fe);
        
        // Step 5: Check r != 0
        if (fe256_is_zero(&r_fe)) {
            kctsb_secure_zero(k_bytes, sizeof(k_bytes));
            continue;
        }
        
        // Check r + k != n
        fe256 k_fe;
        fe256_from_bytes(&k_fe, k_bytes);
        
        fe256 r_plus_k;
        fe256_modn_add(&r_plus_k, &r_fe, &k_fe);
        if (fe256_is_zero(&r_plus_k)) {
            kctsb_secure_zero(k_bytes, sizeof(k_bytes));
            continue;
        }
        
        // Step 6: Compute s = ((1+d)^-1 * (k - r*d)) mod n using fe256
        // First compute r*d mod n
        fe256 rd_fe;
        fe256_modn_mul(&rd_fe, &r_fe, &d_fe);
        
        // Then k - r*d mod n
        fe256 k_minus_rd;
        fe256_modn_sub(&k_minus_rd, &k_fe, &rd_fe);
        
        // Finally s = (1+d)^-1 * (k - r*d) mod n
        fe256_modn_mul(&s_fe, &d_plus_1_inv_fe, &k_minus_rd);
        
        // Secure cleanup of k
        kctsb_secure_zero(k_bytes, sizeof(k_bytes));
        kctsb_secure_zero(&k_fe, sizeof(k_fe));
        
        // Step 7: Check s != 0
        if (!fe256_is_zero(&s_fe)) {
            break;
        }
        
        if (attempts == 99) {
            return KCTSB_ERROR_INTERNAL;
        }
    }
    
    // Step 8: Output signature (r, s)
    fe256_to_bytes(signature->r, &r_fe);
    fe256_to_bytes(signature->s, &s_fe);
    
    // Secure cleanup
    kctsb_secure_zero(z_value, sizeof(z_value));
    kctsb_secure_zero(e_hash, sizeof(e_hash));
    kctsb_secure_zero(&d_fe, sizeof(d_fe));
    kctsb_secure_zero(&d_plus_1_inv_fe, sizeof(d_plus_1_inv_fe));
    
    return KCTSB_SUCCESS;
}

/**
 * @brief SM2 signature verification
 * 
 * Algorithm (GB/T 32918.2-2016):
 * 1. Verify r, s in [1, n-1]
 * 2. Compute e = SM3(Z || M)
 * 3. Compute t = (r + s) mod n, verify t != 0
 * 4. Compute point (x1, y1) = s*G + t*P
 * 5. Compute R = (e + x1) mod n
 * 6. Verify R = r
 * 
 * @param public_key 64-byte public key
 * @param user_id User ID
 * @param user_id_len User ID length
 * @param message Original message
 * @param message_len Message length
 * @param signature Signature to verify
 * @return KCTSB_SUCCESS if valid, KCTSB_ERROR_VERIFICATION_FAILED otherwise
 */
kctsb_error_t verify_internal(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
) {
    using namespace kctsb::internal::sm2::mont;
    
    auto& ctx = SM2Context::instance();
    const ZZ& n = ctx.n();
    
    // Parse signature into fe256
    fe256 r_fe, s_fe;
    fe256_from_bytes(&r_fe, signature->r);
    fe256_from_bytes(&s_fe, signature->s);
    
    // Step 1: Verify r, s in [1, n-1] using ZZ for range validation only
    ZZ r = bytes_to_zz(signature->r, FIELD_SIZE);
    ZZ s = bytes_to_zz(signature->s, FIELD_SIZE);
    if (IsZero(r) || r >= n || IsZero(s) || s >= n) {
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    // Validate public key is on curve (use ZZ only for this check)
    ZZ_p::init(ctx.p());
    ZZ Px = bytes_to_zz(public_key, FIELD_SIZE);
    ZZ Py = bytes_to_zz(public_key + FIELD_SIZE, FIELD_SIZE);
    ecc::internal::AffinePoint P_aff{ZZ_p(Px), ZZ_p(Py)};
    if (!ctx.curve().is_on_curve(ctx.curve().to_jacobian(P_aff))) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Step 2: Compute Z and e = SM3(Z || M)
    uint8_t z_value[32];
    kctsb_error_t err = compute_z_value(user_id, user_id_len, public_key, z_value);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    uint8_t e_hash[32];
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    kctsb_sm3_update(&sm3_ctx, z_value, 32);
    kctsb_sm3_update(&sm3_ctx, message, message_len);
    kctsb_sm3_final(&sm3_ctx, e_hash);
    
    fe256 e_fe;
    fe256_from_bytes(&e_fe, e_hash);
    
    // Step 3: Compute t = (r + s) mod n using fe256
    fe256 t_fe;
    fe256_modn_add(&t_fe, &r_fe, &s_fe);
    if (fe256_is_zero(&t_fe)) {
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    // Step 4: Compute (x1, y1) = s*G + t*P using Montgomery acceleration
    uint8_t s_bytes[FIELD_SIZE];
    uint8_t t_bytes[FIELD_SIZE];
    fe256_to_bytes(s_bytes, &s_fe);
    fe256_to_bytes(t_bytes, &t_fe);
    
    // Compute s*G + t*P using Shamir's trick
    sm2_point_result R_mont;
    if (!scalar_mult_shamir_mont(&R_mont, s_bytes, t_bytes, public_key, public_key + FIELD_SIZE)) {
        kctsb_secure_zero(s_bytes, sizeof(s_bytes));
        kctsb_secure_zero(t_bytes, sizeof(t_bytes));
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    kctsb_secure_zero(s_bytes, sizeof(s_bytes));
    kctsb_secure_zero(t_bytes, sizeof(t_bytes));
    
    // Extract x1 from result
    fe256 x1_fe;
    fe256_from_bytes(&x1_fe, R_mont.x);
    
    // Step 5-6: Compute R = (e + x1) mod n and verify R = r
    fe256 R_fe;
    fe256_modn_add(&R_fe, &e_fe, &x1_fe);
    
    // Compare R with r (constant-time)
    if (fe256_cmp(&R_fe, &r_fe) == 0) {
        return KCTSB_SUCCESS;
    }
    
    return KCTSB_ERROR_VERIFICATION_FAILED;
}

}  // namespace kctsb::internal::sm2

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

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

}  // extern "C"
