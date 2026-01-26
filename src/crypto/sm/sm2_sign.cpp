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
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"
#include "kctsb/core/common.h"

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
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Parse private key
    ZZ d = bytes_to_zz(private_key, FIELD_SIZE);
    if (IsZero(d) || d >= n - 1) {
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
    
    ZZ e = bytes_to_zz(e_hash, 32);
    
    // Compute (1 + d)^-1 mod n
    ZZ d_plus_1 = (d + 1) % n;
    ZZ d_plus_1_inv = InvMod(d_plus_1, n);
    
    ZZ r, s;
    
    // Signature generation loop
    for (int attempts = 0; attempts < 100; attempts++) {
        // Step 2: Generate random k
        ZZ k;
        err = generate_random_k(k, n);
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        // Step 3: Compute (x1, y1) = k * G (using Montgomery ladder)
        ecc::internal::JacobianPoint kG = curve.scalar_mult_base(k);
        ecc::internal::AffinePoint kG_aff = curve.to_affine(kG);
        
        #ifdef KCTSB_DEBUG_SM2
        // Debug: Print k and kG.x for comparison with verification
        ZZ_p::init(ctx.p());
        ecc::internal::AffinePoint G_aff_sign = curve.to_affine(curve.get_generator());
        std::cerr << "[SM2 SIGN DEBUG] k = " << k << "\n";
        std::cerr << "[SM2 SIGN DEBUG] G.x in sign = " << rep(G_aff_sign.x) << "\n";
        std::cerr << "[SM2 SIGN DEBUG] kG.x = " << rep(kG_aff.x) << "\n";
        #endif
        
        // Extract ZZ value immediately after to_affine (ZZ_p context still valid)
        ZZ x1 = rep(kG_aff.x);
        
        // Step 4: Compute r = (e + x1) mod n
        r = (e + x1) % n;
        
        // Step 5: Check r != 0 and r + k != n
        if (IsZero(r) || (r + k) == n) {
            continue;
        }
        
        // Step 6: Compute s = ((1+d)^-1 * (k - r*d)) mod n
        ZZ k_minus_rd = (k - MulMod(r, d, n)) % n;
        if (k_minus_rd < 0) {
            k_minus_rd += n;
        }
        s = MulMod(d_plus_1_inv, k_minus_rd, n);
        
        // Step 7: Check s != 0
        if (!IsZero(s)) {
            break;
        }
        
        if (attempts == 99) {
            return KCTSB_ERROR_INTERNAL;
        }
    }
    
    // Step 8: Output signature (r, s)
    zz_to_bytes(r, signature->r, FIELD_SIZE);
    zz_to_bytes(s, signature->s, FIELD_SIZE);
    
    #ifdef KCTSB_DEBUG_SM2
    std::cerr << "[SM2 DEBUG] Signature generated:\n";
    std::cerr << "  e (hash): " << e << "\n";
    std::cerr << "  x1 (from kG): " << (r - e % n) << "\n";  // Reconstruct x1 from r - e mod n
    std::cerr << "  r (e+x1 mod n): " << r << "\n";
    std::cerr << "  s: " << s << "\n";
    #endif
    
    // Secure cleanup
    kctsb_secure_zero(z_value, sizeof(z_value));
    kctsb_secure_zero(e_hash, sizeof(e_hash));
    
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
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Parse signature
    ZZ r = bytes_to_zz(signature->r, FIELD_SIZE);
    ZZ s = bytes_to_zz(signature->s, FIELD_SIZE);
    
    // Step 1: Verify r, s in [1, n-1]
    if (IsZero(r) || r >= n || IsZero(s) || s >= n) {
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    // Parse public key
    ZZ Px = bytes_to_zz(public_key, FIELD_SIZE);
    ZZ Py = bytes_to_zz(public_key + FIELD_SIZE, FIELD_SIZE);
    
    ZZ_p::init(ctx.p());
    ecc::internal::AffinePoint P_aff{ZZ_p(Px), ZZ_p(Py)};
    ecc::internal::JacobianPoint P_jac = curve.to_jacobian(P_aff);
    
    // Validate public key is on curve
    if (!curve.is_on_curve(P_jac)) {
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
    
    ZZ e = bytes_to_zz(e_hash, 32);
    
    // Step 3: Compute t = (r + s) mod n
    ZZ t = (r + s) % n;
    if (IsZero(t)) {
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    // Step 4: Compute (x1, y1) = s*G + t*P (using Shamir's trick)
    ecc::internal::JacobianPoint G = curve.get_generator();
    
    #ifdef KCTSB_DEBUG_SM2
    // Debug: Check generator point in Jacobian coordinates
    ZZ_p::init(ctx.p());
    std::cerr << "[SM2 DEBUG] G.X (Jacobian) = " << rep(G.X) << "\n";
    std::cerr << "[SM2 DEBUG] G.Y (Jacobian) = " << rep(G.Y) << "\n";
    std::cerr << "[SM2 DEBUG] G.Z (Jacobian) = " << rep(G.Z) << "\n";
    std::cerr << "[SM2 DEBUG] P_jac.X = " << rep(P_jac.X) << "\n";
    std::cerr << "[SM2 DEBUG] P_jac.Y = " << rep(P_jac.Y) << "\n";
    std::cerr << "[SM2 DEBUG] P_jac.Z = " << rep(P_jac.Z) << "\n";
    std::cerr << "[SM2 DEBUG] s = " << s << "\n";
    std::cerr << "[SM2 DEBUG] t = " << t << "\n";
    #endif
    
    // Use separate scalar multiplications for debugging
    // R_point = s*G + t*P
    // Note: Use scalar_mult_base for G to use same path as signature
    ecc::internal::JacobianPoint sG = curve.scalar_mult_base(s);  // Use cached table like signature
    ecc::internal::JacobianPoint tP = curve.scalar_mult(t, P_jac);
    ecc::internal::JacobianPoint R_point = curve.add(sG, tP);
    ecc::internal::AffinePoint R_aff = curve.to_affine(R_point);
    
    // Extract ZZ value immediately after to_affine (ZZ_p context still valid)
    ZZ x1 = rep(R_aff.x);
    
    // Step 5-6: Compute R = (e + x1) mod n and verify R = r
    ZZ R = (e + x1) % n;
    
    if (R == r) {
        return KCTSB_SUCCESS;
    }
    
    // Debug output for verification failure
    #ifdef KCTSB_DEBUG_SM2
    std::cerr << "[SM2 DEBUG] Verification FAILED!\n";
    std::cerr << "  r (from sig): " << r << "\n";
    std::cerr << "  s (from sig): " << s << "\n";
    std::cerr << "  e (hash): " << e << "\n";
    std::cerr << "  t (r+s mod n): " << t << "\n";
    std::cerr << "  x1 (from R_aff): " << x1 << "\n";
    std::cerr << "  R (e+x1 mod n): " << R << "\n";
    std::cerr << "  R == r: " << (R == r ? "YES" : "NO") << "\n";
    #endif
    
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
