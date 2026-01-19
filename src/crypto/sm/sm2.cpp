/**
 * @file sm2.cpp
 * @brief SM2 Elliptic Curve Cryptography Implementation
 * 
 * Complete implementation of GB/T 32918-2016 Chinese National Standard:
 * - Key generation using SM2 curve (256-bit)
 * - Digital signature (SM2DSA) with SM3 hash
 * - Public key encryption/decryption
 * 
 * Architecture: C++ internal implementation + extern "C" API export.
 * 
 * References:
 * - GB/T 32918.1-2016: General
 * - GB/T 32918.2-2016: Digital Signature
 * - GB/T 32918.4-2016: Public Key Encryption
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/crypto/sm/sm2_optimized.h"
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
// C++ Internal Implementation Namespace
// ============================================================================

namespace kctsb::internal::sm2 {

/**
 * @brief SM2 curve parameters (256-bit, Chinese National Standard)
 * 
 * p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
 * a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
 * b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
 * n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
 * Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
 * Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
 */

// Field size in bytes (256-bit = 32 bytes)
constexpr size_t FIELD_SIZE = 32;

// SM2 signature and encryption constants
constexpr size_t SIGNATURE_SIZE = 64;  // r (32) + s (32)
constexpr size_t MAX_HASH_SIZE = 32;   // SM3 output

/**
 * @brief SM2 internal context for curve operations
 */
class SM2Context {
public:
    SM2Context() : curve_(ecc::CurveType::SM2) {
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
    
    const ecc::ECCurve& curve() const { return curve_; }
    const ZZ& n() const { return n_; }
    const ZZ& p() const { return p_; }
    int bit_size() const { return bit_size_; }
    
private:
    ecc::ECCurve curve_;
    ZZ n_;
    ZZ p_;
    int bit_size_;
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Convert byte array to bignum ZZ (big-endian)
 * @param data Input bytes
 * @param len Length of input
 * @return ZZ value
 */
ZZ bytes_to_zz(const uint8_t* data, size_t len) {
    ZZ result = ZZ(0);
    for (size_t i = 0; i < len; i++) {
        result <<= 8;
        result += data[i];
    }
    return result;
}

/**
 * @brief Convert bignum ZZ to byte array (big-endian, fixed length)
 * 
 * This function manually extracts bytes to avoid issues with the bignum
 * library's BytesFromZZ which has assumptions about internal limb storage.
 * 
 * @param z ZZ value
 * @param out Output buffer
 * @param len Output length
 */
void zz_to_bytes(const ZZ& z, uint8_t* out, size_t len) {
    std::memset(out, 0, len);
    
    // Manual extraction: extract bytes from lowest to highest
    ZZ tmp = z;
    for (size_t i = 0; i < len && !IsZero(tmp); i++) {
        // Get lowest byte
        long byte_val = to_long(tmp % 256);
        out[len - 1 - i] = static_cast<uint8_t>(byte_val);
        tmp >>= 8;
    }
}

/**
 * @brief Extract ZZ from ZZ_p value safely
 * @param val ZZ_p value
 * @param modulus The modulus p
 * @return ZZ representation
 */
ZZ extract_zz_from_zzp(const ZZ_p& val, const ZZ& modulus) {
    ZZ_p::init(modulus);
    return rep(val);
}

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
    ecc::CurveParams params = ecc::get_sm2_params();
    
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

/**
 * @brief Generate random k for signature (must be in [1, n-1])
 * @param k Output random value
 * @param n Curve order
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t generate_random_k(ZZ& k, const ZZ& n) {
    uint8_t k_bytes[FIELD_SIZE];
    
    // Retry until we get a valid k in [1, n-1]
    for (int attempts = 0; attempts < 100; attempts++) {
        if (kctsb_random_bytes(k_bytes, FIELD_SIZE) != KCTSB_SUCCESS) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        
        k = bytes_to_zz(k_bytes, FIELD_SIZE);
        
        // Reduce k modulo n
        k = k % n;
        
        // k must be in [1, n-1]
        if (!IsZero(k) && k < n) {
            kctsb_secure_zero(k_bytes, sizeof(k_bytes));
            return KCTSB_SUCCESS;
        }
    }
    
    kctsb_secure_zero(k_bytes, sizeof(k_bytes));
    return KCTSB_ERROR_RANDOM_FAILED;
}

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
    ZZ d;
    uint8_t d_bytes[FIELD_SIZE];
    
    for (int attempts = 0; attempts < 100; attempts++) {
        if (kctsb_random_bytes(d_bytes, FIELD_SIZE) != KCTSB_SUCCESS) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        
        d = bytes_to_zz(d_bytes, FIELD_SIZE);
        d = d % (n - 1);  // Reduce to [0, n-2]
        
        // d must be in [1, n-2]
        if (!IsZero(d)) {
            break;
        }
        
        if (attempts == 99) {
            kctsb_secure_zero(d_bytes, sizeof(d_bytes));
            return KCTSB_ERROR_RANDOM_FAILED;
        }
    }
    
    // Compute public key P = d * G (using wNAF optimization)
    ecc::JacobianPoint P_jac = kctsb::sm2::sm2_fast_scalar_mult_base(curve, d);
    ecc::AffinePoint P_aff = curve.to_affine(P_jac);
    
    // Export private key
    zz_to_bytes(d, keypair->private_key, FIELD_SIZE);
    
    // Export public key (Px || Py) - extract ZZ immediately after to_affine
    ZZ Px = rep(P_aff.x);
    ZZ Py = rep(P_aff.y);
    zz_to_bytes(Px, keypair->public_key, FIELD_SIZE);
    zz_to_bytes(Py, keypair->public_key + FIELD_SIZE, FIELD_SIZE);
    
    // Secure cleanup
    kctsb_secure_zero(d_bytes, sizeof(d_bytes));
    
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
        
        // Step 3: Compute (x1, y1) = k * G (using wNAF optimization)
        ecc::JacobianPoint kG = kctsb::sm2::sm2_fast_scalar_mult_base(curve, k);
        ecc::AffinePoint kG_aff = curve.to_affine(kG);
        
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
    ecc::AffinePoint P_aff(conv<ZZ_p>(Px), conv<ZZ_p>(Py));
    ecc::JacobianPoint P_jac = curve.to_jacobian(P_aff);
    
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
    
    // Step 4: Compute (x1, y1) = s*G + t*P (using wNAF double scalar mult)
    ecc::JacobianPoint R_point = kctsb::sm2::sm2_fast_double_scalar_mult(curve, s, t, P_jac);
    ecc::AffinePoint R_aff = curve.to_affine(R_point);
    
    // Extract ZZ value immediately after to_affine (ZZ_p context still valid)
    ZZ x1 = rep(R_aff.x);
    
    // Step 5-6: Compute R = (e + x1) mod n and verify R = r
    ZZ R = (e + x1) % n;
    
    if (R == r) {
        return KCTSB_SUCCESS;
    }
    
    return KCTSB_ERROR_VERIFICATION_FAILED;
}

// ============================================================================
// Public Key Encryption (SM2 Encryption Scheme)
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
    ecc::AffinePoint P_aff(conv<ZZ_p>(Px), conv<ZZ_p>(Py));
    ecc::JacobianPoint P_jac = curve.to_jacobian(P_aff);
    
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
        
        // Step 2: Compute C1 = k * G (using wNAF optimization)
        ecc::JacobianPoint C1_jac = kctsb::sm2::sm2_fast_scalar_mult_base(curve, k);
        ecc::AffinePoint C1_aff = curve.to_affine(C1_jac);
        
        // Extract ZZ values immediately after to_affine (ZZ_p context still valid)
        ZZ x1 = rep(C1_aff.x);
        ZZ y1 = rep(C1_aff.y);
        
        // Step 3: Compute (x2, y2) = k * P (using wNAF optimization)
        ecc::JacobianPoint kP = kctsb::sm2::sm2_fast_scalar_mult(curve, k, P_jac);
        if (kP.is_infinity()) {
            continue;  // Retry with new k
        }
        ecc::AffinePoint kP_aff = curve.to_affine(kP);
        
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
    ecc::AffinePoint C1_aff(conv<ZZ_p>(x1), conv<ZZ_p>(y1));
    ecc::JacobianPoint C1_jac = curve.to_jacobian(C1_aff);
    
    // Step 2: Verify C1 is on curve
    if (!curve.is_on_curve(C1_jac)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Parse C3 and C2
    const uint8_t* c3_ptr = ciphertext + 1 + 2 * FIELD_SIZE;
    const uint8_t* c2_ptr = c3_ptr + 32;
    
    // Step 3: Compute (x2, y2) = d * C1 (using wNAF optimization)
    ecc::JacobianPoint dC1 = kctsb::sm2::sm2_fast_scalar_mult(curve, d, C1_jac);
    if (dC1.is_infinity()) {
        return KCTSB_ERROR_DECRYPTION_FAILED;
    }
    ecc::AffinePoint dC1_aff = curve.to_affine(dC1);
    
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

// SM2KeyPair implementation
SM2KeyPair::SM2KeyPair() {
    std::memset(&keypair_, 0, sizeof(keypair_));
}

SM2KeyPair::SM2KeyPair(const ByteVec& privateKey) {
    if (privateKey.size() != KCTSB_SM2_PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("Invalid SM2 private key size");
    }
    
    std::memcpy(keypair_.private_key, privateKey.data(), KCTSB_SM2_PRIVATE_KEY_SIZE);
    
    // Derive public key from private key (using wNAF optimization)
    auto& ctx = internal::sm2::SM2Context::instance();
    const auto& curve = ctx.curve();
    
    kctsb::ZZ d = internal::sm2::bytes_to_zz(keypair_.private_key, KCTSB_SM2_PRIVATE_KEY_SIZE);
    ecc::JacobianPoint P_jac = kctsb::sm2::sm2_fast_scalar_mult_base(curve, d);
    ecc::AffinePoint P_aff = curve.to_affine(P_jac);
    
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
