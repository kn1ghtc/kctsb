/**
 * @file fe256_ecc_fast.h
 * @brief Fast Path Integration - fe256 Acceleration for ECCurve
 *
 * Provides conversion utilities and fast path dispatch for 256-bit curves.
 * Enables ~3-5x speedup by using optimized fe256 field operations
 * instead of generic ZZ_p arithmetic.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_ECC_FE256_ECC_FAST_H
#define KCTSB_CRYPTO_ECC_FE256_ECC_FAST_H

#include "fe256.h"
#include "fe256_point.h"
#include <kctsb/crypto/ecc/ecc_curve.h>
#include <cstring>

namespace kctsb {
namespace ecc {

// ============================================================================
// Curve Type Detection
// ============================================================================

/**
 * @brief Check if a curve supports fe256 fast path
 * @param curve_name Curve name
 * @return true if fe256 acceleration is available
 */
inline bool fe256_fast_path_supported(const std::string& curve_name) {
    return (curve_name == "secp256k1" ||
            curve_name == "secp256r1" || curve_name == "P-256" ||
            curve_name == "SM2" || curve_name == "sm2");
}

/**
 * @brief Get fe256 curve type from curve name
 * @param curve_name Curve name
 * @return FE256_CURVE_* constant
 */
inline int fe256_get_curve_type(const std::string& curve_name) {
    if (curve_name == "secp256k1") {
        return FE256_CURVE_SECP256K1;
    } else if (curve_name == "secp256r1" || curve_name == "P-256") {
        return FE256_CURVE_P256;
    } else if (curve_name == "SM2" || curve_name == "sm2") {
        return FE256_CURVE_SM2;
    }
    return FE256_CURVE_SECP256K1;  // Default
}

// ============================================================================
// Conversion Utilities
// ============================================================================

/**
 * @brief Convert ZZ to fe256 (little-endian limbs)
 * @param dst Destination fe256
 * @param src Source ZZ
 */
inline void zz_to_fe256(fe256* dst, const ZZ& src) {
    // Convert to bytes first
    uint8_t bytes[32];
    memset(bytes, 0, sizeof(bytes));
    
    // ZZ to big-endian bytes
    size_t num_bytes = (NumBits(src) + 7) / 8;
    if (num_bytes > 32) num_bytes = 32;
    
    for (size_t i = 0; i < num_bytes; i++) {
        long byte_val = conv<long>((src >> (8 * (num_bytes - 1 - i))) & ZZ(0xFF));
        bytes[32 - num_bytes + i] = static_cast<uint8_t>(byte_val);
    }
    
    // Convert big-endian bytes to little-endian limbs
    fe256_from_bytes(dst, bytes);
}

/**
 * @brief Convert fe256 to ZZ
 * @param src Source fe256
 * @return ZZ value
 */
inline ZZ fe256_to_zz(const fe256* src) {
    uint8_t bytes[32];
    fe256_to_bytes(bytes, src);
    
    // Convert big-endian bytes to ZZ
    ZZ result = ZZ(0);
    for (int i = 0; i < 32; i++) {
        result <<= 8;
        result |= ZZ(bytes[i]);
    }
    return result;
}

/**
 * @brief Convert ZZ to 4x64-bit limbs (little-endian)
 * @param dst Destination limbs
 * @param src Source ZZ
 */
inline void zz_to_limbs(uint64_t dst[4], const ZZ& src) {
    dst[0] = dst[1] = dst[2] = dst[3] = 0;
    
    // Use NTL's byte conversion for reliable extraction
    if (IsZero(src)) return;
    
    // Get number of bytes needed
    long num_bytes = NumBytes(src);
    if (num_bytes > 32) num_bytes = 32;  // Limit to 256 bits
    
    // Convert to bytes (big-endian from NTL)
    unsigned char buf[32];
    memset(buf, 0, sizeof(buf));
    BytesFromZZ(buf, src, static_cast<long>(num_bytes));
    
    // NTL's BytesFromZZ stores in little-endian order
    // So buf[0..7] is limb[0], buf[8..15] is limb[1], etc.
    for (int i = 0; i < 4; i++) {
        dst[i] = 0;
        for (int j = 0; j < 8; j++) {
            int byte_idx = i * 8 + j;
            if (byte_idx < num_bytes) {
                dst[i] |= static_cast<uint64_t>(buf[byte_idx]) << (j * 8);
            }
        }
    }
}

/**
 * @brief Convert 4x64-bit limbs to ZZ
 * @param src Source limbs
 * @return ZZ value
 */
inline ZZ limbs_to_zz(const uint64_t src[4]) {
    // Use byte-based conversion to avoid overflow warnings
    unsigned char buf[32];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            buf[i * 8 + j] = static_cast<unsigned char>((src[i] >> (j * 8)) & 0xFF);
        }
    }
    ZZ result;
    ZZFromBytes(result, buf, 32);
    return result;
}

/**
 * @brief Convert JacobianPoint (ZZ_p) to fe256_point
 * @param dst Destination fe256_point
 * @param src Source JacobianPoint
 * @param curve_type fe256 curve type constant
 */
inline void jacobian_to_fe256_point(fe256_point* dst, const JacobianPoint& src, int curve_type) {
    if (src.is_infinity()) {
        fe256_point_set_infinity(dst);
        return;
    }
    
    // Convert coordinates
    zz_to_fe256(&dst->X, rep(src.X));
    zz_to_fe256(&dst->Y, rep(src.Y));
    zz_to_fe256(&dst->Z, rep(src.Z));
    
    // Convert to Montgomery form based on curve type
    switch (curve_type) {
        case FE256_CURVE_SECP256K1:
            fe256_to_mont_secp256k1(&dst->X, &dst->X);
            fe256_to_mont_secp256k1(&dst->Y, &dst->Y);
            fe256_to_mont_secp256k1(&dst->Z, &dst->Z);
            break;
        case FE256_CURVE_P256:
            fe256_to_mont_p256(&dst->X, &dst->X);
            fe256_to_mont_p256(&dst->Y, &dst->Y);
            fe256_to_mont_p256(&dst->Z, &dst->Z);
            break;
        case FE256_CURVE_SM2:
            fe256_to_mont_sm2(&dst->X, &dst->X);
            fe256_to_mont_sm2(&dst->Y, &dst->Y);
            fe256_to_mont_sm2(&dst->Z, &dst->Z);
            break;
    }
}

/**
 * @brief Convert fe256_point to JacobianPoint (ZZ_p)
 * @param dst Destination JacobianPoint
 * @param src Source fe256_point
 * @param p Prime modulus for ZZ_p context
 * @param curve_type fe256 curve type constant
 */
inline void fe256_point_to_jacobian(JacobianPoint& dst, const fe256_point* src,
                                     const ZZ& p, int curve_type) {
    if (fe256_point_is_infinity(src)) {
        dst.set_infinity();
        return;
    }
    
    // Make a copy for conversion from Montgomery
    fe256 x_copy, y_copy, z_copy;
    fe256_copy(&x_copy, &src->X);
    fe256_copy(&y_copy, &src->Y);
    fe256_copy(&z_copy, &src->Z);
    
    // Convert from Montgomery form
    switch (curve_type) {
        case FE256_CURVE_SECP256K1:
            fe256_from_mont_secp256k1(&x_copy, &x_copy);
            fe256_from_mont_secp256k1(&y_copy, &y_copy);
            fe256_from_mont_secp256k1(&z_copy, &z_copy);
            break;
        case FE256_CURVE_P256:
            fe256_from_mont_p256(&x_copy, &x_copy);
            fe256_from_mont_p256(&y_copy, &y_copy);
            fe256_from_mont_p256(&z_copy, &z_copy);
            break;
        case FE256_CURVE_SM2:
            fe256_from_mont_sm2(&x_copy, &x_copy);
            fe256_from_mont_sm2(&y_copy, &y_copy);
            fe256_from_mont_sm2(&z_copy, &z_copy);
            break;
    }
    
    // Ensure ZZ_p context
    ZZ_p::init(p);
    
    // Convert fe256 to ZZ and then to ZZ_p
    dst.X = conv<ZZ_p>(fe256_to_zz(&x_copy));
    dst.Y = conv<ZZ_p>(fe256_to_zz(&y_copy));
    dst.Z = conv<ZZ_p>(fe256_to_zz(&z_copy));
}

// ============================================================================
// Fast Scalar Multiplication Entry Points
// ============================================================================

/**
 * @brief Fast scalar multiplication using fe256
 * @param curve_name Curve name (for dispatch)
 * @param k Scalar (as ZZ)
 * @param P Base point
 * @param p Prime modulus
 * @return k * P
 */
inline JacobianPoint fe256_fast_scalar_mult(const std::string& curve_name,
                                             const ZZ& k,
                                             const JacobianPoint& P,
                                             const ZZ& p) {
    int curve_type = fe256_get_curve_type(curve_name);
    
    // Convert scalar to limbs
    uint64_t k_limbs[4];
    zz_to_limbs(k_limbs, k);
    
    // Convert base point
    fe256_point p_fe256;
    jacobian_to_fe256_point(&p_fe256, P, curve_type);
    
    // Perform scalar multiplication
    fe256_point result;
    fe256_point_scalar_mult(&result, k_limbs, &p_fe256, curve_type);
    
    // Convert result back
    JacobianPoint result_jac;
    fe256_point_to_jacobian(result_jac, &result, p, curve_type);
    
    return result_jac;
}

/**
 * @brief Fast generator scalar multiplication using fe256
 * @param curve_name Curve name
 * @param k Scalar (as ZZ)
 * @param p Prime modulus
 * @return k * G
 */
inline JacobianPoint fe256_fast_scalar_mult_base(const std::string& curve_name,
                                                  const ZZ& k,
                                                  const ZZ& p) {
    int curve_type = fe256_get_curve_type(curve_name);
    
    // Convert scalar to limbs
    uint64_t k_limbs[4];
    zz_to_limbs(k_limbs, k);
    
    // Perform generator scalar multiplication
    fe256_point result;
    fe256_point_scalar_mult_base(&result, k_limbs, curve_type);
    
    // Convert result back
    JacobianPoint result_jac;
    fe256_point_to_jacobian(result_jac, &result, p, curve_type);
    
    return result_jac;
}

/**
 * @brief Fast double scalar multiplication using fe256 (Shamir's trick)
 * @param curve_name Curve name
 * @param k1 First scalar
 * @param P First point
 * @param k2 Second scalar
 * @param Q Second point
 * @param p Prime modulus
 * @return k1*P + k2*Q
 */
inline JacobianPoint fe256_fast_double_mult(const std::string& curve_name,
                                             const ZZ& k1, const JacobianPoint& P,
                                             const ZZ& k2, const JacobianPoint& Q,
                                             const ZZ& p) {
    int curve_type = fe256_get_curve_type(curve_name);
    
    // Convert scalars
    uint64_t k1_limbs[4], k2_limbs[4];
    zz_to_limbs(k1_limbs, k1);
    zz_to_limbs(k2_limbs, k2);
    
    // Convert points
    fe256_point p_fe256, q_fe256;
    jacobian_to_fe256_point(&p_fe256, P, curve_type);
    jacobian_to_fe256_point(&q_fe256, Q, curve_type);
    
    // Perform double scalar multiplication
    fe256_point result;
    fe256_point_double_mult(&result, k1_limbs, &p_fe256, k2_limbs, &q_fe256, curve_type);
    
    // Convert result back
    JacobianPoint result_jac;
    fe256_point_to_jacobian(result_jac, &result, p, curve_type);
    
    return result_jac;
}

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_CRYPTO_ECC_FE256_ECC_FAST_H
