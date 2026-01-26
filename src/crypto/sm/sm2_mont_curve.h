/**
 * @file sm2_mont_curve.h
 * @brief SM2 Montgomery-Accelerated Curve Operations Interface
 * 
 * Exposes optimized SM2 point multiplication using Montgomery arithmetic
 * and precomputed tables. This interface bridges the low-level Montgomery
 * implementation (sm2_mont.cpp, sm2_precomp.cpp) with high-level SM2 
 * operations (sm2_keygen.cpp, sm2_sign.cpp, sm2_encrypt.cpp).
 * 
 * Performance: ~50x faster than generic ECC implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_SM2_MONT_CURVE_H
#define KCTSB_SM2_MONT_CURVE_H

#include <cstdint>
#include <cstddef>
#include <cstring>

// Include sm2_mont.h for fe256 and related types
#include "kctsb/crypto/sm/sm2_mont.h"

namespace kctsb::internal::sm2 {

/**
 * @brief SM2 point in affine coordinates (x, y)
 * Uses mont::fe256 from sm2_mont.h
 */
struct sm2_point_affine {
    mont::fe256 x;
    mont::fe256 y;
};

/**
 * @brief SM2 point in Jacobian coordinates (X, Y, Z)
 * 
 * Affine conversion: x = X/Z^2, y = Y/Z^3
 * Point at infinity: Z = 0
 * Uses mont::fe256 from sm2_mont.h
 */
struct sm2_point_jacobian {
    mont::fe256 X;
    mont::fe256 Y;
    mont::fe256 Z;
};

/**
 * @brief Result point from scalar multiplication
 */
struct sm2_point_result {
    uint8_t x[32];  // X coordinate (big-endian, for compatibility)
    uint8_t y[32];  // Y coordinate (big-endian, for compatibility)
    bool is_infinity;
};

// Forward declarations of internal functions from sm2_precomp.cpp
namespace precomp {
    // Use mont::fe256 from sm2_mont.h
    using fe256 = mont::fe256;
    
    struct sm2_point_jacobian {
        fe256 X;
        fe256 Y;
        fe256 Z;
    };
    
    void scalar_mul_base(sm2_point_jacobian* r, const uint64_t* k);
    bool is_precomp_ready();
    const char* get_precomp_info();
}

/**
 * @brief Convert field element from Montgomery form to bytes (big-endian)
 */
inline void mont_fe256_to_bytes(uint8_t out[32], const mont::fe256* a) {
    mont::fe256 tmp;
    mont::fe256_from_mont(&tmp, a);
    
    // Convert from little-endian limbs to big-endian bytes
    for (int i = 0; i < 4; i++) {
        uint64_t limb = tmp.limb[3 - i];  // MSB first
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (uint8_t)(limb >> (56 - j * 8));
        }
    }
}

/**
 * @brief Convert bytes (big-endian) to field element in Montgomery form
 */
inline void mont_fe256_from_bytes(mont::fe256* r, const uint8_t in[32]) {
    mont::fe256 tmp;
    
    // Convert from big-endian bytes to little-endian limbs
    tmp.limb[0] = tmp.limb[1] = tmp.limb[2] = tmp.limb[3] = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | in[(3 - i) * 8 + j];
        }
        tmp.limb[3 - i] = limb;
    }
    
    mont::fe256_to_mont(r, &tmp);
}

/**
 * @brief Check if a Jacobian point is the point at infinity
 */
inline bool is_point_at_infinity(const precomp::sm2_point_jacobian* p) {
    return (p->Z.limb[0] == 0 && p->Z.limb[1] == 0 && 
            p->Z.limb[2] == 0 && p->Z.limb[3] == 0);
}

/**
 * @brief SM2 point result in affine form (for output)
 */
struct sm2_point_affine_result {
    precomp::fe256 x;
    precomp::fe256 y;
};

/**
 * @brief Convert Jacobian point to affine coordinates
 * 
 * x = X / Z^2, y = Y / Z^3
 * All coordinates are in Montgomery form.
 */
inline void jacobian_to_affine(sm2_point_affine_result* r, const precomp::sm2_point_jacobian* p) {
    if (is_point_at_infinity(p)) {
        std::memset(r, 0, sizeof(*r));
        return;
    }
    
    // Compute Z^(-1), Z^(-2), Z^(-3)
    mont::fe256 z_inv, z_inv2, z_inv3;
    mont::fe256_mont_inv(&z_inv, (const mont::fe256*)&p->Z);
    mont::fe256_mont_sqr(&z_inv2, &z_inv);           // Z^(-2)
    mont::fe256_mont_mul(&z_inv3, &z_inv2, &z_inv);  // Z^(-3)
    
    // x = X * Z^(-2), y = Y * Z^(-3)
    mont::fe256_mont_mul((mont::fe256*)&r->x, (const mont::fe256*)&p->X, &z_inv2);
    mont::fe256_mont_mul((mont::fe256*)&r->y, (const mont::fe256*)&p->Y, &z_inv3);
}

/**
 * @brief Compute k * G using Montgomery acceleration
 * 
 * This is the main entry point for optimized scalar multiplication.
 * Uses precomputed wNAF table for the base point G.
 * 
 * @param[out] result Output point coordinates (x, y) in big-endian bytes
 * @param[in] k 256-bit scalar as bytes (big-endian)
 * @return true on success, false if result is point at infinity
 */
inline bool scalar_mult_base_mont(sm2_point_result* result, const uint8_t k[32]) {
    // Convert scalar from big-endian bytes to little-endian limbs
    // k_be[24:32] -> limbs[0], k_be[16:24] -> limbs[1], etc.
    uint64_t k_limbs[4];
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;  // 24, 16, 8, 0
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | k[offset + j];
        }
        k_limbs[i] = limb;  // limbs[0]=LSB, limbs[3]=MSB
    }
    
    // Perform scalar multiplication
    precomp::sm2_point_jacobian jac;
    precomp::scalar_mul_base(&jac, k_limbs);
    
    // Check for point at infinity
    if (is_point_at_infinity(&jac)) {
        result->is_infinity = true;
        std::memset(result->x, 0, 32);
        std::memset(result->y, 0, 32);
        return false;
    }
    
    // Convert to affine
    sm2_point_affine_result aff;
    jacobian_to_affine(&aff, &jac);
    
    // Convert to bytes
    mont_fe256_to_bytes(result->x, (const mont::fe256*)&aff.x);
    mont_fe256_to_bytes(result->y, (const mont::fe256*)&aff.y);
    result->is_infinity = false;
    
    return true;
}

/**
 * @brief Check if Montgomery acceleration is available
 */
inline bool is_mont_accel_available() {
    return precomp::is_precomp_ready();
}

/**
 * @brief Get acceleration info string
 */
inline const char* get_mont_accel_info() {
    return precomp::get_precomp_info();
}

// Forward declaration of arbitrary point scalar multiplication
namespace precomp {
    void scalar_mul_point(sm2_point_jacobian* r, const uint64_t* k, 
                          const sm2_point_jacobian* P);
}

/**
 * @brief Compute k * P for arbitrary point P using Montgomery acceleration
 * 
 * This function implements wNAF scalar multiplication for any point P.
 * Uses real-time precomputation of odd multiples of P.
 * 
 * @param[out] result Output point coordinates (x, y) in big-endian bytes
 * @param[in] k 256-bit scalar as bytes (big-endian)
 * @param[in] P_x X coordinate of input point (big-endian)
 * @param[in] P_y Y coordinate of input point (big-endian)
 * @return true on success, false if result is point at infinity
 */
inline bool scalar_mult_point_mont(sm2_point_result* result, 
                                    const uint8_t k[32],
                                    const uint8_t P_x[32],
                                    const uint8_t P_y[32]) {
    // Convert scalar from big-endian bytes to little-endian limbs
    uint64_t k_limbs[4];
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;  // 24, 16, 8, 0
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | k[offset + j];
        }
        k_limbs[i] = limb;
    }
    
    // Convert point P from bytes to Montgomery-Jacobian form
    precomp::sm2_point_jacobian P_jac;
    
    // X coordinate
    mont::fe256 P_x_fe;
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | P_x[offset + j];
        }
        P_x_fe.limb[i] = limb;
    }
    mont::fe256_to_mont((mont::fe256*)&P_jac.X, &P_x_fe);
    
    // Y coordinate
    mont::fe256 P_y_fe;
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | P_y[offset + j];
        }
        P_y_fe.limb[i] = limb;
    }
    mont::fe256_to_mont((mont::fe256*)&P_jac.Y, &P_y_fe);
    
    // Z = 1 in Montgomery form
    static const precomp::fe256 MONT_ONE = {{
        0x0000000000000001ULL,
        0x00000000FFFFFFFFULL,
        0x0000000000000000ULL,
        0x0000000100000000ULL
    }};
    std::memcpy(&P_jac.Z, &MONT_ONE, sizeof(precomp::fe256));
    
    // Perform scalar multiplication
    precomp::sm2_point_jacobian jac;
    precomp::scalar_mul_point(&jac, k_limbs, &P_jac);
    
    // Check for point at infinity
    if (is_point_at_infinity(&jac)) {
        result->is_infinity = true;
        std::memset(result->x, 0, 32);
        std::memset(result->y, 0, 32);
        return false;
    }
    
    // Convert to affine
    sm2_point_affine_result aff;
    jacobian_to_affine(&aff, &jac);
    
    // Convert to bytes
    mont_fe256_to_bytes(result->x, (const mont::fe256*)&aff.x);
    mont_fe256_to_bytes(result->y, (const mont::fe256*)&aff.y);
    result->is_infinity = false;
    
    return true;
}

// Forward declaration for Shamir's trick
extern void scalar_mul_shamir(precomp::sm2_point_jacobian* r, 
                               const uint64_t* k1, 
                               const uint64_t* k2,
                               const precomp::sm2_point_jacobian* P);

/**
 * @brief Compute k1*G + k2*P using Shamir's trick (interleaved scalar multiplication)
 * 
 * This is optimized for signature verification where we need s*G + t*P.
 * Uses joint wNAF scanning for both scalars simultaneously, which is ~50%
 * faster than computing k1*G and k2*P separately.
 * 
 * @param[out] result Output point coordinates (x, y) in big-endian bytes
 * @param[in] k1 256-bit scalar for G (big-endian)
 * @param[in] k2 256-bit scalar for P (big-endian)
 * @param[in] P_x X coordinate of point P (big-endian)
 * @param[in] P_y Y coordinate of point P (big-endian)
 * @return true on success
 */
inline bool scalar_mult_shamir_mont(sm2_point_result* result,
                                     const uint8_t k1[32],
                                     const uint8_t k2[32],
                                     const uint8_t P_x[32],
                                     const uint8_t P_y[32]) {
    // Convert k1 from big-endian bytes to little-endian limbs
    uint64_t k1_limbs[4];
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | k1[offset + j];
        }
        k1_limbs[i] = limb;
    }
    
    // Convert k2 from big-endian bytes to little-endian limbs
    uint64_t k2_limbs[4];
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | k2[offset + j];
        }
        k2_limbs[i] = limb;
    }
    
    // Convert point P from bytes to Montgomery-Jacobian form
    precomp::sm2_point_jacobian P_jac;
    
    // X coordinate
    mont::fe256 P_x_fe;
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | P_x[offset + j];
        }
        P_x_fe.limb[i] = limb;
    }
    mont::fe256_to_mont((mont::fe256*)&P_jac.X, &P_x_fe);
    
    // Y coordinate
    mont::fe256 P_y_fe;
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        int offset = (3 - i) * 8;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | P_y[offset + j];
        }
        P_y_fe.limb[i] = limb;
    }
    mont::fe256_to_mont((mont::fe256*)&P_jac.Y, &P_y_fe);
    
    // Z = 1 in Montgomery form
    static const precomp::fe256 MONT_ONE = {{
        0x0000000000000001ULL,
        0x00000000FFFFFFFFULL,
        0x0000000000000000ULL,
        0x0000000100000000ULL
    }};
    std::memcpy(&P_jac.Z, &MONT_ONE, sizeof(precomp::fe256));
    
    // Call optimized Shamir's trick implementation
    precomp::sm2_point_jacobian jac;
    scalar_mul_shamir(&jac, k1_limbs, k2_limbs, &P_jac);
    
    // Check for point at infinity
    if (is_point_at_infinity(&jac)) {
        result->is_infinity = true;
        std::memset(result->x, 0, 32);
        std::memset(result->y, 0, 32);
        return false;
    }
    
    // Convert to affine
    sm2_point_affine_result aff;
    jacobian_to_affine(&aff, &jac);
    
    // Convert to bytes
    mont_fe256_to_bytes(result->x, (const mont::fe256*)&aff.x);
    mont_fe256_to_bytes(result->y, (const mont::fe256*)&aff.y);
    result->is_infinity = false;
    
    return true;
}

}  // namespace kctsb::internal::sm2

#endif  // KCTSB_SM2_MONT_CURVE_H
