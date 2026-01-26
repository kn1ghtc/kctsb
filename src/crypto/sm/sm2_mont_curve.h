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

namespace kctsb::internal::sm2 {

/**
 * @brief 256-bit field element (4 x 64-bit limbs, little-endian)
 * 
 * This type is binary-compatible with mont::fe256 and precomp::fe256.
 */
struct alignas(32) sm2_fe256 {
    uint64_t limb[4];
};

/**
 * @brief SM2 point in affine coordinates (x, y)
 */
struct sm2_point_affine {
    sm2_fe256 x;
    sm2_fe256 y;
};

/**
 * @brief SM2 point in Jacobian coordinates (X, Y, Z)
 * 
 * Affine conversion: x = X/Z^2, y = Y/Z^3
 * Point at infinity: Z = 0
 */
struct sm2_point_jacobian {
    sm2_fe256 X;
    sm2_fe256 Y;
    sm2_fe256 Z;
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
    // Types defined in sm2_precomp.cpp
    struct alignas(32) fe256 {
        uint64_t limb[4];
    };
    
    struct sm2_point_jacobian {
        fe256 X;
        fe256 Y;
        fe256 Z;
    };
    
    void scalar_mul_base(sm2_point_jacobian* r, const uint64_t* k);
    bool is_precomp_ready();
    const char* get_precomp_info();
}

// Forward declarations of internal functions from sm2_mont.cpp
namespace mont {
    struct fe256 {
        uint64_t limb[4];
    };
    void fe256_from_mont(fe256* r, const fe256* a);
    void fe256_to_mont(fe256* r, const fe256* a);
    void fe256_mont_mul(fe256* r, const fe256* a, const fe256* b);
    void fe256_mont_sqr(fe256* r, const fe256* a);
    void fe256_modp_add(fe256* r, const fe256* a, const fe256* b);
    void fe256_modp_sub(fe256* r, const fe256* a, const fe256* b);
    void fe256_mont_inv(fe256* r, const fe256* a);
}

/**
 * @brief Convert field element from Montgomery form to bytes (big-endian)
 */
inline void fe256_to_bytes(uint8_t out[32], const mont::fe256* a) {
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
inline void fe256_from_bytes(mont::fe256* r, const uint8_t in[32]) {
    mont::fe256 tmp;
    
    // Convert from big-endian bytes to little-endian limbs
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | in[(3 - i) * 8 + (7 - j)];
        }
        tmp.limb[i] = limb;
    }
    
    // Wrong direction - fix:
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
    uint64_t k_limbs[4];
    for (int i = 0; i < 4; i++) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; j++) {
            limb = (limb << 8) | k[(3 - i) * 8 + j];
        }
        k_limbs[3 - i] = limb;
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
    fe256_to_bytes(result->x, (const mont::fe256*)&aff.x);
    fe256_to_bytes(result->y, (const mont::fe256*)&aff.y);
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

}  // namespace kctsb::internal::sm2

#endif  // KCTSB_SM2_MONT_CURVE_H
