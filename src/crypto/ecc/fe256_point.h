/**
 * @file fe256_point.h
 * @brief Optimized Point Arithmetic using fe256 Field Elements
 *
 * High-performance Jacobian point operations for 256-bit curves.
 * Uses fe256 field arithmetic instead of NTL ZZ_p for ~3-5x speedup.
 *
 * Supported curves:
 * - secp256k1 (Bitcoin/Ethereum)
 * - secp256r1 (NIST P-256)
 * - SM2 (Chinese National Standard)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_ECC_FE256_POINT_H
#define KCTSB_CRYPTO_ECC_FE256_POINT_H

#include "fe256.h"
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Curve Type Constants
// ============================================================================

#define FE256_CURVE_SECP256K1   0
#define FE256_CURVE_P256        1
#define FE256_CURVE_SM2         2

// ============================================================================
// Point Structures
// ============================================================================

/**
 * @brief Jacobian point using fe256 field elements
 *
 * Represents point (x, y) as (X/Z², Y/Z³)
 * Point at infinity: Z = 0
 */
typedef struct {
    fe256 X;
    fe256 Y;
    fe256 Z;
} fe256_point;

// ============================================================================
// Point Operations
// ============================================================================

/**
 * @brief Set point to infinity (Z = 0)
 */
void fe256_point_set_infinity(fe256_point* p);

/**
 * @brief Check if point is at infinity (constant-time)
 * @return 1 if infinity, 0 otherwise
 */
int fe256_point_is_infinity(const fe256_point* p);

/**
 * @brief Copy point
 */
void fe256_point_copy(fe256_point* dst, const fe256_point* src);

/**
 * @brief Point addition: r = p + q
 *
 * Uses complete addition formula that handles all edge cases:
 * - p = O → return q
 * - q = O → return p
 * - p = q → doubling
 * - p = -q → return O
 *
 * @param r Result
 * @param p First point
 * @param q Second point
 * @param curve_type Curve identifier (FE256_CURVE_*)
 */
void fe256_point_add(fe256_point* r, const fe256_point* p,
                     const fe256_point* q, int curve_type);

/**
 * @brief Point doubling: r = 2*p
 *
 * Optimized doubling using curve-specific a coefficient.
 *
 * @param r Result
 * @param p Point to double
 * @param curve_type Curve identifier
 */
void fe256_point_double(fe256_point* r, const fe256_point* p, int curve_type);

/**
 * @brief Point negation: r = -p
 */
void fe256_point_negate(fe256_point* r, const fe256_point* p, int curve_type);

/**
 * @brief Scalar multiplication: r = k * p
 *
 * Uses wNAF (width-5 Non-Adjacent Form) for efficiency.
 * Constant-time execution for secret scalars.
 *
 * @param r Result
 * @param k 256-bit scalar (as 4 limbs, little-endian)
 * @param p Base point
 * @param curve_type Curve identifier
 */
void fe256_point_scalar_mult(fe256_point* r, const uint64_t k[4],
                              const fe256_point* p, int curve_type);

/**
 * @brief Generator multiplication: r = k * G
 *
 * Uses precomputed table for the curve's generator point.
 *
 * @param r Result
 * @param k 256-bit scalar
 * @param curve_type Curve identifier
 */
void fe256_point_scalar_mult_base(fe256_point* r, const uint64_t k[4],
                                   int curve_type);

/**
 * @brief Double scalar multiplication: r = k1*p + k2*q
 *
 * Uses Shamir's trick for efficiency.
 *
 * @param r Result
 * @param k1 First scalar
 * @param p First point
 * @param k2 Second scalar
 * @param q Second point
 * @param curve_type Curve identifier
 */
void fe256_point_double_mult(fe256_point* r,
                              const uint64_t k1[4], const fe256_point* p,
                              const uint64_t k2[4], const fe256_point* q,
                              int curve_type);

/**
 * @brief Convert Jacobian to Affine coordinates
 *
 * @param x Output x coordinate
 * @param y Output y coordinate
 * @param p Input Jacobian point
 * @param curve_type Curve identifier
 * @return 0 on success, -1 if point is at infinity
 */
int fe256_point_to_affine(fe256* x, fe256* y, const fe256_point* p,
                           int curve_type);

/**
 * @brief Convert Affine to Jacobian coordinates
 */
void fe256_point_from_affine(fe256_point* p, const fe256* x, const fe256* y);

// ============================================================================
// Generator Points
// ============================================================================

/**
 * @brief Get generator point for specified curve
 */
const fe256_point* fe256_get_generator(int curve_type);

/**
 * @brief Get curve order (n) for specified curve
 */
const uint64_t* fe256_get_order(int curve_type);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_CRYPTO_ECC_FE256_POINT_H */
