/**
 * @file fe256.h
 * @brief High-Performance 256-bit Field Element Arithmetic
 * 
 * Optimized field operations for 256-bit prime fields used in:
 * - secp256k1: p = 2^256 - 2^32 - 977
 * - SM2: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * 
 * Features:
 * - Montgomery multiplication (no division operations)
 * - Specialized modular reduction for each curve's prime
 * - 4-limb representation (4 × 64-bit) for optimal SIMD
 * - Constant-time operations for side-channel resistance
 * 
 * Performance target: 80% of OpenSSL's optimized implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_ECC_FE256_H
#define KCTSB_CRYPTO_ECC_FE256_H

#include <cstdint>
#include <cstring>
#include <array>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Field Element Types
// ============================================================================

/**
 * @brief 256-bit field element in 4-limb representation
 * 
 * For Montgomery form: a is stored as aR mod p where R = 2^256
 */
typedef struct {
    uint64_t limb[4];  // Little-endian: limb[0] is LSB
} fe256;

/**
 * @brief 512-bit intermediate result
 * Used for multiplication before reduction
 */
typedef struct {
    uint64_t limb[8];
} fe512;

// ============================================================================
// secp256k1 Constants
// ============================================================================

/**
 * secp256k1 prime: p = 2^256 - 2^32 - 977
 * = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
 */
extern const fe256 SECP256K1_P;

/**
 * Montgomery constant R^2 mod p for secp256k1
 * Used for converting to Montgomery form: Mont(a) = a * R mod p
 */
extern const fe256 SECP256K1_R2;

/**
 * Montgomery constant -p^(-1) mod 2^64 for secp256k1
 */
extern const uint64_t SECP256K1_N0;

// ============================================================================
// SM2 Constants
// ============================================================================

/**
 * SM2 prime: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * = 0xFFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
 */
extern const fe256 SM2_P;

/**
 * Montgomery constant R^2 mod p for SM2
 */
extern const fe256 SM2_R2;

/**
 * Montgomery constant -p^(-1) mod 2^64 for SM2
 */
extern const uint64_t SM2_N0;

// ============================================================================
// Field Element Operations - Generic
// ============================================================================

/**
 * @brief Copy field element
 * @param dst Destination
 * @param src Source
 */
static inline void fe256_copy(fe256* dst, const fe256* src) {
    dst->limb[0] = src->limb[0];
    dst->limb[1] = src->limb[1];
    dst->limb[2] = src->limb[2];
    dst->limb[3] = src->limb[3];
}

/**
 * @brief Set field element to zero
 * @param a Field element
 */
static inline void fe256_zero(fe256* a) {
    a->limb[0] = 0;
    a->limb[1] = 0;
    a->limb[2] = 0;
    a->limb[3] = 0;
}

/**
 * @brief Set field element to one
 * @param a Field element
 */
static inline void fe256_one(fe256* a) {
    a->limb[0] = 1;
    a->limb[1] = 0;
    a->limb[2] = 0;
    a->limb[3] = 0;
}

/**
 * @brief Check if field element is zero (constant-time)
 * @param a Field element
 * @return 1 if zero, 0 otherwise
 */
static inline int fe256_is_zero(const fe256* a) {
    uint64_t x = a->limb[0] | a->limb[1] | a->limb[2] | a->limb[3];
    // Constant-time zero check
    return ((x | (~x + 1)) >> 63) ^ 1;
}

/**
 * @brief Compare field elements (constant-time)
 * @param a First element
 * @param b Second element
 * @return 1 if equal, 0 otherwise
 */
int fe256_equal(const fe256* a, const fe256* b);

// ============================================================================
// Field Arithmetic - secp256k1
// ============================================================================

/**
 * @brief secp256k1 modular addition: r = (a + b) mod p
 * @param r Result
 * @param a First operand
 * @param b Second operand
 */
void fe256_add_secp256k1(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief secp256k1 modular subtraction: r = (a - b) mod p
 * @param r Result
 * @param a First operand
 * @param b Second operand
 */
void fe256_sub_secp256k1(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief secp256k1 modular negation: r = -a mod p
 * @param r Result
 * @param a Operand
 */
void fe256_neg_secp256k1(fe256* r, const fe256* a);

/**
 * @brief secp256k1 Montgomery multiplication: r = a * b * R^(-1) mod p
 * 
 * This is the core operation for field arithmetic.
 * Uses specialized reduction for p = 2^256 - 2^32 - 977.
 * 
 * @param r Result (Montgomery form)
 * @param a First operand (Montgomery form)
 * @param b Second operand (Montgomery form)
 */
void fe256_mul_mont_secp256k1(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief secp256k1 Montgomery squaring: r = a^2 * R^(-1) mod p
 * @param r Result
 * @param a Operand
 */
void fe256_sqr_mont_secp256k1(fe256* r, const fe256* a);

/**
 * @brief secp256k1 fast modular reduction for 512-bit input
 * 
 * Uses the property: 2^256 ≡ 2^32 + 977 (mod p)
 * 
 * @param r Result (256-bit)
 * @param a Input (512-bit)
 */
void fe256_reduce_secp256k1(fe256* r, const fe512* a);

/**
 * @brief secp256k1 modular inversion: r = a^(-1) mod p
 * Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
 * @param r Result
 * @param a Operand
 */
void fe256_inv_secp256k1(fe256* r, const fe256* a);

/**
 * @brief Convert to Montgomery form: r = a * R mod p
 * @param r Result (Montgomery form)
 * @param a Input (normal form)
 */
void fe256_to_mont_secp256k1(fe256* r, const fe256* a);

/**
 * @brief Convert from Montgomery form: r = a * R^(-1) mod p
 * @param r Result (normal form)
 * @param a Input (Montgomery form)
 */
void fe256_from_mont_secp256k1(fe256* r, const fe256* a);

// ============================================================================
// Field Arithmetic - SM2
// ============================================================================

/**
 * @brief SM2 modular addition: r = (a + b) mod p
 */
void fe256_add_sm2(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief SM2 modular subtraction: r = (a - b) mod p
 */
void fe256_sub_sm2(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief SM2 modular negation: r = -a mod p
 */
void fe256_neg_sm2(fe256* r, const fe256* a);

/**
 * @brief SM2 Montgomery multiplication: r = a * b * R^(-1) mod p
 */
void fe256_mul_mont_sm2(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief SM2 Montgomery squaring: r = a^2 * R^(-1) mod p
 */
void fe256_sqr_mont_sm2(fe256* r, const fe256* a);

/**
 * @brief SM2 fast modular reduction for 512-bit input
 * 
 * Uses the SM2 prime structure for efficient reduction.
 * 
 * @param r Result (256-bit)
 * @param a Input (512-bit)
 */
void fe256_reduce_sm2(fe256* r, const fe512* a);

/**
 * @brief SM2 modular inversion: r = a^(-1) mod p
 */
void fe256_inv_sm2(fe256* r, const fe256* a);

/**
 * @brief Convert to Montgomery form for SM2
 */
void fe256_to_mont_sm2(fe256* r, const fe256* a);

/**
 * @brief Convert from Montgomery form for SM2
 */
void fe256_from_mont_sm2(fe256* r, const fe256* a);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Convert bytes to field element (big-endian)
 * @param r Output field element
 * @param bytes Input bytes (32 bytes)
 */
void fe256_from_bytes(fe256* r, const uint8_t bytes[32]);

/**
 * @brief Convert field element to bytes (big-endian)
 * @param bytes Output bytes (32 bytes)
 * @param a Input field element
 */
void fe256_to_bytes(uint8_t bytes[32], const fe256* a);

/**
 * @brief Conditional move (constant-time)
 * @param r Destination (unchanged if cond=0)
 * @param a Source
 * @param cond Condition (0 or 1)
 */
void fe256_cmov(fe256* r, const fe256* a, int cond);

/**
 * @brief Conditional negate (constant-time)
 * @param r Result
 * @param a Input
 * @param cond If 1, r = -a; if 0, r = a
 * @param curve_type 0 = secp256k1, 1 = SM2
 */
void fe256_cneg(fe256* r, const fe256* a, int cond, int curve_type);

// ============================================================================
// Wide Multiplication Helpers
// ============================================================================

/**
 * @brief Full 256×256 → 512 bit multiplication
 * @param r Result (512-bit)
 * @param a First operand
 * @param b Second operand
 */
void fe256_mul_wide(fe512* r, const fe256* a, const fe256* b);

/**
 * @brief Full 256-bit squaring → 512 bit result
 * @param r Result (512-bit)
 * @param a Operand
 */
void fe256_sqr_wide(fe512* r, const fe256* a);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_CRYPTO_ECC_FE256_H */
