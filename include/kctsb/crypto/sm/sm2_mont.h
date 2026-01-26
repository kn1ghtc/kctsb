/**
 * @file sm2_mont.h
 * @brief SM2 Montgomery Domain Field Arithmetic Header
 * 
 * Optimized 256-bit field arithmetic using Montgomery multiplication
 * for SM2 elliptic curve operations.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CRYPTO_SM_SM2_MONT_H_
#define KCTSB_CRYPTO_SM_SM2_MONT_H_

#include <cstdint>
#include <cstddef>

namespace kctsb::internal::sm2::mont {

// ============================================================================
// Data Types
// ============================================================================

/**
 * @brief 256-bit field element (4 x 64-bit limbs, little-endian)
 */
struct alignas(32) fe256 {
    uint64_t limb[4];
};

/**
 * @brief 512-bit intermediate result
 */
struct fe512 {
    uint64_t limb[8];
};

// ============================================================================
// Constants (defined in sm2_mont.cpp)
// ============================================================================

/// SM2 prime p = 2^256 - 2^224 - 2^96 + 2^64 - 1
extern const fe256 SM2_P;

/// 2^256 - p (used for final reduction and as MONT_ONE)
extern const fe256 SM2_NEG_P;

/// Montgomery constant: p' = -p^(-1) mod 2^256
extern const fe256 SM2_P_PRIME;

/// R^2 mod p (for converting to Montgomery form)
extern const fe256 SM2_RR;

/// 1 in Montgomery form = R mod p
extern const fe256 SM2_MONT_ONE;

/// SM2 curve order n
extern const fe256 SM2_N;

/// 2^256 - n
extern const fe256 SM2_NEG_N;

/// n' = -n^(-1) mod 2^256
extern const fe256 SM2_N_PRIME;

// ============================================================================
// Basic Operations
// ============================================================================

/**
 * @brief Copy fe256
 */
void fe256_copy(fe256* dst, const fe256* src);

/**
 * @brief Set fe256 to zero
 */
void fe256_zero(fe256* a);

/**
 * @brief Constant-time conditional copy
 * @param dst Destination
 * @param src Source
 * @param cond If non-zero, copy src to dst
 */
void fe256_cmov(fe256* dst, const fe256* src, uint64_t cond);

/**
 * @brief Compare two fe256 values
 * @return -1 if a < b, 0 if a == b, 1 if a > b
 */
int fe256_cmp(const fe256* a, const fe256* b);

/**
 * @brief Check if fe256 is zero (constant-time)
 * @return 1 if zero, 0 otherwise
 */
uint64_t fe256_is_zero(const fe256* a);

// ============================================================================
// Modular Arithmetic (mod p)
// ============================================================================

/**
 * @brief Modular addition: r = (a + b) mod p
 */
void fe256_modp_add(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief Modular subtraction: r = (a - b) mod p
 */
void fe256_modp_sub(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief Modular doubling: r = 2*a mod p
 */
void fe256_modp_dbl(fe256* r, const fe256* a);

/**
 * @brief Modular negation: r = -a mod p
 */
void fe256_modp_neg(fe256* r, const fe256* a);

/**
 * @brief Modular halving: r = a/2 mod p
 */
void fe256_modp_half(fe256* r, const fe256* a);

// ============================================================================
// Montgomery Domain Operations
// ============================================================================

/**
 * @brief Montgomery multiplication: r = a * b * R^(-1) mod p
 * 
 * Both a and b should be in Montgomery form.
 * Result r is also in Montgomery form.
 */
void fe256_mont_mul(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief Montgomery squaring: r = a^2 * R^(-1) mod p
 */
void fe256_mont_sqr(fe256* r, const fe256* a);

/**
 * @brief Convert to Montgomery form: r = a * R mod p
 */
void fe256_to_mont(fe256* r, const fe256* a);

/**
 * @brief Convert from Montgomery form: r = a * R^(-1) mod p
 */
void fe256_from_mont(fe256* r, const fe256* a);

/**
 * @brief Montgomery exponentiation: r = a^e mod p (in Montgomery form)
 */
void fe256_mont_exp(fe256* r, const fe256* a, const fe256* e);

/**
 * @brief Montgomery inversion using optimized addition chain
 * 
 * @param r Result (in Montgomery form)
 * @param a Input (in Montgomery form, must be non-zero)
 */
void fe256_mont_inv(fe256* r, const fe256* a);

/**
 * @brief Square root in Montgomery form
 * 
 * @param r Result (in Montgomery form)
 * @param a Input (in Montgomery form)
 * @return 1 if square root exists, 0 otherwise
 */
int fe256_mont_sqrt(fe256* r, const fe256* a);

// ============================================================================
// Byte Conversion
// ============================================================================

/**
 * @brief Convert big-endian bytes to fe256
 */
void fe256_from_bytes(fe256* r, const uint8_t bytes[32]);

/**
 * @brief Convert fe256 to big-endian bytes
 */
void fe256_to_bytes(uint8_t bytes[32], const fe256* a);

// ============================================================================
// Order n Operations
// ============================================================================

/**
 * @brief Modular addition mod n: r = (a + b) mod n
 */
void fe256_modn_add(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief Modular subtraction mod n: r = (a - b) mod n
 */
void fe256_modn_sub(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief Modular negation mod n: r = -a mod n
 */
void fe256_modn_neg(fe256* r, const fe256* a);

/**
 * @brief Montgomery multiplication mod n: r = a * b * R^(-1) mod n
 */
void fe256_modn_mont_mul(fe256* r, const fe256* a, const fe256* b);

/**
 * @brief Montgomery squaring mod n: r = a^2 * R^(-1) mod n
 */
void fe256_modn_mont_sqr(fe256* r, const fe256* a);

/**
 * @brief Convert to Montgomery form mod n: r = a * R mod n
 */
void fe256_modn_to_mont(fe256* r, const fe256* a);

/**
 * @brief Convert from Montgomery form mod n: r = a * R^(-1) mod n
 */
void fe256_modn_from_mont(fe256* r, const fe256* a);

/**
 * @brief Modular inverse mod n using Fermat's little theorem: r = a^(-1) mod n
 */
void fe256_modn_inv(fe256* r, const fe256* a);

/**
 * @brief Modular multiplication mod n: r = (a * b) mod n
 * Not in Montgomery form - direct multiplication with reduction
 */
void fe256_modn_mul(fe256* r, const fe256* a, const fe256* b);

}  // namespace kctsb::internal::sm2::mont

#endif  // KCTSB_CRYPTO_SM_SM2_MONT_H_
