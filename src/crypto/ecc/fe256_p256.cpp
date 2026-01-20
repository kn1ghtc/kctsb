/**
 * @file fe256_p256.cpp
 * @brief NIST P-256 (secp256r1) Specialized Field Element Operations
 *
 * High-performance field arithmetic optimized for NIST P-256 curve.
 * Uses the special structure of the P-256 prime for fast reduction:
 *   p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *
 * Key optimizations:
 * - Solinas reduction exploiting prime structure
 * - Montgomery multiplication with specialized constants
 * - 4-limb representation for optimal 64-bit CPU utilization
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "fe256.h"
#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

// ============================================================================
// 128-bit Arithmetic Helpers (same as fe256.cpp)
// ============================================================================

#if defined(__SIZEOF_INT128__)
// Suppress pedantic warning for __int128 which is supported by GCC/Clang
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
typedef unsigned __int128 uint128_t;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static inline void p256_mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t product = (uint128_t)a * b;
    *lo = (uint64_t)product;
    *hi = (uint64_t)(product >> 64);
}

static inline uint64_t p256_adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint128_t sum = (uint128_t)a + b + carry_in;
    *carry_out = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
}

static inline uint64_t p256_sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint128_t diff = (uint128_t)a - b - borrow_in;
    *borrow_out = (diff >> 127) ? 1 : 0;
    return (uint64_t)diff;
}

#elif defined(_MSC_VER) && defined(_M_X64)

static inline void p256_mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    *lo = _umul128(a, b, hi);
}

static inline uint64_t p256_adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    unsigned char c;
    uint64_t sum = _addcarry_u64((unsigned char)carry_in, a, b, (unsigned long long*)&c);
    *carry_out = c;
    return sum;
}

static inline uint64_t p256_sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    unsigned char c;
    uint64_t diff = _subborrow_u64((unsigned char)borrow_in, a, b, (unsigned long long*)&c);
    *borrow_out = c;
    return diff;
}

#else
// Portable fallback
static inline void p256_mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint32_t a0 = (uint32_t)a, a1 = (uint32_t)(a >> 32);
    uint32_t b0 = (uint32_t)b, b1 = (uint32_t)(b >> 32);
    uint64_t p00 = (uint64_t)a0 * b0;
    uint64_t p01 = (uint64_t)a0 * b1;
    uint64_t p10 = (uint64_t)a1 * b0;
    uint64_t p11 = (uint64_t)a1 * b1;
    uint64_t mid = p01 + p10 + (p00 >> 32);
    *lo = (p00 & 0xFFFFFFFF) | (mid << 32);
    *hi = p11 + (mid >> 32);
}

static inline uint64_t p256_adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint64_t sum = a + b + carry_in;
    *carry_out = (sum < a) || (carry_in && sum == a) ? 1 : 0;
    return sum;
}

static inline uint64_t p256_sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint64_t diff = a - b - borrow_in;
    *borrow_out = (a < b) || (borrow_in && a == b) ? 1 : 0;
    return diff;
}
#endif

// ============================================================================
// P-256 Constants
// ============================================================================

/**
 * P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 * = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 *
 * In 64-bit limbs (little-endian):
 * limb[0] = 0xFFFFFFFFFFFFFFFF  (bits 0-63)
 * limb[1] = 0x00000000FFFFFFFF  (bits 64-127)
 * limb[2] = 0x0000000000000000  (bits 128-191)
 * limb[3] = 0xFFFFFFFF00000001  (bits 192-255)
 */
static const fe256 P256_P = {{
    0xFFFFFFFFFFFFFFFFULL,
    0x00000000FFFFFFFFULL,
    0x0000000000000000ULL,
    0xFFFFFFFF00000001ULL
}};

/**
 * R^2 mod p for Montgomery conversion
 * R = 2^256
 * R^2 mod p precomputed for P-256
 */
static const fe256 P256_R2 = {{
    0x0000000000000003ULL,
    0xFFFFFFFBFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFEULL,
    0x00000004FFFFFFFDULL
}};

/**
 * Montgomery constant n0 = -p^(-1) mod 2^64 for P-256
 */
static const uint64_t P256_N0 = 0x0000000000000001ULL;

// ============================================================================
// P-256 Field Operations
// ============================================================================

/**
 * @brief P-256 modular addition: r = (a + b) mod p
 */
void fe256_add_p256(fe256* r, const fe256* a, const fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    fe256 tmp;

    // Add a + b
    r->limb[0] = p256_adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = p256_adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = p256_adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = p256_adc64(a->limb[3], b->limb[3], carry, &carry);

    // Conditional subtraction of p
    tmp.limb[0] = p256_sbb64(r->limb[0], P256_P.limb[0], 0, &borrow);
    tmp.limb[1] = p256_sbb64(r->limb[1], P256_P.limb[1], borrow, &borrow);
    tmp.limb[2] = p256_sbb64(r->limb[2], P256_P.limb[2], borrow, &borrow);
    tmp.limb[3] = p256_sbb64(r->limb[3], P256_P.limb[3], borrow, &borrow);

    // If no borrow and carry from addition, use reduced value
    int use_reduced = (carry || !borrow) ? 1 : 0;
    fe256_cmov(r, &tmp, use_reduced);
}

/**
 * @brief P-256 modular subtraction: r = (a - b) mod p
 */
void fe256_sub_p256(fe256* r, const fe256* a, const fe256* b) {
    uint64_t borrow = 0;

    r->limb[0] = p256_sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = p256_sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = p256_sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = p256_sbb64(a->limb[3], b->limb[3], borrow, &borrow);

    // If borrow, add p back
    fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = p256_adc64(r->limb[0], P256_P.limb[0], 0, &carry);
    tmp.limb[1] = p256_adc64(r->limb[1], P256_P.limb[1], carry, &carry);
    tmp.limb[2] = p256_adc64(r->limb[2], P256_P.limb[2], carry, &carry);
    tmp.limb[3] = p256_adc64(r->limb[3], P256_P.limb[3], carry, &carry);

    fe256_cmov(r, &tmp, (int)borrow);
}

/**
 * @brief P-256 modular negation: r = -a mod p
 */
void fe256_neg_p256(fe256* r, const fe256* a) {
    int is_nonzero = !fe256_is_zero(a);

    uint64_t borrow = 0;
    r->limb[0] = p256_sbb64(P256_P.limb[0], a->limb[0], 0, &borrow);
    r->limb[1] = p256_sbb64(P256_P.limb[1], a->limb[1], borrow, &borrow);
    r->limb[2] = p256_sbb64(P256_P.limb[2], a->limb[2], borrow, &borrow);
    r->limb[3] = p256_sbb64(P256_P.limb[3], a->limb[3], borrow, &borrow);

    fe256 zero_fe;
    fe256_zero(&zero_fe);
    fe256_cmov(r, &zero_fe, !is_nonzero);
}

/**
 * @brief P-256 Solinas reduction for 512-bit input
 *
 * Uses the identity: 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p)
 *
 * For NIST primes, the reduction can be done with additions/subtractions only.
 * Input: 512-bit value in 8 limbs
 * Output: 256-bit value in 4 limbs (fully reduced mod p)
 *
 * The algorithm follows NIST FIPS 186-4 Appendix D.2.3.
 * For input c = (c15, c14, ..., c1, c0) as 32-bit words:
 *
 * NIST notation uses BIG-ENDIAN conceptually:
 * (A7||A6||A5||A4||A3||A2||A1||A0) means A7 is at bits 224-255 (highest)
 *
 * The formula is:
 * T  = (C7||C6||C5||C4||C3||C2||C1||C0)
 * S1 = (C15||C14||C13||C12||C11||0||0||0)
 * S2 = (0||C15||C14||C13||C12||0||0||0)
 * S3 = (C15||C14||0||0||0||C10||C9||C8)
 * S4 = (C8||C13||C15||C14||C13||C11||C10||C9)
 * D1 = (C10||C8||0||0||0||C13||C12||C11)
 * D2 = (C11||C9||0||0||C15||C14||C13||C12)
 * D3 = (C12||0||C10||C9||C8||C15||C14||C13)
 * D4 = (C13||0||C11||C10||C9||0||C15||C14)
 *
 * Result = T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4 (mod p)
 */
void fe256_reduce_p256(fe256* r, const fe512* a) {
    // Extract 32-bit words from 64-bit limbs
    // c[0] = bits 0-31 (least significant), c[15] = bits 480-511 (most significant)
    uint64_t c[16];
    for (int i = 0; i < 8; i++) {
        c[2*i] = (uint32_t)a->limb[i];
        c[2*i + 1] = (uint32_t)(a->limb[i] >> 32);
    }

    // Use 64-bit accumulators for each 32-bit position
    // t[0..7] for 256-bit result, t[8] for overflow
    int64_t t[9] = {0};

    // T = (c7, c6, c5, c4, c3, c2, c1, c0)
    t[0] = (int64_t)c[0];
    t[1] = (int64_t)c[1];
    t[2] = (int64_t)c[2];
    t[3] = (int64_t)c[3];
    t[4] = (int64_t)c[4];
    t[5] = (int64_t)c[5];
    t[6] = (int64_t)c[6];
    t[7] = (int64_t)c[7];

    // 2*S1 = 2 * (c15, c14, c13, c12, c11, 0, 0, 0)
    t[3] += 2 * (int64_t)c[11];
    t[4] += 2 * (int64_t)c[12];
    t[5] += 2 * (int64_t)c[13];
    t[6] += 2 * (int64_t)c[14];
    t[7] += 2 * (int64_t)c[15];

    // 2*S2 = 2 * (0, c15, c14, c13, c12, 0, 0, 0)
    t[3] += 2 * (int64_t)c[12];
    t[4] += 2 * (int64_t)c[13];
    t[5] += 2 * (int64_t)c[14];
    t[6] += 2 * (int64_t)c[15];

    // S3 = (c15, c14, 0, 0, 0, c10, c9, c8)
    t[0] += (int64_t)c[8];
    t[1] += (int64_t)c[9];
    t[2] += (int64_t)c[10];
    t[6] += (int64_t)c[14];
    t[7] += (int64_t)c[15];

    // S4 = (c8, c13, c15, c14, c13, c11, c10, c9)
    t[0] += (int64_t)c[9];
    t[1] += (int64_t)c[10];
    t[2] += (int64_t)c[11];
    t[3] += (int64_t)c[13];
    t[4] += (int64_t)c[14];
    t[5] += (int64_t)c[15];
    t[6] += (int64_t)c[13];
    t[7] += (int64_t)c[8];

    // -D1 = -(c10, c8, 0, 0, 0, c13, c12, c11)
    t[0] -= (int64_t)c[11];
    t[1] -= (int64_t)c[12];
    t[2] -= (int64_t)c[13];
    t[6] -= (int64_t)c[8];
    t[7] -= (int64_t)c[10];

    // -D2 = -(c11, c9, 0, 0, c15, c14, c13, c12)
    t[0] -= (int64_t)c[12];
    t[1] -= (int64_t)c[13];
    t[2] -= (int64_t)c[14];
    t[3] -= (int64_t)c[15];
    t[6] -= (int64_t)c[9];
    t[7] -= (int64_t)c[11];

    // -D3 = -(c12, 0, c10, c9, c8, c15, c14, c13)
    t[0] -= (int64_t)c[13];
    t[1] -= (int64_t)c[14];
    t[2] -= (int64_t)c[15];
    t[3] -= (int64_t)c[8];
    t[4] -= (int64_t)c[9];
    t[5] -= (int64_t)c[10];
    t[7] -= (int64_t)c[12];

    // -D4 = -(c13, 0, c11, c10, c9, 0, c15, c14)
    t[0] -= (int64_t)c[14];
    t[1] -= (int64_t)c[15];
    t[3] -= (int64_t)c[9];
    t[4] -= (int64_t)c[10];
    t[5] -= (int64_t)c[11];
    t[7] -= (int64_t)c[13];

    // Carry propagation with signed arithmetic
    int64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        t[i] += carry;
        carry = t[i] >> 32;
        t[i] &= 0xFFFFFFFFLL;
    }
    t[8] = carry;

    // Handle overflow/underflow by adding/subtracting p
    // p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    // p[0..7] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 1, 0xFFFFFFFF}
    while (t[8] < 0) {
        int64_t cc = 0;
        t[0] += 0xFFFFFFFFLL + cc; cc = t[0] >> 32; t[0] &= 0xFFFFFFFFLL;
        t[1] += 0xFFFFFFFFLL + cc; cc = t[1] >> 32; t[1] &= 0xFFFFFFFFLL;
        t[2] += 0xFFFFFFFFLL + cc; cc = t[2] >> 32; t[2] &= 0xFFFFFFFFLL;
        t[3] += 0x00000000LL + cc; cc = t[3] >> 32; t[3] &= 0xFFFFFFFFLL;
        t[4] += 0x00000000LL + cc; cc = t[4] >> 32; t[4] &= 0xFFFFFFFFLL;
        t[5] += 0x00000000LL + cc; cc = t[5] >> 32; t[5] &= 0xFFFFFFFFLL;
        t[6] += 0x00000001LL + cc; cc = t[6] >> 32; t[6] &= 0xFFFFFFFFLL;
        t[7] += 0xFFFFFFFFLL + cc; cc = t[7] >> 32; t[7] &= 0xFFFFFFFFLL;
        t[8] += cc;
    }

    while (t[8] > 0) {
        int64_t cc = 0;
        int64_t tmp = t[0] - 0xFFFFFFFFLL - cc;
        cc = (tmp < 0) ? 1 : 0; t[0] = tmp + (cc << 32);
        tmp = t[1] - 0xFFFFFFFFLL - cc;
        cc = (tmp < 0) ? 1 : 0; t[1] = tmp + (cc << 32);
        tmp = t[2] - 0xFFFFFFFFLL - cc;
        cc = (tmp < 0) ? 1 : 0; t[2] = tmp + (cc << 32);
        tmp = t[3] - 0x00000000LL - cc;
        cc = (tmp < 0) ? 1 : 0; t[3] = tmp + (cc << 32);
        tmp = t[4] - 0x00000000LL - cc;
        cc = (tmp < 0) ? 1 : 0; t[4] = tmp + (cc << 32);
        tmp = t[5] - 0x00000000LL - cc;
        cc = (tmp < 0) ? 1 : 0; t[5] = tmp + (cc << 32);
        tmp = t[6] - 0x00000001LL - cc;
        cc = (tmp < 0) ? 1 : 0; t[6] = tmp + (cc << 32);
        tmp = t[7] - 0xFFFFFFFFLL - cc;
        cc = (tmp < 0) ? 1 : 0; t[7] = tmp + (cc << 32);
        t[8] -= cc;
    }

    // Convert back to 64-bit limbs
    r->limb[0] = ((uint64_t)(uint32_t)t[0]) | (((uint64_t)(uint32_t)t[1]) << 32);
    r->limb[1] = ((uint64_t)(uint32_t)t[2]) | (((uint64_t)(uint32_t)t[3]) << 32);
    r->limb[2] = ((uint64_t)(uint32_t)t[4]) | (((uint64_t)(uint32_t)t[5]) << 32);
    r->limb[3] = ((uint64_t)(uint32_t)t[6]) | (((uint64_t)(uint32_t)t[7]) << 32);

    // Final reduction: ensure r < p
    uint64_t borrow = 0;
    fe256 tmp;
    tmp.limb[0] = p256_sbb64(r->limb[0], P256_P.limb[0], 0, &borrow);
    tmp.limb[1] = p256_sbb64(r->limb[1], P256_P.limb[1], borrow, &borrow);
    tmp.limb[2] = p256_sbb64(r->limb[2], P256_P.limb[2], borrow, &borrow);
    tmp.limb[3] = p256_sbb64(r->limb[3], P256_P.limb[3], borrow, &borrow);

    fe256_cmov(r, &tmp, !borrow);
}

/**
 * @brief P-256 Montgomery multiplication: r = a * b * R^(-1) mod p
 */
void fe256_mul_mont_p256(fe256* r, const fe256* a, const fe256* b) {
    fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_p256(r, &wide);
}

/**
 * @brief P-256 Montgomery squaring: r = a^2 * R^(-1) mod p
 */
void fe256_sqr_mont_p256(fe256* r, const fe256* a) {
    fe256_mul_mont_p256(r, a, a);
}

/**
 * @brief Convert to "Montgomery form" for P-256
 *
 * Note: Since fe256_mul_mont_p256 uses Solinas reduction (not true Montgomery),
 * this function is the identity operation. The "Montgomery" naming is kept
 * for API consistency with secp256k1, but no actual conversion occurs.
 */
void fe256_to_mont_p256(fe256* r, const fe256* a) {
    // Identity operation - Solinas reduction doesn't need Montgomery form
    fe256_copy(r, a);
}

/**
 * @brief Convert from "Montgomery form" for P-256
 *
 * Note: Identity operation since we use Solinas reduction, not Montgomery.
 */
void fe256_from_mont_p256(fe256* r, const fe256* a) {
    // Identity operation - no Montgomery form used
    fe256_copy(r, a);
}

/**
 * @brief P-256 modular inversion: r = a^(-1) mod p
 * Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
 *
 * Uses square-and-multiply method, processing from high bit to low.
 */
void fe256_inv_p256(fe256* r, const fe256* a) {
    // a^(-1) = a^(p-2) mod p
    fe256 result, base;

    fe256_copy(&base, a);

    // p-2 for P-256
    // p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    // p-2 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
    // Note: limb[0] = p.limb[0] - 2 (with underflow handling)
    uint64_t p_minus_2[4] = {
        0xFFFFFFFFFFFFFFFDULL,  // P256_P.limb[0] - 2
        0x00000000FFFFFFFFULL,  // P256_P.limb[1]
        0x0000000000000000ULL,  // P256_P.limb[2]
        0xFFFFFFFF00000001ULL   // P256_P.limb[3]
    };

    // Find highest set bit (should be 255)
    int start_bit = 255;
    
    // Start with result = a (not 1), then skip the first bit
    // This is equivalent to: result = 1, then for first bit: sqr(result), mul(result, base)
    // which gives result = base for the first set bit
    fe256_copy(&result, &base);
    
    // Process from bit 254 down to 0
    for (int i = start_bit - 1; i >= 0; i--) {
        int limb = i / 64;
        int bit_pos = i % 64;
        
        // Always square
        fe256_sqr_mont_p256(&result, &result);
        
        // Multiply if bit is set
        if ((p_minus_2[limb] >> bit_pos) & 1) {
            fe256_mul_mont_p256(&result, &result, &base);
        }
    }

    fe256_copy(r, &result);
}

// ============================================================================
// Accessors for P-256 Constants
// ============================================================================

const fe256* fe256_get_p256_prime(void) {
    return &P256_P;
}

const fe256* fe256_get_p256_r2(void) {
    return &P256_R2;
}

uint64_t fe256_get_p256_n0(void) {
    return P256_N0;
}
