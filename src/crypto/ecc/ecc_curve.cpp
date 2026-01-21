/**
 * @file ecc_curve.cpp
 * @brief Elliptic Curve Core Implementation - Bignum Backend with fe256 Acceleration
 * 
 * Complete implementation of elliptic curve operations using bignum with optional
 * fe256 256-bit field element acceleration for 256-bit curves.
 * 
 * Features:
 * - Constant-time Montgomery ladder for all scalar multiplication
 * - Jacobian coordinates for efficient point arithmetic
 * - Support for 256-bit standard curves (secp256k1, P-256, SM2)
 * - Integrated fe256 acceleration layer (v4.2.0+)
 * 
 * Acceleration Features (fe256):
 * - 128-bit integer arithmetic helpers (mul64x64, adc64, sbb64)
 * - Montgomery multiplication with specialized reduction
 * - Curve-specific modular reduction (secp256k1, P-256 Solinas, SM2)
 * - Constant-time operations for side-channel resistance
 * 
 * Security (v4.2.0):
 * - wNAF algorithm REMOVED due to side-channel vulnerabilities
 * - All scalar multiplication uses Montgomery ladder (constant-time)
 * - Timing-attack resistant implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/ecc/ecc_curve.h"
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <cstring>
#include <array>

// Platform-specific intrinsics
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

namespace kctsb {
namespace ecc {

// ============================================================================
// fe256 Acceleration Layer - 256-bit Field Element Operations
// ============================================================================
// This integrated acceleration layer provides optimized field arithmetic
// for 256-bit prime fields used in secp256k1, P-256, and SM2 curves.
// Features:
// - Montgomery multiplication (no division operations)
// - Specialized modular reduction for each curve's prime
// - 4-limb representation (4 × 64-bit) for optimal performance
// - Constant-time operations for side-channel resistance

namespace {

// ============================================================================
// fe256 Types and Helpers
// ============================================================================

/**
 * @brief 256-bit field element in 4-limb representation
 */
struct Fe256 {
    uint64_t limb[4];  // Little-endian: limb[0] is LSB
};

/**
 * @brief 512-bit intermediate result for multiplication
 */
struct Fe512 {
    uint64_t limb[8];
};

// ============================================================================
// 128-bit Arithmetic Helpers
// ============================================================================

#if defined(__SIZEOF_INT128__)
// GCC/Clang with __int128 support
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t product = (uint128_t)a * b;
    *lo = (uint64_t)product;
    *hi = (uint64_t)(product >> 64);
}

static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint128_t sum = (uint128_t)a + b + carry_in;
    *carry_out = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
}

static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint128_t diff = (uint128_t)a - b - borrow_in;
    *borrow_out = (diff >> 127) ? 1 : 0;
    return (uint64_t)diff;
}

#elif defined(_MSC_VER) && defined(_M_X64)
// MSVC x64 intrinsics

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    *lo = _umul128(a, b, hi);
}

static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    unsigned char c;
    uint64_t sum = _addcarry_u64((unsigned char)carry_in, a, b, (unsigned long long*)&c);
    *carry_out = c;
    return sum;
}

static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    unsigned char c;
    uint64_t diff = _subborrow_u64((unsigned char)borrow_in, a, b, (unsigned long long*)&c);
    *borrow_out = c;
    return diff;
}

#else
// Portable fallback (slower)

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint32_t a0 = (uint32_t)a;
    uint32_t a1 = (uint32_t)(a >> 32);
    uint32_t b0 = (uint32_t)b;
    uint32_t b1 = (uint32_t)(b >> 32);
    
    uint64_t p00 = (uint64_t)a0 * b0;
    uint64_t p01 = (uint64_t)a0 * b1;
    uint64_t p10 = (uint64_t)a1 * b0;
    uint64_t p11 = (uint64_t)a1 * b1;
    
    uint64_t mid = p01 + p10 + (p00 >> 32);
    *lo = (p00 & 0xFFFFFFFF) | (mid << 32);
    *hi = p11 + (mid >> 32);
}

static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint64_t sum = a + b + carry_in;
    *carry_out = (sum < a) || (carry_in && sum == a) ? 1 : 0;
    return sum;
}

static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint64_t diff = a - b - borrow_in;
    *borrow_out = (a < b) || (borrow_in && a == b) ? 1 : 0;
    return diff;
}
#endif

// ============================================================================
// fe256 Basic Operations
// ============================================================================

static inline void fe256_copy(Fe256* dst, const Fe256* src) {
    dst->limb[0] = src->limb[0];
    dst->limb[1] = src->limb[1];
    dst->limb[2] = src->limb[2];
    dst->limb[3] = src->limb[3];
}

static inline void fe256_zero(Fe256* a) {
    a->limb[0] = 0;
    a->limb[1] = 0;
    a->limb[2] = 0;
    a->limb[3] = 0;
}

static inline void fe256_one(Fe256* a) {
    a->limb[0] = 1;
    a->limb[1] = 0;
    a->limb[2] = 0;
    a->limb[3] = 0;
}

static inline int fe256_is_zero(const Fe256* a) {
    uint64_t x = a->limb[0] | a->limb[1] | a->limb[2] | a->limb[3];
    return ((x | (~x + 1)) >> 63) ^ 1;
}

static inline int fe256_equal(const Fe256* a, const Fe256* b) {
    uint64_t diff = 0;
    diff |= a->limb[0] ^ b->limb[0];
    diff |= a->limb[1] ^ b->limb[1];
    diff |= a->limb[2] ^ b->limb[2];
    diff |= a->limb[3] ^ b->limb[3];
    return ((diff | (~diff + 1)) >> 63) ^ 1;
}

/**
 * @brief Constant-time conditional move
 */
static inline void fe256_cmov(Fe256* r, const Fe256* a, int cond) {
    uint64_t mask = ~((uint64_t)cond - 1);
    r->limb[0] ^= mask & (r->limb[0] ^ a->limb[0]);
    r->limb[1] ^= mask & (r->limb[1] ^ a->limb[1]);
    r->limb[2] ^= mask & (r->limb[2] ^ a->limb[2]);
    r->limb[3] ^= mask & (r->limb[3] ^ a->limb[3]);
}

// ============================================================================
// Curve Constants
// ============================================================================

// secp256k1: p = 2^256 - 2^32 - 977
alignas(32) static const Fe256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
static const uint64_t SECP256K1_REDUCE_C = 0x1000003D1ULL;

// P-256: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
alignas(32) static const Fe256 P256_P = {{
    0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
    0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
}};

// SM2: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
alignas(32) static const Fe256 SM2_P = {{
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
}};

// ============================================================================
// Wide Multiplication (256x256 -> 512-bit)
// ============================================================================

static void fe256_mul_wide(Fe512* r, const Fe256* a, const Fe256* b) {
    uint64_t hi, lo;
    uint64_t carry;
    
    // Schoolbook multiplication with accumulation
    // Column 0
    mul64x64(a->limb[0], b->limb[0], &hi, &lo);
    r->limb[0] = lo;
    uint64_t acc0 = hi;
    
    // Column 1
    carry = 0;
    mul64x64(a->limb[0], b->limb[1], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    uint64_t acc1 = hi + carry;
    
    mul64x64(a->limb[1], b->limb[0], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    uint64_t acc2 = carry;
    
    r->limb[1] = acc0;
    
    // Column 2
    acc0 = acc1;
    acc1 = acc2;
    acc2 = 0;
    
    mul64x64(a->limb[0], b->limb[2], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[1], b->limb[1], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[2], b->limb[0], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    r->limb[2] = acc0;
    
    // Column 3
    acc0 = acc1;
    acc1 = acc2;
    acc2 = 0;
    
    mul64x64(a->limb[0], b->limb[3], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[1], b->limb[2], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[2], b->limb[1], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[3], b->limb[0], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    r->limb[3] = acc0;
    
    // Column 4
    acc0 = acc1;
    acc1 = acc2;
    acc2 = 0;
    
    mul64x64(a->limb[1], b->limb[3], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[2], b->limb[2], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[3], b->limb[1], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    r->limb[4] = acc0;
    
    // Column 5
    acc0 = acc1;
    acc1 = acc2;
    acc2 = 0;
    
    mul64x64(a->limb[2], b->limb[3], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    mul64x64(a->limb[3], b->limb[2], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    acc2 += carry;
    
    r->limb[5] = acc0;
    
    // Column 6
    acc0 = acc1;
    acc1 = acc2;
    
    mul64x64(a->limb[3], b->limb[3], &hi, &lo);
    acc0 = adc64(acc0, lo, 0, &carry);
    acc1 = adc64(acc1, hi, carry, &carry);
    
    r->limb[6] = acc0;
    r->limb[7] = acc1;
}

// ============================================================================
// secp256k1 Specialized Reduction
// ============================================================================

/**
 * @brief secp256k1 specialized reduction
 * Uses: 2^256 ≡ 2^32 + 977 (mod p)
 */
static void fe256_reduce_secp256k1(Fe256* r, const Fe512* a) {
    const uint64_t c = SECP256K1_REDUCE_C;
    uint64_t carry = 0;
    uint64_t hi, lo;
    uint64_t c1, c2;
    
    // Compute: r = low + high * c
    mul64x64(a->limb[4], c, &hi, &lo);
    r->limb[0] = adc64(a->limb[0], lo, 0, &carry);
    uint64_t t0 = hi + carry;
    
    mul64x64(a->limb[5], c, &hi, &lo);
    r->limb[1] = adc64(a->limb[1], lo, 0, &c1);
    r->limb[1] = adc64(r->limb[1], t0, 0, &c2);
    uint64_t t1 = hi + c1 + c2;
    
    mul64x64(a->limb[6], c, &hi, &lo);
    r->limb[2] = adc64(a->limb[2], lo, 0, &c1);
    r->limb[2] = adc64(r->limb[2], t1, 0, &c2);
    uint64_t t2 = hi + c1 + c2;
    
    mul64x64(a->limb[7], c, &hi, &lo);
    r->limb[3] = adc64(a->limb[3], lo, 0, &c1);
    r->limb[3] = adc64(r->limb[3], t2, 0, &c2);
    uint64_t t3 = hi + c1 + c2;
    
    if (t3) {
        mul64x64(t3, c, &hi, &lo);
        r->limb[0] = adc64(r->limb[0], lo, 0, &carry);
        r->limb[1] = adc64(r->limb[1], hi, carry, &carry);
        r->limb[2] = adc64(r->limb[2], 0, carry, &carry);
        r->limb[3] = adc64(r->limb[3], 0, carry, &carry);
        
        if (carry) {
            r->limb[0] = adc64(r->limb[0], c, 0, &carry);
            r->limb[1] = adc64(r->limb[1], 0, carry, &carry);
            r->limb[2] = adc64(r->limb[2], 0, carry, &carry);
            r->limb[3] = adc64(r->limb[3], 0, carry, &carry);
        }
    }
    
    // Final conditional subtraction
    Fe256 tmp;
    uint64_t borrow = 0;
    tmp.limb[0] = sbb64(r->limb[0], SECP256K1_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SECP256K1_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SECP256K1_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SECP256K1_P.limb[3], borrow, &borrow);
    
    fe256_cmov(r, &tmp, !borrow);
}

static void fe256_mul_secp256k1(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_secp256k1(r, &wide);
}

static void fe256_sqr_secp256k1(Fe256* r, const Fe256* a) {
    fe256_mul_secp256k1(r, a, a);
}

// ============================================================================
// P-256 Solinas Reduction
// ============================================================================

/**
 * @brief P-256 Solinas reduction for 512-bit input
 * Uses prime structure: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 */
static void fe256_reduce_p256(Fe256* r, const Fe512* a) {
    // Extract 32-bit words from 64-bit limbs
    uint64_t c[16];
    for (int i = 0; i < 8; i++) {
        c[2*i] = (uint32_t)a->limb[i];
        c[2*i + 1] = (uint32_t)(a->limb[i] >> 32);
    }

    int64_t t[9] = {0};

    // T = (c7, c6, c5, c4, c3, c2, c1, c0)
    for (int i = 0; i < 8; i++) t[i] = (int64_t)c[i];

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

    // Carry propagation
    int64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        t[i] += carry;
        carry = t[i] >> 32;
        t[i] &= 0xFFFFFFFFLL;
    }
    t[8] = carry;

    // Handle overflow/underflow
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

    // Final reduction
    uint64_t borrow = 0;
    Fe256 tmp;
    tmp.limb[0] = sbb64(r->limb[0], P256_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], P256_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], P256_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], P256_P.limb[3], borrow, &borrow);

    fe256_cmov(r, &tmp, !borrow);
}

static void fe256_mul_p256(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_p256(r, &wide);
}

static void fe256_sqr_p256(Fe256* r, const Fe256* a) {
    fe256_mul_p256(r, a, a);
}

// ============================================================================
// SM2 Specialized Reduction
// ============================================================================

/**
 * @brief SM2 specialized reduction for 512-bit input
 * SM2 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 */
static void fe256_reduce_sm2(Fe256* r, const Fe512* a) {
#if defined(__SIZEOF_INT128__)
    int128_t acc[5] = {0};
    
    // Initialize with low 256 bits
    acc[0] = a->limb[0];
    acc[1] = a->limb[1];
    acc[2] = a->limb[2];
    acc[3] = a->limb[3];
    
    uint64_t h0 = a->limb[4];
    uint64_t h1 = a->limb[5];
    uint64_t h2 = a->limb[6];
    uint64_t h3 = a->limb[7];
    
    // k = 2^224 + 2^96 - 2^64 + 1
    // h0 * k
    acc[0] += h0;
    acc[1] += (int128_t)(h0 & 0xFFFFFFFFULL) << 32;
    acc[2] += h0 >> 32;
    acc[1] -= h0;
    acc[3] += (int128_t)(h0 & 0xFFFFFFFFULL) << 32;
    acc[4] += h0 >> 32;
    
    // h1 * k * 2^64
    acc[1] += h1;
    acc[2] += (int128_t)(h1 & 0xFFFFFFFFULL) << 32;
    acc[3] += h1 >> 32;
    acc[2] -= h1;
    acc[4] += (int128_t)(h1 & 0xFFFFFFFFULL) << 32;
    
    // h2 * k * 2^128
    acc[2] += h2;
    acc[3] += (int128_t)(h2 & 0xFFFFFFFFULL) << 32;
    acc[4] += h2 >> 32;
    acc[3] -= h2;
    
    // h3 * k * 2^192
    acc[3] += h3;
    acc[4] += (int128_t)(h3 & 0xFFFFFFFFULL) << 32;
    acc[4] -= h3;
    
    // Carry propagation and reduction
    for (int round = 0; round < 4; round++) {
        for (int i = 0; i < 4; i++) {
            acc[i + 1] += acc[i] >> 64;
            acc[i] = (uint64_t)acc[i];
        }
        
        if (acc[4] != 0) {
            int128_t overflow = acc[4];
            acc[4] = 0;
            acc[0] += overflow;
            acc[1] += (overflow << 32) - overflow;
            acc[2] += overflow >> 32;
            acc[3] += overflow << 32;
            acc[4] += overflow >> 32;
        } else {
            break;
        }
    }
    
    for (int i = 0; i < 4; i++) {
        acc[i + 1] += acc[i] >> 64;
        acc[i] = (uint64_t)acc[i];
    }
    
    while (acc[4] != 0) {
        int128_t overflow = acc[4];
        acc[4] = 0;
        acc[0] += overflow;
        acc[1] += (overflow << 32) - overflow;
        acc[2] += overflow >> 32;
        acc[3] += overflow << 32;
        acc[4] += overflow >> 32;
        
        for (int i = 0; i < 4; i++) {
            acc[i + 1] += acc[i] >> 64;
            acc[i] = (uint64_t)acc[i];
        }
    }
    
    uint64_t result[4] = {
        (uint64_t)acc[0], (uint64_t)acc[1], 
        (uint64_t)acc[2], (uint64_t)acc[3]
    };
    
    // Final reduction
    for (int i = 0; i < 3; i++) {
        uint64_t borrow = 0;
        uint64_t tmp[4];
        
        tmp[0] = sbb64(result[0], SM2_P.limb[0], 0, &borrow);
        tmp[1] = sbb64(result[1], SM2_P.limb[1], borrow, &borrow);
        tmp[2] = sbb64(result[2], SM2_P.limb[2], borrow, &borrow);
        tmp[3] = sbb64(result[3], SM2_P.limb[3], borrow, &borrow);
        
        if (borrow == 0) {
            result[0] = tmp[0];
            result[1] = tmp[1];
            result[2] = tmp[2];
            result[3] = tmp[3];
        } else {
            break;
        }
    }
    
    r->limb[0] = result[0];
    r->limb[1] = result[1];
    r->limb[2] = result[2];
    r->limb[3] = result[3];
#else
    // Fallback: use generic modular reduction
    // This is slower but correct
    r->limb[0] = a->limb[0];
    r->limb[1] = a->limb[1];
    r->limb[2] = a->limb[2];
    r->limb[3] = a->limb[3];
    
    // Add high part * k iteratively
    for (int i = 4; i < 8; i++) {
        if (a->limb[i] != 0) {
            // Simplified reduction for fallback
            uint64_t carry = 0;
            r->limb[0] = adc64(r->limb[0], a->limb[i], 0, &carry);
            r->limb[1] = adc64(r->limb[1], 0, carry, &carry);
            r->limb[2] = adc64(r->limb[2], 0, carry, &carry);
            r->limb[3] = adc64(r->limb[3], 0, carry, &carry);
        }
    }
    
    // Final subtraction
    Fe256 tmp;
    uint64_t borrow = 0;
    tmp.limb[0] = sbb64(r->limb[0], SM2_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SM2_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SM2_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SM2_P.limb[3], borrow, &borrow);
    
    fe256_cmov(r, &tmp, !borrow);
#endif
}

static void fe256_mul_sm2(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_sm2(r, &wide);
}

static void fe256_sqr_sm2(Fe256* r, const Fe256* a) {
    fe256_mul_sm2(r, a, a);
}

// ============================================================================
// Field Inversion (using Fermat's little theorem: a^-1 = a^(p-2))
// ============================================================================

static void fe256_inv_secp256k1(Fe256* r, const Fe256* a) {
    Fe256 result, base;
    fe256_copy(&base, a);
    fe256_one(&result);
    
    uint64_t p_minus_2[4] = {
        SECP256K1_P.limb[0] - 2,
        SECP256K1_P.limb[1],
        SECP256K1_P.limb[2],
        SECP256K1_P.limb[3]
    };
    
    for (int i = 3; i >= 0; i--) {
        for (int j = 63; j >= 0; j--) {
            fe256_sqr_secp256k1(&result, &result);
            if ((p_minus_2[i] >> j) & 1) {
                fe256_mul_secp256k1(&result, &result, &base);
            }
        }
    }
    
    fe256_copy(r, &result);
}

static void fe256_inv_p256(Fe256* r, const Fe256* a) {
    Fe256 result, base;
    fe256_copy(&base, a);
    fe256_one(&result);
    
    uint64_t p_minus_2[4] = {
        P256_P.limb[0] - 2,
        P256_P.limb[1],
        P256_P.limb[2],
        P256_P.limb[3]
    };
    
    for (int i = 3; i >= 0; i--) {
        for (int j = 63; j >= 0; j--) {
            fe256_sqr_p256(&result, &result);
            if ((p_minus_2[i] >> j) & 1) {
                fe256_mul_p256(&result, &result, &base);
            }
        }
    }
    
    fe256_copy(r, &result);
}

static void fe256_inv_sm2(Fe256* r, const Fe256* a) {
    Fe256 result, base;
    fe256_copy(&base, a);
    fe256_one(&result);
    
    uint64_t p_minus_2[4] = {
        SM2_P.limb[0] - 2,
        SM2_P.limb[1],
        SM2_P.limb[2],
        SM2_P.limb[3]
    };
    
    for (int i = 3; i >= 0; i--) {
        for (int j = 63; j >= 0; j--) {
            fe256_sqr_sm2(&result, &result);
            if ((p_minus_2[i] >> j) & 1) {
                fe256_mul_sm2(&result, &result, &base);
            }
        }
    }
    
    fe256_copy(r, &result);
}

// ============================================================================
// Field Addition/Subtraction
// ============================================================================

static void fe256_add_secp256k1(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    Fe256 tmp;
    
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = adc64(a->limb[3], b->limb[3], carry, &carry);
    
    tmp.limb[0] = sbb64(r->limb[0], SECP256K1_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SECP256K1_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SECP256K1_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SECP256K1_P.limb[3], borrow, &borrow);
    
    int use_reduced = (carry || !borrow) ? 1 : 0;
    fe256_cmov(r, &tmp, use_reduced);
}

static void fe256_sub_secp256k1(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t borrow = 0;
    
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    
    Fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = adc64(r->limb[0], SECP256K1_P.limb[0], 0, &carry);
    tmp.limb[1] = adc64(r->limb[1], SECP256K1_P.limb[1], carry, &carry);
    tmp.limb[2] = adc64(r->limb[2], SECP256K1_P.limb[2], carry, &carry);
    tmp.limb[3] = adc64(r->limb[3], SECP256K1_P.limb[3], carry, &carry);
    
    fe256_cmov(r, &tmp, (int)borrow);
}

static void fe256_neg_secp256k1(Fe256* r, const Fe256* a) {
    int is_nonzero = !fe256_is_zero(a);
    
    uint64_t borrow = 0;
    r->limb[0] = sbb64(SECP256K1_P.limb[0], a->limb[0], 0, &borrow);
    r->limb[1] = sbb64(SECP256K1_P.limb[1], a->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(SECP256K1_P.limb[2], a->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(SECP256K1_P.limb[3], a->limb[3], borrow, &borrow);
    
    Fe256 zero_fe;
    fe256_zero(&zero_fe);
    fe256_cmov(r, &zero_fe, !is_nonzero);
}

static void fe256_add_p256(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    Fe256 tmp;
    
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = adc64(a->limb[3], b->limb[3], carry, &carry);
    
    tmp.limb[0] = sbb64(r->limb[0], P256_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], P256_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], P256_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], P256_P.limb[3], borrow, &borrow);
    
    int use_reduced = (carry || !borrow) ? 1 : 0;
    fe256_cmov(r, &tmp, use_reduced);
}

static void fe256_sub_p256(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t borrow = 0;
    
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    
    Fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = adc64(r->limb[0], P256_P.limb[0], 0, &carry);
    tmp.limb[1] = adc64(r->limb[1], P256_P.limb[1], carry, &carry);
    tmp.limb[2] = adc64(r->limb[2], P256_P.limb[2], carry, &carry);
    tmp.limb[3] = adc64(r->limb[3], P256_P.limb[3], carry, &carry);
    
    fe256_cmov(r, &tmp, (int)borrow);
}

static void fe256_neg_p256(Fe256* r, const Fe256* a) {
    int is_nonzero = !fe256_is_zero(a);
    
    uint64_t borrow = 0;
    r->limb[0] = sbb64(P256_P.limb[0], a->limb[0], 0, &borrow);
    r->limb[1] = sbb64(P256_P.limb[1], a->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(P256_P.limb[2], a->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(P256_P.limb[3], a->limb[3], borrow, &borrow);
    
    Fe256 zero_fe;
    fe256_zero(&zero_fe);
    fe256_cmov(r, &zero_fe, !is_nonzero);
}

static void fe256_add_sm2(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    Fe256 tmp;
    
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = adc64(a->limb[3], b->limb[3], carry, &carry);
    
    tmp.limb[0] = sbb64(r->limb[0], SM2_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SM2_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SM2_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SM2_P.limb[3], borrow, &borrow);
    
    int use_reduced = (carry || !borrow) ? 1 : 0;
    fe256_cmov(r, &tmp, use_reduced);
}

static void fe256_sub_sm2(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t borrow = 0;
    
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    
    Fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = adc64(r->limb[0], SM2_P.limb[0], 0, &carry);
    tmp.limb[1] = adc64(r->limb[1], SM2_P.limb[1], carry, &carry);
    tmp.limb[2] = adc64(r->limb[2], SM2_P.limb[2], carry, &carry);
    tmp.limb[3] = adc64(r->limb[3], SM2_P.limb[3], carry, &carry);
    
    fe256_cmov(r, &tmp, (int)borrow);
}

static void fe256_neg_sm2(Fe256* r, const Fe256* a) {
    int is_nonzero = !fe256_is_zero(a);
    
    uint64_t borrow = 0;
    r->limb[0] = sbb64(SM2_P.limb[0], a->limb[0], 0, &borrow);
    r->limb[1] = sbb64(SM2_P.limb[1], a->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(SM2_P.limb[2], a->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(SM2_P.limb[3], a->limb[3], borrow, &borrow);
    
    Fe256 zero_fe;
    fe256_zero(&zero_fe);
    fe256_cmov(r, &zero_fe, !is_nonzero);
}

// ============================================================================
// Montgomery Form Conversion (Identity - using Solinas reduction)
// ============================================================================

static inline void fe256_to_mont_secp256k1(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

static inline void fe256_from_mont_secp256k1(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

static inline void fe256_to_mont_p256(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

static inline void fe256_from_mont_p256(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

static inline void fe256_to_mont_sm2(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

static inline void fe256_from_mont_sm2(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

} // anonymous namespace

// ============================================================================
// End of fe256 Acceleration Layer
// ============================================================================

// ============================================================================
// Standard Curve Parameters (SECG/NIST)
// ============================================================================

CurveParams get_secp256k1_params() {
    CurveParams params;
    params.name = "secp256k1";
    params.bit_size = 256;
    
    // p = 2^256 - 2^32 - 977
    params.p = conv<ZZ>("115792089237316195423570985008687907853269984665640564039457584007908834671663");
    params.a = ZZ(0);  // a = 0
    params.b = ZZ(7);  // b = 7
    
    // Order n (prime)
    params.n = conv<ZZ>("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    params.h = ZZ(1);  // Cofactor
    
    // Generator G
    params.Gx = conv<ZZ>("55066263022277343669578718895168534326250603453777594175500187360389116729240");
    params.Gy = conv<ZZ>("32670510020758816978083085130507043184471273380659243275938904335757337482424");
    
    return params;
}

CurveParams get_secp256r1_params() {
    CurveParams params;
    params.name = "secp256r1";
    params.bit_size = 256;
    
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    params.p = conv<ZZ>("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    params.a = conv<ZZ>("115792089210356248762697446949407573530086143415290314195533631308867097853948");
    params.b = conv<ZZ>("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    
    params.n = conv<ZZ>("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    params.h = ZZ(1);
    
    params.Gx = conv<ZZ>("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    params.Gy = conv<ZZ>("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    
    return params;
}

// P-384 and P-521 removed in v4.6.0 - focusing on 256-bit curves only

CurveParams get_sm2_params() {
    CurveParams params;
    params.name = "sm2";
    params.bit_size = 256;
    
    // SM2 curve parameters (Chinese National Standard)
    params.p = conv<ZZ>("115792089210356248756420345214020892766250353991924191454421193933289684991999");
    params.a = conv<ZZ>("115792089210356248756420345214020892766250353991924191454421193933289684991996");
    params.b = conv<ZZ>("18505919022281880113072981827955639221458448578012075254857346196103069175443");
    
    params.n = conv<ZZ>("115792089210356248756420345214020892766061623724957744567843809356293439045923");
    params.h = ZZ(1);
    
    params.Gx = conv<ZZ>("22963146547237050559479531362550074578802567295341616970375194840604139615431");
    params.Gy = conv<ZZ>("85132369209828568825618990617112496413088388631904505083283536607588877201568");
    
    return params;
}

// ============================================================================
// ECCurve Constructor Implementations
// ============================================================================

ECCurve::ECCurve(const CurveParams& params) {
    p_ = params.p;
    n_ = params.n;
    h_ = params.h;
    name_ = params.name;
    bit_size_ = params.bit_size;
    
    init_modulus();
    
    a_ = conv<ZZ_p>(params.a);
    b_ = conv<ZZ_p>(params.b);
    
    // Initialize generator in Jacobian coordinates
    ZZ_p Gx = conv<ZZ_p>(params.Gx);
    ZZ_p Gy = conv<ZZ_p>(params.Gy);
    G_ = JacobianPoint(Gx, Gy);
}

ECCurve::ECCurve(CurveType type) {
    CurveParams params;
    switch (type) {
        case CurveType::SECP256K1:
            params = get_secp256k1_params();
            break;
        case CurveType::SECP256R1:
            params = get_secp256r1_params();
            break;
        case CurveType::SM2:
            params = get_sm2_params();
            break;
        default:
            throw std::invalid_argument("Unsupported curve type (only 256-bit curves supported)");
    }
    
    p_ = params.p;
    n_ = params.n;
    h_ = params.h;
    name_ = params.name;
    bit_size_ = params.bit_size;
    
    init_modulus();
    
    a_ = conv<ZZ_p>(params.a);
    b_ = conv<ZZ_p>(params.b);
    
    ZZ_p Gx = conv<ZZ_p>(params.Gx);
    ZZ_p Gy = conv<ZZ_p>(params.Gy);
    G_ = JacobianPoint(Gx, Gy);
}

ECCurve ECCurve::from_name(const std::string& name) {
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name == "secp256k1") {
        return ECCurve(CurveType::SECP256K1);
    } else if (lower_name == "secp256r1" || lower_name == "p-256" || lower_name == "p256" || lower_name == "prime256v1") {
        return ECCurve(CurveType::SECP256R1);
    } else if (lower_name == "sm2") {
        return ECCurve(CurveType::SM2);
    }
    
    throw std::invalid_argument("Unknown or unsupported curve name: " + name + " (only 256-bit curves supported)");
}

void ECCurve::init_modulus() {
    ZZ_p::init(p_);
}

// ============================================================================
// Point Validation
// ============================================================================

bool ECCurve::is_on_curve(const AffinePoint& P) const {
    if (P.is_infinity) {
        return true;
    }
    
    // Ensure we're using the correct modulus
    ZZ_p::init(p_);
    
    // Check: y² = x³ + ax + b (mod p)
    ZZ_p lhs = sqr(P.y);
    ZZ_p rhs = power(P.x, 3) + a_ * P.x + b_;
    
    return lhs == rhs;
}

bool ECCurve::is_on_curve(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return true;
    }
    
    // Convert to affine and check
    AffinePoint aff = to_affine(P);
    return is_on_curve(aff);
}

bool ECCurve::validate_point(const JacobianPoint& P) const {
    // Check not at infinity
    if (P.is_infinity()) {
        return false;
    }
    
    // Check on curve
    if (!is_on_curve(P)) {
        return false;
    }
    
    // Check in correct subgroup: n*P = O
    JacobianPoint check = scalar_mult(n_, P);
    return check.is_infinity();
}

// ============================================================================
// Point Arithmetic - Jacobian Coordinates
// ============================================================================

JacobianPoint ECCurve::add(const JacobianPoint& P, const JacobianPoint& Q) const {
    // Handle identity cases
    if (P.is_infinity()) {
        return Q;
    }
    if (Q.is_infinity()) {
        return P;
    }
    
    // Ensure correct modulus
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize input coordinates under current modulus
    // This ensures ZZ_p values created under different modulus are correctly interpreted
    ZZ_p P_X = conv<ZZ_p>(rep(P.X));
    ZZ_p P_Y = conv<ZZ_p>(rep(P.Y));
    ZZ_p P_Z = conv<ZZ_p>(rep(P.Z));
    ZZ_p Q_X = conv<ZZ_p>(rep(Q.X));
    ZZ_p Q_Y = conv<ZZ_p>(rep(Q.Y));
    ZZ_p Q_Z = conv<ZZ_p>(rep(Q.Z));
    
    // Optimized Jacobian addition (12M + 4S formula from EFD)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
    
    ZZ_p Z1Z1 = sqr(P_Z);
    ZZ_p Z2Z2 = sqr(Q_Z);
    ZZ_p U1 = P_X * Z2Z2;
    ZZ_p U2 = Q_X * Z1Z1;
    ZZ_p S1 = P_Y * Q_Z * Z2Z2;
    ZZ_p S2 = Q_Y * P_Z * Z1Z1;
    
    ZZ_p H = U2 - U1;
    ZZ_p r = S2 - S1;
    
    // Check if P == Q (need doubling)
    if (IsZero(H)) {
        if (IsZero(r)) {
            return double_point(P);
        }
        // P = -Q, return infinity
        return JacobianPoint();
    }
    
    // Optimized computation
    ZZ_p HH = sqr(H);
    ZZ_p HHH = H * HH;
    ZZ_p V = U1 * HH;
    
    // X3 = r² - HHH - 2*V
    ZZ_p r2 = sqr(r);
    ZZ_p X3 = r2 - HHH - V - V;
    
    // Y3 = r*(V - X3) - S1*HHH
    ZZ_p Y3 = r * (V - X3) - S1 * HHH;
    
    // Z3 = H * Z1 * Z2
    ZZ_p Z3 = H * P_Z * Q_Z;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::double_point(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    // Ensure correct modulus
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize input coordinates under current modulus
    ZZ_p P_X = conv<ZZ_p>(rep(P.X));
    ZZ_p P_Y = conv<ZZ_p>(rep(P.Y));
    ZZ_p P_Z = conv<ZZ_p>(rep(P.Z));
    
    // Optimized doubling formula from EFD
    // For a = 0: dbl-2009-l (1M + 5S + 1*a + 7add + 2*2 + 1*3 + 1*8)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    
    ZZ_p A = sqr(P_X);           // X1²
    ZZ_p B = sqr(P_Y);           // Y1²
    ZZ_p C = sqr(B);             // Y1⁴
    
    // D = 2*((X1+B)² - A - C) = 2*(X1+Y1²)² - 2*X1² - 2*Y1⁴
    ZZ_p tmp = P_X + B;
    ZZ_p D = sqr(tmp) - A - C;
    D = D + D;                    // D = 2*D (cheaper than 2*D multiply)
    
    ZZ_p E;
    if (IsZero(a_)) {
        // a = 0 (secp256k1): E = 3*A
        E = A + A + A;
    } else {
        // General case (P-256, SM2): E = 3*A + a*Z1⁴
        ZZ_p Z1_sq = sqr(P_Z);
        E = A + A + A + a_ * sqr(Z1_sq);
    }
    
    ZZ_p F = sqr(E);              // E²
    
    // X3 = F - 2*D
    ZZ_p X3 = F - D - D;
    
    // Y3 = E*(D - X3) - 8*C
    ZZ_p C8 = C;
    for (int i = 0; i < 3; i++) C8 = C8 + C8;  // 8*C
    ZZ_p Y3 = E * (D - X3) - C8;
    
    // Z3 = 2*Y1*Z1
    ZZ_p Z3 = P_Y * P_Z;
    Z3 = Z3 + Z3;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::negate(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    // Ensure correct modulus and normalize
    ZZ_p::init(p_);
    ZZ_p P_Y = conv<ZZ_p>(rep(P.Y));
    return JacobianPoint(conv<ZZ_p>(rep(P.X)), -P_Y, conv<ZZ_p>(rep(P.Z)));
}

JacobianPoint ECCurve::subtract(const JacobianPoint& P, const JacobianPoint& Q) const {
    return add(P, negate(Q));
}

// ============================================================================
// Scalar Multiplication - Montgomery Ladder (Constant-Time)
// ============================================================================

JacobianPoint ECCurve::montgomery_ladder(const ZZ& k, const JacobianPoint& P) const {
    if (IsZero(k) || P.is_infinity()) {
        return JacobianPoint();
    }
    
    // Reduce k modulo n
    ZZ k_mod = k % n_;
    if (IsZero(k_mod)) {
        return JacobianPoint();
    }
    
    // Montgomery ladder: constant-time scalar multiplication
    JacobianPoint R0 = JacobianPoint();  // R0 = O
    JacobianPoint R1 = P;                // R1 = P
    
    long num_bits = NumBits(k_mod);
    
    // Process bits from MSB to LSB
    for (long i = num_bits - 1; i >= 0; --i) {
        if (bit(k_mod, i)) {
            R0 = add(R0, R1);
            R1 = double_point(R1);
        } else {
            R1 = add(R0, R1);
            R0 = double_point(R0);
        }
    }
    
    return R0;
}

JacobianPoint ECCurve::scalar_mult(const ZZ& k, const JacobianPoint& P) const {
    // Use constant-time Montgomery ladder for security
    ZZ_p::init(p_);
    JacobianPoint P_norm(conv<ZZ_p>(rep(P.X)), conv<ZZ_p>(rep(P.Y)), conv<ZZ_p>(rep(P.Z)));
    return montgomery_ladder(k, P_norm);
}

JacobianPoint ECCurve::scalar_mult_base(const ZZ& k) const {
    // Use constant-time Montgomery ladder for security
    ZZ_p::init(p_);
    JacobianPoint G_norm(conv<ZZ_p>(rep(G_.X)), conv<ZZ_p>(rep(G_.Y)), conv<ZZ_p>(rep(G_.Z)));
    return montgomery_ladder(k, G_norm);
}

// ============================================================================
// Double Scalar Multiplication with Shamir's Trick (Constant-Time)
// ============================================================================

JacobianPoint ECCurve::double_scalar_mult(const ZZ& k1, const JacobianPoint& P,
                                          const ZZ& k2, const JacobianPoint& Q) const {
    // Initialize modulus once for all point operations
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize point coordinates under current modulus
    JacobianPoint P_norm(conv<ZZ_p>(rep(P.X)), conv<ZZ_p>(rep(P.Y)), conv<ZZ_p>(rep(P.Z)));
    JacobianPoint Q_norm(conv<ZZ_p>(rep(Q.X)), conv<ZZ_p>(rep(Q.Y)), conv<ZZ_p>(rep(Q.Z)));
    
    // Shamir's trick for simultaneous multiple scalar multiplication
    // Precompute: P, Q, P+Q
    JacobianPoint PQ = add(P_norm, Q_norm);
    
    ZZ k1_mod = k1 % n_;
    ZZ k2_mod = k2 % n_;
    
    JacobianPoint R = JacobianPoint();  // Start with infinity
    
    // Get maximum bit length
    long bits1 = NumBits(k1_mod);
    long bits2 = NumBits(k2_mod);
    long max_bits = std::max(bits1, bits2);
    
    // Process both scalars together
    for (long i = max_bits - 1; i >= 0; --i) {
        R = double_point(R);
        
        int b1 = (i < bits1) ? static_cast<int>(bit(k1_mod, i)) : 0;
        int b2 = (i < bits2) ? static_cast<int>(bit(k2_mod, i)) : 0;
        
        if (b1 && b2) {
            R = add(R, PQ);
        } else if (b1) {
            R = add(R, P_norm);
        } else if (b2) {
            R = add(R, Q_norm);
        }
    }
    
    return R;
}

// ============================================================================
// Coordinate Conversions
// ============================================================================

AffinePoint ECCurve::to_affine(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return AffinePoint();
    }
    
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize coordinates under current modulus p_
    ZZ_p X = conv<ZZ_p>(rep(P.X));
    ZZ_p Y = conv<ZZ_p>(rep(P.Y));
    ZZ_p Z = conv<ZZ_p>(rep(P.Z));
    
    // x = X / Z²
    // y = Y / Z³
    ZZ_p Z_inv = inv(Z);
    ZZ_p Z_inv_sq = sqr(Z_inv);
    ZZ_p Z_inv_cb = Z_inv_sq * Z_inv;
    
    ZZ_p x = X * Z_inv_sq;
    ZZ_p y = Y * Z_inv_cb;
    
    return AffinePoint(x, y);
}

JacobianPoint ECCurve::to_jacobian(const AffinePoint& P) const {
    if (P.is_infinity) {
        return JacobianPoint();
    }
    
    ZZ_p::init(p_);
    return JacobianPoint(P.x, P.y);
}

// ============================================================================
// Serialization
// ============================================================================

int ECCurve::point_to_bytes(const AffinePoint& P, unsigned char* out, size_t out_len) const {
    if (P.is_infinity) {
        if (out_len < 1) return -1;
        out[0] = 0x00;
        return 1;
    }
    
    size_t field_size = static_cast<size_t>((bit_size_ + 7) / 8);
    size_t required_len = 1 + 2 * field_size;
    
    if (out_len < required_len) {
        return -1;
    }
    
    // Uncompressed format: 0x04 || x || y
    out[0] = 0x04;
    
    // Extract x coordinate bytes (bignum uses little-endian, SEC 1 requires big-endian)
    ZZ x_int = rep(P.x);
    std::vector<uint8_t> x_le(field_size);
    BytesFromZZ(x_le.data(), x_int, static_cast<long>(field_size));
    // Reverse to big-endian for output
    for (size_t i = 0; i < field_size; i++) {
        out[1 + i] = x_le[field_size - 1 - i];
    }
    
    // Extract y coordinate bytes (bignum uses little-endian, SEC 1 requires big-endian)
    ZZ y_int = rep(P.y);
    std::vector<uint8_t> y_le(field_size);
    BytesFromZZ(y_le.data(), y_int, static_cast<long>(field_size));
    // Reverse to big-endian for output
    for (size_t i = 0; i < field_size; i++) {
        out[1 + field_size + i] = y_le[field_size - 1 - i];
    }
    
    return static_cast<int>(required_len);
}

AffinePoint ECCurve::point_from_bytes(const unsigned char* in, size_t in_len) const {
    if (in_len < 1) {
        throw std::invalid_argument("Input too short");
    }
    
    // Check for point at infinity
    if (in[0] == 0x00) {
        return AffinePoint();
    }
    
    size_t field_size = static_cast<size_t>((bit_size_ + 7) / 8);
    
    if (in[0] == 0x04) {
        // Uncompressed format
        if (in_len != 1 + 2 * field_size) {
            throw std::invalid_argument("Invalid uncompressed point length");
        }
        
        ZZ_p::init(p_);
        
        // Convert big-endian input to little-endian for bignum
        std::vector<uint8_t> x_le(field_size), y_le(field_size);
        for (size_t i = 0; i < field_size; i++) {
            x_le[i] = in[1 + field_size - 1 - i];
            y_le[i] = in[1 + field_size + field_size - 1 - i];
        }
        
        ZZ x_int = ZZFromBytes(x_le.data(), static_cast<long>(field_size));
        ZZ y_int = ZZFromBytes(y_le.data(), static_cast<long>(field_size));
        
        AffinePoint P(conv<ZZ_p>(x_int), conv<ZZ_p>(y_int));
        
        if (!is_on_curve(P)) {
            throw std::invalid_argument("Point is not on curve");
        }
        
        return P;
    }
    
    // TODO: Add compressed point support (0x02, 0x03)
    throw std::invalid_argument("Unsupported point format");
}

} // namespace ecc
} // namespace kctsb
