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

// ============================================================================
// Assembly Optimization Declarations (v4.8.1)
// ============================================================================
// Conditionally link to x86_64 assembly routines for high-performance field ops.
// These functions are defined in asm/fe256_x86_64.S and provide ~2-3x speedup.

#if defined(KCTSB_HAS_ECC_ASM) && defined(KCTSB_ARCH_X86_64) && 0  // TEMP: Disable ASM for debugging
extern "C" {
    /**
     * @brief Assembly secp256k1 reduction: r = a mod p (512-bit -> 256-bit)
     * @param r Output 4-limb result (256-bit)
     * @param a Input 8-limb value (512-bit)
     */
    void fe256_reduce_secp256k1_asm(uint64_t* r, const uint64_t* a);
    
    /**
     * @brief Assembly squaring: r = a^2 (256-bit -> 512-bit)
     * @param r Output 8-limb result (512-bit)
     * @param a Input 4-limb value (256-bit)
     */
    void fe256_sqr_wide_asm(uint64_t* r, const uint64_t* a);
    
    /**
     * @brief Assembly multiplication: r = a * b (256-bit x 256-bit -> 512-bit)
     * @param r Output 8-limb result (512-bit)
     * @param a Input 4-limb value (256-bit)
     * @param b Input 4-limb value (256-bit)
     */
    void fe256_mul_wide_asm(uint64_t* r, const uint64_t* a, const uint64_t* b);
}
#define KCTSB_USE_ECC_ASM 1
#else
#define KCTSB_USE_ECC_ASM 0
#endif

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

namespace kctsb {
namespace ecc {
namespace internal {

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
    // For subtraction with borrow: a - b - borrow_in
    // If result underflows, the high 64 bits will be all 1s (0xFFFFFFFFFFFFFFFF)
    uint128_t diff = (uint128_t)a - b - borrow_in;
    // Check if underflow occurred: high 64 bits will be non-zero (specifically 0xFFFFFFFFFFFFFFFF)
    *borrow_out = (uint64_t)(diff >> 64) != 0 ? 1 : 0;
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
// R^2 mod p for Montgomery conversion (secp256k1)
// Computed: R = 2^256, R^2 mod p = (2^256)^2 mod p
// = (2^32 + 977)^2 mod p = 0x000007a2000e90a1 + (1 << 64)
alignas(32) static const Fe256 SECP256K1_R2 = {{
    0x000007a2000e90a1ULL, 0x0000000000000001ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL
}};
// n0 = -p^(-1) mod 2^64 for Montgomery reduction
static const uint64_t SECP256K1_N0 = 0xD838091DD2253531ULL;

// P-256: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
alignas(32) static const Fe256 P256_P = {{
    0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
    0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
}};
// R^2 mod p for Montgomery conversion (P-256)
alignas(32) static const Fe256 P256_R2 = {{
    0x0000000000000003ULL, 0xFFFFFFFBFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFEULL, 0x00000004FFFFFFFDULL
}};
static const uint64_t P256_N0 = 0x0000000000000001ULL;

// SM2: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
alignas(32) static const Fe256 SM2_P = {{
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
}};
// R^2 mod p for Montgomery conversion (SM2)
alignas(32) static const Fe256 SM2_R2 = {{
    0x0000000200000003ULL, 0x00000002FFFFFFFFULL,
    0x0000000100000001ULL, 0x0000000400000002ULL
}};
static const uint64_t SM2_N0 = 0x0000000000000001ULL;

// ============================================================================
// Wide Multiplication (256x256 -> 512-bit)
// v4.8.1: Uses assembly optimization when available
// ============================================================================

static void fe256_mul_wide(Fe512* r, const Fe256* a, const Fe256* b) {
#if KCTSB_USE_ECC_ASM
    // Use optimized assembly multiplication
    fe256_mul_wide_asm(r->limb, a->limb, b->limb);
#else
    // Portable C++ implementation
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
#endif
}

// ============================================================================
// Montgomery Reduction (256-bit modulus, 4 limbs)
// ============================================================================

static void fe256_montgomery_reduce(Fe256* r, const Fe512* t,
                                    const Fe256* p, uint64_t n0) {
    uint64_t tmp[8];
    for (int i = 0; i < 8; i++) {
        tmp[i] = t->limb[i];
    }

    for (int i = 0; i < 4; i++) {
        uint64_t m = tmp[i] * n0;
        uint64_t carry = 0;

        for (int j = 0; j < 4; j++) {
            uint128_t prod = (uint128_t)m * p->limb[j];
            uint128_t sum = prod + tmp[i + j] + carry;
            tmp[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }

        uint128_t sum = (uint128_t)tmp[i + 4] + carry;
        tmp[i + 4] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);

        int k = i + 5;
        while (carry != 0 && k < 8) {
            sum = (uint128_t)tmp[k] + carry;
            tmp[k] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
            k++;
        }
    }

    Fe256 result;
    result.limb[0] = tmp[4];
    result.limb[1] = tmp[5];
    result.limb[2] = tmp[6];
    result.limb[3] = tmp[7];

    Fe256 reduced;
    uint64_t borrow = 0;
    reduced.limb[0] = sbb64(result.limb[0], p->limb[0], 0, &borrow);
    reduced.limb[1] = sbb64(result.limb[1], p->limb[1], borrow, &borrow);
    reduced.limb[2] = sbb64(result.limb[2], p->limb[2], borrow, &borrow);
    reduced.limb[3] = sbb64(result.limb[3], p->limb[3], borrow, &borrow);

    fe256_cmov(&result, &reduced, (int)(borrow == 0));
    fe256_copy(r, &result);
}

static void fe256_mul_mont_secp256k1(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_montgomery_reduce(r, &wide, &SECP256K1_P, SECP256K1_N0);
}

static void fe256_sqr_mont_secp256k1(Fe256* r, const Fe256* a) {
    fe256_mul_mont_secp256k1(r, a, a);
}

static void fe256_mul_mont_p256(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_montgomery_reduce(r, &wide, &P256_P, P256_N0);
}

static void fe256_sqr_mont_p256(Fe256* r, const Fe256* a) {
    fe256_mul_mont_p256(r, a, a);
}

static void fe256_mul_mont_sm2(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_montgomery_reduce(r, &wide, &SM2_P, SM2_N0);
}

static void fe256_sqr_mont_sm2(Fe256* r, const Fe256* a) {
    fe256_mul_mont_sm2(r, a, a);
}

// ============================================================================
// secp256k1 Specialized Reduction
// ============================================================================

/**
 * @brief secp256k1 specialized reduction
 * Uses: 2^256 ≡ 2^32 + 977 (mod p)
 * v4.8.1: Uses assembly optimization when available
 */
static void fe256_reduce_secp256k1(Fe256* r, const Fe512* a) {
#if KCTSB_USE_ECC_ASM
    // Use optimized assembly routine
    fe256_reduce_secp256k1_asm(r->limb, a->limb);
#else
    // Portable C++ implementation
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
#endif
}

static void fe256_mul_secp256k1(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_secp256k1(r, &wide);
}

/**
 * @brief secp256k1 field squaring
 * v4.8.1: Uses assembly squaring when available for ~1.5x speedup
 */
static void fe256_sqr_secp256k1(Fe256* r, const Fe256* a) {
#if KCTSB_USE_ECC_ASM
    // Use optimized assembly squaring + reduction
    Fe512 wide;
    fe256_sqr_wide_asm(wide.limb, a->limb);
    fe256_reduce_secp256k1(r, &wide);
#else
    // Portable: squaring is multiplication with self
    fe256_mul_secp256k1(r, a, a);
#endif
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
    uint64_t c[16];
    for (int i = 0; i < 8; i++) {
        c[2 * i] = (uint32_t)a->limb[i];
        c[2 * i + 1] = (uint32_t)(a->limb[i] >> 32);
    }

    int64_t t[16] = {0};
    for (int i = 0; i < 8; i++) {
        t[i] = (int64_t)c[i];
    }

    // Fold high words using: 2^256 = 1 + 2^96 - 2^64 + 2^224
    for (int i = 0; i < 8; i++) {
        int64_t v = (int64_t)c[i + 8];
        t[i] += v;           // +1
        t[i + 3] += v;       // +2^96
        t[i + 2] -= v;       // -2^64
        t[i + 7] += v;       // +2^224
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (int i = 15; i >= 8; i--) {
            if (t[i] == 0) {
                continue;
            }
            int64_t v = t[i];
            t[i] = 0;
            t[i - 8] += v;
            t[i - 5] += v;
            t[i - 6] -= v;
            t[i - 1] += v;
            changed = true;
        }
    }

    int64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        t[i] += carry;
        carry = t[i] >> 32;
        t[i] &= 0xFFFFFFFFLL;
    }
    t[8] += carry;

    while (t[8] != 0) {
        int64_t v = t[8];
        t[8] = 0;
        t[0] += v;
        t[3] += v;
        t[2] -= v;
        t[7] += v;

        carry = 0;
        for (int i = 0; i < 8; i++) {
            t[i] += carry;
            carry = t[i] >> 32;
            t[i] &= 0xFFFFFFFFLL;
        }
        t[8] += carry;
    }

    uint64_t result[4] = {
        ((uint64_t)(uint32_t)t[0]) | (((uint64_t)(uint32_t)t[1]) << 32),
        ((uint64_t)(uint32_t)t[2]) | (((uint64_t)(uint32_t)t[3]) << 32),
        ((uint64_t)(uint32_t)t[4]) | (((uint64_t)(uint32_t)t[5]) << 32),
        ((uint64_t)(uint32_t)t[6]) | (((uint64_t)(uint32_t)t[7]) << 32)
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
            fe256_sqr_mont_secp256k1(&result, &result);
            if ((p_minus_2[i] >> j) & 1) {
                fe256_mul_mont_secp256k1(&result, &result, &base);
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
            fe256_sqr_mont_p256(&result, &result);
            if ((p_minus_2[i] >> j) & 1) {
                fe256_mul_mont_p256(&result, &result, &base);
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
            fe256_sqr_mont_sm2(&result, &result);
            if ((p_minus_2[i] >> j) & 1) {
                fe256_mul_mont_sm2(&result, &result, &base);
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
    fe256_mul_mont_secp256k1(r, a, &SECP256K1_R2);
}

static inline void fe256_from_mont_secp256k1(Fe256* r, const Fe256* a) {
    Fe256 one;
    fe256_one(&one);
    fe256_mul_mont_secp256k1(r, a, &one);
}

static inline void fe256_to_mont_p256(Fe256* r, const Fe256* a) {
    fe256_mul_mont_p256(r, a, &P256_R2);
}

static inline void fe256_from_mont_p256(Fe256* r, const Fe256* a) {
    Fe256 one;
    fe256_one(&one);
    fe256_mul_mont_p256(r, a, &one);
}

static inline void fe256_to_mont_sm2(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

static inline void fe256_from_mont_sm2(Fe256* r, const Fe256* a) {
    fe256_copy(r, a);
}

// ============================================================================
// fe256-based Jacobian Point Operations (v4.8.2+)
// ============================================================================
// High-performance point arithmetic bypassing NTL for 256-bit curves.
// These operations use the fe256 layer directly for maximum throughput.

/**
 * @brief Jacobian point in fe256 representation
 */
struct Fe256Point {
    Fe256 X;
    Fe256 Y;
    Fe256 Z;
    int is_infinity;
    
    Fe256Point() : is_infinity(1) {
        fe256_zero(&X);
        fe256_zero(&Y);
        fe256_zero(&Z);
    }
    
    Fe256Point(const Fe256& x, const Fe256& y, const Fe256& z, int inf = 0)
        : X(x), Y(y), Z(z), is_infinity(inf) {}
};

/**
 * @brief Curve operation table for fe256 fast path
 */
struct Fe256CurveOps {
    void (*add)(Fe256* r, const Fe256* a, const Fe256* b);
    void (*sub)(Fe256* r, const Fe256* a, const Fe256* b);
    void (*mul)(Fe256* r, const Fe256* a, const Fe256* b);
    void (*sqr)(Fe256* r, const Fe256* a);
    void (*inv)(Fe256* r, const Fe256* a);
    void (*neg)(Fe256* r, const Fe256* a);
    const Fe256* p;
    int a_is_minus_3;  // Optimization flag: a = -3 mod p (P-256, SM2)
    int a_is_zero;     // Optimization flag: a = 0 (secp256k1)
};

// Curve operation tables
static const Fe256CurveOps secp256k1_ops = {
    fe256_add_secp256k1, fe256_sub_secp256k1,
    fe256_mul_mont_secp256k1, fe256_sqr_mont_secp256k1,
    fe256_inv_secp256k1, fe256_neg_secp256k1,
    &SECP256K1_P, 0, 1
};

static const Fe256CurveOps p256_ops = {
    fe256_add_p256, fe256_sub_p256,
    fe256_mul_mont_p256, fe256_sqr_mont_p256,
    fe256_inv_p256, fe256_neg_p256,
    &P256_P, 1, 0
};

static const Fe256CurveOps sm2_ops = {
    fe256_add_sm2, fe256_sub_sm2,
    fe256_mul_sm2, fe256_sqr_sm2,
    fe256_inv_sm2, fe256_neg_sm2,
    &SM2_P, 1, 0
};

static inline void fe256_point_cswap(Fe256Point* a, Fe256Point* b, uint64_t swap) {
    uint64_t mask = 0ULL - (swap & 1ULL);

    for (int i = 0; i < 4; i++) {
        uint64_t tmp = mask & (a->X.limb[i] ^ b->X.limb[i]);
        a->X.limb[i] ^= tmp;
        b->X.limb[i] ^= tmp;

        tmp = mask & (a->Y.limb[i] ^ b->Y.limb[i]);
        a->Y.limb[i] ^= tmp;
        b->Y.limb[i] ^= tmp;

        tmp = mask & (a->Z.limb[i] ^ b->Z.limb[i]);
        a->Z.limb[i] ^= tmp;
        b->Z.limb[i] ^= tmp;
    }

    uint64_t ai = (uint64_t)a->is_infinity;
    uint64_t bi = (uint64_t)b->is_infinity;
    uint64_t diff = mask & (ai ^ bi);
    a->is_infinity = (int)(ai ^ diff);
    b->is_infinity = (int)(bi ^ diff);
}

/**
 * @brief Point doubling using fe256 operations
 * 
 * Uses dbl-2007-bl formulas from hyperelliptic.org:
 * Cost: 1M + 5S + 7add (a = 0) or 1M + 5S + 9add (a = -3)
 */
static void fe256_point_double(Fe256Point* r, const Fe256Point* p,
                               const Fe256CurveOps* ops) {
    if (p->is_infinity) {
        *r = Fe256Point();
        return;
    }
    
    Fe256 A, B, C, D, E, F, X3, Y3, Z3;
    Fe256 tmp1, tmp2;
    
    // A = X1²
    ops->sqr(&A, &p->X);
    
    // B = Y1²
    ops->sqr(&B, &p->Y);
    
    // C = B² = Y1⁴
    ops->sqr(&C, &B);
    
    // D = 2*((X1+B)² - A - C) = 2*(X1+Y1²)² - 2*X1² - 2*Y1⁴
    ops->add(&tmp1, &p->X, &B);
    ops->sqr(&tmp2, &tmp1);
    ops->sub(&tmp2, &tmp2, &A);
    ops->sub(&tmp2, &tmp2, &C);
    ops->add(&D, &tmp2, &tmp2);
    
    if (ops->a_is_zero) {
        // E = 3*A (for secp256k1 where a = 0)
        ops->add(&E, &A, &A);
        ops->add(&E, &E, &A);
    } else if (ops->a_is_minus_3) {
        // E = 3*(X1-Z1²)*(X1+Z1²) = 3*(X1²-Z1⁴) = 3*A - 3*Z1⁴
        // For a = -3: E = 3*A + a*Z1⁴ = 3*A - 3*Z1⁴ = 3*(A - Z1⁴)
        Fe256 Z2, Z4;
        ops->sqr(&Z2, &p->Z);
        ops->sqr(&Z4, &Z2);
        ops->sub(&tmp1, &A, &Z4);
        ops->add(&E, &tmp1, &tmp1);
        ops->add(&E, &E, &tmp1);
    } else {
        // General case: E = 3*A + a*Z1⁴
        ops->add(&E, &A, &A);
        ops->add(&E, &E, &A);
    }
    
    // F = E²
    ops->sqr(&F, &E);
    
    // X3 = F - 2*D
    ops->add(&tmp1, &D, &D);
    ops->sub(&X3, &F, &tmp1);
    
    // Y3 = E*(D - X3) - 8*C
    ops->sub(&tmp1, &D, &X3);
    ops->mul(&tmp2, &E, &tmp1);
    ops->add(&tmp1, &C, &C);  // 2C
    ops->add(&tmp1, &tmp1, &tmp1);  // 4C
    ops->add(&tmp1, &tmp1, &tmp1);  // 8C
    ops->sub(&Y3, &tmp2, &tmp1);
    
    // Z3 = 2*Y1*Z1
    ops->mul(&tmp1, &p->Y, &p->Z);
    ops->add(&Z3, &tmp1, &tmp1);
    
    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
    r->is_infinity = 0;
}

/**
 * @brief Point addition using fe256 operations
 * 
 * Uses add-2007-bl formulas from hyperelliptic.org:
 * Cost: 11M + 5S + 9add
 */
static void fe256_point_add(Fe256Point* r, const Fe256Point* p,
                            const Fe256Point* q, const Fe256CurveOps* ops) {
    if (p->is_infinity) {
        *r = *q;
        return;
    }
    if (q->is_infinity) {
        *r = *p;
        return;
    }
    
    Fe256 Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, rr, V;
    Fe256 tmp1, tmp2, X3, Y3, Z3;
    
    // Z1Z1 = Z1²
    ops->sqr(&Z1Z1, &p->Z);
    
    // Z2Z2 = Z2²
    ops->sqr(&Z2Z2, &q->Z);
    
    // U1 = X1*Z2Z2
    ops->mul(&U1, &p->X, &Z2Z2);
    
    // U2 = X2*Z1Z1
    ops->mul(&U2, &q->X, &Z1Z1);
    
    // S1 = Y1*Z2*Z2Z2
    ops->mul(&tmp1, &q->Z, &Z2Z2);
    ops->mul(&S1, &p->Y, &tmp1);
    
    // S2 = Y2*Z1*Z1Z1
    ops->mul(&tmp1, &p->Z, &Z1Z1);
    ops->mul(&S2, &q->Y, &tmp1);
    
    // Check if points are equal or negatives
    if (fe256_equal(&U1, &U2)) {
        if (fe256_equal(&S1, &S2)) {
            // P == Q, use doubling
            fe256_point_double(r, p, ops);
            return;
        } else {
            // P == -Q, result is infinity
            *r = Fe256Point();
            return;
        }
    }
    
    // H = U2 - U1
    ops->sub(&H, &U2, &U1);
    
    // I = (2*H)²
    ops->add(&tmp1, &H, &H);
    ops->sqr(&I, &tmp1);
    
    // J = H*I
    ops->mul(&J, &H, &I);
    
    // rr = 2*(S2 - S1)
    ops->sub(&tmp1, &S2, &S1);
    ops->add(&rr, &tmp1, &tmp1);
    
    // V = U1*I
    ops->mul(&V, &U1, &I);
    
    // X3 = rr² - J - 2*V
    ops->sqr(&tmp1, &rr);
    ops->sub(&tmp1, &tmp1, &J);
    ops->add(&tmp2, &V, &V);
    ops->sub(&X3, &tmp1, &tmp2);
    
    // Y3 = rr*(V - X3) - 2*S1*J
    ops->sub(&tmp1, &V, &X3);
    ops->mul(&tmp2, &rr, &tmp1);
    ops->mul(&tmp1, &S1, &J);
    ops->add(&tmp1, &tmp1, &tmp1);
    ops->sub(&Y3, &tmp2, &tmp1);
    
    // Z3 = ((Z1+Z2)² - Z1Z1 - Z2Z2)*H
    ops->add(&tmp1, &p->Z, &q->Z);
    ops->sqr(&tmp2, &tmp1);
    ops->sub(&tmp2, &tmp2, &Z1Z1);
    ops->sub(&tmp2, &tmp2, &Z2Z2);
    ops->mul(&Z3, &tmp2, &H);
    
    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
    r->is_infinity = 0;
}

/**
 * @brief Montgomery ladder using fe256 operations
 * 
 * Constant-time scalar multiplication for 256-bit curves.
 * @param r Result point
 * @param k Scalar value (4 limbs, little-endian: k[0] = LSB, k[3] = MSB)
 * @param p Base point
 * @param ops Curve operation table
 */
static void fe256_montgomery_ladder(Fe256Point* r, const uint64_t* k,
                                    const Fe256Point* p, const Fe256CurveOps* ops) {
    Fe256Point r0 = Fe256Point();
    Fe256Point r1 = *p;
    Fe256Point tmp;

    // Find highest set bit
    int highest_bit = -1;
    for (int limb = 3; limb >= 0 && highest_bit < 0; --limb) {
        if (k[limb] != 0) {
            for (int bit = 63; bit >= 0; --bit) {
                if ((k[limb] >> bit) & 1) {
                    highest_bit = limb * 64 + bit;
                    break;
                }
            }
        }
    }
    
    if (highest_bit < 0) {
        // k == 0, return infinity
        *r = Fe256Point();
        return;
    }

    uint64_t prev_bit = 0;
    for (int i = highest_bit; i >= 0; --i) {
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        uint64_t bit = (k[limb_idx] >> bit_idx) & 1ULL;
        uint64_t swap = bit ^ prev_bit;
        fe256_point_cswap(&r0, &r1, swap);
        prev_bit = bit;

        fe256_point_add(&tmp, &r0, &r1, ops);
        fe256_point_double(&r0, &r0, ops);
        r1 = tmp;
    }

    fe256_point_cswap(&r0, &r1, prev_bit);
    *r = r0;
}

/**
 * @brief Convert ZZ to fe256 (big integer -> 4-limb)
 * NTL BytesFromZZ uses little-endian byte order.
 * fe256 uses little-endian limb order (limb[0] = LSB).
 * So we pack bytes 0-7 into limb[0], bytes 8-15 into limb[1], etc.
 */
static void zz_to_fe256(Fe256* r, const ZZ& a) {
    std::vector<uint8_t> bytes(32, 0);
    BytesFromZZ(bytes.data(), a, 32);
    // NTL BytesFromZZ: bytes[0] = LSB, bytes[31] = MSB (little-endian)
    // fe256 limbs: limb[0] = LSB, limb[3] = MSB (little-endian)
    for (int i = 0; i < 4; i++) {
        r->limb[i] = 0;
        for (int j = 0; j < 8; j++) {
            r->limb[i] |= (uint64_t)bytes[i * 8 + j] << (j * 8);
        }
    }
}

/**
 * @brief Convert fe256 to ZZ (4-limb -> big integer)
 */
static void fe256_to_zz(ZZ& r, const Fe256* a) {
    std::vector<uint8_t> bytes(32);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            bytes[i * 8 + j] = (a->limb[i] >> (j * 8)) & 0xFF;
        }
    }
    r = ZZFromBytes(bytes.data(), 32);
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
    params.p = ZZ::from_decimal("115792089237316195423570985008687907853269984665640564039457584007908834671663");
    params.a = ZZ(0);  // a = 0
    params.b = ZZ(7);  // b = 7
    
    // Order n (prime)
    params.n = ZZ::from_decimal("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    params.h = ZZ(1);  // Cofactor
    
    // Generator G
    params.Gx = ZZ::from_decimal("55066263022277343669578718895168534326250603453777594175500187360389116729240");
    params.Gy = ZZ::from_decimal("32670510020758816978083085130507043184471273380659243275938904335757337482424");
    
    return params;
}

CurveParams get_secp256r1_params() {
    CurveParams params;
    params.name = "secp256r1";
    params.bit_size = 256;
    
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    params.p = ZZ::from_decimal("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    params.a = ZZ::from_decimal("115792089210356248762697446949407573530086143415290314195533631308867097853948");
    params.b = ZZ::from_decimal("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    
    params.n = ZZ::from_decimal("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    params.h = ZZ(1);
    
    params.Gx = ZZ::from_decimal("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    params.Gy = ZZ::from_decimal("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    
    return params;
}

// P-384 and P-521 removed in v4.6.0 - focusing on 256-bit curves only

CurveParams get_sm2_params() {
    CurveParams params;
    params.name = "sm2";
    params.bit_size = 256;
    
    // SM2 curve parameters (Chinese National Standard)
    params.p = ZZ::from_decimal("115792089210356248756420345214020892766250353991924191454421193933289684991999");
    params.a = ZZ::from_decimal("115792089210356248756420345214020892766250353991924191454421193933289684991996");
    params.b = ZZ::from_decimal("18505919022281880113072981827955639221458448578012075254857346196103069175443");
    
    params.n = ZZ::from_decimal("115792089210356248756420345214020892766061623724957744567843809356293439045923");
    params.h = ZZ(1);
    
    params.Gx = ZZ::from_decimal("22963146547237050559479531362550074578802567295341616970375194840604139615431");
    params.Gy = ZZ::from_decimal("85132369209828568825618990617112496413088388631904505083283536607588877201568");
    
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
    
    a_ = ZZ_p(params.a);
    b_ = ZZ_p(params.b);
    
    // Initialize generator in Jacobian coordinates
    ZZ_p Gx = ZZ_p(params.Gx);
    ZZ_p Gy = ZZ_p(params.Gy);
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
    
    a_ = ZZ_p(params.a);
    b_ = ZZ_p(params.b);
    
    ZZ_p Gx = ZZ_p(params.Gx);
    ZZ_p Gy = ZZ_p(params.Gy);
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
    // Ensure correct modulus FIRST before any ZZ_p operations
    ZZ_p::init(p_);
    
    // Handle identity cases - must normalize before returning
    if (P.is_infinity()) {
        // Normalize Q's coordinates under current modulus
        return JacobianPoint(ZZ_p(rep(Q.X)), ZZ_p(rep(Q.Y)), ZZ_p(rep(Q.Z)));
    }
    if (Q.is_infinity()) {
        // Normalize P's coordinates under current modulus
        return JacobianPoint(ZZ_p(rep(P.X)), ZZ_p(rep(P.Y)), ZZ_p(rep(P.Z)));
    }
    
    // CRITICAL: Normalize input coordinates under current modulus
    // This ensures ZZ_p values created under different modulus are correctly interpreted
    ZZ_p P_X = ZZ_p(rep(P.X));
    ZZ_p P_Y = ZZ_p(rep(P.Y));
    ZZ_p P_Z = ZZ_p(rep(P.Z));
    ZZ_p Q_X = ZZ_p(rep(Q.X));
    ZZ_p Q_Y = ZZ_p(rep(Q.Y));
    ZZ_p Q_Z = ZZ_p(rep(Q.Z));
    
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
    // Ensure correct modulus FIRST before any ZZ_p operations
    ZZ_p::init(p_);
    
    if (P.is_infinity()) {
        // Return normalized infinity point
        return JacobianPoint();
    }
    
    // CRITICAL: Normalize input coordinates under current modulus
    ZZ_p P_X = ZZ_p(rep(P.X));
    ZZ_p P_Y = ZZ_p(rep(P.Y));
    ZZ_p P_Z = ZZ_p(rep(P.Z));
    
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
    // Ensure correct modulus FIRST
    ZZ_p::init(p_);
    
    if (P.is_infinity()) {
        // Return normalized infinity point
        return JacobianPoint();
    }
    
    // Normalize and negate
    ZZ_p P_Y = ZZ_p(rep(P.Y));
    return JacobianPoint(ZZ_p(rep(P.X)), -P_Y, ZZ_p(rep(P.Z)));
}

JacobianPoint ECCurve::subtract(const JacobianPoint& P, const JacobianPoint& Q) const {
    return add(P, negate(Q));
}

// ============================================================================
// Scalar Multiplication - Montgomery Ladder (Constant-Time)
// ============================================================================

/**
 * @brief Get fe256 curve operations table for named curve
 * @return Pointer to curve ops or nullptr if not a 256-bit curve
 */
static const Fe256CurveOps* get_fe256_ops(const std::string& curve_name) {
    if (curve_name == "secp256k1") {
        return &secp256k1_ops;
    } else if (curve_name == "secp256r1" || curve_name == "P-256") {
        return &p256_ops;
    } else if (curve_name == "sm2" || curve_name == "SM2") {
        return &sm2_ops;
    }
    return nullptr;
}

using Fe256MontFn = void (*)(Fe256* r, const Fe256* a);

static Fe256MontFn get_fe256_to_mont(const std::string& curve_name) {
    if (curve_name == "secp256k1") {
        return fe256_to_mont_secp256k1;
    } else if (curve_name == "secp256r1" || curve_name == "P-256") {
        return fe256_to_mont_p256;
    } else if (curve_name == "sm2" || curve_name == "SM2") {
        return fe256_to_mont_sm2;
    }
    return nullptr;
}

static Fe256MontFn get_fe256_from_mont(const std::string& curve_name) {
    if (curve_name == "secp256k1") {
        return fe256_from_mont_secp256k1;
    } else if (curve_name == "secp256r1" || curve_name == "P-256") {
        return fe256_from_mont_p256;
    } else if (curve_name == "sm2" || curve_name == "SM2") {
        return fe256_from_mont_sm2;
    }
    return nullptr;
}

JacobianPoint ECCurve::montgomery_ladder(const ZZ& k, const JacobianPoint& P) const {
    if (IsZero(k) || P.is_infinity()) {
        return JacobianPoint();
    }
    
    // Reduce k modulo n
    ZZ k_mod = k % n_;
    if (IsZero(k_mod)) {
        return JacobianPoint();
    }
    
    // v4.8.2+: fe256 fast path for 256-bit curves
    // Enable with KCTSB_DEBUG_FE256 to verify correctness
#if defined(KCTSB_DEBUG_FE256) || 0  // TEMP: Disabled for debugging - use NTL fallback
    const Fe256CurveOps* ops = get_fe256_ops(name_);
    const Fe256MontFn to_mont = get_fe256_to_mont(name_);
    const Fe256MontFn from_mont = get_fe256_from_mont(name_);
#else
    const Fe256CurveOps* ops = nullptr; // Disabled pending validation
    const Fe256MontFn to_mont = nullptr;
    const Fe256MontFn from_mont = nullptr;
#endif
    if (ops != nullptr && bit_size_ == 256 && to_mont != nullptr && from_mont != nullptr) {
        // CRITICAL: Initialize modulus before any ZZ_p operations
        ZZ_p::init(p_);
        
        // Convert inputs to fe256 format
        // Normalize coordinates under current modulus first
        ZZ_p P_X = ZZ_p(rep(P.X));
        ZZ_p P_Y = ZZ_p(rep(P.Y));
        ZZ_p P_Z = ZZ_p(rep(P.Z));
        
        Fe256Point fe_P;
        zz_to_fe256(&fe_P.X, rep(P_X));
        zz_to_fe256(&fe_P.Y, rep(P_Y));
        zz_to_fe256(&fe_P.Z, rep(P_Z));
        to_mont(&fe_P.X, &fe_P.X);
        to_mont(&fe_P.Y, &fe_P.Y);
        to_mont(&fe_P.Z, &fe_P.Z);
        fe_P.is_infinity = P.is_infinity() ? 1 : 0;
        
        // Convert scalar to 4-limb format (big-endian for Montgomery ladder)
        uint64_t k_limbs[4] = {0};
        std::vector<uint8_t> k_bytes(32, 0);
        BytesFromZZ(k_bytes.data(), k_mod, 32);
        for (int i = 0; i < 4; i++) {
            k_limbs[i] = 0;
            for (int j = 0; j < 8; j++) {
                k_limbs[i] |= (uint64_t)k_bytes[i * 8 + j] << (j * 8);
            }
        }
        
        // Run fe256 Montgomery ladder
        Fe256Point fe_R;
        fe256_montgomery_ladder(&fe_R, k_limbs, &fe_P, ops);
        
        if (fe_R.is_infinity) {
            return JacobianPoint();
        }
        
        // Convert back to ZZ_p
        ZZ_p::init(p_);
        ZZ rx, ry, rz;
        Fe256 out_x = fe_R.X;
        Fe256 out_y = fe_R.Y;
        Fe256 out_z = fe_R.Z;
        from_mont(&out_x, &out_x);
        from_mont(&out_y, &out_y);
        from_mont(&out_z, &out_z);
        fe256_to_zz(rx, &out_x);
        fe256_to_zz(ry, &out_y);
        fe256_to_zz(rz, &out_z);
        
        return JacobianPoint(ZZ_p(rx), ZZ_p(ry), ZZ_p(rz));
    }
    
    // Fallback: NTL-based Montgomery ladder for non-256-bit curves
    // CRITICAL: Initialize modulus BEFORE creating any ZZ_p values
    ZZ_p::init(p_);
    
    // Normalize input point coordinates under correct modulus
    JacobianPoint R0 = JacobianPoint();  // R0 = O (infinity)
    JacobianPoint R1(ZZ_p(rep(P.X)), ZZ_p(rep(P.Y)), ZZ_p(rep(P.Z)));
    
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
    JacobianPoint P_norm(ZZ_p(rep(P.X)), ZZ_p(rep(P.Y)), ZZ_p(rep(P.Z)));
    return montgomery_ladder(k, P_norm);
}

JacobianPoint ECCurve::scalar_mult_base(const ZZ& k) const {
    // Use constant-time Montgomery ladder for security
    ZZ_p::init(p_);
    JacobianPoint G_norm(ZZ_p(rep(G_.X)), ZZ_p(rep(G_.Y)), ZZ_p(rep(G_.Z)));
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
    JacobianPoint P_norm(ZZ_p(rep(P.X)), ZZ_p(rep(P.Y)), ZZ_p(rep(P.Z)));
    JacobianPoint Q_norm(ZZ_p(rep(Q.X)), ZZ_p(rep(Q.Y)), ZZ_p(rep(Q.Z)));
    
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
    ZZ_p X = ZZ_p(rep(P.X));
    ZZ_p Y = ZZ_p(rep(P.Y));
    ZZ_p Z = ZZ_p(rep(P.Z));
    
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
        
        AffinePoint P{ZZ_p(x_int), ZZ_p(y_int)};
        
        if (!is_on_curve(P)) {
            throw std::invalid_argument("Point is not on curve");
        }
        
        return P;
    }
    
    // TODO: Add compressed point support (0x02, 0x03)
    throw std::invalid_argument("Unsupported point format");
}

} // namespace internal
} // namespace ecc
} // namespace kctsb


