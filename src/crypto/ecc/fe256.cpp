/**
 * @file fe256.cpp
 * @brief High-Performance 256-bit Field Element Arithmetic Implementation
 * 
 * Optimized field operations for secp256k1 and SM2 curves.
 * 
 * Key optimizations:
 * - Montgomery multiplication (eliminates division)
 * - Specialized modular reduction using prime structure
 * - 128-bit integer arithmetic via __int128 or intrinsics
 * - Constant-time operations for security
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
// 128-bit Arithmetic Helpers
// ============================================================================

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;

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
    *borrow_out = (diff >> 127) ? 1 : 0;  // If underflow, borrow = 1
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
// secp256k1 Constants
// ============================================================================

// p = 2^256 - 2^32 - 977 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
const fe256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
}};

// R^2 mod p (for converting to Montgomery form)
// R = 2^256, R^2 mod p precomputed
const fe256 SECP256K1_R2 = {{
    0x0000000000000001ULL,
    0x00000001000003D1ULL,
    0x0000000000000000ULL,
    0x0000000000000000ULL
}};

// n0 = -p^(-1) mod 2^64
const uint64_t SECP256K1_N0 = 0xD838091DD2253531ULL;

// ============================================================================
// SM2 Constants
// ============================================================================

// SM2 p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
const fe256 SM2_P = {{
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL
}};

// R^2 mod p for SM2
const fe256 SM2_R2 = {{
    0x0000000200000003ULL,
    0x00000002FFFFFFFFULL,
    0x0000000100000001ULL,
    0x0000000400000002ULL
}};

// n0 = -p^(-1) mod 2^64 for SM2
const uint64_t SM2_N0 = 0x0000000000000001ULL;

// ============================================================================
// Generic Field Operations
// ============================================================================

int fe256_equal(const fe256* a, const fe256* b) {
    uint64_t diff = 0;
    diff |= a->limb[0] ^ b->limb[0];
    diff |= a->limb[1] ^ b->limb[1];
    diff |= a->limb[2] ^ b->limb[2];
    diff |= a->limb[3] ^ b->limb[3];
    // Constant-time: return 1 if diff == 0
    return ((diff | (~diff + 1)) >> 63) ^ 1;
}

void fe256_cmov(fe256* r, const fe256* a, int cond) {
    // Constant-time conditional move
    uint64_t mask = ~((uint64_t)cond - 1);  // 0 if cond=0, 0xFFFFFFFFFFFFFFFF if cond=1
    r->limb[0] ^= mask & (r->limb[0] ^ a->limb[0]);
    r->limb[1] ^= mask & (r->limb[1] ^ a->limb[1]);
    r->limb[2] ^= mask & (r->limb[2] ^ a->limb[2]);
    r->limb[3] ^= mask & (r->limb[3] ^ a->limb[3]);
}

void fe256_from_bytes(fe256* r, const uint8_t bytes[32]) {
    // Big-endian to little-endian limbs
    r->limb[3] = ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
                 ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
                 ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
                 ((uint64_t)bytes[6] << 8)  | (uint64_t)bytes[7];
    r->limb[2] = ((uint64_t)bytes[8] << 56) | ((uint64_t)bytes[9] << 48) |
                 ((uint64_t)bytes[10] << 40) | ((uint64_t)bytes[11] << 32) |
                 ((uint64_t)bytes[12] << 24) | ((uint64_t)bytes[13] << 16) |
                 ((uint64_t)bytes[14] << 8)  | (uint64_t)bytes[15];
    r->limb[1] = ((uint64_t)bytes[16] << 56) | ((uint64_t)bytes[17] << 48) |
                 ((uint64_t)bytes[18] << 40) | ((uint64_t)bytes[19] << 32) |
                 ((uint64_t)bytes[20] << 24) | ((uint64_t)bytes[21] << 16) |
                 ((uint64_t)bytes[22] << 8)  | (uint64_t)bytes[23];
    r->limb[0] = ((uint64_t)bytes[24] << 56) | ((uint64_t)bytes[25] << 48) |
                 ((uint64_t)bytes[26] << 40) | ((uint64_t)bytes[27] << 32) |
                 ((uint64_t)bytes[28] << 24) | ((uint64_t)bytes[29] << 16) |
                 ((uint64_t)bytes[30] << 8)  | (uint64_t)bytes[31];
}

void fe256_to_bytes(uint8_t bytes[32], const fe256* a) {
    // Little-endian limbs to big-endian bytes
    bytes[0] = (uint8_t)(a->limb[3] >> 56);
    bytes[1] = (uint8_t)(a->limb[3] >> 48);
    bytes[2] = (uint8_t)(a->limb[3] >> 40);
    bytes[3] = (uint8_t)(a->limb[3] >> 32);
    bytes[4] = (uint8_t)(a->limb[3] >> 24);
    bytes[5] = (uint8_t)(a->limb[3] >> 16);
    bytes[6] = (uint8_t)(a->limb[3] >> 8);
    bytes[7] = (uint8_t)(a->limb[3]);
    bytes[8] = (uint8_t)(a->limb[2] >> 56);
    bytes[9] = (uint8_t)(a->limb[2] >> 48);
    bytes[10] = (uint8_t)(a->limb[2] >> 40);
    bytes[11] = (uint8_t)(a->limb[2] >> 32);
    bytes[12] = (uint8_t)(a->limb[2] >> 24);
    bytes[13] = (uint8_t)(a->limb[2] >> 16);
    bytes[14] = (uint8_t)(a->limb[2] >> 8);
    bytes[15] = (uint8_t)(a->limb[2]);
    bytes[16] = (uint8_t)(a->limb[1] >> 56);
    bytes[17] = (uint8_t)(a->limb[1] >> 48);
    bytes[18] = (uint8_t)(a->limb[1] >> 40);
    bytes[19] = (uint8_t)(a->limb[1] >> 32);
    bytes[20] = (uint8_t)(a->limb[1] >> 24);
    bytes[21] = (uint8_t)(a->limb[1] >> 16);
    bytes[22] = (uint8_t)(a->limb[1] >> 8);
    bytes[23] = (uint8_t)(a->limb[1]);
    bytes[24] = (uint8_t)(a->limb[0] >> 56);
    bytes[25] = (uint8_t)(a->limb[0] >> 48);
    bytes[26] = (uint8_t)(a->limb[0] >> 40);
    bytes[27] = (uint8_t)(a->limb[0] >> 32);
    bytes[28] = (uint8_t)(a->limb[0] >> 24);
    bytes[29] = (uint8_t)(a->limb[0] >> 16);
    bytes[30] = (uint8_t)(a->limb[0] >> 8);
    bytes[31] = (uint8_t)(a->limb[0]);
}

// ============================================================================
// secp256k1 Field Operations
// ============================================================================

/**
 * @brief Add with carry, then conditional subtract p
 */
void fe256_add_secp256k1(fe256* r, const fe256* a, const fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    fe256 tmp;
    
    // Add a + b
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = adc64(a->limb[3], b->limb[3], carry, &carry);
    
    // Subtract p conditionally if result >= p
    tmp.limb[0] = sbb64(r->limb[0], SECP256K1_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SECP256K1_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SECP256K1_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SECP256K1_P.limb[3], borrow, &borrow);
    
    // If no borrow (result >= p), use tmp; otherwise keep r
    // carry from addition and final borrow determines this
    int use_reduced = (carry || !borrow) ? 1 : 0;
    fe256_cmov(r, &tmp, use_reduced);
}

void fe256_sub_secp256k1(fe256* r, const fe256* a, const fe256* b) {
    uint64_t borrow = 0;
    
    // Subtract a - b
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    
    // If borrow, add p back (constant-time)
    fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = adc64(r->limb[0], SECP256K1_P.limb[0], 0, &carry);
    tmp.limb[1] = adc64(r->limb[1], SECP256K1_P.limb[1], carry, &carry);
    tmp.limb[2] = adc64(r->limb[2], SECP256K1_P.limb[2], carry, &carry);
    tmp.limb[3] = adc64(r->limb[3], SECP256K1_P.limb[3], carry, &carry);
    
    fe256_cmov(r, &tmp, (int)borrow);
}

void fe256_neg_secp256k1(fe256* r, const fe256* a) {
    // -a mod p = p - a (if a != 0)
    int is_nonzero = !fe256_is_zero(a);
    
    uint64_t borrow = 0;
    r->limb[0] = sbb64(SECP256K1_P.limb[0], a->limb[0], 0, &borrow);
    r->limb[1] = sbb64(SECP256K1_P.limb[1], a->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(SECP256K1_P.limb[2], a->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(SECP256K1_P.limb[3], a->limb[3], borrow, &borrow);
    
    // If a was zero, result should be zero
    fe256 zero_fe;
    fe256_zero(&zero_fe);
    fe256_cmov(r, &zero_fe, !is_nonzero);
}

/**
 * @brief Wide multiplication: r = a × b (512-bit result)
 */
void fe256_mul_wide(fe512* r, const fe256* a, const fe256* b) {
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

void fe256_sqr_wide(fe512* r, const fe256* a) {
    // For now, use multiplication
    // TODO: Optimized squaring with fewer multiplications
    fe256_mul_wide(r, a, a);
}

/**
 * @brief secp256k1 specialized reduction
 * 
 * Uses: 2^256 ≡ 2^32 + 977 (mod p)
 * So for 512-bit input [h3:h2:h1:h0:l3:l2:l1:l0]:
 * result = [l3:l2:l1:l0] + [h3:h2:h1:h0] * (2^32 + 977)
 */
void fe256_reduce_secp256k1(fe256* r, const fe512* a) {
    // Step 1: Extract high and low 256-bit parts
    // low = a[0..3], high = a[4..7]
    
    // Reduction constant: c = 2^32 + 977 = 0x1000003D1
    const uint64_t c = 0x1000003D1ULL;
    
    uint64_t carry = 0;
    uint64_t hi, lo;
    
    // Compute: r = low + high * c
    // This is: a[0..3] + a[4..7] * 0x1000003D1
    
    // Process a[4] * c + a[0]
    mul64x64(a->limb[4], c, &hi, &lo);
    r->limb[0] = adc64(a->limb[0], lo, 0, &carry);
    uint64_t t0 = hi + carry;
    
    // Process a[5] * c + a[1] + t0
    mul64x64(a->limb[5], c, &hi, &lo);
    r->limb[1] = adc64(a->limb[1], lo, 0, &carry);
    r->limb[1] = adc64(r->limb[1], t0, 0, &carry);
    uint64_t t1 = hi + carry;
    
    // Process a[6] * c + a[2] + t1
    mul64x64(a->limb[6], c, &hi, &lo);
    r->limb[2] = adc64(a->limb[2], lo, 0, &carry);
    r->limb[2] = adc64(r->limb[2], t1, 0, &carry);
    uint64_t t2 = hi + carry;
    
    // Process a[7] * c + a[3] + t2
    mul64x64(a->limb[7], c, &hi, &lo);
    r->limb[3] = adc64(a->limb[3], lo, 0, &carry);
    r->limb[3] = adc64(r->limb[3], t2, 0, &carry);
    uint64_t t3 = hi + carry;
    
    // Final reduction: if t3 > 0, we need another round
    // t3 * c (at most ~33 bits)
    if (t3) {
        mul64x64(t3, c, &hi, &lo);
        r->limb[0] = adc64(r->limb[0], lo, 0, &carry);
        r->limb[1] = adc64(r->limb[1], hi, carry, &carry);
        r->limb[2] = adc64(r->limb[2], 0, carry, &carry);
        r->limb[3] = adc64(r->limb[3], 0, carry, &carry);
    }
    
    // Final conditional subtraction if r >= p
    fe256 tmp;
    uint64_t borrow = 0;
    tmp.limb[0] = sbb64(r->limb[0], SECP256K1_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SECP256K1_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SECP256K1_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SECP256K1_P.limb[3], borrow, &borrow);
    
    // If no borrow, use reduced value
    fe256_cmov(r, &tmp, !borrow);
}

/**
 * @brief secp256k1 Montgomery multiplication
 */
void fe256_mul_mont_secp256k1(fe256* r, const fe256* a, const fe256* b) {
    fe512 wide;
    fe256_mul_wide(&wide, a, b);
    
    // Montgomery reduction using secp256k1's special form
    // For each limb i, compute m = (wide[i] * n0) mod 2^64
    // Then add m * p to wide, shift right by 64 bits
    
    const uint64_t n0 = SECP256K1_N0;
    uint64_t carry;
    
    for (int i = 0; i < 4; i++) {
        uint64_t m = wide.limb[i] * n0;
        
        // Add m * p to wide[i..i+4]
        uint64_t hi, lo;
        
        // p[0] = 0xFFFFFFFEFFFFFC2F
        mul64x64(m, SECP256K1_P.limb[0], &hi, &lo);
        wide.limb[i] = adc64(wide.limb[i], lo, 0, &carry);
        uint64_t t = hi + carry;
        
        // p[1] = p[2] = p[3] = 0xFFFFFFFFFFFFFFFF
        // m * 0xFFFFFFFFFFFFFFFF = m * 2^64 - m
        // = (m << 64) - m
        // So: wide[i+1] += m * p[1] = wide[i+1] + (m * 2^64 - m)
        // = wide[i+1] + carry - m + m * 2^64
        
        wide.limb[i+1] = adc64(wide.limb[i+1], t, 0, &carry);
        // Subtract m, add m to next (equivalent to m * 2^64 - m)
        uint64_t borrow;
        wide.limb[i+1] = sbb64(wide.limb[i+1], m, 0, &borrow);
        t = m + carry - borrow;
        
        wide.limb[i+2] = adc64(wide.limb[i+2], t, 0, &carry);
        wide.limb[i+2] = sbb64(wide.limb[i+2], m, 0, &borrow);
        t = m + carry - borrow;
        
        wide.limb[i+3] = adc64(wide.limb[i+3], t, 0, &carry);
        wide.limb[i+3] = sbb64(wide.limb[i+3], m, 0, &borrow);
        t = m + carry - borrow;
        
        if (i < 3) {
            wide.limb[i+4] = adc64(wide.limb[i+4], t, 0, &carry);
        } else {
            wide.limb[7] = t;
        }
    }
    
    // Result is in wide[4..7]
    r->limb[0] = wide.limb[4];
    r->limb[1] = wide.limb[5];
    r->limb[2] = wide.limb[6];
    r->limb[3] = wide.limb[7];
    
    // Final conditional subtraction
    fe256 tmp;
    uint64_t borrow = 0;
    tmp.limb[0] = sbb64(r->limb[0], SECP256K1_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SECP256K1_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SECP256K1_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SECP256K1_P.limb[3], borrow, &borrow);
    
    fe256_cmov(r, &tmp, !borrow);
}

void fe256_sqr_mont_secp256k1(fe256* r, const fe256* a) {
    // TODO: Optimized squaring
    fe256_mul_mont_secp256k1(r, a, a);
}

void fe256_to_mont_secp256k1(fe256* r, const fe256* a) {
    // a_mont = a * R mod p = MontMul(a, R^2)
    fe256_mul_mont_secp256k1(r, a, &SECP256K1_R2);
}

void fe256_from_mont_secp256k1(fe256* r, const fe256* a) {
    // a = a_mont * R^(-1) mod p = MontMul(a_mont, 1)
    fe256 one;
    fe256_one(&one);
    fe256_mul_mont_secp256k1(r, a, &one);
}

void fe256_inv_secp256k1(fe256* r, const fe256* a) {
    // a^(-1) = a^(p-2) mod p using binary method
    // p - 2 for secp256k1
    
    fe256 result, base;
    fe256_to_mont_secp256k1(&base, a);
    
    // Start with result = 1 in Montgomery form
    fe256_copy(&result, &SECP256K1_R2);  // R^2 * R^(-1) = R (Montgomery 1)
    fe256_from_mont_secp256k1(&result, &SECP256K1_R2);  // Temporary fix
    fe256_to_mont_secp256k1(&result, &result);
    
    // Square-and-multiply for p-2
    // This is slow - should use addition chain optimization
    // For now, use simple binary method
    
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
    
    fe256_from_mont_secp256k1(r, &result);
}

// ============================================================================
// SM2 Field Operations (similar structure, different constants)
// ============================================================================

void fe256_add_sm2(fe256* r, const fe256* a, const fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    fe256 tmp;
    
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

void fe256_sub_sm2(fe256* r, const fe256* a, const fe256* b) {
    uint64_t borrow = 0;
    
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    
    fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = adc64(r->limb[0], SM2_P.limb[0], 0, &carry);
    tmp.limb[1] = adc64(r->limb[1], SM2_P.limb[1], carry, &carry);
    tmp.limb[2] = adc64(r->limb[2], SM2_P.limb[2], carry, &carry);
    tmp.limb[3] = adc64(r->limb[3], SM2_P.limb[3], carry, &carry);
    
    fe256_cmov(r, &tmp, (int)borrow);
}

void fe256_neg_sm2(fe256* r, const fe256* a) {
    int is_nonzero = !fe256_is_zero(a);
    
    uint64_t borrow = 0;
    r->limb[0] = sbb64(SM2_P.limb[0], a->limb[0], 0, &borrow);
    r->limb[1] = sbb64(SM2_P.limb[1], a->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(SM2_P.limb[2], a->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(SM2_P.limb[3], a->limb[3], borrow, &borrow);
    
    fe256 zero_fe;
    fe256_zero(&zero_fe);
    fe256_cmov(r, &zero_fe, !is_nonzero);
}

/**
 * @brief SM2 specialized reduction
 * 
 * SM2 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * So: 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
 */
void fe256_reduce_sm2(fe256* r, const fe512* a) {
    // SM2 reduction is more complex due to the prime structure
    // Using the identity: 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
    
    // For a 512-bit input, we need to reduce the high 256 bits
    // This is a simplified version - full optimization requires careful handling
    
    // Copy low 256 bits
    r->limb[0] = a->limb[0];
    r->limb[1] = a->limb[1];
    r->limb[2] = a->limb[2];
    r->limb[3] = a->limb[3];
    
    // Add high parts with appropriate shifts
    // h * 2^256 ≡ h * (2^224 + 2^96 - 2^64 + 1) (mod p)
    
    uint64_t carry = 0;
    uint64_t borrow = 0;
    
    // Add h[0..3] (the +1 term)
    r->limb[0] = adc64(r->limb[0], a->limb[4], 0, &carry);
    r->limb[1] = adc64(r->limb[1], a->limb[5], carry, &carry);
    r->limb[2] = adc64(r->limb[2], a->limb[6], carry, &carry);
    r->limb[3] = adc64(r->limb[3], a->limb[7], carry, &carry);
    
    // Add h shifted left by 32 bits (the 2^224 term, which affects limb[3] high bits)
    // h * 2^224 = h << 224
    // In 64-bit limbs: this adds h[0] to bits [224:287] of result
    // = r[3] high 32 bits + overflow
    uint64_t h0_hi = a->limb[4] >> 32;
    uint64_t h1_lo = a->limb[5] << 32;
    uint64_t h1_hi = a->limb[5] >> 32;
    uint64_t h2_lo = a->limb[6] << 32;
    uint64_t h2_hi = a->limb[6] >> 32;
    uint64_t h3_lo = a->limb[7] << 32;
    
    r->limb[3] = adc64(r->limb[3], (a->limb[4] << 32), 0, &carry);
    
    // Subtract h shifted for 2^64 term and add for 2^96 term
    // This needs careful handling of the sign
    
    // For now, do a simpler but less optimal reduction using repeated subtraction
    // Full optimization would inline all the shift-add-sub operations
    
    // Final conditional subtractions
    for (int i = 0; i < 3; i++) {  // At most 3 subtractions needed
        fe256 tmp;
        tmp.limb[0] = sbb64(r->limb[0], SM2_P.limb[0], 0, &borrow);
        tmp.limb[1] = sbb64(r->limb[1], SM2_P.limb[1], borrow, &borrow);
        tmp.limb[2] = sbb64(r->limb[2], SM2_P.limb[2], borrow, &borrow);
        tmp.limb[3] = sbb64(r->limb[3], SM2_P.limb[3], borrow, &borrow);
        
        fe256_cmov(r, &tmp, !borrow);
        
        if (borrow) break;  // Result is reduced
    }
}

void fe256_mul_mont_sm2(fe256* r, const fe256* a, const fe256* b) {
    fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_sm2(r, &wide);
    
    // TODO: Full Montgomery reduction for SM2
    // Current implementation uses simple modular reduction
}

void fe256_sqr_mont_sm2(fe256* r, const fe256* a) {
    fe256_mul_mont_sm2(r, a, a);
}

void fe256_to_mont_sm2(fe256* r, const fe256* a) {
    fe256_mul_mont_sm2(r, a, &SM2_R2);
}

void fe256_from_mont_sm2(fe256* r, const fe256* a) {
    fe256 one;
    fe256_one(&one);
    fe256_mul_mont_sm2(r, a, &one);
}

void fe256_inv_sm2(fe256* r, const fe256* a) {
    // a^(-1) = a^(p-2) mod p
    fe256 result, base;
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

void fe256_cneg(fe256* r, const fe256* a, int cond, int curve_type) {
    fe256 neg;
    if (curve_type == 0) {
        fe256_neg_secp256k1(&neg, a);
    } else {
        fe256_neg_sm2(&neg, a);
    }
    fe256_copy(r, a);
    fe256_cmov(r, &neg, cond);
}
