/**
 * @file sm2_mont.cpp
 * @brief SM2 Montgomery Domain Field Arithmetic
 * 
 * Optimized field arithmetic using Montgomery multiplication for SM2 curve.
 * This provides significant performance improvement over Solinas reduction
 * by reducing the number of operations per multiplication.
 * 
 * Montgomery multiplication: Mont(a, b) = a * b * R^(-1) mod p
 * where R = 2^256
 * 
 * Key constants:
 * - p' = -p^(-1) mod 2^256 (for Montgomery reduction)
 * - RR = R^2 mod p (for converting to Montgomery form)
 * - MONT_ONE = R mod p (multiplicative identity in Montgomery form)
 * 
 * Reference: GmSSL sm2_z256.c, Intel ecp_nistz256 implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <cstdint>
#include <cstring>
#include <array>

// Assembly acceleration header (platform detection + external declarations)
#include "asm/sm2_asm.h"

// Platform detection
#if defined(__x86_64__) || defined(_M_X64)
    #define KCTSB_ARCH_X64 1
#endif

#if defined(__SIZEOF_INT128__)
    #if defined(__GNUC__) && !defined(__clang__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wpedantic"
    #endif
    typedef unsigned __int128 uint128_t;
    typedef __int128 int128_t;
    #define KCTSB_HAS_INT128 1
    #if defined(__GNUC__) && !defined(__clang__)
        #pragma GCC diagnostic pop
    #endif
#else
    #error "SM2 Montgomery implementation requires __int128 support"
#endif

namespace kctsb::internal::sm2::mont {

// ============================================================================
// Constants
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

/**
 * @brief SM2 prime
 * p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 *   = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
 */
static constexpr fe256 SM2_P = {{
    0xFFFFFFFFFFFFFFFFULL,  // limb[0] - LSB
    0xFFFFFFFF00000000ULL,  // limb[1]
    0xFFFFFFFFFFFFFFFFULL,  // limb[2]
    0xFFFFFFFEFFFFFFFFULL   // limb[3] - MSB
}};

/**
 * @brief 2^256 - p (used for final reduction and as MONT_ONE)
 * NEG_P = 2^224 + 2^96 - 2^64 + 1
 */
static constexpr fe256 SM2_NEG_P = {{
    0x0000000000000001ULL,  // +1
    0x00000000FFFFFFFFULL,  // -2^64 + 2^96 = 2^64 * (2^32 - 1)
    0x0000000000000000ULL,  // 0
    0x0000000100000000ULL   // 2^224 = 2^64 * 2^160 at limb[3] position 32
}};

/**
 * @brief Montgomery constant: p' = -p^(-1) mod 2^256
 * Used in Montgomery reduction step
 * 
 * Computed as: sage: -(IntegerModRing(2^256)(p))^-1
 */
static constexpr fe256 SM2_P_PRIME = {{
    0x0000000000000001ULL,
    0xFFFFFFFF00000001ULL,
    0xFFFFFFFE00000000ULL,
    0xFFFFFFFC00000001ULL
}};

/**
 * @brief R^2 mod p (for converting to Montgomery form)
 * R = 2^256, so RR = 2^512 mod p
 * 
 * to_mont(a) = mont_mul(a, RR)
 * 
 * Computed: RR = 0x0000000400000002_0000000100000001_00000002FFFFFFFF_0000000200000003
 */
static constexpr fe256 SM2_RR = {{
    0x0000000200000003ULL,  // limb[0] - LSB
    0x00000002FFFFFFFFULL,  // limb[1]
    0x0000000100000001ULL,  // limb[2]
    0x0000000400000002ULL   // limb[3] - MSB
}};

/**
 * @brief 1 in Montgomery form = R mod p = 2^256 - p = NEG_P
 */
static constexpr fe256 SM2_MONT_ONE = {{
    0x0000000000000001ULL,
    0x00000000FFFFFFFFULL,
    0x0000000000000000ULL,
    0x0000000100000000ULL
}};

// ============================================================================
// Low-level arithmetic primitives
// ============================================================================

/**
 * @brief 64-bit addition with carry
 */
static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint128_t sum = (uint128_t)a + b + carry_in;
    *carry_out = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
}

/**
 * @brief 64-bit subtraction with borrow
 */
static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint128_t diff = (uint128_t)a - b - borrow_in;
    *borrow_out = (diff >> 127) ? 1 : 0;
    return (uint64_t)diff;
}

/**
 * @brief 64x64 -> 128-bit multiplication
 */
static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t product = (uint128_t)a * b;
    *lo = (uint64_t)product;
    *hi = (uint64_t)(product >> 64);
}

// ============================================================================
// Basic fe256 operations
// ============================================================================

/**
 * @brief Copy fe256
 */
static inline void fe256_copy(fe256* dst, const fe256* src) {
    dst->limb[0] = src->limb[0];
    dst->limb[1] = src->limb[1];
    dst->limb[2] = src->limb[2];
    dst->limb[3] = src->limb[3];
}

/**
 * @brief Set fe256 to zero
 */
static inline void fe256_zero(fe256* a) {
    a->limb[0] = 0;
    a->limb[1] = 0;
    a->limb[2] = 0;
    a->limb[3] = 0;
}

/**
 * @brief Constant-time conditional copy: if cond != 0, dst = src
 */
static inline void fe256_cmov(fe256* dst, const fe256* src, uint64_t cond) {
    uint64_t mask = ~(cond - 1);  // 0 if cond==0, all 1s otherwise
    dst->limb[0] ^= mask & (dst->limb[0] ^ src->limb[0]);
    dst->limb[1] ^= mask & (dst->limb[1] ^ src->limb[1]);
    dst->limb[2] ^= mask & (dst->limb[2] ^ src->limb[2]);
    dst->limb[3] ^= mask & (dst->limb[3] ^ src->limb[3]);
}

/**
 * @brief Compare two fe256 values
 * @return -1 if a < b, 0 if a == b, 1 if a > b
 */
static inline int fe256_cmp(const fe256* a, const fe256* b) {
    for (int i = 3; i >= 0; i--) {
        if (a->limb[i] > b->limb[i]) return 1;
        if (a->limb[i] < b->limb[i]) return -1;
    }
    return 0;
}

/**
 * @brief Check if fe256 is zero (constant-time)
 */
static inline uint64_t fe256_is_zero(const fe256* a) {
    uint64_t x = a->limb[0] | a->limb[1] | a->limb[2] | a->limb[3];
    // Return 1 if zero, 0 otherwise
    return ((x | (~x + 1)) >> 63) ^ 1;
}

// ============================================================================
// Modular arithmetic (mod p)
// ============================================================================

/**
 * @brief 256-bit addition: r = a + b, returns carry
 */
static inline uint64_t fe256_add(fe256* r, const fe256* a, const fe256* b) {
    uint64_t c = 0;
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &c);
    r->limb[1] = adc64(a->limb[1], b->limb[1], c, &c);
    r->limb[2] = adc64(a->limb[2], b->limb[2], c, &c);
    r->limb[3] = adc64(a->limb[3], b->limb[3], c, &c);
    return c;
}

/**
 * @brief 256-bit subtraction: r = a - b, returns borrow
 */
static inline uint64_t fe256_sub(fe256* r, const fe256* a, const fe256* b) {
    uint64_t borrow = 0;
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    return borrow;
}

/**
 * @brief Modular addition: r = (a + b) mod p
 * 
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_modp_add(fe256* r, const fe256* a, const fe256* b) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_add(r->limb, a->limb, b->limb);
#else
    uint64_t carry = fe256_add(r, a, b);
    
    if (carry) {
        // a + b >= 2^256, so subtract 2^256 and add (2^256 - p) = NEG_P
        fe256_add(r, r, &SM2_NEG_P);
        return;
    }
    
    // Check if r >= p
    if (fe256_cmp(r, &SM2_P) >= 0) {
        fe256_sub(r, r, &SM2_P);
    }
#endif
}

/**
 * @brief Modular subtraction: r = (a - b) mod p
 * 
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_modp_sub(fe256* r, const fe256* a, const fe256* b) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_sub(r->limb, a->limb, b->limb);
#else
    uint64_t borrow = fe256_sub(r, a, b);
    
    if (borrow) {
        // a - b < 0, so add p (subtract 2^256 - p = NEG_P to compensate)
        fe256_sub(r, r, &SM2_NEG_P);
    }
#endif
}

/**
 * @brief Modular doubling: r = 2*a mod p
 * 
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_modp_dbl(fe256* r, const fe256* a) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_dbl(r->limb, a->limb);
#else
    fe256_modp_add(r, a, a);
#endif
}

/**
 * @brief Modular negation: r = -a mod p = p - a
 * 
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_modp_neg(fe256* r, const fe256* a) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_neg(r->limb, a->limb);
#else
    fe256_sub(r, &SM2_P, a);
#endif
}

/**
 * @brief Modular halving: r = a/2 mod p
 * If a is odd, compute (a + p) / 2
 * 
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_modp_half(fe256* r, const fe256* a) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_half(r->limb, a->limb);
#else
    uint64_t c = 0;
    fe256 tmp;
    
    // If a is odd, add p first
    if (a->limb[0] & 1) {
        c = fe256_add(&tmp, a, &SM2_P);
    } else {
        fe256_copy(&tmp, a);
    }
    
    // Right shift by 1 bit
    r->limb[0] = (tmp.limb[0] >> 1) | ((tmp.limb[1] & 1) << 63);
    r->limb[1] = (tmp.limb[1] >> 1) | ((tmp.limb[2] & 1) << 63);
    r->limb[2] = (tmp.limb[2] >> 1) | ((tmp.limb[3] & 1) << 63);
    r->limb[3] = (tmp.limb[3] >> 1) | ((c & 1) << 63);
#endif
}

// ============================================================================
// Montgomery multiplication
// ============================================================================

/**
 * @brief 256x256 -> 512-bit schoolbook multiplication
 * 
 * Computes r = a * b as a 512-bit product.
 * Uses schoolbook algorithm with proper carry propagation.
 */
static void fe256_mul_512(fe512* r, const fe256* a, const fe256* b) {
    // Use 128-bit intermediate products
    uint128_t acc;
    uint64_t carry;
    
    // Initialize result to zero
    for (int i = 0; i < 8; i++) {
        r->limb[i] = 0;
    }
    
    // Schoolbook multiplication
    for (int i = 0; i < 4; i++) {
        carry = 0;
        for (int j = 0; j < 4; j++) {
            // acc = a[i] * b[j] + r[i+j] + carry
            acc = (uint128_t)a->limb[i] * b->limb[j];
            acc += r->limb[i + j];
            acc += carry;
            
            r->limb[i + j] = (uint64_t)acc;
            carry = (uint64_t)(acc >> 64);
        }
        // Propagate final carry - must ADD to existing value, not overwrite
        r->limb[i + 4] += carry;
    }
}

/**
 * @brief Montgomery reduction step
 * 
 * Given z (512-bit), compute r = z * R^(-1) mod p
 * 
 * Algorithm (CIOS - Coarsely Integrated Operand Scanning):
 *   1. m = (z mod R) * p' mod R    (where R = 2^256)
 *   2. t = z + m * p
 *   3. r = t / R  (right shift by 256 bits)
 *   4. if r >= p then r -= p
 * 
 * The key insight is that m * p makes the low 256 bits of (z + m*p) zero,
 * so dividing by R is just taking the high 256 bits.
 */
static void fe256_mont_reduce(fe256* r, const fe512* z) {
    fe512 mp;    // m * p (512-bit)
    uint64_t c;
    
    // Step 1: m = z_low * p' mod 2^256 (only need low 256 bits)
    // We compute m = z[0..3] * p'[0..3] and take only low 256 bits
    fe256 m;
    {
        // m[0] = z[0] * p'[0] mod 2^64
        // m[1] = (z[0] * p'[1] + z[1] * p'[0] + carry) mod 2^64
        // etc.
        // Since we only need low 256 bits, we can use a simplified multiply
        uint128_t acc;
        uint64_t carry = 0;
        
        // m[0] = z[0] * p'[0] mod 2^64
        acc = (uint128_t)z->limb[0] * SM2_P_PRIME.limb[0];
        m.limb[0] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);
        
        // m[1]
        acc = (uint128_t)z->limb[0] * SM2_P_PRIME.limb[1] + 
              (uint128_t)z->limb[1] * SM2_P_PRIME.limb[0] + carry;
        m.limb[1] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);
        
        // m[2]
        acc = (uint128_t)z->limb[0] * SM2_P_PRIME.limb[2] + 
              (uint128_t)z->limb[1] * SM2_P_PRIME.limb[1] + 
              (uint128_t)z->limb[2] * SM2_P_PRIME.limb[0] + carry;
        m.limb[2] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);
        
        // m[3]
        acc = (uint128_t)z->limb[0] * SM2_P_PRIME.limb[3] + 
              (uint128_t)z->limb[1] * SM2_P_PRIME.limb[2] + 
              (uint128_t)z->limb[2] * SM2_P_PRIME.limb[1] + 
              (uint128_t)z->limb[3] * SM2_P_PRIME.limb[0] + carry;
        m.limb[3] = (uint64_t)acc;
        // Higher bits discarded (mod 2^256)
    }
    
    // Step 2: mp = m * p (full 512-bit result)
    fe256_mul_512(&mp, &m, &SM2_P);
    
    // Step 3: tmp = z + mp (512-bit addition)
    fe512 tmp;
    c = 0;
    for (int i = 0; i < 8; i++) {
        tmp.limb[i] = adc64(z->limb[i], mp.limb[i], c, &c);
    }
    
    // Step 4: r = tmp >> 256 (high 256 bits)
    // Note: tmp.limb[0..3] should be zero if algorithm is correct
    r->limb[0] = tmp.limb[4];
    r->limb[1] = tmp.limb[5];
    r->limb[2] = tmp.limb[6];
    r->limb[3] = tmp.limb[7];
    
    // Step 5: Final reduction - if carry or r >= p, subtract p
    if (c) {
        // tmp was >= 2^512, so r + (2^256 mod p) = r + NEG_P
        fe256_add(r, r, &SM2_NEG_P);
    } else if (fe256_cmp(r, &SM2_P) >= 0) {
        fe256_sub(r, r, &SM2_P);
    }
}

/**
 * @brief Montgomery multiplication: r = a * b * R^(-1) mod p
 * 
 * Both a and b should be in Montgomery form.
 * Result r is also in Montgomery form.
 * 
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_mont_mul(fe256* r, const fe256* a, const fe256* b) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_mont_mul(r->limb, a->limb, b->limb);
#else
    fe512 z;
    fe256_mul_512(&z, a, b);
    fe256_mont_reduce(r, &z);
#endif
}

/**
 * @brief Montgomery squaring: r = a^2 * R^(-1) mod p
 * 
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_mont_sqr(fe256* r, const fe256* a) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_mont_sqr(r->limb, a->limb);
#else
    fe256_mont_mul(r, a, a);
#endif
}

/**
 * @brief Convert to Montgomery form: r = a * R mod p
 * 
 * mont(a) = mont_mul(a, R^2) = a * R^2 * R^(-1) = a * R
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_to_mont(fe256* r, const fe256* a) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_to_mont(r->limb, a->limb);
#else
    fe256_mont_mul(r, a, &SM2_RR);
#endif
}

/**
 * @brief Convert from Montgomery form: r = a * R^(-1) mod p
 * 
 * from_mont(a) = mont_mul(a, 1) = a * 1 * R^(-1) = a * R^(-1)
 * Uses assembly acceleration on x86_64 when available.
 */
void fe256_from_mont(fe256* r, const fe256* a) {
#if defined(KCTSB_SM2_USE_ASM)
    sm2_z256_modp_from_mont(r->limb, a->limb);
#else
    fe256 one;
    fe256_zero(&one);
    one.limb[0] = 1;
    fe256_mont_mul(r, a, &one);
#endif
}

// ============================================================================
// Montgomery exponentiation (for inversion)
// ============================================================================

/**
 * @brief Montgomery exponentiation: r = a^e mod p (in Montgomery form)
 * 
 * Uses square-and-multiply algorithm.
 * Both a and result r are in Montgomery form.
 */
void fe256_mont_exp(fe256* r, const fe256* a, const fe256* e) {
    fe256 t;
    uint64_t w;
    
    // t = 1 in Montgomery form
    fe256_copy(&t, &SM2_MONT_ONE);
    
    // Square-and-multiply from MSB
    for (int i = 3; i >= 0; i--) {
        w = e->limb[i];
        for (int j = 0; j < 64; j++) {
            fe256_mont_sqr(&t, &t);
            if (w & 0x8000000000000000ULL) {
                fe256_mont_mul(&t, &t, a);
            }
            w <<= 1;
        }
    }
    
    fe256_copy(r, &t);
}

/**
 * @brief SM2 p - 2 constant for Fermat inversion
 */
static constexpr fe256 SM2_P_MINUS_2 = {{
    0xFFFFFFFFFFFFFFFDULL,  // p[0] - 2
    0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL
}};

/**
 * @brief Montgomery inversion using optimized addition chain
 * 
 * Computes a^(-1) = a^(p-2) mod p using Fermat's little theorem
 * with optimized addition chain (reference: GmSSL sm2_z256_modp_mont_inv)
 * 
 * @param r Result (in Montgomery form)
 * @param a Input (in Montgomery form, must be non-zero)
 */
void fe256_mont_inv(fe256* r, const fe256* a) {
    fe256 a1, a2, a3, a4, a5;
    int i;
    
    // Build small powers using addition chain
    fe256_mont_sqr(&a1, a);           // a^2
    fe256_mont_mul(&a2, &a1, a);      // a^3
    fe256_mont_sqr(&a3, &a2);
    fe256_mont_sqr(&a3, &a3);         // a^12
    fe256_mont_mul(&a3, &a3, &a2);    // a^15
    fe256_mont_sqr(&a4, &a3);
    fe256_mont_sqr(&a4, &a4);
    fe256_mont_sqr(&a4, &a4);
    fe256_mont_sqr(&a4, &a4);         // a^240
    fe256_mont_mul(&a4, &a4, &a3);    // a^255
    
    // a5 = a^(2^8 - 1) = a^255
    fe256_mont_sqr(&a5, &a4);
    for (i = 1; i < 8; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a5, &a5, &a4);    // a^(2^16 - 1)
    
    for (i = 0; i < 8; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a5, &a5, &a4);    // a^(2^24 - 1)
    
    for (i = 0; i < 4; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a5, &a5, &a3);    // a^(2^28 - 1)
    
    fe256_mont_sqr(&a5, &a5);
    fe256_mont_sqr(&a5, &a5);
    fe256_mont_mul(&a5, &a5, &a2);    // a^(2^30 - 1)
    
    fe256_mont_sqr(&a5, &a5);
    fe256_mont_mul(&a5, &a5, a);      // a^(2^31 - 1)
    
    // Continue building the exponent p-2
    fe256_mont_sqr(&a4, &a5);
    fe256_mont_mul(&a3, &a4, &a1);
    fe256_mont_sqr(&a5, &a4);
    for (i = 1; i < 31; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a4, &a5, &a4);
    fe256_mont_sqr(&a4, &a4);
    fe256_mont_mul(&a4, &a4, a);
    fe256_mont_mul(&a3, &a4, &a2);
    
    for (i = 0; i < 33; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a2, &a5, &a3);
    fe256_mont_mul(&a3, &a2, &a3);
    
    for (i = 0; i < 32; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a2, &a5, &a3);
    fe256_mont_mul(&a3, &a2, &a3);
    fe256_mont_mul(&a4, &a2, &a4);
    
    for (i = 0; i < 32; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a2, &a5, &a3);
    fe256_mont_mul(&a3, &a2, &a3);
    fe256_mont_mul(&a4, &a2, &a4);
    
    for (i = 0; i < 32; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a2, &a5, &a3);
    fe256_mont_mul(&a3, &a2, &a3);
    fe256_mont_mul(&a4, &a2, &a4);
    
    for (i = 0; i < 32; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(&a2, &a5, &a3);
    fe256_mont_mul(&a3, &a2, &a3);
    fe256_mont_mul(&a4, &a2, &a4);
    
    for (i = 0; i < 32; i++) {
        fe256_mont_sqr(&a5, &a5);
    }
    fe256_mont_mul(r, &a4, &a5);
}

/**
 * @brief Square root in Montgomery form: r = sqrt(a) mod p
 * 
 * For SM2 prime p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) mod p
 * 
 * @param r Result (in Montgomery form)
 * @param a Input (in Montgomery form)
 * @return 1 if square root exists, 0 otherwise
 */
int fe256_mont_sqrt(fe256* r, const fe256* a) {
    // (p+1)/4 = 0x3fffffffbfffffffffffffffffffffffffffffffc00000004000000000000000
    static constexpr fe256 SM2_SQRT_EXP = {{
        0x4000000000000000ULL,
        0xFFFFFFFFC0000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x3FFFFFFFBFFFFFFFULL
    }};
    
    fe256 result, check;
    
    // r = a^((p+1)/4)
    fe256_mont_exp(&result, a, &SM2_SQRT_EXP);
    
    // Verify: r^2 == a
    fe256_mont_sqr(&check, &result);
    
    if (fe256_cmp(&check, a) != 0) {
        return 0;  // No square root
    }
    
    fe256_copy(r, &result);
    return 1;
}

// ============================================================================
// Byte conversion
// ============================================================================

/**
 * @brief Convert big-endian bytes to fe256
 */
void fe256_from_bytes(fe256* r, const uint8_t bytes[32]) {
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

/**
 * @brief Convert fe256 to big-endian bytes
 */
void fe256_to_bytes(uint8_t bytes[32], const fe256* a) {
    for (int i = 0; i < 8; i++) {
        bytes[i]      = (uint8_t)(a->limb[3] >> (56 - 8*i));
        bytes[i + 8]  = (uint8_t)(a->limb[2] >> (56 - 8*i));
        bytes[i + 16] = (uint8_t)(a->limb[1] >> (56 - 8*i));
        bytes[i + 24] = (uint8_t)(a->limb[0] >> (56 - 8*i));
    }
}

// ============================================================================
// SM2 Order (n) Montgomery Operations
// ============================================================================

/**
 * @brief SM2 curve order n
 * n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
 */
static constexpr fe256 SM2_N = {{
    0x53BBF40939D54123ULL,
    0x7203DF6B21C6052BULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL
}};

/**
 * @brief 2^256 - n (used as MONT_ONE for order n)
 */
static constexpr fe256 SM2_NEG_N = {{
    0xAC440BF6C62ABEDDULL,
    0x8DFC2094DE39FAD4ULL,
    0x0000000000000000ULL,
    0x0000000100000000ULL
}};

/**
 * @brief n' = -n^(-1) mod 2^256
 */
static constexpr fe256 SM2_N_PRIME = {{
    0x327F9E8872350975ULL,
    0xDF1E8D34FC8319A5ULL,
    0x2B0068D3B08941D4ULL,
    0x6F39132F82E4C7BCULL
}};

/**
 * @brief Modular addition mod n: r = (a + b) mod n
 */
void fe256_modn_add(fe256* r, const fe256* a, const fe256* b) {
    uint64_t carry = fe256_add(r, a, b);
    
    if (carry) {
        fe256_add(r, r, &SM2_NEG_N);
        return;
    }
    
    if (fe256_cmp(r, &SM2_N) >= 0) {
        fe256_sub(r, r, &SM2_N);
    }
}

/**
 * @brief Modular subtraction mod n: r = (a - b) mod n
 */
void fe256_modn_sub(fe256* r, const fe256* a, const fe256* b) {
    uint64_t borrow = fe256_sub(r, a, b);
    
    if (borrow) {
        fe256_sub(r, r, &SM2_NEG_N);
    }
}

/**
 * @brief Modular negation mod n: r = -a mod n = n - a
 */
void fe256_modn_neg(fe256* r, const fe256* a) {
    fe256_sub(r, &SM2_N, a);
}

/**
 * @brief Montgomery multiplication mod n: r = a * b * R^(-1) mod n
 */
void fe256_modn_mont_mul(fe256* r, const fe256* a, const fe256* b) {
    fe512 z, t, tmp;
    uint64_t c;
    
    // z = a * b
    fe256_mul_512(&z, a, b);
    
    // t = low(z) * n'
    fe256 z_low;
    z_low.limb[0] = z.limb[0];
    z_low.limb[1] = z.limb[1];
    z_low.limb[2] = z.limb[2];
    z_low.limb[3] = z.limb[3];
    fe256_mul_512(&t, &z_low, &SM2_N_PRIME);
    
    // t = low(t) * n
    fe256 t_low;
    t_low.limb[0] = t.limb[0];
    t_low.limb[1] = t.limb[1];
    t_low.limb[2] = t.limb[2];
    t_low.limb[3] = t.limb[3];
    fe256_mul_512(&t, &t_low, &SM2_N);
    
    // tmp = z + t
    c = 0;
    for (int i = 0; i < 8; i++) {
        tmp.limb[i] = adc64(z.limb[i], t.limb[i], c, &c);
    }
    
    // r = high(tmp)
    r->limb[0] = tmp.limb[4];
    r->limb[1] = tmp.limb[5];
    r->limb[2] = tmp.limb[6];
    r->limb[3] = tmp.limb[7];
    
    // Final reduction
    if (c) {
        fe256_add(r, r, &SM2_NEG_N);
    } else if (fe256_cmp(r, &SM2_N) >= 0) {
        fe256_sub(r, r, &SM2_N);
    }
}

}  // namespace kctsb::internal::sm2::mont
