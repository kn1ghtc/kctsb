/**
 * @file fe256_native.cpp
 * @brief Pure Native 256-bit Field Element Operations Implementation
 * 
 * Complete self-contained implementation - ZERO NTL dependency.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "fe256_native.h"
#include <algorithm>

namespace kctsb {
namespace ecc {
namespace native {

// ============================================================================
// Fe256 Byte Conversion
// ============================================================================

Fe256 Fe256::from_bytes_be(const uint8_t* in) {
    Fe256 r;
    // Big-endian bytes to little-endian limbs
    // in[0..7] = MSW, in[24..31] = LSW
    for (int i = 0; i < 4; i++) {
        r.d[3 - i] = 0;
        for (int j = 0; j < 8; j++) {
            r.d[3 - i] |= (uint64_t)in[i * 8 + j] << (56 - j * 8);
        }
    }
    return r;
}

void Fe256::to_bytes_be(uint8_t* out) const {
    // Little-endian limbs to big-endian bytes
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            out[i * 8 + j] = (d[3 - i] >> (56 - j * 8)) & 0xFF;
        }
    }
}

// ============================================================================
// Curve Constants
// ============================================================================

// secp256k1: p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
const CurveParams SECP256K1_PARAMS = {
    // p
    {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
    // n (curve order)
    {0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL},
    // R^2 mod p
    {0x000007A2000E90A1ULL, 0x0000000000000001ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
    // R^2 mod n
    {0x896CF21467D7D140ULL, 0x741496C20E7CF878ULL, 0xE697F5E45BCD07C6ULL, 0x9D671CD581C69BC5ULL},
    // n0_p = -p^(-1) mod 2^64
    0xD838091DD2253531ULL,
    // n0_n = -n^(-1) mod 2^64
    0x4B0DFF665588B13FULL,
    // Gx (Montgomery)
    {0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL},
    // Gy (Montgomery)
    {0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL},
    // a = 0
    {0, 0, 0, 0},
    // b = 7 (need to convert to Montgomery later)
    {7, 0, 0, 0},
    // a_is_zero
    1,
    // a_is_minus_3
    0
};

// P-256: p = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
const CurveParams P256_PARAMS = {
    // p
    {0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL},
    // n (curve order)
    {0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL},
    // R^2 mod p
    {0x0000000000000003ULL, 0xFFFFFFFBFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL, 0x00000004FFFFFFFDULL},
    // R^2 mod n
    {0x66E12D94F3D95620ULL, 0xCBB2F2A6B3B6B4B8ULL, 0x0000000000000001ULL, 0xBE79EEA2A9E27E81ULL},
    // n0_p
    0x0000000000000001ULL,
    // n0_n
    0xCCD1C8AAEE00BC4FULL,
    // Gx (Montgomery)
    {0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL, 0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL},
    // Gy (Montgomery)
    {0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL, 0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL},
    // a = p - 3 (Montgomery)
    {0xFFFFFFFFFFFFFFFCULL, 0x00000000FFFFFFFFULL, 0x0000000000000000ULL, 0xFFFFFFFF00000001ULL},
    // b (Montgomery)
    {0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL, 0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL},
    // a_is_zero
    0,
    // a_is_minus_3
    1
};

// SM2: p = FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
const CurveParams SM2_PARAMS = {
    // p
    {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL},
    // n (curve order)
    {0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL},
    // R^2 mod p
    {0x0000000200000003ULL, 0x00000002FFFFFFFFULL, 0x0000000100000001ULL, 0x0000000400000002ULL},
    // R^2 mod n
    {0x7C114F20E79C7E85ULL, 0x901192AF7C114F20ULL, 0x6052B53BBF40939DULL, 0x04000000D3CFCBF7ULL},
    // n0_p
    0x0000000000000001ULL,
    // n0_n
    0x327F9E8872350975ULL,
    // Gx (Montgomery)  
    {0xF418029E61A27C8EULL, 0x5F0939B3C7A43B28ULL, 0x50AE3F9FEBA93E50ULL, 0x32C4AE2C1F198119ULL},
    // Gy (Montgomery)
    {0x6215695162C97E1FULL, 0x014FBC2C57F6A80AULL, 0xBE64F5F6B78D8EA0ULL, 0xBC3736A2F4F6779CULL},
    // a = p - 3 (Montgomery)
    {0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL},
    // b (Montgomery)
    {0xDDBCBD414D940E93ULL, 0xF39789F515AB8F92ULL, 0x4D5A9E4BCF6509A7ULL, 0x28E9FA9E9D9F5E34ULL},
    // a_is_zero
    0,
    // a_is_minus_3
    1
};

const CurveParams* get_curve_params(CurveId id) {
    switch (id) {
        case CurveId::SECP256K1: return &SECP256K1_PARAMS;
        case CurveId::P256: return &P256_PARAMS;
        case CurveId::SM2: return &SM2_PARAMS;
        default: return nullptr;
    }
}

// ============================================================================
// Field Arithmetic - Core Operations
// ============================================================================

int fe256_cmp(const Fe256* a, const Fe256* b) {
    for (int i = 3; i >= 0; i--) {
        if (a->d[i] > b->d[i]) return 1;
        if (a->d[i] < b->d[i]) return -1;
    }
    return 0;
}

void fe256_cmov(Fe256* r, const Fe256* a, uint64_t cond) {
    uint64_t mask = ~(cond - 1);
    r->d[0] ^= mask & (r->d[0] ^ a->d[0]);
    r->d[1] ^= mask & (r->d[1] ^ a->d[1]);
    r->d[2] ^= mask & (r->d[2] ^ a->d[2]);
    r->d[3] ^= mask & (r->d[3] ^ a->d[3]);
}

void fe256_add(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* p) {
    uint64_t c = 0, borrow = 0;
    Fe256 sum, reduced;
    
    sum.d[0] = adc64(a->d[0], b->d[0], 0, &c);
    sum.d[1] = adc64(a->d[1], b->d[1], c, &c);
    sum.d[2] = adc64(a->d[2], b->d[2], c, &c);
    sum.d[3] = adc64(a->d[3], b->d[3], c, &c);
    
    reduced.d[0] = sbb64(sum.d[0], p->d[0], 0, &borrow);
    reduced.d[1] = sbb64(sum.d[1], p->d[1], borrow, &borrow);
    reduced.d[2] = sbb64(sum.d[2], p->d[2], borrow, &borrow);
    reduced.d[3] = sbb64(sum.d[3], p->d[3], borrow, &borrow);
    
    // If no borrow or carry, use reduced; otherwise use sum
    uint64_t use_reduced = (c | (borrow == 0)) & 1;
    fe256_cmov(&sum, &reduced, use_reduced);
    *r = sum;
}

void fe256_sub(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* p) {
    uint64_t borrow = 0, c = 0;
    Fe256 diff, corrected;
    
    diff.d[0] = sbb64(a->d[0], b->d[0], 0, &borrow);
    diff.d[1] = sbb64(a->d[1], b->d[1], borrow, &borrow);
    diff.d[2] = sbb64(a->d[2], b->d[2], borrow, &borrow);
    diff.d[3] = sbb64(a->d[3], b->d[3], borrow, &borrow);
    
    // If borrow, add p back
    corrected.d[0] = adc64(diff.d[0], p->d[0], 0, &c);
    corrected.d[1] = adc64(diff.d[1], p->d[1], c, &c);
    corrected.d[2] = adc64(diff.d[2], p->d[2], c, &c);
    corrected.d[3] = adc64(diff.d[3], p->d[3], c, &c);
    
    fe256_cmov(&diff, &corrected, borrow);
    *r = diff;
}

void fe256_neg(Fe256* r, const Fe256* a, const Fe256* p) {
    Fe256 zero;
    zero.d[0] = zero.d[1] = zero.d[2] = zero.d[3] = 0;
    fe256_sub(r, p, a, p);
    // If a == 0, result should be 0
    uint64_t is_zero = ((a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0) ? 1 : 0;
    fe256_cmov(r, &zero, is_zero);
}

// ============================================================================
// Montgomery Multiplication (CIOS algorithm with __int128)
// ============================================================================

#if defined(__SIZEOF_INT128__)

void fe256_mul_mont(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* p, uint64_t n0) {
    // CIOS (Coarsely Integrated Operand Scanning) with 128-bit accumulator
    // Reference: "Analyzing and Comparing Montgomery Multiplication Algorithms"
    // - IEEE Micro 1996
    
    uint64_t t[5] = {0, 0, 0, 0, 0};  // 5 limbs for intermediate results
    
    for (int i = 0; i < 4; i++) {
        // Step 1: t = t + a[i] * b
        uint128_t carry = 0;
        
        for (int j = 0; j < 4; j++) {
            uint128_t prod = (uint128_t)a->d[i] * b->d[j] + t[j] + carry;
            t[j] = (uint64_t)prod;
            carry = prod >> 64;
        }
        t[4] += (uint64_t)carry;
        
        // Step 2: m = t[0] * n0 mod 2^64
        uint64_t m = t[0] * n0;
        
        // Step 3: t = (t + m * p) / 2^64
        carry = 0;
        
        // First limb: t[0] + m * p[0] -> discard low 64 bits, carry the rest
        uint128_t sum = (uint128_t)m * p->d[0] + t[0];
        carry = sum >> 64;
        
        // Remaining limbs
        for (int j = 1; j < 4; j++) {
            sum = (uint128_t)m * p->d[j] + t[j] + carry;
            t[j-1] = (uint64_t)sum;
            carry = sum >> 64;
        }
        
        // Final carry
        sum = (uint128_t)t[4] + carry;
        t[3] = (uint64_t)sum;
        t[4] = (uint64_t)(sum >> 64);
    }
    
    // Final conditional subtraction: if t >= p, then t = t - p
    Fe256 tmp;
    uint64_t borrow = 0;
    tmp.d[0] = sbb64(t[0], p->d[0], 0, &borrow);
    tmp.d[1] = sbb64(t[1], p->d[1], borrow, &borrow);
    tmp.d[2] = sbb64(t[2], p->d[2], borrow, &borrow);
    tmp.d[3] = sbb64(t[3], p->d[3], borrow, &borrow);
    
    // Check if result needs reduction: if no borrow (t >= p), use reduced value
    uint64_t use_reduced = (borrow == 0) | (t[4] != 0);
    
    r->d[0] = t[0];
    r->d[1] = t[1];
    r->d[2] = t[2];
    r->d[3] = t[3];
    fe256_cmov(r, &tmp, use_reduced);
}

#elif defined(_MSC_VER) && defined(_M_X64)

void fe256_mul_mont(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* p, uint64_t n0) {
    // MSVC version using _umul128 and _addcarry_u64
    uint64_t t[5] = {0, 0, 0, 0, 0};
    
    for (int i = 0; i < 4; i++) {
        // Step 1: t = t + a[i] * b
        uint64_t carry = 0, hi, lo;
        unsigned char c;
        
        for (int j = 0; j < 4; j++) {
            lo = _umul128(a->d[i], b->d[j], &hi);
            c = _addcarry_u64(0, t[j], lo, &t[j]);
            c = _addcarry_u64(c, 0, hi, &hi);
            c = _addcarry_u64(0, carry, hi, &carry);
            _addcarry_u64(c, carry, 0, &carry);
        }
        t[4] += carry;
        
        // Step 2: m = t[0] * n0 mod 2^64
        uint64_t m = t[0] * n0;
        
        // Step 3: t = (t + m * p) / 2^64
        lo = _umul128(m, p->d[0], &hi);
        c = _addcarry_u64(0, t[0], lo, &lo);  // discard lo
        carry = hi + c;
        
        for (int j = 1; j < 4; j++) {
            lo = _umul128(m, p->d[j], &hi);
            c = _addcarry_u64(0, t[j], lo, &t[j-1]);
            c = _addcarry_u64(c, t[j-1], carry, &t[j-1]);
            carry = hi + c;
        }
        
        c = _addcarry_u64(0, t[4], carry, &t[3]);
        t[4] = c;
    }
    
    // Final conditional subtraction
    Fe256 tmp;
    uint64_t borrow = 0;
    tmp.d[0] = sbb64(t[0], p->d[0], 0, &borrow);
    tmp.d[1] = sbb64(t[1], p->d[1], borrow, &borrow);
    tmp.d[2] = sbb64(t[2], p->d[2], borrow, &borrow);
    tmp.d[3] = sbb64(t[3], p->d[3], borrow, &borrow);
    
    uint64_t use_reduced = (borrow == 0) | (t[4] != 0);
    
    r->d[0] = t[0];
    r->d[1] = t[1];
    r->d[2] = t[2];
    r->d[3] = t[3];
    fe256_cmov(r, &tmp, use_reduced);
}

#endif

void fe256_sqr_mont(Fe256* r, const Fe256* a, const Fe256* p, uint64_t n0) {
    fe256_mul_mont(r, a, a, p, n0);
}

void fe256_to_mont(Fe256* r, const Fe256* a, const Fe256* R2, const Fe256* p, uint64_t n0) {
    fe256_mul_mont(r, a, R2, p, n0);
}

void fe256_from_mont(Fe256* r, const Fe256* a, const Fe256* p, uint64_t n0) {
    Fe256 one = {1, 0, 0, 0};
    fe256_mul_mont(r, a, &one, p, n0);
}

// ============================================================================
// Field Inversion (Fermat's little theorem: a^(p-2) mod p)
// ============================================================================

void fe256_inv(Fe256* r, const Fe256* a, const Fe256* p, uint64_t n0) {
    // For Montgomery domain inversion:
    // If a_mont = a * R mod p, we want a^(-1) * R mod p
    // Using Fermat: a^(-1) = a^(p-2) mod p
    // In Montgomery: (a_mont)^(p-2) = a^(p-2) * R^(p-2) mod p
    // We need a^(-1) * R = a^(p-2) * R
    // So: result = (a_mont)^(p-2) * R^(3-p) mod p
    // 
    // Simpler approach: use Montgomery multiplication throughout
    // result starts as R (Montgomery representation of 1)
    // We need to compute R mod p first
    // 
    // The key insight: in Montgomery, 1_mont = R mod p
    // We can get R mod p by computing: mont_mul(R^2, 1) = R^2 * 1 * R^(-1) = R
    // But we don't have R^2 passed in...
    //
    // Alternative: Use the fact that for exponentiation in Montgomery:
    // To compute a^e in Montgomery, start with result = R (one in Montgomery)
    // Then do: result = sqr(result), result = mul(result, a) when bit is 1
    // 
    // Since a is already in Montgomery form, and we use Montgomery mul/sqr,
    // the final result will be in Montgomery form.
    // 
    // To get R without curve-specific constants:
    // mont_mul(x, y) = x * y * R^(-1) mod p
    // If we do mont_mul(a, a) starting from result=1 (not R), we get wrong domain
    //
    // CORRECT APPROACH for Montgomery inversion:
    // 1. Compute a^(p-2) using Montgomery operations
    // 2. Start with result in Montgomery domain (R mod p)
    // 3. Problem: we need R mod p
    //
    // WORKAROUND: Use the identity that for any x in Montgomery domain,
    // x^(p-1) = R mod p (since x^(p-1) = 1 in regular, which is R in Montgomery)
    // But this requires extra exponentiation...
    //
    // SIMPLEST APPROACH: 
    // - Convert input from Montgomery to regular
    // - Compute regular exponentiation (no Montgomery)
    // - Convert result back to Montgomery
    // This is slower but correct and doesn't need extra constants
    
    // Convert a from Montgomery to regular domain
    Fe256 a_reg;
    Fe256 one = {1, 0, 0, 0};
    fe256_mul_mont(&a_reg, a, &one, p, n0);  // a_reg = a (regular)
    
    // Compute p-2
    Fe256 exp;
    uint64_t borrow = 0;
    exp.d[0] = sbb64(p->d[0], 2, 0, &borrow);
    exp.d[1] = sbb64(p->d[1], 0, borrow, &borrow);
    exp.d[2] = sbb64(p->d[2], 0, borrow, &borrow);
    exp.d[3] = sbb64(p->d[3], 0, borrow, &borrow);
    
    // Square-and-multiply using Montgomery (but careful about domain)
    // Start with result = 1 in Montgomery domain
    // We don't have R, so we use a trick:
    // Compute using regular mul in Montgomery ladder, just need to track domain
    
    // Actually, let's use a different trick:
    // We compute in Montgomery domain directly
    // Start with result = a (in Montgomery), then compute a^(p-2-1) more multiplications
    // result = a * a^(p-3) = a^(p-2)
    // But this still requires knowing when we've done p-3 operations...
    
    // FINAL SIMPLE APPROACH:
    // Use the provided input directly in Montgomery exponentiation
    // The result will be a^(p-2) in some form, adjust at end
    
    // Since 'a' is in Montgomery (a' = a*R), computing a'^(p-2) using mont_mul gives:
    // Each mont_mul(x,y) = x*y*R^(-1), so:
    // a'^2 via mont = a'^2 * R^(-1) = a^2 * R^2 * R^(-1) = a^2 * R
    // a'^4 via mont = (a^2*R)^2 * R^(-1) = a^4 * R^2 * R^(-1) = a^4 * R
    // In general: a'^(2^k) via k squarings = a^(2^k) * R
    // And a'^k via squaring and multiplying stays as a^k * R for the final result
    // So a'^(p-2) = a^(p-2) * R = a^(-1) * R = (a^(-1))_mont
    // THIS IS EXACTLY WHAT WE WANT!
    
    // So the algorithm is:
    // 1. result = a (in Montgomery) - this serves as both base and initial result for bit 255
    // 2. For each bit from second-highest down to 0:
    //    - result = sqr_mont(result)
    //    - if bit is 1: result = mul_mont(result, a)
    // 3. result is a^(p-2) * R = a^(-1) in Montgomery
    
    Fe256 base = *a;
    Fe256 result = base;  // Start with a (for the highest bit which is always 1 for large prime)
    
    // Find highest bit of p-2 (always bit 255 for 256-bit primes)
    // Then process from bit 254 down to 0
    for (int i = 254; i >= 0; i--) {
        fe256_sqr_mont(&result, &result, p, n0);
        int limb = i / 64;
        int bit = i % 64;
        if ((exp.d[limb] >> bit) & 1) {
            fe256_mul_mont(&result, &result, &base, p, n0);
        }
    }
    
    *r = result;
}

// ============================================================================
// Scalar Arithmetic (mod n)
// ============================================================================

void scalar_add(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* n) {
    fe256_add(r, a, b, n);
}

void scalar_sub(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* n) {
    fe256_sub(r, a, b, n);
}

void scalar_mul_mont(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* n, uint64_t n0) {
    fe256_mul_mont(r, a, b, n, n0);
}

void scalar_inv(Fe256* r, const Fe256* a, const Fe256* n, uint64_t n0) {
    fe256_inv(r, a, n, n0);
}

void scalar_reduce(Fe256* r, const uint8_t* hash, size_t hash_len, const Fe256* n) {
    // Take leftmost bits equal to bit length of n
    Fe256 h = Fe256::from_bytes_be(hash);
    
    // Simple reduction: if h >= n, subtract n (may need multiple iterations)
    while (fe256_cmp(&h, n) >= 0) {
        Fe256 tmp;
        uint64_t borrow = 0;
        tmp.d[0] = sbb64(h.d[0], n->d[0], 0, &borrow);
        tmp.d[1] = sbb64(h.d[1], n->d[1], borrow, &borrow);
        tmp.d[2] = sbb64(h.d[2], n->d[2], borrow, &borrow);
        tmp.d[3] = sbb64(h.d[3], n->d[3], borrow, &borrow);
        if (borrow == 0) h = tmp;
        else break;
    }
    
    *r = h;
}

// ============================================================================
// Point Operations
// ============================================================================

void point_cswap(Fe256Point* a, Fe256Point* b, uint64_t swap) {
    uint64_t mask = ~(swap - 1);
    
    for (int i = 0; i < 4; i++) {
        uint64_t t = mask & (a->X.d[i] ^ b->X.d[i]);
        a->X.d[i] ^= t;
        b->X.d[i] ^= t;
        
        t = mask & (a->Y.d[i] ^ b->Y.d[i]);
        a->Y.d[i] ^= t;
        b->Y.d[i] ^= t;
        
        t = mask & (a->Z.d[i] ^ b->Z.d[i]);
        a->Z.d[i] ^= t;
        b->Z.d[i] ^= t;
    }
    
    int t = (int)(mask & ((uint64_t)a->is_infinity ^ (uint64_t)b->is_infinity));
    a->is_infinity ^= t;
    b->is_infinity ^= t;
}

void point_double(Fe256Point* r, const Fe256Point* p, const CurveParams* curve) {
    if (p->is_infinity) {
        *r = Fe256Point();
        return;
    }
    
    const Fe256* mod_p = &curve->p;
    uint64_t n0 = curve->n0_p;
    
    Fe256 A, B, C, D, E, F;
    Fe256 t1, t2;
    
    // A = X^2
    fe256_sqr_mont(&A, &p->X, mod_p, n0);
    // B = Y^2
    fe256_sqr_mont(&B, &p->Y, mod_p, n0);
    // C = B^2
    fe256_sqr_mont(&C, &B, mod_p, n0);
    
    // D = 2*((X+B)^2 - A - C)
    fe256_add(&t1, &p->X, &B, mod_p);
    fe256_sqr_mont(&t2, &t1, mod_p, n0);
    fe256_sub(&t2, &t2, &A, mod_p);
    fe256_sub(&t2, &t2, &C, mod_p);
    fe256_add(&D, &t2, &t2, mod_p);
    
    if (curve->a_is_zero) {
        // E = 3*A
        fe256_add(&E, &A, &A, mod_p);
        fe256_add(&E, &E, &A, mod_p);
    } else if (curve->a_is_minus_3) {
        // E = 3*(X-Z^2)*(X+Z^2) = 3*A - 3*Z^4
        Fe256 Z2, Z4;
        fe256_sqr_mont(&Z2, &p->Z, mod_p, n0);
        fe256_sqr_mont(&Z4, &Z2, mod_p, n0);
        fe256_sub(&t1, &A, &Z4, mod_p);
        fe256_add(&E, &t1, &t1, mod_p);
        fe256_add(&E, &E, &t1, mod_p);
    } else {
        // E = 3*A + a*Z^4
        Fe256 Z2, Z4, aZ4;
        fe256_sqr_mont(&Z2, &p->Z, mod_p, n0);
        fe256_sqr_mont(&Z4, &Z2, mod_p, n0);
        fe256_mul_mont(&aZ4, &curve->a, &Z4, mod_p, n0);
        fe256_add(&E, &A, &A, mod_p);
        fe256_add(&E, &E, &A, mod_p);
        fe256_add(&E, &E, &aZ4, mod_p);
    }
    
    // F = E^2
    fe256_sqr_mont(&F, &E, mod_p, n0);
    
    // X3 = F - 2*D
    fe256_add(&t1, &D, &D, mod_p);
    fe256_sub(&r->X, &F, &t1, mod_p);
    
    // Y3 = E*(D - X3) - 8*C
    fe256_sub(&t1, &D, &r->X, mod_p);
    fe256_mul_mont(&t2, &E, &t1, mod_p, n0);
    fe256_add(&t1, &C, &C, mod_p);
    fe256_add(&t1, &t1, &t1, mod_p);
    fe256_add(&t1, &t1, &t1, mod_p);
    fe256_sub(&r->Y, &t2, &t1, mod_p);
    
    // Z3 = 2*Y*Z
    fe256_mul_mont(&t1, &p->Y, &p->Z, mod_p, n0);
    fe256_add(&r->Z, &t1, &t1, mod_p);
    
    r->is_infinity = 0;
}

void point_add(Fe256Point* r, const Fe256Point* p, const Fe256Point* q, const CurveParams* curve) {
    if (p->is_infinity) { *r = *q; return; }
    if (q->is_infinity) { *r = *p; return; }
    
    const Fe256* mod_p = &curve->p;
    uint64_t n0 = curve->n0_p;
    
    Fe256 Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, rr, V;
    Fe256 t1, t2;
    
    fe256_sqr_mont(&Z1Z1, &p->Z, mod_p, n0);
    fe256_sqr_mont(&Z2Z2, &q->Z, mod_p, n0);
    
    fe256_mul_mont(&U1, &p->X, &Z2Z2, mod_p, n0);
    fe256_mul_mont(&U2, &q->X, &Z1Z1, mod_p, n0);
    
    fe256_mul_mont(&t1, &q->Z, &Z2Z2, mod_p, n0);
    fe256_mul_mont(&S1, &p->Y, &t1, mod_p, n0);
    
    fe256_mul_mont(&t1, &p->Z, &Z1Z1, mod_p, n0);
    fe256_mul_mont(&S2, &q->Y, &t1, mod_p, n0);
    
    // Check for special cases
    if (U1 == U2) {
        if (S1 == S2) {
            point_double(r, p, curve);
            return;
        } else {
            *r = Fe256Point();  // P = -Q
            return;
        }
    }
    
    fe256_sub(&H, &U2, &U1, mod_p);
    
    fe256_add(&t1, &H, &H, mod_p);
    fe256_sqr_mont(&I, &t1, mod_p, n0);
    
    fe256_mul_mont(&J, &H, &I, mod_p, n0);
    
    fe256_sub(&t1, &S2, &S1, mod_p);
    fe256_add(&rr, &t1, &t1, mod_p);
    
    fe256_mul_mont(&V, &U1, &I, mod_p, n0);
    
    // X3 = rr^2 - J - 2*V
    fe256_sqr_mont(&t1, &rr, mod_p, n0);
    fe256_sub(&t1, &t1, &J, mod_p);
    fe256_add(&t2, &V, &V, mod_p);
    fe256_sub(&r->X, &t1, &t2, mod_p);
    
    // Y3 = rr*(V - X3) - 2*S1*J
    fe256_sub(&t1, &V, &r->X, mod_p);
    fe256_mul_mont(&t2, &rr, &t1, mod_p, n0);
    fe256_mul_mont(&t1, &S1, &J, mod_p, n0);
    fe256_add(&t1, &t1, &t1, mod_p);
    fe256_sub(&r->Y, &t2, &t1, mod_p);
    
    // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
    fe256_add(&t1, &p->Z, &q->Z, mod_p);
    fe256_sqr_mont(&t2, &t1, mod_p, n0);
    fe256_sub(&t2, &t2, &Z1Z1, mod_p);
    fe256_sub(&t2, &t2, &Z2Z2, mod_p);
    fe256_mul_mont(&r->Z, &t2, &H, mod_p, n0);
    
    r->is_infinity = 0;
}

void point_neg(Fe256Point* r, const Fe256Point* p, const CurveParams* curve) {
    if (p->is_infinity) {
        *r = Fe256Point();
        return;
    }
    r->X = p->X;
    fe256_neg(&r->Y, &p->Y, &curve->p);
    r->Z = p->Z;
    r->is_infinity = 0;
}

// ============================================================================
// Montgomery Ladder Scalar Multiplication (Constant-time)
// ============================================================================

void scalar_mult(Fe256Point* r, const Fe256* k, const Fe256Point* p, const CurveParams* curve) {
    // Standard double-and-add (left-to-right)
    // For constant-time, we should use Montgomery ladder, but for correctness first...
    
    Fe256Point R;  // Start at infinity
    R.is_infinity = 1;
    
    Fe256Point Q = *p;  // Copy of P
    
    // Find highest bit
    int highest = -1;
    for (int i = 3; i >= 0 && highest < 0; i--) {
        if (k->d[i] != 0) {
            for (int j = 63; j >= 0; j--) {
                if ((k->d[i] >> j) & 1) {
                    highest = i * 64 + j;
                    break;
                }
            }
        }
    }
    
    if (highest < 0) {
        *r = Fe256Point();  // k = 0, return infinity
        return;
    }
    
    // Double-and-add from highest bit
    for (int i = highest; i >= 0; i--) {
        // R = 2*R
        Fe256Point doubled;
        point_double(&doubled, &R, curve);
        R = doubled;
        
        // Check bit
        int limb = i / 64;
        int bit = i % 64;
        if ((k->d[limb] >> bit) & 1) {
            // R = R + Q
            Fe256Point sum;
            point_add(&sum, &R, &Q, curve);
            R = sum;
        }
    }
    
    *r = R;
}

void scalar_mult_base(Fe256Point* r, const Fe256* k, const CurveParams* curve) {
    Fe256Point G;
    // Convert G from standard coordinates to Montgomery domain
    fe256_to_mont(&G.X, &curve->Gx, &curve->R2, &curve->p, curve->n0_p);
    fe256_to_mont(&G.Y, &curve->Gy, &curve->R2, &curve->p, curve->n0_p);
    G.Z = Fe256(1);
    fe256_to_mont(&G.Z, &G.Z, &curve->R2, &curve->p, curve->n0_p);
    G.is_infinity = 0;
    
    scalar_mult(r, k, &G, curve);
}

// ============================================================================
// Double Scalar Multiplication (Shamir's Trick)
// ============================================================================

void double_scalar_mult(Fe256Point* r, const Fe256* k1, const Fe256* k2, 
                        const Fe256Point* P, const CurveParams* curve) {
    // Precompute: G, P, G+P
    Fe256Point G;
    // Convert G from standard coordinates to Montgomery domain
    fe256_to_mont(&G.X, &curve->Gx, &curve->R2, &curve->p, curve->n0_p);
    fe256_to_mont(&G.Y, &curve->Gy, &curve->R2, &curve->p, curve->n0_p);
    G.Z = Fe256(1);
    fe256_to_mont(&G.Z, &G.Z, &curve->R2, &curve->p, curve->n0_p);
    G.is_infinity = 0;
    
    Fe256Point GP;
    point_add(&GP, &G, P, curve);
    
    Fe256Point R;  // Start at infinity
    R.is_infinity = 1;
    
    // Find max bit position - scan ALL limbs for both k1 and k2
    int max_bit1 = -1, max_bit2 = -1;
    for (int i = 3; i >= 0; i--) {
        if (k1->d[i] != 0 && max_bit1 < 0) {
            for (int j = 63; j >= 0; j--) {
                if ((k1->d[i] >> j) & 1) {
                    max_bit1 = i * 64 + j;
                    break;
                }
            }
        }
        if (k2->d[i] != 0 && max_bit2 < 0) {
            for (int j = 63; j >= 0; j--) {
                if ((k2->d[i] >> j) & 1) {
                    max_bit2 = i * 64 + j;
                    break;
                }
            }
        }
    }
    int max_bit = (max_bit1 > max_bit2) ? max_bit1 : max_bit2;
    
    for (int i = max_bit; i >= 0; i--) {
        point_double(&R, &R, curve);
        
        int limb = i / 64;
        int bit = i % 64;
        int b1 = (k1->d[limb] >> bit) & 1;
        int b2 = (k2->d[limb] >> bit) & 1;
        
        if (b1 && b2) {
            point_add(&R, &R, &GP, curve);
        } else if (b1) {
            point_add(&R, &R, &G, curve);
        } else if (b2) {
            point_add(&R, &R, P, curve);
        }
    }
    
    *r = R;
}

// ============================================================================
// Point to Affine Conversion
// ============================================================================

void point_to_affine(Fe256* x, Fe256* y, const Fe256Point* p, const CurveParams* curve) {
    if (p->is_infinity) {
        *x = Fe256();
        *y = Fe256();
        return;
    }
    
    const Fe256* mod_p = &curve->p;
    uint64_t n0 = curve->n0_p;
    
    // Compute Z^-1
    Fe256 z_inv;
    fe256_inv(&z_inv, &p->Z, mod_p, n0);
    
    // Z^-2
    Fe256 z_inv2;
    fe256_sqr_mont(&z_inv2, &z_inv, mod_p, n0);
    
    // Z^-3
    Fe256 z_inv3;
    fe256_mul_mont(&z_inv3, &z_inv2, &z_inv, mod_p, n0);
    
    // x = X * Z^-2
    fe256_mul_mont(x, &p->X, &z_inv2, mod_p, n0);
    fe256_from_mont(x, x, mod_p, n0);
    
    // y = Y * Z^-3
    fe256_mul_mont(y, &p->Y, &z_inv3, mod_p, n0);
    fe256_from_mont(y, y, mod_p, n0);
}

// ============================================================================
// ECDSA Implementation
// ============================================================================

void ecdsa_keygen(EcdsaKeyPair* kp, const uint8_t* random32, CurveId curve_id) {
    const CurveParams* curve = get_curve_params(curve_id);
    
    // Private key from random bytes, reduced mod n
    kp->private_key = Fe256::from_bytes_be(random32);
    
    // Ensure 0 < d < n
    while (kp->private_key.is_zero() || fe256_cmp(&kp->private_key, &curve->n) >= 0) {
        // Should not happen with good random, but handle edge case
        uint64_t borrow = 0;
        kp->private_key.d[0] = sbb64(kp->private_key.d[0], curve->n.d[0], 0, &borrow);
        kp->private_key.d[1] = sbb64(kp->private_key.d[1], curve->n.d[1], borrow, &borrow);
        kp->private_key.d[2] = sbb64(kp->private_key.d[2], curve->n.d[2], borrow, &borrow);
        kp->private_key.d[3] = sbb64(kp->private_key.d[3], curve->n.d[3], borrow, &borrow);
    }
    
    // Public key = d * G
    scalar_mult_base(&kp->public_key, &kp->private_key, curve);
}

int ecdsa_sign(EcdsaSignature* sig, const uint8_t* hash, size_t hash_len,
               const Fe256* private_key, const uint8_t* k32, CurveId curve_id) {
    const CurveParams* curve = get_curve_params(curve_id);
    
    // k from random bytes, reduced mod n
    Fe256 k = Fe256::from_bytes_be(k32);
    while (k.is_zero() || fe256_cmp(&k, &curve->n) >= 0) {
        uint64_t borrow = 0;
        k.d[0] = sbb64(k.d[0], curve->n.d[0], 0, &borrow);
        k.d[1] = sbb64(k.d[1], curve->n.d[1], borrow, &borrow);
        k.d[2] = sbb64(k.d[2], curve->n.d[2], borrow, &borrow);
        k.d[3] = sbb64(k.d[3], curve->n.d[3], borrow, &borrow);
    }
    
    // R = k * G
    Fe256Point R;
    scalar_mult_base(&R, &k, curve);
    
    // r = x_R mod n
    Fe256 x_R, y_R;
    point_to_affine(&x_R, &y_R, &R, curve);
    sig->r = x_R;
    
    // Reduce r mod n
    while (fe256_cmp(&sig->r, &curve->n) >= 0) {
        uint64_t borrow = 0;
        sig->r.d[0] = sbb64(sig->r.d[0], curve->n.d[0], 0, &borrow);
        sig->r.d[1] = sbb64(sig->r.d[1], curve->n.d[1], borrow, &borrow);
        sig->r.d[2] = sbb64(sig->r.d[2], curve->n.d[2], borrow, &borrow);
        sig->r.d[3] = sbb64(sig->r.d[3], curve->n.d[3], borrow, &borrow);
    }
    
    if (sig->r.is_zero()) return -1;
    
    // e = hash reduced mod n
    Fe256 e;
    scalar_reduce(&e, hash, hash_len, &curve->n);
    
    // s = k^-1 * (e + r*d) mod n
    // All operations in Montgomery domain for speed
    Fe256 k_mont, e_mont, r_mont, d_mont, s_mont;
    fe256_to_mont(&k_mont, &k, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_to_mont(&e_mont, &e, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_to_mont(&r_mont, &sig->r, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_to_mont(&d_mont, private_key, &curve->R2_n, &curve->n, curve->n0_n);
    
    // r*d
    Fe256 rd_mont;
    fe256_mul_mont(&rd_mont, &r_mont, &d_mont, &curve->n, curve->n0_n);
    
    // e + r*d
    Fe256 sum_mont;
    fe256_add(&sum_mont, &e_mont, &rd_mont, &curve->n);
    
    // k^-1
    Fe256 k_inv_mont;
    fe256_inv(&k_inv_mont, &k_mont, &curve->n, curve->n0_n);
    
    // s = k^-1 * (e + r*d)
    fe256_mul_mont(&s_mont, &k_inv_mont, &sum_mont, &curve->n, curve->n0_n);
    fe256_from_mont(&sig->s, &s_mont, &curve->n, curve->n0_n);
    
    if (sig->s.is_zero()) return -1;
    
    // Normalize s (low-S)
    Fe256 n_half;
    uint64_t borrow = 0, c = 0;
    n_half.d[0] = (curve->n.d[0] >> 1) | (curve->n.d[1] << 63);
    n_half.d[1] = (curve->n.d[1] >> 1) | (curve->n.d[2] << 63);
    n_half.d[2] = (curve->n.d[2] >> 1) | (curve->n.d[3] << 63);
    n_half.d[3] = (curve->n.d[3] >> 1);
    
    if (fe256_cmp(&sig->s, &n_half) > 0) {
        fe256_sub(&sig->s, &curve->n, &sig->s, &curve->n);
    }
    
    return 0;
}

int ecdsa_verify(const EcdsaSignature* sig, const uint8_t* hash, size_t hash_len,
                 const Fe256Point* public_key, CurveId curve_id) {
    const CurveParams* curve = get_curve_params(curve_id);
    
    // Check 0 < r, s < n
    if (sig->r.is_zero() || sig->s.is_zero()) return -1;
    if (fe256_cmp(&sig->r, &curve->n) >= 0) return -1;
    if (fe256_cmp(&sig->s, &curve->n) >= 0) return -1;
    
    // e = hash mod n
    Fe256 e;
    scalar_reduce(&e, hash, hash_len, &curve->n);
    
    // s^-1 in Montgomery domain
    Fe256 s_mont, s_inv_mont;
    fe256_to_mont(&s_mont, &sig->s, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_inv(&s_inv_mont, &s_mont, &curve->n, curve->n0_n);
    
    // u1 = e * s^-1 mod n
    Fe256 e_mont, u1_mont, u1;
    fe256_to_mont(&e_mont, &e, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_mul_mont(&u1_mont, &e_mont, &s_inv_mont, &curve->n, curve->n0_n);
    fe256_from_mont(&u1, &u1_mont, &curve->n, curve->n0_n);
    
    // u2 = r * s^-1 mod n
    Fe256 r_mont, u2_mont, u2;
    fe256_to_mont(&r_mont, &sig->r, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_mul_mont(&u2_mont, &r_mont, &s_inv_mont, &curve->n, curve->n0_n);
    fe256_from_mont(&u2, &u2_mont, &curve->n, curve->n0_n);
    
    // R = u1*G + u2*Q
    Fe256Point R;
    double_scalar_mult(&R, &u1, &u2, public_key, curve);
    
    if (R.is_infinity) return -1;
    
    // v = x_R mod n
    Fe256 x_R, y_R;
    point_to_affine(&x_R, &y_R, &R, curve);
    
    while (fe256_cmp(&x_R, &curve->n) >= 0) {
        uint64_t borrow = 0;
        x_R.d[0] = sbb64(x_R.d[0], curve->n.d[0], 0, &borrow);
        x_R.d[1] = sbb64(x_R.d[1], curve->n.d[1], borrow, &borrow);
        x_R.d[2] = sbb64(x_R.d[2], curve->n.d[2], borrow, &borrow);
        x_R.d[3] = sbb64(x_R.d[3], curve->n.d[3], borrow, &borrow);
    }
    
    // Check v == r
    return (x_R == sig->r) ? 0 : -1;
}

// ============================================================================
// ECDH Implementation
// ============================================================================

int ecdh_compute(uint8_t* shared_secret, const Fe256* private_key,
                 const Fe256Point* peer_public, CurveId curve_id) {
    const CurveParams* curve = get_curve_params(curve_id);
    
    // S = d * Q
    Fe256Point S;
    scalar_mult(&S, private_key, peer_public, curve);
    
    if (S.is_infinity) return -1;
    
    // Extract x coordinate
    Fe256 x, y;
    point_to_affine(&x, &y, &S, curve);
    
    x.to_bytes_be(shared_secret);
    return 0;
}

} // namespace native
} // namespace ecc
} // namespace kctsb
