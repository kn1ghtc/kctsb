/**
 * @file sm2_curve.cpp
 * @brief SM2 Curve Parameters and Field Operations
 * 
 * This file contains:
 * - SM2 curve parameter definitions
 * - fe256 field element operations (256-bit Solinas reduction)
 * - Utility functions for bignum conversion
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "sm2_internal.h"
#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"

#include <cstring>
#include <stdexcept>

using namespace kctsb;

namespace kctsb::internal::sm2 {

// ============================================================================
// SM2 Context Singleton
// ============================================================================

SM2Context& SM2Context::instance() {
    static SM2Context ctx;
    return ctx;
}

SM2Context::SM2Context() : curve_(ecc::internal::CurveType::SM2) {
    // Cache curve parameters
    n_ = curve_.get_order();
    p_ = curve_.get_prime();
    bit_size_ = curve_.get_bit_size();
}

// ============================================================================
// fe256 Field Operations (SM2 Solinas Reduction)
// ============================================================================

namespace fe256_ops {

const fe256 SM2_P = {{
    0xFFFFFFFFFFFFFFFFULL,  // limb[0]
    0xFFFFFFFF00000000ULL,  // limb[1]
    0xFFFFFFFFFFFFFFFFULL,  // limb[2]
    0xFFFFFFFEFFFFFFFFULL   // limb[3]
}};

void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t product = (uint128_t)a * b;
    *lo = (uint64_t)product;
    *hi = (uint64_t)(product >> 64);
}

uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint128_t sum = (uint128_t)a + b + carry_in;
    *carry_out = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
}

uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint128_t diff = (uint128_t)a - b - borrow_in;
    *borrow_out = (diff >> 127) ? 1 : 0;
    return (uint64_t)diff;
}

void fe256_copy(fe256* dst, const fe256* src) {
    dst->limb[0] = src->limb[0];
    dst->limb[1] = src->limb[1];
    dst->limb[2] = src->limb[2];
    dst->limb[3] = src->limb[3];
}

void fe256_zero(fe256* a) {
    a->limb[0] = 0;
    a->limb[1] = 0;
    a->limb[2] = 0;
    a->limb[3] = 0;
}

int fe256_is_zero(const fe256* a) {
    uint64_t x = a->limb[0] | a->limb[1] | a->limb[2] | a->limb[3];
    return ((x | (~x + 1)) >> 63) ^ 1;
}

void fe256_cmov(fe256* r, const fe256* a, int cond) {
    uint64_t mask = ~((uint64_t)cond - 1);
    r->limb[0] ^= mask & (r->limb[0] ^ a->limb[0]);
    r->limb[1] ^= mask & (r->limb[1] ^ a->limb[1]);
    r->limb[2] ^= mask & (r->limb[2] ^ a->limb[2]);
    r->limb[3] ^= mask & (r->limb[3] ^ a->limb[3]);
}

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

void fe256_to_bytes(uint8_t bytes[32], const fe256* a) {
    for (int i = 0; i < 8; i++) {
        bytes[i]      = (uint8_t)(a->limb[3] >> (56 - 8*i));
        bytes[i + 8]  = (uint8_t)(a->limb[2] >> (56 - 8*i));
        bytes[i + 16] = (uint8_t)(a->limb[1] >> (56 - 8*i));
        bytes[i + 24] = (uint8_t)(a->limb[0] >> (56 - 8*i));
    }
}

void fe256_add_sm2(fe256* r, const fe256* a, const fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    fe256 tmp;
    
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = adc64(a->limb[3], b->limb[3], carry, &carry);
    
    // Conditional subtraction of p
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
    
    // Conditional addition of p if underflow
    fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = adc64(r->limb[0], SM2_P.limb[0], 0, &carry);
    tmp.limb[1] = adc64(r->limb[1], SM2_P.limb[1], carry, &carry);
    tmp.limb[2] = adc64(r->limb[2], SM2_P.limb[2], carry, &carry);
    tmp.limb[3] = adc64(r->limb[3], SM2_P.limb[3], carry, &carry);
    
    fe256_cmov(r, &tmp, (int)borrow);
}

void fe256_mul_wide(fe512* r, const fe256* a, const fe256* b) {
    uint64_t carry, hi, lo;
    uint64_t t[8] = {0};
    
    // Schoolbook multiplication
    for (int i = 0; i < 4; i++) {
        carry = 0;
        for (int j = 0; j < 4; j++) {
            mul64x64(a->limb[i], b->limb[j], &hi, &lo);
            t[i+j] = adc64(t[i+j], lo, 0, &carry);
            uint64_t c2;
            t[i+j+1] = adc64(t[i+j+1], hi, carry, &c2);
            carry = c2;
        }
    }
    
    for (int i = 0; i < 8; i++) {
        r->limb[i] = t[i];
    }
}

void fe256_reduce_sm2(fe256* r, const fe512* a) {
    // Use signed 128-bit accumulators for safe handling of negative terms
    int128_t acc[5] = {0, 0, 0, 0, 0};
    
    // Initialize with low 256 bits
    acc[0] = (int128_t)a->limb[0];
    acc[1] = (int128_t)a->limb[1];
    acc[2] = (int128_t)a->limb[2];
    acc[3] = (int128_t)a->limb[3];
    
    uint64_t h0 = a->limb[4];
    uint64_t h1 = a->limb[5];
    uint64_t h2 = a->limb[6];
    uint64_t h3 = a->limb[7];
    
    // SM2 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
    // Apply reduction: h[i] * 2^(256+64*i) ≡ h[i] * 2^(64*i) * k (mod p)
    // where k = 2^224 + 2^96 - 2^64 + 1
    
    acc[0] += (int128_t)h0;
    acc[1] -= (int128_t)h0;
    acc[1] += (int128_t)(h0 & 0xFFFFFFFFULL) << 32;
    acc[2] += (int128_t)(h0 >> 32);
    acc[3] += (int128_t)(h0 & 0xFFFFFFFFULL) << 32;
    acc[4] += (int128_t)(h0 >> 32);
    
    acc[1] += (int128_t)h1;
    acc[2] -= (int128_t)h1;
    acc[2] += (int128_t)(h1 & 0xFFFFFFFFULL) << 32;
    acc[3] += (int128_t)(h1 >> 32);
    acc[4] += (int128_t)(h1 & 0xFFFFFFFFULL) << 32;
    
    acc[2] += (int128_t)h2;
    acc[3] -= (int128_t)h2;
    acc[3] += (int128_t)(h2 & 0xFFFFFFFFULL) << 32;
    acc[4] += (int128_t)(h2 >> 32);
    
    acc[3] += (int128_t)h3;
    acc[4] -= (int128_t)h3;
    acc[4] += (int128_t)(h3 & 0xFFFFFFFFULL) << 32;
    
    // Iterative reduction until acc[4] is zero
    for (int round = 0; round < 5; round++) {
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
    
    // Final carry propagation
    for (int i = 0; i < 4; i++) {
        acc[i + 1] += acc[i] >> 64;
        acc[i] = (uint64_t)acc[i];
    }
    
    // Handle remaining overflow
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
    
    // Final reduction: while result >= p, subtract p
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
}

void fe256_mul_sm2(fe256* r, const fe256* a, const fe256* b) {
    fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_sm2(r, &wide);
}

void fe256_sqr_sm2(fe256* r, const fe256* a) {
    fe256_mul_sm2(r, a, a);
}

void fe256_inv_sm2(fe256* r, const fe256* a) {
    fe256 result, base;
    fe256_copy(&base, a);
    
    fe256_zero(&result);
    result.limb[0] = 1;
    
    // p - 2 for SM2
    uint64_t p_minus_2[4] = {
        SM2_P.limb[0] - 2,
        SM2_P.limb[1],
        SM2_P.limb[2],
        SM2_P.limb[3]
    };
    
    // Square-and-multiply
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

}  // namespace fe256_ops

// ============================================================================
// Bignum Utility Functions
// ============================================================================

ZZ bytes_to_zz(const uint8_t* data, size_t len) {
    ZZ result = ZZ(0);
    for (size_t i = 0; i < len; i++) {
        result <<= 8;
        result += data[i];
    }
    return result;
}

void zz_to_bytes(const ZZ& z, uint8_t* out, size_t len) {
    std::memset(out, 0, len);
    
    ZZ tmp = z;
    for (size_t i = 0; i < len && !IsZero(tmp); i++) {
        long byte_val = to_long(tmp % 256);
        out[len - 1 - i] = static_cast<uint8_t>(byte_val);
        tmp >>= 8;
    }
}

ZZ extract_zz_from_zzp(const ZZ_p& val, const ZZ& modulus) {
    ZZ_p::init(modulus);
    return rep(val);
}

}  // namespace kctsb::internal::sm2
