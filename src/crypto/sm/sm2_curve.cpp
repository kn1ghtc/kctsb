/**
 * @file sm2_curve.cpp
 * @brief SM2 Curve Parameters and Field Operations
 * 
 * Core SM2 elliptic curve implementation:
 * - SM2Context class for curve parameter caching
 * - fe256_ops namespace for optimized 256-bit field arithmetic
 * - Utility functions for bignum conversion
 * 
 * Architecture: Provides shared internal definitions for sm2_*.cpp files.
 * 
 * References:
 * - GB/T 32918.1-2016: SM2 General
 * - SM2 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"
#include "kctsb/core/common.h"

#include <kctsb/math/bignum/ZZ.h>
#include <kctsb/math/bignum/ZZ_p.h>

#include <cstring>
#include <array>
#include <vector>
#include <stdexcept>

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

// ============================================================================
// C++ Internal Implementation Namespace
// ============================================================================

namespace kctsb::internal::sm2 {

// Field size in bytes (256-bit = 32 bytes)
constexpr size_t FIELD_SIZE = 32;

// SM2 signature and encryption constants
constexpr size_t SIGNATURE_SIZE = 64;  // r (32) + s (32)
constexpr size_t MAX_HASH_SIZE = 32;   // SM3 output

/**
 * @brief SM2 internal context for curve operations (forward declaration)
 * 
 * Implementation is at the end of this file.
 * Other sm2_*.cpp files use extern declarations to access this singleton.
 */
class SM2Context {
public:
    static SM2Context& instance();
    
    const ecc::internal::ECCurve& curve() const;
    const ZZ& n() const;
    const ZZ& p() const;
    int bit_size() const;
    
private:
    SM2Context();
    ecc::internal::ECCurve curve_;
    ZZ n_;
    ZZ p_;
    int bit_size_;
};

// ============================================================================
// SM2 Field Acceleration Layer (fe256)
// ============================================================================
// Optimized 256-bit field arithmetic using Solinas reduction
// SM2 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
// Reduction uses identity: 2^256 = 2^224 + 2^96 - 2^64 + 1 (mod p)
// ============================================================================

namespace fe256_ops {

// 128-bit arithmetic helpers (use __int128 for safe accumulation)
#if defined(__SIZEOF_INT128__)
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
#else
#error "SM2 fe256 acceleration requires __int128 support"
#endif

/**
 * @brief 256-bit field element in 4-limb representation
 */
struct fe256 {
    uint64_t limb[4];  // Little-endian: limb[0] is LSB
};

/**
 * @brief 512-bit intermediate for multiplication result
 */
struct fe512 {
    uint64_t limb[8];
};

/**
 * @brief SM2 prime constant
 * p = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
 */
static const fe256 SM2_P = {{
    0xFFFFFFFFFFFFFFFFULL,  // limb[0]
    0xFFFFFFFF00000000ULL,  // limb[1]
    0xFFFFFFFFFFFFFFFFULL,  // limb[2]
    0xFFFFFFFEFFFFFFFFULL   // limb[3]
}};

/**
 * @brief 64x64 -> 128-bit multiplication
 */
static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t product = (uint128_t)a * b;
    *lo = (uint64_t)product;
    *hi = (uint64_t)(product >> 64);
}

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
 * @brief Check if fe256 is zero (constant-time)
 */
static inline int fe256_is_zero(const fe256* a) {
    uint64_t x = a->limb[0] | a->limb[1] | a->limb[2] | a->limb[3];
    return ((x | (~x + 1)) >> 63) ^ 1;
}

/**
 * @brief Constant-time conditional move: if cond != 0, r = a
 */
static inline void fe256_cmov(fe256* r, const fe256* a, int cond) {
    uint64_t mask = ~((uint64_t)cond - 1);
    r->limb[0] ^= mask & (r->limb[0] ^ a->limb[0]);
    r->limb[1] ^= mask & (r->limb[1] ^ a->limb[1]);
    r->limb[2] ^= mask & (r->limb[2] ^ a->limb[2]);
    r->limb[3] ^= mask & (r->limb[3] ^ a->limb[3]);
}

/**
 * @brief Convert big-endian bytes to fe256
 */
static void fe256_from_bytes(fe256* r, const uint8_t bytes[32]) {
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
static void fe256_to_bytes(uint8_t bytes[32], const fe256* a) {
    for (int i = 0; i < 8; i++) {
        bytes[i]      = (uint8_t)(a->limb[3] >> (56 - 8*i));
        bytes[i + 8]  = (uint8_t)(a->limb[2] >> (56 - 8*i));
        bytes[i + 16] = (uint8_t)(a->limb[1] >> (56 - 8*i));
        bytes[i + 24] = (uint8_t)(a->limb[0] >> (56 - 8*i));
    }
}

/**
 * @brief SM2 modular addition: r = (a + b) mod p
 */
static void fe256_add_sm2(fe256* r, const fe256* a, const fe256* b) {
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

/**
 * @brief SM2 modular subtraction: r = (a - b) mod p
 */
static void fe256_sub_sm2(fe256* r, const fe256* a, const fe256* b) {
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

/**
 * @brief Schoolbook 256x256 -> 512-bit multiplication
 */
static void fe256_mul_wide(fe512* r, const fe256* a, const fe256* b) {
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

/**
 * @brief SM2 Solinas reduction for 512-bit input
 * 
 * SM2 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * Identity: 2^256 = 2^224 + 2^96 - 2^64 + 1 (mod p)
 * 
 * This implementation uses int128_t accumulators to handle signed
 * intermediate values safely. Critical: use int64_t, NOT long on Windows.
 * 
 * @param r Result (256-bit, fully reduced)
 * @param a Input (512-bit)
 */
static void fe256_reduce_sm2(fe256* r, const fe512* a) {
    // Use signed 128-bit accumulators for safe handling of negative terms
    int128_t acc[5] = {0, 0, 0, 0, 0};
    
    // Initialize with low 256 bits
    acc[0] = (int128_t)a->limb[0];
    acc[1] = (int128_t)a->limb[1];
    acc[2] = (int128_t)a->limb[2];
    acc[3] = (int128_t)a->limb[3];
    
    // Apply reduction: h[i] * 2^(256+64*i) = h[i] * 2^(64*i) * k (mod p)
    // where k = 2^224 + 2^96 - 2^64 + 1
    uint64_t h0 = a->limb[4];
    uint64_t h1 = a->limb[5];
    uint64_t h2 = a->limb[6];
    uint64_t h3 = a->limb[7];
    
    // h0 * k: contributes at bit positions 0, 64 (negative), 96, 224
    // Term +1: at position 0
    acc[0] += (int128_t)h0;
    // Term -2^64: at position 64 (limb 1)
    acc[1] -= (int128_t)h0;
    // Term +2^96: at position 96 (limb 1 bit 32 and limb 2)
    acc[1] += (int128_t)(h0 & 0xFFFFFFFFULL) << 32;
    acc[2] += (int128_t)(h0 >> 32);
    // Term +2^224: at position 224 (limb 3 bit 32 and limb 4)
    acc[3] += (int128_t)(h0 & 0xFFFFFFFFULL) << 32;
    acc[4] += (int128_t)(h0 >> 32);
    
    // h1 * k * 2^64: bit positions shifted by 64
    // Term +2^64: at position 64 (limb 1)
    acc[1] += (int128_t)h1;
    // Term -2^128: at position 128 (limb 2)
    acc[2] -= (int128_t)h1;
    // Term +2^160: at position 160 (limb 2 bit 32 and limb 3)
    acc[2] += (int128_t)(h1 & 0xFFFFFFFFULL) << 32;
    acc[3] += (int128_t)(h1 >> 32);
    // Term +2^288: overflow to acc[4]
    acc[4] += (int128_t)(h1 & 0xFFFFFFFFULL) << 32;
    
    // h2 * k * 2^128: bit positions shifted by 128
    // Term +2^128: at position 128 (limb 2)
    acc[2] += (int128_t)h2;
    // Term -2^192: at position 192 (limb 3)
    acc[3] -= (int128_t)h2;
    // Term +2^224: at position 224 (limb 3 bit 32 and limb 4)
    acc[3] += (int128_t)(h2 & 0xFFFFFFFFULL) << 32;
    acc[4] += (int128_t)(h2 >> 32);
    
    // h3 * k * 2^192: bit positions shifted by 192
    // Term +2^192: at position 192 (limb 3)
    acc[3] += (int128_t)h3;
    // Term -2^256: at position 256 (limb 4, negative)
    acc[4] -= (int128_t)h3;
    // Term +2^288: overflow (will be handled by iteration)
    acc[4] += (int128_t)(h3 & 0xFFFFFFFFULL) << 32;
    
    // Iterative reduction until acc[4] is zero
    for (int round = 0; round < 5; round++) {
        // Propagate carries (handling signed values)
        for (int i = 0; i < 4; i++) {
            acc[i + 1] += acc[i] >> 64;
            acc[i] = (uint64_t)acc[i];
        }
        
        // If acc[4] is non-zero, reduce it
        if (acc[4] != 0) {
            int128_t overflow = acc[4];
            acc[4] = 0;
            
            // overflow * 2^256 = overflow * k (mod p)
            acc[0] += overflow;
            // 2^96 - 2^64 = 2^64 * (2^32 - 1) at limb 1
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

/**
 * @brief SM2 modular multiplication: r = (a * b) mod p
 */
static void fe256_mul_sm2(fe256* r, const fe256* a, const fe256* b) {
    fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_reduce_sm2(r, &wide);
}

/**
 * @brief SM2 modular squaring: r = a^2 mod p
 */
static void fe256_sqr_sm2(fe256* r, const fe256* a) {
    fe256_mul_sm2(r, a, a);
}

/**
 * @brief SM2 modular inversion: r = a^(-1) mod p
 * Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
 */
static void fe256_inv_sm2(fe256* r, const fe256* a) {
    fe256 result, base;
    fe256_copy(&base, a);
    
    // result = 1
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

// Suppress unused function warnings - these are available for future use
[[maybe_unused]] static void fe256_add_sm2_unused(fe256* r, const fe256* a, const fe256* b) {
    fe256_add_sm2(r, a, b);
}
[[maybe_unused]] static void fe256_sub_sm2_unused(fe256* r, const fe256* a, const fe256* b) {
    fe256_sub_sm2(r, a, b);
}
[[maybe_unused]] static void fe256_from_bytes_unused(fe256* r, const uint8_t bytes[32]) {
    fe256_from_bytes(r, bytes);
}
[[maybe_unused]] static void fe256_to_bytes_unused(uint8_t bytes[32], const fe256* a) {
    fe256_to_bytes(bytes, a);
}
[[maybe_unused]] static int fe256_is_zero_unused(const fe256* a) {
    return fe256_is_zero(a);
}
[[maybe_unused]] static void fe256_inv_sm2_unused(fe256* r, const fe256* a) {
    fe256_inv_sm2(r, a);
}

}  // namespace fe256_ops

// ============================================================================
// SM2Context Implementation (Singleton)
// ============================================================================

SM2Context::SM2Context() : curve_(ecc::internal::CurveType::SM2) {
    n_ = curve_.get_order();
    p_ = curve_.get_prime();
    bit_size_ = curve_.get_bit_size();
}

SM2Context& SM2Context::instance() {
    static SM2Context ctx;
    return ctx;
}

const ecc::internal::ECCurve& SM2Context::curve() const { return curve_; }
const ZZ& SM2Context::n() const { return n_; }
const ZZ& SM2Context::p() const { return p_; }
int SM2Context::bit_size() const { return bit_size_; }

// ============================================================================
// Utility Functions (Exported for other sm2_*.cpp files)
// ============================================================================

/**
 * @brief Convert byte array to bignum ZZ (big-endian)
 * @param data Input bytes
 * @param len Length of input
 * @return ZZ value
 */
ZZ bytes_to_zz(const uint8_t* data, size_t len) {
    ZZ result = ZZ(0);
    for (size_t i = 0; i < len; i++) {
        result <<= 8;
        result += data[i];
    }
    return result;
}

/**
 * @brief Convert bignum ZZ to byte array (big-endian, fixed length)
 * 
 * This function manually extracts bytes to avoid issues with the bignum
 * library's BytesFromZZ which has assumptions about internal limb storage.
 * 
 * @param z ZZ value
 * @param out Output buffer
 * @param len Output length
 */
void zz_to_bytes(const ZZ& z, uint8_t* out, size_t len) {
    std::memset(out, 0, len);
    
    // Manual extraction: extract bytes from lowest to highest
    ZZ tmp = z;
    for (size_t i = 0; i < len && !IsZero(tmp); i++) {
        // Get lowest byte
        long byte_val = to_long(tmp % 256);
        out[len - 1 - i] = static_cast<uint8_t>(byte_val);
        tmp >>= 8;
    }
}

/**
 * @brief Generate random k for signature (must be in [1, n-1])
 * @param k Output random value
 * @param n Curve order
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t generate_random_k(ZZ& k, const ZZ& n) {
    uint8_t k_bytes[FIELD_SIZE];
    
    // Retry until we get a valid k in [1, n-1]
    for (int attempts = 0; attempts < 100; attempts++) {
        if (kctsb_random_bytes(k_bytes, FIELD_SIZE) != KCTSB_SUCCESS) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        
        k = bytes_to_zz(k_bytes, FIELD_SIZE);
        
        // Reduce k modulo n
        k = k % n;
        
        // k must be in [1, n-1]
        if (!IsZero(k) && k < n) {
            kctsb_secure_zero(k_bytes, sizeof(k_bytes));
            return KCTSB_SUCCESS;
        }
    }
    
    kctsb_secure_zero(k_bytes, sizeof(k_bytes));
    return KCTSB_ERROR_RANDOM_FAILED;
}

}  // namespace kctsb::internal::sm2
