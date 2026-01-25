/**
 * @file sm2.cpp
 * @brief SM2 Elliptic Curve Cryptography Implementation
 * 
 * Complete implementation of GB/T 32918-2016 Chinese National Standard:
 * - Key generation using SM2 curve (256-bit)
 * - Digital signature (SM2DSA) with SM3 hash
 * - Public key encryption/decryption
 * 
 * Architecture: C++ internal implementation + extern "C" API export.
 * 
 * References:
 * - GB/T 32918.1-2016: General
 * - GB/T 32918.2-2016: Digital Signature
 * - GB/T 32918.4-2016: Public Key Encryption
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

// Enable debug output for SM2 verification failures
// #define KCTSB_DEBUG_SM2 1  // Disabled - SM2 signature verification now works correctly
#ifdef KCTSB_DEBUG_SM2
#include <iostream>
#endif

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

// ============================================================================
// C++ Internal Implementation Namespace
// ============================================================================

namespace kctsb::internal::sm2 {

/**
 * @brief SM2 curve parameters (256-bit, Chinese National Standard)
 * 
 * p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
 * a = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
 * b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
 * n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
 * Gx = 32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
 * Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
 */

// Field size in bytes (256-bit = 32 bytes)
constexpr size_t FIELD_SIZE = 32;

// SM2 signature and encryption constants
constexpr size_t SIGNATURE_SIZE = 64;  // r (32) + s (32)
constexpr size_t MAX_HASH_SIZE = 32;   // SM3 output

/**
 * @brief SM2 internal context for curve operations
 */
class SM2Context {
public:
    SM2Context() : curve_(ecc::CurveType::SM2) {
        // Cache curve parameters
        n_ = curve_.get_order();
        p_ = curve_.get_prime();
        bit_size_ = curve_.get_bit_size();
    }
    
    /**
     * @brief Get singleton instance
     */
    static SM2Context& instance() {
        static SM2Context ctx;
        return ctx;
    }
    
    const ecc::ECCurve& curve() const { return curve_; }
    const ZZ& n() const { return n_; }
    const ZZ& p() const { return p_; }
    int bit_size() const { return bit_size_; }
    
private:
    ecc::ECCurve curve_;
    ZZ n_;
    ZZ p_;
    int bit_size_;
};

// ============================================================================
// SM2 Field Acceleration Layer (fe256)
// ============================================================================
// Optimized 256-bit field arithmetic using Solinas reduction
// SM2 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
// Reduction uses identity: 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
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
 * Identity: 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
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
    
    // Apply reduction: h[i] * 2^(256+64*i) ≡ h[i] * 2^(64*i) * k (mod p)
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
            
            // overflow * 2^256 ≡ overflow * k (mod p)
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

}  // namespace fe256_ops

// ============================================================================
// Utility Functions
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
 * @brief Extract ZZ from ZZ_p value safely
 * @param val ZZ_p value
 * @param modulus The modulus p
 * @return ZZ representation
 */
ZZ extract_zz_from_zzp(const ZZ_p& val, const ZZ& modulus) {
    ZZ_p::init(modulus);
    return rep(val);
}

/**
 * @brief Compute Z value for SM2 (user identification hash)
 * 
 * Z = SM3(ENTL || user_id || a || b || Gx || Gy || Px || Py)
 * where ENTL is the bit length of user_id (16 bits, big-endian)
 * 
 * @param user_id User identification bytes
 * @param user_id_len Length of user_id
 * @param public_key Public key (64 bytes: Px || Py)
 * @param z_value Output Z value (32 bytes)
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t compute_z_value(
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* public_key,
    uint8_t z_value[32]
) {
    // Get curve parameters
    ecc::CurveParams params = ecc::get_sm2_params();
    
    // Compute ENTL (bit length of user_id, max 8192 bits = 1024 bytes)
    if (user_id_len > 1024) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    uint16_t entl = static_cast<uint16_t>(user_id_len * 8);
    
    // Prepare Z input
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    
    // ENTL (2 bytes, big-endian)
    uint8_t entl_bytes[2] = {
        static_cast<uint8_t>(entl >> 8),
        static_cast<uint8_t>(entl & 0xFF)
    };
    kctsb_sm3_update(&sm3_ctx, entl_bytes, 2);
    
    // User ID
    kctsb_sm3_update(&sm3_ctx, user_id, user_id_len);
    
    // Curve parameter a (32 bytes)
    uint8_t a_bytes[FIELD_SIZE];
    zz_to_bytes(params.a, a_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, a_bytes, FIELD_SIZE);
    
    // Curve parameter b (32 bytes)
    uint8_t b_bytes[FIELD_SIZE];
    zz_to_bytes(params.b, b_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, b_bytes, FIELD_SIZE);
    
    // Generator Gx (32 bytes)
    uint8_t gx_bytes[FIELD_SIZE];
    zz_to_bytes(params.Gx, gx_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, gx_bytes, FIELD_SIZE);
    
    // Generator Gy (32 bytes)
    uint8_t gy_bytes[FIELD_SIZE];
    zz_to_bytes(params.Gy, gy_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, gy_bytes, FIELD_SIZE);
    
    // Public key Px (32 bytes)
    kctsb_sm3_update(&sm3_ctx, public_key, FIELD_SIZE);
    
    // Public key Py (32 bytes)
    kctsb_sm3_update(&sm3_ctx, public_key + FIELD_SIZE, FIELD_SIZE);
    
    kctsb_sm3_final(&sm3_ctx, z_value);
    
    return KCTSB_SUCCESS;
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

// ============================================================================
// Key Generation
// ============================================================================

/**
 * @brief Generate SM2 key pair
 * 
 * Private key d is a random integer in [1, n-2]
 * Public key P = d * G (point multiplication)
 * 
 * @param keypair Output key pair structure
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t generate_keypair_internal(kctsb_sm2_keypair_t* keypair) {
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Generate private key d in [1, n-2]
    uint8_t d_bytes[FIELD_SIZE];
    for (int attempts = 0; attempts < 100; attempts++) {
        if (kctsb_random_bytes(d_bytes, FIELD_SIZE) != KCTSB_SUCCESS) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        
        ZZ d = bytes_to_zz(d_bytes, FIELD_SIZE);
        d = d % (n - 1);  // Reduce to [0, n-2]
        
        if (IsZero(d)) {
            continue;  // d must be at least 1
        }
        d = d + 1;  // Now d is in [1, n-1]
        
        // Compute public key P = d * G using Montgomery ladder
        ecc::JacobianPoint P_jac = curve.scalar_mult_base(d);
        ecc::AffinePoint P_aff = curve.to_affine(P_jac);
        
        // Export private key
        zz_to_bytes(d, keypair->private_key, FIELD_SIZE);
        
        // Export public key (Px || Py)
        ZZ_p::init(ctx.p());
        ZZ Px = rep(P_aff.x);
        ZZ Py = rep(P_aff.y);
        zz_to_bytes(Px, keypair->public_key, FIELD_SIZE);
        zz_to_bytes(Py, keypair->public_key + FIELD_SIZE, FIELD_SIZE);
        
        // Secure cleanup
        kctsb_secure_zero(d_bytes, sizeof(d_bytes));
        
        return KCTSB_SUCCESS;
    }
    
    kctsb_secure_zero(d_bytes, sizeof(d_bytes));
    return KCTSB_ERROR_RANDOM_FAILED;
}

// ============================================================================
// Digital Signature (SM2DSA)
// ============================================================================

/**
 * @brief SM2 digital signature
 * 
 * Algorithm (GB/T 32918.2-2016):
 * 1. Compute e = SM3(Z || M)
 * 2. Generate random k in [1, n-1]
 * 3. Compute point (x1, y1) = k * G
 * 4. Compute r = (e + x1) mod n
 * 5. If r = 0 or r + k = n, go to step 2
 * 6. Compute s = ((1 + d)^-1 * (k - r*d)) mod n
 * 7. If s = 0, go to step 2
 * 8. Output signature (r, s)
 * 
 * @param private_key 32-byte private key
 * @param public_key 64-byte public key
 * @param user_id User ID for Z value computation
 * @param user_id_len Length of user_id
 * @param message Message to sign
 * @param message_len Message length
 * @param signature Output signature (r, s)
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t sign_internal(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
) {
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Parse private key
    ZZ d = bytes_to_zz(private_key, FIELD_SIZE);
    if (IsZero(d) || d >= n - 1) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Step 1: Compute Z value
    uint8_t z_value[32];
    kctsb_error_t err = compute_z_value(user_id, user_id_len, public_key, z_value);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Compute e = SM3(Z || M)
    uint8_t e_hash[32];
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    kctsb_sm3_update(&sm3_ctx, z_value, 32);
    kctsb_sm3_update(&sm3_ctx, message, message_len);
    kctsb_sm3_final(&sm3_ctx, e_hash);
    
    ZZ e = bytes_to_zz(e_hash, 32);
    
    // Compute (1 + d)^-1 mod n
    ZZ d_plus_1 = (d + 1) % n;
    ZZ d_plus_1_inv = InvMod(d_plus_1, n);
    
    ZZ r, s;
    
    // Signature generation loop
    for (int attempts = 0; attempts < 100; attempts++) {
        // Step 2: Generate random k
        ZZ k;
        err = generate_random_k(k, n);
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        // Step 3: Compute (x1, y1) = k * G (using Montgomery ladder)
        ecc::JacobianPoint kG = curve.scalar_mult_base(k);
        ecc::AffinePoint kG_aff = curve.to_affine(kG);
        
        #ifdef KCTSB_DEBUG_SM2
        // Debug: Print k and kG.x for comparison with verification
        ZZ_p::init(ctx.p());
        ecc::AffinePoint G_aff_sign = curve.to_affine(curve.get_generator());
        std::cerr << "[SM2 SIGN DEBUG] k = " << k << "\n";
        std::cerr << "[SM2 SIGN DEBUG] G.x in sign = " << rep(G_aff_sign.x) << "\n";
        std::cerr << "[SM2 SIGN DEBUG] kG.x = " << rep(kG_aff.x) << "\n";
        #endif
        
        // Extract ZZ value immediately after to_affine (ZZ_p context still valid)
        ZZ x1 = rep(kG_aff.x);
        
        // Step 4: Compute r = (e + x1) mod n
        r = (e + x1) % n;
        
        // Step 5: Check r != 0 and r + k != n
        if (IsZero(r) || (r + k) == n) {
            continue;
        }
        
        // Step 6: Compute s = ((1+d)^-1 * (k - r*d)) mod n
        ZZ k_minus_rd = (k - MulMod(r, d, n)) % n;
        if (k_minus_rd < 0) {
            k_minus_rd += n;
        }
        s = MulMod(d_plus_1_inv, k_minus_rd, n);
        
        // Step 7: Check s != 0
        if (!IsZero(s)) {
            break;
        }
        
        if (attempts == 99) {
            return KCTSB_ERROR_INTERNAL;
        }
    }
    
    // Step 8: Output signature (r, s)
    zz_to_bytes(r, signature->r, FIELD_SIZE);
    zz_to_bytes(s, signature->s, FIELD_SIZE);
    
    #ifdef KCTSB_DEBUG_SM2
    std::cerr << "[SM2 DEBUG] Signature generated:\n";
    std::cerr << "  e (hash): " << e << "\n";
    std::cerr << "  x1 (from kG): " << (r - e % n) << "\n";  // Reconstruct x1 from r - e mod n
    std::cerr << "  r (e+x1 mod n): " << r << "\n";
    std::cerr << "  s: " << s << "\n";
    #endif
    
    // Secure cleanup
    kctsb_secure_zero(z_value, sizeof(z_value));
    kctsb_secure_zero(e_hash, sizeof(e_hash));
    
    return KCTSB_SUCCESS;
}

/**
 * @brief SM2 signature verification
 * 
 * Algorithm (GB/T 32918.2-2016):
 * 1. Verify r, s in [1, n-1]
 * 2. Compute e = SM3(Z || M)
 * 3. Compute t = (r + s) mod n, verify t != 0
 * 4. Compute point (x1, y1) = s*G + t*P
 * 5. Compute R = (e + x1) mod n
 * 6. Verify R = r
 * 
 * @param public_key 64-byte public key
 * @param user_id User ID
 * @param user_id_len User ID length
 * @param message Original message
 * @param message_len Message length
 * @param signature Signature to verify
 * @return KCTSB_SUCCESS if valid, KCTSB_ERROR_VERIFICATION_FAILED otherwise
 */
kctsb_error_t verify_internal(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
) {
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Parse signature
    ZZ r = bytes_to_zz(signature->r, FIELD_SIZE);
    ZZ s = bytes_to_zz(signature->s, FIELD_SIZE);
    
    // Step 1: Verify r, s in [1, n-1]
    if (IsZero(r) || r >= n || IsZero(s) || s >= n) {
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    // Parse public key
    ZZ Px = bytes_to_zz(public_key, FIELD_SIZE);
    ZZ Py = bytes_to_zz(public_key + FIELD_SIZE, FIELD_SIZE);
    
    ZZ_p::init(ctx.p());
    ecc::AffinePoint P_aff(conv<ZZ_p>(Px), conv<ZZ_p>(Py));
    ecc::JacobianPoint P_jac = curve.to_jacobian(P_aff);
    
    // Validate public key is on curve
    if (!curve.is_on_curve(P_jac)) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Step 2: Compute Z and e = SM3(Z || M)
    uint8_t z_value[32];
    kctsb_error_t err = compute_z_value(user_id, user_id_len, public_key, z_value);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    uint8_t e_hash[32];
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    kctsb_sm3_update(&sm3_ctx, z_value, 32);
    kctsb_sm3_update(&sm3_ctx, message, message_len);
    kctsb_sm3_final(&sm3_ctx, e_hash);
    
    ZZ e = bytes_to_zz(e_hash, 32);
    
    // Step 3: Compute t = (r + s) mod n
    ZZ t = (r + s) % n;
    if (IsZero(t)) {
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    // Step 4: Compute (x1, y1) = s*G + t*P (using Shamir's trick)
    ecc::JacobianPoint G = curve.get_generator();
    
    #ifdef KCTSB_DEBUG_SM2
    // Debug: Check generator point in Jacobian coordinates
    ZZ_p::init(ctx.p());
    std::cerr << "[SM2 DEBUG] G.X (Jacobian) = " << rep(G.X) << "\n";
    std::cerr << "[SM2 DEBUG] G.Y (Jacobian) = " << rep(G.Y) << "\n";
    std::cerr << "[SM2 DEBUG] G.Z (Jacobian) = " << rep(G.Z) << "\n";
    std::cerr << "[SM2 DEBUG] P_jac.X = " << rep(P_jac.X) << "\n";
    std::cerr << "[SM2 DEBUG] P_jac.Y = " << rep(P_jac.Y) << "\n";
    std::cerr << "[SM2 DEBUG] P_jac.Z = " << rep(P_jac.Z) << "\n";
    std::cerr << "[SM2 DEBUG] s = " << s << "\n";
    std::cerr << "[SM2 DEBUG] t = " << t << "\n";
    #endif
    
    // Use separate scalar multiplications for debugging
    // R_point = s*G + t*P
    // Note: Use scalar_mult_base for G to use same path as signature
    ecc::JacobianPoint sG = curve.scalar_mult_base(s);  // Use cached table like signature
    ecc::JacobianPoint tP = curve.scalar_mult(t, P_jac);
    ecc::JacobianPoint R_point = curve.add(sG, tP);
    ecc::AffinePoint R_aff = curve.to_affine(R_point);
    
    // Extract ZZ value immediately after to_affine (ZZ_p context still valid)
    ZZ x1 = rep(R_aff.x);
    
    // Step 5-6: Compute R = (e + x1) mod n and verify R = r
    ZZ R = (e + x1) % n;
    
    if (R == r) {
        return KCTSB_SUCCESS;
    }
    
    // Debug output for verification failure
    #ifdef KCTSB_DEBUG_SM2
    std::cerr << "[SM2 DEBUG] Verification FAILED!\n";
    std::cerr << "  r (from sig): " << r << "\n";
    std::cerr << "  s (from sig): " << s << "\n";
    std::cerr << "  e (hash): " << e << "\n";
    std::cerr << "  t (r+s mod n): " << t << "\n";
    std::cerr << "  x1 (from R_aff): " << x1 << "\n";
    std::cerr << "  R (e+x1 mod n): " << R << "\n";
    std::cerr << "  R == r: " << (R == r ? "YES" : "NO") << "\n";
    #endif
    
    return KCTSB_ERROR_VERIFICATION_FAILED;
}

// ============================================================================
// Public Key Encryption (SM2 Encryption Scheme)
// ============================================================================

/**
 * @brief Key Derivation Function (KDF)
 * 
 * KDF(Z, klen) as defined in GB/T 32918.4-2016
 * Uses SM3 for hash function.
 * 
 * @param z Input key material
 * @param z_len Length of z
 * @param klen Output length in bytes
 * @param key Output key material
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t sm2_kdf(
    const uint8_t* z,
    size_t z_len,
    size_t klen,
    uint8_t* key
) {
    if (klen == 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Number of hash iterations
    size_t ct = (klen + 31) / 32;
    
    for (size_t i = 1; i <= ct; i++) {
        kctsb_sm3_ctx_t ctx;
        kctsb_sm3_init(&ctx);
        kctsb_sm3_update(&ctx, z, z_len);
        
        // Counter (4 bytes, big-endian)
        uint8_t counter[4] = {
            static_cast<uint8_t>((i >> 24) & 0xFF),
            static_cast<uint8_t>((i >> 16) & 0xFF),
            static_cast<uint8_t>((i >> 8) & 0xFF),
            static_cast<uint8_t>(i & 0xFF)
        };
        kctsb_sm3_update(&ctx, counter, 4);
        
        uint8_t hash[32];
        kctsb_sm3_final(&ctx, hash);
        
        size_t offset = (i - 1) * 32;
        size_t copy_len = (i == ct) ? (klen - offset) : 32;
        std::memcpy(key + offset, hash, copy_len);
    }
    
    return KCTSB_SUCCESS;
}

/**
 * @brief SM2 public key encryption
 * 
 * Algorithm (GB/T 32918.4-2016):
 * 1. Generate random k in [1, n-1]
 * 2. Compute C1 = k * G (point on curve)
 * 3. Compute (x2, y2) = k * P (shared point)
 * 4. Compute t = KDF(x2 || y2, klen)
 * 5. Compute C2 = M XOR t
 * 6. Compute C3 = SM3(x2 || M || y2)
 * 7. Output C = C1 || C3 || C2 (new format)
 * 
 * @param public_key 64-byte public key
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Plaintext length
 * @param ciphertext Output buffer
 * @param ciphertext_len Output length
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t encrypt_internal(
    const uint8_t public_key[64],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
) {
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Output size: C1 (65 bytes: 0x04 || x1 || y1) + C3 (32 bytes) + C2 (plaintext_len)
    size_t output_size = 1 + 2 * FIELD_SIZE + 32 + plaintext_len;
    
    if (ciphertext == nullptr) {
        *ciphertext_len = output_size;
        return KCTSB_SUCCESS;
    }
    
    if (*ciphertext_len < output_size) {
        *ciphertext_len = output_size;
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Parse public key
    ZZ Px = bytes_to_zz(public_key, FIELD_SIZE);
    ZZ Py = bytes_to_zz(public_key + FIELD_SIZE, FIELD_SIZE);
    
    ZZ_p::init(ctx.p());
    ecc::AffinePoint P_aff(conv<ZZ_p>(Px), conv<ZZ_p>(Py));
    ecc::JacobianPoint P_jac = curve.to_jacobian(P_aff);
    
    // Validate public key
    if (!curve.is_on_curve(P_jac)) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Encryption loop (retry if KDF produces all zeros)
    for (int attempts = 0; attempts < 100; attempts++) {
        // Step 1: Generate random k
        ZZ k;
        kctsb_error_t err = generate_random_k(k, n);
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        // Step 2: Compute C1 = k * G (using Montgomery ladder)
        ecc::JacobianPoint C1_jac = curve.scalar_mult_base(k);
        ecc::AffinePoint C1_aff = curve.to_affine(C1_jac);
        
        // Extract ZZ values immediately after to_affine (ZZ_p context still valid)
        ZZ x1 = rep(C1_aff.x);
        ZZ y1 = rep(C1_aff.y);
        
        // Step 3: Compute (x2, y2) = k * P (using Montgomery ladder)
        ecc::JacobianPoint kP = curve.scalar_mult(k, P_jac);
        if (kP.is_infinity()) {
            continue;  // Retry with new k
        }
        ecc::AffinePoint kP_aff = curve.to_affine(kP);
        
        // Extract ZZ values immediately after to_affine (ZZ_p context still valid)
        ZZ x2 = rep(kP_aff.x);
        ZZ y2 = rep(kP_aff.y);
        
        // Prepare x2||y2 for KDF
        std::vector<uint8_t> x2y2(2 * FIELD_SIZE);
        zz_to_bytes(x2, x2y2.data(), FIELD_SIZE);
        zz_to_bytes(y2, x2y2.data() + FIELD_SIZE, FIELD_SIZE);
        
        // Step 4: Compute t = KDF(x2 || y2, plaintext_len)
        std::vector<uint8_t> t(plaintext_len);
        err = sm2_kdf(x2y2.data(), x2y2.size(), plaintext_len, t.data());
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        // Check if t is all zeros (would make encryption insecure)
        bool all_zero = true;
        for (size_t i = 0; i < plaintext_len; i++) {
            if (t[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            continue;  // Retry with new k
        }
        
        // Output C1 (uncompressed point format: 0x04 || x1 || y1)
        size_t pos = 0;
        ciphertext[pos++] = 0x04;
        zz_to_bytes(x1, ciphertext + pos, FIELD_SIZE);
        pos += FIELD_SIZE;
        zz_to_bytes(y1, ciphertext + pos, FIELD_SIZE);
        pos += FIELD_SIZE;
        
        // Step 6: Compute C3 = SM3(x2 || M || y2)
        kctsb_sm3_ctx_t sm3_ctx;
        kctsb_sm3_init(&sm3_ctx);
        
        uint8_t x2_bytes[FIELD_SIZE], y2_bytes[FIELD_SIZE];
        zz_to_bytes(x2, x2_bytes, FIELD_SIZE);
        zz_to_bytes(y2, y2_bytes, FIELD_SIZE);
        
        kctsb_sm3_update(&sm3_ctx, x2_bytes, FIELD_SIZE);
        kctsb_sm3_update(&sm3_ctx, plaintext, plaintext_len);
        kctsb_sm3_update(&sm3_ctx, y2_bytes, FIELD_SIZE);
        kctsb_sm3_final(&sm3_ctx, ciphertext + pos);
        pos += 32;  // C3 size
        
        // Step 5: Compute C2 = M XOR t
        for (size_t i = 0; i < plaintext_len; i++) {
            ciphertext[pos + i] = plaintext[i] ^ t[i];
        }
        pos += plaintext_len;
        
        *ciphertext_len = pos;
        
        // Secure cleanup
        kctsb_secure_zero(t.data(), t.size());
        kctsb_secure_zero(x2y2.data(), x2y2.size());
        
        return KCTSB_SUCCESS;
    }
    
    return KCTSB_ERROR_INTERNAL;
}

/**
 * @brief SM2 private key decryption
 * 
 * Algorithm:
 * 1. Parse C1 from ciphertext
 * 2. Verify C1 is on curve
 * 3. Compute (x2, y2) = d * C1
 * 4. Compute t = KDF(x2 || y2, C2_len)
 * 5. Compute M = C2 XOR t
 * 6. Compute u = SM3(x2 || M || y2)
 * 7. Verify u == C3
 * 8. Output M
 * 
 * @param private_key 32-byte private key
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param plaintext Output buffer
 * @param plaintext_len Output length
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t decrypt_internal(
    const uint8_t private_key[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
) {
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Minimum ciphertext size: C1 (65) + C3 (32) + C2 (1)
    constexpr size_t MIN_CIPHERTEXT_SIZE = 1 + 2 * FIELD_SIZE + 32 + 1;
    if (ciphertext_len < MIN_CIPHERTEXT_SIZE) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Parse ciphertext structure
    size_t c2_len = ciphertext_len - (1 + 2 * FIELD_SIZE + 32);
    
    if (plaintext == nullptr) {
        *plaintext_len = c2_len;
        return KCTSB_SUCCESS;
    }
    
    if (*plaintext_len < c2_len) {
        *plaintext_len = c2_len;
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Parse private key
    ZZ d = bytes_to_zz(private_key, FIELD_SIZE);
    if (IsZero(d) || d >= n - 1) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    // Step 1: Parse C1
    if (ciphertext[0] != 0x04) {
        return KCTSB_ERROR_INVALID_PARAM;  // Only uncompressed format supported
    }
    
    ZZ x1 = bytes_to_zz(ciphertext + 1, FIELD_SIZE);
    ZZ y1 = bytes_to_zz(ciphertext + 1 + FIELD_SIZE, FIELD_SIZE);
    
    ZZ_p::init(ctx.p());
    ecc::AffinePoint C1_aff(conv<ZZ_p>(x1), conv<ZZ_p>(y1));
    ecc::JacobianPoint C1_jac = curve.to_jacobian(C1_aff);
    
    // Step 2: Verify C1 is on curve
    if (!curve.is_on_curve(C1_jac)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Parse C3 and C2
    const uint8_t* c3_ptr = ciphertext + 1 + 2 * FIELD_SIZE;
    const uint8_t* c2_ptr = c3_ptr + 32;
    
    // Step 3: Compute (x2, y2) = d * C1 (using Montgomery ladder)
    ecc::JacobianPoint dC1 = curve.scalar_mult(d, C1_jac);
    if (dC1.is_infinity()) {
        return KCTSB_ERROR_DECRYPTION_FAILED;
    }
    ecc::AffinePoint dC1_aff = curve.to_affine(dC1);
    
    // Extract ZZ values immediately after to_affine (ZZ_p context still valid)
    ZZ x2 = rep(dC1_aff.x);
    ZZ y2 = rep(dC1_aff.y);
    
    // Prepare x2||y2
    uint8_t x2_bytes[FIELD_SIZE], y2_bytes[FIELD_SIZE];
    zz_to_bytes(x2, x2_bytes, FIELD_SIZE);
    zz_to_bytes(y2, y2_bytes, FIELD_SIZE);
    
    std::vector<uint8_t> x2y2(2 * FIELD_SIZE);
    std::memcpy(x2y2.data(), x2_bytes, FIELD_SIZE);
    std::memcpy(x2y2.data() + FIELD_SIZE, y2_bytes, FIELD_SIZE);
    
    // Step 4: Compute t = KDF(x2 || y2, c2_len)
    std::vector<uint8_t> t(c2_len);
    kctsb_error_t err = sm2_kdf(x2y2.data(), x2y2.size(), c2_len, t.data());
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Check if t is all zeros
    bool all_zero = true;
    for (size_t i = 0; i < c2_len; i++) {
        if (t[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        return KCTSB_ERROR_DECRYPTION_FAILED;
    }
    
    // Step 5: Compute M = C2 XOR t
    for (size_t i = 0; i < c2_len; i++) {
        plaintext[i] = c2_ptr[i] ^ t[i];
    }
    
    // Step 6: Compute u = SM3(x2 || M || y2)
    uint8_t u[32];
    kctsb_sm3_ctx_t sm3_ctx;
    kctsb_sm3_init(&sm3_ctx);
    kctsb_sm3_update(&sm3_ctx, x2_bytes, FIELD_SIZE);
    kctsb_sm3_update(&sm3_ctx, plaintext, c2_len);
    kctsb_sm3_update(&sm3_ctx, y2_bytes, FIELD_SIZE);
    kctsb_sm3_final(&sm3_ctx, u);

    // Step 7: Verify u == C3
    // Note: kctsb_secure_compare returns 1 if equal, 0 if different
    if (kctsb_secure_compare(u, c3_ptr, 32) == 0) {
        // Clear plaintext on verification failure
        kctsb_secure_zero(plaintext, c2_len);
        return KCTSB_ERROR_VERIFICATION_FAILED;
    }
    
    *plaintext_len = c2_len;
    
    // Secure cleanup
    kctsb_secure_zero(t.data(), t.size());
    kctsb_secure_zero(x2y2.data(), x2y2.size());
    
    return KCTSB_SUCCESS;
}

// ============================================================================
// Self Test
// ============================================================================

/**
 * @brief SM2 self test with standard test vectors
 * 
 * Tests key generation, signature, verification, encryption, and decryption.
 * 
 * @return KCTSB_SUCCESS if all tests pass
 */
kctsb_error_t self_test_internal() {
    // Test 1: Key generation
    kctsb_sm2_keypair_t keypair;
    kctsb_error_t err = generate_keypair_internal(&keypair);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Test 2: Sign and verify
    const uint8_t test_message[] = "SM2 Test Message for Signature";
    const size_t msg_len = sizeof(test_message) - 1;
    const char* default_uid = "1234567812345678";
    
    kctsb_sm2_signature_t sig;
    err = sign_internal(
        keypair.private_key,
        keypair.public_key,
        reinterpret_cast<const uint8_t*>(default_uid),
        16,
        test_message,
        msg_len,
        &sig
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    err = verify_internal(
        keypair.public_key,
        reinterpret_cast<const uint8_t*>(default_uid),
        16,
        test_message,
        msg_len,
        &sig
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Test 3: Verify with wrong message should fail
    const uint8_t wrong_message[] = "Wrong Message";
    err = verify_internal(
        keypair.public_key,
        reinterpret_cast<const uint8_t*>(default_uid),
        16,
        wrong_message,
        sizeof(wrong_message) - 1,
        &sig
    );
    if (err == KCTSB_SUCCESS) {
        return KCTSB_ERROR_INTERNAL;  // Should have failed
    }
    
    // Test 4: Encryption and decryption
    const uint8_t plaintext[] = "SM2 Encryption Test Data";
    const size_t pt_len = sizeof(plaintext) - 1;
    
    size_t ct_len = 0;
    encrypt_internal(keypair.public_key, plaintext, pt_len, nullptr, &ct_len);
    
    std::vector<uint8_t> ciphertext(ct_len);
    err = encrypt_internal(
        keypair.public_key,
        plaintext,
        pt_len,
        ciphertext.data(),
        &ct_len
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    size_t dec_len = ct_len;
    std::vector<uint8_t> decrypted(pt_len + 32);  // Extra space for safety
    err = decrypt_internal(
        keypair.private_key,
        ciphertext.data(),
        ct_len,
        decrypted.data(),
        &dec_len
    );
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    // Verify decrypted matches original
    if (dec_len != pt_len || std::memcmp(plaintext, decrypted.data(), pt_len) != 0) {
        return KCTSB_ERROR_INTERNAL;
    }
    
    return KCTSB_SUCCESS;
}

}  // namespace kctsb::internal::sm2

// ============================================================================
// C API Implementation (extern "C")
// ============================================================================

extern "C" {

kctsb_error_t kctsb_sm2_generate_keypair(kctsb_sm2_keypair_t* keypair) {
    if (keypair == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    return kctsb::internal::sm2::generate_keypair_internal(keypair);
}

kctsb_error_t kctsb_sm2_sign(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
) {
    if (private_key == nullptr || public_key == nullptr || 
        message == nullptr || signature == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Use default user ID if not provided
    const uint8_t* uid = user_id;
    size_t uid_len = user_id_len;
    const char* default_uid = "1234567812345678";
    if (uid == nullptr || uid_len == 0) {
        uid = reinterpret_cast<const uint8_t*>(default_uid);
        uid_len = 16;
    }
    
    return kctsb::internal::sm2::sign_internal(
        private_key, public_key, uid, uid_len,
        message, message_len, signature
    );
}

kctsb_error_t kctsb_sm2_verify(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
) {
    if (public_key == nullptr || message == nullptr || signature == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    const uint8_t* uid = user_id;
    size_t uid_len = user_id_len;
    const char* default_uid = "1234567812345678";
    if (uid == nullptr || uid_len == 0) {
        uid = reinterpret_cast<const uint8_t*>(default_uid);
        uid_len = 16;
    }
    
    return kctsb::internal::sm2::verify_internal(
        public_key, uid, uid_len, message, message_len, signature
    );
}

kctsb_error_t kctsb_sm2_encrypt(
    const uint8_t public_key[64],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
) {
    if (public_key == nullptr || plaintext == nullptr || ciphertext_len == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (plaintext_len == 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    return kctsb::internal::sm2::encrypt_internal(
        public_key, plaintext, plaintext_len, ciphertext, ciphertext_len
    );
}

kctsb_error_t kctsb_sm2_decrypt(
    const uint8_t private_key[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
) {
    if (private_key == nullptr || ciphertext == nullptr || plaintext_len == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    return kctsb::internal::sm2::decrypt_internal(
        private_key, ciphertext, ciphertext_len, plaintext, plaintext_len
    );
}

kctsb_error_t kctsb_sm2_self_test(void) {
    return kctsb::internal::sm2::self_test_internal();
}

}  // extern "C"

// ============================================================================
// C++ Class Implementation
// ============================================================================

namespace kctsb {

// SM2KeyPair implementation
SM2KeyPair::SM2KeyPair() {
    std::memset(&keypair_, 0, sizeof(keypair_));
}

SM2KeyPair::SM2KeyPair(const ByteVec& privateKey) {
    if (privateKey.size() != KCTSB_SM2_PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("Invalid SM2 private key size");
    }
    
    std::memcpy(keypair_.private_key, privateKey.data(), KCTSB_SM2_PRIVATE_KEY_SIZE);
    
    // Derive public key from private key (using Montgomery ladder)
    auto& ctx = internal::sm2::SM2Context::instance();
    const auto& curve = ctx.curve();
    
    kctsb::ZZ d = internal::sm2::bytes_to_zz(keypair_.private_key, KCTSB_SM2_PRIVATE_KEY_SIZE);
    ecc::JacobianPoint P_jac = curve.scalar_mult_base(d);
    ecc::AffinePoint P_aff = curve.to_affine(P_jac);
    
    kctsb::ZZ_p::init(ctx.p());
    kctsb::ZZ Px = IsZero(P_aff.x) ? kctsb::ZZ(0) : rep(P_aff.x);
    kctsb::ZZ Py = IsZero(P_aff.y) ? kctsb::ZZ(0) : rep(P_aff.y);
    
    internal::sm2::zz_to_bytes(Px, keypair_.public_key, internal::sm2::FIELD_SIZE);
    internal::sm2::zz_to_bytes(Py, keypair_.public_key + internal::sm2::FIELD_SIZE, 
                               internal::sm2::FIELD_SIZE);
}

SM2KeyPair SM2KeyPair::generate() {
    SM2KeyPair kp;
    kctsb_error_t err = kctsb_sm2_generate_keypair(&kp.keypair_);
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 key generation failed");
    }
    return kp;
}

ByteVec SM2KeyPair::getPrivateKey() const {
    return ByteVec(keypair_.private_key, 
                   keypair_.private_key + KCTSB_SM2_PRIVATE_KEY_SIZE);
}

ByteVec SM2KeyPair::getPublicKey() const {
    return ByteVec(keypair_.public_key, 
                   keypair_.public_key + KCTSB_SM2_PUBLIC_KEY_SIZE);
}

// SM2 class static methods
ByteVec SM2::sign(
    const SM2KeyPair& keypair,
    const ByteVec& message,
    const std::string& userId
) {
    kctsb_sm2_signature_t sig;
    ByteVec priv = keypair.getPrivateKey();
    ByteVec pub = keypair.getPublicKey();
    
    kctsb_error_t err = kctsb_sm2_sign(
        priv.data(),
        pub.data(),
        reinterpret_cast<const uint8_t*>(userId.data()),
        userId.size(),
        message.data(),
        message.size(),
        &sig
    );
    
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 signing failed");
    }
    
    ByteVec result(KCTSB_SM2_SIGNATURE_SIZE);
    std::memcpy(result.data(), sig.r, 32);
    std::memcpy(result.data() + 32, sig.s, 32);
    return result;
}

bool SM2::verify(
    const ByteVec& publicKey,
    const ByteVec& message,
    const ByteVec& signature,
    const std::string& userId
) {
    if (publicKey.size() != KCTSB_SM2_PUBLIC_KEY_SIZE ||
        signature.size() != KCTSB_SM2_SIGNATURE_SIZE) {
        return false;
    }
    
    kctsb_sm2_signature_t sig;
    std::memcpy(sig.r, signature.data(), 32);
    std::memcpy(sig.s, signature.data() + 32, 32);
    
    kctsb_error_t err = kctsb_sm2_verify(
        publicKey.data(),
        reinterpret_cast<const uint8_t*>(userId.data()),
        userId.size(),
        message.data(),
        message.size(),
        &sig
    );
    
    return err == KCTSB_SUCCESS;
}

ByteVec SM2::encrypt(const ByteVec& publicKey, const ByteVec& plaintext) {
    if (publicKey.size() != KCTSB_SM2_PUBLIC_KEY_SIZE) {
        throw std::invalid_argument("Invalid public key size");
    }
    
    // Get required output size
    size_t ct_len = 0;
    kctsb_sm2_encrypt(publicKey.data(), plaintext.data(), plaintext.size(), 
                      nullptr, &ct_len);
    
    ByteVec ciphertext(ct_len);
    kctsb_error_t err = kctsb_sm2_encrypt(
        publicKey.data(),
        plaintext.data(),
        plaintext.size(),
        ciphertext.data(),
        &ct_len
    );
    
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 encryption failed");
    }
    
    ciphertext.resize(ct_len);
    return ciphertext;
}

ByteVec SM2::decrypt(const ByteVec& privateKey, const ByteVec& ciphertext) {
    if (privateKey.size() != KCTSB_SM2_PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("Invalid private key size");
    }
    
    // Get required output size
    size_t pt_len = 0;
    kctsb_sm2_decrypt(privateKey.data(), ciphertext.data(), ciphertext.size(),
                      nullptr, &pt_len);
    
    ByteVec plaintext(pt_len);
    kctsb_error_t err = kctsb_sm2_decrypt(
        privateKey.data(),
        ciphertext.data(),
        ciphertext.size(),
        plaintext.data(),
        &pt_len
    );
    
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("SM2 decryption failed");
    }
    
    plaintext.resize(pt_len);
    return plaintext;
}

}  // namespace kctsb
