/**
 * @file fe256.h
 * @brief Self-Contained 256-bit Field Element Library for kctsb v5.0
 * 
 * Optimized 256-bit modular arithmetic for elliptic curve cryptography.
 * Used for secp256k1, P-256, SM2, Curve25519, and Ed25519.
 * 
 * Features:
 * - Montgomery multiplication with specialized reduction
 * - Curve-specific optimizations (Solinas reduction for P-256/SM2)
 * - Constant-time operations for side-channel resistance
 * - 4-limb representation (4 × 64-bit) for optimal performance
 * - x86_64 intrinsics for hardware acceleration
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CORE_FE256_H
#define KCTSB_CORE_FE256_H

#include <cstdint>
#include <cstring>
#include <array>

// Platform detection
#if defined(__SIZEOF_INT128__)
    #define KCTSB_HAS_INT128 1
    typedef unsigned __int128 uint128_t;
    typedef __int128 int128_t;
#elif defined(_MSC_VER) && defined(_M_X64)
    #define KCTSB_HAS_UMUL128 1
    #include <intrin.h>
#else
    #define KCTSB_NO_INT128 1
#endif

namespace kctsb {

// ============================================================================
// Fe256: 256-bit Field Element
// ============================================================================

/**
 * @brief 256-bit field element in 4-limb representation
 * 
 * Little-endian: limb[0] contains the least significant 64 bits.
 */
struct Fe256 {
    uint64_t limb[4];  ///< Four 64-bit limbs (256 bits total)
    
    // ========================================================================
    // Constructors
    // ========================================================================
    
    /**
     * @brief Default constructor - zero initialize
     */
    Fe256() : limb{0, 0, 0, 0} {}
    
    /**
     * @brief Construct from single 64-bit value
     */
    explicit Fe256(uint64_t val) : limb{val, 0, 0, 0} {}
    
    /**
     * @brief Construct from all four limbs
     */
    Fe256(uint64_t l0, uint64_t l1, uint64_t l2, uint64_t l3)
        : limb{l0, l1, l2, l3} {}
    
    /**
     * @brief Construct from byte array (big-endian)
     */
    explicit Fe256(const uint8_t* bytes) {
        from_bytes_be(bytes, 32);
    }
    
    // ========================================================================
    // Array-style Access
    // ========================================================================
    
    uint64_t& operator[](size_t i) { return limb[i]; }
    const uint64_t& operator[](size_t i) const { return limb[i]; }
    
    // ========================================================================
    // Byte Conversion
    // ========================================================================
    
    /**
     * @brief Convert from big-endian byte array
     */
    void from_bytes_be(const uint8_t* bytes, size_t len) {
        limb[0] = limb[1] = limb[2] = limb[3] = 0;
        
        size_t offset = (len > 32) ? (len - 32) : 0;
        size_t actual_len = (len > 32) ? 32 : len;
        
        for (size_t i = 0; i < actual_len; ++i) {
            size_t byte_idx = actual_len - 1 - i;
            size_t limb_idx = i / 8;
            size_t bit_offset = (i % 8) * 8;
            limb[limb_idx] |= static_cast<uint64_t>(bytes[offset + byte_idx]) << bit_offset;
        }
    }
    
    /**
     * @brief Convert to big-endian byte array
     */
    void to_bytes_be(uint8_t* bytes, size_t len) const {
        std::memset(bytes, 0, len);
        
        size_t start = (len > 32) ? (len - 32) : 0;
        size_t actual_len = (len > 32) ? 32 : len;
        
        for (size_t i = 0; i < actual_len; ++i) {
            size_t byte_idx = actual_len - 1 - i;
            size_t limb_idx = i / 8;
            size_t bit_offset = (i % 8) * 8;
            bytes[start + byte_idx] = static_cast<uint8_t>(limb[limb_idx] >> bit_offset);
        }
    }
    
    /**
     * @brief Convert from little-endian byte array
     */
    void from_bytes_le(const uint8_t* bytes, size_t len) {
        limb[0] = limb[1] = limb[2] = limb[3] = 0;
        
        size_t actual_len = (len > 32) ? 32 : len;
        for (size_t i = 0; i < actual_len; ++i) {
            size_t limb_idx = i / 8;
            size_t bit_offset = (i % 8) * 8;
            limb[limb_idx] |= static_cast<uint64_t>(bytes[i]) << bit_offset;
        }
    }
    
    /**
     * @brief Convert to little-endian byte array
     */
    void to_bytes_le(uint8_t* bytes, size_t len) const {
        std::memset(bytes, 0, len);
        
        size_t actual_len = (len > 32) ? 32 : len;
        for (size_t i = 0; i < actual_len; ++i) {
            size_t limb_idx = i / 8;
            size_t bit_offset = (i % 8) * 8;
            bytes[i] = static_cast<uint8_t>(limb[limb_idx] >> bit_offset);
        }
    }
    
    // ========================================================================
    // Basic Operations
    // ========================================================================
    
    /**
     * @brief Check if zero
     */
    bool is_zero() const {
        return (limb[0] | limb[1] | limb[2] | limb[3]) == 0;
    }
    
    /**
     * @brief Check if odd
     */
    bool is_odd() const {
        return (limb[0] & 1) != 0;
    }
    
    /**
     * @brief Set to zero
     */
    void zero() {
        limb[0] = limb[1] = limb[2] = limb[3] = 0;
    }
    
    /**
     * @brief Set to one
     */
    void one() {
        limb[0] = 1;
        limb[1] = limb[2] = limb[3] = 0;
    }
    
    /**
     * @brief Secure zero (not optimized away)
     */
    void secure_zero() {
        volatile uint64_t* p = limb;
        p[0] = p[1] = p[2] = p[3] = 0;
    }
    
    // ========================================================================
    // Comparison (constant-time)
    // ========================================================================
    
    /**
     * @brief Constant-time equality check
     */
    bool ct_equal(const Fe256& other) const {
        uint64_t diff = 0;
        diff |= limb[0] ^ other.limb[0];
        diff |= limb[1] ^ other.limb[1];
        diff |= limb[2] ^ other.limb[2];
        diff |= limb[3] ^ other.limb[3];
        return ((diff | (~diff + 1)) >> 63) ^ 1;
    }
    
    /**
     * @brief Constant-time less than (this < other)
     */
    bool ct_less_than(const Fe256& other) const {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t a = limb[i];
            uint64_t b = other.limb[i];
            uint64_t diff = a - b - borrow;
            borrow = (a < b) || (borrow && a == b) ? 1 : 0;
        }
        return borrow != 0;
    }
    
    bool operator==(const Fe256& other) const { return ct_equal(other); }
    bool operator!=(const Fe256& other) const { return !ct_equal(other); }
    bool operator<(const Fe256& other) const { return ct_less_than(other); }
    bool operator>=(const Fe256& other) const { return !ct_less_than(other); }
    
    // ========================================================================
    // Conditional Operations (constant-time)
    // ========================================================================
    
    /**
     * @brief Constant-time conditional move
     * If cond is true, set this = src
     */
    void ct_cmov(const Fe256& src, bool cond) {
        uint64_t mask = static_cast<uint64_t>(cond) - 1;  // 0 if true, 0xFF...FF if false
        mask = ~mask;  // 0xFF...FF if true, 0 if false
        for (int i = 0; i < 4; ++i) {
            limb[i] ^= mask & (limb[i] ^ src.limb[i]);
        }
    }
    
    /**
     * @brief Constant-time conditional swap
     */
    static void ct_cswap(Fe256& a, Fe256& b, bool cond) {
        uint64_t mask = static_cast<uint64_t>(cond) - 1;
        mask = ~mask;
        for (int i = 0; i < 4; ++i) {
            uint64_t diff = mask & (a.limb[i] ^ b.limb[i]);
            a.limb[i] ^= diff;
            b.limb[i] ^= diff;
        }
    }
};

// ============================================================================
// Fe512: 512-bit Intermediate for Multiplication
// ============================================================================

/**
 * @brief 512-bit intermediate result for wide multiplication
 */
struct Fe512 {
    uint64_t limb[8];
    
    Fe512() : limb{0, 0, 0, 0, 0, 0, 0, 0} {}
    
    uint64_t& operator[](size_t i) { return limb[i]; }
    const uint64_t& operator[](size_t i) const { return limb[i]; }
};

// ============================================================================
// 128-bit Arithmetic Helpers
// ============================================================================

namespace fe256_ops {

#ifdef KCTSB_HAS_INT128

/**
 * @brief 64x64 -> 128 bit multiplication
 */
inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t product = static_cast<uint128_t>(a) * b;
    *lo = static_cast<uint64_t>(product);
    *hi = static_cast<uint64_t>(product >> 64);
}

/**
 * @brief Add with carry
 */
inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint128_t sum = static_cast<uint128_t>(a) + b + carry_in;
    *carry_out = static_cast<uint64_t>(sum >> 64);
    return static_cast<uint64_t>(sum);
}

/**
 * @brief Subtract with borrow
 */
inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint128_t diff = static_cast<uint128_t>(a) - b - borrow_in;
    *borrow_out = (diff >> 64) != 0 ? 1 : 0;
    return static_cast<uint64_t>(diff);
}

#elif defined(KCTSB_HAS_UMUL128)

inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    *lo = _umul128(a, b, hi);
}

inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    unsigned char c;
    uint64_t sum;
    c = _addcarry_u64(static_cast<unsigned char>(carry_in), a, b, 
                      reinterpret_cast<unsigned long long*>(&sum));
    *carry_out = c;
    return sum;
}

inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    unsigned char c;
    uint64_t diff;
    c = _subborrow_u64(static_cast<unsigned char>(borrow_in), a, b,
                       reinterpret_cast<unsigned long long*>(&diff));
    *borrow_out = c;
    return diff;
}

#else

// Portable fallback
inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint32_t a0 = static_cast<uint32_t>(a);
    uint32_t a1 = static_cast<uint32_t>(a >> 32);
    uint32_t b0 = static_cast<uint32_t>(b);
    uint32_t b1 = static_cast<uint32_t>(b >> 32);
    
    uint64_t p00 = static_cast<uint64_t>(a0) * b0;
    uint64_t p01 = static_cast<uint64_t>(a0) * b1;
    uint64_t p10 = static_cast<uint64_t>(a1) * b0;
    uint64_t p11 = static_cast<uint64_t>(a1) * b1;
    
    uint64_t mid = p01 + p10 + (p00 >> 32);
    *lo = (p00 & 0xFFFFFFFF) | (mid << 32);
    *hi = p11 + (mid >> 32);
}

inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint64_t sum = a + b + carry_in;
    *carry_out = (sum < a) || (carry_in && sum == a) ? 1 : 0;
    return sum;
}

inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint64_t diff = a - b - borrow_in;
    *borrow_out = (a < b) || (borrow_in && a == b) ? 1 : 0;
    return diff;
}

#endif

// ============================================================================
// Basic Field Operations
// ============================================================================

/**
 * @brief Copy: dst = src
 */
inline void fe256_copy(Fe256* dst, const Fe256* src) {
    dst->limb[0] = src->limb[0];
    dst->limb[1] = src->limb[1];
    dst->limb[2] = src->limb[2];
    dst->limb[3] = src->limb[3];
}

/**
 * @brief Wide multiplication: r = a * b (256x256 -> 512 bit)
 */
inline void fe256_mul_wide(Fe512* r, const Fe256* a, const Fe256* b) {
    uint64_t hi, lo;
    uint64_t carry;
    
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
    acc1 += hi + carry;
    
    r->limb[6] = acc0;
    r->limb[7] = acc1;
}

/**
 * @brief Wide squaring: r = a^2 (256-bit -> 512-bit)
 */
inline void fe256_sqr_wide(Fe512* r, const Fe256* a) {
    // Use multiplication for now (can be optimized)
    fe256_mul_wide(r, a, a);
}

/**
 * @brief Addition: r = a + b (no reduction)
 * @return carry out
 */
inline uint64_t fe256_add(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t carry = 0;
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = adc64(a->limb[3], b->limb[3], carry, &carry);
    return carry;
}

/**
 * @brief Subtraction: r = a - b (no reduction)
 * @return borrow out
 */
inline uint64_t fe256_sub(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t borrow = 0;
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    return borrow;
}

} // namespace fe256_ops

// ============================================================================
// Curve-Specific Constants
// ============================================================================

/**
 * @brief secp256k1 prime: p = 2^256 - 2^32 - 977
 */
inline const Fe256& secp256k1_p() {
    static const Fe256 p(
        0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
    );
    return p;
}

/**
 * @brief P-256 (NIST) prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 */
inline const Fe256& p256_p() {
    static const Fe256 p(
        0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
        0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
    );
    return p;
}

/**
 * @brief SM2 prime: p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 */
inline const Fe256& sm2_p() {
    static const Fe256 p(
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
    );
    return p;
}

/**
 * @brief Curve25519 prime: p = 2^255 - 19
 */
inline const Fe256& curve25519_p() {
    static const Fe256 p(
        0xFFFFFFFFFFFFFFEDULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL
    );
    return p;
}

// ============================================================================
// Curve-Specific Reduction Functions
// ============================================================================

namespace fe256_reduce {

/**
 * @brief secp256k1 reduction: r = a mod p
 * 
 * Uses identity: 2^256 ≡ 2^32 + 977 (mod p)
 * c = 0x1000003D1 = 2^32 + 977
 */
void reduce_secp256k1(Fe256* r, const Fe512* a);

/**
 * @brief P-256 Solinas reduction: r = a mod p
 * 
 * Uses Solinas prime structure for efficient reduction.
 */
void reduce_p256(Fe256* r, const Fe512* a);

/**
 * @brief SM2 Solinas reduction: r = a mod p
 * 
 * Uses identity: 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
 */
void reduce_sm2(Fe256* r, const Fe512* a);

/**
 * @brief Generic Barrett reduction
 */
void reduce_generic(Fe256* r, const Fe512* a, const Fe256* p);

} // namespace fe256_reduce

// ============================================================================
// Montgomery Arithmetic for Fe256
// ============================================================================

/**
 * @brief Montgomery context for modular arithmetic
 */
struct Fe256MontContext {
    Fe256 p;        ///< Prime modulus
    Fe256 r2;       ///< R^2 mod p (for Montgomery conversion)
    uint64_t n0;    ///< -p^(-1) mod 2^64 (for Montgomery reduction)
    
    /**
     * @brief Initialize Montgomery context for a prime
     */
    void init(const Fe256& prime);
    
    /**
     * @brief Convert to Montgomery form
     */
    void to_montgomery(Fe256* r, const Fe256* a) const;
    
    /**
     * @brief Convert from Montgomery form
     */
    void from_montgomery(Fe256* r, const Fe256* a) const;
    
    /**
     * @brief Montgomery multiplication: r = a * b * R^(-1) mod p
     */
    void mul_montgomery(Fe256* r, const Fe256* a, const Fe256* b) const;
    
    /**
     * @brief Montgomery squaring: r = a^2 * R^(-1) mod p
     */
    void sqr_montgomery(Fe256* r, const Fe256* a) const;
    
    /**
     * @brief Modular exponentiation using Montgomery ladder
     */
    void pow_mod(Fe256* r, const Fe256* base, const Fe256* exp) const;
    
    /**
     * @brief Modular inverse using Fermat's little theorem
     */
    void inv_mod(Fe256* r, const Fe256* a) const;
};

} // namespace kctsb

#endif // KCTSB_CORE_FE256_H
