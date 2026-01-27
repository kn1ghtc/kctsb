/**
 * @file bigint.h
 * @brief Self-contained Big Integer Library for kctsb v5.0
 * 
 * Single-file big integer implementation for RSA, ECC, and other crypto primitives.
 * Referenced from GMP, OpenSSL, and GMssl implementations.
 * 
 * Features:
 * - 256/512/1024/2048/4096-bit fixed-size integers
 * - Montgomery multiplication for modular exponentiation
 * - Constant-time operations for side-channel resistance
 * - x86_64 SIMD acceleration (BMI2, ADX)
 * - No external dependencies
 * 
 * Design Principles:
 * - Single header + single implementation file
 * - Compile-time size selection via template parameter
 * - Memory-safe with automatic secure zeroing
 * 
 * @author knightc
 * @version 5.0.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CORE_BIGINT_H
#define KCTSB_CORE_BIGINT_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>

// Platform detection
#if defined(__x86_64__) || defined(_M_X64)
    #define KCTSB_BIGINT_X86_64 1
    #ifdef _MSC_VER
        #include <intrin.h>
    #else
        #include <x86intrin.h>
    #endif
#endif

#if defined(__SIZEOF_INT128__) || (defined(__GNUC__) && defined(__x86_64__))
    #define KCTSB_HAS_INT128 1
    typedef unsigned __int128 uint128_t;
#endif

namespace kctsb {

/**
 * @brief Word type for big integer limbs (64-bit)
 */
using limb_t = uint64_t;
using slimb_t = int64_t;

/**
 * @brief Double-precision type for multiplication
 */
#ifdef KCTSB_HAS_INT128
using dlimb_t = uint128_t;
#else
// Fallback: use struct for double-width operations
struct dlimb_t {
    uint64_t lo, hi;
};
#endif

/**
 * @brief Fixed-size big integer template
 * @tparam BITS Number of bits (must be multiple of 64)
 * 
 * Common sizes:
 * - BigInt<256>: For ECC (secp256k1, P-256, SM2)
 * - BigInt<512>: For intermediate products in ECC
 * - BigInt<2048>: For RSA-2048
 * - BigInt<4096>: For RSA-4096
 */
template<size_t BITS>
class BigInt {
    static_assert(BITS >= 64 && BITS % 64 == 0, "BITS must be a positive multiple of 64");
    
public:
    static constexpr size_t NUM_LIMBS = BITS / 64;
    static constexpr size_t BYTE_SIZE = BITS / 8;
    
private:
    alignas(32) std::array<limb_t, NUM_LIMBS> limbs_;
    
public:
    // ========================================================================
    // Constructors
    // ========================================================================
    
    /** @brief Default constructor - initializes to zero */
    BigInt() noexcept : limbs_{} {}
    
    /** @brief Construct from uint64_t */
    explicit BigInt(uint64_t value) noexcept : limbs_{} {
        limbs_[0] = value;
    }
    
    /** @brief Construct from hex string */
    explicit BigInt(const std::string& hex) : limbs_{} {
        from_hex(hex);
    }
    
    /** @brief Construct from byte array (big-endian) */
    BigInt(const uint8_t* data, size_t len) : limbs_{} {
        from_bytes(data, len);
    }
    
    /** @brief Copy constructor */
    BigInt(const BigInt& other) noexcept = default;
    
    /** @brief Move constructor */
    BigInt(BigInt&& other) noexcept = default;
    
    /** @brief Destructor - securely zeroes memory */
    ~BigInt() noexcept {
        secure_zero();
    }
    
    /** @brief Copy assignment */
    BigInt& operator=(const BigInt& other) noexcept = default;
    
    /** @brief Move assignment */
    BigInt& operator=(BigInt&& other) noexcept = default;
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    /** @brief Access limb (read-only) */
    limb_t operator[](size_t i) const noexcept { return limbs_[i]; }
    
    /** @brief Access limb (read-write) */
    limb_t& operator[](size_t i) noexcept { return limbs_[i]; }
    
    /** @brief Get raw limbs array */
    const limb_t* data() const noexcept { return limbs_.data(); }
    limb_t* data() noexcept { return limbs_.data(); }
    
    /** @brief Number of limbs */
    static constexpr size_t size() noexcept { return NUM_LIMBS; }
    
    /** @brief Check if zero */
    bool is_zero() const noexcept {
        limb_t acc = 0;
        for (size_t i = 0; i < NUM_LIMBS; ++i) {
            acc |= limbs_[i];
        }
        return acc == 0;
    }
    
    /** @brief Check if odd */
    bool is_odd() const noexcept { return limbs_[0] & 1; }
    
    /** @brief Get bit at position */
    bool get_bit(size_t pos) const noexcept {
        if (pos >= BITS) return false;
        return (limbs_[pos / 64] >> (pos % 64)) & 1;
    }
    
    /** @brief Set bit at position */
    void set_bit(size_t pos, bool value = true) noexcept {
        if (pos >= BITS) return;
        const size_t idx = pos / 64;
        // Explicit bounds check to help compiler optimization
        if (idx >= NUM_LIMBS) return;
        const limb_t mask = 1ULL << (pos % 64);
        if (value) {
            limbs_[idx] |= mask;
        } else {
            limbs_[idx] &= ~mask;
        }
    }
    
    /** @brief Number of significant bits */
    size_t num_bits() const noexcept {
        for (size_t i = NUM_LIMBS; i > 0; --i) {
            if (limbs_[i-1] != 0) {
                return (i - 1) * 64 + 64 - __builtin_clzll(limbs_[i-1]);
            }
        }
        return 0;
    }
    
    // ========================================================================
    // Serialization
    // ========================================================================
    
    /** @brief Convert to hex string */
    std::string to_hex() const {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(BITS / 4);
        
        bool started = false;
        for (size_t i = NUM_LIMBS; i > 0; --i) {
            limb_t v = limbs_[i-1];
            for (int j = 60; j >= 0; j -= 4) {
                int digit = (v >> j) & 0xF;
                if (digit != 0 || started) {
                    result += hex_chars[digit];
                    started = true;
                }
            }
        }
        return result.empty() ? "0" : result;
    }
    
    /** @brief Parse from hex string */
    void from_hex(const std::string& hex) {
        std::fill(limbs_.begin(), limbs_.end(), 0);
        
        size_t start = 0;
        if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
            start = 2;
        }
        
        size_t bit_pos = 0;
        for (size_t i = hex.size(); i > start && bit_pos < BITS; --i) {
            char c = hex[i-1];
            int digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else continue;
            
            limbs_[bit_pos / 64] |= static_cast<limb_t>(digit) << (bit_pos % 64);
            bit_pos += 4;
        }
    }
    
    /** @brief Convert to bytes (big-endian) */
    std::vector<uint8_t> to_bytes() const {
        std::vector<uint8_t> result(BYTE_SIZE);
        to_bytes(result.data(), BYTE_SIZE);
        return result;
    }
    
    /** @brief Convert to bytes (big-endian) into buffer */
    void to_bytes(uint8_t* out, size_t len) const {
        std::memset(out, 0, len);
        size_t offset = (len > BYTE_SIZE) ? (len - BYTE_SIZE) : 0;
        size_t copy_len = std::min(len, BYTE_SIZE);
        
        for (size_t i = 0; i < copy_len; ++i) {
            size_t byte_idx = BYTE_SIZE - 1 - i;
            out[offset + i] = static_cast<uint8_t>(limbs_[byte_idx / 8] >> ((byte_idx % 8) * 8));
        }
    }
    
    /** @brief Parse from bytes (big-endian) */
    void from_bytes(const uint8_t* data, size_t len) {
        std::fill(limbs_.begin(), limbs_.end(), 0);
        size_t copy_len = std::min(len, BYTE_SIZE);
        
        for (size_t i = 0; i < copy_len; ++i) {
            size_t byte_idx = copy_len - 1 - i;
            limbs_[byte_idx / 8] |= static_cast<limb_t>(data[i]) << ((byte_idx % 8) * 8);
        }
    }
    
    // ========================================================================
    // Arithmetic Operations
    // ========================================================================
    
    /** @brief Addition with carry, returns carry out */
    static limb_t add_with_carry(limb_t a, limb_t b, limb_t carry_in, limb_t& result) noexcept {
#ifdef KCTSB_BIGINT_X86_64
        // Use ADC intrinsic if available
        unsigned char carry = static_cast<unsigned char>(carry_in);
        carry = _addcarry_u64(carry, a, b, reinterpret_cast<unsigned long long*>(&result));
        return carry;
#else
        uint128_t sum = static_cast<uint128_t>(a) + b + carry_in;
        result = static_cast<limb_t>(sum);
        return static_cast<limb_t>(sum >> 64);
#endif
    }
    
    /** @brief Subtraction with borrow, returns borrow out */
    static limb_t sub_with_borrow(limb_t a, limb_t b, limb_t borrow_in, limb_t& result) noexcept {
#ifdef KCTSB_BIGINT_X86_64
        unsigned char borrow = static_cast<unsigned char>(borrow_in);
        borrow = _subborrow_u64(borrow, a, b, reinterpret_cast<unsigned long long*>(&result));
        return borrow;
#else
        uint128_t diff = static_cast<uint128_t>(a) - b - borrow_in;
        result = static_cast<limb_t>(diff);
        return (diff >> 127) & 1;  // Sign bit indicates borrow
#endif
    }
    
    /** @brief 64x64 -> 128 multiplication */
    static void mul64(limb_t a, limb_t b, limb_t& lo, limb_t& hi) noexcept {
#ifdef KCTSB_HAS_INT128
        uint128_t product = static_cast<uint128_t>(a) * b;
        lo = static_cast<limb_t>(product);
        hi = static_cast<limb_t>(product >> 64);
#elif defined(KCTSB_BIGINT_X86_64) && !defined(_MSC_VER)
        __asm__("mulq %3" : "=a"(lo), "=d"(hi) : "a"(a), "rm"(b));
#else
        // Fallback: split into 32-bit parts
        uint64_t a_lo = a & 0xFFFFFFFF, a_hi = a >> 32;
        uint64_t b_lo = b & 0xFFFFFFFF, b_hi = b >> 32;
        
        uint64_t p0 = a_lo * b_lo;
        uint64_t p1 = a_lo * b_hi;
        uint64_t p2 = a_hi * b_lo;
        uint64_t p3 = a_hi * b_hi;
        
        uint64_t carry = (p0 >> 32) + (p1 & 0xFFFFFFFF) + (p2 & 0xFFFFFFFF);
        lo = (p0 & 0xFFFFFFFF) | (carry << 32);
        hi = p3 + (p1 >> 32) + (p2 >> 32) + (carry >> 32);
#endif
    }
    
    /** @brief Addition: this += other, returns carry */
    limb_t add(const BigInt& other) noexcept {
        limb_t carry = 0;
        for (size_t i = 0; i < NUM_LIMBS; ++i) {
            carry = add_with_carry(limbs_[i], other.limbs_[i], carry, limbs_[i]);
        }
        return carry;
    }
    
    /** @brief Subtraction: this -= other, returns borrow */
    limb_t sub(const BigInt& other) noexcept {
        limb_t borrow = 0;
        for (size_t i = 0; i < NUM_LIMBS; ++i) {
            borrow = sub_with_borrow(limbs_[i], other.limbs_[i], borrow, limbs_[i]);
        }
        return borrow;
    }
    
    /** @brief Operator overloads */
    BigInt operator+(const BigInt& other) const {
        BigInt result = *this;
        result.add(other);
        return result;
    }
    
    BigInt operator-(const BigInt& other) const {
        BigInt result = *this;
        result.sub(other);
        return result;
    }
    
    BigInt& operator+=(const BigInt& other) {
        add(other);
        return *this;
    }
    
    BigInt& operator-=(const BigInt& other) {
        sub(other);
        return *this;
    }
    
    /** @brief Comparison */
    int compare(const BigInt& other) const noexcept {
        for (size_t i = NUM_LIMBS; i > 0; --i) {
            if (limbs_[i-1] > other.limbs_[i-1]) return 1;
            if (limbs_[i-1] < other.limbs_[i-1]) return -1;
        }
        return 0;
    }
    
    bool operator==(const BigInt& other) const noexcept { return compare(other) == 0; }
    bool operator!=(const BigInt& other) const noexcept { return compare(other) != 0; }
    bool operator<(const BigInt& other) const noexcept { return compare(other) < 0; }
    bool operator<=(const BigInt& other) const noexcept { return compare(other) <= 0; }
    bool operator>(const BigInt& other) const noexcept { return compare(other) > 0; }
    bool operator>=(const BigInt& other) const noexcept { return compare(other) >= 0; }
    
    /** @brief Left shift by bits */
    BigInt& operator<<=(size_t bits) noexcept {
        if (bits == 0) return *this;
        if (bits >= BITS) {
            std::fill(limbs_.begin(), limbs_.end(), 0);
            return *this;
        }
        
        size_t limb_shift = bits / 64;
        size_t bit_shift = bits % 64;
        
        if (bit_shift == 0) {
            for (size_t i = NUM_LIMBS - 1; i >= limb_shift; --i) {
                limbs_[i] = limbs_[i - limb_shift];
            }
        } else {
            for (size_t i = NUM_LIMBS - 1; i > limb_shift; --i) {
                limbs_[i] = (limbs_[i - limb_shift] << bit_shift) |
                            (limbs_[i - limb_shift - 1] >> (64 - bit_shift));
            }
            limbs_[limb_shift] = limbs_[0] << bit_shift;
        }
        
        for (size_t i = 0; i < limb_shift; ++i) {
            limbs_[i] = 0;
        }
        
        return *this;
    }
    
    /** @brief Right shift by bits */
    BigInt& operator>>=(size_t bits) noexcept {
        if (bits == 0) return *this;
        if (bits >= BITS) {
            std::fill(limbs_.begin(), limbs_.end(), 0);
            return *this;
        }
        
        size_t limb_shift = bits / 64;
        size_t bit_shift = bits % 64;
        
        if (bit_shift == 0) {
            for (size_t i = 0; i < NUM_LIMBS - limb_shift; ++i) {
                limbs_[i] = limbs_[i + limb_shift];
            }
        } else {
            for (size_t i = 0; i < NUM_LIMBS - limb_shift - 1; ++i) {
                limbs_[i] = (limbs_[i + limb_shift] >> bit_shift) |
                            (limbs_[i + limb_shift + 1] << (64 - bit_shift));
            }
            limbs_[NUM_LIMBS - limb_shift - 1] = limbs_[NUM_LIMBS - 1] >> bit_shift;
        }
        
        for (size_t i = NUM_LIMBS - limb_shift; i < NUM_LIMBS; ++i) {
            limbs_[i] = 0;
        }
        
        return *this;
    }
    
    BigInt operator<<(size_t bits) const {
        BigInt result = *this;
        result <<= bits;
        return result;
    }
    
    BigInt operator>>(size_t bits) const {
        BigInt result = *this;
        result >>= bits;
        return result;
    }
    
    // ========================================================================
    // Security
    // ========================================================================
    
    /** @brief Securely zero memory (prevents compiler optimization) */
    void secure_zero() noexcept {
        volatile limb_t* p = limbs_.data();
        for (size_t i = 0; i < NUM_LIMBS; ++i) {
            p[i] = 0;
        }
    }
    
    /** @brief Constant-time conditional swap */
    static void cswap(BigInt& a, BigInt& b, bool swap) noexcept {
        limb_t mask = swap ? ~static_cast<limb_t>(0) : 0;
        for (size_t i = 0; i < NUM_LIMBS; ++i) {
            limb_t t = mask & (a.limbs_[i] ^ b.limbs_[i]);
            a.limbs_[i] ^= t;
            b.limbs_[i] ^= t;
        }
    }
    
    /** @brief Constant-time select: returns a if select==0, b if select==1 */
    static BigInt cselect(const BigInt& a, const BigInt& b, bool select) noexcept {
        BigInt result;
        limb_t mask = select ? ~static_cast<limb_t>(0) : 0;
        for (size_t i = 0; i < NUM_LIMBS; ++i) {
            result.limbs_[i] = a.limbs_[i] ^ (mask & (a.limbs_[i] ^ b.limbs_[i]));
        }
        return result;
    }
};

// ============================================================================
// Type Aliases for Common Sizes
// ============================================================================

using BigInt256 = BigInt<256>;    // ECC: secp256k1, P-256, SM2
using BigInt384 = BigInt<384>;    // ECC: P-384
using BigInt512 = BigInt<512>;    // Intermediate products
using BigInt1024 = BigInt<1024>;  // RSA-1024 (legacy)
using BigInt2048 = BigInt<2048>;  // RSA-2048
using BigInt4096 = BigInt<4096>;  // RSA-4096

// ============================================================================
// Montgomery Arithmetic for Modular Exponentiation
// ============================================================================

/**
 * @brief Montgomery context for modular arithmetic
 * @tparam BITS Size of the modulus in bits
 */
template<size_t BITS>
class MontgomeryContext {
public:
    using Int = BigInt<BITS>;
    using WideInt = BigInt<BITS * 2>;
    
private:
    Int modulus_;       // n
    Int r_squared_;     // R^2 mod n (for Montgomery conversion)
    limb_t n_inv_;      // -n^(-1) mod 2^64
    
public:
    MontgomeryContext() = default;
    
    /** @brief Initialize with modulus */
    explicit MontgomeryContext(const Int& n) : modulus_(n) {
        // Compute n_inv = -n^(-1) mod 2^64 using Newton-Raphson
        limb_t n0 = n[0];
        limb_t inv = n0;  // Start with n (works because n is odd)
        
        // Newton-Raphson: inv = inv * (2 - n0 * inv)
        for (int i = 0; i < 6; ++i) {
            inv = inv * (2 - n0 * inv);
        }
        n_inv_ = -inv;  // We want -n^(-1), not n^(-1)
        
        // Compute R^2 mod n where R = 2^BITS
        // R^2 = (2^BITS)^2 = 2^(2*BITS)
        // We compute this by repeated squaring of R mod n
        WideInt r;
        r.set_bit(BITS);  // r = 2^BITS
        
        // r mod n (R mod n)
        Int r_mod_n = reduce_wide(r);
        
        // R^2 mod n = (R mod n)^2 mod n
        r_squared_ = mul_mod(r_mod_n, r_mod_n);
    }
    
    /** @brief Get modulus */
    const Int& modulus() const noexcept { return modulus_; }
    
    /** @brief Convert to Montgomery form: a * R mod n */
    Int to_montgomery(const Int& a) const {
        return mul_montgomery(a, r_squared_);
    }
    
    /** @brief Convert from Montgomery form: a * R^(-1) mod n */
    Int from_montgomery(const Int& a) const {
        Int one(1);
        return mul_montgomery(a, one);
    }
    
    /** @brief Montgomery multiplication: a * b * R^(-1) mod n */
    Int mul_montgomery(const Int& a, const Int& b) const {
        // CIOS (Coarsely Integrated Operand Scanning) algorithm
        WideInt t;
        
        for (size_t i = 0; i < Int::NUM_LIMBS; ++i) {
            // t = t + a[i] * b
            limb_t carry = 0;
            for (size_t j = 0; j < Int::NUM_LIMBS; ++j) {
                limb_t hi, lo;
                Int::mul64(a[i], b[j], lo, hi);
                
                limb_t c1, c2;
                c1 = Int::add_with_carry(t[i + j], lo, 0, t[i + j]);
                c2 = Int::add_with_carry(t[i + j], carry, 0, t[i + j]);
                carry = hi + c1 + c2;
            }
            t[i + Int::NUM_LIMBS] += carry;
            
            // Montgomery reduction step
            limb_t m = t[i] * n_inv_;
            carry = 0;
            for (size_t j = 0; j < Int::NUM_LIMBS; ++j) {
                limb_t hi, lo;
                Int::mul64(m, modulus_[j], lo, hi);
                
                limb_t c1, c2;
                c1 = Int::add_with_carry(t[i + j], lo, 0, t[i + j]);
                c2 = Int::add_with_carry(t[i + j], carry, 0, t[i + j]);
                carry = hi + c1 + c2;
            }
            
            // Propagate carry
            for (size_t j = Int::NUM_LIMBS; j < WideInt::NUM_LIMBS - i; ++j) {
                carry = Int::add_with_carry(t[i + j], carry, 0, t[i + j]);
                if (carry == 0) break;
            }
        }
        
        // Extract result (upper half)
        Int result;
        for (size_t i = 0; i < Int::NUM_LIMBS; ++i) {
            result[i] = t[i + Int::NUM_LIMBS];
        }
        
        // Conditional subtraction if result >= n
        Int diff = result;
        limb_t borrow = diff.sub(modulus_);
        return Int::cselect(diff, result, borrow != 0);
    }
    
    /** @brief Modular exponentiation using Montgomery ladder (constant-time) */
    Int pow_mod(const Int& base, const Int& exp) const {
        Int mont_base = to_montgomery(base);
        Int mont_one = to_montgomery(Int(1));
        
        Int r0 = mont_one;
        Int r1 = mont_base;
        
        // Find highest bit
        size_t bits = exp.num_bits();
        if (bits == 0) return Int(1);
        
        // Montgomery ladder (constant-time)
        for (size_t i = bits; i > 0; --i) {
            bool bit = exp.get_bit(i - 1);
            
            // Constant-time swap
            Int::cswap(r0, r1, bit);
            
            // Ladder step
            r1 = mul_montgomery(r0, r1);
            r0 = mul_montgomery(r0, r0);
            
            // Swap back
            Int::cswap(r0, r1, bit);
        }
        
        return from_montgomery(r0);
    }
    
private:
    /** 
     * @brief Reduce wide integer mod n using shift-and-subtract
     * 
     * For a 2*BITS-bit value a, computes a mod n where n is BITS bits.
     * Uses a simple but correct shift-and-subtract algorithm.
     * 
     * Algorithm: Process from high bit to low bit
     * - Maintain remainder r
     * - For each bit of a from high to low: r = 2*r + bit, then if r >= n, r -= n
     */
    Int reduce_wide(const WideInt& a) const {
        // Find highest set bit in a
        size_t top_bit = 0;
        for (size_t i = WideInt::NUM_LIMBS; i > 0; --i) {
            if (a[i-1] != 0) {
                top_bit = (i - 1) * 64 + 64 - __builtin_clzll(a[i-1]);
                break;
            }
        }
        
        if (top_bit == 0) {
            return Int();  // a is zero
        }
        
        // For small values that fit in BITS, just copy and reduce
        if (top_bit <= BITS) {
            Int result;
            for (size_t i = 0; i < Int::NUM_LIMBS; ++i) {
                result[i] = a[i];
            }
            while (result >= modulus_) {
                result.sub(modulus_);
            }
            return result;
        }
        
        // Shift-and-subtract algorithm for large values
        // Start with r = 0, then for each bit from top to bottom:
        // r = 2*r + bit(a, i), if r >= n then r -= n
        Int r;  // Remainder, starts at 0
        
        for (size_t i = top_bit; i > 0; --i) {
            // r = 2*r (shift left by 1)
            limb_t carry = 0;
            for (size_t j = 0; j < Int::NUM_LIMBS; ++j) {
                limb_t new_carry = r[j] >> 63;
                r[j] = (r[j] << 1) | carry;
                carry = new_carry;
            }
            
            // Add bit i-1 of a to r
            bool bit = a.get_bit(i - 1);
            if (bit) {
                limb_t add_carry = 0;
                add_carry = Int::add_with_carry(r[0], 1, 0, r[0]);
                for (size_t j = 1; j < Int::NUM_LIMBS && add_carry; ++j) {
                    add_carry = Int::add_with_carry(r[j], add_carry, 0, r[j]);
                }
            }
            
            // If r >= n, subtract n (constant-time would use cselect)
            if (r >= modulus_ || carry) {
                r.sub(modulus_);
            }
        }
        
        return r;
    }
    
    /** @brief Standard modular multiplication (for R^2 computation) */
    Int mul_mod(const Int& a, const Int& b) const {
        WideInt product;
        
        // Schoolbook multiplication
        for (size_t i = 0; i < Int::NUM_LIMBS; ++i) {
            limb_t carry = 0;
            for (size_t j = 0; j < Int::NUM_LIMBS; ++j) {
                limb_t hi, lo;
                Int::mul64(a[i], b[j], lo, hi);
                
                limb_t c1, c2;
                c1 = Int::add_with_carry(product[i + j], lo, 0, product[i + j]);
                c2 = Int::add_with_carry(product[i + j], carry, 0, product[i + j]);
                carry = hi + c1 + c2;
            }
            product[i + Int::NUM_LIMBS] += carry;
        }
        
        return reduce_wide(product);
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Generate random big integer
 * @tparam BITS Size in bits
 * @param rng Random number generator
 */
template<size_t BITS, typename RNG>
BigInt<BITS> random_bigint(RNG& rng) {
    BigInt<BITS> result;
    std::uniform_int_distribution<uint64_t> dist;
    for (size_t i = 0; i < BigInt<BITS>::NUM_LIMBS; ++i) {
        result[i] = dist(rng);
    }
    return result;
}

/**
 * @brief Generate random big integer in range [0, max)
 */
template<size_t BITS, typename RNG>
BigInt<BITS> random_bigint_mod(RNG& rng, const BigInt<BITS>& max) {
    BigInt<BITS> result;
    do {
        result = random_bigint<BITS>(rng);
        // Clear upper bits if max uses fewer bits
        size_t max_bits = max.num_bits();
        for (size_t i = max_bits; i < BITS; ++i) {
            result.set_bit(i, false);
        }
    } while (result >= max);
    return result;
}

/**
 * @brief Modular inverse using extended Euclidean algorithm
 * @return a^(-1) mod n, or zero if gcd(a, n) != 1
 */
template<size_t BITS>
BigInt<BITS> mod_inverse(const BigInt<BITS>& a, const BigInt<BITS>& n) {
    using Int = BigInt<BITS>;
    
    if (a.is_zero()) return Int();
    
    // Standard Extended Euclidean Algorithm
    // We compute gcd(a, n) and coefficients s, t such that:
    // a * s + n * t = gcd(a, n)
    // If gcd = 1, then s is the modular inverse of a mod n
    
    Int r0 = n, r1 = a;
    Int s0(0), s1(1);
    
    // Normalize r1 to be less than r0
    while (r1 >= r0) {
        r1 -= r0;
    }
    
    while (!r1.is_zero()) {
        // q = r0 / r1, r = r0 % r1
        Int q(0), r = r0;
        
        // Division: find q such that q * r1 <= r0 < (q+1) * r1
        // Binary search for quotient bit by bit
        Int temp = r1;
        Int temp_q(1);
        
        // Find the highest power of 2 where r1 * 2^k <= r0
        while (temp <= r) {
            Int doubled = temp;
            doubled <<= 1;
            if (doubled > r || doubled < temp) break;  // Overflow check
            temp = doubled;
            temp_q <<= 1;
        }
        
        // Subtract multiples of r1 from r
        while (temp >= r1 && !r.is_zero()) {
            if (r >= temp) {
                r -= temp;
                q += temp_q;
            }
            temp >>= 1;
            temp_q >>= 1;
        }
        
        // Update: r0 = r1, r1 = r, s0 = s1, s1 = s0 - q * s1
        r0 = r1;
        r1 = r;
        
        // Compute q * s1 mod n using double-and-add with overflow check
        Int qs(0);
        Int q_copy = q;
        Int s1_copy = s1;
        
        // Ensure s1_copy < n before starting
        while (s1_copy >= n) s1_copy -= n;
        
        // qs = q * s1 mod n using doubling
        while (!q_copy.is_zero()) {
            if (q_copy.is_odd()) {
                qs += s1_copy;
                while (qs >= n) qs -= n;
            }
            // Double s1_copy mod n - must check for overflow before shift
            // If s1_copy >= n/2, then 2*s1_copy >= n, so we need to handle
            // Actually, after shift, just reduce mod n
            bool high_bit = s1_copy[Int::NUM_LIMBS - 1] & (1ULL << 63);
            s1_copy <<= 1;
            if (high_bit || s1_copy >= n) {
                // s1_copy might have overflowed or be >= n
                while (s1_copy >= n) s1_copy -= n;
            }
            q_copy >>= 1;
        }
        
        // s_new = s0 - qs mod n
        Int s_new;
        if (s0 >= qs) {
            s_new = s0;
            s_new -= qs;
        } else {
            s_new = n;
            s_new -= qs;
            s_new += s0;
            while (s_new >= n) s_new -= n;
        }
        
        s0 = s1;
        s1 = s_new;
    }
    
    // gcd is r0, inverse is s0 if gcd = 1
    Int one(1);
    if (r0 == one) {
        return s0;
    }
    
    return Int();  // No inverse exists (gcd != 1)
}

} // namespace kctsb

#endif // KCTSB_CORE_BIGINT_H
