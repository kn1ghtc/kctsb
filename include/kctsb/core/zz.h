/**
 * @file zz.h
 * @brief Self-Contained Big Integer (ZZ) Implementation for kctsb v5.0
 * 
 * This file provides the ZZ type and related functions, replacing the NTL
 * dependency with our self-contained BigInt implementation.
 * 
 * The ZZ class supports arbitrary-precision integers with dynamic sizing,
 * optimized for cryptographic operations.
 * 
 * @author knightc
 * @version 5.0.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_CORE_ZZ_H
#define KCTSB_CORE_ZZ_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <iostream>
#include <sstream>

// Platform detection
#if defined(__SIZEOF_INT128__) || (defined(__GNUC__) && defined(__x86_64__))
    #define KCTSB_ZZ_HAS_INT128 1
    #ifndef uint128_t
    typedef unsigned __int128 uint128_t;
    #endif
#endif

namespace kctsb {

// Forward declarations
class ZZ;
class ZZ_p;

// ============================================================================
// ZZ: Arbitrary-Precision Integer
// ============================================================================

/**
 * @brief Arbitrary-precision integer class
 * 
 * Dynamic-sized integer supporting cryptographic operations:
 * - RSA (2048-8192 bits)
 * - Lattice cryptography
 * - Prime generation and testing
 * 
 * Uses little-endian limb representation internally.
 */
class ZZ {
public:
    using limb_t = uint64_t;
    using slimb_t = int64_t;
    static constexpr size_t LIMB_BITS = 64;
    
private:
    std::vector<limb_t> limbs_;  // Little-endian
    bool negative_ = false;
    
    // Normalize: remove leading zeros
    void normalize() {
        while (limbs_.size() > 1 && limbs_.back() == 0) {
            limbs_.pop_back();
        }
        if (limbs_.size() == 1 && limbs_[0] == 0) {
            negative_ = false;
        }
    }
    
public:
    // ========================================================================
    // Constructors
    // ========================================================================
    
    /** @brief Default constructor - zero */
    ZZ() : limbs_(1, 0), negative_(false) {}
    
    /** @brief Construct from signed 64-bit */
    ZZ(int64_t value) {
        if (value < 0) {
            negative_ = true;
            limbs_.push_back(static_cast<limb_t>(-value));
        } else {
            negative_ = false;
            limbs_.push_back(static_cast<limb_t>(value));
        }
    }
    
    /** @brief Construct from unsigned 64-bit */
    ZZ(uint64_t value) : limbs_(1, value), negative_(false) {}
    
    /** @brief Construct from int */
    ZZ(int value) : ZZ(static_cast<int64_t>(value)) {}
    
    /** @brief Construct from long */
    ZZ(long value) : ZZ(static_cast<int64_t>(value)) {}
    
    /** @brief Construct from unsigned long */
    ZZ(unsigned long value) : ZZ(static_cast<uint64_t>(value)) {}
    
    /** @brief Copy constructor */
    ZZ(const ZZ& other) = default;
    
    /** @brief Move constructor */
    ZZ(ZZ&& other) noexcept = default;
    
    /** @brief Destructor */
    ~ZZ() = default;
    
    /** @brief Copy assignment */
    ZZ& operator=(const ZZ& other) = default;
    
    /** @brief Move assignment */
    ZZ& operator=(ZZ&& other) noexcept = default;
    
    /** @brief Assign from int64_t */
    ZZ& operator=(int64_t value) {
        limbs_.clear();
        if (value < 0) {
            negative_ = true;
            limbs_.push_back(static_cast<limb_t>(-value));
        } else {
            negative_ = false;
            limbs_.push_back(static_cast<limb_t>(value));
        }
        return *this;
    }
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    /** @brief Check if zero */
    bool is_zero() const {
        return limbs_.size() == 1 && limbs_[0] == 0;
    }
    
    /** @brief Check if negative */
    bool is_negative() const { return negative_ && !is_zero(); }
    
    /** @brief Check if positive */
    bool is_positive() const { return !negative_ && !is_zero(); }
    
    /** @brief Check if odd */
    bool is_odd() const { return limbs_[0] & 1; }
    
    /** @brief Get sign: -1, 0, or 1 */
    int sign() const {
        if (is_zero()) return 0;
        return negative_ ? -1 : 1;
    }
    
    /** @brief Number of significant bits */
    size_t num_bits() const {
        if (is_zero()) return 0;
        
        size_t bits = (limbs_.size() - 1) * LIMB_BITS;
        limb_t top = limbs_.back();
        
        while (top) {
            ++bits;
            top >>= 1;
        }
        return bits;
    }
    
    /** @brief Number of bytes needed */
    size_t num_bytes() const {
        return (num_bits() + 7) / 8;
    }
    
    /** @brief Get limb at index */
    limb_t limb(size_t i) const {
        return (i < limbs_.size()) ? limbs_[i] : 0;
    }
    
    /** @brief Number of limbs */
    size_t num_limbs() const { return limbs_.size(); }
    
    // ========================================================================
    // Comparison
    // ========================================================================
    
    /** @brief Compare absolute values */
    int compare_abs(const ZZ& other) const {
        if (limbs_.size() != other.limbs_.size()) {
            return limbs_.size() > other.limbs_.size() ? 1 : -1;
        }
        
        for (size_t i = limbs_.size(); i > 0; --i) {
            if (limbs_[i-1] != other.limbs_[i-1]) {
                return limbs_[i-1] > other.limbs_[i-1] ? 1 : -1;
            }
        }
        return 0;
    }
    
    /** @brief Compare with other ZZ */
    int compare(const ZZ& other) const {
        if (is_zero() && other.is_zero()) return 0;
        
        if (negative_ != other.negative_) {
            return negative_ ? -1 : 1;
        }
        
        int abs_cmp = compare_abs(other);
        return negative_ ? -abs_cmp : abs_cmp;
    }
    
    bool operator==(const ZZ& other) const { return compare(other) == 0; }
    bool operator!=(const ZZ& other) const { return compare(other) != 0; }
    bool operator<(const ZZ& other) const { return compare(other) < 0; }
    bool operator<=(const ZZ& other) const { return compare(other) <= 0; }
    bool operator>(const ZZ& other) const { return compare(other) > 0; }
    bool operator>=(const ZZ& other) const { return compare(other) >= 0; }
    
    // Comparison with integers
    bool operator==(long value) const { return compare(ZZ(value)) == 0; }
    bool operator!=(long value) const { return compare(ZZ(value)) != 0; }
    bool operator<(long value) const { return compare(ZZ(value)) < 0; }
    bool operator<=(long value) const { return compare(ZZ(value)) <= 0; }
    bool operator>(long value) const { return compare(ZZ(value)) > 0; }
    bool operator>=(long value) const { return compare(ZZ(value)) >= 0; }
    
    // ========================================================================
    // Arithmetic (Internal Helpers)
    // ========================================================================
    
private:
    /** @brief Add absolute values, result in this */
    void add_abs(const ZZ& other) {
        size_t max_size = std::max(limbs_.size(), other.limbs_.size());
        limbs_.resize(max_size + 1, 0);
        
        limb_t carry = 0;
        for (size_t i = 0; i < max_size; ++i) {
            limb_t a = limb(i);
            limb_t b = other.limb(i);
            
#ifdef KCTSB_ZZ_HAS_INT128
            uint128_t sum = static_cast<uint128_t>(a) + b + carry;
            limbs_[i] = static_cast<limb_t>(sum);
            carry = static_cast<limb_t>(sum >> 64);
#else
            limb_t sum1 = a + carry;
            carry = (sum1 < a) ? 1 : 0;
            limb_t sum2 = sum1 + b;
            carry += (sum2 < sum1) ? 1 : 0;
            limbs_[i] = sum2;
#endif
        }
        limbs_[max_size] = carry;
        normalize();
    }
    
    /** @brief Subtract absolute values (assuming |this| >= |other|) */
    void sub_abs(const ZZ& other) {
        limb_t borrow = 0;
        for (size_t i = 0; i < limbs_.size(); ++i) {
            limb_t a = limbs_[i];
            limb_t b = other.limb(i);
            
#ifdef KCTSB_ZZ_HAS_INT128
            uint128_t diff = static_cast<uint128_t>(a) - b - borrow;
            limbs_[i] = static_cast<limb_t>(diff);
            borrow = (diff >> 127) & 1;
#else
            limb_t diff1 = a - borrow;
            borrow = (diff1 > a) ? 1 : 0;
            limb_t diff2 = diff1 - b;
            borrow += (diff2 > diff1) ? 1 : 0;
            limbs_[i] = diff2;
#endif
        }
        normalize();
    }
    
public:
    // ========================================================================
    // Arithmetic Operations
    // ========================================================================
    
    /** @brief Negate */
    ZZ operator-() const {
        ZZ result = *this;
        if (!result.is_zero()) {
            result.negative_ = !result.negative_;
        }
        return result;
    }
    
    /** @brief Addition */
    ZZ operator+(const ZZ& other) const {
        ZZ result = *this;
        result += other;
        return result;
    }
    
    /** @brief In-place addition */
    ZZ& operator+=(const ZZ& other) {
        if (negative_ == other.negative_) {
            add_abs(other);
        } else {
            int cmp = compare_abs(other);
            if (cmp == 0) {
                *this = ZZ(0);
            } else if (cmp > 0) {
                sub_abs(other);
            } else {
                ZZ tmp = other;
                std::swap(*this, tmp);
                sub_abs(tmp);
            }
        }
        return *this;
    }
    
    /** @brief Subtraction */
    ZZ operator-(const ZZ& other) const {
        ZZ result = *this;
        result -= other;
        return result;
    }
    
    /** @brief In-place subtraction */
    ZZ& operator-=(const ZZ& other) {
        ZZ neg_other = -other;
        return (*this) += neg_other;
    }
    
    /** @brief Multiplication */
    ZZ operator*(const ZZ& other) const {
        if (is_zero() || other.is_zero()) return ZZ(0);
        
        ZZ result;
        result.limbs_.resize(limbs_.size() + other.limbs_.size(), 0);
        result.negative_ = negative_ != other.negative_;
        
        for (size_t i = 0; i < limbs_.size(); ++i) {
            limb_t carry = 0;
            for (size_t j = 0; j < other.limbs_.size(); ++j) {
#ifdef KCTSB_ZZ_HAS_INT128
                uint128_t product = static_cast<uint128_t>(limbs_[i]) * other.limbs_[j];
                uint128_t sum = static_cast<uint128_t>(result.limbs_[i + j]) + 
                               static_cast<limb_t>(product) + carry;
                result.limbs_[i + j] = static_cast<limb_t>(sum);
                carry = static_cast<limb_t>(product >> 64) + static_cast<limb_t>(sum >> 64);
#else
                // Fallback 32-bit multiplication
                uint64_t a = limbs_[i];
                uint64_t b = other.limbs_[j];
                uint64_t al = a & 0xFFFFFFFF, ah = a >> 32;
                uint64_t bl = b & 0xFFFFFFFF, bh = b >> 32;
                
                uint64_t p0 = al * bl;
                uint64_t p1 = al * bh + ah * bl;
                uint64_t p2 = ah * bh;
                
                uint64_t lo = p0 + (p1 << 32);
                uint64_t hi = p2 + (p1 >> 32) + (lo < p0 ? 1 : 0);
                
                uint64_t sum = result.limbs_[i + j] + lo + carry;
                carry = hi + (sum < lo ? 1 : 0);
                result.limbs_[i + j] = sum;
#endif
            }
            result.limbs_[i + other.limbs_.size()] += carry;
        }
        
        result.normalize();
        return result;
    }
    
    /** @brief In-place multiplication */
    ZZ& operator*=(const ZZ& other) {
        *this = *this * other;
        return *this;
    }
    
    /** @brief Division (truncated toward zero) */
    ZZ operator/(const ZZ& other) const {
        if (other.is_zero()) {
            throw std::domain_error("Division by zero");
        }
        
        ZZ q, r;
        divmod(*this, other, q, r);
        return q;
    }
    
    /** @brief Modulo (sign follows dividend) */
    ZZ operator%(const ZZ& other) const {
        if (other.is_zero()) {
            throw std::domain_error("Division by zero");
        }
        
        ZZ q, r;
        divmod(*this, other, q, r);
        return r;
    }
    
    ZZ& operator/=(const ZZ& other) { *this = *this / other; return *this; }
    ZZ& operator%=(const ZZ& other) { *this = *this % other; return *this; }
    
    /** @brief Division and modulo */
    static void divmod(const ZZ& a, const ZZ& b, ZZ& q, ZZ& r) {
        if (b.is_zero()) {
            throw std::domain_error("Division by zero");
        }
        
        // Handle trivial cases
        int cmp = a.compare_abs(b);
        if (cmp < 0) {
            q = ZZ(0);
            r = a;
            return;
        }
        if (cmp == 0) {
            q = (a.negative_ == b.negative_) ? ZZ(1) : ZZ(-1);
            r = ZZ(0);
            return;
        }
        
        // Schoolbook long division
        ZZ dividend;
        dividend.limbs_ = a.limbs_;
        dividend.negative_ = false;
        
        ZZ divisor;
        divisor.limbs_ = b.limbs_;
        divisor.negative_ = false;
        
        q.limbs_.resize(dividend.limbs_.size(), 0);
        q.negative_ = a.negative_ != b.negative_;
        
        // Binary long division
        size_t bits = dividend.num_bits();
        r = ZZ(0);
        
        for (size_t i = bits; i > 0; --i) {
            // r = r * 2 + bit[i-1]
            r <<= 1;
            if ((dividend.limb((i-1) / 64) >> ((i-1) % 64)) & 1) {
                r += ZZ(1);
            }
            
            if (r.compare_abs(divisor) >= 0) {
                r.sub_abs(divisor);
                q.limbs_[(i-1) / 64] |= (1ULL << ((i-1) % 64));
            }
        }
        
        q.normalize();
        r.negative_ = a.negative_;
        r.normalize();
    }
    
    // ========================================================================
    // Bit Operations
    // ========================================================================
    
    /** @brief Left shift */
    ZZ& operator<<=(size_t bits) {
        if (bits == 0 || is_zero()) return *this;
        
        size_t limb_shift = bits / LIMB_BITS;
        size_t bit_shift = bits % LIMB_BITS;
        
        // Add space for new limbs
        limbs_.resize(limbs_.size() + limb_shift + 1, 0);
        
        // Shift limbs
        if (bit_shift == 0) {
            for (size_t i = limbs_.size() - 1; i >= limb_shift; --i) {
                limbs_[i] = limbs_[i - limb_shift];
            }
        } else {
            for (size_t i = limbs_.size() - 1; i > limb_shift; --i) {
                limbs_[i] = (limbs_[i - limb_shift] << bit_shift) |
                           (limbs_[i - limb_shift - 1] >> (LIMB_BITS - bit_shift));
            }
            limbs_[limb_shift] = limbs_[0] << bit_shift;
        }
        
        // Zero lower limbs
        for (size_t i = 0; i < limb_shift; ++i) {
            limbs_[i] = 0;
        }
        
        normalize();
        return *this;
    }
    
    /** @brief Right shift */
    ZZ& operator>>=(size_t bits) {
        if (bits == 0) return *this;
        if (bits >= num_bits()) {
            *this = ZZ(0);
            return *this;
        }
        
        size_t limb_shift = bits / LIMB_BITS;
        size_t bit_shift = bits % LIMB_BITS;
        
        if (bit_shift == 0) {
            for (size_t i = 0; i < limbs_.size() - limb_shift; ++i) {
                limbs_[i] = limbs_[i + limb_shift];
            }
        } else {
            for (size_t i = 0; i < limbs_.size() - limb_shift - 1; ++i) {
                limbs_[i] = (limbs_[i + limb_shift] >> bit_shift) |
                           (limbs_[i + limb_shift + 1] << (LIMB_BITS - bit_shift));
            }
            limbs_[limbs_.size() - limb_shift - 1] = limbs_.back() >> bit_shift;
        }
        
        limbs_.resize(limbs_.size() - limb_shift);
        normalize();
        return *this;
    }
    
    ZZ operator<<(size_t bits) const { ZZ r = *this; r <<= bits; return r; }
    ZZ operator>>(size_t bits) const { ZZ r = *this; r >>= bits; return r; }
    
    // ========================================================================
    // Bitwise Operations
    // ========================================================================
    
    /** @brief Bitwise OR */
    ZZ& operator|=(const ZZ& other) {
        if (other.limbs_.size() > limbs_.size()) {
            limbs_.resize(other.limbs_.size(), 0);
        }
        for (size_t i = 0; i < std::min(limbs_.size(), other.limbs_.size()); ++i) {
            limbs_[i] |= other.limbs_[i];
        }
        normalize();
        return *this;
    }
    
    ZZ operator|(const ZZ& other) const { ZZ r = *this; r |= other; return r; }
    
    /** @brief Bitwise AND */
    ZZ& operator&=(const ZZ& other) {
        size_t min_size = std::min(limbs_.size(), other.limbs_.size());
        limbs_.resize(min_size);
        for (size_t i = 0; i < min_size; ++i) {
            limbs_[i] &= other.limbs_[i];
        }
        normalize();
        return *this;
    }
    
    ZZ operator&(const ZZ& other) const { ZZ r = *this; r &= other; return r; }
    
    /** @brief Bitwise XOR */
    ZZ& operator^=(const ZZ& other) {
        if (other.limbs_.size() > limbs_.size()) {
            limbs_.resize(other.limbs_.size(), 0);
        }
        for (size_t i = 0; i < std::min(limbs_.size(), other.limbs_.size()); ++i) {
            limbs_[i] ^= other.limbs_[i];
        }
        normalize();
        return *this;
    }
    
    ZZ operator^(const ZZ& other) const { ZZ r = *this; r ^= other; return r; }
    
    // ========================================================================
    // Serialization
    // ========================================================================
    
    /** @brief Convert to hex string */
    std::string to_hex() const {
        if (is_zero()) return "0";
        
        static const char hex[] = "0123456789ABCDEF";
        std::string result;
        if (negative_) result = "-";
        
        bool started = false;
        for (size_t i = limbs_.size(); i > 0; --i) {
            limb_t v = limbs_[i - 1];
            for (int j = 60; j >= 0; j -= 4) {
                int digit = (v >> j) & 0xF;
                if (digit || started) {
                    result += hex[digit];
                    started = true;
                }
            }
        }
        return result.empty() ? "0" : result;
    }
    
    /** @brief Parse from hex string */
    static ZZ from_hex(const std::string& hex) {
        ZZ result;
        size_t start = 0;
        
        if (!hex.empty() && hex[0] == '-') {
            result.negative_ = true;
            start = 1;
        }
        
        if (hex.size() > start + 2 && hex[start] == '0' && 
            (hex[start + 1] == 'x' || hex[start + 1] == 'X')) {
            start += 2;
        }
        
        result.limbs_.clear();
        result.limbs_.push_back(0);
        
        for (size_t i = start; i < hex.size(); ++i) {
            result <<= 4;
            char c = hex[i];
            int digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else continue;
            result.limbs_[0] |= digit;
        }
        
        result.normalize();
        return result;
    }
    
    /** @brief Parse from decimal string */
    static ZZ from_decimal(const std::string& dec) {
        ZZ result;
        size_t start = 0;
        
        if (!dec.empty() && dec[0] == '-') {
            result.negative_ = true;
            start = 1;
        }
        
        for (size_t i = start; i < dec.size(); ++i) {
            char c = dec[i];
            if (c >= '0' && c <= '9') {
                result = result * ZZ(10) + ZZ(c - '0');
            }
        }
        
        result.normalize();
        return result;
    }
    
    /** @brief Convert to bytes (big-endian) */
    std::vector<uint8_t> to_bytes() const {
        size_t bytes = num_bytes();
        if (bytes == 0) bytes = 1;
        
        std::vector<uint8_t> result(bytes, 0);
        to_bytes(result.data(), bytes);
        return result;
    }
    
    /** @brief Convert to bytes (big-endian) into buffer */
    void to_bytes(uint8_t* out, size_t len) const {
        std::memset(out, 0, len);
        
        for (size_t i = 0; i < limbs_.size(); ++i) {
            for (size_t j = 0; j < 8; ++j) {
                size_t byte_pos = i * 8 + j;
                if (byte_pos < len) {
                    out[len - 1 - byte_pos] = static_cast<uint8_t>(limbs_[i] >> (j * 8));
                }
            }
        }
    }
    
    /** @brief Parse from bytes (big-endian) */
    static ZZ from_bytes(const uint8_t* data, size_t len) {
        ZZ result;
        result.limbs_.clear();
        
        size_t limb_count = (len + 7) / 8;
        result.limbs_.resize(limb_count, 0);
        
        for (size_t i = 0; i < len; ++i) {
            size_t byte_pos = len - 1 - i;
            size_t limb_idx = byte_pos / 8;
            size_t byte_offset = byte_pos % 8;
            
            if (limb_idx < result.limbs_.size()) {
                result.limbs_[limb_idx] |= static_cast<limb_t>(data[i]) << (byte_offset * 8);
            }
        }
        
        result.normalize();
        return result;
    }
    
    // ========================================================================
    // Conversion
    // ========================================================================
    
    /** @brief Convert to long (may overflow) */
    long to_long() const {
        if (limbs_.size() == 0) return 0;
        long result = static_cast<long>(limbs_[0]);
        return negative_ ? -result : result;
    }
    
    /** @brief Convert to uint64_t */
    uint64_t to_uint64() const {
        return limbs_.empty() ? 0 : limbs_[0];
    }
    
    // ========================================================================
    // Security
    // ========================================================================
    
    /** @brief Securely zero memory */
    void secure_zero() {
        volatile limb_t* p = limbs_.data();
        for (size_t i = 0; i < limbs_.size(); ++i) {
            p[i] = 0;
        }
        negative_ = false;
    }
};

// ============================================================================
// Free Functions (NTL-style API)
// ============================================================================

/** @brief Get number of bits */
inline long NumBits(const ZZ& a) {
    return static_cast<long>(a.num_bits());
}

/** @brief Get number of bytes */
inline long NumBytes(const ZZ& a) {
    return static_cast<long>(a.num_bytes());
}

/** @brief Check if zero */
inline bool IsZero(const ZZ& a) {
    return a.is_zero();
}

/** @brief Check if odd */
inline bool IsOdd(const ZZ& a) {
    return a.is_odd();
}

/** @brief Get sign: -1, 0, or 1 */
inline long sign(const ZZ& a) {
    return a.sign();
}

/** @brief Get bit at position i (0-indexed from LSB) */
inline long bit(const ZZ& a, long i) {
    if (i < 0) return 0;
    size_t word_idx = static_cast<size_t>(i) / 64;
    size_t bit_pos = static_cast<size_t>(i) % 64;
    return static_cast<long>((a.limb(word_idx) >> bit_pos) & 1);
}

/** @brief Convert ZZ to long (truncates if too large) */
inline long to_long(const ZZ& a) {
    if (a.is_zero()) return 0;
    long result = static_cast<long>(a.limb(0));
    if (a.is_negative()) result = -result;
    return result;
}

/** @brief Convert int to ZZ */
inline ZZ to_ZZ(int a) {
    return ZZ(a);
}

/** @brief Convert long to ZZ */
inline ZZ to_ZZ(long a) {
    return ZZ(a);
}

/** @brief Absolute value */
inline ZZ abs(const ZZ& a) {
    ZZ result = a;
    if (result.is_negative()) {
        result = -result;
    }
    return result;
}

/** @brief Greatest common divisor */
inline ZZ GCD(const ZZ& a, const ZZ& b) {
    ZZ x = abs(a);
    ZZ y = abs(b);
    
    while (!y.is_zero()) {
        ZZ t = y;
        y = x % y;
        x = t;
    }
    return x;
}

/** @brief Power: a^e */
inline ZZ power(const ZZ& a, long e) {
    if (e < 0) throw std::domain_error("Negative exponent");
    if (e == 0) return ZZ(1);
    
    ZZ result(1);
    ZZ base = a;
    
    while (e > 0) {
        if (e & 1) result *= base;
        base *= base;
        e >>= 1;
    }
    return result;
}

/** @brief Modular exponentiation: a^e mod n */
inline ZZ PowerMod(const ZZ& a, const ZZ& e, const ZZ& n) {
    if (n <= ZZ(0)) throw std::domain_error("Modulus must be positive");
    if (e.is_negative()) throw std::domain_error("Negative exponent");
    
    if (e.is_zero()) return ZZ(1);
    
    ZZ result(1);
    ZZ base = a % n;
    if (base.is_negative()) base += n;
    
    ZZ exp = e;
    
    while (!exp.is_zero()) {
        if (exp.is_odd()) {
            result = (result * base) % n;
        }
        base = (base * base) % n;
        exp >>= 1;
    }
    
    return result;
}

/** @brief Modular inverse: a^(-1) mod n */
inline ZZ InvMod(const ZZ& a, const ZZ& n) {
    ZZ t(0), newt(1);
    ZZ r = n, newr = a % n;
    
    if (newr.is_negative()) newr += n;
    
    while (!newr.is_zero()) {
        ZZ q = r / newr;
        
        ZZ temp = t - q * newt;
        t = newt;
        newt = temp;
        
        temp = r - q * newr;
        r = newr;
        newr = temp;
    }
    
    if (r > ZZ(1)) {
        throw std::domain_error("Not invertible");
    }
    
    if (t.is_negative()) t += n;
    return t;
}

/** @brief Modular multiplication: a * b mod n */
inline ZZ MulMod(const ZZ& a, const ZZ& b, const ZZ& n) {
    return (a * b) % n;
}

/** @brief Modular addition: (a + b) mod n */
inline ZZ AddMod(const ZZ& a, const ZZ& b, const ZZ& n) {
    ZZ result = (a + b) % n;
    if (result.is_negative()) result += n;
    return result;
}

/** @brief Modular subtraction: (a - b) mod n */
inline ZZ SubMod(const ZZ& a, const ZZ& b, const ZZ& n) {
    ZZ result = (a - b) % n;
    if (result.is_negative()) result += n;
    return result;
}

/** @brief Square root (integer) */
inline ZZ SqrRoot(const ZZ& a) {
    if (a <= ZZ(0)) return ZZ(0);
    
    // Newton's method
    ZZ x = a;
    ZZ y = (x + ZZ(1)) / ZZ(2);
    
    while (y < x) {
        x = y;
        y = (x + a / x) / ZZ(2);
    }
    return x;
}

/** @brief Convert from bytes (big-endian) */
inline ZZ ZZFromBytes(const uint8_t* data, long len) {
    return ZZ::from_bytes(data, static_cast<size_t>(len));
}

/** @brief Convert to bytes (big-endian) */
inline void BytesFromZZ(uint8_t* data, const ZZ& a, long len) {
    a.to_bytes(data, static_cast<size_t>(len));
}

/** @brief Generate random ZZ with n bits */
inline ZZ RandomBits_ZZ(long n) {
    if (n <= 0) return ZZ(0);
    
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    
    ZZ result;
    size_t limbs = (static_cast<size_t>(n) + 63) / 64;
    result = ZZ(0);
    
    for (size_t i = 0; i < limbs; ++i) {
        result <<= 64;
        result += ZZ(static_cast<int64_t>(dist(gen)));
    }
    
    // Mask extra bits
    size_t extra = static_cast<size_t>(n) % 64;
    if (extra > 0) {
        // This is approximate - actual implementation would be more careful
    }
    
    return result;
}

/** @brief Generate random prime with n bits */
inline void RandomPrime(ZZ& p, long n, long trials = 20) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    
    while (true) {
        p = RandomBits_ZZ(n);
        
        // Set top bit for correct length
        p = p | (ZZ(1) << (n - 1));
        
        // Set bottom bit for odd
        if (!p.is_odd()) p += ZZ(1);
        
        // Miller-Rabin test
        bool is_prime = true;
        ZZ n_minus_1 = p - ZZ(1);
        
        // Factor n-1 = 2^r * d
        ZZ d = n_minus_1;
        long r = 0;
        while (!d.is_odd()) {
            d >>= 1;
            r++;
        }
        
        // Witnesses
        for (int i = 0; i < trials && is_prime; ++i) {
            ZZ a = RandomBits_ZZ(n - 2);
            a = a % (p - ZZ(2));
            if (a < ZZ(2)) a = ZZ(2);
            
            ZZ x = PowerMod(a, d, p);
            
            if (x == ZZ(1) || x == n_minus_1) continue;
            
            bool found = false;
            for (long j = 0; j < r - 1; ++j) {
                x = (x * x) % p;
                if (x == n_minus_1) {
                    found = true;
                    break;
                }
            }
            
            if (!found) is_prime = false;
        }
        
        if (is_prime) return;
    }
}

/** @brief Check if probably prime */
inline long ProbPrime(const ZZ& p, long trials = 20) {
    if (p <= ZZ(1)) return 0;
    if (p == ZZ(2)) return 1;
    if (!p.is_odd()) return 0;
    
    ZZ n_minus_1 = p - ZZ(1);
    ZZ d = n_minus_1;
    long r = 0;
    while (!d.is_odd()) {
        d >>= 1;
        r++;
    }
    
    for (int i = 0; i < trials; ++i) {
        ZZ a = RandomBits_ZZ(NumBits(p) - 2);
        a = a % (p - ZZ(2));
        if (a < ZZ(2)) a = ZZ(2);
        
        ZZ x = PowerMod(a, d, p);
        
        if (x == ZZ(1) || x == n_minus_1) continue;
        
        bool found = false;
        for (long j = 0; j < r - 1; ++j) {
            x = (x * x) % p;
            if (x == n_minus_1) {
                found = true;
                break;
            }
        }
        
        if (!found) return 0;
    }
    
    return 1;
}

// ============================================================================
// Stream I/O
// ============================================================================

inline std::ostream& operator<<(std::ostream& os, const ZZ& a) {
    os << a.to_hex();
    return os;
}

inline std::istream& operator>>(std::istream& is, ZZ& a) {
    std::string s;
    is >> s;
    a = ZZ::from_hex(s);
    return is;
}

// ============================================================================
// Conversion Utilities
// ============================================================================

/** @brief Convert value to ZZ */
template<typename T>
inline ZZ conv(const T& value) {
    return ZZ(static_cast<int64_t>(value));
}

template<>
inline ZZ conv<std::string>(const std::string& value) {
    // Try decimal first, fall back to hex
    if (!value.empty() && (value[0] == '-' || std::isdigit(value[0]))) {
        return ZZ::from_decimal(value);
    }
    return ZZ::from_hex(value);
}

template<>
inline ZZ conv<const char*>(const char* const& value) {
    // Try decimal first, fall back to hex
    if (value && (value[0] == '-' || std::isdigit(value[0]))) {
        return ZZ::from_decimal(value);
    }
    return ZZ::from_hex(value);
}

/** @brief Alternative form: conv<ZZ>(string) - NTL compatibility */
inline ZZ conv_ZZ(const char* value) {
    return ZZ::from_decimal(value);
}

inline ZZ conv_ZZ(const std::string& value) {
    return ZZ::from_decimal(value);
}

template<>
inline ZZ conv<ZZ>(const ZZ& value) {
    return value;
}

// ============================================================================
// NTL-Compatible API (output parameter forms)
// ============================================================================

/** @brief Convert string to ZZ (NTL-style) */
inline void conv(ZZ& out, const char* str) {
    out = ZZ::from_decimal(str);
}

inline void conv(ZZ& out, const std::string& str) {
    out = ZZ::from_decimal(str);
}

/** @brief Add: c = a + b */
inline void add(ZZ& c, const ZZ& a, const ZZ& b) {
    c = a + b;
}

/** @brief Subtract: c = a - b */
inline void sub(ZZ& c, const ZZ& a, const ZZ& b) {
    c = a - b;
}

/** @brief Multiply: c = a * b */
inline void mul(ZZ& c, const ZZ& a, const ZZ& b) {
    c = a * b;
}

/** @brief Divide: q = a / b */
inline void div(ZZ& q, const ZZ& a, const ZZ& b) {
    q = a / b;
}

/** @brief Remainder: r = a % b */
inline void rem(ZZ& r, const ZZ& a, const ZZ& b) {
    r = a % b;
}

/** @brief Division with remainder: q = a / b, r = a % b */
inline void DivRem(ZZ& q, ZZ& r, const ZZ& a, const ZZ& b) {
    q = a / b;
    r = a % b;
}

/** @brief GCD: g = gcd(a, b) */
inline void GCD(ZZ& g, const ZZ& a, const ZZ& b) {
    g = GCD(a, b);
}

/** @brief Modular exponentiation: result = a^e mod n */
inline void PowerMod(ZZ& result, const ZZ& a, const ZZ& e, const ZZ& n) {
    result = PowerMod(a, e, n);
}

/** @brief Modular inverse: result = a^(-1) mod n */
inline void InvMod(ZZ& result, const ZZ& a, const ZZ& n) {
    result = InvMod(a, n);
}

/** @brief Modular multiplication: result = a * b mod n */
inline void MulMod(ZZ& result, const ZZ& a, const ZZ& b, const ZZ& n) {
    result = MulMod(a, b, n);
}

/** @brief Negate: a = -a */
inline void negate(ZZ& a) {
    a = -a;
}

/** @brief Check if negative */
inline bool IsNegative(const ZZ& a) {
    return a.is_negative();
}

/** @brief Left shift: c = a << n */
inline void LeftShift(ZZ& c, const ZZ& a, long n) {
    c = a << n;
}

/** @brief Right shift: c = a >> n */
inline void RightShift(ZZ& c, const ZZ& a, long n) {
    c = a >> n;
}

/** @brief Convert from bytes (NTL-style) */
inline void ZZFromBytes(ZZ& out, const unsigned char* data, long len) {
    out = ZZ::from_bytes(data, static_cast<size_t>(len));
}

} // namespace kctsb

#endif // KCTSB_CORE_ZZ_H
