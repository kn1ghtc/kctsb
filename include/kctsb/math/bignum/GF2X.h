/**
 * @file GF2X.h
 * @brief Binary Field Polynomial (GF(2)[X]) - v5.0 Self-Contained Implementation
 * 
 * Polynomials over GF(2) - used in binary field cryptography.
 * 
 * @author knightc
 * @version 5.0.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_BIGNUM_GF2X_H
#define KCTSB_MATH_BIGNUM_GF2X_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <algorithm>

namespace kctsb {

/**
 * @brief Polynomial over GF(2)
 * 
 * Represents polynomials with coefficients in {0, 1}.
 * Used for binary field arithmetic in ECC and symmetric cryptography.
 */
class GF2X {
private:
    std::vector<uint64_t> data_;  // Bit vector representation
    
public:
    /** @brief Default constructor - zero polynomial */
    GF2X() = default;
    
    /** @brief Construct from single coefficient */
    explicit GF2X(uint64_t val) : data_{val} {
        normalize();
    }
    
    /** @brief Get degree of polynomial (-1 for zero polynomial) */
    long deg() const {
        if (data_.empty()) return -1;
        
        for (size_t i = data_.size(); i > 0; --i) {
            if (data_[i - 1] != 0) {
                // Find highest bit in this word
                uint64_t w = data_[i - 1];
                int bits = 63;
                while (bits >= 0 && !(w & (1ULL << bits))) --bits;
                return static_cast<long>((i - 1) * 64 + bits);
            }
        }
        return -1;
    }
    
    /** @brief Check if zero */
    bool IsZero() const { return deg() < 0; }
    
    /** @brief Check if one */
    bool IsOne() const {
        return data_.size() == 1 && data_[0] == 1;
    }
    
    /** @brief Get coefficient at position i */
    int coeff(long i) const {
        if (i < 0) return 0;
        size_t word = i / 64;
        size_t bit = i % 64;
        if (word >= data_.size()) return 0;
        return (data_[word] >> bit) & 1;
    }
    
    /** @brief Set coefficient at position i */
    void SetCoeff(long i, int val = 1) {
        if (i < 0) return;
        size_t word = i / 64;
        size_t bit = i % 64;
        
        if (word >= data_.size()) {
            data_.resize(word + 1, 0);
        }
        
        if (val) {
            data_[word] |= (1ULL << bit);
        } else {
            data_[word] &= ~(1ULL << bit);
        }
        normalize();
    }
    
    /** @brief Addition/subtraction in GF(2) (same as XOR) */
    GF2X operator+(const GF2X& other) const {
        GF2X result;
        result.data_.resize(std::max(data_.size(), other.data_.size()), 0);
        
        for (size_t i = 0; i < result.data_.size(); ++i) {
            uint64_t a = (i < data_.size()) ? data_[i] : 0;
            uint64_t b = (i < other.data_.size()) ? other.data_[i] : 0;
            result.data_[i] = a ^ b;
        }
        
        result.normalize();
        return result;
    }
    
    GF2X& operator+=(const GF2X& other) {
        *this = *this + other;
        return *this;
    }
    
    /** @brief Same as addition in GF(2) */
    GF2X operator-(const GF2X& other) const {
        return *this + other;
    }
    
    GF2X& operator-=(const GF2X& other) {
        return *this += other;
    }
    
    /** @brief Multiplication */
    GF2X operator*(const GF2X& other) const {
        if (IsZero() || other.IsZero()) return GF2X();
        
        long deg_a = deg();
        long deg_b = other.deg();
        
        GF2X result;
        result.data_.resize((deg_a + deg_b + 64) / 64, 0);
        
        for (long i = 0; i <= deg_a; ++i) {
            if (coeff(i)) {
                for (long j = 0; j <= deg_b; ++j) {
                    if (other.coeff(j)) {
                        long pos = i + j;
                        size_t word = pos / 64;
                        size_t bit = pos % 64;
                        result.data_[word] ^= (1ULL << bit);
                    }
                }
            }
        }
        
        result.normalize();
        return result;
    }
    
    GF2X& operator*=(const GF2X& other) {
        *this = *this * other;
        return *this;
    }
    
    /** @brief Comparison */
    bool operator==(const GF2X& other) const {
        return data_ == other.data_;
    }
    
    bool operator!=(const GF2X& other) const {
        return !(*this == other);
    }
    
private:
    /** @brief Remove leading zeros */
    void normalize() {
        while (!data_.empty() && data_.back() == 0) {
            data_.pop_back();
        }
    }
};

// Free functions

/** @brief Clear polynomial */
inline void clear(GF2X& p) {
    p = GF2X();
}

/** @brief Set to one */
inline void set(GF2X& p) {
    p = GF2X(1);
}

/** @brief Check if zero */
inline bool IsZero(const GF2X& p) {
    return p.IsZero();
}

/** @brief Check if one */
inline bool IsOne(const GF2X& p) {
    return p.IsOne();
}

/** @brief Get degree */
inline long deg(const GF2X& p) {
    return p.deg();
}

/** @brief Get coefficient */
inline int coeff(const GF2X& p, long i) {
    return p.coeff(i);
}

/** @brief Set coefficient */
inline void SetCoeff(GF2X& p, long i, int val = 1) {
    p.SetCoeff(i, val);
}

/** @brief Add: c = a + b */
inline void add(GF2X& c, const GF2X& a, const GF2X& b) {
    c = a + b;
}

/** @brief Subtract: c = a - b (same as add in GF2) */
inline void sub(GF2X& c, const GF2X& a, const GF2X& b) {
    c = a + b;
}

/** @brief Multiply: c = a * b */
inline void mul(GF2X& c, const GF2X& a, const GF2X& b) {
    c = a * b;
}

/** @brief GCD of polynomials */
inline GF2X GCD(const GF2X& a, const GF2X& b) {
    GF2X x = a;
    GF2X y = b;
    
    while (!y.IsZero()) {
        // TODO: Implement proper polynomial division
        // For now, return placeholder
        break;
    }
    
    return x;
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_GF2X_H
