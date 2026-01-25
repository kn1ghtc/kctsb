/**
 * @file ZZX.h
 * @brief NTL Compatibility Layer - Polynomials over ZZ
 * 
 * Provides ZZX (univariate polynomials over integers) functionality.
 * 
 * @version 5.0.0 - Self-contained implementation
 */

#ifndef KCTSB_MATH_BIGNUM_ZZX_H
#define KCTSB_MATH_BIGNUM_ZZX_H

#include "kctsb/core/zz.h"
#include <kctsb/math/bignum/vec_ZZ.h>
#include <vector>
#include <algorithm>

namespace kctsb {

/**
 * @brief ZZX: Univariate polynomial over ZZ
 * 
 * Coefficients stored from low to high degree.
 */
class ZZX {
public:
    /**
     * @brief Internal coefficient vector (NTL-compatible 'rep' member)
     */
    vec_ZZ rep;
    
private:
    void normalize() {
        while (rep.length() > 1 && rep[rep.length()-1].is_zero()) {
            rep.SetLength(rep.length() - 1);
        }
        if (rep.length() == 0) rep.SetLength(1);
    }
    
public:
    ZZX() { rep.SetLength(1); rep[0] = ZZ(0); }
    
    explicit ZZX(const ZZ& c) { rep.SetLength(1); rep[0] = c; }
    explicit ZZX(long c) { rep.SetLength(1); rep[0] = ZZ(c); }
    
    // Degree
    long deg() const {
        if (rep.length() == 1 && rep[0].is_zero()) return -1;
        return rep.length() - 1;
    }
    
    // Coefficient access
    const ZZ& coeff(long i) const {
        static ZZ zero;
        if (i < 0 || i >= rep.length()) return zero;
        return rep[i];
    }
    
    void SetCoeff(long i, const ZZ& c) {
        if (i < 0) return;
        if (i >= rep.length()) {
            long old_len = rep.length();
            rep.SetLength(i + 1);
            for (long j = old_len; j < i; ++j) rep[j] = ZZ(0);
        }
        rep[i] = c;
        normalize();
    }
    
    // Leading coefficient
    const ZZ& LeadCoeff() const {
        return rep[rep.length() - 1];
    }
    
    // Zero check
    bool IsZero() const {
        return rep.length() == 1 && rep[0].is_zero();
    }
    
    // Arithmetic
    ZZX operator+(const ZZX& other) const {
        ZZX result;
        long max_len = std::max(rep.length(), other.rep.length());
        result.rep.SetLength(max_len);
        
        for (long i = 0; i < max_len; ++i) {
            result.rep[i] = coeff(i) + other.coeff(i);
        }
        result.normalize();
        return result;
    }
    
    ZZX operator-(const ZZX& other) const {
        ZZX result;
        long max_len = std::max(rep.length(), other.rep.length());
        result.rep.SetLength(max_len);
        
        for (long i = 0; i < max_len; ++i) {
            result.rep[i] = coeff(i) - other.coeff(i);
        }
        result.normalize();
        return result;
    }
    
    ZZX operator*(const ZZX& other) const {
        if (IsZero() || other.IsZero()) return ZZX();
        
        ZZX result;
        result.rep.SetLength(rep.length() + other.rep.length() - 1);
        for (long k = 0; k < result.rep.length(); ++k) result.rep[k] = ZZ(0);
        
        for (long i = 0; i < rep.length(); ++i) {
            for (long j = 0; j < other.rep.length(); ++j) {
                result.rep[i + j] += rep[i] * other.rep[j];
            }
        }
        result.normalize();
        return result;
    }
    
    ZZX operator*(const ZZ& c) const {
        ZZX result;
        result.rep.SetLength(rep.length());
        for (long i = 0; i < rep.length(); ++i) {
            result.rep[i] = rep[i] * c;
        }
        result.normalize();
        return result;
    }
    
    ZZX& operator+=(const ZZX& other) { *this = *this + other; return *this; }
    ZZX& operator-=(const ZZX& other) { *this = *this - other; return *this; }
    ZZX& operator*=(const ZZX& other) { *this = *this * other; return *this; }
    ZZX& operator*=(const ZZ& c) { *this = *this * c; return *this; }
    
    bool operator==(const ZZX& other) const {
        if (deg() != other.deg()) return false;
        for (long i = 0; i < rep.length(); ++i) {
            if (rep[i] != other.rep[i]) return false;
        }
        return true;
    }
    
    bool operator!=(const ZZX& other) const { return !(*this == other); }
};

/** @brief Set coefficient */
inline void SetCoeff(ZZX& f, long i, const ZZ& c) {
    f.SetCoeff(i, c);
}

inline void SetCoeff(ZZX& f, long i, long c) {
    f.SetCoeff(i, ZZ(c));
}

/** @brief Degree of polynomial */
inline long deg(const ZZX& f) {
    return f.deg();
}

/** @brief Leading coefficient */
inline const ZZ& LeadCoeff(const ZZX& f) {
    return f.LeadCoeff();
}

/** @brief Check if zero */
inline bool IsZero(const ZZX& f) {
    return f.IsZero();
}

/** @brief Coefficient access */
inline const ZZ& coeff(const ZZX& f, long i) {
    return f.coeff(i);
}

/** @brief Clear polynomial */
inline void clear(ZZX& f) {
    f = ZZX();
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_ZZX_H
