/**
 * @file ZZ_pX.h  
 * @brief NTL Compatibility Layer - Polynomials over Z/pZ
 * 
 * Provides ZZ_pX (univariate polynomials over modular integers).
 * 
 * @version 5.0.0 - Self-contained implementation
 */

#ifndef KCTSB_MATH_BIGNUM_ZZ_PX_H
#define KCTSB_MATH_BIGNUM_ZZ_PX_H

#include "ZZ_p.h"
#include <vector>

namespace kctsb {

/**
 * @brief ZZ_pX: Univariate polynomial over ZZ_p
 */
class ZZ_pX {
private:
    std::vector<ZZ_p> coeffs_;
    
    void normalize() {
        while (coeffs_.size() > 1 && coeffs_.back().is_zero()) {
            coeffs_.pop_back();
        }
    }
    
public:
    ZZ_pX() : coeffs_(1, ZZ_p(ZZ(0))) {}
    
    explicit ZZ_pX(const ZZ_p& c) : coeffs_(1, c) {}
    explicit ZZ_pX(long c) : coeffs_(1, ZZ_p(ZZ(c))) {}
    
    // Degree
    long deg() const {
        if (coeffs_.size() == 1 && coeffs_[0].is_zero()) return -1;
        return static_cast<long>(coeffs_.size()) - 1;
    }
    
    // Coefficient access
    const ZZ_p& coeff(long i) const {
        static ZZ_p zero;
        if (i < 0 || static_cast<size_t>(i) >= coeffs_.size()) return zero;
        return coeffs_[static_cast<size_t>(i)];
    }
    
    void SetCoeff(long i, const ZZ_p& c) {
        if (i < 0) return;
        if (static_cast<size_t>(i) >= coeffs_.size()) {
            coeffs_.resize(static_cast<size_t>(i) + 1, ZZ_p(ZZ(0)));
        }
        coeffs_[static_cast<size_t>(i)] = c;
        normalize();
    }
    
    void SetCoeff(long i, long c) {
        SetCoeff(i, ZZ_p(ZZ(c)));
    }
    
    // Leading coefficient
    const ZZ_p& LeadCoeff() const {
        return coeffs_.back();
    }
    
    // Zero check
    bool IsZero() const {
        return coeffs_.size() == 1 && coeffs_[0].is_zero();
    }
    
    // Arithmetic
    ZZ_pX operator+(const ZZ_pX& other) const {
        ZZ_pX result;
        size_t max_size = std::max(coeffs_.size(), other.coeffs_.size());
        result.coeffs_.resize(max_size, ZZ_p(ZZ(0)));
        
        for (size_t i = 0; i < max_size; ++i) {
            result.coeffs_[i] = coeff(static_cast<long>(i)) + 
                                other.coeff(static_cast<long>(i));
        }
        result.normalize();
        return result;
    }
    
    ZZ_pX operator-(const ZZ_pX& other) const {
        ZZ_pX result;
        size_t max_size = std::max(coeffs_.size(), other.coeffs_.size());
        result.coeffs_.resize(max_size, ZZ_p(ZZ(0)));
        
        for (size_t i = 0; i < max_size; ++i) {
            result.coeffs_[i] = coeff(static_cast<long>(i)) - 
                                other.coeff(static_cast<long>(i));
        }
        result.normalize();
        return result;
    }
    
    ZZ_pX operator*(const ZZ_pX& other) const {
        if (IsZero() || other.IsZero()) return ZZ_pX();
        
        ZZ_pX result;
        result.coeffs_.resize(coeffs_.size() + other.coeffs_.size() - 1, ZZ_p(ZZ(0)));
        
        for (size_t i = 0; i < coeffs_.size(); ++i) {
            for (size_t j = 0; j < other.coeffs_.size(); ++j) {
                result.coeffs_[i + j] += coeffs_[i] * other.coeffs_[j];
            }
        }
        result.normalize();
        return result;
    }
    
    ZZ_pX& operator+=(const ZZ_pX& other) { *this = *this + other; return *this; }
    ZZ_pX& operator-=(const ZZ_pX& other) { *this = *this - other; return *this; }
    ZZ_pX& operator*=(const ZZ_pX& other) { *this = *this * other; return *this; }
    
    bool operator==(const ZZ_pX& other) const {
        if (deg() != other.deg()) return false;
        for (size_t i = 0; i < coeffs_.size(); ++i) {
            if (coeffs_[i] != other.coeffs_[i]) return false;
        }
        return true;
    }
    
    bool operator!=(const ZZ_pX& other) const { return !(*this == other); }
};

/** @brief Set coefficient */
inline void SetCoeff(ZZ_pX& f, long i, const ZZ_p& c) {
    f.SetCoeff(i, c);
}

inline void SetCoeff(ZZ_pX& f, long i, long c) {
    f.SetCoeff(i, c);
}

/** @brief Degree */
inline long deg(const ZZ_pX& f) {
    return f.deg();
}

/** @brief Check if zero */
inline bool IsZero(const ZZ_pX& f) {
    return f.IsZero();
}

/** @brief Clear polynomial */
inline void clear(ZZ_pX& f) {
    f = ZZ_pX();
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_ZZ_PX_H
