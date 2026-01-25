/**
 * @file GF2EX.h
 * @brief GF2EX polynomial stubs for v5.0
 */

#ifndef KCTSB_MATH_BIGNUM_GF2EX_H
#define KCTSB_MATH_BIGNUM_GF2EX_H

#include <kctsb/math/bignum/GF2E.h>
#include <kctsb/math/bignum/vec_ZZ.h>
#include <vector>

namespace kctsb {

/**
 * @brief Polynomial over GF(2^n) - univariate
 */
class GF2EX {
private:
    std::vector<GF2E> coeffs_;

public:
    GF2EX() = default;
    
    long IsZero() const {
        for (const auto& c : coeffs_) {
            if (!kctsb::IsZero(c)) return 0;
        }
        return 1;
    }
    
    void SetLength(long n) { coeffs_.resize(static_cast<size_t>(n)); }
    long length() const { return static_cast<long>(coeffs_.size()); }
    
    GF2E& operator[](long i) { return coeffs_[static_cast<size_t>(i)]; }
    const GF2E& operator[](long i) const { return coeffs_[static_cast<size_t>(i)]; }
    
    void SetCoeff(long i, const GF2E& c) {
        if (i >= static_cast<long>(coeffs_.size())) {
            coeffs_.resize(static_cast<size_t>(i + 1));
        }
        coeffs_[static_cast<size_t>(i)] = c;
    }
    
    void SetCoeff(long i, long c) {
        SetCoeff(i, GF2E(c));
    }
    
    const GF2E& coeff(long i) const {
        static GF2E zero;
        if (i < 0 || i >= static_cast<long>(coeffs_.size())) return zero;
        return coeffs_[static_cast<size_t>(i)];
    }
};

inline long IsZero(const GF2EX& p) { return p.IsZero(); }
inline long deg(const GF2EX& p) { 
    for (long i = p.length() - 1; i >= 0; --i) {
        if (!IsZero(p[i])) return i;
    }
    return -1; 
}

inline void SetCoeff(GF2EX& p, long i, const GF2E& c) { p.SetCoeff(i, c); }
inline void SetCoeff(GF2EX& p, long i, long c) { p.SetCoeff(i, c); }
inline const GF2E& coeff(const GF2EX& p, long i) { return p.coeff(i); }

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_GF2EX_H
