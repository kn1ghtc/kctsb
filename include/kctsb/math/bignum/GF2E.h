/**
 * @file GF2E.h
 * @brief NTL-compatible GF(2^n) elements for kctsb v5.0
 * @author kctsb Team
 * @version 5.0
 * 
 * Self-contained implementation replacing NTL GF2E.
 * GF(2^n) is constructed as GF(2)[X] / (f(X)) where f is an irreducible polynomial.
 */

#ifndef KCTSB_MATH_BIGNUM_GF2E_H
#define KCTSB_MATH_BIGNUM_GF2E_H

#include <kctsb/math/bignum/GF2X.h>

namespace kctsb {

/**
 * @brief Context for GF(2^n) - holds the irreducible modulus
 */
class GF2EContext {
private:
    GF2X modulus_;
    long degree_;
    static GF2EContext* current_;

public:
    GF2EContext() : degree_(0) {}
    
    explicit GF2EContext(const GF2X& f) : modulus_(f), degree_(deg(f)) {}
    
    const GF2X& modulus() const { return modulus_; }
    long degree() const { return degree_; }
    
    void restore() { current_ = this; }
    static GF2EContext* current() { return current_; }
};

/**
 * @brief Initialize GF(2^n) with irreducible polynomial
 */
inline void GF2E_init(const GF2X& f) {
    static GF2EContext ctx;
    ctx = GF2EContext(f);
    ctx.restore();
}

/**
 * @brief Element of GF(2^n)
 */
class GF2E {
private:
    GF2X rep_; // Representative polynomial (degree < n)
    
    void reduce() {
        if (GF2EContext::current() && deg(rep_) >= GF2EContext::current()->degree()) {
            // Reduce modulo the irreducible polynomial
            // Simple implementation: repeated subtraction
            while (deg(rep_) >= GF2EContext::current()->degree()) {
                long shift = deg(rep_) - GF2EContext::current()->degree();
                GF2X shifted = GF2EContext::current()->modulus();
                // Shift left by 'shift' positions
                GF2X temp;
                for (long i = 0; i <= deg(shifted); ++i) {
                    SetCoeff(temp, i + shift, coeff(shifted, i));
                }
                rep_ = rep_ + temp; // In GF(2), + is XOR
            }
        }
    }

public:
    GF2E() = default;
    
    explicit GF2E(const GF2X& a) : rep_(a) { reduce(); }
    explicit GF2E(long val) {
        if (val & 1) SetCoeff(rep_, 0, 1);
        reduce();
    }
    
    /** @brief Initialize GF(2^n) with irreducible polynomial (static) */
    static void init(const GF2X& f) {
        GF2E_init(f);
    }
    
    // Accessor
    const GF2X& rep() const { return rep_; }
    GF2X& rep() { return rep_; }
    
    // Arithmetic
    GF2E operator+(const GF2E& other) const {
        GF2E result;
        add(result.rep_, rep_, other.rep_);
        return result;
    }
    
    GF2E operator-(const GF2E& other) const { return *this + other; } // Same in GF(2)
    
    GF2E operator*(const GF2E& other) const {
        GF2E result;
        mul(result.rep_, rep_, other.rep_);
        result.reduce();
        return result;
    }
    
    GF2E& operator+=(const GF2E& other) { *this = *this + other; return *this; }
    GF2E& operator-=(const GF2E& other) { *this = *this + other; return *this; }
    GF2E& operator*=(const GF2E& other) { *this = *this * other; return *this; }
    
    bool operator==(const GF2E& other) const { return IsZero(rep_ - other.rep_); }
    bool operator!=(const GF2E& other) const { return !(*this == other); }
    
    bool is_zero() const { return IsZero(rep_); }
};

inline bool IsZero(const GF2E& a) { return a.is_zero(); }
inline bool IsOne(const GF2E& a) { 
    const GF2X& r = a.rep();
    return deg(r) == 0 && coeff(r, 0) == 1;
}
inline void clear(GF2E& a) { a = GF2E(); }
inline void set(GF2E& a) { a = GF2E(1); }

inline const GF2X& rep(const GF2E& a) { return a.rep(); }

/** @brief Degree of extension field */
inline long GF2E_degree() {
    return GF2EContext::current() ? GF2EContext::current()->degree() : 0;
}

/** @brief Get the modulus */
inline const GF2X& GF2E_modulus() {
    return GF2EContext::current()->modulus();
}

/** @brief Square in GF(2^n) */
inline GF2E sqr(const GF2E& a) {
    return a * a;
}

/** @brief Power in GF(2^n) */
inline GF2E power(const GF2E& a, long e) {
    if (e == 0) return GF2E(1);
    if (e < 0) {
        // TODO: implement inverse
        return GF2E(0);
    }
    
    GF2E result(1);
    GF2E base = a;
    
    while (e > 0) {
        if (e & 1) result *= base;
        base = sqr(base);
        e >>= 1;
    }
    return result;
}

/** @brief Convert int to GF2E */
inline GF2E to_GF2E(int val) {
    return GF2E(static_cast<long>(val));
}

/** @brief Convert long to GF2E */
inline GF2E to_GF2E(long val) {
    return GF2E(val);
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_GF2E_H
