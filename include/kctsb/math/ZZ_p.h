/**
 * @file ZZ_p.h
 * @brief NTL Compatibility Layer - Modular Arithmetic (Z/pZ)
 * 
 * Provides ZZ_p (integers modulo prime p) functionality using
 * the self-contained ZZ implementation.
 * 
 * @version 5.0.0 - Self-contained implementation
 */

#ifndef KCTSB_MATH_BIGNUM_ZZ_P_H
#define KCTSB_MATH_BIGNUM_ZZ_P_H

#include "kctsb/core/zz.h"

namespace kctsb {

/**
 * @brief ZZ_p context - holds the modulus p
 */
class ZZ_pContext {
private:
    ZZ modulus_;
    static ZZ_pContext* current_;
    
public:
    ZZ_pContext() = default;
    explicit ZZ_pContext(const ZZ& p) : modulus_(p) {}
    
    const ZZ& modulus() const { return modulus_; }
    
    void restore() { current_ = this; }
    
    static ZZ_pContext* current() { return current_; }
};

/**
 * @brief Initialize ZZ_p modulus (free function)
 */
inline void ZZ_p_init(const ZZ& p) {
    static ZZ_pContext ctx;
    ctx = ZZ_pContext(p);
    ctx.restore();
}

/**
 * @brief ZZ_p: Integer modulo p
 */
class ZZ_p {
private:
    ZZ rep_;  // Representative in [0, p-1]
    
    void reduce() {
        if (ZZ_pContext::current()) {
            const ZZ& p = ZZ_pContext::current()->modulus();
            rep_ = rep_ % p;
            if (rep_.is_negative()) rep_ += p;
        }
    }
    
public:
    /** @brief Initialize modulus (static, NTL-compatible) */
    static void init(const ZZ& p) {
        ZZ_p_init(p);
    }
    
public:
    ZZ_p() : rep_(0) {}
    
    explicit ZZ_p(const ZZ& a) : rep_(a) { reduce(); }
    explicit ZZ_p(long a) : rep_(a) { reduce(); }
    explicit ZZ_p(int a) : rep_(a) { reduce(); }
    
    // Accessor
    const ZZ& rep() const { return rep_; }
    ZZ& rep() { return rep_; }
    
    // Arithmetic
    ZZ_p operator+(const ZZ_p& other) const {
        return ZZ_p(AddMod(rep_, other.rep_, ZZ_pContext::current()->modulus()));
    }
    
    ZZ_p operator-(const ZZ_p& other) const {
        return ZZ_p(SubMod(rep_, other.rep_, ZZ_pContext::current()->modulus()));
    }
    
    ZZ_p operator*(const ZZ_p& other) const {
        return ZZ_p(MulMod(rep_, other.rep_, ZZ_pContext::current()->modulus()));
    }
    
    ZZ_p operator-() const {
        if (rep_.is_zero()) return ZZ_p(ZZ(0));
        return ZZ_p(ZZ_pContext::current()->modulus() - rep_);
    }
    
    ZZ_p& operator+=(const ZZ_p& other) { *this = *this + other; return *this; }
    ZZ_p& operator-=(const ZZ_p& other) { *this = *this - other; return *this; }
    ZZ_p& operator*=(const ZZ_p& other) { *this = *this * other; return *this; }
    
    bool operator==(const ZZ_p& other) const { return rep_ == other.rep_; }
    bool operator!=(const ZZ_p& other) const { return rep_ != other.rep_; }
    
    // Zero check
    bool is_zero() const { return rep_.is_zero(); }
};

/** @brief Get modulus */
inline const ZZ& ZZ_p_modulus() {
    return ZZ_pContext::current()->modulus();
}

/** @brief Invert in Z/pZ */
inline ZZ_p inv(const ZZ_p& a) {
    return ZZ_p(InvMod(a.rep(), ZZ_pContext::current()->modulus()));
}

/** @brief Square */
inline ZZ_p sqr(const ZZ_p& a) {
    return a * a;
}

/** @brief Power */
inline ZZ_p power(const ZZ_p& a, long e) {
    if (e < 0) return power(inv(a), -e);
    if (e == 0) return ZZ_p(ZZ(1));
    
    ZZ_p result(ZZ(1));
    ZZ_p base = a;
    
    while (e > 0) {
        if (e & 1) result *= base;
        base = sqr(base);
        e >>= 1;
    }
    return result;
}

/** @brief Get representative */
inline const ZZ& rep(const ZZ_p& a) {
    return a.rep();
}

/** @brief Convert to ZZ_p */
inline ZZ_p to_ZZ_p(const ZZ& a) {
    return ZZ_p(a);
}

/** @brief Convert long to ZZ_p */
inline ZZ_p to_ZZ_p(long a) {
    return ZZ_p(a);
}

/** @brief Convert int to ZZ_p */
inline ZZ_p to_ZZ_p(int a) {
    return ZZ_p(a);
}

/** @brief Check if ZZ_p is zero */
inline bool IsZero(const ZZ_p& a) {
    return a.is_zero();
}

/** @brief Check if ZZ_p is one */
inline bool IsOne(const ZZ_p& a) {
    return a.rep() == ZZ(1);
}

/** @brief Clear ZZ_p to zero */
inline void clear(ZZ_p& a) {
    a = ZZ_p(0);
}

/** @brief Set ZZ_p to one */
inline void set(ZZ_p& a) {
    a = ZZ_p(1);
}

/** @brief Random ZZ_p element */
inline void random(ZZ_p& a) {
    // Simple placeholder - proper implementation should use secure RNG
    a = ZZ_p(ZZ(0));  // TODO: implement proper random
}

/** @brief Negate ZZ_p */
inline void negate(ZZ_p& result, const ZZ_p& a) {
    result = -a;
}

/** @brief Division in Z/pZ */
inline ZZ_p operator/(const ZZ_p& a, const ZZ_p& b) {
    return a * inv(b);
}

/** @brief Integer * ZZ_p */
inline ZZ_p operator*(long a, const ZZ_p& b) {
    return ZZ_p(a) * b;
}

inline ZZ_p operator*(int a, const ZZ_p& b) {
    return ZZ_p(a) * b;
}

inline ZZ_p operator*(const ZZ_p& a, long b) {
    return a * ZZ_p(b);
}

inline ZZ_p operator*(const ZZ_p& a, int b) {
    return a * ZZ_p(b);
}

/** @brief Convert ZZ to ZZ_p */
inline ZZ_p conv_ZZ_p(const ZZ& a) {
    return ZZ_p(a);
}

inline ZZ_p conv_ZZ_p(long a) {
    return ZZ_p(a);
}

inline ZZ_p conv_ZZ_p(const ZZ_p& a) {
    return a;
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_ZZ_P_H
