/**
 * @file vec_ZZ_p.h
 * @brief NTL-compatible vector of ZZ_p elements for kctsb v5.0
 * @author kctsb Team
 * @version 5.0
 * 
 * Self-contained implementation replacing NTL vec_ZZ_p.
 */

#ifndef KCTSB_MATH_BIGNUM_VEC_ZZ_P_H
#define KCTSB_MATH_BIGNUM_VEC_ZZ_P_H

#include <kctsb/math/bignum/ZZ_p.h>
#include <vector>
#include <stdexcept>
#include <initializer_list>

namespace kctsb {

/**
 * @brief Vector of ZZ_p elements (integers modulo p)
 * 
 * NTL-compatible vector class for modular arithmetic elements.
 */
class vec_ZZ_p {
public:
    using value_type = ZZ_p;
    using size_type = long;
    using reference = ZZ_p&;
    using const_reference = const ZZ_p&;
    using iterator = std::vector<ZZ_p>::iterator;
    using const_iterator = std::vector<ZZ_p>::const_iterator;

private:
    std::vector<ZZ_p> data_;

public:
    // Constructors
    vec_ZZ_p() = default;
    
    explicit vec_ZZ_p(size_type n) : data_(static_cast<size_t>(n)) {}
    
    vec_ZZ_p(size_type n, const ZZ_p& val) : data_(static_cast<size_t>(n), val) {}
    
    vec_ZZ_p(std::initializer_list<ZZ_p> init) : data_(init) {}
    
    vec_ZZ_p(const vec_ZZ_p&) = default;
    vec_ZZ_p(vec_ZZ_p&&) noexcept = default;
    vec_ZZ_p& operator=(const vec_ZZ_p&) = default;
    vec_ZZ_p& operator=(vec_ZZ_p&&) noexcept = default;
    ~vec_ZZ_p() = default;
    
    // Size and capacity
    size_type length() const noexcept { return static_cast<size_type>(data_.size()); }
    bool empty() const noexcept { return data_.empty(); }
    
    void SetLength(size_type n) { data_.resize(static_cast<size_t>(n)); }
    void SetLength(size_type n, const ZZ_p& val) { data_.resize(static_cast<size_t>(n), val); }
    
    void kill() { data_.clear(); data_.shrink_to_fit(); }
    
    // Element access
    reference operator[](size_type i) { return data_[static_cast<size_t>(i)]; }
    const_reference operator[](size_type i) const { return data_[static_cast<size_t>(i)]; }
    
    reference operator()(size_type i) { return data_[static_cast<size_t>(i - 1)]; } // 1-indexed
    const_reference operator()(size_type i) const { return data_[static_cast<size_t>(i - 1)]; }
    
    reference at(size_type i) { 
        if (i < 0 || i >= length()) throw std::out_of_range("vec_ZZ_p index out of range");
        return data_.at(static_cast<size_t>(i)); 
    }
    const_reference at(size_type i) const { 
        if (i < 0 || i >= length()) throw std::out_of_range("vec_ZZ_p index out of range");
        return data_.at(static_cast<size_t>(i)); 
    }
    
    // Iterators
    iterator begin() noexcept { return data_.begin(); }
    const_iterator begin() const noexcept { return data_.begin(); }
    iterator end() noexcept { return data_.end(); }
    const_iterator end() const noexcept { return data_.end(); }
    
    // Modifiers
    void append(const ZZ_p& val) { data_.push_back(val); }
    void append(ZZ_p&& val) { data_.push_back(std::move(val)); }
    
    void swap(vec_ZZ_p& other) noexcept { data_.swap(other.data_); }
    
    // Comparison
    bool operator==(const vec_ZZ_p& other) const { return data_ == other.data_; }
    bool operator!=(const vec_ZZ_p& other) const { return data_ != other.data_; }
    
    // Raw access
    ZZ_p* elts() noexcept { return data_.data(); }
    const ZZ_p* elts() const noexcept { return data_.data(); }
};

// Free functions for NTL compatibility

inline void clear(vec_ZZ_p& v) { v.kill(); }
inline void swap(vec_ZZ_p& a, vec_ZZ_p& b) noexcept { a.swap(b); }

inline long IsZero(const vec_ZZ_p& v) {
    for (long i = 0; i < v.length(); ++i) {
        if (!IsZero(v[i])) return 0;
    }
    return 1;
}

/**
 * @brief Inner product of two vectors
 */
inline void InnerProduct(ZZ_p& result, const vec_ZZ_p& a, const vec_ZZ_p& b) {
    if (a.length() != b.length()) {
        throw std::invalid_argument("vec_ZZ_p InnerProduct: length mismatch");
    }
    result = ZZ_p(0);
    for (long i = 0; i < a.length(); ++i) {
        result = result + a[i] * b[i];
    }
}

inline ZZ_p InnerProduct(const vec_ZZ_p& a, const vec_ZZ_p& b) {
    ZZ_p result;
    InnerProduct(result, a, b);
    return result;
}

/**
 * @brief Vector addition
 */
inline void add(vec_ZZ_p& c, const vec_ZZ_p& a, const vec_ZZ_p& b) {
    if (a.length() != b.length()) {
        throw std::invalid_argument("vec_ZZ_p add: length mismatch");
    }
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        c[i] = a[i] + b[i];
    }
}

inline vec_ZZ_p operator+(const vec_ZZ_p& a, const vec_ZZ_p& b) {
    vec_ZZ_p c;
    add(c, a, b);
    return c;
}

/**
 * @brief Vector subtraction
 */
inline void sub(vec_ZZ_p& c, const vec_ZZ_p& a, const vec_ZZ_p& b) {
    if (a.length() != b.length()) {
        throw std::invalid_argument("vec_ZZ_p sub: length mismatch");
    }
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        c[i] = a[i] - b[i];
    }
}

inline vec_ZZ_p operator-(const vec_ZZ_p& a, const vec_ZZ_p& b) {
    vec_ZZ_p c;
    sub(c, a, b);
    return c;
}

/**
 * @brief Scalar multiplication
 */
inline void mul(vec_ZZ_p& c, const vec_ZZ_p& a, const ZZ_p& s) {
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        c[i] = a[i] * s;
    }
}

inline vec_ZZ_p operator*(const vec_ZZ_p& a, const ZZ_p& s) {
    vec_ZZ_p c;
    mul(c, a, s);
    return c;
}

inline vec_ZZ_p operator*(const ZZ_p& s, const vec_ZZ_p& a) {
    return a * s;
}

/**
 * @brief Negate vector
 */
inline void negate(vec_ZZ_p& c, const vec_ZZ_p& a) {
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        c[i] = -a[i];
    }
}

inline vec_ZZ_p operator-(const vec_ZZ_p& a) {
    vec_ZZ_p c;
    negate(c, a);
    return c;
}

/**
 * @brief Random vector generation
 */
inline void random(vec_ZZ_p& v, long n) {
    v.SetLength(n);
    for (long i = 0; i < n; ++i) {
        random(v[i]);
    }
}

inline vec_ZZ_p random_vec_ZZ_p(long n) {
    vec_ZZ_p v;
    random(v, n);
    return v;
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_VEC_ZZ_P_H
