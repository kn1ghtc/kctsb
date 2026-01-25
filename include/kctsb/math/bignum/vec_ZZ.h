/**
 * @file vec_ZZ.h
 * @brief NTL-compatible vector of ZZ elements for kctsb v5.0
 * @author kctsb Team
 * @version 5.0
 * 
 * Self-contained implementation replacing NTL vec_ZZ.
 */

#ifndef KCTSB_MATH_BIGNUM_VEC_ZZ_H
#define KCTSB_MATH_BIGNUM_VEC_ZZ_H

#include <kctsb/math/bignum/ZZ.h>
#include <vector>
#include <stdexcept>
#include <initializer_list>

namespace kctsb {

/**
 * @brief Vector of ZZ elements
 * 
 * NTL-compatible vector class for arbitrary-precision integers.
 */
class vec_ZZ {
public:
    using value_type = ZZ;
    using size_type = long;
    using reference = ZZ&;
    using const_reference = const ZZ&;
    using iterator = std::vector<ZZ>::iterator;
    using const_iterator = std::vector<ZZ>::const_iterator;

private:
    std::vector<ZZ> data_;

public:
    // Constructors
    vec_ZZ() = default;
    
    explicit vec_ZZ(size_type n) : data_(static_cast<size_t>(n)) {}
    
    vec_ZZ(size_type n, const ZZ& val) : data_(static_cast<size_t>(n), val) {}
    
    vec_ZZ(std::initializer_list<ZZ> init) : data_(init) {}
    
    vec_ZZ(const vec_ZZ&) = default;
    vec_ZZ(vec_ZZ&&) noexcept = default;
    vec_ZZ& operator=(const vec_ZZ&) = default;
    vec_ZZ& operator=(vec_ZZ&&) noexcept = default;
    ~vec_ZZ() = default;
    
    // Size and capacity
    size_type length() const noexcept { return static_cast<size_type>(data_.size()); }
    bool empty() const noexcept { return data_.empty(); }
    
    void SetLength(size_type n) { data_.resize(static_cast<size_t>(n)); }
    void SetLength(size_type n, const ZZ& val) { data_.resize(static_cast<size_t>(n), val); }
    
    void kill() { data_.clear(); data_.shrink_to_fit(); }
    
    // Element access (1-indexed for NTL compatibility, but we use 0-indexed internally)
    reference operator[](size_type i) { return data_[static_cast<size_t>(i)]; }
    const_reference operator[](size_type i) const { return data_[static_cast<size_t>(i)]; }
    
    reference operator()(size_type i) { return data_[static_cast<size_t>(i - 1)]; } // 1-indexed
    const_reference operator()(size_type i) const { return data_[static_cast<size_t>(i - 1)]; }
    
    reference at(size_type i) { 
        if (i < 0 || i >= length()) throw std::out_of_range("vec_ZZ index out of range");
        return data_.at(static_cast<size_t>(i)); 
    }
    const_reference at(size_type i) const { 
        if (i < 0 || i >= length()) throw std::out_of_range("vec_ZZ index out of range");
        return data_.at(static_cast<size_t>(i)); 
    }
    
    // Iterators
    iterator begin() noexcept { return data_.begin(); }
    const_iterator begin() const noexcept { return data_.begin(); }
    iterator end() noexcept { return data_.end(); }
    const_iterator end() const noexcept { return data_.end(); }
    
    // Modifiers
    void append(const ZZ& val) { data_.push_back(val); }
    void append(ZZ&& val) { data_.push_back(std::move(val)); }
    
    void swap(vec_ZZ& other) noexcept { data_.swap(other.data_); }
    
    // Comparison
    bool operator==(const vec_ZZ& other) const { return data_ == other.data_; }
    bool operator!=(const vec_ZZ& other) const { return data_ != other.data_; }
    
    // Raw access
    ZZ* elts() noexcept { return data_.data(); }
    const ZZ* elts() const noexcept { return data_.data(); }
};

// Free functions for NTL compatibility

inline void clear(vec_ZZ& v) { v.kill(); }
inline void swap(vec_ZZ& a, vec_ZZ& b) noexcept { a.swap(b); }
inline long IsZero(const vec_ZZ& v) {
    for (long i = 0; i < v.length(); ++i) {
        if (!IsZero(v[i])) return 0;
    }
    return 1;
}

/**
 * @brief Inner product of two vectors
 */
inline void InnerProduct(ZZ& result, const vec_ZZ& a, const vec_ZZ& b) {
    if (a.length() != b.length()) {
        throw std::invalid_argument("vec_ZZ InnerProduct: length mismatch");
    }
    result = ZZ(0);
    ZZ temp;
    for (long i = 0; i < a.length(); ++i) {
        mul(temp, a[i], b[i]);
        add(result, result, temp);
    }
}

inline ZZ InnerProduct(const vec_ZZ& a, const vec_ZZ& b) {
    ZZ result;
    InnerProduct(result, a, b);
    return result;
}

/**
 * @brief Vector addition
 */
inline void add(vec_ZZ& c, const vec_ZZ& a, const vec_ZZ& b) {
    if (a.length() != b.length()) {
        throw std::invalid_argument("vec_ZZ add: length mismatch");
    }
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        add(c[i], a[i], b[i]);
    }
}

inline vec_ZZ operator+(const vec_ZZ& a, const vec_ZZ& b) {
    vec_ZZ c;
    add(c, a, b);
    return c;
}

/**
 * @brief Vector subtraction
 */
inline void sub(vec_ZZ& c, const vec_ZZ& a, const vec_ZZ& b) {
    if (a.length() != b.length()) {
        throw std::invalid_argument("vec_ZZ sub: length mismatch");
    }
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        sub(c[i], a[i], b[i]);
    }
}

inline vec_ZZ operator-(const vec_ZZ& a, const vec_ZZ& b) {
    vec_ZZ c;
    sub(c, a, b);
    return c;
}

/**
 * @brief Scalar multiplication
 */
inline void mul(vec_ZZ& c, const vec_ZZ& a, const ZZ& s) {
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        mul(c[i], a[i], s);
    }
}

inline vec_ZZ operator*(const vec_ZZ& a, const ZZ& s) {
    vec_ZZ c;
    mul(c, a, s);
    return c;
}

inline vec_ZZ operator*(const ZZ& s, const vec_ZZ& a) {
    return a * s;
}

/**
 * @brief Negate vector
 */
inline void negate(vec_ZZ& c, const vec_ZZ& a) {
    c.SetLength(a.length());
    for (long i = 0; i < a.length(); ++i) {
        c[i] = -a[i];
    }
}

inline vec_ZZ operator-(const vec_ZZ& a) {
    vec_ZZ c;
    negate(c, a);
    return c;
}

/**
 * @brief Output stream operator for vec_ZZ
 */
inline std::ostream& operator<<(std::ostream& os, const vec_ZZ& v) {
    os << "[";
    for (long i = 0; i < v.length(); ++i) {
        if (i > 0) os << " ";
        os << v[i];
    }
    os << "]";
    return os;
}

/**
 * @brief Input stream operator for vec_ZZ
 */
inline std::istream& operator>>(std::istream& is, vec_ZZ& v) {
    char c;
    is >> c; // expect '['
    v.kill();
    ZZ elem;
    while (is >> elem) {
        v.append(elem);
        is >> std::ws;
        if (is.peek() == ']') {
            is >> c;
            break;
        }
    }
    return is;
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_VEC_ZZ_H
