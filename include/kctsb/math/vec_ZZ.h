/**
 * @file vec_ZZ.h
 * @brief Vector of ZZ elements
 * 
 * Provides vec_ZZ type for use in cryptographic algorithms.
 * Uses std::vector<ZZ> as underlying storage.
 * 
 * @version 5.1.0 - Simplified implementation
 */

#ifndef KCTSB_MATH_VEC_ZZ_H
#define KCTSB_MATH_VEC_ZZ_H

#include "kctsb/math/ZZ.h"
#include <vector>

namespace kctsb {

/**
 * @brief Vector of ZZ (big integers)
 */
class vec_ZZ {
private:
    std::vector<ZZ> data_;
    
public:
    vec_ZZ() = default;
    explicit vec_ZZ(size_t n) : data_(n) {}
    vec_ZZ(size_t n, const ZZ& val) : data_(n, val) {}
    
    // Size operations
    size_t length() const { return data_.size(); }
    void SetLength(size_t n) { data_.resize(n); }
    void SetLength(size_t n, const ZZ& val) { data_.resize(n, val); }
    bool empty() const { return data_.empty(); }
    
    // Element access
    ZZ& operator[](size_t i) { return data_[i]; }
    const ZZ& operator[](size_t i) const { return data_[i]; }
    ZZ& operator()(size_t i) { return data_[i]; }
    const ZZ& operator()(size_t i) const { return data_[i]; }
    
    // Iterators
    auto begin() { return data_.begin(); }
    auto end() { return data_.end(); }
    auto begin() const { return data_.begin(); }
    auto end() const { return data_.end(); }
    
    // Modifiers
    void append(const ZZ& val) { data_.push_back(val); }
    void clear() { data_.clear(); }
    
    // Underlying storage access
    std::vector<ZZ>& data() { return data_; }
    const std::vector<ZZ>& data() const { return data_; }
};

// Free functions for NTL compatibility
inline long IsZero(const vec_ZZ& v) { return v.empty() ? 1 : 0; }
inline void clear(vec_ZZ& v) { v.clear(); }

} // namespace kctsb

#endif // KCTSB_MATH_VEC_ZZ_H
