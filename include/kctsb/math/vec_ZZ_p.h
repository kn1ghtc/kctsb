/**
 * @file vec_ZZ_p.h
 * @brief Vector of ZZ_p elements
 * 
 * Provides vec_ZZ_p type for use in cryptographic algorithms
 * such as zero-knowledge proofs and homomorphic encryption.
 * Uses std::vector<ZZ_p> as underlying storage.
 * 
 * @version 5.1.0 - Simplified implementation
 */

#ifndef KCTSB_MATH_VEC_ZZ_P_H
#define KCTSB_MATH_VEC_ZZ_P_H

#include "kctsb/math/ZZ_p.h"
#include <vector>

namespace kctsb {

/**
 * @brief Vector of ZZ_p (modular integers)
 */
class vec_ZZ_p {
private:
    std::vector<ZZ_p> data_;
    
public:
    vec_ZZ_p() = default;
    explicit vec_ZZ_p(size_t n) : data_(n) {}
    vec_ZZ_p(size_t n, const ZZ_p& val) : data_(n, val) {}
    
    // Size operations
    size_t length() const { return data_.size(); }
    void SetLength(size_t n) { data_.resize(n); }
    void SetLength(size_t n, const ZZ_p& val) { data_.resize(n, val); }
    bool empty() const { return data_.empty(); }
    
    // Element access
    ZZ_p& operator[](size_t i) { return data_[i]; }
    const ZZ_p& operator[](size_t i) const { return data_[i]; }
    ZZ_p& operator()(size_t i) { return data_[i]; }
    const ZZ_p& operator()(size_t i) const { return data_[i]; }
    
    // Iterators
    auto begin() { return data_.begin(); }
    auto end() { return data_.end(); }
    auto begin() const { return data_.begin(); }
    auto end() const { return data_.end(); }
    
    // Modifiers
    void append(const ZZ_p& val) { data_.push_back(val); }
    void clear() { data_.clear(); }
    
    // Underlying storage access
    std::vector<ZZ_p>& data() { return data_; }
    const std::vector<ZZ_p>& data() const { return data_; }
};

// Free functions for NTL compatibility
inline long IsZero(const vec_ZZ_p& v) { return v.empty() ? 1 : 0; }
inline void clear(vec_ZZ_p& v) { v.clear(); }

} // namespace kctsb

#endif // KCTSB_MATH_VEC_ZZ_P_H
