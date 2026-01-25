/**
 * @file mat_GF2.h
 * @brief NTL-compatible matrix over GF(2) for kctsb v5.0
 * @author kctsb Team
 * @version 5.0
 * 
 * Self-contained implementation replacing NTL mat_GF2.
 */

#ifndef KCTSB_MATH_BIGNUM_MAT_GF2_H
#define KCTSB_MATH_BIGNUM_MAT_GF2_H

#include <kctsb/math/bignum/GF2X.h>
#include <kctsb/core/zz.h>
#include <vector>
#include <stdexcept>
#include <cstdint>

namespace kctsb {

/**
 * @brief Element of GF(2) - single bit
 */
class GF2 {
private:
    uint8_t bit_;

public:
    GF2() : bit_(0) {}
    explicit GF2(long val) : bit_(static_cast<uint8_t>(val & 1)) {}
    explicit GF2(int val) : bit_(static_cast<uint8_t>(val & 1)) {}
    
    GF2(const GF2&) = default;
    GF2& operator=(const GF2&) = default;
    
    // Conversion
    explicit operator long() const { return static_cast<long>(bit_); }
    explicit operator int() const { return static_cast<int>(bit_); }
    long IsOne() const { return bit_ == 1 ? 1 : 0; }
    long IsZero() const { return bit_ == 0 ? 1 : 0; }
    
    // Arithmetic (in GF(2), addition = XOR)
    GF2 operator+(const GF2& other) const { return GF2(bit_ ^ other.bit_); }
    GF2 operator-(const GF2& other) const { return GF2(bit_ ^ other.bit_); } // Same as +
    GF2 operator*(const GF2& other) const { return GF2(bit_ & other.bit_); }
    
    GF2& operator+=(const GF2& other) { bit_ ^= other.bit_; return *this; }
    GF2& operator-=(const GF2& other) { bit_ ^= other.bit_; return *this; }
    GF2& operator*=(const GF2& other) { bit_ &= other.bit_; return *this; }
    
    // Comparison
    bool operator==(const GF2& other) const { return bit_ == other.bit_; }
    bool operator!=(const GF2& other) const { return bit_ != other.bit_; }
};

inline long IsZero(const GF2& a) { return a.IsZero(); }
inline long IsOne(const GF2& a) { return a.IsOne(); }
inline void clear(GF2& a) { a = GF2(0); }
inline void set(GF2& a) { a = GF2(1); }

/** @brief Convert int to GF2 */
inline GF2 to_GF2(int val) { return GF2(val); }

/** @brief Convert long to GF2 */
inline GF2 to_GF2(long val) { return GF2(val); }

/** @brief Convert ZZ to GF2 */
inline GF2 to_GF2(const ZZ& val) { 
    return GF2(val.is_odd() ? 1 : 0); 
}

/**
 * @brief Vector over GF(2)
 */
class vec_GF2 {
private:
    std::vector<uint8_t> data_; // Packed bits
    long length_;

    // Helper to access bit
    void set_bit(long i, bool val) {
        long byte_idx = i / 8;
        long bit_idx = i % 8;
        if (val) {
            data_[static_cast<size_t>(byte_idx)] |= static_cast<uint8_t>(1 << bit_idx);
        } else {
            data_[static_cast<size_t>(byte_idx)] &= static_cast<uint8_t>(~(1 << bit_idx));
        }
    }
    
    bool get_bit(long i) const {
        long byte_idx = i / 8;
        long bit_idx = i % 8;
        return (data_[static_cast<size_t>(byte_idx)] >> bit_idx) & 1;
    }

public:
    vec_GF2() : length_(0) {}
    
    explicit vec_GF2(long n) : length_(n) {
        data_.resize(static_cast<size_t>((n + 7) / 8), 0);
    }
    
    long length() const { return length_; }
    
    void SetLength(long n) {
        data_.resize(static_cast<size_t>((n + 7) / 8), 0);
        length_ = n;
    }
    
    void kill() { data_.clear(); length_ = 0; }
    
    // Element access - returns a proxy or value
    GF2 get(long i) const { return GF2(get_bit(i) ? 1 : 0); }
    void put(long i, const GF2& val) { set_bit(i, static_cast<long>(val) != 0); }
    void put(long i, long val) { set_bit(i, (val & 1) != 0); }
    
    // For compatibility with NTL-style indexing
    GF2 operator[](long i) const { return get(i); }
    
    void swap(vec_GF2& other) {
        data_.swap(other.data_);
        std::swap(length_, other.length_);
    }
    
    bool IsZero() const {
        for (auto b : data_) {
            if (b != 0) return false;
        }
        return true;
    }
};

inline void swap(vec_GF2& a, vec_GF2& b) { a.swap(b); }
inline long IsZero(const vec_GF2& v) { return v.IsZero() ? 1 : 0; }

/**
 * @brief Matrix over GF(2)
 */
class mat_GF2 {
private:
    std::vector<vec_GF2> rows_;
    long num_rows_;
    long num_cols_;

public:
    mat_GF2() : num_rows_(0), num_cols_(0) {}
    
    mat_GF2(long r, long c) : num_rows_(r), num_cols_(c) {
        rows_.resize(static_cast<size_t>(r));
        for (auto& row : rows_) {
            row.SetLength(c);
        }
    }
    
    long NumRows() const { return num_rows_; }
    long NumCols() const { return num_cols_; }
    
    void SetDims(long r, long c) {
        rows_.resize(static_cast<size_t>(r));
        for (auto& row : rows_) {
            row.SetLength(c);
        }
        num_rows_ = r;
        num_cols_ = c;
    }
    
    void kill() {
        rows_.clear();
        num_rows_ = 0;
        num_cols_ = 0;
    }
    
    // Row access
    vec_GF2& operator[](long i) { return rows_[static_cast<size_t>(i)]; }
    const vec_GF2& operator[](long i) const { return rows_[static_cast<size_t>(i)]; }
    
    // Element access
    GF2 get(long i, long j) const { return rows_[static_cast<size_t>(i)].get(j); }
    void put(long i, long j, const GF2& val) { rows_[static_cast<size_t>(i)].put(j, val); }
    void put(long i, long j, long val) { rows_[static_cast<size_t>(i)].put(j, val); }
    
    void swap_rows(long i, long j) {
        rows_[static_cast<size_t>(i)].swap(rows_[static_cast<size_t>(j)]);
    }
    
    bool IsZero() const {
        for (const auto& row : rows_) {
            if (!row.IsZero()) return false;
        }
        return true;
    }
};

inline long IsZero(const mat_GF2& M) { return M.IsZero() ? 1 : 0; }

/**
 * @brief Gaussian elimination on GF(2) matrix
 * @return Rank of matrix
 */
inline long gauss(mat_GF2& M) {
    long n = M.NumRows();
    long m = M.NumCols();
    long rank = 0;
    
    for (long col = 0; col < m && rank < n; ++col) {
        // Find pivot
        long pivot = -1;
        for (long row = rank; row < n; ++row) {
            if (IsOne(M.get(row, col))) {
                pivot = row;
                break;
            }
        }
        
        if (pivot < 0) continue;
        
        if (pivot != rank) {
            M.swap_rows(pivot, rank);
        }
        
        // Eliminate
        for (long row = 0; row < n; ++row) {
            if (row != rank && IsOne(M.get(row, col))) {
                // XOR rows
                for (long j = 0; j < m; ++j) {
                    GF2 val = M.get(row, j) + M.get(rank, j);
                    M.put(row, j, val);
                }
            }
        }
        
        ++rank;
    }
    
    return rank;
}

/**
 * @brief Matrix-vector multiplication
 */
inline void mul(vec_GF2& result, const mat_GF2& M, const vec_GF2& v) {
    if (M.NumCols() != v.length()) {
        throw std::invalid_argument("mat_GF2 mul: dimension mismatch");
    }
    
    result.SetLength(M.NumRows());
    for (long i = 0; i < M.NumRows(); ++i) {
        GF2 sum(0);
        for (long j = 0; j < M.NumCols(); ++j) {
            sum += M.get(i, j) * v.get(j);
        }
        result.put(i, sum);
    }
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_MAT_GF2_H
