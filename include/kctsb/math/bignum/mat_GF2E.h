/**
 * @file mat_GF2E.h
 * @brief NTL-compatible matrix over GF(2^n) for kctsb v5.0
 * @author kctsb Team
 * @version 5.0
 * 
 * Self-contained implementation replacing NTL mat_GF2E.
 */

#ifndef KCTSB_MATH_BIGNUM_MAT_GF2E_H
#define KCTSB_MATH_BIGNUM_MAT_GF2E_H

#include <kctsb/math/bignum/GF2E.h>
#include <vector>
#include <stdexcept>

namespace kctsb {

/**
 * @brief Vector of GF2E elements
 */
class vec_GF2E {
public:
    using value_type = GF2E;
    using size_type = long;

private:
    std::vector<GF2E> data_;

public:
    vec_GF2E() = default;
    explicit vec_GF2E(size_type n) : data_(static_cast<size_t>(n)) {}
    
    size_type length() const { return static_cast<size_type>(data_.size()); }
    
    void SetLength(size_type n) { data_.resize(static_cast<size_t>(n)); }
    void kill() { data_.clear(); }
    
    GF2E& operator[](size_type i) { return data_[static_cast<size_t>(i)]; }
    const GF2E& operator[](size_type i) const { return data_[static_cast<size_t>(i)]; }
    
    void swap(vec_GF2E& other) { data_.swap(other.data_); }
    
    bool operator==(const vec_GF2E& other) const { return data_ == other.data_; }
    bool operator!=(const vec_GF2E& other) const { return data_ != other.data_; }
};

inline void swap(vec_GF2E& a, vec_GF2E& b) { a.swap(b); }
inline long IsZero(const vec_GF2E& v) {
    for (long i = 0; i < v.length(); ++i) {
        if (!IsZero(v[i])) return 0;
    }
    return 1;
}

/**
 * @brief Matrix over GF(2^n)
 */
class mat_GF2E {
private:
    std::vector<vec_GF2E> rows_;
    long num_rows_;
    long num_cols_;

public:
    mat_GF2E() : num_rows_(0), num_cols_(0) {}
    
    mat_GF2E(long r, long c) : num_rows_(r), num_cols_(c) {
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
    
    vec_GF2E& operator[](long i) { return rows_[static_cast<size_t>(i)]; }
    const vec_GF2E& operator[](long i) const { return rows_[static_cast<size_t>(i)]; }
    
    void swap_rows(long i, long j) {
        rows_[static_cast<size_t>(i)].swap(rows_[static_cast<size_t>(j)]);
    }
    
    bool IsZero() const {
        for (const auto& row : rows_) {
            if (!kctsb::IsZero(row)) return false;
        }
        return true;
    }
};

inline long IsZero(const mat_GF2E& M) { return M.IsZero() ? 1 : 0; }

/**
 * @brief Gaussian elimination on GF(2^n) matrix
 * @return Rank of matrix
 */
inline long gauss(mat_GF2E& M) {
    long n = M.NumRows();
    long m = M.NumCols();
    long rank = 0;
    
    for (long col = 0; col < m && rank < n; ++col) {
        // Find pivot
        long pivot = -1;
        for (long row = rank; row < n; ++row) {
            if (!IsZero(M[row][col])) {
                pivot = row;
                break;
            }
        }
        
        if (pivot < 0) continue;
        
        if (pivot != rank) {
            M.swap_rows(pivot, rank);
        }
        
        // Normalize pivot row (TODO: multiply by inverse)
        // Eliminate (simplified - full implementation needs field arithmetic)
        
        ++rank;
    }
    
    return rank;
}

/**
 * @brief Matrix-vector multiplication
 */
inline void mul(vec_GF2E& result, const mat_GF2E& M, const vec_GF2E& v) {
    if (M.NumCols() != v.length()) {
        throw std::invalid_argument("mat_GF2E mul: dimension mismatch");
    }
    
    result.SetLength(M.NumRows());
    for (long i = 0; i < M.NumRows(); ++i) {
        GF2E sum;
        clear(sum);
        for (long j = 0; j < M.NumCols(); ++j) {
            sum += M[i][j] * v[j];
        }
        result[i] = sum;
    }
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_MAT_GF2E_H
