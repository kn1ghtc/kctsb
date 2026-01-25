/**
 * @file mat_ZZ.h
 * @brief Matrix of ZZ elements - v5.0 Self-Contained Implementation
 * 
 * @author knightc
 * @version 5.0.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_BIGNUM_MAT_ZZ_H
#define KCTSB_MATH_BIGNUM_MAT_ZZ_H

#include <kctsb/math/bignum/vec_ZZ.h>
#include <vector>
#include <stdexcept>

namespace kctsb {

/**
 * @brief Matrix of arbitrary-precision integers
 */
class mat_ZZ {
private:
    std::vector<vec_ZZ> rows_;
    long num_rows_ = 0;
    long num_cols_ = 0;
    
public:
    /** @brief Default constructor */
    mat_ZZ() = default;
    
    /** @brief Construct with dimensions */
    mat_ZZ(long rows, long cols) : num_rows_(rows), num_cols_(cols) {
        rows_.resize(static_cast<size_t>(rows));
        for (auto& row : rows_) {
            row.SetLength(cols);
        }
    }
    
    /** @brief Get number of rows */
    long NumRows() const { return num_rows_; }
    
    /** @brief Get number of columns */
    long NumCols() const { return num_cols_; }
    
    /** @brief Set dimensions */
    void SetDims(long rows, long cols) {
        num_rows_ = rows;
        num_cols_ = cols;
        rows_.resize(static_cast<size_t>(rows));
        for (auto& row : rows_) {
            row.SetLength(cols);
        }
    }
    
    /** @brief Access element */
    ZZ& operator()(long i, long j) {
        return rows_[static_cast<size_t>(i)][j];
    }
    
    const ZZ& operator()(long i, long j) const {
        return rows_[static_cast<size_t>(i)][j];
    }
    
    /** @brief Access row */
    vec_ZZ& operator[](long i) {
        return rows_[static_cast<size_t>(i)];
    }
    
    const vec_ZZ& operator[](long i) const {
        return rows_[static_cast<size_t>(i)];
    }
    
    /** @brief Clear matrix */
    void clear() {
        rows_.clear();
        num_rows_ = num_cols_ = 0;
    }
    
    /** @brief Kill (same as clear) */
    void kill() { clear(); }
    
    /** @brief Swap two rows */
    void swap_rows(long i, long j) {
        if (i < num_rows_ && j < num_rows_ && i >= 0 && j >= 0) {
            rows_[static_cast<size_t>(i)].swap(rows_[static_cast<size_t>(j)]);
        }
    }
};

/** @brief Clear matrix */
inline void clear(mat_ZZ& M) { M.clear(); }

/** @brief Check if matrix is zero */
inline long IsZero(const mat_ZZ& M) {
    for (long i = 0; i < M.NumRows(); ++i) {
        if (!IsZero(M[i])) return 0;
    }
    return 1;
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_MAT_ZZ_H
