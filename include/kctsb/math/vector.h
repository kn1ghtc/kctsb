/**
 * @file vector.h
 * @brief Vector and matrix operations
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_MATH_VECTOR_H
#define KCTSB_MATH_VECTOR_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double* data;
    size_t size;
} kctsb_vector_t;

typedef struct {
    double* data;
    size_t rows;
    size_t cols;
} kctsb_matrix_t;

// Vector operations
KCTSB_API kctsb_vector_t* kctsb_vec_create(size_t size);
KCTSB_API void kctsb_vec_free(kctsb_vector_t* v);
KCTSB_API double kctsb_vec_dot(const kctsb_vector_t* a, const kctsb_vector_t* b);
KCTSB_API double kctsb_vec_norm(const kctsb_vector_t* v);

// Matrix operations
KCTSB_API kctsb_matrix_t* kctsb_mat_create(size_t rows, size_t cols);
KCTSB_API void kctsb_mat_free(kctsb_matrix_t* m);
KCTSB_API kctsb_matrix_t* kctsb_mat_mul(const kctsb_matrix_t* a, const kctsb_matrix_t* b);
KCTSB_API kctsb_matrix_t* kctsb_mat_transpose(const kctsb_matrix_t* m);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_MATH_VECTOR_H
