/**
 * @file polynomials.h
 * @brief Polynomial arithmetic
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_MATH_POLYNOMIALS_H
#define KCTSB_MATH_POLYNOMIALS_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    double* coeffs;
    size_t degree;
} kctsb_polynomial_t;

KCTSB_API kctsb_polynomial_t* kctsb_poly_create(size_t degree);
KCTSB_API void kctsb_poly_free(kctsb_polynomial_t* p);
KCTSB_API kctsb_polynomial_t* kctsb_poly_add(const kctsb_polynomial_t* a, const kctsb_polynomial_t* b);
KCTSB_API kctsb_polynomial_t* kctsb_poly_mul(const kctsb_polynomial_t* a, const kctsb_polynomial_t* b);
KCTSB_API double kctsb_poly_eval(const kctsb_polynomial_t* p, double x);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_MATH_POLYNOMIALS_H
