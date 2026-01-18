/**
 * @file bignum.h
 * @brief Unified bignum include header for kctsb
 *
 * This header provides a single include point for all bignum math functionality
 * integrated into kctsb. Include this header instead of individual bignum headers.
 *
 * All symbols are defined in the kctsb namespace.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_BIGNUM_H
#define KCTSB_MATH_BIGNUM_H

// kctsb bignum configuration (must be first)
#include "kctsb_kctsb_config.h"

// Core types
#include "ZZ.h"
#include "ZZ_p.h"
#include "ZZ_pE.h"

// Single-precision types
#include "lzz_p.h"
#include "lzz_pE.h"

// GF(2) types
#include "GF2.h"
#include "GF2E.h"

// Polynomials
#include "ZZX.h"
#include "ZZ_pX.h"
#include "ZZ_pEX.h"
#include "lzz_pX.h"
#include "lzz_pEX.h"
#include "GF2X.h"
#include "GF2EX.h"

// Matrices
#include "mat_ZZ.h"
#include "mat_ZZ_p.h"
#include "mat_lzz_p.h"
#include "mat_GF2.h"

// Vectors
#include "vec_ZZ.h"
#include "vec_ZZ_p.h"
#include "vec_lzz_p.h"
#include "vec_GF2.h"

// Precision types
#include "RR.h"
#include "xdouble.h"
#include "quad_float.h"

// Lattice algorithms
#include "LLL.h"
#include "HNF.h"

// Factorization
#include "ZZXFactoring.h"
#include "ZZ_pXFactoring.h"
#include "GF2XFactoring.h"

// FFT
#include "FFT.h"

#endif // KCTSB_MATH_BIGNUM_H
