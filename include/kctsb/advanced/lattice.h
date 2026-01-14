/**
 * @file lattice.h
 * @brief Lattice-based cryptography primitives
 * 
 * Post-quantum cryptographic primitives based on lattice problems:
 * - LLL basis reduction
 * - Learning With Errors (LWE)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_ADVANCED_LATTICE_H
#define KCTSB_ADVANCED_LATTICE_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief LLL basis reduction algorithm
 * @param basis Input basis matrix (row vectors)
 * @param rows Number of rows
 * @param cols Number of columns
 * @param delta LLL parameter (typically 0.75)
 * @param reduced Output reduced basis
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_lll_reduce(
    const double* basis,
    int rows,
    int cols,
    double delta,
    double* reduced
);

/**
 * @brief LLL self test
 * @return KCTSB_SUCCESS if test passes
 */
KCTSB_API kctsb_error_t kctsb_lll_self_test(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <vector>

namespace kctsb {

/**
 * @brief Lattice operations
 */
class Lattice {
public:
    using Matrix = std::vector<std::vector<double>>;
    
    /**
     * @brief LLL basis reduction
     * @param basis Input basis
     * @param delta LLL parameter (default 0.75)
     * @return Reduced basis
     */
    static Matrix lllReduce(const Matrix& basis, double delta = 0.75);
    
    /**
     * @brief Compute Gram-Schmidt orthogonalization
     * @param basis Input basis
     * @return Orthogonalized basis
     */
    static Matrix gramSchmidt(const Matrix& basis);
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_LATTICE_H
