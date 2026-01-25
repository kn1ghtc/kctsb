/**
 * @file ZZ_pXFactoring.h
 * @brief NTL Compatibility Layer - Polynomial Factoring over Z/pZ
 * 
 * Stub header for polynomial factorization.
 * 
 * @version 5.0.0 - Stub implementation
 */

#ifndef KCTSB_MATH_BIGNUM_ZZ_PXFACTORING_H
#define KCTSB_MATH_BIGNUM_ZZ_PXFACTORING_H

#include "ZZ_pX.h"
#include <vector>

namespace kctsb {

using vec_pair_ZZ_pX_long = std::vector<std::pair<ZZ_pX, long>>;

inline void factor(vec_pair_ZZ_pX_long& factors, const ZZ_pX& f) {
    factors.clear();
    if (!f.IsZero()) {
        factors.push_back({f, 1});
    }
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_ZZ_PXFACTORING_H
