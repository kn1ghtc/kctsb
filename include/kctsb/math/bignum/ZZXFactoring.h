/**
 * @file ZZXFactoring.h
 * @brief NTL Compatibility Layer - Polynomial Factoring
 * 
 * Stub header for polynomial factorization over integers.
 * This is a minimal compatibility layer for v5.0.
 * 
 * @version 5.0.0 - Stub implementation
 */

#ifndef KCTSB_MATH_BIGNUM_ZZXFACTORING_H
#define KCTSB_MATH_BIGNUM_ZZXFACTORING_H

#include "ZZX.h"
#include <vector>

namespace kctsb {

/**
 * @brief Polynomial factoring result
 */
using vec_pair_ZZX_long = std::vector<std::pair<ZZX, long>>;

/**
 * @brief Factor polynomial (stub - not fully implemented)
 */
inline void factor(ZZ& content, vec_pair_ZZX_long& factors, const ZZX& f) {
    content = ZZ(1);
    factors.clear();
    if (!f.IsZero()) {
        factors.push_back({f, 1});
    }
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_ZZXFACTORING_H
