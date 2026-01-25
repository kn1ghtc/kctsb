/**
 * @file GF2EXFactoring.h
 * @brief GF2EX polynomial factoring stubs for v5.0
 */

#ifndef KCTSB_MATH_BIGNUM_GF2EXFACTORING_H
#define KCTSB_MATH_BIGNUM_GF2EXFACTORING_H

#include <kctsb/math/bignum/GF2EX.h>
#include <vector>

namespace kctsb {

/**
 * @brief Factor GF2EX polynomial (stub)
 */
inline void factor(std::vector<std::pair<GF2EX, long>>& factors, const GF2EX& f) {
    (void)f;
    factors.clear();
}

/**
 * @brief Check if GF2EX polynomial is irreducible (stub)
 */
inline long IsIrreducible(const GF2EX& f) {
    (void)f;
    return 1;
}

/**
 * @brief Build irreducible GF2EX polynomial
 */
inline void BuildIrred(GF2EX& f, long n) {
    f = GF2EX();
    f.SetCoeff(n, 1);
    f.SetCoeff(0, 1);
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_GF2EXFACTORING_H
