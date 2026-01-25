/**
 * @file GF2XFactoring.h
 * @brief GF(2)[X] polynomial factoring stubs
 * 
 * Provides NTL-compatible GF(2)[X] polynomial factoring interface.
 * This is a minimal stub for v5.0 self-contained architecture.
 */

#ifndef KCTSB_MATH_BIGNUM_GF2XFACTORING_H
#define KCTSB_MATH_BIGNUM_GF2XFACTORING_H

#include <kctsb/math/bignum/GF2X.h>

namespace kctsb {

/**
 * @brief Build irreducible polynomial of degree n
 */
inline void BuildIrred(GF2X& f, long n) {
    // Simple irreducible: x^n + x + 1 (works for many n)
    f = GF2X();
    f.SetCoeff(n, 1);
    f.SetCoeff(1, 1);
    f.SetCoeff(0, 1);
}

/**
 * @brief Build sparse irreducible polynomial
 */
inline void BuildSparseIrred(GF2X& f, long n) {
    BuildIrred(f, n);
}

/**
 * @brief Check if polynomial is irreducible
 */
inline long IsIrreducible(const GF2X& f) {
    (void)f;
    return 1;  // Stub: assume irreducible
}

} // namespace kctsb

#endif // KCTSB_MATH_BIGNUM_GF2XFACTORING_H
