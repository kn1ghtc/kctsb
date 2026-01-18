
#ifndef KCTSB_mat_poly_ZZ__H
#define KCTSB_mat_poly_ZZ__H

#include <kctsb/math/bignum/mat_ZZ.h>
#include <kctsb/math/bignum/ZZX.h>

KCTSB_OPEN_NNS

void CharPoly(ZZX& f, const mat_ZZ& M, long deterministic=0);

KCTSB_CLOSE_NNS

#endif
