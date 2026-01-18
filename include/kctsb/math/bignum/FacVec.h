
#ifndef KCTSB_FacVec__H
#define KCTSB_FacVec__H

#include <kctsb/math/bignum/vector.h>

KCTSB_OPEN_NNS

struct IntFactor {
   long q;
   long a;
   long val;
   long link;
};


typedef Vec<IntFactor> vec_IntFactor;
typedef vec_IntFactor FacVec;

void FactorInt(FacVec& fvec, long n);

KCTSB_CLOSE_NNS

#endif
