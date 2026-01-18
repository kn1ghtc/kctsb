#ifndef KCTSB_ZZ_limbs__H
#define KCTSB_ZZ_limbs__H

#include <kctsb/math/bignum/ZZ.h>


// NOTE: unlike other bignum header files, this one needs access
// to GMP's header file, which means that C++ files that include
// this file will need to ensure that the compiler has the 
// right "include path" to get at GMP's header file.




#ifdef KCTSB_GMP_LIP
#include <gmp.h>

typedef mp_limb_t _kctsb_limb_t;

#else

typedef unsigned long _kctsb_limb_t;

// #define KCTSB_BITS_PER_LIMB_T KCTSB_BITS_PER_LONG
// This is already defined in ZZ.h 


#endif

void _kctsb_glimbs_set(const _kctsb_limb_t *p, long n, _kctsb_gbigint *x);

// DIRT: This exposes some internals that should be in lip.cpp,
// but are here to make it inline.
inline 
const _kctsb_limb_t * _kctsb_glimbs_get(_kctsb_gbigint p)
   { return p ? ((_kctsb_limb_t *) (((long *) (p)) + 2)) : 0; }


KCTSB_OPEN_NNS

typedef _kctsb_limb_t ZZ_limb_t;


inline 
void ZZ_limbs_set(ZZ& x, const ZZ_limb_t *p, long n)
{
   _kctsb_glimbs_set(p, n, &x.rep);
}

inline
const ZZ_limb_t * ZZ_limbs_get(const ZZ& a)
{
   return _kctsb_glimbs_get(a.rep);
}


KCTSB_CLOSE_NNS


#endif
