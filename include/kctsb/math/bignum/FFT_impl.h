
#ifndef KCTSB_FFT_impl__H
#define KCTSB_FFT_impl__H

#include <kctsb/math/bignum/tools.h>

KCTSB_OPEN_NNS

#ifdef KCTSB_ENABLE_AVX_FFT

#if (!defined(KCTSB_HAVE_AVX512F) && !(defined(KCTSB_HAVE_AVX2) && defined(KCTSB_HAVE_FMA)))
#error "KCTSB_ENABLE_AVX_FFT: not supported on this platform"
#endif

#if (defined(KCTSB_HAVE_AVX512F) && !defined(KCTSB_AVOID_AVX512))
#define KCTSB_LG2_PDSZ (3)
#else
#define KCTSB_LG2_PDSZ (2)
#endif

#define KCTSB_FFT_RDUP (KCTSB_LG2_PDSZ+3)
#define KCTSB_PDSZ (1 << KCTSB_LG2_PDSZ)

#else

#define KCTSB_FFT_RDUP (4)
// Currently, this should be at least 2 to support
// loop unrolling in the FFT implementation

#endif

inline
long FFTRoundUp(long xn, long k)
// Assumes k >= 0.
// Returns an integer m such that 1 <= m <= n = 2^k and 
// m divsisible my 2^KCTSB_FFT_RDUP.
// Also, if xn <= n, then m >= xn.
{
   long n = 1L << k;
   if (xn <= 0) xn = 1;

   xn = ((xn+((1L << KCTSB_FFT_RDUP)-1)) >> KCTSB_FFT_RDUP) << KCTSB_FFT_RDUP; 

   if (k >= 10) {
      if (xn > n - (n >> 4)) xn = n;
   }
   else {
      if (xn > n - (n >> 3)) xn = n;
   }
   // truncation just a bit below n does not really help
   // at all, and can sometimes slow things down slightly, so round up 
   // to n.  This also takes care of cases where xn > n.
   // Actually, for smallish n, we should round up sooner,
   // at n-n/8, and for larger n, we should round up later,
   // at n-m/16.  At least, experimentally, this is what I see.

   return xn;
}


KCTSB_CLOSE_NNS

#endif
