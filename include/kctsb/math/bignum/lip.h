
#ifndef KCTSB_g_lip__H
#define KCTSB_g_lip__H

#include <kctsb/math/bignum/ctools.h>

#ifdef KCTSB_GMP_LIP
#include <kctsb/math/bignum/gmp_aux.h>
#endif


/*
 * This way of defining the bigint handle type is a bit non-standard,
 * but better for debugging.
 */

struct _kctsb_gbigint_body {
   long alloc_;
   long size_;
};

typedef _kctsb_gbigint_body *_kctsb_gbigint;




#ifdef KCTSB_GMP_LIP


#if (defined(KCTSB_HAVE_LL_TYPE) && !defined(KCTSB_LEGACY_SP_MULMOD))

#define KCTSB_LONGLONG_SP_MULMOD

// on 64 bit machines, hold KCTSB_SP_NBITS to 60 bits,
// as certain operations (in particular, TBL_REM in g_lip_impl.h)
// are a bit faster


#if (!defined(KCTSB_MAXIMIZE_SP_NBITS) && KCTSB_BITS_PER_LONG >= 64)
#define KCTSB_SP_NBITS (KCTSB_BITS_PER_LONG-4)
#else
#define KCTSB_SP_NBITS (KCTSB_BITS_PER_LONG-2)
#endif


#if (defined(KCTSB_ENABLE_AVX_FFT) && (KCTSB_SP_NBITS > 50))
#undef KCTSB_SP_NBITS
#define KCTSB_SP_NBITS (50)
#endif


#elif (KCTSB_LONGDOUBLE_OK && !defined(KCTSB_LEGACY_SP_MULMOD) && !defined(KCTSB_DISABLE_LONGDOUBLE) && !defined(KCTSB_ENABLE_AVX_FFT))

#define KCTSB_LONGDOUBLE_SP_MULMOD

#define KCTSB_SP_NBITS KCTSB_WNBITS_MAX

// on 64 bit machines, hold KCTSB_SP_NBITS to 60 bits (see above)

#if (!defined(KCTSB_MAXIMIZE_SP_NBITS) && KCTSB_BITS_PER_LONG >= 64 && KCTSB_SP_NBITS > KCTSB_BITS_PER_LONG-4)
#undef KCTSB_SP_NBITS
#define KCTSB_SP_NBITS (KCTSB_BITS_PER_LONG-4)
#endif


#else


#define KCTSB_SP_NBITS KCTSB_NBITS_MAX


#endif

#if (KCTSB_SP_NBITS > KCTSB_ZZ_NBITS)
// if nails, we need to ensure KCTSB_SP_NBITS does not exceed
// KCTSB_ZZ_NBITS

#undef KCTSB_SP_NBITS
#define KCTSB_SP_NBITS KCTSB_ZZ_NBITS
#endif

#define KCTSB_NSP_NBITS KCTSB_NBITS_MAX
#if (KCTSB_NSP_NBITS > KCTSB_SP_NBITS)
#undef KCTSB_NSP_NBITS
#define KCTSB_NSP_NBITS KCTSB_SP_NBITS
#endif

#define KCTSB_WSP_NBITS (KCTSB_BITS_PER_LONG-2)
#if (KCTSB_WSP_NBITS > KCTSB_ZZ_NBITS)
// if nails, we need to ensure KCTSB_WSP_NBITS does not exceed
// KCTSB_ZZ_NBITS

#undef KCTSB_WSP_NBITS
#define KCTSB_WSP_NBITS KCTSB_ZZ_NBITS
#endif

// KCTSB_SP_BOUND, KCTSB_NSP_BOUND, KCTSB_WSP_BOUND
// With KCTSB_BITS_PER_LONG=32 on Windows, KCTSB_SP_NBITS<=30, so 1L is safe
#define KCTSB_SP_BOUND (1L << KCTSB_SP_NBITS)
#define KCTSB_NSP_BOUND (1L << KCTSB_NSP_NBITS)
#define KCTSB_WSP_BOUND (1L << KCTSB_WSP_NBITS)

/* define the following so an error is raised */

#define KCTSB_RADIX ......
#define KCTSB_NBITSH ......
#define KCTSB_RADIXM ......
#define KCTSB_RADIXROOT ......
#define KCTSB_RADIXROOTM ......
#define KCTSB_FRADIX_INV ......




#else

#define KCTSB_NBITS KCTSB_NBITS_MAX


#define KCTSB_RADIX           (1L<<KCTSB_NBITS)
#define KCTSB_NBITSH          (KCTSB_NBITS>>1)
#define KCTSB_RADIXM          (KCTSB_RADIX-1)
#define KCTSB_RADIXROOT       (1L<<KCTSB_NBITSH)
#define KCTSB_RADIXROOTM      (KCTSB_RADIXROOT-1)

#define KCTSB_FRADIX ((double) KCTSB_RADIX)
#define KCTSB_FRADIX_INV  (((double) 1.0)/((double) KCTSB_RADIX))

// These are now defined in kctsb_bignum_config.h and gmp_aux.h
// Do NOT redefine them here - they must match GMP's limb size
// #define KCTSB_BITS_PER_LIMB_T KCTSB_BITS_PER_LONG  // WRONG for GMP mode
// #define KCTSB_ZZ_NBITS KCTSB_NBITS                 // WRONG - see kctsb_bignum_config.h

// Fallback only if not already defined (should come from config/gmp_aux.h)
#ifndef KCTSB_ZZ_FRADIX
    #define KCTSB_ZZ_FRADIX ((double) (1ULL << KCTSB_ZZ_NBITS))
#endif
#ifndef KCTSB_ZZ_WIDE_FRADIX
    #define KCTSB_ZZ_WIDE_FRADIX ((double) (1ULL << KCTSB_ZZ_NBITS))
#endif

#define KCTSB_SP_NBITS KCTSB_NBITS
#define KCTSB_SP_BOUND (1L << KCTSB_SP_NBITS)

#define KCTSB_NSP_NBITS KCTSB_NBITS
#define KCTSB_NSP_BOUND (1L << KCTSB_NSP_NBITS)

#define KCTSB_WSP_NBITS KCTSB_ZZ_NBITS
#define KCTSB_WSP_BOUND (1ULL << KCTSB_WSP_NBITS)



// Legacy function
long _kctsb_gdigit(_kctsb_gbigint a, long i);

#endif


// Some sanity checks on KCTSB_SP_NBITS...

// First check that KCTSB_SP_NBITS >= 30, as the documentation
// guarantees this.  This should only be a problem if GMP
// uses some really funny nail bits.

#if (KCTSB_SP_NBITS < 30)
#error "KCTSB_SP_NBITS too small"
#endif

// Second, check that KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS == 2 or 
// KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS >= 4.
// Some code in sp_arith.h seems to rely on this assumption.
// Again, this should only be a problem if GMP
// uses some really funny nail bits.

#if (KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS != 2 && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS < 4)
#error "KCTSB_SP_NBITS is invalid"
#endif






// DIRT: These are copied from lip.cpp file

inline long& _kctsb_ALLOC(_kctsb_gbigint p)
   { return p->alloc_; }

inline long& _kctsb_SIZE(_kctsb_gbigint p)
   { return p->size_; }

inline long _kctsb_ZEROP(_kctsb_gbigint p)
{
   return !p || !_kctsb_SIZE(p);
}

inline long _kctsb_PINNED(_kctsb_gbigint p)
  { return p && (_kctsb_ALLOC(p) & 1); }


/***********************************************************************

   Basic Functions

***********************************************************************/
    


    void _kctsb_gsadd(_kctsb_gbigint a, long d, _kctsb_gbigint *b);
       /* *b = a + d */

    void _kctsb_gssub(_kctsb_gbigint a, long d, _kctsb_gbigint *b);
       /* *b = a - d */

    void _kctsb_gadd(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
       /*  *c = a + b */

    void _kctsb_gsub(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
       /* *c = a - b */

    void _kctsb_gsubpos(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
       /* *c = a - b; assumes a >= b >= 0 */

    void _kctsb_gsmul(_kctsb_gbigint a, long d, _kctsb_gbigint *b);
       /* *b = d * a */

    void _kctsb_gmul(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
       /* *c = a * b */

    void _kctsb_gsq(_kctsb_gbigint a, _kctsb_gbigint *c);
       /* *c = a * a */

    long _kctsb_gsdiv(_kctsb_gbigint a, long b, _kctsb_gbigint *q);
       /* (*q) = floor(a/b) and a - floor(a/b)*(*q) is returned;
          error is raised if b == 0;
          if b does not divide a, then sign(*q) == sign(b) */

    void _kctsb_gdiv(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *q, _kctsb_gbigint *r);
       /* (*q) = floor(a/b) and (*r) = a - floor(a/b)*(*q);
          error is raised if b == 0;
          if b does not divide a, then sign(*q) == sign(b) */

    void _kctsb_gmod(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *r);
       /* same as _kctsb_gdiv, but only remainder is computed */

    long _kctsb_gsmod(_kctsb_gbigint a, long d);
       /* same as _kctsb_gsdiv, but only remainder is computed */

    void _kctsb_gquickmod(_kctsb_gbigint *r, _kctsb_gbigint b);
       /* *r = *r % b; 
	  The division is performed in place (but may sometimes
	  assumes b > 0 and *r >= 0;
          cause *r to grow by one digit) */

    void _kctsb_gsaddmul(_kctsb_gbigint x, long y,  _kctsb_gbigint *ww);
      /* *ww += x*y */

    void _kctsb_gaddmul(_kctsb_gbigint x, _kctsb_gbigint y,  _kctsb_gbigint *ww);
      /* *ww += x*y */

    void _kctsb_gssubmul(_kctsb_gbigint x, long y,  _kctsb_gbigint *ww);
      /* *ww -= x*y */

    void _kctsb_gsubmul(_kctsb_gbigint x, _kctsb_gbigint y,  _kctsb_gbigint *ww);
      /* *ww -= x*y */





/********************************************************************

   Shifting and bit manipulation

*********************************************************************/


    void _kctsb_glshift(_kctsb_gbigint n, long k, _kctsb_gbigint *a);
       /* *a = sign(n) * (|n| << k);
          shift is in reverse direction for negative k */

    void _kctsb_grshift(_kctsb_gbigint n, long k, _kctsb_gbigint *a);
       /* *a = sign(n) * (|n| >> k);
          shift is in reverse direction for negative k */
    
    long _kctsb_gmakeodd(_kctsb_gbigint *n);
       /*
          if (n != 0)
              *n = m;
              return (k such that n == 2 ^ k * m with m odd);
          else
              return (0); 
        */

    long _kctsb_gnumtwos(_kctsb_gbigint n);
        /* return largest e such that 2^e divides n, or zero if n is zero */

    long _kctsb_godd(_kctsb_gbigint a);
       /* returns 1 if n is odd and 0 if it is even */

    long _kctsb_gbit(_kctsb_gbigint a, long p);
       /* returns p-th bit of a, where the low order bit is indexed by 0;
          p out of range returns 0 */

    long _kctsb_gsetbit(_kctsb_gbigint *a, long p);
       /* returns original value of p-th bit of |a|, and replaces
          p-th bit of a by 1 if it was zero;
          error if p < 0 */

    long _kctsb_gswitchbit(_kctsb_gbigint *a, long p);
       /* returns original value of p-th bit of |a|, and switches
          the value of p-th bit of a;
          p starts counting at 0;
          error if p < 0 */


     void _kctsb_glowbits(_kctsb_gbigint a, long k, _kctsb_gbigint *b);
        /* places k low order bits of |a| in b */ 

     long _kctsb_gslowbits(_kctsb_gbigint a, long k);
        /* returns k low order bits of |a| */

    long _kctsb_gweights(long a);
        /* returns Hamming weight of |a| */

    long _kctsb_gweight(_kctsb_gbigint a);
        /* returns Hamming weight of |a| */

    void _kctsb_gand(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
        /* c gets bit pattern `bits of |a|` and `bits of |b|` */

    void _kctsb_gor(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
        /* c gets bit pattern `bits of |a|` inclusive or `bits of |b|` */

    void _kctsb_gxor(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
        /* c gets bit pattern `bits of |a|` exclusive or `bits of |b|` */




/************************************************************************

   Comparison

*************************************************************************/

    long _kctsb_gcompare(_kctsb_gbigint a, _kctsb_gbigint b);
       /*
          if (a > b)
              return (1);
          if (a == b)
              return (0);
          if (a < b)
              return (-1);
         */

    long _kctsb_gscompare(_kctsb_gbigint a, long b);
       /* single-precision version of the above */

    inline
    long _kctsb_giszero (_kctsb_gbigint a)
    {
      return _kctsb_ZEROP(a);
    }
       /* test for 0 */


    inline
    long _kctsb_gsign(_kctsb_gbigint a)
    {
       long sa;

       if (!a) return 0;

       sa = _kctsb_SIZE(a);
       if (sa > 0) return 1;
       if (sa == 0) return 0;
       return -1;
    }
       /* 
          if (a > 0)
              return (1);
          if (a == 0)
              return (0);
          if (a < 0)
              return (-1);
        */

    void _kctsb_gabs(_kctsb_gbigint *a);
       /* *a = |a| */

    void _kctsb_gnegate(_kctsb_gbigint *a);
       /* *a = -a */

    void _kctsb_gcopy(_kctsb_gbigint a, _kctsb_gbigint *b);
       /* *b = a;  */

    void _kctsb_gswap(_kctsb_gbigint *a, _kctsb_gbigint *b);
       /* swap a and b (by swaping pointers) */

    long _kctsb_g2log(_kctsb_gbigint a);
       /* number of bits in |a|; returns 0 if a = 0 */

    inline
    long _kctsb_g2logs(long a)
        /* single-precision version of the above */
    {
       unsigned long aa = a >= 0 ? a : - ((unsigned long) a);
       return _kctsb_count_bits(aa);
    }


/********************************************************************

   Conversion

*********************************************************************/
        
    void _kctsb_gzero(_kctsb_gbigint *a);
       /* *a = 0;  */

    void _kctsb_gone(_kctsb_gbigint *a);
       /* *a = 1 */

    void _kctsb_gintoz(long d, _kctsb_gbigint *a);
       /* *a = d;  */


    void _kctsb_guintoz(unsigned long d, _kctsb_gbigint *a);
       /* *a = d;  space is allocated  */

    long _kctsb_gtoint(_kctsb_gbigint a);
       /* converts a to a long;  overflow results in value
          mod 2^{KCTSB_BITS_PER_LONG}. */

    unsigned long _kctsb_gtouint(_kctsb_gbigint a);
       /* converts a to a long;  overflow results in value
          mod 2^{KCTSB_BITS_PER_LONG}. */

   


    double _kctsb_gdoub(_kctsb_gbigint n);
       /* converts a to a double;  no overflow check */

    long _kctsb_ground_correction(_kctsb_gbigint a, long k, long residual);
       /* k >= 1, |a| >= 2^k, and residual is 0, 1, or -1.
          The result is what we should add to (a >> k) to round
          x = a/2^k to the nearest integer using IEEE-like rounding rules
          (i.e., round to nearest, and round to even to break ties).
          The result is either 0 or sign(a).
          If residual is not zero, it is as if x were replaced by
          x' = x + residual*2^{-(k+1)}.
          This can be used to break ties when x is exactly
          half way between two integers. */

    double _kctsb_glog(_kctsb_gbigint a);
       /* computes log(a), protecting against overflow */

    void _kctsb_gdoubtoz(double a, _kctsb_gbigint *x);
       /* x = floor(a);  */
    



/************************************************************************

   Square roots

*************************************************************************/


    long _kctsb_gsqrts(long n);
       /* return floor(sqrt(n));  error raised in n < 0 */

    void _kctsb_gsqrt(_kctsb_gbigint n, _kctsb_gbigint *r);
       /* *r =  floor(sqrt(n));  error raised in n < 0 */

/*********************************************************************
 
    Exponentiation
 
**********************************************************************/

   void _kctsb_gexp(_kctsb_gbigint a, long e, _kctsb_gbigint *b);
       /* *b = a^e;  error raised if e < 0 */

   void _kctsb_gexps(long a, long e, _kctsb_gbigint *b);
       /* *b = a^e;  error raised if e < 0 */
       

/*********************************************************************

   Modular Arithmetic

   Addition, subtraction, multiplication, squaring division, inversion,
   and exponentiation modulo a positive modulus n, where all operands
   (except for the exponent in exponentiation) and results are in the
   range [0, n-1].   

   ALIAS RESTRICTION:  output parameters should not alias n

***********************************************************************/

    void _kctsb_gaddmod(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint n, _kctsb_gbigint *c);
       /* *c = (a + b) % n */

    void _kctsb_gsubmod(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint n, _kctsb_gbigint *c);
       /* *c = (a - b) % n */

    void _kctsb_gsmulmod(_kctsb_gbigint a, long b, _kctsb_gbigint n, _kctsb_gbigint *c);
       /* *c = (a * b) % n */

    void _kctsb_gmulmod(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint n, _kctsb_gbigint *c);
       /* *c = (a * b) % n */

    void _kctsb_gsqmod(_kctsb_gbigint a, _kctsb_gbigint n, _kctsb_gbigint *c);
       /* *c = (a ^ 2) % n */

    void _kctsb_ginvmod(_kctsb_gbigint a, _kctsb_gbigint n, _kctsb_gbigint *c);
       /* *c = (1 / a) % n; error raised if gcd(b, n) != 1 */

    void _kctsb_gpowermod(_kctsb_gbigint g, _kctsb_gbigint e, _kctsb_gbigint F,
                        _kctsb_gbigint *h);

       /* *b = (a ^ e) % n; */




/**************************************************************************

   Euclidean Algorithms

***************************************************************************/
    void _kctsb_ggcd(_kctsb_gbigint m1, _kctsb_gbigint m2, _kctsb_gbigint *r);
       /* *r = greatest common divisor of m1 and m2;  */

    void _kctsb_ggcd_alt(_kctsb_gbigint m1, _kctsb_gbigint m2, _kctsb_gbigint *r);
       /* *r = greatest common divisor of m1 and m2;  
          a simpler algorithm used for validation
        */


    void _kctsb_gexteucl(_kctsb_gbigint a, _kctsb_gbigint *xa,
                 _kctsb_gbigint b, _kctsb_gbigint *xb,
                 _kctsb_gbigint *d);
       /*
          *d = a * *xa + b * *xb = gcd(a, b);
          sets *d, *xa and *xb given a and b;
        */


    long _kctsb_ginv(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *c);
       /*
          if (a and b coprime)
          {
              *c = inv; 
              return(0);
          }
          else
          {
              *c = gcd(a, b);
              return(1);
          }
          
          where inv is such that (inv * a)  == 1 mod b;
          error raised if a < 0 or b <= 0
        */

     long _kctsb_gxxratrecon(_kctsb_gbigint x, _kctsb_gbigint m,  
                      _kctsb_gbigint a_bound, _kctsb_gbigint b_bound,
                      _kctsb_gbigint *a, _kctsb_gbigint *b);

        /* rational reconstruction: see doc in ZZ.txt */


        
/**********************************************************************

    Storage Allocation

    These routines use malloc and free.

***********************************************************************/

    inline
    long _kctsb_gmaxalloc(_kctsb_gbigint x)
    {
      if (!x)
         return 0;
      else
         return _kctsb_ALLOC(x) >> 2;
    }

    // DIRT: see lip.c for more info on ALLOC 

    void _kctsb_gsetlength(_kctsb_gbigint *v, long len);
       /* Allocates enough space to hold a len-digit number,
          where each digit has KCTSB_NBITS bits.
          If space must be allocated, space for one extra digit
          is always allocated. if (exact) then no rounding
          occurs. */

    void _kctsb_gfree(_kctsb_gbigint x);
       /* Free's space held by x. */


/*******************************************************************

    Special routines

********************************************************************/

inline
long _kctsb_gsize(_kctsb_gbigint rep)
{
  if (!rep)
      return 0;
   else if (_kctsb_SIZE(rep) < 0)
      return -_kctsb_SIZE(rep);
   else
      return _kctsb_SIZE(rep);
}

long _kctsb_gisone(_kctsb_gbigint n);

long _kctsb_gsptest(_kctsb_gbigint a);
long _kctsb_gwsptest(_kctsb_gbigint a);
long _kctsb_gcrtinrange(_kctsb_gbigint g, _kctsb_gbigint a);

void _kctsb_gfrombytes(_kctsb_gbigint *x, const unsigned char *p, long n);
void _kctsb_gbytesfromz(unsigned char *p, _kctsb_gbigint a, long nn);


long _kctsb_gblock_construct_alloc(_kctsb_gbigint *x, long d, long n);
void _kctsb_gblock_construct_set(_kctsb_gbigint x, _kctsb_gbigint *y, long i);
long _kctsb_gblock_destroy(_kctsb_gbigint x);
long _kctsb_gblock_storage(long d);



// These are common to both implementations

class _kctsb_tmp_vec {
public:
   virtual ~_kctsb_tmp_vec() { }
};

class _kctsb_crt_struct {
public:
   virtual ~_kctsb_crt_struct() { }
   virtual bool special() = 0;
   virtual void insert(long i, _kctsb_gbigint m) = 0;
   virtual _kctsb_tmp_vec *extract() = 0;
   virtual _kctsb_tmp_vec *fetch() = 0;
   virtual void eval(_kctsb_gbigint *x, const long *b, 
                     _kctsb_tmp_vec *tmp_vec) = 0;
};

_kctsb_crt_struct * 
_kctsb_crt_struct_build(long n, _kctsb_gbigint p, long (*primes)(long));

class _kctsb_rem_struct {
public:
   virtual ~_kctsb_rem_struct() { }
   virtual void eval(long *x, _kctsb_gbigint a, _kctsb_tmp_vec *tmp_vec) = 0;
   virtual _kctsb_tmp_vec *fetch() = 0;
};

_kctsb_rem_struct *
_kctsb_rem_struct_build(long n, _kctsb_gbigint modulus, long (*p)(long));


// montgomery
class _kctsb_reduce_struct {
public:
   virtual ~_kctsb_reduce_struct() { }
   virtual void eval(_kctsb_gbigint *x, _kctsb_gbigint *a) = 0;
   virtual void adjust(_kctsb_gbigint *x) = 0;
};

_kctsb_reduce_struct *
_kctsb_reduce_struct_build(_kctsb_gbigint modulus, _kctsb_gbigint excess);


// faster reduction with preconditioning -- general usage, single modulus

struct _kctsb_general_rem_one_struct;

_kctsb_general_rem_one_struct *
_kctsb_general_rem_one_struct_build(long p);

long 
_kctsb_general_rem_one_struct_apply(_kctsb_gbigint a, long p, _kctsb_general_rem_one_struct *pinfo);

void
_kctsb_general_rem_one_struct_delete(_kctsb_general_rem_one_struct *pinfo);

long _kctsb_gvalidate(_kctsb_gbigint a);


// special-purpose routines for accumulating CRT-like summations
void
_kctsb_quick_accum_begin(_kctsb_gbigint *xp, long sz);

void
_kctsb_quick_accum_muladd(_kctsb_gbigint x, _kctsb_gbigint y, long b);

void
_kctsb_quick_accum_end(_kctsb_gbigint x);

// special-purpose routines for SSMul in ZZX

#if (defined(KCTSB_GMP_LIP) && (KCTSB_ZZ_NBITS & (KCTSB_ZZ_NBITS-1)) == 0)
// NOTE: the test (KCTSB_ZZ_NBITS & (KCTSB_ZZ_NBITS-1)) == 0
// effectively checks that KCTSB_ZZ_NBITS is a power of two

#define KCTSB_PROVIDES_SS_LIP_IMPL

void
_kctsb_leftrotate(_kctsb_gbigint *a, const _kctsb_gbigint *b, long e,
                _kctsb_gbigint p, long n, _kctsb_gbigint *scratch);

void 
_kctsb_ss_addmod(_kctsb_gbigint *x, const _kctsb_gbigint *a,
               const _kctsb_gbigint *b, _kctsb_gbigint p, long n);
void 
_kctsb_ss_submod(_kctsb_gbigint *x, const _kctsb_gbigint *a,
               const _kctsb_gbigint *b, _kctsb_gbigint p, long n);
#endif


#endif
