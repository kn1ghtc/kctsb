
/*
 * This is a "wrapper" layer that builds on top of the "mpn" layer of gmp.
 * This layer provides much of the same functionality of the "mpz"
 * layer of gmp, but the interface it provides is much more like
 * the interface provided by lip.
 *
 * This layer was written under the following assumptions about gmp:
 *  1) mp_limb_t is an unsigned integral type
 *  2) sizeof(mp_limb_t) == sizeof(long) or sizeof(mp_limb_t) == 2*sizeof(long)
 *  3) the number of bits of an mp_limb_t is equal to that of a long,
 *     or twice that of a long
 *  4) the number of bits of a gmp radix is equal to the number of bits
 *     of an mp_limb_t
 *
 * Except for assumption (1), these assumptions are verified in the
 * installation script, and they should be universally satisfied in practice,
 * except when gmp is built using the proposed, new "nail" fetaure
 * (in which some bits of an mp_limb_t are unused).
 * The code here will not work properly with the "nail" feature;
 * however, I have (attempted to) identify all such problem spots,
 * and any other places where assumptions (2-4) are made,
 * with a comment labeled "DIRT".
 */



#include <kctsb/math/bignum/lip.h>

#include <kctsb/math/bignum/tools.h>
#include <kctsb/math/bignum/vector.h>
#include <kctsb/math/bignum/SmartPtr.h>

#include <kctsb/math/bignum/sp_arith.h>


#ifdef KCTSB_GMP_LIP
#include <gmp.h>

#if (__GNU_MP_VERSION < 5)
#error "GMP version 5.0.0 or later required"
#endif 

#endif

KCTSB_IMPORT_FROM_STD
KCTSB_USE_NNS


#if (defined(KCTSB_HAVE_LL_TYPE) && KCTSB_BITS_PER_LIMB_T == KCTSB_BITS_PER_LONG)
#define KCTSB_VIABLE_LL
#endif


#ifdef KCTSB_GMP_LIP

typedef mp_limb_t _kctsb_limb_t;

#define KCTSB_MPN(fun) mpn_ ## fun

#else

typedef unsigned long _kctsb_limb_t;
typedef long _kctsb_signed_limb_t;

#define KCTSB_MPN(fun) _kctsb_mpn_ ## fun

#endif



typedef _kctsb_limb_t *_kctsb_limb_t_ptr;

#define KCTSB_NAIL_BITS (KCTSB_BITS_PER_LIMB_T-KCTSB_ZZ_NBITS)

#define KCTSB_LIMB_MASK (_kctsb_limb_t(-1) >> KCTSB_NAIL_BITS)

#define KCTSB_ZZ_RADIX (KCTSB_LIMB_MASK+_kctsb_limb_t(1))
// this will be zero if no nails

#define KCTSB_ZZ_FRADIX_INV  (1.0/KCTSB_ZZ_FRADIX)




#if (KCTSB_ZZ_NBITS > KCTSB_BITS_PER_LONG-2)

static inline double 
DBL(_kctsb_limb_t x)
{
   return double(x);
}

#else

// this might be a bit faster
static inline double 
DBL(_kctsb_limb_t x)
{
   return double(long(x));
}

#endif


// DIRT: we assume that KCTSB_BITS_PER_LIMB_T >= BITS_PER_LONG
static inline _kctsb_limb_t
ABS(long x)
{
   if (x < 0)
      return -_kctsb_limb_t(x); // careful !
   else
      return _kctsb_limb_t(x);
}

static inline long
XOR(long a, long b)
{
   return a ^ b;
}


static 
inline _kctsb_limb_t CLIP(_kctsb_limb_t a)
{
   return a & KCTSB_LIMB_MASK;
}

static 
inline _kctsb_limb_t XCLIP(_kctsb_limb_t a)
{
   return a & ~KCTSB_LIMB_MASK;
}


#if (KCTSB_BITS_PER_LIMB_T == KCTSB_BITS_PER_LONG)
static
inline long COUNT_BITS(_kctsb_limb_t x)
{
   return _kctsb_count_bits(x);
}
#else
static
inline long COUNT_BITS(_kctsb_limb_t x)
{
   if (!x) { return 0; } 

   long res = KCTSB_BITS_PER_LIMB_T;
   while (x < (_kctsb_limb_t(1) << (KCTSB_BITS_PER_LIMB_T-1))) {
      x <<= 1;
      res--;
   }

   return res;
}
#endif





/* A bigint is represented as two long's, ALLOC and SIZE, followed by a 
 * vector DATA of _kctsb_limb_t's.  
 * 
 * ALLOC is of the form
 *    (alloc << 2) | continue_flag | frozen_flag
 * where 
 *    - alloc is the number of allocated _kctsb_limb_t's,
 *    - continue flag is either 2 or 0,
 *    - frozen_flag is either 1 or 0.
 * If frozen_flag is set, then the space for this bigint is *not*
 * managed by the _kctsb_gsetlength and _kctsb_gfree routines,
 * but are instead managed by the vec_ZZ_p and ZZVec routines.
 * The continue_flag is only set when the frozen_flag is set.
 * 
 * SIZE is the number of _kctsb_limb_t's actually
 * used by the bigint, with the sign of SIZE having
 * the sign of the bigint.
 * Note that the zero bigint is represented as SIZE=0.
 * 
 * Bigint's are accessed through a handle, which is pointer to void.
 * A null handle logically represents the bigint zero.
 * This is done so that the interface presented to higher level
 * routines is essentially the same as that of bignum's traditional
 * long integer package.
 * 
 * The components ALLOC, SIZE, and DATA are all accessed through
 * macros using pointer casts.  While all of may seem a bit dirty, 
 * it should be quite portable: objects are never referenced
 * through pointers of different types, and no alignmement
 * problems should arise.
 * 
 * DIRT: This rule is broken in the file g_lip.h: the inline definition
 * of _kctsb_gmaxalloc in that file has the definition of ALLOC pasted in.
 * 
 * Actually, _kctsb_limb_t is usually the type unsigned long.
 * However, on some 64-bit platforms, the type long is only 32 bits,
 * and gmp makes _kctsb_limb_t unsigned long long in this case.
 * This is fairly rare, as the industry standard for Unix is to
 * have 64-bit longs on 64-bit machines.
 */ 

/* DIRT: STORAGE computes the number of bytes to allocate for a bigint
 * of maximal SIZE len.  This should be computed so that one
 * can store several such bigints in a contiguous array
 * of memory without breaking any alignment requirements.
 * Currently, it is assumed (and explicitly checked in the bignum installation
 * script) that sizeof(_kctsb_limb_t) is either sizeof(long) or
 * 2*sizeof(long), and therfore, nothing special needs to
 * be done to enfoce alignment requirements.  If this assumption
 * should change, then the storage layout for bigints must be
 * re-designed.   
 */


static
inline long& ALLOC(_kctsb_gbigint p) 
   { return p->alloc_; }

static
inline long& SIZE(_kctsb_gbigint p) 
   { return p->size_; }

static
inline _kctsb_limb_t * DATA(_kctsb_gbigint p) 
   { return (_kctsb_limb_t *) (p+1); }

static
inline long STORAGE(long len)
   { return ((long)(sizeof(_kctsb_gbigint_body) + (len)*sizeof(_kctsb_limb_t))); }

static
inline long MustAlloc(_kctsb_gbigint c, long len)  
   { return (!(c) || (ALLOC(c) >> 2) < (len)); }


static
inline void GET_SIZE_NEG(long& sz, long& neg, _kctsb_gbigint p)
{ 
   long s; 
   s = SIZE(p); 
   if (s < 0) {
      sz = -s;
      neg = 1;
   }
   else {
      sz = s;
      neg = 0;
   }
}

static
inline void STRIP(long& sz, const _kctsb_limb_t *p)
{
   long n = sz;
   while (n > 0 && p[n-1] == 0) n--;
   sz = n;
}

static
inline long ZEROP(_kctsb_gbigint p)
{
   return !p || !SIZE(p);
}

static
inline long ONEP(_kctsb_gbigint p)
{
   return p && SIZE(p) == 1 && DATA(p)[0] == 1;
}

static
inline void SWAP_BIGINT(_kctsb_gbigint& a, _kctsb_gbigint& b)
{
   _kctsb_gbigint t;
   t = a;
   a = b;
   b = t;
}

static
inline void SWAP_LONG(long& a, long& b)
{
   long t;
   t = a;
   a = b;
   b = t;
}

static
inline void SWAP_LIMB_PTR(_kctsb_limb_t_ptr& a, _kctsb_limb_t_ptr& b)
{
   _kctsb_limb_t_ptr t;
   t = a;
   a = b;
   b = t;
}


static void DUMP(_kctsb_gbigint a)
{
   if (ZEROP(a)) 
      cerr << "[]";
   else {
      long sa = SIZE(a);
      if (sa < 0) { cerr << "-"; sa = -sa; }
      cerr << "[ ";
      for (long i = 0; i < sa; i++)
         cerr << DATA(a)[i] << " ";
      cerr << "]";
   }
   cerr << "\n";
}




#if (defined(KCTSB_CRT_ALTCODE) || defined(KCTSB_CRT_ALTCODE_SMALL))

#if (defined(KCTSB_VIABLE_LL) && KCTSB_NAIL_BITS == 0)

// alternative CRT code is requested and viable
// we do not attempt to implement this with non-empty nails,
// as it is not a huge win
#define KCTSB_TBL_CRT

#else


// raise an error if running the wizard
#ifdef KCTSB_WIZARD_HACK
#error "KCTSB_CRT_ALTCODE/KCTSB_CRT_ALTCODE_SMALL not viable"
#endif


#endif

#endif


#if (defined(KCTSB_TBL_REM) && !defined(KCTSB_VIABLE_LL))
#undef KCTSB_TBL_REM
// raise an error if running the wizard
#ifdef KCTSB_WIZARD_HACK
#error "KCTSB_TBL_REM not viable"
#endif
#endif




class _kctsb_gbigint_watcher {
public:
   _kctsb_gbigint *watched;

   explicit
   _kctsb_gbigint_watcher(_kctsb_gbigint *_watched) : watched(_watched) {}

   ~_kctsb_gbigint_watcher() 
   {
      if (*watched && (ALLOC(*watched) >> 2) > KCTSB_RELEASE_THRESH) {
         _kctsb_gfree(*watched);
         *watched = 0;
      }
   }
};



class _kctsb_gbigint_deleter {
public:
   static void apply(_kctsb_gbigint p) { _kctsb_gfree(p); }
};

typedef WrappedPtr<_kctsb_gbigint_body, _kctsb_gbigint_deleter> _kctsb_gbigint_wrapped;

static inline void
_kctsb_swap(_kctsb_gbigint_wrapped& p, _kctsb_gbigint_wrapped& q)
{
   p.swap(q);
}



// GRegisters are used for local "scratch" variables.

// NOTE: the first implementation of GRegister below wraps a bigint in a class
// whose destructor ensures that its space is reclaimed at program/thread termination.
// It really only is necesary in a multi-threading environment, but it doesn't
// seem to incurr significant cost.

// The second implementation does not do this wrapping, and so should not be
// used in a multi-threading environment.

// Both versions use a local "watcher" variable, which does the following:
// when the local scope closes (e.g., the function returns), the space
// for the bigint is freed *unless* it is fairly small.  This balanced
// approach leads significantly faster performance, while not holding
// to too many resouces.

// The third version releases local memory every time.  It can be significantly
// slower.

// The fourth version --- which was the original strategy --- never releases
// memory.  It can be faster, but can become a memory hog.

// All of this code is overly complicated, due to the fact that I'm "retrofitting"
// this logic onto what was originally pure-C code.


#define GRegister(x) KCTSB_TLS_LOCAL(_kctsb_gbigint_wrapped, x); _kctsb_gbigint_watcher _WATCHER__ ## x(&x)

//#define GRegister(x) KCTSB_THREAD_LOCAL static _kctsb_gbigint x(0); _kctsb_gbigint_watcher _WATCHER__ ## x(&x)

// #define GRegister(x) _kctsb_gbigint_wrapped x(0);

// #define GRegister(x) static _kctsb_gbigint x = 0 





#define STORAGE_OVF(len) KCTSB_OVERFLOW(len, sizeof(_kctsb_limb_t), 2*sizeof(long))



#ifndef KCTSB_GMP_LIP
// legacy function

long _kctsb_gdigit(_kctsb_gbigint a, long i)
{
   if (ZEROP(a) || i < 0) return 0;
   long sa = SIZE(a);
   if (sa < 0) sa = -sa;
   if (i >= sa) return 0;
   return DATA(a)[i];
}


#endif


long _kctsb_gvalidate(_kctsb_gbigint a)
{
   if (ZEROP(a)) return 1;
   long sa = SIZE(a);
   if (sa < 0) sa = -sa;

   _kctsb_limb_t *adata = DATA(a);
   for (long i = 0; i < sa; i++)
      if (XCLIP(adata[i])) return 0;

   if (adata[sa-1] == 0) return 0;
   return 1;
}


/* ForceNormal ensures a normalized bigint */

static 
void ForceNormal(_kctsb_gbigint x)
{
   long sx, xneg;
   _kctsb_limb_t *xdata;

   if (!x) return;
   GET_SIZE_NEG(sx, xneg, x);
   xdata = DATA(x);
   STRIP(sx, xdata);
   if (xneg) sx = -sx;
   SIZE(x) = sx;
}


#define MIN_SETL	(4)
   /* _kctsb_gsetlength allocates a multiple of MIN_SETL digits */



void _kctsb_gsetlength(_kctsb_gbigint *v, long len)
{
   _kctsb_gbigint x = *v;

   if (len < 0)
      LogicError("negative size allocation in _kctsb_zgetlength");

   if (KCTSB_OVERFLOW(len, KCTSB_ZZ_NBITS, 0))
      ResourceError("size too big in _kctsb_gsetlength");

#ifdef KCTSB_SMALL_MP_SIZE_T
   /* this makes sure that numbers don't get too big for GMP */
   if (len >= (1L << (KCTSB_BITS_PER_INT-4)))
      ResourceError("size too big for GMP");
#endif


   if (x) {
      long oldlen = ALLOC(x);
      long fixed = oldlen & 1;
      oldlen = oldlen >> 2;

      if (fixed) {
         if (len > oldlen) 
            LogicError("internal error: can't grow this _kctsb_gbigint");
         else
            return;
      }

      if (len <= oldlen) return;

      len++;  /* always allocate at least one more than requested */

      oldlen = _kctsb_vec_grow(oldlen);
      if (len < oldlen)
         len = oldlen;

      /* round up to multiple of MIN_SETL */
      len = ((len+(MIN_SETL-1))/MIN_SETL)*MIN_SETL; 

      /* test len again */
      if (KCTSB_OVERFLOW(len, KCTSB_ZZ_NBITS, 0))
         ResourceError("size too big in _kctsb_gsetlength");

      if (STORAGE_OVF(len))
         ResourceError("reallocation failed in _kctsb_gsetlength");

      if (!(x = (_kctsb_gbigint)KCTSB_SNS_REALLOC((void *) x, 1, STORAGE(len), 0))) {
         MemoryError();
      }
      ALLOC(x) = len << 2;
   }
   else {
      len++;  /* as above, always allocate one more than explicitly reqested */
      len = ((len+(MIN_SETL-1))/MIN_SETL)*MIN_SETL; 

      /* test len again */
      if (KCTSB_OVERFLOW(len, KCTSB_ZZ_NBITS, 0))
         ResourceError("size too big in _kctsb_gsetlength");

      if (STORAGE_OVF(len))
         ResourceError("reallocation failed in _kctsb_gsetlength");

      if (!(x = (_kctsb_gbigint)KCTSB_SNS_MALLOC(1, STORAGE(len), 0))) {
         MemoryError();
      }
      ALLOC(x) = len << 2;
      SIZE(x) = 0;
   }

   *v = x;
}

void _kctsb_gfree(_kctsb_gbigint x)
{


   if (!x)
      return;

   if (ALLOC(x) & 1)
      TerminalError("Internal error: can't free this _kctsb_gbigint");

   free((void*) x);
   return;
}

void
_kctsb_gswap(_kctsb_gbigint *a, _kctsb_gbigint *b)
{
   if ((*a && (ALLOC(*a) & 1)) || (*b && (ALLOC(*b) & 1))) {
      // one of the inputs points to an bigint that is 
      // "pinned down" in memory, so we have to swap the data,
      // not just the pointers

      GRegister(t);
      long sz_a, sz_b, sz;

      sz_a = _kctsb_gsize(*a); 
      sz_b = _kctsb_gsize(*b); 
      sz = (sz_a > sz_b) ? sz_a : sz_b;

      _kctsb_gsetlength(a, sz);
      _kctsb_gsetlength(b, sz);

      // EXCEPTIONS: all of the above ensures that swap provides strong ES

      _kctsb_gcopy(*a, &t);
      _kctsb_gcopy(*b, a);
      _kctsb_gcopy(t, b);
      return;
   }

   SWAP_BIGINT(*a, *b);
}


void _kctsb_gcopy(_kctsb_gbigint a, _kctsb_gbigint *bb)
{
   _kctsb_gbigint b;
   long sa, abs_sa, i;
   _kctsb_limb_t *adata, *bdata;

   b = *bb;

   if (!a || (sa = SIZE(a)) == 0) {
      if (b) SIZE(b) = 0;
   }
   else {
      if (a != b) {
         if (sa >= 0)
            abs_sa = sa;
         else
            abs_sa = -sa;

         if (MustAlloc(b, abs_sa)) {
            _kctsb_gsetlength(&b, abs_sa);
            *bb = b;
         }

         adata = DATA(a);
         bdata = DATA(b);

         for (i = 0; i < abs_sa; i++)
            bdata[i] = adata[i];

         SIZE(b) = sa;
      }
   }
}

void _kctsb_glimbs_set(const _kctsb_limb_t *p, long n, _kctsb_gbigint *x)
{
   if (n < 0) LogicError("_kctsb_glimbs_set: negative size");
   if (n > 0 && !p) LogicError("_kctsb_glimbs_set: unexpected NULL pointer");

   STRIP(n, p);
   if (n == 0) {
      _kctsb_gzero(x);
      return;
   }

   if (MustAlloc(*x, n)) _kctsb_gsetlength(x, n);
   _kctsb_limb_t *xdata = DATA(*x);
   for (long i = 0; i < n; i++) xdata[i] = p[i];
   SIZE(*x) = n;

}




void _kctsb_gzero(_kctsb_gbigint *aa) 
{
   _kctsb_gbigint a = *aa;

   if (a) SIZE(a) = 0;
}

void _kctsb_gone(_kctsb_gbigint *aa)
{
   _kctsb_gbigint a = *aa;
   if (!a) {
      _kctsb_gsetlength(&a, 1);
      *aa = a;
   }

   SIZE(a) = 1;
   DATA(a)[0] = 1;
}

long _kctsb_godd(_kctsb_gbigint a)
{
   if (ZEROP(a)) 
      return 0;
   else
      return DATA(a)[0]&1;
}

long _kctsb_gbit(_kctsb_gbigint a, long p)
{
   long bl;
   long sa;
   _kctsb_limb_t wh;

   if (p < 0 || !a) return 0;

   bl = p/KCTSB_ZZ_NBITS;
   wh = ((_kctsb_limb_t) 1) << (p - KCTSB_ZZ_NBITS*bl);

   sa = SIZE(a);
   if (sa < 0) sa = -sa;

   if (sa <= bl) return 0;
   if (DATA(a)[bl] & wh) return 1;
   return 0;
}

void _kctsb_glowbits(_kctsb_gbigint a, long b, _kctsb_gbigint *cc)
{
   _kctsb_gbigint c;

   long bl;
   long wh;
   long sa;
   long i;
   _kctsb_limb_t *adata, *cdata;

   if (ZEROP(a) || (b<=0)) {
      _kctsb_gzero(cc);
      return;
   }

   bl = b/KCTSB_ZZ_NBITS;
   wh = b - KCTSB_ZZ_NBITS*bl;
   if (wh != 0) 
      bl++;
   else
      wh = KCTSB_ZZ_NBITS;

   sa = SIZE(a);
   if (sa < 0) sa = -sa;

   if (sa < bl) {
      _kctsb_gcopy(a,cc);
      _kctsb_gabs(cc);
      return;
   }

   c = *cc;

   /* a won't move if c aliases a */
   _kctsb_gsetlength(&c, bl);
   *cc = c;

   adata = DATA(a);
   cdata = DATA(c);

   for (i = 0; i < bl-1; i++)
      cdata[i] = adata[i];

   if (wh == KCTSB_ZZ_NBITS)
      cdata[bl-1] = adata[bl-1];
   else
      cdata[bl-1] = adata[bl-1] & ((((_kctsb_limb_t) 1) << wh) - ((_kctsb_limb_t) 1));

   STRIP(bl, cdata);
   SIZE(c) = bl; 
}

long _kctsb_gslowbits(_kctsb_gbigint a, long p)
{
   GRegister(x);

   if (p > KCTSB_BITS_PER_LONG)
      p = KCTSB_BITS_PER_LONG;

   _kctsb_glowbits(a, p, &x);

   return _kctsb_gtoint(x);
}

long _kctsb_gsetbit(_kctsb_gbigint *a, long b)
{
   long bl;
   long sa, aneg;
   long i;
   _kctsb_limb_t wh, *adata, tmp;

   if (b<0) LogicError("_kctsb_gsetbit: negative index");

   bl = (b/KCTSB_ZZ_NBITS);
   wh = ((_kctsb_limb_t) 1) << (b - KCTSB_ZZ_NBITS*bl);

   if (!*a) 
      sa = aneg = 0;
   else
      GET_SIZE_NEG(sa, aneg, *a);

   if (sa > bl) {
      adata = DATA(*a);
      tmp = adata[bl] & wh;
      adata[bl] |= wh;
      if (tmp) return 1;
      return 0;
   } 
   else {
      _kctsb_gsetlength(a, bl+1);
      adata = DATA(*a);
      for (i = sa; i < bl; i++)
         adata[i] = 0;
      adata[bl] = wh;

      sa = bl+1;
      if (aneg) sa = -sa;
      SIZE(*a) = sa;
      return 0;
   }
}

long _kctsb_gswitchbit(_kctsb_gbigint *a, long b)
{
   long bl;
   long sa, aneg;
   long i;
   _kctsb_limb_t wh, *adata, tmp;

   if (b<0) LogicError("_kctsb_gswitchbit: negative index");

   bl = (b/KCTSB_ZZ_NBITS);
   wh = ((_kctsb_limb_t) 1) << (b - KCTSB_ZZ_NBITS*bl);

   if (!*a) 
      sa = aneg = 0;
   else
      GET_SIZE_NEG(sa, aneg, *a);

   if (sa > bl) {
      adata = DATA(*a);
      tmp = adata[bl] & wh;
      adata[bl] ^= wh;

      if (bl == sa-1) {
         STRIP(sa, adata);
         if (aneg) sa = -sa;
         SIZE(*a) = sa;
      }

      if (tmp) return 1;
      return 0;
   } 
   else {
      _kctsb_gsetlength(a, bl+1);
      adata = DATA(*a);
      for (i = sa; i < bl; i++)
         adata[i] = 0;
      adata[bl] = wh;

      sa = bl+1;
      if (aneg) sa = -sa;
      SIZE(*a) = sa;
      return 0;
   }
}

long
_kctsb_gweights(
	long aa
	)
{
	unsigned long a;
	long res = 0;
	if (aa < 0) 
		a = -((unsigned long) aa);
	else
		a = aa;
   
	while (a) {
		if (a & 1) res ++;
		a >>= 1;
	}
	return (res);
}

static long
gweights_mp_limb(
	_kctsb_limb_t a
	)
{
	long res = 0;
   
	while (a) {
		if (a & 1) res ++;
		a >>= 1;
	}
	return (res);
}

long
_kctsb_gweight(
        _kctsb_gbigint a
        )
{
	long i;
	long sa;
	_kctsb_limb_t *adata;
	long res;

	if (!a) return (0);

	sa = SIZE(a);
	if (sa < 0) sa = -sa;
	adata = DATA(a);

	res = 0;
	for (i = 0; i < sa; i++)
		res += gweights_mp_limb(adata[i]);

	return (res);
}


long _kctsb_g2log(_kctsb_gbigint a)
{
   long la;
   long t;

   if (!a) return 0;
   la = SIZE(a);
   if (la == 0) return 0;
   if (la < 0) la = -la;
   t = COUNT_BITS(DATA(a)[la-1]);
   return KCTSB_ZZ_NBITS*(la - 1) + t;
}



long _kctsb_gmakeodd(_kctsb_gbigint *nn)
{
   _kctsb_gbigint n = *nn;
   long shift;
   _kctsb_limb_t *ndata;
   _kctsb_limb_t i;

   if (ZEROP(n))
      return (0);

   shift = 0;
   ndata = DATA(n);

   while (ndata[shift] == 0)
      shift++;

   i = ndata[shift];

   shift = KCTSB_ZZ_NBITS * shift;

   while ((i & 1) == 0) {
      shift++;
      i >>= 1;
   }
   _kctsb_grshift(n, shift, &n);
   return shift;
}


long _kctsb_gnumtwos(_kctsb_gbigint n)
{
   long shift;
   _kctsb_limb_t *ndata;
   _kctsb_limb_t i;

   if (ZEROP(n))
      return (0);

   shift = 0;
   ndata = DATA(n);

   while (ndata[shift] == 0)
      shift++;

   i = ndata[shift];

   shift = KCTSB_ZZ_NBITS * shift;

   while ((i & 1) == 0) {
      shift++;
      i >>= 1;
   }

   return shift;
}


void _kctsb_gand(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   _kctsb_gbigint c;
   long sa;
   long sb;
   long sm;
   long i;
   long a_alias, b_alias;
   _kctsb_limb_t *adata, *bdata, *cdata;

   if (ZEROP(a) || ZEROP(b)) {
      _kctsb_gzero(cc);
      return;
   }

   c = *cc;
   a_alias = (a == c);
   b_alias = (b == c);

   sa = SIZE(a);
   if (sa < 0) sa = -sa;

   sb = SIZE(b);
   if (sb < 0) sb = -sb;

   sm = (sa > sb ? sb : sa);

   _kctsb_gsetlength(&c, sm);
   if (a_alias) a = c;
   if (b_alias) b = c;
   *cc = c;

   adata = DATA(a);
   bdata = DATA(b);
   cdata = DATA(c);

   for (i = 0; i < sm; i++)
      cdata[i] = adata[i] & bdata[i];

   STRIP(sm, cdata);
   SIZE(c) = sm;
}


void _kctsb_gxor(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   _kctsb_gbigint c;
   long sa;
   long sb;
   long sm;
   long la;
   long i;
   long a_alias, b_alias;
   _kctsb_limb_t *adata, *bdata, *cdata;

   if (ZEROP(a)) {
      _kctsb_gcopy(b,cc);
      _kctsb_gabs(cc);
      return;
   }

   if (ZEROP(b)) {
      _kctsb_gcopy(a,cc);
      _kctsb_gabs(cc);
      return;
   }

   c = *cc;
   a_alias = (a == c);
   b_alias = (b == c);

   sa = SIZE(a);
   if (sa < 0) sa = -sa;

   sb = SIZE(b);
   if (sb < 0) sb = -sb;

   if (sa > sb) {
      la = sa;
      sm = sb;
   } 
   else {
      la = sb;
      sm = sa;
   }

   _kctsb_gsetlength(&c, la);
   if (a_alias) a = c;
   if (b_alias) b = c;
   *cc = c;

   adata = DATA(a);
   bdata = DATA(b);
   cdata = DATA(c);

   for (i = 0; i < sm; i ++)
      cdata[i] = adata[i] ^ bdata[i];

   if (sa > sb)
      for (;i < la; i++) cdata[i] = adata[i];
   else
      for (;i < la; i++) cdata[i] = bdata[i];

   STRIP(la, cdata);
   SIZE(c) = la;
}


void _kctsb_gor(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   _kctsb_gbigint c;
   long sa;
   long sb;
   long sm;
   long la;
   long i;
   long a_alias, b_alias;
   _kctsb_limb_t *adata, *bdata, *cdata;

   if (ZEROP(a)) {
      _kctsb_gcopy(b,cc);
      _kctsb_gabs(cc);
      return;
   }

   if (ZEROP(b)) {
      _kctsb_gcopy(a,cc);
      _kctsb_gabs(cc);
      return;
   }

   c = *cc;
   a_alias = (a == c);
   b_alias = (b == c);

   sa = SIZE(a);
   if (sa < 0) sa = -sa;

   sb = SIZE(b);
   if (sb < 0) sb = -sb;

   if (sa > sb) {
      la = sa;
      sm = sb;
   } 
   else {
      la = sb;
      sm = sa;
   }

   _kctsb_gsetlength(&c, la);
   if (a_alias) a = c;
   if (b_alias) b = c;
   *cc = c;

   adata = DATA(a);
   bdata = DATA(b);
   cdata = DATA(c);

   for (i = 0; i < sm; i ++)
      cdata[i] = adata[i] | bdata[i];

   if (sa > sb)
      for (;i < la; i++) cdata[i] = adata[i];
   else
      for (;i < la; i++) cdata[i] = bdata[i];

   STRIP(la, cdata);
   SIZE(c) = la;
}


void _kctsb_gnegate(_kctsb_gbigint *aa)
{
   _kctsb_gbigint a = *aa;
   if (a) SIZE(a) = -SIZE(a);
}



#if (KCTSB_ZZ_NBITS >= KCTSB_BITS_PER_LONG)

void _kctsb_gintoz(long d, _kctsb_gbigint *aa)
{
   _kctsb_gbigint a = *aa;

   if (d == 0) {
      if (a) SIZE(a) = 0;
   }
   else {
      if (!a) {
         _kctsb_gsetlength(&a, 1);
         *aa = a;
      }
   
      SIZE(a) = d < 0 ? -1 : 1;
      DATA(a)[0] = ABS(d);
   }
}

#else


void _kctsb_gintoz(long d, _kctsb_gbigint *aa)
{
   long sa, i;
   _kctsb_limb_t d1, d2;

   _kctsb_gbigint a = *aa;

   if (d == 0) {
      if (a) SIZE(a) = 0;
      return;
   }

   d1 = ABS(d);

   sa = 0;
   d2 = d1;
   do {
      d2 >>= KCTSB_ZZ_NBITS;
      sa++;
   }
   while (d2);

   if (MustAlloc(a, sa)) {
      _kctsb_gsetlength(&a, sa);
      *aa = a;
   }
 
   _kctsb_limb_t *adata = DATA(a);

   for (i = 0; i < sa; i++) {
      adata[i] = CLIP(d1);
      d1 >>= KCTSB_ZZ_NBITS;
   }

   if (d < 0) sa = -sa;
   SIZE(a) = sa;
}

#endif




#if (KCTSB_ZZ_NBITS >= KCTSB_BITS_PER_LONG)

void _kctsb_guintoz(unsigned long d, _kctsb_gbigint *aa)
{
   _kctsb_gbigint a = *aa;

   if (d == 0) {
      if (a) SIZE(a) = 0;
   }
   else {
      if (!a) {
         _kctsb_gsetlength(&a, 1);
         *aa = a;
      }
   
      SIZE(a) = 1;
      DATA(a)[0] = d;
   }
}

#else


void _kctsb_guintoz(unsigned long d, _kctsb_gbigint *aa)
{
   long sa, i;
   _kctsb_limb_t d1, d2;

   _kctsb_gbigint a = *aa;

   if (d == 0) {
      if (a) SIZE(a) = 0;
      return;
   }

   d1 = d;

   sa = 0;
   d2 = d1;
   do {
      d2 >>= KCTSB_ZZ_NBITS;
      sa++;
   }
   while (d2);

   if (MustAlloc(a, sa)) {
      _kctsb_gsetlength(&a, sa);
      *aa = a;
   }
 
   _kctsb_limb_t *adata = DATA(a);

   for (i = 0; i < sa; i++) {
      adata[i] = CLIP(d1);
      d1 >>= KCTSB_ZZ_NBITS;
   }

   SIZE(a) = sa;
}


#endif



long _kctsb_gtoint(_kctsb_gbigint a)
{
   unsigned long res = _kctsb_gtouint(a);
   return cast_signed(res);
}





#if (KCTSB_ZZ_NBITS >= KCTSB_BITS_PER_LONG)

unsigned long _kctsb_gtouint(_kctsb_gbigint a)
{
   if (ZEROP(a)) 
      return 0;

   if (SIZE(a) > 0) 
      return DATA(a)[0];

   return -DATA(a)[0];
}

#else

unsigned long _kctsb_gtouint(_kctsb_gbigint a)
{
   if (ZEROP(a))
      return 0;

   long sa, aneg;
   _kctsb_limb_t *adata;
   GET_SIZE_NEG(sa, aneg, a);
   adata = DATA(a);

   unsigned long d = adata[0];
   long bits = KCTSB_ZZ_NBITS;
   long i = 1;
   while (bits < KCTSB_BITS_PER_LONG && i < sa) {
      d |= adata[i] << bits; 
      bits += KCTSB_ZZ_NBITS; 
      i++;
   }

   if (aneg) d = -d;
   return d;
}

#endif







long _kctsb_gcompare(_kctsb_gbigint a, _kctsb_gbigint b)
{
   long sa, sb, cmp;
   _kctsb_limb_t *adata, *bdata;

   if (!a) 
      sa = 0;
   else
      sa = SIZE(a);

   if (!b) 
      sb = 0;
   else
      sb = SIZE(b);

   if (sa != sb) {
      if (sa > sb)
         return 1;
      else
         return -1;
   }

   if (sa == 0)
      return 0;

   adata = DATA(a);
   bdata = DATA(b);

   if (sa > 0) {
      cmp = KCTSB_MPN(cmp)(adata, bdata, sa);

      if (cmp > 0)
         return 1;
      else if (cmp < 0) 
         return -1;
      else
         return 0;
   }
   else {
      cmp = KCTSB_MPN(cmp)(adata, bdata, -sa);

      if (cmp > 0)
         return -1;
      else if (cmp < 0) 
         return 1;
      else
         return 0;
   }
}


void _kctsb_gabs(_kctsb_gbigint *pa)
{
   _kctsb_gbigint a = *pa;

   if (!a) return;
   if (SIZE(a) < 0) SIZE(a) = -SIZE(a);
}

long _kctsb_gscompare(_kctsb_gbigint a, long b)
{
   if (b == 0) {
      long sa;
      if (!a) return 0;
      sa = SIZE(a);
      if (sa > 0) return 1;
      if (sa == 0) return 0;
      return -1;
   }
   else {
      GRegister(B);
      _kctsb_gintoz(b, &B);
      return _kctsb_gcompare(a, B);
   }
}


void _kctsb_glshift(_kctsb_gbigint n, long k, _kctsb_gbigint *rres)
{
   _kctsb_gbigint res;
   _kctsb_limb_t *ndata, *resdata, *resdata1;
   long limb_cnt, i, sn, nneg, sres;
   long n_alias;

   if (ZEROP(n)) {
      _kctsb_gzero(rres);
      return;
   }

   res = *rres;
   n_alias = (n == res);

   if (!k) {
      if (!n_alias)
         _kctsb_gcopy(n, rres);
      return;
   }

   if (k < 0) {
      if (k < -KCTSB_MAX_LONG) 
         _kctsb_gzero(rres);
      else
         _kctsb_grshift(n, -k, rres);
      return;
   }

   GET_SIZE_NEG(sn, nneg, n);

   limb_cnt = ((unsigned long) k) / KCTSB_ZZ_NBITS;
   k = ((unsigned long) k) % KCTSB_ZZ_NBITS;
   sres = sn + limb_cnt;
   if (k != 0) sres++;

   if (MustAlloc(res, sres)) {
      _kctsb_gsetlength(&res, sres);
      if (n_alias) n = res;
      *rres = res;
   }

   ndata = DATA(n);
   resdata = DATA(res);
   resdata1 = resdata + limb_cnt;

   if (k != 0) {
      _kctsb_limb_t t = KCTSB_MPN(lshift)(resdata1, ndata, sn, k);
      if (t != 0) 
         resdata[sres-1] = t;
      else
         sres--;
   }
   else {
      for (i = sn-1; i >= 0; i--)
         resdata1[i] = ndata[i];
   }

   for (i = 0; i < limb_cnt; i++)
      resdata[i] = 0;

   if (nneg) sres = -sres;
   SIZE(res) = sres;
}

void _kctsb_grshift(_kctsb_gbigint n, long k, _kctsb_gbigint *rres)
{
   _kctsb_gbigint res;
   _kctsb_limb_t *ndata, *resdata, *ndata1;
   long limb_cnt, i, sn, nneg, sres;

   if (ZEROP(n)) {
      _kctsb_gzero(rres);
      return;
   }

   if (!k) {
      if (n != *rres)
         _kctsb_gcopy(n, rres);
      return;
   }

   if (k < 0) {
      if (k < -KCTSB_MAX_LONG) ResourceError("overflow in _kctsb_glshift");
      _kctsb_glshift(n, -k, rres);
      return;
   }

   GET_SIZE_NEG(sn, nneg, n);

   limb_cnt = ((unsigned long) k) / KCTSB_ZZ_NBITS;

   sres = sn - limb_cnt;

   if (sres <= 0) {
      _kctsb_gzero(rres);
      return;
   }

   res = *rres;
   if (MustAlloc(res, sres)) {
      /* n won't move if res aliases n */
      _kctsb_gsetlength(&res, sres);
      *rres = res;
   }

   ndata = DATA(n);
   resdata = DATA(res);
   ndata1 = ndata + limb_cnt;
   k = ((unsigned long) k) % KCTSB_ZZ_NBITS;

   if (k != 0) {
      KCTSB_MPN(rshift)(resdata, ndata1, sres, k);
      if (resdata[sres-1] == 0)
         sres--;
   }
   else {
      for (i = 0; i < sres; i++)
         resdata[i] = ndata1[i];
   }

   if (nneg) sres = -sres;
   SIZE(res) = sres;
}
   




void
_kctsb_gadd(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   long sa, aneg, sb, bneg, sc, cmp;
   _kctsb_limb_t *adata, *bdata, *cdata, carry;
   _kctsb_gbigint c;
   long a_alias, b_alias;

   if (ZEROP(a)) {
      _kctsb_gcopy(b, cc);
      return;
   }

   if (ZEROP(b)) {
      _kctsb_gcopy(a, cc);
      return;
   }

   GET_SIZE_NEG(sa, aneg, a);
   GET_SIZE_NEG(sb, bneg, b);

   if (sa < sb) {
      SWAP_BIGINT(a, b);
      SWAP_LONG(sa, sb);
      SWAP_LONG(aneg, bneg);
   }

   /* sa >= sb */

   c = *cc;
   a_alias = (a == c);
   b_alias = (b == c);

   if (aneg == bneg) {
      /* same sign => addition */

      sc = sa + 1;
      if (MustAlloc(c, sc)) {
         _kctsb_gsetlength(&c, sc);
         if (a_alias) a = c; 
         if (b_alias) b = c;
         *cc = c;
      }

      adata = DATA(a);
      bdata = DATA(b);
      cdata = DATA(c);

      carry = KCTSB_MPN(add)(cdata, adata, sa, bdata, sb);
      if (carry) 
         cdata[sc-1] = carry;
      else
         sc--;

      if (aneg) sc = -sc;
      SIZE(c) = sc;
   }
   else {
      /* opposite sign => subtraction */

      sc = sa;
      if (MustAlloc(c, sc)) {
         _kctsb_gsetlength(&c, sc);
         if (a_alias) a = c; 
         if (b_alias) b = c;
         *cc = c;
      }

      adata = DATA(a);
      bdata = DATA(b);
      cdata = DATA(c);

      if (sa > sb) 
         cmp = 1;
      else
         cmp = KCTSB_MPN(cmp)(adata, bdata, sa);

      if (cmp == 0) {
         SIZE(c) = 0;
      }
      else {
         if (cmp < 0) cmp = 0;
         if (cmp > 0) cmp = 1;
         /* abs(a) != abs(b) && (abs(a) > abs(b) <=> cmp) */

         if (cmp)
            KCTSB_MPN(sub)(cdata, adata, sa, bdata, sb);
         else
            KCTSB_MPN(sub)(cdata, bdata, sb, adata, sa); /* sa == sb */

         STRIP(sc, cdata);
         if (aneg == cmp) sc = -sc;
         SIZE(c) = sc;
      }
   }
}


void
_kctsb_gsadd(_kctsb_gbigint a, long b, _kctsb_gbigint *cc)
{
   if (b == 0) {
      _kctsb_gcopy(a, cc);
      return;
   }

   _kctsb_limb_t abs_b = ABS(b);

   if (XCLIP(abs_b)) {
      GRegister(xb);
      _kctsb_gintoz(b,&xb);
      _kctsb_gadd(a, xb, cc);
      return;
   }

   long bneg = b < 0;


   if (ZEROP(a)) {
      if (!*cc) _kctsb_gsetlength(cc, 1);
      SIZE(*cc) = 1 - 2*bneg;
      DATA(*cc)[0] = abs_b;
      return;
   }

   long sa, aneg;

   GET_SIZE_NEG(sa, aneg, a);

   if (aneg == bneg) {
      // signs equal: addition

      if (a == *cc) {
         // a aliases c

         _kctsb_limb_t *adata = DATA(a);
         _kctsb_limb_t carry = KCTSB_MPN(add_1)(adata, adata, sa, abs_b);

         if (carry) {
            if (MustAlloc(a, sa+1)) {
               _kctsb_gsetlength(cc, sa+1);
               a = *cc;
               adata = DATA(a);
            } 
            adata[sa] = 1;
            sa++;
            if (aneg) sa = -sa;
            SIZE(a) = sa;
         }
      }
      else {
         // a and c do not alias
         if (MustAlloc(*cc, sa+1)) _kctsb_gsetlength(cc, sa+1);
         _kctsb_limb_t *adata = DATA(a);
         _kctsb_limb_t *cdata = DATA(*cc);
         _kctsb_limb_t carry = KCTSB_MPN(add_1)(cdata, adata, sa, abs_b);
         if (carry) {
            cdata[sa] = 1;
            sa++;
         }
         if (aneg) sa = -sa;
         SIZE(*cc) = sa;
      }
   }
   else {
      // opposite sign: subtraction

      if (sa == 1) {
         _kctsb_limb_t abs_a = DATA(a)[0];
         if (abs_a == abs_b) 
            _kctsb_gzero(cc);
         else if (abs_a > abs_b) {
            if (MustAlloc(*cc, 1)) _kctsb_gsetlength(cc, 1);
            DATA(*cc)[0] = abs_a - abs_b;
            SIZE(*cc) = 1-2*aneg;
         }
         else {
            if (MustAlloc(*cc, 1)) _kctsb_gsetlength(cc, 1);
            DATA(*cc)[0] = abs_b - abs_a;
            SIZE(*cc) = -1+2*aneg;
         }
      }
      else {
         if (MustAlloc(*cc, sa)) _kctsb_gsetlength(cc, sa);
         _kctsb_limb_t *adata = DATA(a);
         _kctsb_limb_t *cdata = DATA(*cc);
         KCTSB_MPN(sub_1)(cdata, adata, sa, abs_b);
         if (cdata[sa-1] == 0) sa--;
         if (aneg) sa = -sa;
         SIZE(*cc) = sa;
      }
   }

}

void
_kctsb_gssub(_kctsb_gbigint a, long b, _kctsb_gbigint *cc)
{
   if (b == 0) {
      _kctsb_gcopy(a, cc);
      return;
   }

   _kctsb_limb_t abs_b = ABS(b);

   if (XCLIP(abs_b)) {
      GRegister(xb);
      _kctsb_gintoz(b,&xb);
      _kctsb_gsub(a, xb, cc);
      return;
   }

   // the rest of this routine is precisely the same
   // as gsadd, except for the following line,
   // which has the sense of the test reversed
   long bneg = b >= 0;


   if (ZEROP(a)) {
      if (!*cc) _kctsb_gsetlength(cc, 1);
      SIZE(*cc) = 1 - 2*bneg;
      DATA(*cc)[0] = abs_b;
      return;
   }

   long sa, aneg;

   GET_SIZE_NEG(sa, aneg, a);

   if (aneg == bneg) {
      // signs equal: addition

      if (a == *cc) {
         // a aliases c

         _kctsb_limb_t *adata = DATA(a);
         _kctsb_limb_t carry = KCTSB_MPN(add_1)(adata, adata, sa, abs_b);

         if (carry) {
            if (MustAlloc(a, sa+1)) {
               _kctsb_gsetlength(cc, sa+1);
               a = *cc;
               adata = DATA(a);
            } 
            adata[sa] = 1;
            sa++;
            if (aneg) sa = -sa;
            SIZE(a) = sa;
         }
      }
      else {
         // a and c do not alias
         if (MustAlloc(*cc, sa+1)) _kctsb_gsetlength(cc, sa+1);
         _kctsb_limb_t *adata = DATA(a);
         _kctsb_limb_t *cdata = DATA(*cc);
         _kctsb_limb_t carry = KCTSB_MPN(add_1)(cdata, adata, sa, abs_b);
         if (carry) {
            cdata[sa] = 1;
            sa++;
         }
         if (aneg) sa = -sa;
         SIZE(*cc) = sa;
      }
   }
   else {
      // opposite sign: subtraction

      if (sa == 1) {
         _kctsb_limb_t abs_a = DATA(a)[0];
         if (abs_a == abs_b) 
            _kctsb_gzero(cc);
         else if (abs_a > abs_b) {
            if (MustAlloc(*cc, 1)) _kctsb_gsetlength(cc, 1);
            DATA(*cc)[0] = abs_a - abs_b;
            SIZE(*cc) = 1-2*aneg;
         }
         else {
            if (MustAlloc(*cc, 1)) _kctsb_gsetlength(cc, 1);
            DATA(*cc)[0] = abs_b - abs_a;
            SIZE(*cc) = -1+2*aneg;
         }
      }
      else {
         if (MustAlloc(*cc, sa)) _kctsb_gsetlength(cc, sa);
         _kctsb_limb_t *adata = DATA(a);
         _kctsb_limb_t *cdata = DATA(*cc);
         KCTSB_MPN(sub_1)(cdata, adata, sa, abs_b);
         if (cdata[sa-1] == 0) sa--;
         if (aneg) sa = -sa;
         SIZE(*cc) = sa;
      }
   }

}



void
_kctsb_gsub(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   long sa, aneg, sb, bneg, sc, cmp, rev;
   _kctsb_limb_t *adata, *bdata, *cdata, carry;
   _kctsb_gbigint c;
   long a_alias, b_alias;

   if (ZEROP(a)) {
      _kctsb_gcopy(b, cc);
      c = *cc;
      if (c) SIZE(c) = -SIZE(c); 
      return;
   }

   if (ZEROP(b)) {
      _kctsb_gcopy(a, cc);
      return;
   }

   GET_SIZE_NEG(sa, aneg, a);
   GET_SIZE_NEG(sb, bneg, b);

   if (sa < sb) {
      SWAP_BIGINT(a, b);
      SWAP_LONG(sa, sb);
      SWAP_LONG(aneg, bneg);
      rev = 1;
   }
   else 
      rev = 0;

   /* sa >= sb */

   c = *cc;
   a_alias = (a == c);
   b_alias = (b == c);

   if (aneg != bneg) {
      /* opposite sign => addition */

      sc = sa + 1;
      if (MustAlloc(c, sc)) {
         _kctsb_gsetlength(&c, sc);
         if (a_alias) a = c; 
         if (b_alias) b = c;
         *cc = c;
      }

      adata = DATA(a);
      bdata = DATA(b);
      cdata = DATA(c);

      carry = KCTSB_MPN(add)(cdata, adata, sa, bdata, sb);
      if (carry) 
         cdata[sc-1] = carry;
      else
         sc--;

      if (aneg ^ rev) sc = -sc;
      SIZE(c) = sc;
   }
   else {
      /* same sign => subtraction */

      sc = sa;
      if (MustAlloc(c, sc)) {
         _kctsb_gsetlength(&c, sc);
         if (a_alias) a = c; 
         if (b_alias) b = c;
         *cc = c;
      }

      adata = DATA(a);
      bdata = DATA(b);
      cdata = DATA(c);

      if (sa > sb) 
         cmp = 1;
      else
         cmp = KCTSB_MPN(cmp)(adata, bdata, sa);

      if (cmp == 0) {
         SIZE(c) = 0;
      }
      else {
         if (cmp < 0) cmp = 0;
         if (cmp > 0) cmp = 1;
         /* abs(a) != abs(b) && (abs(a) > abs(b) <=> cmp) */

         if (cmp)
            KCTSB_MPN(sub)(cdata, adata, sa, bdata, sb);
         else
            KCTSB_MPN(sub)(cdata, bdata, sb, adata, sa); /* sa == sb */

         STRIP(sc, cdata);
         if ((aneg == cmp) ^ rev) sc = -sc;
         SIZE(c) = sc;
      }
   }
}

void
_kctsb_gsubpos(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   long sa, sb, sc;
   _kctsb_limb_t *adata, *bdata, *cdata;
   _kctsb_gbigint c;
   long a_alias, b_alias;

   if (ZEROP(a)) {
      _kctsb_gzero(cc);
      return;
   }

   if (ZEROP(b)) {
      _kctsb_gcopy(a, cc);
      return;
   }

   sa = SIZE(a);
   sb = SIZE(b);

   c = *cc;
   a_alias = (a == c);
   b_alias = (b == c);

   sc = sa;
   if (MustAlloc(c, sc)) {
      _kctsb_gsetlength(&c, sc);
      if (a_alias) a = c; 
      if (b_alias) b = c;
      *cc = c;
   }

   adata = DATA(a);
   bdata = DATA(b);
   cdata = DATA(c);

   KCTSB_MPN(sub)(cdata, adata, sa, bdata, sb);

   STRIP(sc, cdata);
   SIZE(c) = sc;
}

#if 1

// This version is faster for small inputs.
// It avoids some overheads incurred only when dealing with
// aliased outputs.
// It also makes direct calls to lower-level mpn functions
// for smaller inputs (and for one limb inputs, it avoids
// function calls altogether (usually)).

// Speedup: 2.5x 1 limb
//          1.4x 2 limb
//          1.3x 3 limb

static inline _kctsb_limb_t
base_mul (_kctsb_limb_t* rp, const _kctsb_limb_t* up, long un, const _kctsb_limb_t* vp, long vn)
{
  rp[un] = KCTSB_MPN(mul_1) (rp, up, un, vp[0]);

  while (--vn >= 1)
    {
      rp += 1, vp += 1;
      rp[un] = KCTSB_MPN(addmul_1) (rp, up, un, vp[0]);
    }
  return rp[un];
}

void _kctsb_gmul(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   long sa, aneg, sb, bneg, alias, sc;
   _kctsb_limb_t *adata, *bdata, *cdata, msl;
   _kctsb_gbigint c;

   if (ZEROP(a) || ZEROP(b)) {
      _kctsb_gzero(cc);
      return;
   }

   GET_SIZE_NEG(sa, aneg, a);
   GET_SIZE_NEG(sb, bneg, b);

   if (a != *cc && b != *cc) {
      // no aliasing

      c = *cc;

      sc = sa + sb;
      if (MustAlloc(c, sc)) {
	 _kctsb_gsetlength(&c, sc);
         *cc = c;
      }

      adata = DATA(a);
      bdata = DATA(b);
      cdata = DATA(c);

      if (adata == bdata) {
#if (1 && defined(KCTSB_VIABLE_LL) && KCTSB_NAIL_BITS==0)
         if (sa == 1) {
            ll_type prod;
            ll_mul(prod, adata[0], adata[0]);
            cdata[0] = ll_get_lo(prod);
            msl = cdata[1] = ll_get_hi(prod);
         } else
#endif
         {
            KCTSB_MPN(sqr)(cdata, adata, sa);
            msl = cdata[2*sa-1];
         }
      }
      else {
#if 1
	 if (sa >= sb) {
#if (1 && defined(KCTSB_VIABLE_LL) && KCTSB_NAIL_BITS==0)
	    if (sa == 1) {
	       ll_type prod;
	       ll_mul(prod, adata[0], bdata[0]);
	       cdata[0] = ll_get_lo(prod);
	       msl = cdata[1] = ll_get_hi(prod);
	    } else
#endif
	    if (sa <= 4)
	       msl = base_mul(cdata, adata, sa, bdata, sb);
	    else
	       msl = KCTSB_MPN(mul)(cdata, adata, sa, bdata, sb);
	 }
	 else {
	    if (sb <= 4)
	       msl = base_mul(cdata, bdata, sb, adata, sa);
	    else
	       msl = KCTSB_MPN(mul)(cdata, bdata, sb, adata, sa);
	 }
#else
	 if (sa >= sb) {
	    msl = KCTSB_MPN(mul)(cdata, adata, sa, bdata, sb);
	 }
	 else {
	    msl = KCTSB_MPN(mul)(cdata, bdata, sb, adata, sa);
	 }
#endif
      }

      if (!msl) sc--;
      if (aneg != bneg) sc = -sc;
      SIZE(c) = sc;
   }
   else {
      // aliasing
      GRegister(mem);

      c = mem;

      sc = sa + sb;
      if (MustAlloc(c, sc)) {
	 _kctsb_gsetlength(&c, sc);
         mem = c;
      }

      adata = DATA(a);
      bdata = DATA(b);
      cdata = DATA(c);

      if (adata == bdata) {
#if (1 && defined(KCTSB_VIABLE_LL) && KCTSB_NAIL_BITS==0)
         if (sa == 1) {
            ll_type prod;
            ll_mul(prod, adata[0], adata[0]);
            cdata[0] = ll_get_lo(prod);
            msl = cdata[1] = ll_get_hi(prod);
         } else
#endif
         {
            KCTSB_MPN(sqr)(cdata, adata, sa);
            msl = cdata[2*sa-1];
         }
      }
      else {
#if 1
	 if (sa >= sb) {
#if (1 && defined(KCTSB_VIABLE_LL) && KCTSB_NAIL_BITS==0)
	    if (sa == 1) {
	       ll_type prod;
	       ll_mul(prod, adata[0], bdata[0]);
	       cdata[0] = ll_get_lo(prod);
	       msl = cdata[1] = ll_get_hi(prod);
	    } else
#endif
	    if (sa <= 4)
	       msl = base_mul(cdata, adata, sa, bdata, sb);
	    else
	       msl = KCTSB_MPN(mul)(cdata, adata, sa, bdata, sb);
	 }
	 else {
	    if (sb <= 4)
	       msl = base_mul(cdata, bdata, sb, adata, sa);
	    else
	       msl = KCTSB_MPN(mul)(cdata, bdata, sb, adata, sa);
	 }
#else
	 if (sa >= sb) {
	    msl = KCTSB_MPN(mul)(cdata, adata, sa, bdata, sb);
	 }
	 else {
	    msl = KCTSB_MPN(mul)(cdata, bdata, sb, adata, sa);
	 }
#endif
      }

      if (!msl) sc--;
      if (aneg != bneg) sc = -sc;
      SIZE(c) = sc;

      _kctsb_gcopy(mem, cc);
   }

}

#else
void _kctsb_gmul(_kctsb_gbigint a, _kctsb_gbigint b, _kctsb_gbigint *cc)
{
   GRegister(mem);

   long sa, aneg, sb, bneg, alias, sc;
   _kctsb_limb_t *adata, *bdata, *cdata, msl;
   _kctsb_gbigint c;

   if (ZEROP(a) || ZEROP(b)) {
      _kctsb_gzero(cc);
      return;
   }

   GET_SIZE_NEG(sa, aneg, a);
   GET_SIZE_NEG(sb, bneg, b);

   if (a == *cc || b == *cc) {
      c = mem;
      alias = 1;
   }
   else {
      c = *cc;
      alias = 0;
   }

   sc = sa + sb;
   if (MustAlloc(c, sc))
      _kctsb_gsetlength(&c, sc);

   if (alias)
      mem = c;
   else
      *cc = c;

   adata = DATA(a);
   bdata = DATA(b);
   cdata = DATA(c);

   if (sa >= sb)
      msl = KCTSB_MPN(mul)(cdata, adata, sa, bdata, sb);
   else
      msl = KCTSB_MPN(mul)(cdata, bdata, sb, adata, sa);

   if (!msl) sc--;
   if (aneg != bneg) sc = -sc;
   SIZE(c) = sc;

   if (alias) _kctsb_gcopy(mem, cc);
}
#endif

void _kctsb_gsq(_kctsb_gbigint a, _kctsb_gbigint *cc)
{
   long sa, aneg, alias, sc;
   _kctsb_limb_t *adata, *cdata, msl;
   _kctsb_gbigint c;

   if (ZEROP(a)) {
      _kctsb_gzero(cc);
      return;
   }

   GET_SIZE_NEG(sa, aneg, a);

   if (a != *cc) {
      // no aliasing

      c = *cc;

      sc = sa + sa;
      if (MustAlloc(c, sc)) {
	 _kctsb_gsetlength(&c, sc);
         *cc = c;
      }

      adata = DATA(a);
      cdata = DATA(c);

#if (1 && defined(KCTSB_VIABLE_LL) && KCTSB_NAIL_BITS==0)
      if (sa == 1) {
	 ll_type prod;
	 ll_mul(prod, adata[0], adata[0]);
	 cdata[0] = ll_get_lo(prod);
	 msl = cdata[1] = ll_get_hi(prod);
      } else
#endif
      {
	 KCTSB_MPN(sqr)(cdata, adata, sa);
	 msl = cdata[2*sa-1];
      }

      if (!msl) sc--;
      SIZE(c) = sc;
   }
   else {
      // aliasing
      GRegister(mem);

      c = mem;

      sc = sa + sa;
      if (MustAlloc(c, sc)) {
	 _kctsb_gsetlength(&c, sc);
         mem = c;
      }

      adata = DATA(a);
      cdata = DATA(c);

#if (1 && defined(KCTSB_VIABLE_LL) && KCTSB_NAIL_BITS==0)
      if (sa == 1) {
	 ll_type prod;
	 ll_mul(prod, adata[0], adata[0]);
	 cdata[0] = ll_get_lo(prod);
	 msl = cdata[1] = ll_get_hi(prod);
      } else
#endif
      {
	 KCTSB_MPN(sqr)(cdata, adata, sa);
	 msl = cdata[2*sa-1];
      }

      if (!msl) sc--;
      SIZE(c) = sc;

      _kctsb_gcopy(mem, cc);
   }

}



void
_kctsb_gsmul(_kctsb_gbigint a, long d, _kctsb_gbigint *bb)
{
   long sa, sb;
   long anegative, bnegative;
   _kctsb_gbigint b;
   _kctsb_limb_t *adata, *bdata;
   _kctsb_limb_t dd, carry;
   long a_alias;

   if (ZEROP(a) || !d) {
      _kctsb_gzero(bb);
      return;
   }

   dd = ABS(d);

   if (XCLIP(dd)) {
      GRegister(xd);
      _kctsb_gintoz(d,&xd);
      _kctsb_gmul(a, xd, bb);
      return;
   }

   // we may now assume that |d| fits in one limb

   GET_SIZE_NEG(sa, anegative, a);

   bnegative = XOR(anegative, d < 0);

   sb = sa + 1;

   b = *bb;
   a_alias = (a == b);

   if (MustAlloc(b, sb)) {
      _kctsb_gsetlength(&b, sb);
      if (a_alias) a = b;
      *bb = b;
   }

   adata = DATA(a);
   bdata = DATA(b);

   if (dd == 2) 
      carry = KCTSB_MPN(lshift)(bdata, adata, sa, 1);
   else
      carry = KCTSB_MPN(mul_1)(bdata, adata, sa, dd);

   if (carry) 
      bdata[sa] = carry;
   else
      sb--;

   if (bnegative) sb = -sb;
   SIZE(b) = sb;
}




long _kctsb_gsdiv(_kctsb_gbigint a, long d, _kctsb_gbigint *bb)
{
   long sa, aneg, sb, dneg;
   _kctsb_gbigint b;
   _kctsb_limb_t dd, *adata, *bdata;
   long r;

   if (!d) {
      ArithmeticError("division by zero in _kctsb_gsdiv");
   }

   if (ZEROP(a)) {
      _kctsb_gzero(bb);
      return (0);
   }

   dd = ABS(d);

   if (XCLIP(dd)) {
      GRegister(xd);
      GRegister(xr);
      _kctsb_gintoz(d,&xd);
      _kctsb_gdiv(a, xd, bb, &xr);
      return _kctsb_gtoint(xr);
   }

   // we may now assume that |d| fits in one limb

   GET_SIZE_NEG(sa, aneg, a);

   dneg = d < 0;

   sb = sa;
   b = *bb;
   if (MustAlloc(b, sb)) {
      /* if b aliases a, then b won't move */
      _kctsb_gsetlength(&b, sb);
      *bb = b;
   }

   adata = DATA(a);
   bdata = DATA(b);

   if (dd == 2) 
      r = KCTSB_MPN(rshift)(bdata, adata, sa, 1) >> (KCTSB_ZZ_NBITS - 1);
   else
      r = KCTSB_MPN(divmod_1)(bdata, adata, sa, dd);

   if (bdata[sb-1] == 0)
      sb--;

   SIZE(b) = sb;

   if (aneg || dneg) {
      if (aneg != dneg) {
         if (!r) {
            SIZE(b) = -SIZE(b);
         }
         else {
            _kctsb_gsadd(b, 1, &b);
            SIZE(b) = -SIZE(b);
            if (dneg)
               r = r + d;
            else
               r = d - r;
            *bb = b;
         }
      }
      else
         r = -r;
   }

   return r;
}

long _kctsb_gsmod(_kctsb_gbigint a, long d)
{
   long sa, aneg, dneg;
   _kctsb_limb_t dd, *adata;
   long r;

   if (!d) {
      ArithmeticError("division by zero in _kctsb_gsmod");
   }

   if (ZEROP(a)) {
      return (0);
   }

   dd = ABS(d);

   if (XCLIP(dd)) {
      GRegister(xd);
      GRegister(xr);
      _kctsb_gintoz(d,&xd);
      _kctsb_gmod(a, xd, &xr);
      return _kctsb_gtoint(xr);
   }

   // we may now assume that |d| fits in one limb

   GET_SIZE_NEG(sa, aneg, a);

   dneg = d < 0;

   adata = DATA(a);

   if (dd == 2) 
      r = adata[0] & 1;
   else
      r = KCTSB_MPN(mod_1)(adata, sa, dd);

   if (aneg || dneg) {
      if (aneg != dneg) {
         if (r) {
            if (dneg)
               r = r + d;
            else
               r = d - r;
         }
      }
      else
         r = -r;
   }

   return r;
}




void _kctsb_gdiv(_kctsb_gbigint a, _kctsb_gbigint d, 
               _kctsb_gbigint *bb, _kctsb_gbigint *rr)
{
   GRegister(b);
   GRegister(rmem);

   _kctsb_gbigint *rp;

   long sa, aneg, sb, sd, dneg, sr, in_place;
   _kctsb_limb_t *adata, *ddata, *bdata, *rdata;

   if (ZEROP(d)) {
      ArithmeticError("division by zero in _kctsb_gdiv");
   }

   if (ZEROP(a)) {
      if (bb) _kctsb_gzero(bb);
      if (rr) _kctsb_gzero(rr);
      return;
   }

   GET_SIZE_NEG(sa, aneg, a);
   GET_SIZE_NEG(sd, dneg, d);

   if (!aneg && !dneg && rr && *rr != a && *rr != d) {
      in_place = 1;
      rp = rr;
   }
   else {
      in_place = 0;
      rp = &rmem;
   }


   if (sa < sd) {
      _kctsb_gzero(&b);
      _kctsb_gcopy(a, rp);
      if (aneg) SIZE(*rp) = -SIZE(*rp);
      goto done;
   }

   sb = sa-sd+1;
   if (MustAlloc(b, sb))
      _kctsb_gsetlength(&b, sb);

   sr = sd;
   if (MustAlloc(*rp, sr))
      _kctsb_gsetlength(rp, sr);


   adata = DATA(a);
   ddata = DATA(d);
   bdata = DATA(b);
   rdata = DATA(*rp);

   KCTSB_MPN(tdiv_qr)(bdata, rdata, 0, adata, sa, ddata, sd);

   if (bdata[sb-1] == 0)
      sb--;
   SIZE(b) = sb;

   STRIP(sr, rdata);
   SIZE(*rp) = sr;

done:

   if (aneg || dneg) {
      if (aneg != dneg) {
         if (ZEROP(*rp)) {
            SIZE(b) = -SIZE(b);
         }
         else {
            if (bb) {
               _kctsb_gsadd(b, 1, &b);
               SIZE(b) = -SIZE(b);
            }
            if (rr) {
               if (dneg)
                  _kctsb_gadd(*rp, d, rp);
               else
                  _kctsb_gsub(d, *rp, rp);
            }
         }
      }
      else
         SIZE(*rp) = -SIZE(*rp);
   }

   if (bb) _kctsb_gcopy(b, bb);

   if (rr && !in_place)
      _kctsb_gcopy(*rp, rr);
}


/* a simplified mod operation:  assumes a >= 0, d > 0 are non-negative,
 * that space for the result has already been allocated,
 * and that inputs do not alias output. */

static
void gmod_simple(_kctsb_gbigint a, _kctsb_gbigint d, _kctsb_gbigint *rr)
{
   GRegister(b);

   long sa, sb, sd, sr;
   _kctsb_limb_t *adata, *ddata, *bdata, *rdata;
   _kctsb_gbigint r;

   if (ZEROP(a)) {
      _kctsb_gzero(rr);
      return;
   }

   sa = SIZE(a);
   sd = SIZE(d);

   if (sa < sd) {
      _kctsb_gcopy(a, rr);
      return;
   }

   sb = sa-sd+1;
   if (MustAlloc(b, sb))
      _kctsb_gsetlength(&b, sb);

   sr = sd;
   r = *rr;

   adata = DATA(a);
   ddata = DATA(d);
   bdata = DATA(b);
   rdata = DATA(r);

   KCTSB_MPN(tdiv_qr)(bdata, rdata, 0, adata, sa, ddata, sd);

   STRIP(sr, rdata);
   SIZE(r) = sr;
}


void _kctsb_gmod(_kctsb_gbigint a, _kctsb_gbigint d, _kctsb_gbigint *rr)
{
   _kctsb_gdiv(a, d, 0, rr);
}

void _kctsb_gquickmod(_kctsb_gbigint *rr, _kctsb_gbigint d)
{
   _kctsb_gdiv(*rr, d, 0, rr);
}




#if (defined(KCTSB_GMP_LIP) && (KCTSB_ZZ_NBITS >= KCTSB_BITS_PER_LONG))

long _kctsb_gsqrts(long n)
{
   _kctsb_limb_t ndata, rdata;

   if (n == 0) {
      return 0;
   }

   if (n < 0) ArithmeticError("negative argument to _kctsb_sqrts");

   ndata = n;

   KCTSB_MPN(sqrtrem)(&rdata, 0, &ndata, 1);

   return rdata;
}


#else

long 
_kctsb_gsqrts(long n)
{

   if (n < 0) 
      ArithmeticError("_kctsb_gsqrts: negative argument");

   if (n <= 0) return (0);
   if (n <= 3) return (1);
   if (n <= 8) return (2);

   if (n >= KCTSB_WSP_BOUND)
   {
      GRegister(xn);
      GRegister(xr);
      _kctsb_gintoz(n,&xn);
      _kctsb_gsqrt(xn,&xr);
      return _kctsb_gtoint(xr);
   }

   long a;
   long ndiva;
   long newa;


   newa = 3L << (2 * ((KCTSB_WSP_NBITS/2) - 1)); 
   // DIRT: here we use the assumption that KCTSB_WSP_NBITS is
   // even --- this logic comes from Lenstra's LIP, and I don't know
   // what happens if it is odd

   a = 1L << (KCTSB_WSP_NBITS/2);
   while (!(n & newa)) {
      newa >>= 2;
      a >>= 1;
   }

   while (1) {
      newa = ((ndiva = n / a) + a) / 2;
      if (newa - ndiva <= 1) {
         if (newa * newa <= n)
            return newa;
         else
            return ndiva;
      }
      a = newa;
   }
}



#endif





#ifdef KCTSB_GMP_LIP 


void _kctsb_gsqrt(_kctsb_gbigint n, _kctsb_gbigint *rr)
{
   GRegister(r);

   long sn, sr;
   _kctsb_limb_t *ndata, *rdata;

   if (ZEROP(n)) {
      _kctsb_gzero(rr);
      return;
   }

   sn = SIZE(n);
   if (sn < 0) ArithmeticError("negative argument to _kctsb_gsqrt");

   sr = (sn+1)/2;
   _kctsb_gsetlength(&r, sr);

   ndata = DATA(n);
   rdata = DATA(r);

   mpn_sqrtrem(rdata, 0, ndata, sn);

   STRIP(sr, rdata);
   SIZE(r) = sr;

   _kctsb_gcopy(r, rr);
}

#else 


void _kctsb_gsqrt(_kctsb_gbigint n, _kctsb_gbigint *rr)
{
   GRegister(a);
   GRegister(ndiva);
   GRegister(diff);
   GRegister(r);

   if (ZEROP(n)) {
      _kctsb_gzero(rr);
      return;
   }

   long sn = SIZE(n);
   if (sn < 0) ArithmeticError("negative argument to _kctsb_gsqrt");

   _kctsb_limb_t *ndata = DATA(n);

   if (sn == 1) {
      _kctsb_gintoz(_kctsb_gsqrts(ndata[0]), rr);
      return;
   }

   _kctsb_gsetlength(&a, sn);
   _kctsb_gsetlength(&ndiva, sn);
   _kctsb_gsetlength(&diff, sn);

   long sa = (sn+1)/2;
   _kctsb_limb_t *adata = DATA(a);
   
   adata[sa-1] = _kctsb_gsqrts(ndata[sn-1]) + 1;
   if (!(sn & 1))
      adata[sa-1] <<= (KCTSB_ZZ_NBITS/2);
      // DIRT: here we use the assumption that KCTSB_ZZ_NBITS is
      // even --- this logic comes from Lenstra's LIP, and I don't know
      // what happens if it is odd

   if (adata[sa-1] & KCTSB_ZZ_RADIX) {
      sa++;
      adata[sa-1] = 1;
   }

   for (long i = 0; i < sa-1; i++) adata[i] = 0;
   SIZE(a) = sa;

   while (1) {
      _kctsb_gdiv(n, a, &ndiva, &r);
      _kctsb_gadd(a, ndiva, &r);
      _kctsb_grshift(r, 1, &r);
      if (_kctsb_gcompare(r, ndiva) <= 0) 
         goto done;

      _kctsb_gsubpos(r, ndiva, &diff);
      if (ZEROP(diff) || ONEP(diff)) {
         _kctsb_gsq(r, &diff);
         if (_kctsb_gcompare(diff, n) > 0)
            _kctsb_gcopy(ndiva, &r);

         goto done;
      }
      _kctsb_gcopy(r, &a);
   }
done:
   _kctsb_gcopy(r, rr);
}



#endif










#ifdef KCTSB_GMP_LIP

void _kctsb_ggcd(_kctsb_gbigint m1, _kctsb_gbigint m2, _kctsb_gbigint *r)
{
   GRegister(s1);
   GRegister(s2);
   GRegister(res);

   long k1, k2, k_min, l1, l2, ss1, ss2, sres;

   _kctsb_gcopy(m1, &s1);
   _kctsb_gabs(&s1);

   _kctsb_gcopy(m2, &s2);
   _kctsb_gabs(&s2);

   if (ZEROP(s1)) {
      _kctsb_gcopy(s2, r);
      return;
   }

   if (ZEROP(s2)) {
      _kctsb_gcopy(s1, r);
      return;
   }

   k1 = _kctsb_gmakeodd(&s1);
   k2 = _kctsb_gmakeodd(&s2);

   if (k1 <= k2)
      k_min = k1;
   else
      k_min = k2;

   l1 = _kctsb_g2log(s1);
   l2 = _kctsb_g2log(s2);

   ss1 = SIZE(s1);
   ss2 = SIZE(s2);

   if (ss1 >= ss2)
      sres = ss1;
   else
      sres = ss2;

   /* set to max: gmp documentation is unclear on this point */

   _kctsb_gsetlength(&res, sres);
   
   // NOTE: older versions of GMP require first operand has
   // at least as many bits as the second.
   // It seems this requirement has been relaxed in more
   // recent versions.

   if (l1 >= l2)
      SIZE(res) = mpn_gcd(DATA(res), DATA(s1), ss1, DATA(s2), ss2);
   else
      SIZE(res) = mpn_gcd(DATA(res), DATA(s2), ss2, DATA(s1), ss1);

   _kctsb_glshift(res, k_min, &res);

   _kctsb_gcopy(res, r);
}

void
_kctsb_ggcd_alt(_kctsb_gbigint mm1, _kctsb_gbigint mm2, _kctsb_gbigint *rres)
{
   _kctsb_ggcd(mm1, mm2, rres);
}


#else



// Interestingly, the Lehmer code even for basic GCD
// about twice as fast as the binary gcd

static void
gxxeucl_basic(
   _kctsb_gbigint ain,
   _kctsb_gbigint nin,
   _kctsb_gbigint *uu
   )
{
   GRegister(a);
   GRegister(n);
   GRegister(q);
   GRegister(x);
   GRegister(y);
   GRegister(z);


   long diff;
   long ilo;
   long sa;
   long sn;
   long temp;
   long e;
   long fast;
   long parity;
   long gotthem;
   _kctsb_limb_t *p;
   long try11;
   long try12;
   long try21;
   long try22;
   long got11;
   long got12;
   long got21;
   long got22;
   double hi;
   double lo;
   double dt;
   double fhi, fhi1;
   double flo, flo1;
   double num;
   double den;
   double dirt;

   if (SIZE(ain) < SIZE(nin)) {
      _kctsb_swap(ain, nin);
   }
   e = SIZE(ain)+2;

   _kctsb_gsetlength(&a, e);
   _kctsb_gsetlength(&n, e);
   _kctsb_gsetlength(&q, e);
   _kctsb_gsetlength(&x, e);
   _kctsb_gsetlength(&y, e);
   _kctsb_gsetlength(&z, e);

   fhi1 = double(1L) + double(32L)/KCTSB_FDOUBLE_PRECISION;
   flo1 = double(1L) - double(32L)/KCTSB_FDOUBLE_PRECISION;

   fhi = double(1L) + double(8L)/KCTSB_FDOUBLE_PRECISION;
   flo = double(1L) - double(8L)/KCTSB_FDOUBLE_PRECISION;

   _kctsb_gcopy(ain, &a);
   _kctsb_gcopy(nin, &n);


   while (SIZE(n) > 0)
   {
      gotthem = 0;
      sa = SIZE(a);
      sn = SIZE(n);
      diff = sa - sn;
      if (!diff || diff == 1)
      {
         sa = SIZE(a);
         p = DATA(a) + (sa-1);
         num = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sa > 1)
            num += DBL(*(--p));
         num *= KCTSB_ZZ_FRADIX;
         if (sa > 2)
            num += DBL(*(p - 1));

         sn = SIZE(n);
         p = DATA(n) + (sn-1);
         den = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sn > 1)
            den += DBL(*(--p));
         den *= KCTSB_ZZ_FRADIX;
         if (sn > 2)
            den += DBL(*(p - 1));

         hi = fhi1 * (num + double(1L)) / den;
         lo = flo1 * num / (den + double(1L));
         if (diff > 0)
         {
            hi *= KCTSB_ZZ_FRADIX;
            lo *= KCTSB_ZZ_FRADIX;
         }
         try11 = 1;
         try12 = 0;
         try21 = 0;
         try22 = 1;
         parity = 1;
         fast = 1; 
         while (fast > 0)
         {
            parity = 1 - parity;
            if (hi >= KCTSB_NSP_BOUND)
               fast = 0;
            else
            {
               ilo = (long)lo;
               dirt = hi - double(ilo);
               if (dirt < 1.0/KCTSB_FDOUBLE_PRECISION || !ilo || ilo < (long)hi)
                  fast = 0;
               else
               {
                  dt = lo-double(ilo);
                  lo = flo / dirt;
                  if (dt > 1.0/KCTSB_FDOUBLE_PRECISION)
                     hi = fhi / dt;
                  else
                     hi = double(KCTSB_NSP_BOUND);
                  temp = try11;
                  try11 = try21;
                  if ((KCTSB_WSP_BOUND - temp) / ilo < try21)
                     fast = 0;
                  else
                     try21 = temp + ilo * try21;
                  temp = try12;
                  try12 = try22;
                  if ((KCTSB_WSP_BOUND - temp) / ilo < try22)
                     fast = 0;
                  else
                     try22 = temp + ilo * try22;
                  if ((fast > 0) && (parity > 0))
                  {
                     gotthem = 1;
                     got11 = try11;
                     got12 = try12;
                     got21 = try21;
                     got22 = try22;
                  }
               }
            }
         }
      }
      if (gotthem)
      {
         _kctsb_gsmul(a, got11, &x);
         _kctsb_gsmul(n, got12, &y);
         _kctsb_gsmul(a, got21, &z);
         _kctsb_gsmul(n, got22, &n);
         _kctsb_gsub(x, y, &a);
         _kctsb_gsub(n, z, &n);
      }
      else
      {
         _kctsb_gdiv(a, n, &q, &a);
         if (!ZEROP(a))
         {
            _kctsb_gdiv(n, a, &q, &n);
         }
         else
         {
            _kctsb_gcopy(n, &a);
            _kctsb_gzero(&n);
         }
      }
   }

   _kctsb_gcopy(a, uu);

   return;
}

void
_kctsb_ggcd(_kctsb_gbigint mm1, _kctsb_gbigint mm2, _kctsb_gbigint *rres)
{
   GRegister(a);
   GRegister(b);
   GRegister(inv);

   if (ZEROP(mm1))
   {
      _kctsb_gcopy(mm2, rres);
      _kctsb_gabs(rres);
      return;
   }

   if (ZEROP(mm2))
   {
      _kctsb_gcopy(mm1, rres);
      _kctsb_gabs(rres);
      return;
   }

   _kctsb_gcopy(mm1, &a);
   _kctsb_gabs(&a);
   _kctsb_gcopy(mm2, &b);
   _kctsb_gabs(&b);
   gxxeucl_basic(a, b, rres);
}


// This is the binary gcd algorithm

void
_kctsb_ggcd_alt(_kctsb_gbigint mm1, _kctsb_gbigint mm2, _kctsb_gbigint *rres)
{
   GRegister(a);
   GRegister(b);
   GRegister(c);

   long agrb;
   long shibl;

   if (ZEROP(mm1))
   {
      _kctsb_gcopy(mm2, rres);
      _kctsb_gabs(rres);
      return;
   }

   if (ZEROP(mm2))
   {
      _kctsb_gcopy(mm1, rres);
      _kctsb_gabs(rres);
      return;
   }

   if (mm1 == mm2)
   {
      _kctsb_gcopy(mm1, rres);
      _kctsb_gabs(rres);
      return;
   }

   long s1 = SIZE(mm1);
   if (s1 < 0) s1 = -s1;

   long s2 = SIZE(mm2);
   if (s2 < 0) s2 = -s2;

   long maxs1s2 = max(s1, s2);

   _kctsb_gsetlength(&a, maxs1s2); 
   _kctsb_gsetlength(&b, maxs1s2);
   _kctsb_gsetlength(&c, maxs1s2);

   if (s1 != s2)
   {
      if (s1 > s2)
      {
         _kctsb_gcopy(mm2, &a);
         _kctsb_gabs(&a);

         _kctsb_gcopy(mm1, &c);
         _kctsb_gabs(&c);

         _kctsb_gmod(c, a, &b);
      }
      else
      {
         _kctsb_gcopy(mm1, &a);
         _kctsb_gabs(&a);

         _kctsb_gcopy(mm2, &c);
         _kctsb_gabs(&c);
         _kctsb_gmod(c, a, &b);
      }
      if (ZEROP(b)) goto done;
   }
   else
   {
      _kctsb_gcopy(mm1, &a);
      _kctsb_gabs(&a);
      _kctsb_gcopy(mm2, &b);
      _kctsb_gabs(&b);
   }

   if ((agrb = _kctsb_gmakeodd(&a)) < (shibl = _kctsb_gmakeodd(&b))) shibl = agrb;
   if (!(agrb = _kctsb_gcompare(a, b))) goto endshift;

   if (agrb < 0)
   {
      _kctsb_swap(a, b);
   }

   _kctsb_gsubpos(a, b, &c);
   do
   {
      _kctsb_gmakeodd(&c);
      if (!(agrb = _kctsb_gcompare(b, c)))
      {
         _kctsb_swap(a, b);
         goto endshift;
      }

      if (agrb > 0)
      {
         // (a, b, c) = (b, c, a)
         _kctsb_swap(a, b);
         _kctsb_swap(b, c);
      }
      else
      {
         // (a, b, c) = (c, b, a)
         _kctsb_swap(a, c);
      }
      _kctsb_gsubpos(a, b, &c);
   } while (!ZEROP(c));

endshift:
   _kctsb_glshift(a, shibl, &a);

done:
   _kctsb_gcopy(a, rres);
}

#endif





#ifdef KCTSB_GMP_LIP



void
_kctsb_gexteucl(
	_kctsb_gbigint ain,
	_kctsb_gbigint *xap,
	_kctsb_gbigint bin,
	_kctsb_gbigint *xbp,
	_kctsb_gbigint *dp
	)
{
   if (ZEROP(bin)) {
      long asign = _kctsb_gsign(ain);

      _kctsb_gcopy(ain, dp);
      _kctsb_gabs(dp);
      _kctsb_gintoz( (asign >= 0 ? 1 : -1), xap);
      _kctsb_gzero(xbp);
   }
   else if (ZEROP(ain)) {
      long bsign = _kctsb_gsign(bin);

      _kctsb_gcopy(bin, dp);
      _kctsb_gabs(dp);
      _kctsb_gzero(xap);
      _kctsb_gintoz(bsign, xbp); 
   }
   else {
      GRegister(a);
      GRegister(b);
      GRegister(xa);
      GRegister(xb);
      GRegister(d);
      GRegister(tmp);

      long sa, aneg, sb, bneg, rev;
      _kctsb_limb_t *adata, *bdata, *ddata, *xadata;
      mp_size_t sxa, sd;

      GET_SIZE_NEG(sa, aneg, ain);
      GET_SIZE_NEG(sb, bneg, bin);

      _kctsb_gsetlength(&a, sa+1); /* +1 because mpn_gcdext may need it */
      _kctsb_gcopy(ain, &a);

      _kctsb_gsetlength(&b, sb+1); /* +1 because mpn_gcdext may need it */
      _kctsb_gcopy(bin, &b);


      adata = DATA(a);
      bdata = DATA(b);

      if (sa < sb || (sa == sb && KCTSB_MPN(cmp)(adata, bdata, sa) < 0)) {
         SWAP_BIGINT(ain, bin);
         SWAP_LONG(sa, sb);
         SWAP_LONG(aneg, bneg);
         SWAP_LIMB_PTR(adata, bdata);
         rev = 1;
      }
      else 
         rev = 0;

      _kctsb_gsetlength(&d, sa+1); /* +1 because mpn_gcdext may need it...
                                    documentation is unclear, but this is
                                    what is done in mpz_gcdext */
      _kctsb_gsetlength(&xa, sa+1); /* ditto */

      ddata = DATA(d);
      xadata = DATA(xa);

      sd = mpn_gcdext(ddata, xadata, &sxa, adata, sa, bdata, sb);

      SIZE(d) = sd;
      SIZE(xa) = sxa;

#if 0
      // since we're now requiring GMP version 5.0.0 or later,
      // these workarounds are no longer required

      /* These two ForceNormal's are work-arounds for GMP bugs 
         in GMP 4.3.0 */
      ForceNormal(d);
      ForceNormal(xa);

      /* now we normalize xa, so that so that xa in ( -b/2d, b/2d ],
         which makes the output agree with Euclid's algorithm,
         regardless of what mpn_gcdext does */

      if (!ZEROP(xa)) {
         _kctsb_gcopy(bin, &b);
         SIZE(b) = sb;
         if (!ONEP(d)) {
            _kctsb_gdiv(b, d, &b, &tmp);
            if (!ZEROP(tmp)) TerminalError("internal bug in _kctsb_gexteucl");
         }

         if (SIZE(xa) > 0) { /* xa positive */
            if (_kctsb_gcompare(xa, b) > 0) { 
               _kctsb_gmod(xa, b, &xa);
            }
            _kctsb_glshift(xa, 1, &tmp);
            if (_kctsb_gcompare(tmp, b) > 0) {
               _kctsb_gsub(xa, b, &xa);
            }
         }
         else { /* xa negative */
            SIZE(xa) = -SIZE(xa);
            if (_kctsb_gcompare(xa, b) > 0) {
               SIZE(xa) = -SIZE(xa);
               _kctsb_gmod(xa, b, &xa);
               _kctsb_gsub(xa, b, &xa);
            }
            else {
               SIZE(xa) = -SIZE(xa);
            }
            _kctsb_glshift(xa, 1, &tmp);
            SIZE(tmp) = -SIZE(tmp);
            if (_kctsb_gcompare(tmp, b) >= 0) {
               _kctsb_gadd(xa, b, &xa);
            }
         }
      }

      /* end normalize */
#endif
    

      if (aneg) _kctsb_gnegate(&xa);

      _kctsb_gmul(ain, xa, &tmp);
      _kctsb_gsub(d, tmp, &tmp);
      _kctsb_gdiv(tmp, bin, &xb, &tmp);

      if (!ZEROP(tmp)) TerminalError("internal bug in _kctsb_gexteucl");

      if (rev) SWAP_BIGINT(xa, xb);

      _kctsb_gcopy(xa, xap);
      _kctsb_gcopy(xb, xbp);
      _kctsb_gcopy(d, dp); 
   }
}


long _kctsb_ginv(_kctsb_gbigint ain, _kctsb_gbigint nin, _kctsb_gbigint *invv)
{
   GRegister(u);
   GRegister(d);
   GRegister(a);
   GRegister(n);

   long sz; 
   long sd;
   mp_size_t su;

   if (_kctsb_gscompare(nin, 1) <= 0) {
      LogicError("InvMod: second input <= 1");
   }

   if (_kctsb_gsign(ain) < 0) {
      LogicError("InvMod: first input negative");
   }

   if (_kctsb_gcompare(ain, nin) >= 0) {
      LogicError("InvMod: first input too big");
   }

   sz = SIZE(nin) + 2;

   if (MustAlloc(a, sz))
      _kctsb_gsetlength(&a, sz);


   if (MustAlloc(n, sz))
       _kctsb_gsetlength(&n, sz);


   if (MustAlloc(d, sz))
       _kctsb_gsetlength(&d, sz);

   if (MustAlloc(u, sz))
       _kctsb_gsetlength(&u, sz);

   _kctsb_gadd(ain, nin, &a);
   _kctsb_gcopy(nin, &n);

   /* We apply mpn_gcdext to (a, n) = (ain+nin, nin), because that function
    * only computes the co-factor of the larger input. This way, we avoid
    * a multiplication and a division.
    */

   sd = mpn_gcdext(DATA(d), DATA(u), &su, DATA(a), SIZE(a), DATA(n), SIZE(n));

   SIZE(d) = sd;
   SIZE(u) = su;

#if 0
   // since we're now requiring GMP version 5.0.0 or later,
   // these workarounds are no longer required

   /* Thes two ForceNormal's are work-arounds for GMP bugs 
      in GMP 4.3.0 */
   ForceNormal(d);
   ForceNormal(u);
#endif

   if (ONEP(d)) {

      /*
       * We make sure that u is in range 0..n-1, just in case
       * GMP is sloppy.
       */

#if 0
      // since we're now requiring GMP version 5.0.0 or later,
      // these workarounds are no longer required

      if (_kctsb_gsign(u) < 0) {
         _kctsb_gadd(u, nin, &u);
         if (_kctsb_gsign(u) < 0) {
            _kctsb_gmod(u, nin, &u);
         }
      }
      else if (_kctsb_gcompare(u, nin) >= 0) {
         _kctsb_gsub(u, nin, &u);
         if (_kctsb_gcompare(u, nin) >= 0) {
             _kctsb_gmod(u, nin, &u);
         }
      }
#else
      if (_kctsb_gsign(u) < 0) {
         _kctsb_gadd(u, nin, &u);
      }

#endif

      _kctsb_gcopy(u, invv);
      return 0;
   }
   else {
      _kctsb_gcopy(d, invv);
      return 1;
   }
}



#else

static long 
gxxeucl(
   _kctsb_gbigint ain,
   _kctsb_gbigint nin,
   _kctsb_gbigint *invv,
   _kctsb_gbigint *uu
   )
{
   GRegister(a);
   GRegister(n);
   GRegister(q);
   GRegister(w);
   GRegister(x);
   GRegister(y);
   GRegister(z);

   GRegister(inv);

   long diff;
   long ilo;
   long sa;
   long sn;
   long temp;
   long e;
   long fast;
   long parity;
   long gotthem;
   _kctsb_limb_t *p;
   long try11;
   long try12;
   long try21;
   long try22;
   long got11;
   long got12;
   long got21;
   long got22;
   double hi;
   double lo;
   double dt;
   double fhi, fhi1;
   double flo, flo1;
   double num;
   double den;
   double dirt;

   _kctsb_gsetlength(&a, (e = 2 + (SIZE(ain) > SIZE(nin) ? SIZE(ain) : SIZE(nin))));
   _kctsb_gsetlength(&n, e);
   _kctsb_gsetlength(&q, e);
   _kctsb_gsetlength(&w, e);
   _kctsb_gsetlength(&x, e);
   _kctsb_gsetlength(&y, e);
   _kctsb_gsetlength(&z, e);
   _kctsb_gsetlength(&inv, e);

   fhi1 = double(1L) + double(32L)/KCTSB_FDOUBLE_PRECISION;
   flo1 = double(1L) - double(32L)/KCTSB_FDOUBLE_PRECISION;

   fhi = double(1L) + double(8L)/KCTSB_FDOUBLE_PRECISION;
   flo = double(1L) - double(8L)/KCTSB_FDOUBLE_PRECISION;

   _kctsb_gcopy(ain, &a);
   _kctsb_gcopy(nin, &n);

   _kctsb_gone(&inv);
   _kctsb_gzero(&w);

   while (SIZE(n) > 0)
   {
      gotthem = 0;
      sa = SIZE(a);
      sn = SIZE(n);
      diff = sa - sn;
      if (!diff || diff == 1)
      {
         sa = SIZE(a);
         p = DATA(a) + (sa-1);
         num = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sa > 1)
            num += DBL(*(--p));
         num *= KCTSB_ZZ_FRADIX;
         if (sa > 2)
            num += DBL(*(p - 1));

         sn = SIZE(n);
         p = DATA(n) + (sn-1);
         den = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sn > 1)
            den += DBL(*(--p));
         den *= KCTSB_ZZ_FRADIX;
         if (sn > 2)
            den += DBL(*(p - 1));

         hi = fhi1 * (num + double(1L)) / den;
         lo = flo1 * num / (den + double(1L));
         if (diff > 0)
         {
            hi *= KCTSB_ZZ_FRADIX;
            lo *= KCTSB_ZZ_FRADIX;
         }
         try11 = 1;
         try12 = 0;
         try21 = 0;
         try22 = 1;
         parity = 1;
         fast = 1; 
         while (fast > 0)
         {
            parity = 1 - parity;
            if (hi >= KCTSB_NSP_BOUND)
               fast = 0;
            else
            {
               ilo = (long)lo;
               dirt = hi - double(ilo);
               if (dirt < 1.0/KCTSB_FDOUBLE_PRECISION || !ilo || ilo < (long)hi)
                  fast = 0;
               else
               {
                  dt = lo-double(ilo);
                  lo = flo / dirt;
                  if (dt > 1.0/KCTSB_FDOUBLE_PRECISION)
                     hi = fhi / dt;
                  else
                     hi = double(KCTSB_NSP_BOUND);
                  temp = try11;
                  try11 = try21;
                  if ((KCTSB_WSP_BOUND - temp) / ilo < try21)
                     fast = 0;
                  else
                     try21 = temp + ilo * try21;
                  temp = try12;
                  try12 = try22;
                  if ((KCTSB_WSP_BOUND - temp) / ilo < try22)
                     fast = 0;
                  else
                     try22 = temp + ilo * try22;
                  if ((fast > 0) && (parity > 0))
                  {
                     gotthem = 1;
                     got11 = try11;
                     got12 = try12;
                     got21 = try21;
                     got22 = try22;
                  }
               }
            }
         }
      }
      if (gotthem)
      {
         _kctsb_gsmul(inv, got11, &x);
         _kctsb_gsmul(w, got12, &y);
         _kctsb_gsmul(inv, got21, &z);
         _kctsb_gsmul(w, got22, &w);
         _kctsb_gadd(x, y, &inv);
         _kctsb_gadd(z, w, &w);
         _kctsb_gsmul(a, got11, &x);
         _kctsb_gsmul(n, got12, &y);
         _kctsb_gsmul(a, got21, &z);
         _kctsb_gsmul(n, got22, &n);
         _kctsb_gsub(x, y, &a);
         _kctsb_gsub(n, z, &n);
      }
      else
      {
         _kctsb_gdiv(a, n, &q, &a);
         _kctsb_gmul(q, w, &x);
         _kctsb_gadd(inv, x, &inv);
         if (!ZEROP(a))
         {
            _kctsb_gdiv(n, a, &q, &n);
            _kctsb_gmul(q, inv, &x);
            _kctsb_gadd(w, x, &w);
         }
         else
         {
            _kctsb_gcopy(n, &a);
            _kctsb_gzero(&n);
            _kctsb_gcopy(w, &inv);
            _kctsb_gnegate(&inv);
         }
      }
   }

   if (_kctsb_gscompare(a, 1) == 0)
      e = 0;
   else 
      e = 1;

   _kctsb_gcopy(a, uu);
   _kctsb_gcopy(inv, invv);

   return (e);
}

void
_kctsb_gexteucl(
	_kctsb_gbigint aa,
	_kctsb_gbigint *xa,
	_kctsb_gbigint bb,
	_kctsb_gbigint *xb,
	_kctsb_gbigint *d
	)
{
   GRegister(modcon);
   GRegister(a);
   GRegister(b);

   long anegative = 0;
   long bnegative = 0;

   _kctsb_gcopy(aa, &a);
   _kctsb_gcopy(bb, &b);

   if (a && SIZE(a) < 0) {
      anegative = 1;
      SIZE(a) = -SIZE(a);
   }
   else
      anegative = 0;

   if (b && SIZE(b) < 0) {
      bnegative = 1;
      SIZE(b) = -SIZE(b);
   }
   else
      bnegative = 0;


   if (ZEROP(b))
   {
      _kctsb_gone(xa);
      _kctsb_gzero(xb);
      _kctsb_gcopy(a, d);
      goto done;
   }

   if (ZEROP(a))
   {
      _kctsb_gzero(xa);
      _kctsb_gone(xb);
      _kctsb_gcopy(b, d);
      goto done;
   }

   gxxeucl(a, b, xa, d);
   _kctsb_gmul(a, *xa, xb);
   _kctsb_gsub(*d, *xb, xb);
   _kctsb_gdiv(*xb, b, xb, &modcon);

   if (!ZEROP(modcon))
   {
      TerminalError("non-zero remainder in _kctsb_gexteucl   BUG");
   }


done:
   if (anegative)
   {
      _kctsb_gnegate(xa);
   }
   if (bnegative)
   {
      _kctsb_gnegate(xb);
   }
}

long 
_kctsb_ginv(
        _kctsb_gbigint ain,
        _kctsb_gbigint nin,
        _kctsb_gbigint *invv
        )
{
        GRegister(u);
        GRegister(v);
        long sgn;


        if (_kctsb_gscompare(nin, 1) <= 0) {
                LogicError("InvMod: second input <= 1");
        }

        sgn = _kctsb_gsign(ain);
        if (sgn < 0) {
                LogicError("InvMod: first input negative");
        }

        if (_kctsb_gcompare(ain, nin) >= 0) {
                LogicError("InvMod: first input too big");
        }


        if (sgn == 0) {
                _kctsb_gcopy(nin, invv);
                return 1;
        }

        if (!(gxxeucl(ain, nin, &v, &u))) {
                if (_kctsb_gsign(v) < 0) _kctsb_gadd(v, nin, &v);
                _kctsb_gcopy(v, invv);
                return 0;
        }

        _kctsb_gcopy(u, invv);
        return 1;
}



#endif



void
_kctsb_ginvmod(
	_kctsb_gbigint a,
	_kctsb_gbigint n,
	_kctsb_gbigint *c
	)
{
	if (_kctsb_ginv(a, n, c))
		ArithmeticError("undefined inverse in _kctsb_ginvmod");
}

void
_kctsb_gaddmod(
	_kctsb_gbigint a,
	_kctsb_gbigint b,
	_kctsb_gbigint n,
	_kctsb_gbigint *c
	)
{
	if (*c != n) {
		_kctsb_gadd(a, b, c);
		if (_kctsb_gcompare(*c, n) >= 0)
			_kctsb_gsubpos(*c, n, c);
	}
	else {
                GRegister(mem);

		_kctsb_gadd(a, b, &mem);
		if (_kctsb_gcompare(mem, n) >= 0)
			_kctsb_gsubpos(mem, n, c);
		else
			_kctsb_gcopy(mem, c);
	}
}


void
_kctsb_gsubmod(
	_kctsb_gbigint a,
	_kctsb_gbigint b,
	_kctsb_gbigint n,
	_kctsb_gbigint *c
	)
{
        GRegister(mem);
	long cmp;

	if ((cmp=_kctsb_gcompare(a, b)) < 0) {
		_kctsb_gadd(n, a, &mem);
		_kctsb_gsubpos(mem, b, c);
	} else if (!cmp) 
		_kctsb_gzero(c);
	else 
		_kctsb_gsubpos(a, b, c);
}

void
_kctsb_gsmulmod(
	_kctsb_gbigint a,
	long d,
	_kctsb_gbigint n,
	_kctsb_gbigint *c
	)
{
        GRegister(mem);

	_kctsb_gsmul(a, d, &mem);
	_kctsb_gmod(mem, n, c);
}



void
_kctsb_gmulmod(
	_kctsb_gbigint a,
	_kctsb_gbigint b,
	_kctsb_gbigint n,
	_kctsb_gbigint *c
	)
{
        GRegister(mem);

	_kctsb_gmul(a, b, &mem);
	_kctsb_gmod(mem, n, c);
}

void
_kctsb_gsqmod(
	_kctsb_gbigint a,
	_kctsb_gbigint n,
	_kctsb_gbigint *c
	)
{
	_kctsb_gmulmod(a, a, n, c);
}


double _kctsb_gdoub_aux(_kctsb_gbigint n)
{
   double res;
   _kctsb_limb_t *ndata;
   long i, sn, nneg;

   if (!n)
      return ((double) 0);

   GET_SIZE_NEG(sn, nneg, n);

   ndata = DATA(n);

   res = 0;
   for (i = sn-1; i >= 0; i--)
      res = res * KCTSB_ZZ_FRADIX + DBL(ndata[i]);

   if (nneg) res = -res;

   return res;
}

long _kctsb_ground_correction(_kctsb_gbigint a, long k, long residual)
{
   long direction;
   long p;
   long sgn;
   long bl;
   _kctsb_limb_t wh;
   long i;
   _kctsb_limb_t *adata;

   if (SIZE(a) > 0)
      sgn = 1;
   else
      sgn = -1;

   adata = DATA(a);

   p = k - 1;
   bl = (p/KCTSB_ZZ_NBITS);
   wh = ((_kctsb_limb_t) 1) << (p - KCTSB_ZZ_NBITS*bl);

   if (adata[bl] & wh) {
      /* bit is 1...we have to see if lower bits are all 0
         in order to implement "round to even" */

      if (adata[bl] & (wh - ((_kctsb_limb_t) 1))) 
         direction = 1;
      else {
         i = bl - 1;
         while (i >= 0 && adata[i] == 0) i--;
         if (i >= 0)
            direction = 1;
         else
            direction = 0;
      }

      /* use residual to break ties */

      if (direction == 0 && residual != 0) {
         if (residual == sgn)
            direction = 1;
         else 
            direction = -1;
      }

      if (direction == 0) {
         /* round to even */

         wh = CLIP(wh << 1); 

         if (wh == 0) {
            wh = 1;
            bl++;
         }

         if (adata[bl] & wh)
            direction = 1;
         else
            direction = -1;
      }
   }
   else
      direction = -1;

   if (direction == 1)
      return sgn;

   return 0;
}




double _kctsb_gdoub(_kctsb_gbigint n)
{
   GRegister(tmp);

   long s;
   long shamt;
   long correction;
   double x;

   s = _kctsb_g2log(n);
   shamt = s - KCTSB_DOUBLE_PRECISION;

   if (shamt <= 0)
      return _kctsb_gdoub_aux(n);

   _kctsb_grshift(n, shamt, &tmp);

   correction = _kctsb_ground_correction(n, shamt, 0);

   if (correction) _kctsb_gsadd(tmp, correction, &tmp);

   x = _kctsb_gdoub_aux(tmp);

   x = _kctsb_ldexp(x, shamt);

   return x;
}


double _kctsb_glog(_kctsb_gbigint n)
{
   GRegister(tmp);

   static const double log_2 = log(2.0); // GLOBAL (assumes C++11 thread-safe init)

   long s;
   long shamt;
   long correction;
   double x;

   if (_kctsb_gsign(n) <= 0)
      ArithmeticError("log argument <= 0");

   s = _kctsb_g2log(n);
   shamt = s - KCTSB_DOUBLE_PRECISION;

   if (shamt <= 0)
      return log(_kctsb_gdoub_aux(n));

   _kctsb_grshift(n, shamt, &tmp);

   correction = _kctsb_ground_correction(n, shamt, 0);

   if (correction) _kctsb_gsadd(tmp, correction, &tmp);

   x = _kctsb_gdoub_aux(tmp);

   return log(x) + shamt*log_2;
}



void _kctsb_gdoubtoz(double a, _kctsb_gbigint *xx)
{
   GRegister(x);

   long neg, i, t, sz;

   a = floor(a);

   if (!IsFinite(&a))
      ArithmeticError("_kctsb_gdoubtoz: attempt to convert non-finite value");

   if (a < 0) {
      a = -a;
      neg = 1;
   }
   else
      neg = 0;

   if (a == 0) {
      _kctsb_gzero(xx);
      return;
   }

   sz = 0;
   while (a >= 1) {
      a = a*(1.0/double(KCTSB_NSP_BOUND));
      sz++;
   }

   i = 0;
   _kctsb_gzero(&x);

   while (a != 0) {
      i++;
      a = a*double(KCTSB_NSP_BOUND);
      t = (long) a;
      a = a - t; // NOTE: this subtraction should be exact

      if (i == 1) {
         _kctsb_gintoz(t, &x);
      }
      else {
         _kctsb_glshift(x, KCTSB_NSP_NBITS, &x);
         _kctsb_gsadd(x, t, &x);
      }
   }

   if (i > sz) TerminalError("bug in _kctsb_gdoubtoz");

   _kctsb_glshift(x, (sz-i)*KCTSB_NSP_NBITS, xx);
   if (neg) _kctsb_gnegate(xx);
}



/* I've adapted LIP's extended euclidean algorithm to
 * do rational reconstruction.  -- VJS.
 */


long 
_kctsb_gxxratrecon(
   _kctsb_gbigint ain,
   _kctsb_gbigint nin,
   _kctsb_gbigint num_bound,
   _kctsb_gbigint den_bound,
   _kctsb_gbigint *num_out,
   _kctsb_gbigint *den_out
   )
{
   GRegister(a);
   GRegister(n);
   GRegister(q);
   GRegister(w);
   GRegister(x);
   GRegister(y);
   GRegister(z);
   GRegister(inv);
   GRegister(u);
   GRegister(a_bak);
   GRegister(n_bak);
   GRegister(inv_bak);
   GRegister(w_bak);

   _kctsb_limb_t *p;

   long diff;
   long ilo;
   long sa;
   long sn;
   long snum;
   long sden;
   long e;
   long fast;
   long temp;
   long parity;
   long gotthem;
   long try11;
   long try12;
   long try21;
   long try22;
   long got11;
   long got12;
   long got21;
   long got22;

   double hi;
   double lo;
   double dt;
   double fhi, fhi1;
   double flo, flo1;
   double num;
   double den;
   double dirt;

   if (_kctsb_gsign(num_bound) < 0)
      LogicError("rational reconstruction: bad numerator bound");

   if (!num_bound)
      snum = 0;
   else
      snum = SIZE(num_bound);

   if (_kctsb_gsign(den_bound) <= 0)
      LogicError("rational reconstruction: bad denominator bound");

   sden = SIZE(den_bound);

   if (_kctsb_gsign(nin) <= 0)
      LogicError("rational reconstruction: bad modulus");

   if (_kctsb_gsign(ain) < 0 || _kctsb_gcompare(ain, nin) >= 0)
      LogicError("rational reconstruction: bad residue");

      
   e = 2+SIZE(nin);

   _kctsb_gsetlength(&a, e);
   _kctsb_gsetlength(&n, e);
   _kctsb_gsetlength(&q, e);
   _kctsb_gsetlength(&w, e);
   _kctsb_gsetlength(&x, e);
   _kctsb_gsetlength(&y, e);
   _kctsb_gsetlength(&z, e);
   _kctsb_gsetlength(&inv, e);
   _kctsb_gsetlength(&u, e);
   _kctsb_gsetlength(&a_bak, e);
   _kctsb_gsetlength(&n_bak, e);
   _kctsb_gsetlength(&inv_bak, e);
   _kctsb_gsetlength(&w_bak, e);

   fhi1 = double(1L) + double(32L)/KCTSB_FDOUBLE_PRECISION;
   flo1 = double(1L) - double(32L)/KCTSB_FDOUBLE_PRECISION;

   fhi = double(1L) + double(8L)/KCTSB_FDOUBLE_PRECISION;
   flo = double(1L) - double(8L)/KCTSB_FDOUBLE_PRECISION;

   _kctsb_gcopy(ain, &a);
   _kctsb_gcopy(nin, &n);

   _kctsb_gone(&inv);
   _kctsb_gzero(&w);

   while (1)
   {
      if (SIZE(w) >= sden && _kctsb_gcompare(w, den_bound) > 0) break;
      if (SIZE(n) <= snum && _kctsb_gcompare(n, num_bound) <= 0) break;

      _kctsb_gcopy(a, &a_bak);
      _kctsb_gcopy(n, &n_bak);
      _kctsb_gcopy(w, &w_bak);
      _kctsb_gcopy(inv, &inv_bak);

      gotthem = 0;
      sa = SIZE(a);
      sn = SIZE(n);
      diff = sa - sn;
      if (!diff || diff == 1)
      {
         sa = SIZE(a);
         p = DATA(a) + (sa-1);
         num = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sa > 1)
            num += DBL(*(--p));
         num *= KCTSB_ZZ_FRADIX;
         if (sa > 2)
            num += DBL(*(p - 1));

         sn = SIZE(n);
         p = DATA(n) + (sn-1);
         den = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sn > 1)
            den += DBL(*(--p));
         den *= KCTSB_ZZ_FRADIX;
         if (sn > 2)
            den += DBL(*(p - 1));

         hi = fhi1 * (num + double(1L)) / den;
         lo = flo1 * num / (den + double(1L));
         if (diff > 0)
         {
            hi *= KCTSB_ZZ_FRADIX;
            lo *= KCTSB_ZZ_FRADIX;
         }

         try11 = 1;
         try12 = 0;
         try21 = 0;
         try22 = 1;
         parity = 1;
         fast = 1; 
         while (fast > 0)
         {
            parity = 1 - parity;
            if (hi >= KCTSB_NSP_BOUND)
               fast = 0;
            else
            {
               ilo = (long)lo;
               dirt = hi - double(ilo);
               if (dirt < 1.0/KCTSB_FDOUBLE_PRECISION || !ilo || ilo < (long)hi)
                  fast = 0;
               else
               {
                  dt = lo-double(ilo);
                  lo = flo / dirt;
                  if (dt > 1.0/KCTSB_FDOUBLE_PRECISION)
                     hi = fhi / dt;
                  else
                     hi = double(KCTSB_NSP_BOUND);
                  temp = try11;
                  try11 = try21;
                  if ((KCTSB_WSP_BOUND - temp) / ilo < try21)
                     fast = 0;
                  else
                     try21 = temp + ilo * try21;
                  temp = try12;
                  try12 = try22;
                  if ((KCTSB_WSP_BOUND - temp) / ilo < try22)
                     fast = 0;
                  else
                     try22 = temp + ilo * try22;
                  if ((fast > 0) && (parity > 0))
                  {
                     gotthem = 1;
                     got11 = try11;
                     got12 = try12;
                     got21 = try21;
                     got22 = try22;
                  }
               }
            }
         }
      }
      if (gotthem)
      {
         _kctsb_gsmul(inv, got11, &x);
         _kctsb_gsmul(w, got12, &y);
         _kctsb_gsmul(inv, got21, &z);
         _kctsb_gsmul(w, got22, &w);
         _kctsb_gadd(x, y, &inv);
         _kctsb_gadd(z, w, &w);
         _kctsb_gsmul(a, got11, &x);
         _kctsb_gsmul(n, got12, &y);
         _kctsb_gsmul(a, got21, &z);
         _kctsb_gsmul(n, got22, &n);
         _kctsb_gsub(x, y, &a);
         _kctsb_gsub(n, z, &n);
      }
      else
      {
         _kctsb_gdiv(a, n, &q, &a);
         _kctsb_gmul(q, w, &x);
         _kctsb_gadd(inv, x, &inv);
         if (!ZEROP(a))
         {
            _kctsb_gdiv(n, a, &q, &n);
            _kctsb_gmul(q, inv, &x);
            _kctsb_gadd(w, x, &w);
         }
         else
         {
            break;
         }
      }
   }

   _kctsb_gcopy(a_bak, &a);
   _kctsb_gcopy(n_bak, &n);
   _kctsb_gcopy(w_bak, &w);
   _kctsb_gcopy(inv_bak, &inv);

   _kctsb_gnegate(&w);

   while (1)
   {
      sa = SIZE(w);
      if (sa < 0) SIZE(w) = -sa;
      if (SIZE(w) >= sden && _kctsb_gcompare(w, den_bound) > 0) return 0;
      SIZE(w) = sa;

      if (SIZE(n) <= snum && _kctsb_gcompare(n, num_bound) <= 0) break;
      
      fast = 0;
      sa = SIZE(a);
      sn = SIZE(n);
      diff = sa - sn;
      if (!diff || diff == 1)
      {
         sa = SIZE(a);
         p = DATA(a) + (sa-1);
         num = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sa > 1)
            num += DBL(*(--p));
         num *= KCTSB_ZZ_FRADIX;
         if (sa > 2)
            num += DBL(*(p - 1));

         sn = SIZE(n);
         p = DATA(n) + (sn-1);
         den = DBL(*p) * KCTSB_ZZ_FRADIX;
         if (sn > 1)
            den += DBL(*(--p));
         den *= KCTSB_ZZ_FRADIX;
         if (sn > 2)
            den += DBL(*(p - 1));

         hi = fhi1 * (num + double(1L)) / den;
         lo = flo1 * num / (den + double(1L));
         if (diff > 0)
         {
            hi *= KCTSB_ZZ_FRADIX;
            lo *= KCTSB_ZZ_FRADIX;
         }

         if (hi < KCTSB_NSP_BOUND)
         {
            ilo = (long)lo;
            if (ilo == (long)hi)
               fast = 1;
         }
      }

      if (fast) 
      {
         if (ilo != 0) {
            if (ilo == 1) {
               _kctsb_gsub(inv, w, &inv);
               _kctsb_gsubpos(a, n, &a);
            }
            else {
               _kctsb_gsmul(w, ilo, &x);
               _kctsb_gsub(inv, x, &inv);
               _kctsb_gsmul(n, ilo, &x);
               _kctsb_gsubpos(a, x, &a);
            }
         }
      }
      else {
         _kctsb_gdiv(a, n, &q, &a);
         _kctsb_gmul(q, w, &x);
         _kctsb_gsub(inv, x, &inv);
      }

      _kctsb_gswap(&a, &n);
      _kctsb_gswap(&inv, &w);
   }

   if (_kctsb_gsign(w) < 0) {
      _kctsb_gnegate(&w);
      _kctsb_gnegate(&n);
   }

   _kctsb_gcopy(n, num_out);
   _kctsb_gcopy(w, den_out);

   return 1;
}


void
_kctsb_gexp(
	_kctsb_gbigint a,
	long e,
	_kctsb_gbigint *bb
	)
{
	long k;
	long len_a;
        GRegister(res);

	if (!e)
	{
		_kctsb_gone(bb);
		return;
	}

	if (e < 0)
		ArithmeticError("negative exponent in _kctsb_gexp");

	if (ZEROP(a))
	{
		_kctsb_gzero(bb);
		return;
	}

	len_a = _kctsb_g2log(a);
	if (len_a > (KCTSB_MAX_LONG-(KCTSB_ZZ_NBITS-1))/e)
		ResourceError("overflow in _kctsb_gexp");

	_kctsb_gsetlength(&res, (len_a*e+KCTSB_ZZ_NBITS-1)/KCTSB_ZZ_NBITS);

	_kctsb_gcopy(a, &res);
	k = 1;
	while ((k << 1) <= e)
		k <<= 1;
	while (k >>= 1) {
		_kctsb_gsq(res, &res);
		if (e & k)
			_kctsb_gmul(a, res, &res);
	}

	_kctsb_gcopy(res, bb);
}

void
_kctsb_gexps(
	long a,
	long e,
	_kctsb_gbigint *bb
	)
{
	long k;
	long len_a;
        GRegister(res);

	if (!e)
	{
		_kctsb_gone(bb);
		return;
	}

	if (e < 0)
		ArithmeticError("negative exponent in _kctsb_zexps");

	if (!a)
	{
		_kctsb_gzero(bb);
		return;
	}

	len_a = _kctsb_g2logs(a);
	if (len_a > (KCTSB_MAX_LONG-(KCTSB_ZZ_NBITS-1))/e)
		ResourceError("overflow in _kctsb_gexps");

	_kctsb_gsetlength(&res, (len_a*e+KCTSB_ZZ_NBITS-1)/KCTSB_ZZ_NBITS);

	_kctsb_gintoz(a, &res);
	k = 1;
	while ((k << 1) <= e)
		k <<= 1;
	while (k >>= 1) {
		_kctsb_gsq(res, &res);
		if (e & k)
			_kctsb_gsmul(res, a, &res);
	}

	_kctsb_gcopy(res, bb);
}


static
long OptWinSize(long n)
/* finds k that minimizes n/(k+1) + 2^{k-1} */

{
   long k;
   double v, v_new;


   v = n/2.0 + 1.0;
   k = 1;

   for (;;) {
      v_new = n/((double)(k+2)) + ((double)(1L << k));
      if (v_new >= v) break;
      v = v_new;
      k++;
   }

   return k;
}



static
_kctsb_limb_t neg_inv_mod_limb(_kctsb_limb_t m0)
{
   _kctsb_limb_t x; 
   long k;

   x = 1; 
   k = 1; 
   while (k < KCTSB_ZZ_NBITS) {
      x += x * (1UL - x * m0); 
      k <<= 1;
   }

   return CLIP(-x); 
}


/* Montgomery reduction:
 * This computes res = T/b^m mod N, where b = 2^{KCTSB_ZZ_NBITS}.
 * It is assumed that N has n limbs, and that T has at most n + m limbs.
 * Also, inv should be set to -N^{-1} mod b.
 * Finally, it is assumed that T has space allocated for n + m limbs,
 * and that res has space allocated for n limbs.  
 * Note: res should not overlap any inputs, and T is destroyed.
 * Note: res will have at most n limbs, but may not be fully reduced
 * mod N.  In general, we will have res < T/b^m + N.
 */


static
void redc(_kctsb_gbigint T, _kctsb_gbigint N, long m, _kctsb_limb_t inv, 
          _kctsb_gbigint res) 
{
   long n, sT, i;
   _kctsb_limb_t *Ndata, *Tdata, *resdata, q, d, t, c;

   n = SIZE(N);
   Ndata = DATA(N);
   sT = SIZE(T);
   Tdata = DATA(T);
   resdata = DATA(res);

   for (i = sT; i < m+n; i++)
      Tdata[i] = 0;

   c = 0;
   for (i = 0; i < m; i++) {
      q = CLIP(Tdata[i]*inv);
      d = KCTSB_MPN(addmul_1)(Tdata+i, Ndata, n, q);

      // (c, Tdata[i+n]) = c + d + Tdata[i+n]
      t = CLIP(Tdata[i+n] + d);
      Tdata[i+n] = CLIP(t + c);
      if (t < d || (c == 1 && CLIP(t + c)  == 0)) 
         c = 1;
      else
         c = 0;
   }

   if (c) {
      KCTSB_MPN(sub_n)(resdata, Tdata + m, Ndata, n);
   }
   else {
      for (i = 0; i < n; i++)
         resdata[i] = Tdata[m + i];
   }

   i = n;
   STRIP(i, resdata);

   SIZE(res) = i;
   SIZE(T) = 0;
}


// This montgomery code is for external consumption...
// This is currently used in the CRT reconstruction step
// for ZZ_pX arithmetic.  It gives a nontrivial speedup
// for smallish p (up to a few hundred bits)

class _kctsb_reduce_struct_montgomery : public _kctsb_reduce_struct {
public:
   long m;
   _kctsb_limb_t inv;
   _kctsb_gbigint_wrapped N;

   void eval(_kctsb_gbigint *rres, _kctsb_gbigint *TT);
   void adjust(_kctsb_gbigint *x);
};




void _kctsb_reduce_struct_montgomery::eval(_kctsb_gbigint *rres, _kctsb_gbigint *TT)
{
   long n, sT, i;
   _kctsb_limb_t *Ndata, *Tdata, *resdata, q, d, t, c;
   _kctsb_gbigint res, T;


   T = *TT;

   // quick zero test, in case of sparse polynomials
   if (ZEROP(T)) {
      _kctsb_gzero(rres);
      return;
   }

   n = SIZE(N);
   Ndata = DATA(N);

   if (MustAlloc(T, m+n)) {
      _kctsb_gsetlength(&T, m+n);
      *TT = T;
   }

   res = *rres;
   if (MustAlloc(res, n)) {
      _kctsb_gsetlength(&res, n);
      *rres = res;
   }

   sT = SIZE(T);
   Tdata = DATA(T);
   resdata = DATA(res);

   for (i = sT; i < m+n; i++)
      Tdata[i] = 0;

   c = 0;
   for (i = 0; i < m; i++) {
      q = CLIP(Tdata[i]*inv);
      d = KCTSB_MPN(addmul_1)(Tdata+i, Ndata, n, q);

      // (c, Tdata[i+n]) = c + d + Tdata[i+n]
      t = CLIP(Tdata[i+n] + d);
      Tdata[i+n] = CLIP(t + c);
      if (t < d || (c == 1 && CLIP(t + c)  == 0)) 
         c = 1;
      else
         c = 0;
   }

   if (c || KCTSB_MPN(cmp)(Tdata + m, Ndata, n) >= 0) {
      KCTSB_MPN(sub_n)(resdata, Tdata + m, Ndata, n);
   }
   else {
      for (i = 0; i < n; i++)
         resdata[i] = Tdata[m + i];
   }

   i = n;
   STRIP(i, resdata);

   SIZE(res) = i;
   SIZE(T) = 0;
}

// this will adjust the given number by multiplying by the
// montgomery scaling factor

void _kctsb_reduce_struct_montgomery::adjust(_kctsb_gbigint *x)
{
   GRegister(tmp);
   _kctsb_glshift(*x, m*KCTSB_ZZ_NBITS, &tmp); 
   _kctsb_gmod(tmp, N, x);
}




class _kctsb_reduce_struct_plain : public _kctsb_reduce_struct {
public:
   _kctsb_gbigint_wrapped N;

   void eval(_kctsb_gbigint *rres, _kctsb_gbigint *TT)
   {
      _kctsb_gmod(*TT, N, rres);
   }

   void adjust(_kctsb_gbigint *x) { }
};

// assumption: all values passed to eval for montgomery reduction
// are in [0, modulus*excess]

_kctsb_reduce_struct *
_kctsb_reduce_struct_build(_kctsb_gbigint modulus, _kctsb_gbigint excess)
{
   if (_kctsb_godd(modulus)) {
      UniquePtr<_kctsb_reduce_struct_montgomery> C;
      C.make();

      C->m = _kctsb_gsize(excess);
      C->inv = neg_inv_mod_limb(DATA(modulus)[0]);
      _kctsb_gcopy(modulus, &C->N);

      return C.release();
   }
   else {
      UniquePtr<_kctsb_reduce_struct_plain> C;
      C.make();

      _kctsb_gcopy(modulus, &C->N);

      return C.release();
   }
}


#if (defined(KCTSB_GMP_LIP) && KCTSB_NAIL_BITS == 0)
// DIRT: only works with empty nails
// Assumes: F > 1,   0 < g < F,   e > 0

struct wrapped_mpz {
   mpz_t body;

   wrapped_mpz() { mpz_init(body); }
   ~wrapped_mpz() { mpz_clear(body); }
};

static
void _kctsb_gmp_powermod(_kctsb_gbigint g, _kctsb_gbigint e, _kctsb_gbigint F,
                       _kctsb_gbigint *h)
{
   wrapped_mpz gg;
   wrapped_mpz ee;
   wrapped_mpz FF;
   wrapped_mpz res;

   mpz_import(gg.body, SIZE(g), -1, sizeof(mp_limb_t), 0, 0, DATA(g));
   mpz_import(ee.body, SIZE(e), -1, sizeof(mp_limb_t), 0, 0, DATA(e));
   mpz_import(FF.body, SIZE(F), -1, sizeof(mp_limb_t), 0, 0, DATA(F));

   mpz_powm(res.body, gg.body, ee.body, FF.body);

   if (mpz_sgn(res.body) == 0) {
      _kctsb_gzero(h);
      return;
   }

   long sz = mpz_size(res.body);

   _kctsb_gsetlength(h, sz);
   _kctsb_limb_t *hdata = DATA(*h);
   SIZE(*h) = sz;

   mpz_export(hdata, 0, -1, sizeof(mp_limb_t), 0, 0, res.body);
}


#if 1
// This version avoids memory allocations.
// On 2-limb numbers, it is about 10% faster.

static
void _kctsb_gmp_powermod_alt(_kctsb_gbigint g, _kctsb_gbigint e, _kctsb_gbigint F,
                           _kctsb_gbigint *h)
{
   KCTSB_TLS_LOCAL(wrapped_mpz, gg);
   KCTSB_TLS_LOCAL(wrapped_mpz, ee);
   KCTSB_TLS_LOCAL(wrapped_mpz, FF);
   KCTSB_TLS_LOCAL(wrapped_mpz, res);

   mpz_import(gg.body, SIZE(g), -1, sizeof(mp_limb_t), 0, 0, DATA(g));
   mpz_import(ee.body, SIZE(e), -1, sizeof(mp_limb_t), 0, 0, DATA(e));
   mpz_import(FF.body, SIZE(F), -1, sizeof(mp_limb_t), 0, 0, DATA(F));

   mpz_powm(res.body, gg.body, ee.body, FF.body);

   if (mpz_sgn(res.body) == 0) {
      _kctsb_gzero(h);
      return;
   }

   long sz = mpz_size(res.body);

   _kctsb_gsetlength(h, sz);
   _kctsb_limb_t *hdata = DATA(*h);
   SIZE(*h) = sz;

   mpz_export(hdata, 0, -1, sizeof(mp_limb_t), 0, 0, res.body);
}
#endif


#endif

#define REDC_CROSS (32)

void _kctsb_gpowermod(_kctsb_gbigint g, _kctsb_gbigint e, _kctsb_gbigint F,
                    _kctsb_gbigint *h)

/* h = g^e mod f using "sliding window" algorithm

   remark: the notation (h, g, e, F) is strange, because I
   copied the code from BB.c.
*/

{
 
   
   if (_kctsb_gsign(e) < 0 || _kctsb_gsign(g) < 0 || _kctsb_gcompare(g, F) >= 0 || 
       _kctsb_gscompare(F, 1) <= 0) {
      LogicError("PowerMod: bad args");
   }

   if (ZEROP(e)) {
      _kctsb_gone(h);
      return;
   }

   if (ONEP(e)) {
      _kctsb_gcopy(g, h);
      return;
   }

   if (_kctsb_gscompare(e, 2) == 0) {
      _kctsb_gsqmod(g, F, h);
      return;
   }

   if (ZEROP(g)) {
      _kctsb_gzero(h);
      return;
   }

   long n = _kctsb_g2log(e);

#if (1 && defined(KCTSB_GMP_LIP) && KCTSB_NAIL_BITS == 0)
   if (n > 10) {
      if (SIZE(F) < 6 && SIZE(e) < 10) 
         _kctsb_gmp_powermod_alt(g, e, F, h); 
      else
         _kctsb_gmp_powermod(g, e, F, h);
      return;
   }
#endif

   _kctsb_gbigint_wrapped res, gg, t;
   UniqueArray<_kctsb_gbigint_wrapped> v;

   long i, k, val, cnt, m;
   long use_redc, sF;
   _kctsb_limb_t inv;

   sF = SIZE(F);

   res = 0;
   _kctsb_gsetlength(&res, sF*2);

   t = 0;
   _kctsb_gsetlength(&t, sF*2);

#ifdef KCTSB_GMP_LIP
   // NOTE: GMP has a fast division routine for larger 
   // numbers, so we only use Montgomery for smallish moduli
   use_redc = (DATA(F)[0] & 1) && sF < REDC_CROSS;
#else
   use_redc = (DATA(F)[0] & 1);
#endif

   gg = 0;

   if (use_redc) {
      _kctsb_glshift(g, sF*KCTSB_ZZ_NBITS, &res);
      _kctsb_gmod(res, F, &gg);

      inv = neg_inv_mod_limb(DATA(F)[0]);
   }
   else
      _kctsb_gcopy(g, &gg);


   if (_kctsb_gscompare(g, 2) == 0) {
      /* plain square-and-multiply algorithm, optimized for g == 2 */

      _kctsb_gbigint_wrapped F1;

      if (use_redc) {
         long shamt;

         shamt = COUNT_BITS(DATA(F)[sF-1]);
         shamt = KCTSB_ZZ_NBITS - shamt;
         _kctsb_glshift(F, shamt, &F1);
      }

      _kctsb_gcopy(gg, &res);

      for (i = n - 2; i >= 0; i--) {
         _kctsb_gsq(res, &t);
         if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);

         if (_kctsb_gbit(e, i)) {
            _kctsb_gadd(res, res, &res);

            if (use_redc) {
               while (SIZE(res) > sF) {
                  _kctsb_gsubpos(res, F1, &res);
               }
            }
            else {
               if (_kctsb_gcompare(res, F) >= 0)
                  _kctsb_gsubpos(res, F, &res);
            }
         }
      }


      if (use_redc) {
         _kctsb_gcopy(res, &t);
         redc(t, F, sF, inv, res);
         if (_kctsb_gcompare(res, F) >= 0) {
            _kctsb_gsub(res, F, &res);
         }
      }

      _kctsb_gcopy(res, h);
      return;
   }


   if (n < 16) { 
      /* plain square-and-multiply algorithm */

      _kctsb_gcopy(gg, &res);

      for (i = n - 2; i >= 0; i--) {
         _kctsb_gsq(res, &t);
         if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);

         if (_kctsb_gbit(e, i)) {
            _kctsb_gmul(res, gg, &t);
            if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);
         }
      }


      if (use_redc) {
         _kctsb_gcopy(res, &t);
         redc(t, F, sF, inv, res);
         if (_kctsb_gcompare(res, F) >= 0) {
            _kctsb_gsub(res, F, &res);
         }
      }

      _kctsb_gcopy(res, h);
      return;
   }

   k = OptWinSize(n);

   if (k > 5) k = 5;

   v.SetLength(1L << (k-1));
   for (i = 0; i < (1L << (k-1)); i++) {
      v[i] = 0; 
      _kctsb_gsetlength(&v[i], sF);
   }

   _kctsb_gcopy(gg, &v[0]);
 
   if (k > 1) {
      _kctsb_gsq(gg, &t);
      if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);

      for (i = 1; i < (1L << (k-1)); i++) {
         _kctsb_gmul(v[i-1], res, &t);
         if (use_redc) redc(t, F, sF, inv, v[i]); else _kctsb_gmod(t, F, &v[i]);
      }
   }

   _kctsb_gcopy(gg, &res);

   val = 0;
   for (i = n-2; i >= 0; i--) {
      val = (val << 1) | _kctsb_gbit(e, i); 
      if (val == 0) {
         _kctsb_gsq(res, &t);
         if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);
      }
      else if (val >= (1L << (k-1)) || i == 0) {
         cnt = 0;
         while ((val & 1) == 0) {
            val = val >> 1;
            cnt++;
         }

         m = val;
         while (m > 0) {
            _kctsb_gsq(res, &t);
            if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);
            m = m >> 1;
         }

         _kctsb_gmul(res, v[val >> 1], &t);
         if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);

         while (cnt > 0) {
            _kctsb_gsq(res, &t);
            if (use_redc) redc(t, F, sF, inv, res); else _kctsb_gmod(t, F, &res);
            cnt--;
         }

         val = 0;
      }
   }

   if (use_redc) {
      _kctsb_gcopy(res, &t);
      redc(t, F, sF, inv, res);
      if (_kctsb_gcompare(res, F) >= 0) {
         _kctsb_gsub(res, F, &res);
      }
   }

   _kctsb_gcopy(res, h);
}


long _kctsb_gisone(_kctsb_gbigint rep)
{
   return ONEP(rep); 
}

long _kctsb_gsptest(_kctsb_gbigint rep)
{
   return !rep || SIZE(rep) == 0 ||
          ((SIZE(rep) == 1 || SIZE(rep) == -1) && 
           DATA(rep)[0] < ((_kctsb_limb_t) KCTSB_SP_BOUND));
}

long _kctsb_gwsptest(_kctsb_gbigint rep)
{
   return !rep || SIZE(rep) == 0 ||
          ((SIZE(rep) == 1 || SIZE(rep) == -1) && 
           DATA(rep)[0] < ((_kctsb_limb_t) KCTSB_WSP_BOUND));
}



long _kctsb_gcrtinrange(_kctsb_gbigint g, _kctsb_gbigint a)
{
   long sa, sg, i; 
   _kctsb_limb_t carry, u, v;
   _kctsb_limb_t *adata, *gdata;

   if (!a || SIZE(a) <= 0) return 0;

   sa = SIZE(a);

   if (!g) return 1;

   sg = SIZE(g);

   if (sg == 0) return 1;

   if (sg < 0) sg = -sg;

   if (sa-sg > 1) return 1;

   if (sa-sg < 0) return 0;

   adata = DATA(a);
   gdata = DATA(g);

   carry=0;

   if (sa-sg == 1) {
      if (adata[sa-1] > ((_kctsb_limb_t) 1)) return 1;
      carry = 1;
   }

   i = sg-1;
   u = 0;
   v = 0;
   while (i >= 0 && u == v) {
      u = (carry << (KCTSB_ZZ_NBITS-1)) + (adata[i] >> 1);
      v = gdata[i];
      carry = (adata[i] & 1);
      i--;
   }

   if (u == v) {
      if (carry) return 1;
      return (SIZE(g) > 0);
   }
   else
      return (u > v);
}





#if (KCTSB_NAIL_BITS == 0)

/* DIRT: this routine will not work with non-empty "nails" */
/* and assumes KCTSB_ZZ_NBITS is a multiple of 8 */

#if (KCTSB_ZZ_NBITS % 8 != 0)
#error "assumption that KCTSB_ZZ_NBITS % 8 != 0"
#endif

void _kctsb_gfrombytes(_kctsb_gbigint *x, const unsigned char *p, long n)
{
   long lw, r, i, j;
   _kctsb_limb_t *xp, t;

   while (n > 0 && p[n-1] == 0) n--;
   if (n <= 0) {
      _kctsb_gzero(x);
      return;
   }

   const long BytesPerLimb = KCTSB_ZZ_NBITS/8;


   lw = n/BytesPerLimb;
   r = n - lw*BytesPerLimb;

   if (r != 0) 
      lw++;
   else
      r = BytesPerLimb;

   _kctsb_gsetlength(x, lw); 
   xp = DATA(*x);

   for (i = 0; i < lw-1; i++) {
      t = 0;
      for (j = 0; j < BytesPerLimb; j++) {
         t >>= 8;
         t += (((_kctsb_limb_t)(*p)) & ((_kctsb_limb_t) 255)) << ((BytesPerLimb-1)*8);
         p++;
      }
      xp[i] = t;
   }

   t = 0;
   for (j = 0; j < r; j++) {
      t >>= 8;
      t += (((_kctsb_limb_t)(*p)) & ((_kctsb_limb_t) 255)) << ((BytesPerLimb-1)*8);
      p++;
   }

   t >>= (BytesPerLimb-r)*8;
   xp[lw-1] = t;

   // strip not necessary here
   // STRIP(lw, xp);
   SIZE(*x) = lw; 
}

void _kctsb_gbytesfromz(unsigned char *p, _kctsb_gbigint a, long n)
{
   long lbits, lbytes, min_bytes, min_words, r;
   long i, j;
   _kctsb_limb_t *ap, t;

   if (n < 0) n = 0;

   const long BytesPerLimb = KCTSB_ZZ_NBITS/8;

   lbits = _kctsb_g2log(a);
   lbytes = (lbits+7)/8;

   min_bytes = (lbytes < n) ? lbytes : n;

   min_words = min_bytes/BytesPerLimb;

   r = min_bytes - min_words*BytesPerLimb;
   if (r != 0)
      min_words++;
   else
      r = BytesPerLimb;

   if (a)
      ap = DATA(a);
   else
      ap = 0;


   for (i = 0; i < min_words-1; i++) {
      t = ap[i];
      for (j = 0; j < BytesPerLimb; j++) {
         *p = t & ((_kctsb_limb_t) 255);
         t >>= 8;
         p++;
      }
   }

   if (min_words > 0) {
      t = ap[min_words-1];
      for (j = 0; j < r; j++) {
         *p = t & ((_kctsb_limb_t) 255);
         t >>= 8;
         p++;
      }
   }

   for (j = min_bytes; j < n; j++) {
      *p = 0;
      p++;
   }
}



#else

void _kctsb_gfrombytes(_kctsb_gbigint *x, const unsigned char *p, long n)
{
   long sz;
   long i;
   _kctsb_limb_t *xdata;
   _kctsb_limb_t carry, tmp;

   long bitpos, wordpos, bitoffset, diff;
   long nbits;

   while (n > 0 && p[n-1] == 0) n--;
   if (n <= 0) {
      _kctsb_gzero(x);
      return;
   }

   if (n > (KCTSB_MAX_LONG-(KCTSB_ZZ_NBITS-1))/8)
      ResourceError("ZZFromBytes: excessive length");

   nbits = 0;
   tmp = p[n-1];
   while (tmp) {
      tmp >>= 1;
      nbits++;
   }

   sz = ((n-1)*8 + nbits + KCTSB_ZZ_NBITS-1)/KCTSB_ZZ_NBITS;

   _kctsb_gsetlength(x, sz);

   xdata = DATA(*x);

   for (i = 0; i < sz; i++)
      xdata[i] = 0;

   carry = 0;
   for (i = 0; i < n; i++) {
      bitpos = i*8;
      wordpos = bitpos/KCTSB_ZZ_NBITS;
      bitoffset = bitpos - wordpos*KCTSB_ZZ_NBITS;
      diff = KCTSB_ZZ_NBITS-bitoffset;

      tmp = _kctsb_limb_t(p[i]) & _kctsb_limb_t(255); 

      xdata[wordpos] |= carry | CLIP(tmp << bitoffset);
      carry = tmp >> diff;
   }

   xdata[sz-1] |= carry;
   SIZE(*x) = sz;
}




void _kctsb_gbytesfromz(unsigned char *p, _kctsb_gbigint a, long nn)
{
   long k = _kctsb_g2log(a);
   long n = (k+7)/8;
   long sz = _kctsb_gsize(a);
   long min_n = min(n, nn); 
   _kctsb_limb_t *ap;
   long i;


   if (a)
      ap = DATA(a);
   else
      ap = 0;


   for (i = 0; i < min_n; i++) {
      long bitpos = i*8;
      long wordpos = bitpos/KCTSB_ZZ_NBITS;
      long bitoffset = bitpos - wordpos*KCTSB_ZZ_NBITS;
      long diff;

      p[i] = (ap[wordpos] >> bitoffset) & _kctsb_limb_t(255);

      diff = KCTSB_ZZ_NBITS - bitoffset;

      if (diff < 8 && wordpos < sz-1) {
         _kctsb_limb_t msk = (_kctsb_limb_t(1) << (8-diff))-_kctsb_limb_t(1);
         p[i] |= ((ap[wordpos+1] & msk) << diff);
      }
   }

   for (i = min_n; i < nn; i++)
      p[i] = 0;
}


#endif





long _kctsb_gblock_construct_alloc(_kctsb_gbigint *x, long d, long n)
{
   long d1, sz, AllocAmt, m, j, alloc;
   char *p;
   _kctsb_gbigint t;


   /* check n value */

   if (n <= 0)
      LogicError("block construct: n must be positive");



   /* check d value */

   if (d <= 0)
      LogicError("block construct: d must be positive");

   if (KCTSB_OVERFLOW(d, KCTSB_ZZ_NBITS, KCTSB_ZZ_NBITS))
      ResourceError("block construct: d too large");

   d1 = d + 1;

#ifdef KCTSB_SMALL_MP_SIZE_T
   /* this makes sure that numbers don't get too big for GMP */
   if (d1 >= (1L << (KCTSB_BITS_PER_INT-4)))
      ResourceError("size too big for GMP");
#endif


   if (STORAGE_OVF(d1))
      ResourceError("block construct: d too large");



   sz = STORAGE(d1);

   AllocAmt = KCTSB_MAX_ALLOC_BLOCK/sz;
   if (AllocAmt == 0) AllocAmt = 1;

   if (AllocAmt < n)
      m = AllocAmt;
   else
      m = n;

   p = (char *) KCTSB_SNS_MALLOC(m, sz, 0);
   if (!p) MemoryError();

   *x = (_kctsb_gbigint) p;

   for (j = 0; j < m; j++) {
      t = (_kctsb_gbigint) p;
      alloc = (d1 << 2) | 1;
      if (j < m-1) alloc |= 2;
      ALLOC(t) = alloc;
      SIZE(t) = 0;
      p += sz;
   }

   return m;
}


void _kctsb_gblock_construct_set(_kctsb_gbigint x, _kctsb_gbigint *y, long i)
{
   long d1, sz;


   d1 = ALLOC(x) >> 2;
   sz = STORAGE(d1);

   *y = (_kctsb_gbigint) (((char *) x) + i*sz);
}


long _kctsb_gblock_destroy(_kctsb_gbigint x)
{
   long d1, sz, alloc, m;
   char *p;
   _kctsb_gbigint t;

   
   d1 = ALLOC(x) >> 2;
   sz = STORAGE(d1);

   p = (char *) x;

   m = 1;

   for (;;) {
      t = (_kctsb_gbigint) p;
      alloc = ALLOC(t);

      // NOTE: this must not throw 
      if ((alloc & 1) == 0) 
         TerminalError("corrupted memory detected in _kctsb_gblock_destroy");

      if ((alloc & 2) == 0) break;
      m++;
      p += sz;
   }

   free(x);
   return m;
}


long _kctsb_gblock_storage(long d)
{
   long d1, sz; 

   d1 = d + 1;
   sz = STORAGE(d1) + sizeof(_kctsb_gbigint);

   return sz;
}



static
long SpecialPower(long e, long p)
{
   long a;
   long x, y;

   a = (long) ((((_kctsb_limb_t) 1) << (KCTSB_ZZ_NBITS-2)) % ((_kctsb_limb_t) p));
   a = MulMod(a, 2, p);
   a = MulMod(a, 2, p);

   x = 1;
   y = a;
   while (e) {
      if (e & 1) x = MulMod(x, y, p);
      y = MulMod(y, y, p);
      e = e >> 1;
   }

   return x;
}


static
void sp_ext_eucl(long *dd, long *ss, long *tt, long a, long b)
{
   long  u, v, u0, v0, u1, v1, u2, v2, q, r;

   long aneg = 0, bneg = 0;

   if (a < 0) {
      if (a < -KCTSB_MAX_LONG) ResourceError("integer overflow");
      a = -a;
      aneg = 1;
   }

   if (b < 0) {
      if (b < -KCTSB_MAX_LONG) ResourceError("integer overflow");
      b = -b;
      bneg = 1;
   }

   u1=1; v1=0;
   u2=0; v2=1;
   u = a; v = b;

   while (v != 0) {
      q = u / v;
      r = u % v;
      u = v;
      v = r;
      u0 = u2;
      v0 = v2;
      u2 =  u1 - q*u2;
      v2 = v1- q*v2;
      u1 = u0;
      v1 = v0;
   }

   if (aneg)
      u1 = -u1;

   if (bneg)
      v1 = -v1;

   *dd = u;
   *ss = u1;
   *tt = v1;
}

static
long sp_inv_mod(long a, long n)
{
   long d, s, t;

   sp_ext_eucl(&d, &s, &t, a, n);
   if (d != 1) ArithmeticError("inverse undefined");
   if (s < 0)
      return s + n;
   else
      return s;
}




class _kctsb_tmp_vec_crt_fast : public  _kctsb_tmp_vec {
public:
   UniqueArray<_kctsb_gbigint_wrapped> rem_vec;
   UniqueArray<_kctsb_gbigint_wrapped> temps;
   UniqueArray<long> val_vec;

};


class _kctsb_crt_struct_basic : public _kctsb_crt_struct {
public:
   UniqueArray<_kctsb_gbigint_wrapped> v;
   long sbuf;
   long n;

   bool special();
   void insert(long i, _kctsb_gbigint m);
   _kctsb_tmp_vec *extract();
   _kctsb_tmp_vec *fetch();
   void eval(_kctsb_gbigint *x, const long *b, _kctsb_tmp_vec *tmp_vec);
};


#if (defined(KCTSB_TBL_CRT))

class _kctsb_crt_struct_tbl : public _kctsb_crt_struct {
public:
   Unique2DArray<_kctsb_limb_t> v;
   long n;
   long sz;

   bool special();
   void insert(long i, _kctsb_gbigint m);
   _kctsb_tmp_vec *extract();
   _kctsb_tmp_vec *fetch();
   void eval(_kctsb_gbigint *x, const long *b, _kctsb_tmp_vec *tmp_vec);

};

#endif




class _kctsb_crt_struct_fast : public _kctsb_crt_struct {
public:
   long n;
   long levels;
   UniqueArray<long> primes;
   UniqueArray<long> inv_vec;
   UniqueArray<long> index_vec;
   UniqueArray<_kctsb_gbigint_wrapped> prod_vec;
   UniqueArray<_kctsb_gbigint_wrapped> coeff_vec;
   _kctsb_gbigint_wrapped modulus;
   UniquePtr<_kctsb_tmp_vec_crt_fast> stored_tmp_vec;

   bool special();
   void insert(long i, _kctsb_gbigint m);
   _kctsb_tmp_vec *extract();
   _kctsb_tmp_vec *fetch();
   void eval(_kctsb_gbigint *x, const long *b, _kctsb_tmp_vec *tmp_vec);
};






#define GCRT_TMPS (2)


_kctsb_crt_struct * 
_kctsb_crt_struct_build(long n, _kctsb_gbigint p, long (*primes)(long))
{
#ifdef KCTSB_GMP_LIP
   if (n > 800)
#else
   if (0)
   // NOTE: without GMP, this does not seem to help
#endif
   {
      UniqueArray<long> q;
      UniqueArray<long> inv_vec;
      UniqueArray<long> index_vec;
      UniqueArray<_kctsb_gbigint_wrapped> prod_vec, rem_vec, coeff_vec;
      UniqueArray<_kctsb_gbigint_wrapped> temps;

      long i, j;
      long levels, vec_len;

      levels = 0;
      while ((n >> levels) >= 16) levels++;
      vec_len = (1L << levels) - 1;

      temps.SetLength(GCRT_TMPS);
      rem_vec.SetLength(vec_len);

      q.SetLength(n);
      for (i = 0; i < n; i++)
         q[i] = primes(i);

      inv_vec.SetLength(n);


      index_vec.SetLength(vec_len+1);
      prod_vec.SetLength(vec_len);
      coeff_vec.SetLength(n);

      index_vec[0] = 0;
      index_vec[1] = n;

      for (i = 0; i <= levels-2; i++) {
         long start = (1L << i) - 1;
         long finish = (1L << (i+1)) - 2;
         for (j = finish; j >= start; j--) {
            index_vec[2*j+2] = index_vec[j] + (index_vec[j+1] - index_vec[j])/2;
            index_vec[2*j+1] = index_vec[j];
         }
         index_vec[2*finish+3] = n;
      }

      for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
         /* multiply primes index_vec[i]..index_vec[i+1]-1 into 
          * prod_vec[i]
          */

         _kctsb_gone(&prod_vec[i]);
         for (j = index_vec[i]; j < index_vec[i+1]; j++)
            _kctsb_gsmul(prod_vec[i], q[j], &prod_vec[i]);
      }

      for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
         for (j = index_vec[i]; j < index_vec[i+1]; j++)
            _kctsb_gsdiv(prod_vec[i], q[j], &coeff_vec[j]);
      }

      for (i = (1L << (levels-1)) - 2; i >= 0; i--)
         _kctsb_gmul(prod_vec[2*i+1], prod_vec[2*i+2], &prod_vec[i]);

     /*** new asymptotically fast code to compute inv_vec ***/

      _kctsb_gone(&rem_vec[0]);
      for (i = 0; i < (1L << (levels-1)) - 1; i++) {
         _kctsb_gmod(rem_vec[i], prod_vec[2*i+1], &temps[0]);
         _kctsb_gmul(temps[0], prod_vec[2*i+2], &temps[1]);
         _kctsb_gmod(temps[1], prod_vec[2*i+1], &rem_vec[2*i+1]);

         _kctsb_gmod(rem_vec[i], prod_vec[2*i+2], &temps[0]);
         _kctsb_gmul(temps[0], prod_vec[2*i+1], &temps[1]);
         _kctsb_gmod(temps[1], prod_vec[2*i+2], &rem_vec[2*i+2]);
      }

      for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
         for (j = index_vec[i]; j < index_vec[i+1]; j++) {
            long tt, tt1, tt2;
            _kctsb_gsdiv(prod_vec[i], q[j], &temps[0]);
            tt = _kctsb_gsmod(temps[0], q[j]);
            tt1 = _kctsb_gsmod(rem_vec[i], q[j]);
            tt2 = MulMod(tt, tt1, q[j]);
            inv_vec[j] = sp_inv_mod(tt2, q[j]);
         }
      }


      UniquePtr<_kctsb_crt_struct_fast> C;
      C.make();

      C->n = n;
      C->primes.move(q);
      C->inv_vec.move(inv_vec);
      C->levels = levels;
      C->index_vec.move(index_vec);
      C->prod_vec.move(prod_vec);
      C->coeff_vec.move(coeff_vec);

      _kctsb_gcopy(p, &C->modulus);

      C->stored_tmp_vec.make();
      C->stored_tmp_vec->rem_vec.move(rem_vec);
      C->stored_tmp_vec->temps.move(temps);
      C->stored_tmp_vec->val_vec.SetLength(n);

      return C.release();
   }


#if (defined(KCTSB_TBL_CRT))

// assert: defined(KCTSB_CRT_ALTCODE) ||  defined(KCTSB_CRT_ALTCODE_SMALL)
// we use the alternative CRT code, either unconditionally,
// or only for small moduli.

#if (!defined(KCTSB_CRT_ALTCODE)) 
   if (n <= 16)
#endif
   {
      UniquePtr<_kctsb_crt_struct_tbl> C;
      C.make();
      C->n = n;
      C->sz = SIZE(p);
      C->v.SetDims(C->sz, C->n);

      return C.release();
   }
#endif

// as a fallback, we use the basic CRT code

   {
      UniquePtr<_kctsb_crt_struct_basic> C;
      C.make();


      C->n = n;
      C->v.SetLength(n);
      C->sbuf = SIZE(p)+2;

      return C.release();
   }

}

/* extracts existing tmp_vec, if possible -- read/write operation */

_kctsb_tmp_vec *_kctsb_crt_struct_basic::extract()
{
   return 0;
}

#if (defined(KCTSB_TBL_CRT))
_kctsb_tmp_vec *_kctsb_crt_struct_tbl::extract()
{
   return 0;
}
#endif

_kctsb_tmp_vec *_kctsb_crt_struct_fast::extract()
{
   if (stored_tmp_vec) 
      return stored_tmp_vec.release();
   else
      return fetch();
}


/* read only operation */

_kctsb_tmp_vec *_kctsb_crt_struct_basic::fetch()
{
   return 0;
}

#if (defined(KCTSB_TBL_CRT))
_kctsb_tmp_vec *_kctsb_crt_struct_tbl::fetch()
{
   return 0;
}
#endif

_kctsb_tmp_vec *_kctsb_crt_struct_fast::fetch()
{
   long vec_len = (1L << levels) - 1;

   UniquePtr<_kctsb_tmp_vec_crt_fast> res;
   res.make();
   res->temps.SetLength(GCRT_TMPS);
   res->rem_vec.SetLength(vec_len);
   res->val_vec.SetLength(n);

   return res.release();
}


void _kctsb_crt_struct_basic::insert(long i, _kctsb_gbigint m)
{
   _kctsb_gcopy(m, &v[i]);
}

#if (defined(KCTSB_TBL_CRT))
void _kctsb_crt_struct_tbl::insert(long i, _kctsb_gbigint m)
{
   if (i < 0 || i >= n) LogicError("insert: bad args");

   if (!m) 
      for (long j = 0; j < sz; j++) v[j][i] = 0;
   else {
      long sm = SIZE(m);
      if (sm < 0 || sm > sz) LogicError("insert: bad args");
      const _kctsb_limb_t *mdata = DATA(m);
      for (long j = 0; j < sm; j++) 
         v[j][i] = mdata[j];
      for (long j = sm; j < sz; j++)
         v[j][i] = 0;
   }
}
#endif

void _kctsb_crt_struct_fast::insert(long i, _kctsb_gbigint m)
{
   LogicError("insert called improperly");
}


void _kctsb_crt_struct_basic::eval(_kctsb_gbigint *x, const long *b, _kctsb_tmp_vec *generic_tmp_vec)
{
   _kctsb_limb_t *xx, *yy; 
   _kctsb_gbigint x1;
   long i, sx;
   long sy;
   _kctsb_limb_t carry;

   sx = sbuf;
   _kctsb_gsetlength(x, sx);
   x1 = *x;
   xx = DATA(x1);

   for (i = 0; i < sx; i++)
      xx[i] = 0;

   for (i = 0; i < n; i++) {
      if (!v[i]) continue;

      yy = DATA(v[i]);
      sy = SIZE(v[i]); 

      if (!sy || !b[i]) continue;

      carry = KCTSB_MPN(addmul_1)(xx, yy, sy, b[i]);
      yy = xx + sy;
      *yy = CLIP(*yy + carry);

      if (*yy < carry) { /* unsigned comparison! */
         do {
            yy++;
            *yy = CLIP(*yy + 1);
         } while (*yy == 0);
      }
   }

   STRIP(sx, xx);
   SIZE(x1) = sx;
}


#if (defined(KCTSB_TBL_CRT))

#define CRT_ALTCODE_UNROLL (1)

void _kctsb_crt_struct_tbl::eval(_kctsb_gbigint *x, const long *b, _kctsb_tmp_vec *generic_tmp_vec)
{
   long sx;
   _kctsb_gbigint x1;
   long i, j;

   // quick test for zero vector
   // most likely, they are either all zero (if we are working 
   // with some sparse polynomials) or none of them are zero,
   // so in the general case, this should go fast
   if (!b[0]) {
      i = 1;
      while (i < n && !b[i]) i++;
      if (i >= n) {
         _kctsb_gzero(x);
         return;
      }
   }

   sx = sz + 2;
   _kctsb_gsetlength(x, sx);
   x1 = *x;
   _kctsb_limb_t * KCTSB_RESTRICT xx = DATA(x1);


   const long Bnd = 1L << (KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS);

   if (n <= Bnd) {
      _kctsb_limb_t carry=0;

      for (i = 0; i < sz; i++) {
         const _kctsb_limb_t *row = v[i];

         ll_type acc;
         ll_mul(acc, row[0], b[0]);

#if (CRT_ALTCODE_UNROLL && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS == 4)
         switch (n) {
         case 16: ll_mul_add(acc, row[16-1], b[16-1]);
         case 15: ll_mul_add(acc, row[15-1], b[15-1]);
         case 14: ll_mul_add(acc, row[14-1], b[14-1]);
         case 13: ll_mul_add(acc, row[13-1], b[13-1]);
         case 12: ll_mul_add(acc, row[12-1], b[12-1]);
         case 11: ll_mul_add(acc, row[11-1], b[11-1]);
         case 10: ll_mul_add(acc, row[10-1], b[10-1]);
         case 9: ll_mul_add(acc, row[9-1], b[9-1]);
         case 8: ll_mul_add(acc, row[8-1], b[8-1]);
         case 7: ll_mul_add(acc, row[7-1], b[7-1]);
         case 6: ll_mul_add(acc, row[6-1], b[6-1]);
         case 5: ll_mul_add(acc, row[5-1], b[5-1]);
         case 4: ll_mul_add(acc, row[4-1], b[4-1]);
         case 3: ll_mul_add(acc, row[3-1], b[3-1]);
         case 2: ll_mul_add(acc, row[2-1], b[2-1]);
         }
#elif (CRT_ALTCODE_UNROLL)
         long j = n;
         for (; j > 16; j -= 16) {
            ll_mul_add(acc, row[j-1], b[j-1]);
            ll_mul_add(acc, row[j-2], b[j-2]);
            ll_mul_add(acc, row[j-3], b[j-3]);
            ll_mul_add(acc, row[j-4], b[j-4]);
            ll_mul_add(acc, row[j-5], b[j-5]);
            ll_mul_add(acc, row[j-6], b[j-6]);
            ll_mul_add(acc, row[j-7], b[j-7]);
            ll_mul_add(acc, row[j-8], b[j-8]);
            ll_mul_add(acc, row[j-9], b[j-9]);
            ll_mul_add(acc, row[j-10], b[j-10]);
            ll_mul_add(acc, row[j-11], b[j-11]);
            ll_mul_add(acc, row[j-12], b[j-12]);
            ll_mul_add(acc, row[j-13], b[j-13]);
            ll_mul_add(acc, row[j-14], b[j-14]);
            ll_mul_add(acc, row[j-15], b[j-15]);
            ll_mul_add(acc, row[j-16], b[j-16]);
         }
         switch (j) {
         case 16:  ll_mul_add(acc, row[16-1], b[16-1]);
         case 15:  ll_mul_add(acc, row[15-1], b[15-1]);
         case 14:  ll_mul_add(acc, row[14-1], b[14-1]);
         case 13:  ll_mul_add(acc, row[13-1], b[13-1]);
         case 12:  ll_mul_add(acc, row[12-1], b[12-1]);
         case 11:  ll_mul_add(acc, row[11-1], b[11-1]);
         case 10:  ll_mul_add(acc, row[10-1], b[10-1]);
         case 9:  ll_mul_add(acc, row[9-1], b[9-1]);
         case 8:  ll_mul_add(acc, row[8-1], b[8-1]);
         case 7:  ll_mul_add(acc, row[7-1], b[7-1]);
         case 6:  ll_mul_add(acc, row[6-1], b[6-1]);
         case 5:  ll_mul_add(acc, row[5-1], b[5-1]);
         case 4:  ll_mul_add(acc, row[4-1], b[4-1]);
         case 3:  ll_mul_add(acc, row[3-1], b[3-1]);
         case 2:  ll_mul_add(acc, row[2-1], b[2-1]);
         }

#else
         for (j = 1; j < n; j++) 
            ll_mul_add(acc, row[j], b[j]);
#endif

         ll_add(acc, carry);
         xx[i] = ll_get_lo(acc);
         carry = ll_get_hi(acc);
      }

      xx[sz] = carry;
      xx[sz+1] = 0;
   }
   else {
      ll_type carry;
      ll_init(carry, 0);

      for (i = 0; i < sz; i++) {
         const _kctsb_limb_t *row = v[i];

         ll_type acc21;
         _kctsb_limb_t acc0;

         {
            ll_type sum;
            ll_mul(sum, row[0], b[0]);

#if (CRT_ALTCODE_UNROLL && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS == 4)
            ll_mul_add(sum, row[1], b[1]);
            ll_mul_add(sum, row[2], b[2]);
            ll_mul_add(sum, row[3], b[3]);
            ll_mul_add(sum, row[4], b[4]);
            ll_mul_add(sum, row[5], b[5]);
            ll_mul_add(sum, row[6], b[6]);
            ll_mul_add(sum, row[7], b[7]);
            ll_mul_add(sum, row[8], b[8]);
            ll_mul_add(sum, row[9], b[9]);
            ll_mul_add(sum, row[10], b[10]);
            ll_mul_add(sum, row[11], b[11]);
            ll_mul_add(sum, row[12], b[12]);
            ll_mul_add(sum, row[13], b[13]);
            ll_mul_add(sum, row[14], b[14]);
            ll_mul_add(sum, row[15], b[15]);
#elif (CRT_ALTCODE_UNROLL && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS == 2)
            ll_mul_add(sum, row[1], b[1]);
            ll_mul_add(sum, row[2], b[2]);
            ll_mul_add(sum, row[3], b[3]);
#else
            for (j = 1; j < Bnd; j++)
               ll_mul_add(sum, row[j], b[j]);
#endif

       
            ll_init(acc21, ll_get_hi(sum));
            acc0 = ll_get_lo(sum);
         }

         const _kctsb_limb_t *ap = row;
         const long *tp = b;

#if (CRT_ALTCODE_UNROLL && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS == 2)
         long m = n - 4;
         ap += 4;
         tp += 4;

         for (; m >= 8; m -= 8, ap += 8, tp += 8) {
            {
               ll_type sum;
               ll_mul(sum, ap[0], tp[0]);
               ll_mul_add(sum, ap[1], tp[1]);
               ll_mul_add(sum, ap[2], tp[2]);
               ll_mul_add(sum, ap[3], tp[3]);

               ll_add(sum, acc0);
               acc0 = ll_get_lo(sum);
               ll_add(acc21, ll_get_hi(sum));
            }
            {
               ll_type sum;
               ll_mul(sum, ap[4+0], tp[4+0]);
               ll_mul_add(sum, ap[4+1], tp[4+1]);
               ll_mul_add(sum, ap[4+2], tp[4+2]);
               ll_mul_add(sum, ap[4+3], tp[4+3]);

               ll_add(sum, acc0);
               acc0 = ll_get_lo(sum);
               ll_add(acc21, ll_get_hi(sum));
            }
         }

         for (; m >= 4; m -= 4, ap += 4, tp += 4) {
	    ll_type sum;
	    ll_mul(sum, ap[0], tp[0]);
            ll_mul_add(sum, ap[1], tp[1]);
            ll_mul_add(sum, ap[2], tp[2]);
            ll_mul_add(sum, ap[3], tp[3]);

	    ll_add(sum, acc0);
	    acc0 = ll_get_lo(sum);
	    ll_add(acc21, ll_get_hi(sum));
         }


#else
         long m;
         for (m = n-Bnd, ap += Bnd, tp += Bnd; m >= Bnd; m -= Bnd, ap += Bnd, tp += Bnd) {

	    ll_type sum;
	    ll_mul(sum, ap[0], tp[0]);

#if (CRT_ALTCODE_UNROLL && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS == 4)
            ll_mul_add(sum, ap[1], tp[1]);
            ll_mul_add(sum, ap[2], tp[2]);
            ll_mul_add(sum, ap[3], tp[3]);
            ll_mul_add(sum, ap[4], tp[4]);
            ll_mul_add(sum, ap[5], tp[5]);
            ll_mul_add(sum, ap[6], tp[6]);
            ll_mul_add(sum, ap[7], tp[7]);
            ll_mul_add(sum, ap[8], tp[8]);
            ll_mul_add(sum, ap[9], tp[9]);
            ll_mul_add(sum, ap[10], tp[10]);
            ll_mul_add(sum, ap[11], tp[11]);
            ll_mul_add(sum, ap[12], tp[12]);
            ll_mul_add(sum, ap[13], tp[13]);
            ll_mul_add(sum, ap[14], tp[14]);
            ll_mul_add(sum, ap[15], tp[15]);
#else
            for (long j = 1; j < Bnd; j++)
               ll_mul_add(sum, ap[j], tp[j]);
#endif

	    ll_add(sum, acc0);
	    acc0 = ll_get_lo(sum);
	    ll_add(acc21, ll_get_hi(sum));
         }
#endif

         if (m > 0) {
	    ll_type sum;
	    ll_mul(sum, ap[0], tp[0]);

#if (CRT_ALTCODE_UNROLL && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS == 4)
            switch (m) {
            case 15:  ll_mul_add(sum, ap[15-1], tp[15-1]);
            case 14:  ll_mul_add(sum, ap[14-1], tp[14-1]);
            case 13:  ll_mul_add(sum, ap[13-1], tp[13-1]);
            case 12:  ll_mul_add(sum, ap[12-1], tp[12-1]);
            case 11:  ll_mul_add(sum, ap[11-1], tp[11-1]);
            case 10:  ll_mul_add(sum, ap[10-1], tp[10-1]);
            case 9:  ll_mul_add(sum, ap[9-1], tp[9-1]);
            case 8:  ll_mul_add(sum, ap[8-1], tp[8-1]);
            case 7:  ll_mul_add(sum, ap[7-1], tp[7-1]);
            case 6:  ll_mul_add(sum, ap[6-1], tp[6-1]);
            case 5:  ll_mul_add(sum, ap[5-1], tp[5-1]);
            case 4:  ll_mul_add(sum, ap[4-1], tp[4-1]);
            case 3:  ll_mul_add(sum, ap[3-1], tp[3-1]);
            case 2:  ll_mul_add(sum, ap[2-1], tp[2-1]);
            }
#else
            for (m--, ap++, tp++; m > 0; m--, ap++, tp++)
               ll_mul_add(sum, ap[0], tp[0]);
#endif
	    ll_add(sum, acc0);
	    acc0 = ll_get_lo(sum);
	    ll_add(acc21, ll_get_hi(sum));

         }

         ll_add(carry, acc0);
         xx[i] = ll_get_lo(carry);
         ll_add(acc21, ll_get_hi(carry));
         carry = acc21;
      }

      xx[sz] = ll_get_lo(carry);
      xx[sz+1] = ll_get_hi(carry);
   }


   STRIP(sx, xx);
   SIZE(x1) = sx;
}
#endif

static
void gadd_mul_many(_kctsb_gbigint *res, _kctsb_gbigint *a, long *b, 
                      long n, long sz)

{
   _kctsb_limb_t *xx, *yy; 
   long i, sx;
   long sy;
   _kctsb_limb_t carry;

   sx = sz + 2;
   if (MustAlloc(*res, sx))
      _kctsb_gsetlength(res, sx);

   xx = DATA(*res);

   for (i = 0; i < sx; i++)
      xx[i] = 0;

   for (i = 0; i < n; i++) {
      if (!a[i]) continue;

      yy = DATA(a[i]);
      sy = SIZE(a[i]); 

      if (!sy || !b[i]) continue;

      carry = KCTSB_MPN(addmul_1)(xx, yy, sy, b[i]);
      yy = xx + sy;
      *yy = CLIP(*yy + carry);

      if (*yy < carry) { /* unsigned comparison! */
         do {
            yy++;
            *yy = CLIP(*yy + 1);
         } while (*yy == 0);
      }
   }

   STRIP(sx, xx);
   SIZE(*res) = sx;
}

void _kctsb_crt_struct_fast::eval(_kctsb_gbigint *x, const long *b, _kctsb_tmp_vec *generic_tmp_vec)
{
   _kctsb_tmp_vec_crt_fast *tmp_vec = static_cast<_kctsb_tmp_vec_crt_fast*> (generic_tmp_vec);

   long *val_vec = tmp_vec->val_vec.get();
   _kctsb_gbigint_wrapped *temps = tmp_vec->temps.get();
   _kctsb_gbigint_wrapped *rem_vec = tmp_vec->rem_vec.get();

   long vec_len = (1L << levels) - 1;

   long i;

   for (i = 0; i < n; i++) {
      val_vec[i] = MulMod(b[i], inv_vec[i], primes[i]);
   }

   for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
      long j1 = index_vec[i];
      long j2 = index_vec[i+1];
      gadd_mul_many(&rem_vec[i], &coeff_vec[j1], &val_vec[j1], j2-j1, 
                       SIZE(prod_vec[i]));
   }

   for (i = (1L << (levels-1)) - 2; i >= 0; i--) {
      _kctsb_gmul(prod_vec[2*i+1], rem_vec[2*i+2], &temps[0]);
      _kctsb_gmul(rem_vec[2*i+1], prod_vec[2*i+2], &temps[1]);
      _kctsb_gadd(temps[0], temps[1], &rem_vec[i]);
   }

   /* temps[0] = rem_vec[0] mod prod_vec[0] (least absolute residue) */
   _kctsb_gmod(rem_vec[0], prod_vec[0], &temps[0]);
   _kctsb_gsub(temps[0], prod_vec[0], &temps[1]);
   _kctsb_gnegate(&temps[1]);
   if (_kctsb_gcompare(temps[0], temps[1]) > 0) {
      _kctsb_gnegate(&temps[1]);
      _kctsb_gcopy(temps[1], &temps[0]);
   }

   _kctsb_gmod(temps[0], modulus, &temps[1]);
   _kctsb_gcopy(temps[1], x);
}


bool _kctsb_crt_struct_basic::special()  { return false; }

#if (defined(KCTSB_TBL_CRT))
bool _kctsb_crt_struct_tbl::special()  { return false; }
#endif


bool _kctsb_crt_struct_fast::special()   { return true; }



// ************** rem code


#ifdef KCTSB_HAVE_LL_TYPE

// This is the same logic as in sp_arith.h, but assumes 
// NumBits(d) == KCTSB_SP_NBITS


static inline
unsigned long tbl_red_inv(long d)
{
   return (unsigned long) ( ((_kctsb_ulonglong(1) << (KCTSB_SP_NBITS+KCTSB_BITS_PER_LONG))-1UL) / _kctsb_ulonglong(d) );
}

// assumes hi < d
static inline 
long tbl_red_21(unsigned long hi, unsigned long lo, long d, unsigned long dinv)
{
   unsigned long H = (hi << (KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS)) | (lo >> KCTSB_SP_NBITS);
   unsigned long Q = ll_mul_hi(H, dinv) + H;
   unsigned long rr = lo - Q*cast_unsigned(d); // rr in [0..4*d)
   long r = sp_CorrectExcess(rr, 2*d); // r in [0..2*d)
   r = sp_CorrectExcess(r, d);
   return r;
}


// assumes x2 < d
static inline
unsigned long tbl_red_31(unsigned long x2, unsigned long x1, unsigned long x0,
                     long d, unsigned long dinv)
{
   long carry = tbl_red_21(x2, x1, d, dinv);
   return tbl_red_21(carry, x0, d, dinv);
}

#endif


class _kctsb_tmp_vec_rem_impl : public  _kctsb_tmp_vec {
public:
   UniqueArray<_kctsb_gbigint_wrapped> rem_vec;
};






class _kctsb_rem_struct_basic : public _kctsb_rem_struct {
public:
   long n;
   UniqueArray<long> primes;

   void eval(long *x, _kctsb_gbigint a, _kctsb_tmp_vec *tmp_vec);
   _kctsb_tmp_vec *fetch();
};


class _kctsb_rem_struct_fast : public _kctsb_rem_struct {
public:
   long n;
   long levels;
   UniqueArray<long> primes;
   UniqueArray<long> index_vec;
   UniqueArray<_kctsb_gbigint_wrapped> prod_vec;
   long modulus_size;

   void eval(long *x, _kctsb_gbigint a, _kctsb_tmp_vec *tmp_vec);
   _kctsb_tmp_vec *fetch();
};


class _kctsb_rem_struct_medium : public _kctsb_rem_struct {
public:
   long n;
   long levels;
   UniqueArray<long> primes;
   UniqueArray<long> index_vec;
   UniqueArray<long> len_vec;
   UniqueArray<_kctsb_limb_t> inv_vec;
   UniqueArray<long> corr_vec;
   UniqueArray<mulmod_precon_t> corraux_vec;
   UniqueArray<_kctsb_gbigint_wrapped> prod_vec;

   void eval(long *x, _kctsb_gbigint a, _kctsb_tmp_vec *tmp_vec);
   _kctsb_tmp_vec *fetch();
};



#ifdef KCTSB_TBL_REM


#define KCTSB_GAP_BITS (2*KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS-KCTSB_ZZ_NBITS)

// NOTE: do not allow KCTSB_GAP_BITS to exceed 28.
// This is largely academic, but it avoids some potential
// integer overflow issues.
#if (KCTSB_GAP_BITS > 28)
#undef KCTSB_GAP_BITS
#define KCTSB_GAP_BITS (28)
#endif


class _kctsb_rem_struct_tbl : public _kctsb_rem_struct {
public:
   long n;
   UniqueArray<long> primes;
   UniqueArray<_kctsb_limb_t> inv_primes;
   Unique2DArray<_kctsb_limb_t> tbl;

   void eval(long *x, _kctsb_gbigint a, _kctsb_tmp_vec *tmp_vec);
   _kctsb_tmp_vec *fetch();

};

#endif



_kctsb_rem_struct *_kctsb_rem_struct_build(long n, _kctsb_gbigint modulus, long (*p)(long))
{

#ifdef KCTSB_TBL_REM

// FIXME: I should incorporate the logic from _kctsb_general_rem_one_struct_apply
// to keep the table sizes smaller

#ifdef KCTSB_GMP_LIP
   if (n <= 800) 
#else
   if (1) 
   // NOTE: without GMP, this is always the fastest
#endif
   {
      UniqueArray<long> q;
      UniqueArray<_kctsb_limb_t> inv_primes;
      Unique2DArray<_kctsb_limb_t> tbl;
      long i, j;
      long qq, t, t1;
      long sz = SIZE(modulus);

      q.SetLength(n);
      for (i = 0; i < n; i++)
         q[i] = p(i);

      inv_primes.SetLength(n);
      for (i = 0; i < n; i++) 
         inv_primes[i] = tbl_red_inv(q[i]);

      tbl.SetDims(n, sz);

      for (i = 0; i < n; i++) {
         qq = q[i];
         t = 1;
         for (j = 0; j < KCTSB_ZZ_NBITS; j++) {
            t += t;
            if (t >= qq) t -= qq;
         }
         t1 = 1;
         tbl[i][0] = 1;
         for (j = 1; j < sz; j++) {
            t1 = MulMod(t1, t, qq);
            tbl[i][j] = t1;
         }
      }

      UniquePtr<_kctsb_rem_struct_tbl> R;
      R.make();
 
      R->n = n;
      R->primes.move(q);
      R->inv_primes.move(inv_primes);
      R->tbl.move(tbl);

      return R.release();
   }
#endif

#ifdef KCTSB_GMP_LIP
   if (0)
   // NOTE: this does not seem useful with GMP
#else
   if (n > 600)
   // NOTE: this seems to be useful without GMP, but only if TBL_REM
   // does not work
#endif
   {

      UniqueArray<long> q;
      long i, j;
      long levels, vec_len;
      UniqueArray<long> index_vec;
      UniqueArray<long> len_vec, corr_vec;
      UniqueArray<mulmod_precon_t> corraux_vec;
      UniqueArray<_kctsb_limb_t> inv_vec;
      UniqueArray<_kctsb_gbigint_wrapped> prod_vec;

   
      q.SetLength(n);
      for (i = 0; i < n; i++)
         q[i] = p(i);

      levels = 0;
      while ((n >> levels) >= 4) levels++;

      vec_len = (1L << levels) - 1;

      index_vec.SetLength(vec_len+1);
      len_vec.SetLength(vec_len);
      inv_vec.SetLength(vec_len);

      corr_vec.SetLength(n);
      corraux_vec.SetLength(n);

      prod_vec.SetLength(vec_len);

      index_vec[0] = 0;
      index_vec[1] = n;

      for (i = 0; i <= levels-2; i++) {
         long start = (1L << i) - 1;
         long finish = (1L << (i+1)) - 2;
         for (j = finish; j >= start; j--) {
            index_vec[2*j+2] = index_vec[j] + (index_vec[j+1] - index_vec[j])/2;
            index_vec[2*j+1] = index_vec[j];
         }
         index_vec[2*finish+3] = n;
      }

      for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
         /* multiply primes index_vec[i]..index_vec[i+1]-1 into 
          * prod_vec[i]
          */

         _kctsb_gone(&prod_vec[i]);
         for (j = index_vec[i]; j < index_vec[i+1]; j++)
            _kctsb_gsmul(prod_vec[i], q[j], &prod_vec[i]); 
      }

      for (i = (1L << (levels-1)) - 2; i >= 3; i--)
         _kctsb_gmul(prod_vec[2*i+1], prod_vec[2*i+2], &prod_vec[i]);

      
      for (i = 3; i < vec_len; i++)
         len_vec[i] = _kctsb_gsize(prod_vec[i]);

      /* Set len_vec[1] = len_vec[2] = 
       *    max(_kctsb_gsize(modulus), len_vec[3..6]).
       * This is a bit paranoid, but it makes the code
       * more robust. */

      j = _kctsb_gsize(modulus);
      for (i = 3; i <= 6; i++)
         if (len_vec[i] > j) j = len_vec[i];

      len_vec[1] = len_vec[2] = j;

      for (i = 3; i < vec_len; i++)
         inv_vec[i] = neg_inv_mod_limb(DATA(prod_vec[i])[0]);


      for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
         for (j = index_vec[i]; j < index_vec[i+1]; j++) {
            corr_vec[j] = SpecialPower(len_vec[1] - len_vec[i], q[j]);
            corraux_vec[j] = PrepMulModPrecon(corr_vec[j], q[j]);
         }
      }



      UniquePtr<_kctsb_rem_struct_medium> R;
      R.make();

      R->n = n;
      R->levels = levels;
      R->primes.move(q);
      R->index_vec.move(index_vec);
      R->len_vec.move(len_vec);
      R->inv_vec.move(inv_vec);
      R->corr_vec.move(corr_vec);
      R->corraux_vec.move(corraux_vec);
      R->prod_vec.move(prod_vec);

      return R.release();
   }


   if (n > 800) 
   {
      UniqueArray<long> q;
      long i, j;
      long levels, vec_len;
      UniqueArray<long> index_vec;
      UniqueArray<_kctsb_gbigint_wrapped> prod_vec;
   
      q.SetLength(n);
      for (i = 0; i < n; i++)
         q[i] = p(i);

      levels = 0;
      while ((n >> levels) >= 4) levels++;

      vec_len = (1L << levels) - 1;

      index_vec.SetLength(vec_len+1);
      prod_vec.SetLength(vec_len);

      index_vec[0] = 0;
      index_vec[1] = n;

      for (i = 0; i <= levels-2; i++) {
         long start = (1L << i) - 1;
         long finish = (1L << (i+1)) - 2;
         for (j = finish; j >= start; j--) {
            index_vec[2*j+2] = index_vec[j] + (index_vec[j+1] - index_vec[j])/2;
            index_vec[2*j+1] = index_vec[j];
         }
         index_vec[2*finish+3] = n;
      }

      for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
         /* multiply primes index_vec[i]..index_vec[i+1]-1 into 
          * prod_vec[i]
          */

         _kctsb_gone(&prod_vec[i]);
         for (j = index_vec[i]; j < index_vec[i+1]; j++)
            _kctsb_gsmul(prod_vec[i], q[j], &prod_vec[i]); 
      }

      for (i = (1L << (levels-1)) - 2; i >= 3; i--)
         _kctsb_gmul(prod_vec[2*i+1], prod_vec[2*i+2], &prod_vec[i]);


      
      UniquePtr<_kctsb_rem_struct_fast> R;
      R.make();

      R->n = n;
      R->levels = levels;
      R->primes.move(q);
      R->index_vec.move(index_vec);
      R->prod_vec.move(prod_vec);
      R->modulus_size = _kctsb_gsize(modulus);

      return R.release();
   }

   {
      // basic case

      UniqueArray<long> q;
      long i;

      UniquePtr<_kctsb_rem_struct_basic> R;
      R.make();

      R->n = n;
      R->primes.SetLength(n);
      for (i = 0; i < n; i++)
         R->primes[i] = p(i);

      return R.release();
   }
}

_kctsb_tmp_vec *_kctsb_rem_struct_basic::fetch()
{
   return 0;
}


#ifdef KCTSB_TBL_REM

_kctsb_tmp_vec *_kctsb_rem_struct_tbl::fetch()
{
   return 0;
}

#endif

_kctsb_tmp_vec *_kctsb_rem_struct_fast::fetch()
{
   long vec_len = (1L << levels) - 1;
   UniquePtr<_kctsb_tmp_vec_rem_impl> res;
   res.make();
   res->rem_vec.SetLength(vec_len);
   _kctsb_gbigint_wrapped *rem_vec = res->rem_vec.get();

   long i;

   /* allocate length in advance to streamline eval code */

   _kctsb_gsetlength(&rem_vec[1], modulus_size);
   _kctsb_gsetlength(&rem_vec[2], modulus_size);

   for (i = 1; i < (1L << (levels-1)) - 1; i++) {
      _kctsb_gsetlength(&rem_vec[2*i+1], _kctsb_gsize(prod_vec[2*i+1]));
      _kctsb_gsetlength(&rem_vec[2*i+2], _kctsb_gsize(prod_vec[2*i+2]));
   }

   return res.release();
}

_kctsb_tmp_vec *_kctsb_rem_struct_medium::fetch()
{
   long vec_len = (1L << levels) - 1;
   UniquePtr<_kctsb_tmp_vec_rem_impl> res;
   res.make();
   res->rem_vec.SetLength(vec_len);
   _kctsb_gbigint_wrapped *rem_vec = res->rem_vec.get();

   long i;

   /* allocate length in advance to streamline eval code */

   _kctsb_gsetlength(&rem_vec[0], len_vec[1]); /* a special temp */

   for (i = 1; i < vec_len; i++)
      _kctsb_gsetlength(&rem_vec[i], len_vec[i]);

   return res.release();
}





#ifdef KCTSB_TBL_REM


#if (KCTSB_GAP_BITS == 2)

// special case, some loop unrolling: slightly faster


void _kctsb_rem_struct_tbl::eval(long *x, _kctsb_gbigint a, 
                                 _kctsb_tmp_vec *generic_tmp_vec)
{
   if (ZEROP(a)) {
      long i;
      for (i = 0; i < n; i++) x[i] = 0;
      return;
   }

   long sa = SIZE(a);
   _kctsb_limb_t *adata = DATA(a);

   if (sa <= 4) {
      long i;
      for (i = 0; i < n; i++) {
         _kctsb_limb_t *tp = tbl[i]; 
         ll_type acc;
         ll_init(acc, adata[0]);
         long j;
         for (j = 1; j < sa; j++)
            ll_mul_add(acc, adata[j], tp[j]);

         _kctsb_limb_t accvec[2];
         x[i] = tbl_red_31(0, ll_get_hi(acc), ll_get_lo(acc), primes[i], inv_primes[i]);
      }
   }
   else {
      long i;
      for (i = 0; i < n; i++) {
         _kctsb_limb_t *ap = adata;
         _kctsb_limb_t *tp = tbl[i]; 

         ll_type acc21;
         _kctsb_limb_t acc0;

         {
            ll_type sum;
            ll_init(sum, ap[0]);

            ll_mul_add(sum, ap[1], tp[1]);
            ll_mul_add(sum, ap[2], tp[2]);
            ll_mul_add(sum, ap[3], tp[3]);

            ll_init(acc21,  ll_get_hi(sum));
            acc0 = ll_get_lo(sum);
         }

         long m=sa-4;
         ap += 4;
         tp += 4;

         for (; m >= 8; m -= 8, ap += 8, tp += 8) {
            {
               ll_type sum;
               ll_mul(sum, ap[0], tp[0]);
               ll_mul_add(sum, ap[1], tp[1]);
               ll_mul_add(sum, ap[2], tp[2]);
               ll_mul_add(sum, ap[3], tp[3]);
   
               ll_add(sum, acc0);
               acc0 = ll_get_lo(sum);
               ll_add(acc21,  ll_get_hi(sum));
            }
            {
   
               ll_type sum;
               ll_mul(sum, ap[4+0], tp[4+0]);
               ll_mul_add(sum, ap[4+1], tp[4+1]);
               ll_mul_add(sum, ap[4+2], tp[4+2]);
               ll_mul_add(sum, ap[4+3], tp[4+3]);
   
               ll_add(sum, acc0);
               acc0 = ll_get_lo(sum);
               ll_add(acc21,  ll_get_hi(sum));
            }
         }

         for (; m >= 4; m -= 4, ap += 4, tp += 4) {
            ll_type sum;
            ll_mul(sum, ap[0], tp[0]);
            ll_mul_add(sum, ap[1], tp[1]);
            ll_mul_add(sum, ap[2], tp[2]);
            ll_mul_add(sum, ap[3], tp[3]);
   
	    ll_add(sum, acc0);
	    acc0 = ll_get_lo(sum);
	    ll_add(acc21,  ll_get_hi(sum));
         }

         if (m > 0) {
            ll_type sum;
            ll_mul(sum, ap[0], tp[0]);
            for (m--, ap++, tp++; m > 0; m--, ap++, tp++)
               ll_mul_add(sum, ap[0], tp[0]);

   
	    ll_add(sum, acc0);
	    acc0 = ll_get_lo(sum);
	    ll_add(acc21,  ll_get_hi(sum));
         }

         x[i] = tbl_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, primes[i], inv_primes[i]);
      }
   }
}

#else

// General case: some loop unrolling (also using "Duff's Device")
// for the case where BPL-SPNBITS == 4: this is the common
// case on 64-bit machines.  The loop unrolling and Duff seems
// to shave off 5-10%

#define TBL_UNROLL (1)

void _kctsb_rem_struct_tbl::eval(long *x, _kctsb_gbigint a, 
                                 _kctsb_tmp_vec *generic_tmp_vec)
{
   if (ZEROP(a)) {
      long i;
      for (i = 0; i < n; i++) x[i] = 0;
      return;
   }

   long sa = SIZE(a);
   _kctsb_limb_t *adata = DATA(a);

   const long Bnd =  1L << KCTSB_GAP_BITS;

   if (sa <= Bnd) {
      long i;
      for (i = 0; i < n; i++) {
         _kctsb_limb_t *tp = tbl[i]; 


         ll_type acc;
         ll_init(acc, adata[0]);

#if (TBL_UNROLL && KCTSB_GAP_BITS == 4)
         switch (sa) {
         case 16:  ll_mul_add(acc, adata[16-1], tp[16-1]);
         case 15:  ll_mul_add(acc, adata[15-1], tp[15-1]);
         case 14:  ll_mul_add(acc, adata[14-1], tp[14-1]);
         case 13:  ll_mul_add(acc, adata[13-1], tp[13-1]);
         case 12:  ll_mul_add(acc, adata[12-1], tp[12-1]);
         case 11:  ll_mul_add(acc, adata[11-1], tp[11-1]);
         case 10:  ll_mul_add(acc, adata[10-1], tp[10-1]);
         case 9:  ll_mul_add(acc, adata[9-1], tp[9-1]);
         case 8:  ll_mul_add(acc, adata[8-1], tp[8-1]);
         case 7:  ll_mul_add(acc, adata[7-1], tp[7-1]);
         case 6:  ll_mul_add(acc, adata[6-1], tp[6-1]);
         case 5:  ll_mul_add(acc, adata[5-1], tp[5-1]);
         case 4:  ll_mul_add(acc, adata[4-1], tp[4-1]);
         case 3:  ll_mul_add(acc, adata[3-1], tp[3-1]);
         case 2:  ll_mul_add(acc, adata[2-1], tp[2-1]);
         }

#elif (TBL_UNROLL)
         long j = sa;
         for (; j > 16; j -= 16) {
            ll_mul_add(acc, adata[j-1], tp[j-1]);
            ll_mul_add(acc, adata[j-2], tp[j-2]);
            ll_mul_add(acc, adata[j-3], tp[j-3]);
            ll_mul_add(acc, adata[j-4], tp[j-4]);
            ll_mul_add(acc, adata[j-5], tp[j-5]);
            ll_mul_add(acc, adata[j-6], tp[j-6]);
            ll_mul_add(acc, adata[j-7], tp[j-7]);
            ll_mul_add(acc, adata[j-8], tp[j-8]);
            ll_mul_add(acc, adata[j-9], tp[j-9]);
            ll_mul_add(acc, adata[j-10], tp[j-10]);
            ll_mul_add(acc, adata[j-11], tp[j-11]);
            ll_mul_add(acc, adata[j-12], tp[j-12]);
            ll_mul_add(acc, adata[j-13], tp[j-13]);
            ll_mul_add(acc, adata[j-14], tp[j-14]);
            ll_mul_add(acc, adata[j-15], tp[j-15]);
            ll_mul_add(acc, adata[j-16], tp[j-16]);
         }
         switch (j) {
         case 16:  ll_mul_add(acc, adata[16-1], tp[16-1]);
         case 15:  ll_mul_add(acc, adata[15-1], tp[15-1]);
         case 14:  ll_mul_add(acc, adata[14-1], tp[14-1]);
         case 13:  ll_mul_add(acc, adata[13-1], tp[13-1]);
         case 12:  ll_mul_add(acc, adata[12-1], tp[12-1]);
         case 11:  ll_mul_add(acc, adata[11-1], tp[11-1]);
         case 10:  ll_mul_add(acc, adata[10-1], tp[10-1]);
         case 9:  ll_mul_add(acc, adata[9-1], tp[9-1]);
         case 8:  ll_mul_add(acc, adata[8-1], tp[8-1]);
         case 7:  ll_mul_add(acc, adata[7-1], tp[7-1]);
         case 6:  ll_mul_add(acc, adata[6-1], tp[6-1]);
         case 5:  ll_mul_add(acc, adata[5-1], tp[5-1]);
         case 4:  ll_mul_add(acc, adata[4-1], tp[4-1]);
         case 3:  ll_mul_add(acc, adata[3-1], tp[3-1]);
         case 2:  ll_mul_add(acc, adata[2-1], tp[2-1]);
         }

#else
         long j;
         for (j = 1; j < sa; j++)
            ll_mul_add(acc, adata[j], tp[j]);
#endif

         x[i] = tbl_red_31(0, ll_get_hi(acc), ll_get_lo(acc), primes[i], inv_primes[i]);
      }
   }
   else {
      long i;
      for (i = 0; i < n; i++) {
         _kctsb_limb_t *ap = adata;
         _kctsb_limb_t *tp = tbl[i]; 

         ll_type acc21;
         _kctsb_limb_t acc0;

         {
            ll_type sum;
            ll_init(sum, ap[0]);

#if (TBL_UNROLL && KCTSB_GAP_BITS == 4)
            ll_mul_add(sum, ap[1], tp[1]);
            ll_mul_add(sum, ap[2], tp[2]);
            ll_mul_add(sum, ap[3], tp[3]);
            ll_mul_add(sum, ap[4], tp[4]);
            ll_mul_add(sum, ap[5], tp[5]);
            ll_mul_add(sum, ap[6], tp[6]);
            ll_mul_add(sum, ap[7], tp[7]);
            ll_mul_add(sum, ap[8], tp[8]);
            ll_mul_add(sum, ap[9], tp[9]);
            ll_mul_add(sum, ap[10], tp[10]);
            ll_mul_add(sum, ap[11], tp[11]);
            ll_mul_add(sum, ap[12], tp[12]);
            ll_mul_add(sum, ap[13], tp[13]);
            ll_mul_add(sum, ap[14], tp[14]);
            ll_mul_add(sum, ap[15], tp[15]);
#else
            for (long j = 1; j < Bnd; j++)
               ll_mul_add(sum, ap[j], tp[j]);
#endif

            ll_init(acc21, ll_get_hi(sum));
	    acc0 = ll_get_lo(sum);
         }

         long m;
         for (m = sa-Bnd, ap += Bnd, tp += Bnd; m >= Bnd; m -= Bnd, ap += Bnd, tp += Bnd) {

            ll_type sum;
            ll_mul(sum, ap[0], tp[0]);

#if (TBL_UNROLL && KCTSB_GAP_BITS == 4)
            ll_mul_add(sum, ap[1], tp[1]);
            ll_mul_add(sum, ap[2], tp[2]);
            ll_mul_add(sum, ap[3], tp[3]);
            ll_mul_add(sum, ap[4], tp[4]);
            ll_mul_add(sum, ap[5], tp[5]);
            ll_mul_add(sum, ap[6], tp[6]);
            ll_mul_add(sum, ap[7], tp[7]);
            ll_mul_add(sum, ap[8], tp[8]);
            ll_mul_add(sum, ap[9], tp[9]);
            ll_mul_add(sum, ap[10], tp[10]);
            ll_mul_add(sum, ap[11], tp[11]);
            ll_mul_add(sum, ap[12], tp[12]);
            ll_mul_add(sum, ap[13], tp[13]);
            ll_mul_add(sum, ap[14], tp[14]);
            ll_mul_add(sum, ap[15], tp[15]);
#else
            for (long j = 1; j < Bnd; j++)
               ll_mul_add(sum, ap[j], tp[j]);
#endif
            ll_add(sum, acc0); 
            acc0 = ll_get_lo(sum);
            ll_add(acc21, ll_get_hi(sum));
         }

         if (m > 0) {
            ll_type sum;
            ll_mul(sum, ap[0], tp[0]);

#if (TBL_UNROLL && KCTSB_GAP_BITS == 4)
            switch (m) {
            case 15:  ll_mul_add(sum, ap[15-1], tp[15-1]);
            case 14:  ll_mul_add(sum, ap[14-1], tp[14-1]);
            case 13:  ll_mul_add(sum, ap[13-1], tp[13-1]);
            case 12:  ll_mul_add(sum, ap[12-1], tp[12-1]);
            case 11:  ll_mul_add(sum, ap[11-1], tp[11-1]);
            case 10:  ll_mul_add(sum, ap[10-1], tp[10-1]);
            case 9:  ll_mul_add(sum, ap[9-1], tp[9-1]);
            case 8:  ll_mul_add(sum, ap[8-1], tp[8-1]);
            case 7:  ll_mul_add(sum, ap[7-1], tp[7-1]);
            case 6:  ll_mul_add(sum, ap[6-1], tp[6-1]);
            case 5:  ll_mul_add(sum, ap[5-1], tp[5-1]);
            case 4:  ll_mul_add(sum, ap[4-1], tp[4-1]);
            case 3:  ll_mul_add(sum, ap[3-1], tp[3-1]);
            case 2:  ll_mul_add(sum, ap[2-1], tp[2-1]);
            }
#else
            for (m--, ap++, tp++; m > 0; m--, ap++, tp++)
               ll_mul_add(sum, ap[0], tp[0]);
#endif
            ll_add(sum, acc0); 
            acc0 = ll_get_lo(sum);
            ll_add(acc21, ll_get_hi(sum));
         }

         x[i] = tbl_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, 
                           primes[i], inv_primes[i]);
      }
   }
}

#endif


#endif


void _kctsb_rem_struct_basic::eval(long *x, _kctsb_gbigint a, 
                                 _kctsb_tmp_vec *generic_tmp_vec)
{
   long *q = primes.get();

   long j;
   _kctsb_limb_t *adata;
   long sa;

   if (!a) 
      sa = 0;
   else
      sa = SIZE(a);

   if (sa == 0) {
      for (j = 0; j < n; j++)
         x[j] = 0;

      return;
   }

   adata = DATA(a);

   for (j = 0; j < n; j++)
      x[j] = KCTSB_MPN(mod_1)(adata, sa, q[j]);

}

void _kctsb_rem_struct_fast::eval(long *x, _kctsb_gbigint a, 
                                _kctsb_tmp_vec *generic_tmp_vec)
{
   long *q = primes.get();
   _kctsb_gbigint_wrapped *rem_vec = 
      (static_cast<_kctsb_tmp_vec_rem_impl *> (generic_tmp_vec))->rem_vec.get();
   long vec_len = (1L << levels) - 1;

   long i, j;

   if (ZEROP(a)) {
      for (j = 0; j < n; j++)
         x[j] = 0;

      return;
   }

   _kctsb_gcopy(a, &rem_vec[1]);
   _kctsb_gcopy(a, &rem_vec[2]);

   for (i = 1; i < (1L << (levels-1)) - 1; i++) {
      gmod_simple(rem_vec[i], prod_vec[2*i+1], &rem_vec[2*i+1]);
      gmod_simple(rem_vec[i], prod_vec[2*i+2], &rem_vec[2*i+2]);
   }

   for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
      long lo = index_vec[i];
      long hi = index_vec[i+1];
      _kctsb_limb_t *s1p = DATA(rem_vec[i]);
      long s1size = SIZE(rem_vec[i]);
      if (s1size == 0) {
         for (j = lo; j <hi; j++)
            x[j] = 0;
      }
      else {
         for (j = lo; j < hi; j++)
            x[j] = KCTSB_MPN(mod_1)(s1p, s1size, q[j]);
      }
   }
}

void _kctsb_rem_struct_medium::eval(long *x, _kctsb_gbigint a, 
                                  _kctsb_tmp_vec *generic_tmp_vec)
{
   long *q = primes.get();
   _kctsb_gbigint_wrapped *rem_vec = 
      (static_cast<_kctsb_tmp_vec_rem_impl *> (generic_tmp_vec))->rem_vec.get();
   long vec_len = (1L << levels) - 1;

   long i, j;

   if (ZEROP(a)) {
      for (j = 0; j < n; j++)
         x[j] = 0;

      return;
   }

   _kctsb_gcopy(a, &rem_vec[1]);
   _kctsb_gcopy(a, &rem_vec[2]);

   for (i = 1; i < (1L << (levels-1)) - 1; i++) {
      _kctsb_gcopy(rem_vec[i], &rem_vec[0]);
      redc(rem_vec[0], prod_vec[2*i+1], len_vec[i]-len_vec[2*i+1],
           inv_vec[2*i+1], rem_vec[2*i+1]);
      redc(rem_vec[i], prod_vec[2*i+2], len_vec[i]-len_vec[2*i+2],
           inv_vec[2*i+2], rem_vec[2*i+2]);
   }

   for (i = (1L << (levels-1)) - 1; i < vec_len; i++) {
      long lo = index_vec[i];
      long hi = index_vec[i+1];
      _kctsb_limb_t *s1p = DATA(rem_vec[i]);
      long s1size = SIZE(rem_vec[i]);
      if (s1size == 0) {
         for (j = lo; j < hi; j++)
            x[j] = 0;
      }
      else {
         for (j = lo; j < hi; j++) {
            long t = KCTSB_MPN(mod_1)(s1p, s1size, q[j]);
            x[j] = MulModPrecon(t, corr_vec[j], q[j], corraux_vec[j]);
         }
      }
   }
}



/* routines for x += a*b for multi-precision b  
 */
   

void
_kctsb_gaorsmul(_kctsb_gbigint x, _kctsb_gbigint y, long sub,  _kctsb_gbigint *ww)
{
   GRegister(tmp);

   _kctsb_gmul(x, y, &tmp);
   if (sub)
      _kctsb_gsub(*ww, tmp, ww);
   else
      _kctsb_gadd(*ww, tmp, ww);
}


void
_kctsb_gaddmul(_kctsb_gbigint x, _kctsb_gbigint y,  _kctsb_gbigint *ww)
{
  _kctsb_gaorsmul(x, y, 0, ww);
}

void
_kctsb_gsubmul(_kctsb_gbigint x, _kctsb_gbigint y,  _kctsb_gbigint *ww)
{
  _kctsb_gaorsmul(x, y, 1, ww);
}


/* routines for x += a*b for single-precision b 
 * Lightly massaged code taken from GMP's mpz routines */


static inline 
void _kctsb_mpn_com_n(_kctsb_limb_t *d, _kctsb_limb_t *s, long n) 
{
  do {
    *d++ = CLIP(~ *s++); 
  } while (--n); 
}

#if 0
#define _kctsb_mpn_com_n(d,s,n) \
  do { \
    _kctsb_limb_t *  __d = (d); \
    _kctsb_limb_t *  __s = (s); \
    long  __n = (n); \
    do \
      *__d++ = CLIP(~ *__s++); \
    while (--__n); \
  } while (0)
#endif



static inline 
void _kctsb_MPN_MUL_1C(_kctsb_limb_t& cout, _kctsb_limb_t *dst, 
                     _kctsb_limb_t *src, long size, _kctsb_limb_t n, 
                     _kctsb_limb_t cin) 
{
    _kctsb_limb_t cy; 
    cy = KCTSB_MPN(mul_1) (dst, src, size, n); 
    cout = CLIP(cy + KCTSB_MPN(add_1) (dst, dst, size, cin)); 
}



#if 0
#define _kctsb_MPN_MUL_1C(cout, dst, src, size, n, cin) \
  do { \
    _kctsb_limb_t __cy; \
    __cy = KCTSB_MPN(mul_1) (dst, src, size, n); \
    (cout) = CLIP(__cy + KCTSB_MPN(add_1) (dst, dst, size, cin)); \
  } while (0)
#endif




static inline
void _kctsb_g_inc(_kctsb_limb_t *p, long n)
{
    while (n > 0) {  
       *p = CLIP(*p + 1); 
       if (*p != 0) break;  
       p++;  
       n--;  
    }
}

#if 0
#define _kctsb_g_inc(p, n)   \
  do {   \
    _kctsb_limb_t * __p = (p);  \
    long __n = (n);  \
    while (__n > 0) {  \
       *__p = CLIP(*__p + 1); \
       if (*__p != 0) break;  \
       __p++;  \
       __n--;  \
    }  \
  } while (0);
#endif

static inline
void _kctsb_g_inc_carry(_kctsb_limb_t& c, _kctsb_limb_t *p, long n)   
{
   long addc = 1; 
   while (n > 0) {  
      *p = CLIP(*p + 1); 
      if (*p != 0) { addc = 0; break; }  
      p++;  
      n--;  
   }  
   c = CLIP(c + addc); 
}

#if 0
#define _kctsb_g_inc_carry(c, p, n)   \
  do {   \
    _kctsb_limb_t * __p = (p);  \
    long __n = (n);  \
    long __addc = 1; \
    while (__n > 0) {  \
       *__p = CLIP(*__p + 1); \
       if (*__p != 0) { __addc = 0; break; }  \
       __p++;  \
       __n--;  \
    }  \
    c = CLIP(c + __addc); \
  } while (0);
#endif 


static inline
void _kctsb_g_dec(_kctsb_limb_t *p, long n)   
{
   _kctsb_limb_t tmp; 
   while (n > 0) {  
      tmp = *p; 
      *p = CLIP(*p - 1); 
      if (tmp != 0) break;  
      p++;  
      n--;  
   }  
}


#if 0
#define _kctsb_g_dec(p, n)   \
  do {   \
    _kctsb_limb_t * __p = (p);  \
    _kctsb_limb_t __tmp; \
    long __n = (n);  \
    while (__n > 0) {  \
       __tmp = *__p; \
       *__p = CLIP(*__p - 1); \
       if (__tmp != 0) break;  \
       __p++;  \
       __n--;  \
    }  \
  } while (0);
#endif
  


/* sub==0 means an addmul w += x*y, sub==1 means a submul w -= x*y. */
void
_kctsb_gaorsmul_1(_kctsb_gbigint x, long yy, long sub, _kctsb_gbigint *ww)
{
  long  xsize, xneg, wsize, wneg, new_wsize, min_size, dsize;
  _kctsb_gbigint w;
  _kctsb_limb_t *xp;
  _kctsb_limb_t *wp;
  _kctsb_limb_t  cy;
  _kctsb_limb_t  y;

  if (ZEROP(x) || yy == 0)
    return;

  if (ZEROP(*ww)) {
    _kctsb_gsmul(x, yy, ww);
    if (sub) SIZE(*ww) = -SIZE(*ww);
    return;
  }

  if (yy == 1) {
    if (sub)
      _kctsb_gsub(*ww, x, ww);
    else
      _kctsb_gadd(*ww, x, ww);
    return;
  }

  if (yy == -1) {
    if (sub)
      _kctsb_gadd(*ww, x, ww);
    else
      _kctsb_gsub(*ww, x, ww);
    return;
  }

  if (*ww == x) {
    GRegister(tmp);
    _kctsb_gsmul(x, yy, &tmp);
    if (sub)
       _kctsb_gsub(*ww, tmp, ww);
    else
       _kctsb_gadd(*ww, tmp, ww);
    return;
  }

  y = ABS(yy);
  if (XCLIP(y)) {
    GRegister(xyy);
    _kctsb_gintoz(yy, &xyy);
    _kctsb_gaorsmul(x, xyy, sub, ww);
    return;
  }

  GET_SIZE_NEG(xsize, xneg, x);
  sub = XOR(sub, xneg);
  sub = XOR(sub, yy < 0);

  w = *ww;

  GET_SIZE_NEG(wsize, wneg, w);
  sub = XOR(sub, wneg);

  new_wsize = max(wsize, xsize);
  min_size = min(wsize, xsize);

  if (MustAlloc(w, new_wsize+1)) {
    _kctsb_gsetlength(&w, new_wsize+1);
    *ww = w;
  }

  wp = DATA(w);
  xp = DATA(x);

  if (sub == 0)
    {
      /* addmul of absolute values */

      cy = KCTSB_MPN(addmul_1) (wp, xp, min_size, y);
      wp += min_size;
      xp += min_size;

      dsize = xsize - wsize;
      if (dsize != 0)
        {
          _kctsb_limb_t  cy2;
          if (dsize > 0) {
            cy2 = KCTSB_MPN(mul_1) (wp, xp, dsize, y);
          }
          else {
            dsize = -dsize;
            cy2 = 0;
          }
          cy = CLIP(cy2 + KCTSB_MPN(add_1) (wp, wp, dsize, cy));
        }

      wp[dsize] = cy;
      new_wsize += (cy != 0);
    }
  else
    {
      /* submul of absolute values */

      cy = KCTSB_MPN(submul_1) (wp, xp, min_size, y);
      if (wsize >= xsize)
        {
          /* if w bigger than x, then propagate borrow through it */
          if (wsize != xsize) {
            cy = KCTSB_MPN(sub_1) (wp+xsize, wp+xsize, wsize-xsize, cy);
          }

          if (cy != 0)
            {
              /* Borrow out of w, take twos complement negative to get
                 absolute value, flip sign of w.  */
              wp[new_wsize] = CLIP(~-cy);  /* extra limb is 0-cy */
              _kctsb_mpn_com_n (wp, wp, new_wsize);
              new_wsize++;
              _kctsb_g_inc(wp, new_wsize);
              wneg = XOR(wneg, 1); 
            }
        }
      else /* wsize < xsize */
        {
          /* x bigger than w, so want x*y-w.  Submul has given w-x*y, so
             take twos complement and use an mpn_mul_1 for the rest.  */

          _kctsb_limb_t  cy2;

          /* -(-cy*b^n + w-x*y) = (cy-1)*b^n + ~(w-x*y) + 1 */
          _kctsb_mpn_com_n (wp, wp, wsize);
          _kctsb_g_inc_carry(cy, wp, wsize);
          cy = CLIP(cy-1);

          /* If cy-1 == -1 then hold that -1 for latter.  mpn_submul_1 never
             returns cy==MP_LIMB_T_MAX so that value always indicates a -1. */
          cy2 = (cy == CLIP(_kctsb_limb_t(-1)));
          cy = CLIP(cy + cy2);
          _kctsb_MPN_MUL_1C (cy, wp+wsize, xp+wsize, xsize-wsize, y, cy);
          wp[new_wsize] = cy;
          new_wsize += (cy != 0);

          /* Apply any -1 from above.  The value at wp+wsize is non-zero
             because y!=0 and the high limb of x will be non-zero.  */
          if (cy2) {
            _kctsb_g_dec(wp+wsize, new_wsize-wsize);
          }

          wneg = XOR(wneg, 1);
        }

      /* submul can produce high zero limbs due to cancellation, both when w
         has more limbs or x has more  */
      STRIP(new_wsize, wp);
    }

  if (wneg) new_wsize = -new_wsize;
  SIZE(w) = new_wsize;
}


void
_kctsb_gsaddmul(_kctsb_gbigint x, long yy,  _kctsb_gbigint *ww)
{
  _kctsb_gaorsmul_1(x, yy, 0, ww);
}

void
_kctsb_gssubmul(_kctsb_gbigint x, long yy,  _kctsb_gbigint *ww)
{
  _kctsb_gaorsmul_1(x, yy, 1, ww);
}




// general preconditioned remainder



#ifndef KCTSB_VIABLE_LL


struct _kctsb_general_rem_one_struct  { };

_kctsb_general_rem_one_struct *
_kctsb_general_rem_one_struct_build(long p)
{
   return 0;
}

long 
_kctsb_general_rem_one_struct_apply(_kctsb_gbigint a, long p, _kctsb_general_rem_one_struct *pinfo)
{
   return _kctsb_gsmod(a, p);
}

void
_kctsb_general_rem_one_struct_delete(_kctsb_general_rem_one_struct *pinfo) 
{
}


#else


#define REM_ONE_SZ (128)

struct _kctsb_general_rem_one_struct  {
   sp_ll_reduce_struct red_struct;
   long Bnd;
   UniqueArray<_kctsb_limb_t> tbl;
};



_kctsb_general_rem_one_struct *
_kctsb_general_rem_one_struct_build(long p)
{
   if (p < 2 || p >= KCTSB_SP_BOUND)
      LogicError("_kctsb_general_rem_one_struct_build: bad args (p)");

   UniquePtr<_kctsb_general_rem_one_struct> pinfo;
   pinfo.make();

   pinfo->red_struct = make_sp_ll_reduce_struct(p);

   long pbits = _kctsb_g2logs(p);
   long gapbits = min(28, 2*KCTSB_BITS_PER_LONG - pbits - KCTSB_ZZ_NBITS);
   // hold gapbits to a max of 28 to avoid some potential overflow
   // issues

   pinfo->Bnd = 1L << gapbits;

   pinfo->tbl.SetLength(REM_ONE_SZ+3);

   long t = 1;
   for (long j = 0; j < KCTSB_ZZ_NBITS; j++) {
      t += t;
      if (t >= p) t -= p;
   }

   long t2 = t;
   for (long j = KCTSB_ZZ_NBITS; j < KCTSB_BITS_PER_LONG; j++) {
      t2 += t2;
      if (t2 >= p) t2 -= p;
   }

   long t1 = 1;
   pinfo->tbl[0] = 1;
   for (long j = 1; j <= REM_ONE_SZ; j++) {
      t1 = MulMod(t1, t, p);
      pinfo->tbl[j] = t1;
   }

   // careful! for non-empty nails, we have to initialize
   // the last two table entries differently

   for (long j = REM_ONE_SZ+1; j < REM_ONE_SZ+3; j++) {
      t1 = MulMod(t1, t2, p);
      pinfo->tbl[j] = t1;
   }

   return pinfo.release();
}


long 
_kctsb_general_rem_one_struct_apply1(_kctsb_limb_t *a_data, long a_sz, long a_neg, long p, 
                                   _kctsb_general_rem_one_struct *pinfo)
{
   sp_ll_reduce_struct red_struct = pinfo->red_struct;
   long Bnd = pinfo->Bnd;
   _kctsb_limb_t *tbl = pinfo->tbl.elts();

   long idx = ((cast_unsigned(a_sz+REM_ONE_SZ-1)/REM_ONE_SZ)-1)*REM_ONE_SZ;
   ll_type leftover;
   long sz = a_sz-idx;
   a_data += idx;

   for ( ; ; sz = REM_ONE_SZ, a_data -= REM_ONE_SZ, idx -= REM_ONE_SZ) {
      if (sz <= Bnd) {
	 ll_type acc;
	 ll_init(acc, 0);

	 {
	    long j = 0;

	    for (; j <= sz-16; j += 16) {
	       ll_mul_add(acc, a_data[j+0], tbl[j+0]);
	       ll_mul_add(acc, a_data[j+1], tbl[j+1]);
	       ll_mul_add(acc, a_data[j+2], tbl[j+2]);
	       ll_mul_add(acc, a_data[j+3], tbl[j+3]);
	       ll_mul_add(acc, a_data[j+4], tbl[j+4]);
	       ll_mul_add(acc, a_data[j+5], tbl[j+5]);
	       ll_mul_add(acc, a_data[j+6], tbl[j+6]);
	       ll_mul_add(acc, a_data[j+7], tbl[j+7]);
	       ll_mul_add(acc, a_data[j+8], tbl[j+8]);
	       ll_mul_add(acc, a_data[j+9], tbl[j+9]);
	       ll_mul_add(acc, a_data[j+10], tbl[j+10]);
	       ll_mul_add(acc, a_data[j+11], tbl[j+11]);
	       ll_mul_add(acc, a_data[j+12], tbl[j+12]);
	       ll_mul_add(acc, a_data[j+13], tbl[j+13]);
	       ll_mul_add(acc, a_data[j+14], tbl[j+14]);
	       ll_mul_add(acc, a_data[j+15], tbl[j+15]);
	    }

	    for (; j <= sz-4; j += 4) {
	       ll_mul_add(acc, a_data[j+0], tbl[j+0]);
	       ll_mul_add(acc, a_data[j+1], tbl[j+1]);
	       ll_mul_add(acc, a_data[j+2], tbl[j+2]);
	       ll_mul_add(acc, a_data[j+3], tbl[j+3]);
	    }

	    for (; j < sz; j++)
	       ll_mul_add(acc, a_data[j+0], tbl[j+0]);
	 }

         if (idx + REM_ONE_SZ >= a_sz) { // first time
            if (idx == 0) { // last time
	      long res = sp_ll_red_31(0, ll_get_hi(acc), ll_get_lo(acc), p, red_struct);
	      if (a_neg) res = NegateMod(res, p);
	      return res;
            }
            else {
               ll_mul(leftover, ll_get_lo(acc), tbl[REM_ONE_SZ]);
               ll_mul_add(leftover, ll_get_hi(acc), tbl[REM_ONE_SZ+1]);
            }
         }
         else {
	    ll_type acc21;
	    _kctsb_limb_t acc0;

	    ll_add(leftover, ll_get_lo(acc));
	    acc0 = ll_get_lo(leftover);
	    ll_init(acc21, ll_get_hi(leftover));
	    ll_add(acc21, ll_get_hi(acc));

            if (idx == 0) { // last time
	       long res = sp_ll_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
	       if (a_neg) res = NegateMod(res, p);
	       return res;
            }
            else {
               ll_mul(leftover, acc0, tbl[REM_ONE_SZ]);
               ll_mul_add(leftover, ll_get_lo(acc21), tbl[REM_ONE_SZ+1]);
               ll_mul_add(leftover, ll_get_hi(acc21), tbl[REM_ONE_SZ+2]);
            }
         }
      }
      else {
	 ll_type acc21;
	 ll_init(acc21, 0);
	 _kctsb_limb_t acc0 = 0;

	 if (Bnd > 16) {
	    long jj = 0;
	    for (; jj <= sz-Bnd; jj += Bnd) {
	       ll_type acc;
	       ll_init(acc, acc0);

	       long j = jj;

	       for (; j <= jj+Bnd-16; j += 16) {
		  ll_mul_add(acc, a_data[j+0], tbl[j+0]);
		  ll_mul_add(acc, a_data[j+1], tbl[j+1]);
		  ll_mul_add(acc, a_data[j+2], tbl[j+2]);
		  ll_mul_add(acc, a_data[j+3], tbl[j+3]);
		  ll_mul_add(acc, a_data[j+4], tbl[j+4]);
		  ll_mul_add(acc, a_data[j+5], tbl[j+5]);
		  ll_mul_add(acc, a_data[j+6], tbl[j+6]);
		  ll_mul_add(acc, a_data[j+7], tbl[j+7]);
		  ll_mul_add(acc, a_data[j+8], tbl[j+8]);
		  ll_mul_add(acc, a_data[j+9], tbl[j+9]);
		  ll_mul_add(acc, a_data[j+10], tbl[j+10]);
		  ll_mul_add(acc, a_data[j+11], tbl[j+11]);
		  ll_mul_add(acc, a_data[j+12], tbl[j+12]);
		  ll_mul_add(acc, a_data[j+13], tbl[j+13]);
		  ll_mul_add(acc, a_data[j+14], tbl[j+14]);
		  ll_mul_add(acc, a_data[j+15], tbl[j+15]);
	       }

	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }

	    if (jj < sz) {
	       ll_type acc;
	       ll_init(acc, acc0);

	       long j = jj;

	       for (; j <= sz-4; j += 4) {
		  ll_mul_add(acc, a_data[j+0], tbl[j+0]);
		  ll_mul_add(acc, a_data[j+1], tbl[j+1]);
		  ll_mul_add(acc, a_data[j+2], tbl[j+2]);
		  ll_mul_add(acc, a_data[j+3], tbl[j+3]);
	       }

	       for (; j < sz; j++)
		  ll_mul_add(acc, a_data[j+0], tbl[j+0]);

	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }
	 }
	 else if (Bnd == 16) {

	    long jj = 0;
	    for (; jj <= sz-16; jj += 16) {
	       ll_type acc;

	       long j = jj;

	       ll_mul(acc, a_data[j+0], tbl[j+0]);
	       ll_mul_add(acc, a_data[j+1], tbl[j+1]);
	       ll_mul_add(acc, a_data[j+2], tbl[j+2]);
	       ll_mul_add(acc, a_data[j+3], tbl[j+3]);
	       ll_mul_add(acc, a_data[j+4], tbl[j+4]);
	       ll_mul_add(acc, a_data[j+5], tbl[j+5]);
	       ll_mul_add(acc, a_data[j+6], tbl[j+6]);
	       ll_mul_add(acc, a_data[j+7], tbl[j+7]);
	       ll_mul_add(acc, a_data[j+8], tbl[j+8]);
	       ll_mul_add(acc, a_data[j+9], tbl[j+9]);
	       ll_mul_add(acc, a_data[j+10], tbl[j+10]);
	       ll_mul_add(acc, a_data[j+11], tbl[j+11]);
	       ll_mul_add(acc, a_data[j+12], tbl[j+12]);
	       ll_mul_add(acc, a_data[j+13], tbl[j+13]);
	       ll_mul_add(acc, a_data[j+14], tbl[j+14]);
	       ll_mul_add(acc, a_data[j+15], tbl[j+15]);

	       ll_add(acc, acc0);
	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }

	    if (jj < sz) {
	       ll_type acc;
	       ll_init(acc, acc0);

	       long j = jj;

	       for (; j <= sz-4; j += 4) {
		  ll_mul_add(acc, a_data[j+0], tbl[j+0]);
		  ll_mul_add(acc, a_data[j+1], tbl[j+1]);
		  ll_mul_add(acc, a_data[j+2], tbl[j+2]);
		  ll_mul_add(acc, a_data[j+3], tbl[j+3]);
	       }

	       for (; j < sz; j++)
		  ll_mul_add(acc, a_data[j+0], tbl[j+0]);

	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }
	 }
	 else if (Bnd == 8)  {
	    long jj = 0;
	    for (; jj <= sz-8; jj += 8) {
	       ll_type acc;

	       long j = jj;

	       ll_mul(acc, a_data[j+0], tbl[j+0]);
	       ll_mul_add(acc, a_data[j+1], tbl[j+1]);
	       ll_mul_add(acc, a_data[j+2], tbl[j+2]);
	       ll_mul_add(acc, a_data[j+3], tbl[j+3]);
	       ll_mul_add(acc, a_data[j+4], tbl[j+4]);
	       ll_mul_add(acc, a_data[j+5], tbl[j+5]);
	       ll_mul_add(acc, a_data[j+6], tbl[j+6]);
	       ll_mul_add(acc, a_data[j+7], tbl[j+7]);

	       ll_add(acc, acc0);
	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }

	    if (jj < sz) {
	       ll_type acc;
	       ll_init(acc, acc0);

	       long j = jj;

	       for (; j < sz; j++)
		  ll_mul_add(acc, a_data[j+0], tbl[j+0]);

	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }
	 }
	 else /* Bnd == 4 */  {
	    long jj = 0;
	    for (; jj <= sz-4; jj += 4) {
	       ll_type acc;

	       long j = jj;

	       ll_mul(acc, a_data[j+0], tbl[j+0]);
	       ll_mul_add(acc, a_data[j+1], tbl[j+1]);
	       ll_mul_add(acc, a_data[j+2], tbl[j+2]);
	       ll_mul_add(acc, a_data[j+3], tbl[j+3]);


	       ll_add(acc, acc0);
	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }

	    if (jj < sz) {
	       ll_type acc;
	       ll_init(acc, acc0);

	       long j = jj;

	       for (; j < sz; j++)
		  ll_mul_add(acc, a_data[j+0], tbl[j+0]);


	       acc0 = ll_get_lo(acc);
	       ll_add(acc21, ll_get_hi(acc));
	    }
	 }

	 if (idx + REM_ONE_SZ < a_sz) { // not first time
	    ll_add(leftover, acc0);
	    acc0 = ll_get_lo(leftover);
	    ll_add(acc21, ll_get_hi(leftover));
	 }

	 if (idx == 0) { // last time
	    long res = sp_ll_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
	    if (a_neg) res = NegateMod(res, p);
	    return res;
	 }
	 else {
	    ll_mul(leftover, acc0, tbl[REM_ONE_SZ]);
	    ll_mul_add(leftover, ll_get_lo(acc21), tbl[REM_ONE_SZ+1]);
	    ll_mul_add(leftover, ll_get_hi(acc21), tbl[REM_ONE_SZ+2]);
	 }
      }
   }
}


long 
_kctsb_general_rem_one_struct_apply(_kctsb_gbigint a, long p, _kctsb_general_rem_one_struct *pinfo)
{
   if (ZEROP(a)) return 0;

   if (!pinfo) {
      return _kctsb_gsmod(a, p);
   }

   sp_ll_reduce_struct red_struct = pinfo->red_struct;
   long Bnd = pinfo->Bnd;
   _kctsb_limb_t *tbl = pinfo->tbl.elts();

   long a_sz, a_neg;
   _kctsb_limb_t *a_data;
   GET_SIZE_NEG(a_sz, a_neg, a);
   a_data = DATA(a);

   if (a_sz > REM_ONE_SZ) {
      return _kctsb_general_rem_one_struct_apply1(a_data, a_sz, a_neg, p, pinfo);
   }

   if (a_sz <= Bnd) {
      ll_type acc;
      ll_init(acc, 0);

      {
         long j = 0;

         for (; j <= a_sz-16; j += 16) {
            ll_mul_add(acc, a_data[j+0], tbl[j+0]);
            ll_mul_add(acc, a_data[j+1], tbl[j+1]);
            ll_mul_add(acc, a_data[j+2], tbl[j+2]);
            ll_mul_add(acc, a_data[j+3], tbl[j+3]);
            ll_mul_add(acc, a_data[j+4], tbl[j+4]);
            ll_mul_add(acc, a_data[j+5], tbl[j+5]);
            ll_mul_add(acc, a_data[j+6], tbl[j+6]);
            ll_mul_add(acc, a_data[j+7], tbl[j+7]);
            ll_mul_add(acc, a_data[j+8], tbl[j+8]);
            ll_mul_add(acc, a_data[j+9], tbl[j+9]);
            ll_mul_add(acc, a_data[j+10], tbl[j+10]);
            ll_mul_add(acc, a_data[j+11], tbl[j+11]);
            ll_mul_add(acc, a_data[j+12], tbl[j+12]);
            ll_mul_add(acc, a_data[j+13], tbl[j+13]);
            ll_mul_add(acc, a_data[j+14], tbl[j+14]);
            ll_mul_add(acc, a_data[j+15], tbl[j+15]);
         }

         for (; j <= a_sz-4; j += 4) {
            ll_mul_add(acc, a_data[j+0], tbl[j+0]);
            ll_mul_add(acc, a_data[j+1], tbl[j+1]);
            ll_mul_add(acc, a_data[j+2], tbl[j+2]);
            ll_mul_add(acc, a_data[j+3], tbl[j+3]);
         }

	 for (; j < a_sz; j++)
            ll_mul_add(acc, a_data[j+0], tbl[j+0]);
      }


      long res = sp_ll_red_31(0, ll_get_hi(acc), ll_get_lo(acc), p, red_struct);
      if (a_neg) res = NegateMod(res, p);
      return res;
   }
   else if (Bnd > 16) {
      ll_type acc21;
      ll_init(acc21, 0);
      _kctsb_limb_t acc0 = 0;

      long jj = 0;
      for (; jj <= a_sz-Bnd; jj += Bnd) {
         ll_type acc;
         ll_init(acc, acc0);

         long j = jj;

         for (; j <= jj+Bnd-16; j += 16) {
            ll_mul_add(acc, a_data[j+0], tbl[j+0]);
            ll_mul_add(acc, a_data[j+1], tbl[j+1]);
            ll_mul_add(acc, a_data[j+2], tbl[j+2]);
            ll_mul_add(acc, a_data[j+3], tbl[j+3]);
            ll_mul_add(acc, a_data[j+4], tbl[j+4]);
            ll_mul_add(acc, a_data[j+5], tbl[j+5]);
            ll_mul_add(acc, a_data[j+6], tbl[j+6]);
            ll_mul_add(acc, a_data[j+7], tbl[j+7]);
            ll_mul_add(acc, a_data[j+8], tbl[j+8]);
            ll_mul_add(acc, a_data[j+9], tbl[j+9]);
            ll_mul_add(acc, a_data[j+10], tbl[j+10]);
            ll_mul_add(acc, a_data[j+11], tbl[j+11]);
            ll_mul_add(acc, a_data[j+12], tbl[j+12]);
            ll_mul_add(acc, a_data[j+13], tbl[j+13]);
            ll_mul_add(acc, a_data[j+14], tbl[j+14]);
            ll_mul_add(acc, a_data[j+15], tbl[j+15]);
         }

         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

      if (jj < a_sz) {
         ll_type acc;
         ll_init(acc, acc0);

         long j = jj;

         for (; j <= a_sz-4; j += 4) {
            ll_mul_add(acc, a_data[j+0], tbl[j+0]);
            ll_mul_add(acc, a_data[j+1], tbl[j+1]);
            ll_mul_add(acc, a_data[j+2], tbl[j+2]);
            ll_mul_add(acc, a_data[j+3], tbl[j+3]);
         }

	 for (; j < a_sz; j++)
            ll_mul_add(acc, a_data[j+0], tbl[j+0]);

         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

      long res = sp_ll_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
      if (a_neg) res = NegateMod(res, p);
      return res;
   }
   else if (Bnd == 16) {
      ll_type acc21;
      ll_init(acc21, 0);
      _kctsb_limb_t acc0 = 0;

      long jj = 0;
      for (; jj <= a_sz-16; jj += 16) {
         ll_type acc;

         long j = jj;

         ll_mul(acc, a_data[j+0], tbl[j+0]);
         ll_mul_add(acc, a_data[j+1], tbl[j+1]);
         ll_mul_add(acc, a_data[j+2], tbl[j+2]);
         ll_mul_add(acc, a_data[j+3], tbl[j+3]);
         ll_mul_add(acc, a_data[j+4], tbl[j+4]);
         ll_mul_add(acc, a_data[j+5], tbl[j+5]);
         ll_mul_add(acc, a_data[j+6], tbl[j+6]);
         ll_mul_add(acc, a_data[j+7], tbl[j+7]);
         ll_mul_add(acc, a_data[j+8], tbl[j+8]);
         ll_mul_add(acc, a_data[j+9], tbl[j+9]);
         ll_mul_add(acc, a_data[j+10], tbl[j+10]);
         ll_mul_add(acc, a_data[j+11], tbl[j+11]);
         ll_mul_add(acc, a_data[j+12], tbl[j+12]);
         ll_mul_add(acc, a_data[j+13], tbl[j+13]);
         ll_mul_add(acc, a_data[j+14], tbl[j+14]);
         ll_mul_add(acc, a_data[j+15], tbl[j+15]);

         ll_add(acc, acc0);
         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

      if (jj < a_sz) {
         ll_type acc;
         ll_init(acc, acc0);

         long j = jj;

         for (; j <= a_sz-4; j += 4) {
	    ll_mul_add(acc, a_data[j+0], tbl[j+0]);
	    ll_mul_add(acc, a_data[j+1], tbl[j+1]);
	    ll_mul_add(acc, a_data[j+2], tbl[j+2]);
	    ll_mul_add(acc, a_data[j+3], tbl[j+3]);
         }

	 for (; j < a_sz; j++)
	    ll_mul_add(acc, a_data[j+0], tbl[j+0]);

         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

#if (KCTSB_NAIL_BITS == 0 && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS==4)
// DIRT: only works if no nails
// NOTE: this is a very minor optimization
      long res = sp_ll_red_31_normalized(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
#else
      long res = sp_ll_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
#endif
      if (a_neg) res = NegateMod(res, p);
      return res;
   }
   else if (Bnd == 8)  {
      ll_type acc21;
      ll_init(acc21, 0);
      _kctsb_limb_t acc0 = 0;

      long jj = 0;
      for (; jj <= a_sz-8; jj += 8) {
         ll_type acc;

         long j = jj;

         ll_mul(acc, a_data[j+0], tbl[j+0]);
         ll_mul_add(acc, a_data[j+1], tbl[j+1]);
         ll_mul_add(acc, a_data[j+2], tbl[j+2]);
         ll_mul_add(acc, a_data[j+3], tbl[j+3]);
         ll_mul_add(acc, a_data[j+4], tbl[j+4]);
         ll_mul_add(acc, a_data[j+5], tbl[j+5]);
         ll_mul_add(acc, a_data[j+6], tbl[j+6]);
         ll_mul_add(acc, a_data[j+7], tbl[j+7]);

         ll_add(acc, acc0);
         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

      if (jj < a_sz) {
         ll_type acc;
         ll_init(acc, acc0);

         long j = jj;

	 for (; j < a_sz; j++)
	    ll_mul_add(acc, a_data[j+0], tbl[j+0]);

         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

      long res = sp_ll_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
      if (a_neg) res = NegateMod(res, p);
      return res;
   }
   else /* Bnd == 4 */  {
      ll_type acc21;
      ll_init(acc21, 0);
      _kctsb_limb_t acc0 = 0;

      long jj = 0;
      for (; jj <= a_sz-4; jj += 4) {
         ll_type acc;

         long j = jj;

         ll_mul(acc, a_data[j+0], tbl[j+0]);
         ll_mul_add(acc, a_data[j+1], tbl[j+1]);
         ll_mul_add(acc, a_data[j+2], tbl[j+2]);
         ll_mul_add(acc, a_data[j+3], tbl[j+3]);


         ll_add(acc, acc0);
         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

      if (jj < a_sz) {
         ll_type acc;
         ll_init(acc, acc0);

         long j = jj;

	 for (; j < a_sz; j++)
	    ll_mul_add(acc, a_data[j+0], tbl[j+0]);


         acc0 = ll_get_lo(acc);
         ll_add(acc21, ll_get_hi(acc));
      }

#if (KCTSB_NAIL_BITS == 0 && KCTSB_BITS_PER_LONG-KCTSB_SP_NBITS==2)
// DIRT: only works if no nails
// NOTE: this is a very minor optimization
      long res = sp_ll_red_31_normalized(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
#else
      long res = sp_ll_red_31(ll_get_hi(acc21), ll_get_lo(acc21), acc0, p, red_struct);
#endif
      if (a_neg) res = NegateMod(res, p);
      return res;
   }
}

void
_kctsb_general_rem_one_struct_delete(_kctsb_general_rem_one_struct *pinfo) 
{
   delete pinfo;
}


#endif


void
_kctsb_quick_accum_begin(_kctsb_gbigint *xp, long sz)
{
   long sbuf = sz+2;
   _kctsb_gbigint x = *xp;
   if (MustAlloc(x, sbuf)) {
      _kctsb_gsetlength(&x, sbuf);
      *xp = x;
   }

   _kctsb_limb_t *xx = DATA(x);
   for (long i = 0; i < sbuf; i++) xx[i] = 0;
   SIZE(x) = sbuf;
}

void 
_kctsb_quick_accum_muladd(_kctsb_gbigint x, _kctsb_gbigint y, long b)
{
   if (!y) return;

   _kctsb_limb_t *yy = DATA(y);
   long sy = SIZE(y);
   if (!sy || !b) return;

   _kctsb_limb_t *xx = DATA(x);

   _kctsb_limb_t carry = KCTSB_MPN(addmul_1)(xx, yy, sy, b);
   yy = xx + sy;
   *yy = CLIP(*yy + carry);

   if (*yy < carry) { /* unsigned comparison! */
      do {
	 yy++;
	 *yy = CLIP(*yy + 1);
      } while (*yy == 0);
   }
}

void
_kctsb_quick_accum_end(_kctsb_gbigint x)
{
   _kctsb_limb_t *xx = DATA(x);
   long sx = SIZE(x);
   STRIP(sx, xx);
   SIZE(x) = sx;
}


#ifdef KCTSB_PROVIDES_SS_LIP_IMPL

void
_kctsb_leftrotate(_kctsb_gbigint *a, const _kctsb_gbigint *b, long e,
                _kctsb_gbigint p, long n, _kctsb_gbigint *scratch)
{
   if (e == 0 || ZEROP(*b)) {
      _kctsb_gcopy(*b, a);
      return;
   }

   long sb, nwords;

   if (a == b || ((unsigned long) n) % KCTSB_ZZ_NBITS != 0 ||
       (sb = SIZE(*b)) == 1 + (nwords = ((unsigned long) n) / KCTSB_ZZ_NBITS)) {

      _kctsb_grshift(*b, n-e, scratch);
      _kctsb_glowbits(*b, n-e, a);
      _kctsb_glshift(*a, e, a);

      if (_kctsb_gcompare(*a, *scratch) < 0) {
         _kctsb_gswitchbit(a, n);
         _kctsb_gsadd(*a, 1, a);
         _kctsb_gsubpos(*a, *scratch, a);
      }
      else {
         _kctsb_gsubpos(*a, *scratch, a);
      }

      return;
   }

   long ewords = ((unsigned long) e) / KCTSB_ZZ_NBITS;
   long ebits  = ((unsigned long) e) % KCTSB_ZZ_NBITS;

   if (MustAlloc(*a, nwords+1)) _kctsb_gsetlength(a, nwords+1);

   _kctsb_limb_t *adata = DATA(*a);
   _kctsb_limb_t *bdata = DATA(*b);


   long special_carry = 0;
   long sa = 0;

   if (ewords) {
      long hiwords = sb - (nwords-ewords);
      if (hiwords > 0) {

         _kctsb_limb_t borrow = KCTSB_MPN(neg)(adata, bdata + (nwords-ewords),
                                           hiwords); 
         if (hiwords < ewords) {
            if (borrow) {
               for (long i = hiwords; i < ewords; i++) 
                  adata[i] = _kctsb_limb_t(-1); 
            }
            else {
               for (long i = hiwords; i < ewords; i++) 
                  adata[i] = 0;
            }
         }

         if (borrow) {
            borrow = KCTSB_MPN(sub_1)(adata + ewords, bdata, nwords-ewords, 1);
            if (borrow) {
               special_carry = KCTSB_MPN(add_1)(adata, adata, nwords, 1);
               // special case: result so far is 2^n
            }
         }
         else {
            for (long i = 0; i < nwords-ewords; i++) adata[i+ewords] = bdata[i];
         }

         sa = nwords;         
      }
      else {
         for (long i = 0; i < ewords; i++) adata[i] = 0;
         for (long i = 0; i < sb; i++) adata[i+ewords] = bdata[i];

         sa = ewords + sb;
      }
   }
   else {
      for (long i = 0; i < sb; i++) adata[i] = bdata[i];
      sa = sb;
   }

   long here = 0;

   if (ebits) {
      if (special_carry) {
         KCTSB_MPN(sub_1)(adata, adata, nwords, (1L << ebits) - 1L);
      }
      else if (sa == nwords) {
         _kctsb_limb_t shout = KCTSB_MPN(lshift)(adata, adata, sa, ebits);
         if (shout) {
            _kctsb_limb_t borrow = KCTSB_MPN(sub_1)(adata, adata, sa, shout);
            if (borrow) {
               _kctsb_limb_t carry = KCTSB_MPN(add_1)(adata, adata, sa, 1);
               if (carry) {
                  adata[sa] = 1;
                  sa++;
               }
            }
         }
      }
      else { // sa < nwords
         _kctsb_limb_t shout = KCTSB_MPN(lshift)(adata, adata, sa, ebits);
         if (shout) {
            adata[sa] = shout;
            sa++;
         }
      }
   }
   else {
      if (special_carry) {
         adata[sa] = 1;
         sa++;
      }
   }

   STRIP(sa, adata);
   SIZE(*a) = sa;

}

void 
_kctsb_ss_addmod(_kctsb_gbigint *x, const _kctsb_gbigint *a,
               const _kctsb_gbigint *b, _kctsb_gbigint p, long n)
{
   if (((unsigned long) n) % KCTSB_ZZ_NBITS != 0) { 
      _kctsb_gadd(*a, *b, x);
      if (_kctsb_gcompare(*x, p) >= 0) {
         _kctsb_gsadd(*x, -1, x);
         _kctsb_gswitchbit(x, n);
      }
   }
   else {
      _kctsb_gadd(*a, *b, x);
      long sx, nwords;
      if (!*x ||
          (sx = SIZE(*x)) <= (nwords = ((unsigned long) n) / KCTSB_ZZ_NBITS))
         return;

      _kctsb_limb_t *xdata = DATA(*x);
      if (xdata[nwords] == 2) {
         for (long i = 0; i < nwords; i++) xdata[i] = _kctsb_limb_t(-1);
         SIZE(*x) = nwords;
         return;
      }

      long i = nwords-1;
      while (i >= 0 && xdata[i] == 0) i--;
      if (i < 0) return;

      KCTSB_MPN(sub_1)(xdata, xdata, nwords, 1);
      sx = nwords;
      STRIP(sx, xdata);
      SIZE(*x) = sx;
   }
}


void 
_kctsb_ss_submod(_kctsb_gbigint *x, const _kctsb_gbigint *a,
               const _kctsb_gbigint *b, _kctsb_gbigint p, long n)
{
   if (((unsigned long) n) % KCTSB_ZZ_NBITS != 0) {
      if (_kctsb_gcompare(*a, *b) < 0) {
         _kctsb_gadd(*a, p, x);
         _kctsb_gsubpos(*x, *b, x);
      }
      else {
         _kctsb_gsubpos(*a, *b, x);
      }
   }
   else {
      if (ZEROP(*b)) {
         _kctsb_gcopy(*a, x);
         return;
      }

      long sb = SIZE(*b);
      _kctsb_limb_t *bdata = DATA(*b);

      long sa;

      if (!*a) 
         sa = 0;
      else
         sa = SIZE(*a);

      long nwords = ((unsigned long) n) / KCTSB_ZZ_NBITS;
      if (MustAlloc(*x, nwords+1)) _kctsb_gsetlength(x, nwords+1);
      _kctsb_limb_t *xdata = DATA(*x);

      if (sa >= sb) {
         _kctsb_limb_t *adata = DATA(*a);
         _kctsb_limb_t borrow = KCTSB_MPN(sub)(xdata, adata, sa, bdata, sb);
         if (borrow) {
            for (long i = sa; i < nwords; i++) xdata[i] = _kctsb_limb_t(-1);
            _kctsb_limb_t carry = KCTSB_MPN(add_1)(xdata, xdata, nwords, 1);
            if (carry) {
               xdata[nwords] = 1;
               SIZE(*x) = nwords+1;
            }
            else {
               long sx = nwords;
               STRIP(sx, xdata);
               SIZE(*x) = sx;
            }
         }
         else {
            long sx = sa;
            STRIP(sx, xdata);
            SIZE(*x) = sx;
         }
      }
      else {
         if (sa == 0) {
            xdata[0] = 1;
         }
         else {
            _kctsb_limb_t *adata = DATA(*a); 
            xdata[sa] = KCTSB_MPN(add_1)(xdata, adata, sa, 1);
         }
         for (long i = sa+1; i <= nwords; i++) xdata[i] = 0;
         xdata[nwords]++;
         _kctsb_limb_t borrow = KCTSB_MPN(sub_n)(xdata, xdata, bdata, sb);
         if (borrow) {
            KCTSB_MPN(sub_1)(xdata+sb, xdata+sb, nwords+1-sb, 1);
         }
         long sx = nwords+1;
         STRIP(sx, xdata);
         SIZE(*x) = sx;
      }
   }
}

#endif



