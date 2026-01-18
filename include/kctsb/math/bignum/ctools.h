
#ifndef KCTSB_ctools__H
#define KCTSB_ctools__H

#include <kctsb/math/bignum/config.h>
#include <kctsb/math/bignum/mach_desc.h>

#include <kctsb/math/bignum/ALL_FEATURES.h>

#include <kctsb/math/bignum/PackageInfo.h>

#if (defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)))
#define KCTSB_GNUC_INTEL
#endif

#if (!defined(KCTSB_HAVE_LL_TYPE) && defined(KCTSB_WINPACK) &&  (defined(_MSC_VER) || defined(KCTSB_GNUC_INTEL)))
// for the windows distribution, 
//   we assume LL_TYPE works for MSVC++ (which is true for both x86 and ARM)
//   and for GNUC/Intel platforms (e.g., Code Blocks)
#define KCTSB_HAVE_LL_TYPE
#endif

// Define the working C++ standard.
// Both KCTSB_STD_CXX14 and KCTSB_STD_CXX11, and we take the highest one

#if defined(KCTSB_STD_CXX14)
#define KCTSB_CXX_STANDARD (2014)
#elif defined(KCTSB_STD_CXX11)
#define KCTSB_CXX_STANDARD (2011)
#else
#define KCTSB_CXX_STANDARD (1998)
#endif

// define some macros regarding noexcept declarations

#if (KCTSB_CXX_STANDARD >= 2011)

#define KCTSB_NOEXCEPT noexcept

#ifdef KCTSB_EXCEPTIONS
#define KCTSB_FAKE_NOEXCEPT
#else
#define KCTSB_FAKE_NOEXCEPT noexcept
#endif

#else

#define KCTSB_NOEXCEPT 
#define KCTSB_FAKE_NOEXCEPT

#endif


/*
 * Resolve double-word integer type.
 *
 * Unfortunately, there is no "standard" way to do this.
 * On 32-bit machines, 'long long' usually works (but not
 * on MSVC++ or BORLAND), and on 64-bit machines, there is
 * no standard.  However, most compilers do offer *some*
 * non-standard double-word type.  
 *
 * Note that C99 creates a standard header <stdint.h>,
 * but it is not clear how widely this is implemented,
 * and for example, older versions of GCC does not provide a type int128_t 
 * in <stdint.h> on 64-bit machines.
 */



#if (defined(KCTSB_UNSIGNED_LONG_LONG_TYPE))

#define KCTSB_ULL_TYPE KCTSB_UNSIGNED_LONG_LONG_TYPE

#elif (KCTSB_BITS_PER_LONG == 64 && defined(__GNUC__))

#define KCTSB_ULL_TYPE __uint128_t 

#elif (KCTSB_BITS_PER_LONG == 32 && (defined(_MSC_VER) || defined(__BORLANDC__)))

#define KCTSB_ULL_TYPE unsigned __int64

#elif (KCTSB_BITS_PER_LONG == 64 && (defined(_MSC_VER) || defined(__BORLANDC__)))

#define KCTSB_ULL_TYPE unsigned __int128

#endif

#if (!defined(KCTSB_ULL_TYPE))

#define KCTSB_ULL_TYPE unsigned long long

#endif


#ifdef KCTSB_HAVE_LL_TYPE

typedef KCTSB_ULL_TYPE _kctsb_ulonglong;
// typenames are more convenient than macros

#else

#undef KCTSB_ULL_TYPE
// prevent any use of these macros

class _kctsb_ulonglong { private: _kctsb_ulonglong() { } };
// cannot create variables of these types


#endif

/********************************************************/



// Define an unsigned type with at least 32 bits
// there is no truly portable way to do this, yet...


#if (KCTSB_BITS_PER_INT >= 32)

typedef unsigned int _kctsb_uint32; // 32-bit word
#define KCTSB_BITS_PER_INT32 KCTSB_BITS_PER_INT

#else

// NOTE: C++ standard guarantees longs are at least 32-bits wide,
// and this is also explicitly checked at builod time

typedef unsigned long _kctsb_uint32; // 32-bit word
#define KCTSB_BITS_PER_INT32 KCTSB_BITS_PER_LONG

#endif



// The usual token pasting stuff...

#define KCTSB_PASTE_TOKENS2(a,b) a ## b
#define KCTSB_PASTE_TOKENS(a,b) KCTSB_PASTE_TOKENS2(a,b)

#define KCTSB_STRINGIFY(x) KCTSB_STRINGIFY_AUX(x)
#define KCTSB_STRINGIFY_AUX(x) #x






// KCTSB_OVFBND: General bound to keep integer values bounded away from overflow
// With KCTSB_BITS_PER_LONG properly set to 32 on Windows, this is safe
#define KCTSB_OVFBND (1L << (KCTSB_BITS_PER_LONG-4))

/*
 * KCTSB_OVFBND is the general bound used throughout bignum to keep various
 * integer values comfortably bounded away from an integer overflow
 * condition.  Do not change this value!
 */





#if ((KCTSB_BITS_PER_SIZE_T-1) < (KCTSB_BITS_PER_LONG-4))
#define KCTSB_OVFBND1 (1L << (KCTSB_BITS_PER_SIZE_T-1))
#else
#define KCTSB_OVFBND1 KCTSB_OVFBND
#endif

/*
 * KCTSB_OVFBND1 is a smaller bound than KCTSB_OVF when size_t is
 * narrower than long.  This prevents overflow on calls to malloc
 * and realloc.
 */






#define KCTSB_OVERFLOW(n, a, b) \
   (((b) >= KCTSB_OVFBND) || (((long) (n)) > 0 && (((a) >= KCTSB_OVFBND) || \
    (((long) (n)) >= (KCTSB_OVFBND-((long)(b))+((long)(a))-1)/((long)(a))))))

/*
 * KCTSB_OVERFLOW(n, a, b) returns 1 if n*a + b >= KCTSB_OVFBND,
 * and returns 0 otherwise.  The value n is effectively treated as type long,
 * while the values a and b may be *any* integral type.  It is assumed that
 * n >= 0, a > 0, and b >= 0.  Care is taken to ensure that overflow does
 * not occur. If a and b are constants, and n has no side effects,
 * a good optimizing compiler will * translate this into a single test 
 * of the form n >= c, where c is a constant.
 */






#define KCTSB_OVERFLOW1(n, a, b) \
   (((b) >= KCTSB_OVFBND1) || (((long) (n)) > 0 && (((a) >= KCTSB_OVFBND1) || \
    (((long) (n)) >= (KCTSB_OVFBND1-((long)(b))+((long)(a))-1)/((long)(a))))))

/*
 * KCTSB_OVERFLOW1 is the same as KCTSB_OVERFLOW, except that it uses the
 * bound KCTSB_OVFBND1 instead of KCTSB_OVFBND.
 */




#ifdef KCTSB_TEST_EXCEPTIONS

extern unsigned long exception_counter;

#define KCTSB_BASIC_MALLOC(n, a, b) \
   (KCTSB_OVERFLOW1(n, a, b) ? ((void *) 0) : \
    ((void *) malloc(((long)(n))*((long)(a)) + ((long)(b)))))

#define KCTSB_MALLOC(n, a, b) \
   (--exception_counter == 0 ? (void *) 0 : KCTSB_BASIC_MALLOC(n, a, b))

#else

#define KCTSB_MALLOC(n, a, b) \
   (KCTSB_OVERFLOW1(n, a, b) ? ((void *) 0) : \
    ((void *) malloc(((long)(n))*((long)(a)) + ((long)(b)))))


#endif

/*
 * KCTSB_MALLOC(n, a, b) returns 0 if a*n + b >= KCTSB_OVFBND1, and otherwise
 * returns malloc(n*a + b). 
 * The programmer must ensure that the name "malloc" is visible
 * at the point in the source code where this macro is expanded.
 */


#ifdef KCTSB_TEST_EXCEPTIONS

#define KCTSB_BASIC_SNS_MALLOC(n, a, b) \
   (KCTSB_OVERFLOW1(n, a, b) ? ((void *) 0) : \
    ((void *) KCTSB_SNS malloc(((long)(n))*((long)(a)) + ((long)(b)))))


#define KCTSB_SNS_MALLOC(n, a, b) \
   (--exception_counter == 0 ? (void *) 0 : KCTSB_BASIC_SNS_MALLOC(n, a, b))


#else

#define KCTSB_SNS_MALLOC(n, a, b) \
   (KCTSB_OVERFLOW1(n, a, b) ? ((void *) 0) : \
    ((void *) KCTSB_SNS malloc(((long)(n))*((long)(a)) + ((long)(b)))))

#endif

/*
 * KCTSB_SNS_MALLOC is the same as KCTSB_MALLOC, except that the call
 * to malloc is prefixed by KCTSB_SNS.
 */








#define KCTSB_REALLOC(p, n, a, b) \
   (KCTSB_OVERFLOW1(n, a, b) ? ((void *) 0) : \
    ((void *) realloc((p), ((long)(n))*((long)(a)) + ((long)(b)))))

/*
 * KCTSB_REALLOC(n, a, b) returns 0 if a*n + b >= KCTSB_OVFBND1, and otherwise
 * returns realloc(p, n*a + b).
 * The programmer must ensure that the name "realloc" is visible
 * at the point in the source code where this macro is expanded.
 */






#define KCTSB_SNS_REALLOC(p, n, a, b) \
   (KCTSB_OVERFLOW1(n, a, b) ? ((void *) 0) : \
    ((void *) KCTSB_SNS realloc((p), ((long)(n))*((long)(a)) + ((long)(b)))))

/*
 * KCTSB_SNS_REALLOC is the same as KCTSB_REALLOC, except that the call
 * to realloc is prefixed by KCTSB_SNS.
 */





#define KCTSB_MAX_ALLOC_BLOCK (40000)

/*
 * KCTSB_MAX_ALLOC_BLOCK is the number of bytes that are allocated in
 * a single block in a number of places throughout bignum (for
 * vec_ZZ_p, ZZVec, vec_GF2X, and GF2XVec).
 */


#define KCTSB_ULONG_TO_LONG(a) \
   ((((unsigned long) a) >> (KCTSB_BITS_PER_LONG-1)) ? \
    (((long) (((unsigned long) a) ^ ((unsigned long) KCTSB_MIN_LONG))) ^ \
       KCTSB_MIN_LONG) : \
    ((long) a))

/* 
 * This macro converts from unsigned long to signed long.  It is portable
 * among platforms for which a long has a 2's complement representation
 * of the same width as an unsigned long.  While it avoids assumptions
 * about the behavior of non-standard conversions,  a good optimizing
 * compiler should turn it into the identity function.
 */


#define KCTSB_UINT_TO_INT(a) \
   ((((unsigned int) a) >> (KCTSB_BITS_PER_INT-1)) ? \
    (((int) (((unsigned int) a) ^ ((unsigned int) KCTSB_MIN_INT))) ^ \
       KCTSB_MIN_INT) : \
    ((int) a))

/* 
 * This macro converts from unsigned int to signed int.  It is portable
 * among platforms for which an int has a 2's complement representation
 * of the same width as an unsigned int.  While it avoids assumptions
 * about the behavior of non-standard conversions,  a good optimizing
 * compiler should turn it into the identity function.
 */


#ifdef KCTSB_THREADS

#define KCTSB_THREAD_LOCAL thread_local 

#ifdef __GNUC__
#define KCTSB_CHEAP_THREAD_LOCAL __thread
#else
#define KCTSB_CHEAP_THREAD_LOCAL thread_local
#endif

#else

#define KCTSB_THREAD_LOCAL 
#define KCTSB_CHEAP_THREAD_LOCAL 

#endif


#define KCTSB_RELEASE_THRESH (128)

/*
 * threshold for releasing scratch memory.
 */



double _kctsb_GetWallTime();


long _kctsb_IsFinite(double *p);
/* This forces a double into memory, and tests if it is "normal";
   that means, not NaN, not +/- infinity, not denormalized, etc.
   Forcing into memory is sometimes necessary on machines 
   with "extended" double precision registers (e.g., Intel x86s)
   to force the standard IEEE format. */

void _kctsb_ForceToMem(double *p);
/* This is do-nothing routine that has the effect of forcing
   a double into memory (see comment above). */


double _kctsb_ldexp(double x, long e);


#define KCTSB_DEFINE_SWAP(T)\
inline void _kctsb_swap(T& a, T& b)\
{\
   T t = a; a = b; b = t;\
}

KCTSB_DEFINE_SWAP(long)
KCTSB_DEFINE_SWAP(int)
KCTSB_DEFINE_SWAP(short)
KCTSB_DEFINE_SWAP(char)

KCTSB_DEFINE_SWAP(unsigned long)
KCTSB_DEFINE_SWAP(unsigned int)
KCTSB_DEFINE_SWAP(unsigned short)
KCTSB_DEFINE_SWAP(unsigned char)

KCTSB_DEFINE_SWAP(double)
KCTSB_DEFINE_SWAP(float)

   
template<class T>
void _kctsb_swap(T*& a, T*& b)
{
   T* t = a; a = b; b = t;
}

/* These are convenience routines.  I don't want it to overload
   the std library's swap function, nor do I want to rely on the latter,
   as the C++ standard is kind of broken on the issue of where
   swap is defined. And I also only want it defined for built-in types.
 */


// The following do for "move" what the above does for swap

#define KCTSB_DEFINE_SCALAR_MOVE(T)\
inline T _kctsb_scalar_move(T& a)\
{\
   T t = a; a = 0; return t;\
}

KCTSB_DEFINE_SCALAR_MOVE(long)
KCTSB_DEFINE_SCALAR_MOVE(int)
KCTSB_DEFINE_SCALAR_MOVE(short)
KCTSB_DEFINE_SCALAR_MOVE(char)

KCTSB_DEFINE_SCALAR_MOVE(unsigned long)
KCTSB_DEFINE_SCALAR_MOVE(unsigned int)
KCTSB_DEFINE_SCALAR_MOVE(unsigned short)
KCTSB_DEFINE_SCALAR_MOVE(unsigned char)

KCTSB_DEFINE_SCALAR_MOVE(double)
KCTSB_DEFINE_SCALAR_MOVE(float)

   
template<class T>
T* _kctsb_scalar_move(T*& a)
{
   T *t = a; a = 0; return t;
}





// The following routine increments a pointer so that
// it is properly aligned.  
// It is assumed that align > 0.
// If align is a constant power of 2, it compiles
// into a small handful of simple instructions.

// KCTSB_UPTRINT_T: unsigned integer type that can hold a pointer value
// On Windows x64 (LLP64), pointer is 64-bit but unsigned long is 32-bit
// Use std::uintptr_t from <cstdint> for proper portability
#include <cstdint>
#define KCTSB_UPTRINT_T std::uintptr_t


#ifdef KCTSB_HAVE_ALIGNED_ARRAY

inline
char *_kctsb_make_aligned(char *p, long align)
{
   // Use uintptr_t for portable pointer arithmetic
   std::uintptr_t r = (std::uintptr_t(p)) % (std::uintptr_t(align));
   return p + (((std::uintptr_t(align)) - r) % (std::uintptr_t(align)));
}

#else


inline
char *_kctsb_make_aligned(char *p, long align)
{
   return p;
}


#endif





// The following is for aligning small local arrays
// Equivalent to type x[n], but aligns to align bytes
// Only works for POD types
// NOTE: the gcc aligned attribute might work, but there is
// some chatter on the web that this was (at some point) buggy.
// Not clear what the current status is.
// Anyway, this is only intended for use with gcc on intel
// machines, so it should be OK.


#define KCTSB_ALIGNED_LOCAL_ARRAY(align, x, type, n) \
   char x##__kctsb_hidden_variable_storage[n*sizeof(type)+align]; \
   type *x = (type *) _kctsb_make_aligned(&x##__kctsb_hidden_variable_storage[0], align);


#define KCTSB_AVX_BYTE_ALIGN (32)
#define KCTSB_AVX_DBL_ALIGN (KCTSB_AVX_BYTE_ALIGN/long(sizeof(double)))

#define KCTSB_AVX_LOCAL_ARRAY(x, type, n) KCTSB_ALIGNED_LOCAL_ARRAY(KCTSB_AVX_BYTE_ALIGN, x, type, n)

#define KCTSB_AVX512_BYTE_ALIGN (64)

#define KCTSB_AVX512_LOCAL_ARRAY(x, type, n) KCTSB_ALIGNED_LOCAL_ARRAY(KCTSB_AVX512_BYTE_ALIGN, x, type, n)


#define KCTSB_DEFAULT_ALIGN (128)
// this should be big enough to satisfy any SIMD instructions,
// and it should also be as big as a cache line
// x86 has cache line size of 64, while Aarch64 has cache line size of 128
// The cache line size requirement is not critical for correctness,
// but can lead to better memory performance



#ifdef KCTSB_HAVE_BUILTIN_CLZL

inline long 
_kctsb_count_bits(unsigned long x)
{
   return x ? (KCTSB_BITS_PER_LONG - __builtin_clzl(x)) : 0;
}

#else

inline long 
_kctsb_count_bits(unsigned long x)
{
   if (!x) return 0;

   long res = KCTSB_BITS_PER_LONG;
   while (x < (1UL << (KCTSB_BITS_PER_LONG-1))) {
      x <<= 1;
      res--;
   }

   return res;
}

#endif




#if (!defined(KCTSB_CLEAN_INT) && KCTSB_ARITH_RIGHT_SHIFT && (KCTSB_BITS_PER_LONG == (1 << (KCTSB_NUMBITS_BPL-1))))



inline void
_kctsb_bpl_divrem(long a, long& q, long& r)
{
   q = a >> (KCTSB_NUMBITS_BPL-1);
   r = a & (KCTSB_BITS_PER_LONG-1);
}

#else

inline void
_kctsb_bpl_divrem(long a, long& q, long& r)
{
   q = a / KCTSB_BITS_PER_LONG;
   r = a % KCTSB_BITS_PER_LONG;
   if (r < 0) {
      q--;
      r += KCTSB_BITS_PER_LONG;
   }
}

#endif

inline void
_kctsb_bpl_divrem(unsigned long a, long& q, long& r)
{
   q = a / KCTSB_BITS_PER_LONG;
   r = a % KCTSB_BITS_PER_LONG;
}


// vectors are grown by a factor of 1.5
inline long _kctsb_vec_grow(long n)
{ return n + n/2; }


template <class T>
struct _kctsb_is_char_pointer
{
 enum {value = false};
};

template <>
struct _kctsb_is_char_pointer<char*>
{
 enum {value = true};
};

template <>
struct _kctsb_is_char_pointer<const char*>
{
 enum {value = true};
};

template <bool, typename T = void>
struct _kctsb_enable_if
{};

template <typename T>
struct _kctsb_enable_if<true, T> {
  typedef T type;
};


// returns x, disabling constant folding
int _kctsb_nofold(int x); 
long _kctsb_nofold(long x); 
double _kctsb_nofold(double x); 




#endif
