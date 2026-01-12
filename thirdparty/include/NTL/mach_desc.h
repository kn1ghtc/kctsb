/**
 * NTL Machine Description for Windows 64-bit (LLP64 model)
 * 
 * Windows LLP64 Data Model:
 *   - char:      8 bits
 *   - short:     16 bits
 *   - int:       32 bits
 *   - long:      32 bits (differs from Unix LP64 where long = 64 bits)
 *   - long long: 64 bits
 *   - pointer:   64 bits
 *   - size_t:    64 bits
 * 
 * This configuration is for MinGW-w64/GCC on Windows 64-bit.
 * Generated for kctsb v3.0.0
 */

#ifndef NTL_mach_desc__H
#define NTL_mach_desc__H

/* Windows 64-bit LLP64: long = 32 bits */
#define NTL_BITS_PER_LONG (32)
#define NTL_NUMBITS_BPL (5)
#define NTL_MAX_LONG (2147483647L)
#define NTL_MIN_LONG (-NTL_MAX_LONG - 1L)

/* int = 32 bits */
#define NTL_BITS_PER_INT (32)
#define NTL_MAX_INT (2147483647)
#define NTL_MIN_INT (-NTL_MAX_INT - 1)

/* size_t = 64 bits on Windows 64-bit */
#define NTL_BITS_PER_SIZE_T (64)

/* Arithmetic right shift available */
#define NTL_ARITH_RIGHT_SHIFT (1)

/* SP (single precision) modular arithmetic bounds */
/* For 32-bit long, NTL_SP_NBITS is typically 30 */
#define NTL_NBITS_MAX (30)
#define NTL_WNBITS_MAX (30)

/* Floating point precision */
#define NTL_DOUBLE_PRECISION (53)
#define NTL_FDOUBLE_PRECISION (((double)(1L<<30))*((double)(1L<<22)))
#define NTL_WIDE_DOUBLE_DP ((wide_double(1L<<26))*(wide_double(1L<<26)))
#define NTL_QUAD_FLOAT_SPLIT ((((double)(1L<<13))+1.0))

/* Long double support - disabled for portability */
#define NTL_LONGDOUBLE_OK (0)

/* Extended double precision - not available */
#define NTL_EXT_DOUBLE (0)

/* FMA (Fused Multiply-Add) - disabled for portability */
#define NTL_FMA_DETECTED (0)

/* BIG_POINTERS: sizeof(void*) > sizeof(long) on Windows 64-bit */
#define NTL_BIG_POINTERS (1)


/*
 * GF2X multiplication macros for 32-bit long
 * These implement binary polynomial multiplication in GF(2)[x]
 */

/* BB_MUL1_BITS - number of bits for lookup table (4 for 16-entry table) */
#define NTL_BB_MUL1_BITS (4)


/* mul1: c[0..1] = a * b where a,b are single words */
#define NTL_BB_MUL_CODE0 \
   _ntl_ulong hi, lo, t;\
   _ntl_ulong A[16];\
   A[0] = 0;\
   A[1] = a;\
   A[2] = A[1] << 1;\
   A[3] = A[2] ^ A[1];\
   A[4] = A[2] << 1;\
   A[5] = A[4] ^ A[1];\
   A[6] = A[3] << 1;\
   A[7] = A[6] ^ A[1];\
   A[8] = A[4] << 1;\
   A[9] = A[8] ^ A[1];\
   A[10] = A[5] << 1;\
   A[11] = A[10] ^ A[1];\
   A[12] = A[6] << 1;\
   A[13] = A[12] ^ A[1];\
   A[14] = A[7] << 1;\
   A[15] = A[14] ^ A[1];\
   lo = A[b & 15]; t = A[(b >> 4) & 15]; hi = t >> 28; lo ^= t << 4;\
   t = A[(b >> 8) & 15]; hi ^= t >> 24; lo ^= t << 8;\
   t = A[(b >> 12) & 15]; hi ^= t >> 20; lo ^= t << 12;\
   t = A[(b >> 16) & 15]; hi ^= t >> 16; lo ^= t << 16;\
   t = A[(b >> 20) & 15]; hi ^= t >> 12; lo ^= t << 20;\
   t = A[(b >> 24) & 15]; hi ^= t >> 8; lo ^= t << 24;\
   t = A[b >> 28]; hi ^= t >> 4; lo ^= t << 28;\
   if (a >> 31) hi ^= ((b & 0xeeeeeeeeUL) >> 1);\
   if ((a >> 30) & 1) hi ^= ((b & 0xccccccccUL) >> 2);\
   if ((a >> 29) & 1) hi ^= ((b & 0x88888888UL) >> 3);\
   c[0] = lo; c[1] = hi;


/* Mul1: cp[0..sb] = bp[0..sb-1] * a */
#define NTL_BB_MUL_CODE1 \
   long i;\
   _ntl_ulong carry = 0, b;\
   _ntl_ulong hi, lo, t;\
   _ntl_ulong A[16];\
   A[0] = 0;\
   A[1] = a;\
   A[2] = A[1] << 1;\
   A[3] = A[2] ^ A[1];\
   A[4] = A[2] << 1;\
   A[5] = A[4] ^ A[1];\
   A[6] = A[3] << 1;\
   A[7] = A[6] ^ A[1];\
   A[8] = A[4] << 1;\
   A[9] = A[8] ^ A[1];\
   A[10] = A[5] << 1;\
   A[11] = A[10] ^ A[1];\
   A[12] = A[6] << 1;\
   A[13] = A[12] ^ A[1];\
   A[14] = A[7] << 1;\
   A[15] = A[14] ^ A[1];\
   for (i = 0; i < sb; i++) {\
      b = bp[i];\
      lo = A[b & 15]; t = A[(b >> 4) & 15]; hi = t >> 28; lo ^= t << 4;\
      t = A[(b >> 8) & 15]; hi ^= t >> 24; lo ^= t << 8;\
      t = A[(b >> 12) & 15]; hi ^= t >> 20; lo ^= t << 12;\
      t = A[(b >> 16) & 15]; hi ^= t >> 16; lo ^= t << 16;\
      t = A[(b >> 20) & 15]; hi ^= t >> 12; lo ^= t << 20;\
      t = A[(b >> 24) & 15]; hi ^= t >> 8; lo ^= t << 24;\
      t = A[b >> 28]; hi ^= t >> 4; lo ^= t << 28;\
      if (a >> 31) hi ^= ((b & 0xeeeeeeeeUL) >> 1);\
      if ((a >> 30) & 1) hi ^= ((b & 0xccccccccUL) >> 2);\
      if ((a >> 29) & 1) hi ^= ((b & 0x88888888UL) >> 3);\
      cp[i] = carry ^ lo; carry = hi;\
   }\
   cp[sb] = carry;


/* AddMul1: cp[0..sb] ^= bp[0..sb-1] * a
 * Function signature: AddMul1(_ntl_ulong *cp, const _ntl_ulong* bp, long sb, _ntl_ulong a) */
#define NTL_BB_MUL_CODE2 \
   long i;\
   _ntl_ulong carry = 0, b;\
   _ntl_ulong hi, lo, t;\
   _ntl_ulong A[16];\
   A[0] = 0;\
   A[1] = a;\
   A[2] = A[1] << 1;\
   A[3] = A[2] ^ A[1];\
   A[4] = A[2] << 1;\
   A[5] = A[4] ^ A[1];\
   A[6] = A[3] << 1;\
   A[7] = A[6] ^ A[1];\
   A[8] = A[4] << 1;\
   A[9] = A[8] ^ A[1];\
   A[10] = A[5] << 1;\
   A[11] = A[10] ^ A[1];\
   A[12] = A[6] << 1;\
   A[13] = A[12] ^ A[1];\
   A[14] = A[7] << 1;\
   A[15] = A[14] ^ A[1];\
   for (i = 0; i < sb; i++) {\
      b = bp[i];\
      lo = A[b & 15]; t = A[(b >> 4) & 15]; hi = t >> 28; lo ^= t << 4;\
      t = A[(b >> 8) & 15]; hi ^= t >> 24; lo ^= t << 8;\
      t = A[(b >> 12) & 15]; hi ^= t >> 20; lo ^= t << 12;\
      t = A[(b >> 16) & 15]; hi ^= t >> 16; lo ^= t << 16;\
      t = A[(b >> 20) & 15]; hi ^= t >> 12; lo ^= t << 20;\
      t = A[(b >> 24) & 15]; hi ^= t >> 8; lo ^= t << 24;\
      t = A[b >> 28]; hi ^= t >> 4; lo ^= t << 28;\
      if (a >> 31) hi ^= ((b & 0xeeeeeeeeUL) >> 1);\
      if ((a >> 30) & 1) hi ^= ((b & 0xccccccccUL) >> 2);\
      if ((a >> 29) & 1) hi ^= ((b & 0x88888888UL) >> 3);\
      cp[i] ^= (carry ^ lo); carry = hi;\
   }\
   cp[sb] ^= carry;


/* Mul1_short: optimized for short vectors */
#define NTL_SHORT_BB_MUL_CODE1 \
   long i;\
   _ntl_ulong carry = 0, b;\
   _ntl_ulong hi, lo, t;\
   _ntl_ulong A[16];\
   A[0] = 0;\
   A[1] = a;\
   A[2] = A[1] << 1;\
   A[3] = A[2] ^ A[1];\
   A[4] = A[2] << 1;\
   A[5] = A[4] ^ A[1];\
   A[6] = A[3] << 1;\
   A[7] = A[6] ^ A[1];\
   A[8] = A[4] << 1;\
   A[9] = A[8] ^ A[1];\
   A[10] = A[5] << 1;\
   A[11] = A[10] ^ A[1];\
   A[12] = A[6] << 1;\
   A[13] = A[12] ^ A[1];\
   A[14] = A[7] << 1;\
   A[15] = A[14] ^ A[1];\
   for (i = 0; i < sb; i++) {\
      b = bp[i];\
      lo = A[b & 15]; t = A[(b >> 4) & 15]; hi = t >> 28; lo ^= t << 4;\
      t = A[(b >> 8) & 15]; hi ^= t >> 24; lo ^= t << 8;\
      t = A[(b >> 12) & 15]; hi ^= t >> 20; lo ^= t << 12;\
      t = A[(b >> 16) & 15]; hi ^= t >> 16; lo ^= t << 16;\
      t = A[(b >> 20) & 15]; hi ^= t >> 12; lo ^= t << 20;\
      t = A[(b >> 24) & 15]; hi ^= t >> 8; lo ^= t << 24;\
      t = A[b >> 28]; hi ^= t >> 4; lo ^= t << 28;\
      if (a >> 31) hi ^= ((b & 0xeeeeeeeeUL) >> 1);\
      if ((a >> 30) & 1) hi ^= ((b & 0xccccccccUL) >> 2);\
      if ((a >> 29) & 1) hi ^= ((b & 0x88888888UL) >> 3);\
      cp[i] = carry ^ lo; carry = hi;\
   }\
   cp[sb] = carry;


/* mul_half: c[0] = low half of a * b (no high bits)
 * Function signature: mul_half(_ntl_ulong *c, _ntl_ulong a, _ntl_ulong b) */
#define NTL_HALF_BB_MUL_CODE0 \
   _ntl_ulong lo, t;\
   _ntl_ulong A[16];\
   A[0] = 0;\
   A[1] = a;\
   A[2] = A[1] << 1;\
   A[3] = A[2] ^ A[1];\
   A[4] = A[2] << 1;\
   A[5] = A[4] ^ A[1];\
   A[6] = A[3] << 1;\
   A[7] = A[6] ^ A[1];\
   A[8] = A[4] << 1;\
   A[9] = A[8] ^ A[1];\
   A[10] = A[5] << 1;\
   A[11] = A[10] ^ A[1];\
   A[12] = A[6] << 1;\
   A[13] = A[12] ^ A[1];\
   A[14] = A[7] << 1;\
   A[15] = A[14] ^ A[1];\
   lo = A[b & 15]; t = A[(b >> 4) & 15]; lo ^= t << 4;\
   t = A[(b >> 8) & 15]; lo ^= t << 8;\
   t = A[(b >> 12) & 15]; lo ^= t << 12;\
   c[0] = lo;


/* sqr1: c[0..1] = a^2 using lookup table
 * sqrtab[256] is defined in GF2X.cpp
 * Function declares: _ntl_ulong hi, lo; before calling this macro
 * Then function does: c[0] = lo; c[1] = hi; after this macro */
#define NTL_BB_SQR_CODE \
lo=sqrtab[a&255];\
lo=lo|(sqrtab[(a>>8)&255]<<16);\
hi=sqrtab[(a>>16)&255];\
hi=hi|(sqrtab[(a>>24)&255]<<16);


/* rev1: reverse bits of a using lookup table
 * revtab[256] is defined in GF2X.cpp
 * This is a pure expression - used as: return NTL_BB_REV_CODE; */
#define NTL_BB_REV_CODE \
(revtab[(a>>0)&255]<<24)|(revtab[(a>>8)&255]<<16)|(revtab[(a>>16)&255]<<8)|(revtab[(a>>24)&255]<<0)


#endif /* NTL_mach_desc__H */

