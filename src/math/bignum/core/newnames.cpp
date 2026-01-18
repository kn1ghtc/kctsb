
/************************************************************************

This program can be compiled under either C or C++.
It copies its input to its output, substituting all old
bignum macro names by new bignum macro names.
This is intended to automate the transition from bignum 3.1 to 3.5.

Each maximal length alphanumeric substring in the input
is looked up in a table, and if there is a match, the substring
is replaced.

*************************************************************************/


#include <stdio.h>
#include <string.h>

#define NumNames (79)

const char *names[NumNames][2] = {
{ "BB_HALF_MUL_CODE", "KCTSB_BB_HALF_MUL_CODE" },
{ "BB_MUL_CODE", "KCTSB_BB_MUL_CODE" },
{ "BB_REV_CODE", "KCTSB_BB_REV_CODE" },
{ "BB_SQR_CODE", "KCTSB_BB_SQR_CODE" },
{ "FFTFudge", "KCTSB_FFTFudge" },
{ "FFTMaxRoot", "KCTSB_FFTMaxRoot" },
{ "FFTMaxRootBnd", "KCTSB_FFTMaxRootBnd" },
{ "QUAD_FLOAT_SPLIT", "KCTSB_QUAD_FLOAT_SPLIT" },
{ "WV_KCTSB_RANGE_CHECK_CODE", "KCTSB_WV_RANGE_CHECK_CODE" },
{ "WordVectorExpansionRatio", "KCTSB_WordVectorExpansionRatio" },
{ "WordVectorInputBlock", "KCTSB_WordVectorInputBlock" },
{ "WordVectorMinAlloc", "KCTSB_WordVectorMinAlloc" },
{ "XD_BOUND", "KCTSB_XD_BOUND" },
{ "XD_BOUND_INV", "KCTSB_XD_BOUND_INV" },
{ "XD_HBOUND", "KCTSB_XD_HBOUND" },
{ "XD_HBOUND_INV", "KCTSB_XD_HBOUND_INV" },
{ "ZZ_ARITH_RIGHT_SHIFT", "KCTSB_ARITH_RIGHT_SHIFT" },
{ "ZZ_BITS_PER_INT", "KCTSB_BITS_PER_INT" },
{ "ZZ_BITS_PER_LONG", "KCTSB_BITS_PER_LONG" },
{ "ZZ_DOUBLES_LOW_HIGH", "KCTSB_DOUBLES_LOW_HIGH" },
{ "ZZ_DOUBLE_PRECISION", "KCTSB_DOUBLE_PRECISION" },
{ "ZZ_EXT_DOUBLE", "KCTSB_EXT_DOUBLE" },
{ "ZZ_FDOUBLE_PRECISION", "KCTSB_FDOUBLE_PRECISION" },
{ "ZZ_FRADIX", "KCTSB_FRADIX" },
{ "ZZ_FRADIX_INV", "KCTSB_FRADIX_INV" },
{ "ZZ_FetchHiLo", "KCTSB_FetchHiLo" },
{ "ZZ_FetchLo", "KCTSB_FetchLo" },
{ "ZZ_HI_WD", "KCTSB_HI_WD" },
{ "ZZ_LO_WD", "KCTSB_LO_WD" },
{ "ZZ_MAX_INT", "KCTSB_MAX_INT" },
{ "ZZ_MAX_LONG", "KCTSB_MAX_LONG" },
{ "ZZ_MIN_INT", "KCTSB_MIN_INT" },
{ "ZZ_MIN_LONG", "KCTSB_MIN_LONG" },
{ "ZZ_NBITS", "KCTSB_NBITS" },
{ "ZZ_NBITSH", "KCTSB_NBITSH" },
{ "ZZ_NBITS_MAX", "KCTSB_NBITS_MAX" },
{ "ZZ_KCTSB_SINGLE_MUL_OK", "KCTSB_SINGLE_MUL_OK" },
{ "ZZ_PRIME_BND", "KCTSB_PRIME_BND" },
{ "ZZ_RADIX", "KCTSB_RADIX" },
{ "ZZ_RADIXM", "KCTSB_RADIXM" },
{ "ZZ_RADIXROOT", "KCTSB_RADIXROOT" },
{ "ZZ_RADIXROOTM", "KCTSB_RADIXROOTM" },
{ "ZZ_pRegister", "KCTSB_ZZ_pRegister" },
{ "ZZ_pX_BERMASS_CROSSOVER", "KCTSB_ZZ_pX_BERMASS_CROSSOVER" },
{ "ZZ_pX_DIV_CROSSOVER", "KCTSB_ZZ_pX_DIV_CROSSOVER" },
{ "ZZ_pX_FFT_CROSSOVER", "KCTSB_ZZ_pX_FFT_CROSSOVER" },
{ "ZZ_pX_GCD_CROSSOVER", "KCTSB_ZZ_pX_GCD_CROSSOVER" },
{ "ZZ_pX_HalfGCD_CROSSOVER", "KCTSB_ZZ_pX_HalfGCD_CROSSOVER" },
{ "ZZ_pX_NEWTON_CROSSOVER", "KCTSB_ZZ_pX_NEWTON_CROSSOVER" },
{ "ZZ_pX_TRACE_CROSSOVER", "KCTSB_ZZ_pX_TRACE_CROSSOVER" },
{ "ntl_eq_matrix_decl", "KCTSB_eq_matrix_decl" },
{ "ntl_eq_matrix_impl", "KCTSB_eq_matrix_impl" },
{ "ntl_eq_vector_decl", "KCTSB_eq_vector_decl" },
{ "ntl_eq_vector_impl", "KCTSB_eq_vector_impl" },
{ "ntl_io_matrix_decl", "KCTSB_io_matrix_decl" },
{ "ntl_io_matrix_impl", "KCTSB_io_matrix_impl" },
{ "ntl_io_vector_decl", "KCTSB_io_vector_decl" },
{ "ntl_io_vector_impl", "KCTSB_io_vector_impl" },
{ "ntl_matrix_decl", "KCTSB_matrix_decl" },
{ "ntl_matrix_impl", "KCTSB_matrix_impl" },
{ "ntl_pair_decl", "KCTSB_pair_decl" },
{ "ntl_pair_eq_decl", "KCTSB_pair_eq_decl" },
{ "ntl_pair_eq_impl", "KCTSB_pair_eq_impl" },
{ "ntl_pair_impl", "KCTSB_pair_impl" },
{ "ntl_pair_io_decl", "KCTSB_pair_io_decl" },
{ "ntl_pair_io_impl", "KCTSB_pair_io_impl" },
{ "ntl_vector_decl", "KCTSB_vector_decl" },
{ "ntl_vector_default", "KCTSB_vector_default" },
{ "ntl_vector_impl", "KCTSB_vector_impl" },
{ "ntl_vector_impl_plain", "KCTSB_vector_impl_plain" },
{ "zz_pRegister", "KCTSB_zz_pRegister" },
{ "zz_pX_BERMASS_CROSSOVER", "KCTSB_zz_pX_BERMASS_CROSSOVER" },
{ "zz_pX_DIV_CROSSOVER", "KCTSB_zz_pX_DIV_CROSSOVER" },
{ "zz_pX_GCD_CROSSOVER", "KCTSB_zz_pX_GCD_CROSSOVER" },
{ "zz_pX_HalfGCD_CROSSOVER", "KCTSB_zz_pX_HalfGCD_CROSSOVER" },
{ "zz_pX_MOD_CROSSOVER", "KCTSB_zz_pX_MOD_CROSSOVER" },
{ "zz_pX_MUL_CROSSOVER", "KCTSB_zz_pX_MUL_CROSSOVER" },
{ "zz_pX_NEWTON_CROSSOVER", "KCTSB_zz_pX_NEWTON_CROSSOVER" },
{ "zz_pX_TRACE_CROSSOVER", "KCTSB_zz_pX_TRACE_CROSSOVER" },
};


void PrintName(const char *name)
{
   int i;

   i = 0;
   while (i < NumNames && strcmp(name, names[i][0]))
      i++;

   if (i >= NumNames)
      printf("%s", name);
   else
      printf("%s", names[i][1]);
}


int IsAlphaNum(int c)
{
   return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c == '_') || (c >= '0' && c <= '9'));
}

char buf[10000];


int main()
{
   int c;
   int state;
   int len;

   state = 0;
   len = 0;


   do {
      c = getchar();

      switch (state) {
      case 0:
         if (IsAlphaNum(c)) {
            buf[len] = c;
            len++;
            state = 1;
         }
         else {
            if (c != EOF) putchar(c);
         }

         break;

      case 1:
         if (IsAlphaNum(c)) {
            buf[len] = c;
            len++;
         }
         else {
            buf[len] = '\0';
            PrintName(buf);
            len = 0;

            if (c != EOF) putchar(c);
            state = 0;
         }

         break;
      }
   } while (c != EOF);
   
   return 0;
}
