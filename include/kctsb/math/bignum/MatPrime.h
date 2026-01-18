
#ifndef KCTSB_MatPrime__H
#define KCTSB_MatPrime__H

#include <kctsb/math/bignum/ZZ.h>
#include <kctsb/math/bignum/ZZVec.h>
#include <kctsb/math/bignum/lzz_p.h>
#include <kctsb/math/bignum/vector.h>
#include <kctsb/math/bignum/SmartPtr.h>
#include <kctsb/math/bignum/LazyTable.h>

KCTSB_OPEN_NNS

#define KCTSB_MatPrimeFudge (3)
// similar to the FFTPrime strategy...ensures
// we can use floating point to approximate a quotient

#define KCTSB_MatPrimeLimit (1L << 20)
// Limit on dimension for matrix mul



#ifdef KCTSB_HAVE_AVX
#define KCTSB_MatPrime_NBITS (23)
#else
#define KCTSB_MatPrime_NBITS KCTSB_SP_NBITS
#endif

#if (KCTSB_MatPrime_NBITS > KCTSB_SP_NBITS)
// This is mainly academic
#define KCTSB_MatPrime_NBITS KCTSB_SP_NBITS
#endif

#if (KCTSB_MatPrime_NBITS < KCTSB_BITS_PER_INT)
typedef int MatPrime_residue_t;
#else
typedef long MatPrime_residue_t;
#endif

#if (2*KCTSB_MatPrime_NBITS+1 <= KCTSB_SP_NBITS)
#define KCTSB_MatPrime_HALF_SIZE_STRATEGY
#endif


struct MatPrimeInfo {
   long q;   
   zz_pContext context; 
};

void InitMatPrimeInfo(MatPrimeInfo& info, long q, long w);


#define KCTSB_MAX_MATPRIMES (20000)


typedef LazyTable<MatPrimeInfo, KCTSB_MAX_MATPRIMES> MatPrimeTablesType;

extern MatPrimeTablesType MatPrimeTables;
// a truly GLOBAL variable, shared among all threads


inline 
long GetMatPrime(long i)
{
   return MatPrimeTables[i]->q;
}

inline
void RestoreMatPrime(long i)
{
   MatPrimeTables[i]->context.restore();
}

void UseMatPrime(long index);
// allocates and initializes information for Mat prime



#ifndef KCTSB_MatPrime_HALF_SIZE_STRATEGY


struct MatPrime_crt_helper_scratch {
   ZZ t;
};

struct MatPrime_crt_helper {

   long NumPrimes;
   long sz;
   ZZ MinusMModP;  //  -M mod p, M = product of primes

   // the following arrays are indexed 0..NumPrimes-1
   // q[i] = MatPrime[i]
   Vec<long> prime;  // prime[i] = q[i]
   Vec<double> prime_recip;  // prime_recip[i] = 1/double(q[i])
   Vec<long> u;  // u[i] = (M/q[i])^{-1} mod q[i]
   Vec<mulmod_precon_t> uqinv;
   Vec<const sp_ZZ_reduce_struct*> ZZ_red_struct;

   ZZVec coeff;

   ZZ_ReduceStructAdapter montgomery_struct;

   long GetNumPrimes() const { return NumPrimes; }

   double cost;
   double GetCost() const { return cost; }


};


#else



struct MatPrime_crt_helper_scratch {
   ZZ t;
};

struct MatPrime_crt_helper {

   long NumPrimes;
   long sz;
   ZZ MinusMModP;  //  -M mod p, M = product of primes

   // the following arrays are indexed 0..NumPrimes-1
   // q[i] = MatPrime[i]
   Vec<long> prime;  // prime[i] = q[i]
   Vec<double> prime_recip;  // prime_recip[i] = 1/double(q[i])
   Vec<long> u;  // u[i] = (M/q[i])^{-1} mod q[i]
   Vec<mulmod_precon_t> uqinv;
   Vec<sp_reduce_struct> red_struct;

   // Indexed 0..ceil(NumPrimes/2)-1
   Vec<sp_ZZ_reduce_struct> ZZ_red_struct;

   // Indexed 0..ceil(NumPrimes/2)-1
   ZZVec coeff;

   ZZ_ReduceStructAdapter montgomery_struct;

   long GetNumPrimes() const { return NumPrimes; }

   double cost;
   double GetCost() const { return cost; }


};

#endif

void build(MatPrime_crt_helper& H, const ZZ& P);

void init_scratch(const MatPrime_crt_helper& H, MatPrime_crt_helper_scratch& scratch);

void reduce(const MatPrime_crt_helper& H, const ZZ& value, MatPrime_residue_t *remainders, 
	    MatPrime_crt_helper_scratch& scratch);

void reconstruct(const MatPrime_crt_helper& H, ZZ& value, const MatPrime_residue_t *remainders, 
		 MatPrime_crt_helper_scratch& scratch);







KCTSB_CLOSE_NNS

#endif
