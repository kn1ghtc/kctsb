
#include <kctsb/math/bignum/BasicThreadPool.h>

// make a global symbol, just to supress warnings
int _kctsb_BasicThreadPool_dummy_symbol = 0;

#ifdef KCTSB_THREAD_BOOST

KCTSB_START_IMPL


KCTSB_TLS_GLOBAL_DECL(UniquePtr<BasicThreadPool>, KctsbThreadPool_stg)

KCTSB_CHEAP_THREAD_LOCAL BasicThreadPool *KctsbThreadPool_ptr = 0;

void ResetThreadPool(BasicThreadPool *pool)
{
   KCTSB_TLS_GLOBAL_ACCESS(KctsbThreadPool_stg);
   KctsbThreadPool_stg.reset(pool);
   KctsbThreadPool_ptr = pool;
}

BasicThreadPool *ReleaseThreadPool()
{
   KCTSB_TLS_GLOBAL_ACCESS(KctsbThreadPool_stg);
   BasicThreadPool *pool = KctsbThreadPool_stg.release();
   KctsbThreadPool_ptr = 0;
   return pool;
}



KCTSB_END_IMPL

#endif
