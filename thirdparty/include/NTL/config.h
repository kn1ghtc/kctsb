#ifndef NTL_config__H
#define NTL_config__H

/*************************************************************************

                          NTL Configuration File
                          ----------------------

Generated for kctsb v3.0.0 - Windows MinGW-w64 build

 *************************************************************************/

/* TLS hack for thread safety */
#if 1
#define NTL_TLS_HACK
#endif

/* Thread-safe library */
#if 1
#define NTL_THREADS
#endif

/* Thread boost for internal parallelism */
#if 1
#define NTL_THREAD_BOOST
#endif

/* Use GMP for large integer arithmetic */
#if 1
#define NTL_GMP_LIP
#endif

/* C++11 features */
#if 1
#define NTL_STD_CXX11
#endif

/* C++14 features */
#if 1
#define NTL_STD_CXX14
#endif

/* Disable move assignment for stability */
#if 1
#define NTL_DISABLE_MOVE_ASSIGN
#endif

/* Clean pointer arithmetic */
#if 1
#define NTL_CLEAN_PTR
#endif

/* Safe vector operations */
#if 1
#define NTL_SAFE_VECTORS
#endif

/* No init trans optimization */
#if 1
#define NTL_NO_INIT_TRANS
#endif

/* Performance tuning for generic architecture */
#if 1
#define NTL_SPMM_ULL
#endif

#if 1
#define NTL_AVOID_BRANCHING
#endif

#if 1
#define NTL_FFT_BIGTAB
#endif

#if 1
#define NTL_FFT_LAZYMUL
#endif

#if 1
#define NTL_TBL_REM
#endif

#if 1
#define NTL_CRT_ALTCODE
#endif

/* Note: GF2X_ALTCODE1 requires platform-specific MUL macros */
/* Disabled for Windows generic build */
#if 0
#define NTL_GF2X_ALTCODE1
#endif

/* Windows-specific: enable WINPACK mode */
#if defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__) || defined(__MINGW64__)
#define NTL_WINPACK
#endif

/* sanity checks */
#if (defined(NTL_THREAD_BOOST) && !defined(NTL_THREADS))
#error "NTL_THREAD_BOOST defined but not NTL_THREADS"
#endif

#if (defined(NTL_THREADS) && !(defined(NTL_STD_CXX11) || defined(NTL_STD_CXX14)))
#error "NTL_THREADS defined but not NTL_STD_CXX11 or NTL_STD_CXX14"
#endif

#if (defined(NTL_SAFE_VECTORS) && !(defined(NTL_STD_CXX11) || defined(NTL_STD_CXX14)))
#error "NTL_SAFE_VECTORS defined but not NTL_STD_CXX11 or NTL_STD_CXX14"
#endif

#endif /* NTL_config__H */
