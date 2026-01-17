/**
 * @file pthread.h
 * @brief Minimal pthread stub for Windows/clangd compatibility
 *
 * This is a minimal stub header to satisfy NTL's pthread.h include
 * when analyzing code with clangd on Windows. The actual pthread
 * functionality is not needed because:
 * 1. NTL_TLS_HACK is disabled on Windows in NTL/config.h
 * 2. Windows uses native TLS (__declspec(thread) or thread_local)
 *
 * For actual pthread support on Windows, use:
 * - MinGW's pthread implementation
 * - pthreads-win32 library
 * - vcpkg install pthreads
 *
 * @note This file is only for IDE/clangd compatibility, not for actual builds
 */

#ifndef _PTHREAD_H_STUB
#define _PTHREAD_H_STUB

#ifdef __cplusplus
extern "C" {
#endif

/* Basic pthread types - minimal definitions for clangd */
typedef void* pthread_t;
typedef void* pthread_attr_t;
typedef void* pthread_mutex_t;
typedef void* pthread_mutexattr_t;
typedef void* pthread_cond_t;
typedef void* pthread_condattr_t;
typedef void* pthread_rwlock_t;
typedef void* pthread_rwlockattr_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;

/* Thread functions */
int pthread_create(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
int pthread_join(pthread_t, void**);
int pthread_detach(pthread_t);
pthread_t pthread_self(void);
int pthread_equal(pthread_t, pthread_t);
void pthread_exit(void*);

/* Thread-specific data (TLS) - used by NTL_TLS_HACK */
int pthread_key_create(pthread_key_t*, void (*)(void*));
int pthread_key_delete(pthread_key_t);
void* pthread_getspecific(pthread_key_t);
int pthread_setspecific(pthread_key_t, const void*);

/* Mutex functions */
int pthread_mutex_init(pthread_mutex_t*, const pthread_mutexattr_t*);
int pthread_mutex_destroy(pthread_mutex_t*);
int pthread_mutex_lock(pthread_mutex_t*);
int pthread_mutex_trylock(pthread_mutex_t*);
int pthread_mutex_unlock(pthread_mutex_t*);

/* Condition variable functions */
int pthread_cond_init(pthread_cond_t*, const pthread_condattr_t*);
int pthread_cond_destroy(pthread_cond_t*);
int pthread_cond_wait(pthread_cond_t*, pthread_mutex_t*);
int pthread_cond_signal(pthread_cond_t*);
int pthread_cond_broadcast(pthread_cond_t*);

/* Read-write lock functions */
int pthread_rwlock_init(pthread_rwlock_t*, const pthread_rwlockattr_t*);
int pthread_rwlock_destroy(pthread_rwlock_t*);
int pthread_rwlock_rdlock(pthread_rwlock_t*);
int pthread_rwlock_wrlock(pthread_rwlock_t*);
int pthread_rwlock_unlock(pthread_rwlock_t*);

/* Initialization constants */
#define PTHREAD_MUTEX_INITIALIZER ((pthread_mutex_t)0)
#define PTHREAD_COND_INITIALIZER ((pthread_cond_t)0)
#define PTHREAD_RWLOCK_INITIALIZER ((pthread_rwlock_t)0)
#define PTHREAD_ONCE_INIT 0

#ifdef __cplusplus
}
#endif

#endif /* _PTHREAD_H_STUB */
