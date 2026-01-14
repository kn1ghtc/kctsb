/**
 * @file security.c
 * @brief Security primitives implementation - Side-channel resistant operations
 *
 * Production-grade implementation of security-critical operations with:
 * - Constant-time execution paths
 * - Platform-specific CSPRNG
 * - Memory safety operations
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/core/security.h"
#include "kctsb/core/common.h"
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#else
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>  /* arc4random_buf on macOS/BSD */
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#endif
#endif

// Compiler memory barrier macros
#if defined(__GNUC__) || defined(__clang__)
#define COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")
#elif defined(_MSC_VER)
#include <intrin.h>
#define COMPILER_BARRIER() _ReadWriteBarrier()
#else
#define COMPILER_BARRIER()
#endif

// ============================================================================
// Secure Memory Operations
// ============================================================================

// Volatile function pointer to prevent optimization
typedef void (*volatile secure_zero_fn)(void*, size_t);

static void secure_zero_impl(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

static secure_zero_fn secure_zero_ptr = secure_zero_impl;

void kctsb_secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;

#ifdef _WIN32
    // Windows secure zero
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    // C11 Annex K
    memset_s(ptr, len, 0, len);
#else
    // Fallback: use volatile pointer to prevent optimization
    secure_zero_ptr(ptr, len);
#endif

    COMPILER_BARRIER();
}

int kctsb_secure_compare(const void* a, const void* b, size_t len) {
    if (!a || !b) return 0;  // Return false for invalid pointers

    const volatile unsigned char* pa = (const volatile unsigned char*)a;
    const volatile unsigned char* pb = (const volatile unsigned char*)b;

    volatile unsigned char diff = 0;

    // Constant-time comparison: always iterate through all bytes
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }

    COMPILER_BARRIER();

    // Return 1 if equal (diff == 0), 0 if different
    return (diff == 0) ? 1 : 0;
}

// ============================================================================
// Constant-Time Operations
// ============================================================================

uint64_t kctsb_ct_select(uint64_t condition, uint64_t a, uint64_t b) {
    // Create mask: all 0s if condition is 0, all 1s otherwise
    uint64_t mask = (uint64_t)(-(int64_t)(condition != 0));
    return (b & mask) | (a & ~mask);
}

void kctsb_ct_swap(uint64_t condition, uint64_t* a, uint64_t* b) {
    if (!a || !b) return;

    // Create mask: all 0s if condition is 0, all 1s otherwise
    uint64_t mask = (uint64_t)(-(int64_t)(condition != 0));

    // XOR swap with conditional mask
    uint64_t t = (*a ^ *b) & mask;
    *a ^= t;
    *b ^= t;
}

int kctsb_secure_copy(void* dest, size_t dest_size, const void* src, size_t count) {
    if (!dest || !src) return -1;
    if (count > dest_size) return -2;

    memcpy(dest, src, count);
    return 0;
}

// ============================================================================
// CSPRNG Implementation
// ============================================================================

#ifdef _WIN32

int kctsb_random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;

    NTSTATUS status = BCryptGenRandom(
        NULL,
        (PUCHAR)buf,
        (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    return (status == STATUS_SUCCESS) ? KCTSB_SUCCESS : KCTSB_ERROR_RANDOM_FAILED;
}

#elif defined(__linux__)

int kctsb_random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;

    unsigned char* p = (unsigned char*)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t ret = getrandom(p, remaining, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            // Fallback to /dev/urandom
            int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
            if (fd < 0) return KCTSB_ERROR_RANDOM_FAILED;

            while (remaining > 0) {
                ret = read(fd, p, remaining);
                if (ret < 0) {
                    if (errno == EINTR) continue;
                    close(fd);
                    return KCTSB_ERROR_RANDOM_FAILED;
                }
                p += ret;
                remaining -= (size_t)ret;
            }
            close(fd);
            return KCTSB_SUCCESS;
        }
        p += ret;
        remaining -= (size_t)ret;
    }

    return KCTSB_SUCCESS;
}

#elif defined(__APPLE__)

int kctsb_random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;

    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess) {
        return KCTSB_SUCCESS;
    }

    // Fallback to arc4random_buf
    arc4random_buf(buf, len);
    return KCTSB_SUCCESS;
}

#else
// Generic POSIX fallback

int kctsb_random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return KCTSB_ERROR_RANDOM_FAILED;

    unsigned char* p = (unsigned char*)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t ret = read(fd, p, remaining);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        if (ret == 0) {
            close(fd);
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        p += ret;
        remaining -= (size_t)ret;
    }

    close(fd);
    return KCTSB_SUCCESS;
}

#endif

// ============================================================================
// Security Environment Check (simplified for compatibility)
// ============================================================================

uint32_t kctsb_security_check(void) {
    uint32_t flags = 0;

    // Verify CSPRNG works
    uint8_t test_buf[16];
    if (kctsb_random_bytes(test_buf, sizeof(test_buf)) == KCTSB_SUCCESS) {
        // Check that random output isn't all zeros (basic sanity)
        int has_nonzero = 0;
        for (int i = 0; i < 16; i++) {
            if (test_buf[i] != 0) {
                has_nonzero = 1;
                break;
            }
        }
        if (has_nonzero) {
            flags |= KCTSB_SEC_RANDOM_AVAILABLE;
        }
    }

    // Secure zero test
    uint8_t zero_test[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    kctsb_secure_zero(zero_test, sizeof(zero_test));
    int all_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (zero_test[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) {
        flags |= KCTSB_SEC_SECURE_MEMORY;
    }

#ifdef _WIN32
    // Basic Windows security flags
    flags |= KCTSB_SEC_ASLR_ENABLED;  // Assume ASLR on modern Windows
    flags |= KCTSB_SEC_DEP_ENABLED;   // Assume DEP on modern Windows
#elif defined(__linux__) || defined(__APPLE__)
    // Basic Unix security flags
    flags |= KCTSB_SEC_ASLR_ENABLED;  // Modern kernels have ASLR
#endif

    kctsb_secure_zero(test_buf, sizeof(test_buf));
    return flags;
}
