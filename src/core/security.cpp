/**
 * @file security.cpp
 * @brief Security Primitives Implementation
 *
 * Production-grade implementation of security-critical operations with:
 * - Constant-time execution paths
 * - Platform-specific CSPRNG
 * - Secure memory operations
 *
 * C++ Core + C ABI Architecture (v3.4.0)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/core/security.h"
#include "kctsb/core/common.h"
#include <cstring>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#ifndef STATUS_SUCCESS
// Use constexpr instead of old-style macro cast to avoid -Wold-style-cast
constexpr NTSTATUS KCTSB_STATUS_SUCCESS = 0x00000000L;
#define STATUS_SUCCESS KCTSB_STATUS_SUCCESS
#endif
#else
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#if defined(__linux__)
// sys/random.h requires glibc 2.25+, use runtime detection instead
// Check for getrandom via syscall on older systems
#include <sys/syscall.h>
#ifdef SYS_getrandom
#define KCTSB_HAS_GETRANDOM_SYSCALL 1
static inline ssize_t kctsb_getrandom(void* buf, size_t len, unsigned int flags) {
    return syscall(SYS_getrandom, buf, len, flags);
}
#endif
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#endif
#endif

namespace kctsb {
namespace internal {

// ============================================================================
// Compiler Memory Barrier
// ============================================================================

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
using SecureZeroFn = void (*volatile)(void*, size_t);

static void secure_zero_impl(void* ptr, size_t len) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

static SecureZeroFn secure_zero_ptr = secure_zero_impl;

void secure_zero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;

#ifdef _WIN32
    SecureZeroMemory(ptr, len);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#else
    secure_zero_ptr(ptr, len);
#endif

    COMPILER_BARRIER();
}

bool secure_compare(const void* a, const void* b, size_t len) {
    if (!a || !b) return false;

    const volatile unsigned char* pa = static_cast<const volatile unsigned char*>(a);
    const volatile unsigned char* pb = static_cast<const volatile unsigned char*>(b);

    volatile unsigned char diff = 0;

    // Constant-time comparison: always iterate through all bytes
    for (size_t i = 0; i < len; i++) {
        diff |= static_cast<unsigned char>(pa[i] ^ pb[i]);
    }

    COMPILER_BARRIER();

    return diff == 0;
}

// ============================================================================
// Constant-Time Operations
// ============================================================================

uint64_t ct_select(uint64_t condition, uint64_t a, uint64_t b) {
    // Create mask: all 0s if condition is 0, all 1s otherwise
    uint64_t mask = static_cast<uint64_t>(-static_cast<int64_t>(condition != 0));
    return (b & mask) | (a & ~mask);
}

void ct_swap(uint64_t condition, uint64_t* a, uint64_t* b) {
    if (!a || !b) return;

    // Create mask: all 0s if condition is 0, all 1s otherwise
    uint64_t mask = static_cast<uint64_t>(-static_cast<int64_t>(condition != 0));

    // XOR swap with conditional mask
    uint64_t t = (*a ^ *b) & mask;
    *a ^= t;
    *b ^= t;
}

int secure_copy(void* dest, size_t dest_size, const void* src, size_t count) {
    if (!dest || !src) return -1;
    if (count > dest_size) return -2;

    std::memcpy(dest, src, count);
    return 0;
}

// ============================================================================
// CSPRNG Implementation
// ============================================================================

#ifdef _WIN32

int random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        static_cast<PUCHAR>(buf),
        static_cast<ULONG>(len),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    return (status == STATUS_SUCCESS) ? KCTSB_SUCCESS : KCTSB_ERROR_RANDOM_FAILED;
}

#elif defined(__linux__)

int random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;

    unsigned char* p = static_cast<unsigned char*>(buf);
    size_t remaining = len;

#ifdef KCTSB_HAS_GETRANDOM_SYSCALL
    // Try getrandom syscall first (works on kernel 3.17+)
    while (remaining > 0) {
        ssize_t ret = kctsb_getrandom(p, remaining, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break; // getrandom not available, fall through to /dev/urandom

            // Other errors, try fallback
            break;
        }
        p += ret;
        remaining -= static_cast<size_t>(ret);
    }

    if (remaining == 0) return KCTSB_SUCCESS;

    // Reset for fallback
    p = static_cast<unsigned char*>(buf);
    remaining = len;
#endif

    // Fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        // Try without O_CLOEXEC for older kernels
        fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return KCTSB_ERROR_RANDOM_FAILED;
    }

    while (remaining > 0) {
        ssize_t ret = read(fd, p, remaining);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        p += ret;
        remaining -= static_cast<size_t>(ret);
    }
    close(fd);
    return KCTSB_SUCCESS;
}

#elif defined(__APPLE__)

int random_bytes(void* buf, size_t len) {
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

int random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return KCTSB_ERROR_RANDOM_FAILED;

    unsigned char* p = static_cast<unsigned char*>(buf);
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
        remaining -= static_cast<size_t>(ret);
    }

    close(fd);
    return KCTSB_SUCCESS;
}

#endif

// ============================================================================
// Security Environment Check
// ============================================================================

uint32_t security_check() {
    uint32_t flags = 0;

    // Verify CSPRNG works
    uint8_t test_buf[16];
    if (random_bytes(test_buf, sizeof(test_buf)) == KCTSB_SUCCESS) {
        // Check that random output isn't all zeros (basic sanity)
        bool has_nonzero = false;
        for (int i = 0; i < 16; i++) {
            if (test_buf[i] != 0) {
                has_nonzero = true;
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
    secure_zero(zero_test, sizeof(zero_test));
    bool all_zero = true;
    for (int i = 0; i < 16; i++) {
        if (zero_test[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        flags |= KCTSB_SEC_SECURE_MEMORY;
    }

#ifdef _WIN32
    // Basic Windows security flags
    flags |= KCTSB_SEC_ASLR_ENABLED;
    flags |= KCTSB_SEC_DEP_ENABLED;
#elif defined(__linux__) || defined(__APPLE__)
    // Basic Unix security flags
    flags |= KCTSB_SEC_ASLR_ENABLED;
#endif

    secure_zero(test_buf, sizeof(test_buf));
    return flags;
}

}  // namespace internal
}  // namespace kctsb

// ============================================================================
// C ABI Exports
// ============================================================================

extern "C" {

void kctsb_secure_zero(void* ptr, size_t len) {
    kctsb::internal::secure_zero(ptr, len);
}

int kctsb_secure_compare(const void* a, const void* b, size_t len) {
    return kctsb::internal::secure_compare(a, b, len) ? 1 : 0;
}

uint64_t kctsb_ct_select(uint64_t condition, uint64_t a, uint64_t b) {
    return kctsb::internal::ct_select(condition, a, b);
}

void kctsb_ct_swap(uint64_t condition, uint64_t* a, uint64_t* b) {
    kctsb::internal::ct_swap(condition, a, b);
}

int kctsb_secure_copy(void* dest, size_t dest_size, const void* src, size_t count) {
    return kctsb::internal::secure_copy(dest, dest_size, src, count);
}

int kctsb_random_bytes(void* buf, size_t len) {
    return kctsb::internal::random_bytes(buf, len);
}

uint32_t kctsb_security_check(void) {
    return kctsb::internal::security_check();
}

}  // extern "C"
