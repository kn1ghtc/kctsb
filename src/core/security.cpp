/**
 * @file security.cpp
 * @brief Security Primitives Implementation
 *
 * Production-grade implementation of security-critical operations with:
 * - Constant-time execution paths
 * - Secure memory operations
 * - CSPRNG via CTR_DRBG (delegated to aes.cpp for AES-NI acceleration)
 *
 * C++ Core + C ABI Architecture (v3.4.2)
 *
 * Note: CSPRNG is now implemented in aes.cpp using NIST SP 800-90A CTR_DRBG
 * with AES-256 and hardware acceleration. This file provides the public API
 * wrapper and legacy compatibility.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/core/security.h"
#include "kctsb/core/common.h"
#include "kctsb/utils/random.h"
#include <cstring>
#include <cstdint>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
// Note: CSPRNG now implemented in aes.cpp using CTR_DRBG with BCryptGenRandom entropy
#else
#include <sys/types.h>
#endif

// Forward declaration of CSPRNG API from aes.cpp
extern "C" int kctsb_csprng_random_bytes(void* buf, size_t len);

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
// CSPRNG Implementation (Delegated to CTR_DRBG in aes.cpp)
// ============================================================================
// 
// The actual CSPRNG implementation is in aes.cpp using NIST SP 800-90A
// CTR_DRBG with AES-256 and hardware acceleration (AES-NI).
// This function is a simple wrapper for API compatibility.
//
// Benefits of integrated CTR_DRBG in aes.cpp:
// - Uses BCryptGenRandom (Windows system component) for entropy
// - Hardware accelerated via AES-NI
// - Consistent security level (AES-256 strength)
// - Automatic reseeding every 512KB
// ============================================================================

int random_bytes(void* buf, size_t len) {
    return kctsb_csprng_random_bytes(buf, len);
}

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

KCTSB_API uint32_t kctsb_random_u32(void) {
    uint32_t val = 0;
    kctsb::internal::random_bytes(&val, sizeof(val));
    return val;
}

KCTSB_API uint64_t kctsb_random_u64(void) {
    uint64_t val = 0;
    kctsb::internal::random_bytes(&val, sizeof(val));
    return val;
}

KCTSB_API uint32_t kctsb_random_range(uint32_t max) {
    if (max <= 1) return 0;
    
    // Rejection sampling to avoid modulo bias
    uint32_t threshold = (~max + 1) % max;  // = (2^32 - max) % max
    uint32_t val;
    do {
        kctsb::internal::random_bytes(&val, sizeof(val));
    } while (val < threshold);
    
    return val % max;
}

uint32_t kctsb_security_check(void) {
    return kctsb::internal::security_check();
}

}  // extern "C"

// ============================================================================
// C++ Namespace Wrappers
// ============================================================================

namespace kctsb {

ByteVec randomBytes(size_t len) {
    ByteVec result(len);
    if (len > 0) {
        internal::random_bytes(result.data(), len);
    }
    return result;
}

uint32_t randomU32() {
    return kctsb_random_u32();
}

uint64_t randomU64() {
    return kctsb_random_u64();
}

uint32_t randomRange(uint32_t max) {
    return kctsb_random_range(max);
}

}  // namespace kctsb
