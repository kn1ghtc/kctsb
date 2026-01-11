/**
 * @file export.cpp
 * @brief Library export and initialization functions
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/kctsb.h"
#include <cstring>

#ifdef KCTSB_PLATFORM_WINDOWS
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

// Global initialization state
static int g_kctsb_initialized = 0;

extern "C" {

const char* kctsb_version(void) {
    return KCTSB_VERSION_STRING;
}

const char* kctsb_platform(void) {
    return KCTSB_PLATFORM_NAME;
}

int kctsb_init(void) {
    if (g_kctsb_initialized) {
        return KCTSB_SUCCESS;
    }
    
    // Platform-specific initialization
#ifdef KCTSB_PLATFORM_WINDOWS
    // Windows: BCrypt is available by default
#else
    // Unix: Check /dev/urandom availability
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return KCTSB_ERROR_INTERNAL;
    }
    close(fd);
#endif
    
    g_kctsb_initialized = 1;
    return KCTSB_SUCCESS;
}

void kctsb_cleanup(void) {
    g_kctsb_initialized = 0;
}

const char* kctsb_error_string(kctsb_error_t error) {
    switch (error) {
        case KCTSB_SUCCESS:
            return "Success";
        case KCTSB_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case KCTSB_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case KCTSB_ERROR_MEMORY_ALLOC:
            return "Memory allocation failed";
        case KCTSB_ERROR_INVALID_KEY:
            return "Invalid key";
        case KCTSB_ERROR_INVALID_IV:
            return "Invalid IV";
        case KCTSB_ERROR_ENCRYPTION_FAILED:
            return "Encryption failed";
        case KCTSB_ERROR_DECRYPTION_FAILED:
            return "Decryption failed";
        case KCTSB_ERROR_VERIFICATION_FAILED:
            return "Verification failed";
        case KCTSB_ERROR_NOT_IMPLEMENTED:
            return "Not implemented";
        case KCTSB_ERROR_INTERNAL:
            return "Internal error";
        default:
            return "Unknown error";
    }
}

void kctsb_secure_zero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        volatile unsigned char* p = (volatile unsigned char*)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

int kctsb_secure_compare(const void* a, const void* b, size_t size) {
    const volatile unsigned char* pa = (const volatile unsigned char*)a;
    const volatile unsigned char* pb = (const volatile unsigned char*)b;
    unsigned char diff = 0;
    
    for (size_t i = 0; i < size; i++) {
        diff |= pa[i] ^ pb[i];
    }
    
    return diff;
}

// Secure random bytes implementation
kctsb_error_t kctsb_random_bytes(uint8_t* buffer, size_t len) {
    if (!buffer || len == 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
#ifdef KCTSB_PLATFORM_WINDOWS
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        return KCTSB_ERROR_INTERNAL;
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return KCTSB_ERROR_INTERNAL;
    }
    
    ssize_t bytes_read = read(fd, buffer, len);
    close(fd);
    
    if (bytes_read != (ssize_t)len) {
        return KCTSB_ERROR_INTERNAL;
    }
#endif
    
    return KCTSB_SUCCESS;
}

uint32_t kctsb_random_u32(void) {
    uint32_t value;
    kctsb_random_bytes((uint8_t*)&value, sizeof(value));
    return value;
}

uint64_t kctsb_random_u64(void) {
    uint64_t value;
    kctsb_random_bytes((uint8_t*)&value, sizeof(value));
    return value;
}

uint32_t kctsb_random_range(uint32_t max) {
    if (max == 0) return 0;
    uint32_t threshold = (0xFFFFFFFFU - max + 1) % max;
    uint32_t value;
    do {
        value = kctsb_random_u32();
    } while (value < threshold);
    return value % max;
}

} // extern "C"

// C++ implementations
namespace kctsb {

ByteVec randomBytes(size_t len) {
    ByteVec result(len);
    kctsb_random_bytes(result.data(), len);
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

} // namespace kctsb
