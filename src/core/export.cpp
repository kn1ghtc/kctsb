/**
 * @file export.cpp
 * @brief Library export and initialization functions
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/kctsb.h"
#include "kctsb/core/security.h"
#include <cstring>

#ifdef KCTSB_PLATFORM_WINDOWS
    // Note: BCrypt is loaded dynamically in aes.cpp, no static linking needed
    #include <windows.h>
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

kctsb_error_t kctsb_init(void) {
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
        case KCTSB_ERROR_AUTH_FAILED:
            return "Authentication failed";
        case KCTSB_ERROR_RANDOM_FAILED:
            return "Random generation failed";
        case KCTSB_ERROR_SECURITY_CHECK:
            return "Security check failed";
        default:
            return "Unknown error";
    }
}

// Random functions are now defined in security.cpp to avoid duplication

} // extern "C"
