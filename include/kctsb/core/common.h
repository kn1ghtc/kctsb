/**
 * @file common.h
 * @brief Common definitions and utility macros for kctsb library
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CORE_COMMON_H
#define KCTSB_CORE_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Platform detection
// ============================================================================
#if defined(_WIN32) || defined(_WIN64)
    #define KCTSB_PLATFORM_WINDOWS 1
    #define KCTSB_PLATFORM_NAME "Windows"
#elif defined(__linux__)
    #define KCTSB_PLATFORM_LINUX 1
    #define KCTSB_PLATFORM_NAME "Linux"
#elif defined(__APPLE__)
    #define KCTSB_PLATFORM_MACOS 1
    #define KCTSB_PLATFORM_NAME "macOS"
#else
    #define KCTSB_PLATFORM_UNKNOWN 1
    #define KCTSB_PLATFORM_NAME "Unknown"
#endif

// ============================================================================
// Export/Import macros for shared library
// ============================================================================
#ifdef KCTSB_PLATFORM_WINDOWS
    #ifdef KCTSB_SHARED_LIBRARY
        #ifdef KCTSB_BUILDING
            #define KCTSB_API __declspec(dllexport)
        #else
            #define KCTSB_API __declspec(dllimport)
        #endif
    #else
        #define KCTSB_API
    #endif
#else
    #ifdef KCTSB_SHARED_LIBRARY
        #define KCTSB_API __attribute__((visibility("default")))
    #else
        #define KCTSB_API
    #endif
#endif

// ============================================================================
// Error codes
// ============================================================================
typedef enum {
    KCTSB_SUCCESS = 0,
    KCTSB_ERROR_INVALID_PARAM = -1,
    KCTSB_ERROR_BUFFER_TOO_SMALL = -2,
    KCTSB_ERROR_MEMORY_ALLOC = -3,
    KCTSB_ERROR_INVALID_KEY = -4,
    KCTSB_ERROR_INVALID_IV = -5,
    KCTSB_ERROR_ENCRYPTION_FAILED = -6,
    KCTSB_ERROR_DECRYPTION_FAILED = -7,
    KCTSB_ERROR_VERIFICATION_FAILED = -8,
    KCTSB_ERROR_NOT_IMPLEMENTED = -9,
    KCTSB_ERROR_INTERNAL = -10,
    KCTSB_ERROR_AUTH_FAILED = -11,      // AEAD authentication failed
    KCTSB_ERROR_RANDOM_FAILED = -12,    // CSPRNG failure
    KCTSB_ERROR_SECURITY_CHECK = -13    // Security check failed
} kctsb_error_t;


// Block cipher modes - v3.0 only supports secure modes
typedef enum {
    // DEPRECATED: ECB and CBC are insecure and not supported
    // KCTSB_MODE_ECB = 0,  // NOT SUPPORTED - deterministic encryption
    // KCTSB_MODE_CBC = 1,  // NOT SUPPORTED - padding oracle attacks
    KCTSB_MODE_CTR = 2,     // Counter mode - secure streaming
    KCTSB_MODE_GCM = 3,     // Galois/Counter Mode - AEAD
    KCTSB_MODE_CFB = 4,     // Cipher Feedback - streaming
    KCTSB_MODE_OFB = 5      // Output Feedback - streaming
} kctsb_cipher_mode_t;

// Padding modes
typedef enum {
    KCTSB_PADDING_NONE = 0,
    KCTSB_PADDING_PKCS7 = 1,
    KCTSB_PADDING_ZERO = 2,
    KCTSB_PADDING_ISO7816 = 3
} kctsb_padding_mode_t;

// Key sizes
#define KCTSB_AES_128_KEY_SIZE   16
#define KCTSB_AES_192_KEY_SIZE   24
#define KCTSB_AES_256_KEY_SIZE   32
#define KCTSB_AES_BLOCK_SIZE     16

#define KCTSB_SM4_KEY_SIZE       16
#define KCTSB_SM4_BLOCK_SIZE     16

#define KCTSB_CHACHA20_KEY_SIZE  32
#define KCTSB_CHACHA20_NONCE_SIZE 12

// Hash output sizes
#define KCTSB_SHA256_DIGEST_SIZE  32
#define KCTSB_SHA384_DIGEST_SIZE  48
#define KCTSB_SHA512_DIGEST_SIZE  64
#define KCTSB_SM3_DIGEST_SIZE     32
#define KCTSB_BLAKE2B_DIGEST_SIZE 64

// Utility macros
#define KCTSB_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define KCTSB_MIN(a, b) ((a) < (b) ? (a) : (b))
#define KCTSB_MAX(a, b) ((a) > (b) ? (a) : (b))

// Rotate operations
#define KCTSB_ROTL8(x, n)  ((uint8_t)(((x) << (n)) | ((x) >> (8 - (n)))))
#define KCTSB_ROTR8(x, n)  ((uint8_t)(((x) >> (n)) | ((x) << (8 - (n)))))
#define KCTSB_ROTL32(x, n) ((uint32_t)(((x) << (n)) | ((x) >> (32 - (n)))))
#define KCTSB_ROTR32(x, n) ((uint32_t)(((x) >> (n)) | ((x) << (32 - (n)))))
#define KCTSB_ROTL64(x, n) ((uint64_t)(((x) << (n)) | ((x) >> (64 - (n)))))
#define KCTSB_ROTR64(x, n) ((uint64_t)(((x) >> (n)) | ((x) << (64 - (n)))))

// Byte order operations
#ifdef KCTSB_PLATFORM_WINDOWS
    #include <stdlib.h>
    #define KCTSB_BSWAP16(x) _byteswap_ushort(x)
    #define KCTSB_BSWAP32(x) _byteswap_ulong(x)
    #define KCTSB_BSWAP64(x) _byteswap_uint64(x)
#else
    #define KCTSB_BSWAP16(x) __builtin_bswap16(x)
    #define KCTSB_BSWAP32(x) __builtin_bswap32(x)
    #define KCTSB_BSWAP64(x) __builtin_bswap64(x)
#endif

/**
 * @brief Get error message for error code
 * @param error Error code
 * @return Human-readable error message
 */
KCTSB_API const char* kctsb_error_string(kctsb_error_t error);

/**
 * @brief Secure memory zeroing
 * @param ptr Pointer to memory
 * @param size Size of memory to zero
 */
KCTSB_API void kctsb_secure_zero(void* ptr, size_t size);

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param size Size to compare
 * @return 0 if equal, non-zero otherwise
 */
KCTSB_API int kctsb_secure_compare(const void* a, const void* b, size_t size);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_CORE_COMMON_H
