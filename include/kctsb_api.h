/**
 * @file kctsb_api.h
 * @brief Unified Public API for kctsb Cryptographic Library
 *
 * This single header file exposes all public interfaces of the kctsb library.
 * Include only this header in your application for a clean, stable API.
 *
 * Design Philosophy (Inspired by OpenSSL):
 * - Single include for all crypto functionality
 * - Clean C API for maximum portability
 * - Optional C++ wrappers with RAII
 * - All internal implementation details hidden
 * - Stable ABI across minor versions
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 * @version 3.3.0
 */

#ifndef KCTSB_API_H
#define KCTSB_API_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Platform Detection and Export Macros
 * ============================================================================ */

#if defined(_WIN32) || defined(_WIN64)
    #ifdef KCTSB_BUILD_DLL
        #define KCTSB_API __declspec(dllexport)
    #elif defined(KCTSB_USE_DLL)
        #define KCTSB_API __declspec(dllimport)
    #else
        #define KCTSB_API
    #endif
#else
    #if defined(__GNUC__) && __GNUC__ >= 4
        #define KCTSB_API __attribute__((visibility("default")))
    #else
        #define KCTSB_API
    #endif
#endif

/* ============================================================================
 * Version Information - Include unified version header
 * ============================================================================ */

#include "kctsb/version.h"

/**
 * @brief Get the library version string
 * @return Version string "major.minor.patch"
 */
KCTSB_API const char* kctsb_version(void);

/**
 * @brief Get the build platform name
 * @return Platform string ("windows", "linux", "macos")
 */
KCTSB_API const char* kctsb_platform(void);

/**
 * @brief Get supported SIMD features
 * @return Human-readable SIMD info string
 */
KCTSB_API const char* kctsb_simd_info(void);

/* ============================================================================
 * Standard Types
 * ============================================================================ */

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Error codes for all kctsb functions
 */
typedef enum {
    KCTSB_SUCCESS = 0,              /**< Operation succeeded */
    KCTSB_ERROR_INVALID_PARAM = -1, /**< Invalid parameter */
    KCTSB_ERROR_INVALID_KEY = -2,   /**< Invalid key length or format */
    KCTSB_ERROR_BUFFER_TOO_SMALL = -3, /**< Output buffer too small */
    KCTSB_ERROR_AUTH_FAILED = -4,   /**< Authentication tag verification failed */
    KCTSB_ERROR_RANDOM_FAILED = -5, /**< Random number generation failed */
    KCTSB_ERROR_NOT_SUPPORTED = -6, /**< Feature not supported on this platform */
    KCTSB_ERROR_INTERNAL = -99      /**< Internal error */
} kctsb_error_t;

/* ============================================================================
 * Library Initialization
 * ============================================================================ */

/**
 * @brief Initialize the kctsb library
 * @return KCTSB_SUCCESS on success
 * @note Thread-safe, can be called multiple times
 */
KCTSB_API kctsb_error_t kctsb_init(void);

/**
 * @brief Cleanup and free library resources
 * @note Call once when done using the library
 */
KCTSB_API void kctsb_cleanup(void);

/* ============================================================================
 * SECTION: Symmetric Encryption - AES
 * ============================================================================ */

/** AES block size in bytes */
#define KCTSB_AES_BLOCK_SIZE 16

/** AES-128 key size in bytes */
#define KCTSB_AES_128_KEY_SIZE 16

/** AES-192 key size in bytes */
#define KCTSB_AES_192_KEY_SIZE 24

/** AES-256 key size in bytes */
#define KCTSB_AES_256_KEY_SIZE 32

/** GCM recommended IV size in bytes */
#define KCTSB_GCM_IV_SIZE 12

/** GCM authentication tag size in bytes */
#define KCTSB_GCM_TAG_SIZE 16

/**
 * @brief Opaque AES context structure
 * @note Internal layout hidden from users
 */
typedef struct kctsb_aes_ctx_s {
    uint32_t round_keys[60];  /**< Expanded key schedule */
    int rounds;               /**< Number of rounds (10/12/14) */
    int key_bits;             /**< Key size in bits */
} kctsb_aes_ctx_t;

/**
 * @brief Initialize AES context with key
 * @param ctx AES context to initialize
 * @param key Encryption key (16/24/32 bytes)
 * @param key_len Key length in bytes
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_aes_init(kctsb_aes_ctx_t* ctx,
                                        const uint8_t* key, size_t key_len);

/**
 * @brief AES-GCM authenticated encryption
 * @param ctx Initialized AES context
 * @param iv Initialization vector (12 bytes recommended)
 * @param iv_len IV length in bytes
 * @param aad Additional authenticated data (optional, can be NULL)
 * @param aad_len AAD length in bytes
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length in bytes
 * @param ciphertext Output ciphertext (same length as plaintext)
 * @param tag Output authentication tag (16 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_encrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext, uint8_t tag[16]);

/**
 * @brief AES-GCM authenticated decryption
 * @param ctx Initialized AES context
 * @param iv Initialization vector
 * @param iv_len IV length in bytes
 * @param aad Additional authenticated data (optional)
 * @param aad_len AAD length in bytes
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length in bytes
 * @param tag Authentication tag to verify (16 bytes)
 * @param plaintext Output plaintext
 * @return KCTSB_SUCCESS on success, KCTSB_ERROR_AUTH_FAILED if tag invalid
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_decrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16], uint8_t* plaintext);

/**
 * @brief Securely clear AES context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_aes_clear(kctsb_aes_ctx_t* ctx);

/* ============================================================================
 * SECTION: Symmetric Encryption - ChaCha20-Poly1305
 * ============================================================================ */

/** ChaCha20 key size in bytes */
#define KCTSB_CHACHA20_KEY_SIZE 32

/** ChaCha20 nonce size in bytes */
#define KCTSB_CHACHA20_NONCE_SIZE 12

/** Poly1305 authentication tag size in bytes */
#define KCTSB_POLY1305_TAG_SIZE 16

/**
 * @brief ChaCha20-Poly1305 authenticated encryption
 * @param key 32-byte encryption key
 * @param nonce 12-byte nonce (must be unique per key)
 * @param aad Additional authenticated data (optional)
 * @param aad_len AAD length in bytes
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext
 * @param tag Output authentication tag (16 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext, uint8_t tag[16]);

/**
 * @brief ChaCha20-Poly1305 authenticated decryption
 * @return KCTSB_SUCCESS on success, KCTSB_ERROR_AUTH_FAILED if tag invalid
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_decrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16], uint8_t* plaintext);

/* ============================================================================
 * SECTION: Hash Functions
 * ============================================================================ */

/** SHA-256 output size in bytes */
#define KCTSB_SHA256_DIGEST_SIZE 32

/** SHA-512 output size in bytes */
#define KCTSB_SHA512_DIGEST_SIZE 64

/** SHA3-256 output size in bytes */
#define KCTSB_SHA3_256_DIGEST_SIZE 32

/** BLAKE2b-256 output size in bytes */
#define KCTSB_BLAKE2B_256_DIGEST_SIZE 32

/**
 * @brief Compute SHA-256 hash
 * @param data Input data
 * @param len Input length in bytes
 * @param hash Output hash (32 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha256(const uint8_t* data, size_t len,
                                      uint8_t hash[32]);

/**
 * @brief Compute SHA-512 hash
 * @param data Input data
 * @param len Input length in bytes
 * @param hash Output hash (64 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha512(const uint8_t* data, size_t len,
                                      uint8_t hash[64]);

/**
 * @brief Compute SHA3-256 (Keccak) hash
 * @param data Input data
 * @param len Input length in bytes
 * @param hash Output hash (32 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256(const uint8_t* data, size_t len,
                                        uint8_t hash[32]);

/**
 * @brief Compute BLAKE2b-256 hash
 * @param data Input data
 * @param len Input length in bytes
 * @param hash Output hash (32 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_blake2b_256(const uint8_t* data, size_t len,
                                           uint8_t hash[32]);

/* ============================================================================
 * SECTION: Message Authentication Codes (MAC)
 * ============================================================================ */

/**
 * @brief Compute HMAC-SHA256
 * @param key HMAC key
 * @param key_len Key length in bytes
 * @param data Input data
 * @param data_len Data length in bytes
 * @param mac Output MAC (32 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_hmac_sha256(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t mac[32]);

/* ============================================================================
 * SECTION: Chinese National Standards (SM Series)
 * ============================================================================ */

/** SM4 block size in bytes */
#define KCTSB_SM4_BLOCK_SIZE 16

/** SM4 key size in bytes */
#define KCTSB_SM4_KEY_SIZE 16

/** SM3 output size in bytes */
#define KCTSB_SM3_DIGEST_SIZE 32

/**
 * @brief Compute SM3 hash (Chinese national standard)
 * @param data Input data
 * @param len Input length in bytes
 * @param hash Output hash (32 bytes)
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sm3(const uint8_t* data, size_t len,
                                   uint8_t hash[32]);

/**
 * @brief SM4-CBC encryption
 * @param key 16-byte encryption key
 * @param iv 16-byte initialization vector
 * @param plaintext Input plaintext (must be padded to 16-byte boundary)
 * @param len Plaintext length in bytes
 * @param ciphertext Output ciphertext
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sm4_cbc_encrypt(
    const uint8_t key[16], const uint8_t iv[16],
    const uint8_t* plaintext, size_t len,
    uint8_t* ciphertext);

/**
 * @brief SM4-CBC decryption
 */
KCTSB_API kctsb_error_t kctsb_sm4_cbc_decrypt(
    const uint8_t key[16], const uint8_t iv[16],
    const uint8_t* ciphertext, size_t len,
    uint8_t* plaintext);

/* ============================================================================
 * SECTION: Random Number Generation
 * ============================================================================ */

/**
 * @brief Generate cryptographically secure random bytes
 * @param buf Output buffer
 * @param len Number of bytes to generate
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_random_bytes(uint8_t* buf, size_t len);

/* ============================================================================
 * SECTION: Utility Functions
 * ============================================================================ */

/**
 * @brief Securely zero memory (not optimized away by compiler)
 * @param ptr Memory to zero
 * @param len Length in bytes
 */
KCTSB_API void kctsb_secure_zero(void* ptr, size_t len);

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 1 if equal, 0 if different
 */
KCTSB_API int kctsb_secure_compare(const uint8_t* a, const uint8_t* b, size_t len);

/**
 * @brief Convert bytes to hexadecimal string
 * @param data Input bytes
 * @param len Input length
 * @param hex Output hex string (must be at least len*2+1 bytes)
 */
KCTSB_API void kctsb_bytes_to_hex(const uint8_t* data, size_t len, char* hex);

/**
 * @brief Convert hexadecimal string to bytes
 * @param hex Input hex string
 * @param data Output bytes
 * @param max_len Maximum output length
 * @return Number of bytes written, or -1 on error
 */
KCTSB_API int kctsb_hex_to_bytes(const char* hex, uint8_t* data, size_t max_len);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* ============================================================================
 * SECTION: C++ API (Optional)
 * ============================================================================ */

#ifdef __cplusplus

#include <array>
#include <vector>
#include <string>
#include <stdexcept>

namespace kctsb {

using ByteVec = std::vector<uint8_t>;

/**
 * @brief C++ wrapper for AES-GCM with RAII
 */
class AES {
public:
    explicit AES(const ByteVec& key);
    explicit AES(const uint8_t* key, size_t key_len);
    ~AES();

    // Non-copyable
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;

    // Movable
    AES(AES&& other) noexcept;
    AES& operator=(AES&& other) noexcept;

    /**
     * @brief AES-GCM encryption
     * @param plaintext Input data
     * @param iv Initialization vector
     * @param aad Additional authenticated data
     * @return Pair of (ciphertext, tag)
     */
    std::pair<ByteVec, std::array<uint8_t, 16>> gcmEncrypt(
        const ByteVec& plaintext,
        const ByteVec& iv,
        const ByteVec& aad = {}) const;

    /**
     * @brief AES-GCM decryption
     * @throws std::runtime_error if authentication fails
     */
    ByteVec gcmDecrypt(
        const ByteVec& ciphertext,
        const ByteVec& iv,
        const std::array<uint8_t, 16>& tag,
        const ByteVec& aad = {}) const;

    /**
     * @brief Generate random IV
     */
    static ByteVec generateIV(size_t len = 12);

private:
    kctsb_aes_ctx_t ctx_;
};

/**
 * @brief SHA-256 hash function
 */
inline std::array<uint8_t, 32> sha256(const ByteVec& data) {
    std::array<uint8_t, 32> hash;
    kctsb_sha256(data.data(), data.size(), hash.data());
    return hash;
}

/**
 * @brief SHA3-256 hash function
 */
inline std::array<uint8_t, 32> sha3_256(const ByteVec& data) {
    std::array<uint8_t, 32> hash;
    kctsb_sha3_256(data.data(), data.size(), hash.data());
    return hash;
}

/**
 * @brief BLAKE2b-256 hash function
 */
inline std::array<uint8_t, 32> blake2b_256(const ByteVec& data) {
    std::array<uint8_t, 32> hash;
    kctsb_blake2b_256(data.data(), data.size(), hash.data());
    return hash;
}

/**
 * @brief Generate random bytes
 */
inline ByteVec randomBytes(size_t len) {
    ByteVec buf(len);
    if (kctsb_random_bytes(buf.data(), len) != KCTSB_SUCCESS) {
        throw std::runtime_error("Random number generation failed");
    }
    return buf;
}

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_API_H
