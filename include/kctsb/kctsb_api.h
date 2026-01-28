/**
 * @file kctsb_api.h
 * @brief kctsb Unified Public API Header
 *
 * This is the ONLY header file needed for external users of kctsb library.
 * Similar to OpenSSL's evp.h approach - one header exposes all public APIs.
 *
 * Supported Algorithms:
 * - Hash: SHA-256, SHA-384, SHA-512, SHA3-256/512, BLAKE2b/s, SM3
 * - AEAD: AES-GCM, AES-CTR, ChaCha20-Poly1305, SM4-GCM
 * - MAC: HMAC-SHA256, CMAC-AES, Poly1305
 * - Security: Constant-time ops, CSPRNG, secure memory
 *
 * Usage:
 * @code
 *   #include <kctsb_api.h>
 *
 *   // Hash example
 *   uint8_t hash[KCTSB_SHA256_DIGEST_SIZE];
 *   kctsb_sha256(data, len, hash);
 *
 *   // AEAD example
 *   kctsb_aes_ctx_t ctx;
 *   kctsb_aes_init(&ctx, key, 32);
 *   kctsb_aes_gcm_encrypt(&ctx, iv, iv_len, aad, aad_len, pt, pt_len, ct, tag);
 * @endcode
 *
 * @author knightc
 * @version 5.0.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_API_H
#define KCTSB_API_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Platform Detection & Export Macros
 * ============================================================================ */

#if defined(_WIN32) || defined(_WIN64)
    #define KCTSB_PLATFORM_WINDOWS 1
#elif defined(__linux__)
    #define KCTSB_PLATFORM_LINUX 1
#elif defined(__APPLE__)
    #define KCTSB_PLATFORM_MACOS 1
#endif

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

/* ============================================================================
 * Version Information (with guard for kctsb.h inclusion)
 * ============================================================================ */

#ifndef KCTSB_VERSION_MAJOR
#define KCTSB_VERSION_MAJOR 5
#define KCTSB_VERSION_MINOR 0
#define KCTSB_VERSION_PATCH 0
#define KCTSB_VERSION_STRING "5.0.0"
#endif

/* ============================================================================
 * Error Codes
 * ============================================================================ */

#ifndef KCTSB_ERROR_T_DEFINED
#define KCTSB_ERROR_T_DEFINED
typedef enum {
    KCTSB_SUCCESS               =  0,
    KCTSB_ERROR_INVALID_PARAM   = -1,
    KCTSB_ERROR_BUFFER_TOO_SMALL= -2,
    KCTSB_ERROR_MEMORY_ALLOC    = -3,
    KCTSB_ERROR_INVALID_KEY     = -4,
    KCTSB_ERROR_INVALID_IV      = -5,
    KCTSB_ERROR_ENCRYPTION_FAILED=-6,
    KCTSB_ERROR_DECRYPTION_FAILED=-7,
    KCTSB_ERROR_VERIFICATION_FAILED=-8,
    KCTSB_ERROR_NOT_IMPLEMENTED = -9,
    KCTSB_ERROR_INTERNAL        = -10,
    KCTSB_ERROR_AUTH_FAILED     = -11,
    KCTSB_ERROR_RANDOM_FAILED   = -12,
    KCTSB_ERROR_SECURITY_CHECK  = -13
} kctsb_error_t;
#endif

/* ============================================================================
 * Algorithm Constants
 * ============================================================================ */

/* Key sizes */
#define KCTSB_AES_128_KEY_SIZE   16
#define KCTSB_AES_192_KEY_SIZE   24
#define KCTSB_AES_256_KEY_SIZE   32
#define KCTSB_AES_BLOCK_SIZE     16
#define KCTSB_AES_GCM_TAG_SIZE   16

#define KCTSB_CHACHA20_KEY_SIZE  32
#define KCTSB_CHACHA20_NONCE_SIZE 12
#define KCTSB_POLY1305_TAG_SIZE  16

#define KCTSB_SM4_KEY_SIZE       16
#define KCTSB_SM4_BLOCK_SIZE     16
#define KCTSB_SM4_GCM_IV_SIZE    12
#define KCTSB_SM4_GCM_TAG_SIZE   16

/* Hash digest sizes */
#define KCTSB_SHA256_DIGEST_SIZE 32
#define KCTSB_SHA256_BLOCK_SIZE  64
#define KCTSB_SHA384_DIGEST_SIZE 48
#define KCTSB_SHA512_DIGEST_SIZE 64

#define KCTSB_SHA3_224_DIGEST_SIZE 28
#define KCTSB_SHA3_256_DIGEST_SIZE 32
#define KCTSB_SHA3_384_DIGEST_SIZE 48
#define KCTSB_SHA3_512_DIGEST_SIZE 64

#define KCTSB_BLAKE2B_OUTBYTES   64
#define KCTSB_BLAKE2S_OUTBYTES   32

#define KCTSB_SM3_DIGEST_SIZE    32

/* RSA sizes (HTTPS recommended) */
#define KCTSB_RSA_3072_BITS 3072
#define KCTSB_RSA_4096_BITS 4096
#define KCTSB_RSA_3072_BYTES 384
#define KCTSB_RSA_4096_BYTES 512
#define KCTSB_RSA_MAX_MODULUS_BYTES 512
#define KCTSB_RSA_MAX_PRIME_BYTES 256

/* ============================================================================
 * Context Structures
 * ============================================================================ */

/**
 * @brief AES context for CTR/GCM operations
 */
typedef struct {
    uint32_t round_keys[60];
    int key_bits;
    int rounds;
} kctsb_aes_ctx_t;

/**
 * @brief AES-GCM context for streaming operations
 */
#ifndef KCTSB_AES_GCM_CTX_DEFINED
#define KCTSB_AES_GCM_CTX_DEFINED
typedef struct {
    kctsb_aes_ctx_t aes_ctx;
    uint8_t h[16];            /**< H = AES(K, 0^128) for GHASH */
    uint8_t j0[16];           /**< Initial counter block */
    uint8_t counter[16];      /**< Current counter */
    uint8_t tag[16];          /**< Running authentication tag */
    uint64_t aad_len;         /**< Total AAD length processed */
    uint64_t ct_len;          /**< Total ciphertext length processed */
    int finalized;            /**< Whether finalized */
} kctsb_aes_gcm_ctx_t;
#endif

/**
 * @brief SHA-256 context
 */
#ifndef KCTSB_SHA256_CTX_DEFINED
#define KCTSB_SHA256_CTX_DEFINED
typedef struct kctsb_sha256_ctx_s {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
    size_t buflen;
} kctsb_sha256_ctx_t;
#endif

/**
 * @brief SHA-512/384 context
 */
#ifndef KCTSB_SHA512_CTX_DEFINED
#define KCTSB_SHA512_CTX_DEFINED
typedef struct kctsb_sha512_ctx_s {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
    size_t buflen;
} kctsb_sha512_ctx_t;
#endif

/** SHA-384 uses same context as SHA-512 */
#ifndef KCTSB_SHA384_CTX_DEFINED
#define KCTSB_SHA384_CTX_DEFINED
typedef kctsb_sha512_ctx_t kctsb_sha384_ctx_t;
#endif

/**
 * @brief SHA3/Keccak context
 */
#ifndef KCTSB_SHA3_CTX_DEFINED
#define KCTSB_SHA3_CTX_DEFINED
typedef struct kctsb_sha3_ctx_s {
#ifdef __cplusplus
    alignas(32) uint64_t state[25];
#else
    uint64_t state[25];
#endif
    size_t rate;
    size_t capacity;
    size_t absorbed;
    uint8_t suffix;
    size_t digest_size;
} kctsb_sha3_ctx_t;
#endif

/**
 * @brief BLAKE2b context
 */
#ifndef KCTSB_BLAKE2B_CTX_DEFINED
#define KCTSB_BLAKE2B_CTX_DEFINED
typedef struct kctsb_blake2b_ctx_s {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[128];
    size_t buflen;
    size_t outlen;
} kctsb_blake2b_ctx_t;
#endif

/**
 * @brief BLAKE2s context
 */
#ifndef KCTSB_BLAKE2S_CTX_DEFINED
#define KCTSB_BLAKE2S_CTX_DEFINED
typedef struct kctsb_blake2s_ctx_s {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[64];
    size_t buflen;
    size_t outlen;
} kctsb_blake2s_ctx_t;
#endif

/**
 * @brief SM3 context
 */
#ifndef KCTSB_SM3_CTX_DEFINED
#define KCTSB_SM3_CTX_DEFINED
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} kctsb_sm3_ctx_t;
#endif

/**
 * @brief SM4 base context
 */
#ifndef KCTSB_SM4_CTX_DEFINED
#define KCTSB_SM4_CTX_DEFINED
typedef struct {
    uint32_t round_keys[32];
} kctsb_sm4_ctx_t;
#endif

/**
 * @brief SM4-GCM context
 */
#ifndef KCTSB_SM4_GCM_CTX_DEFINED
#define KCTSB_SM4_GCM_CTX_DEFINED
typedef struct {
    kctsb_sm4_ctx_t cipher_ctx;
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t ghash_state[16];
    size_t aad_len;
    size_t cipher_len;
} kctsb_sm4_gcm_ctx_t;
#endif

/**
 * @brief ChaCha20 context
 */
#ifndef KCTSB_CHACHA20_CTX_DEFINED
#define KCTSB_CHACHA20_CTX_DEFINED
typedef struct {
    uint32_t state[16];
    uint8_t keystream[64];
    size_t remaining;
} kctsb_chacha20_ctx_t;
#endif

/**
 * @brief Poly1305 context
 */
#ifndef KCTSB_POLY1305_CTX_DEFINED
#define KCTSB_POLY1305_CTX_DEFINED
typedef struct {
    uint32_t r[5];        // Clamped key r (radix-2^26, for fallback)
    uint32_t s[4];        // Key s
    uint32_t h[5];        // Accumulator (radix-2^26, for fallback)
    uint64_t r44[3];      // Pre-computed r (radix-2^44) for optimized block processing
    uint64_t s44[3];      // Pre-computed 5*r (radix-2^44) for reduction
    uint64_t h44[3];      // Accumulator (radix-2^44) for optimized processing
    uint8_t buffer[16];   // Partial block buffer
    size_t buffer_len;    // Bytes in buffer
    int finalized;        // Whether finalized
} kctsb_poly1305_ctx_t;
#endif

/**
 * @brief ChaCha20-Poly1305 streaming context
 */
#ifndef KCTSB_CHACHA20_POLY1305_CTX_DEFINED
#define KCTSB_CHACHA20_POLY1305_CTX_DEFINED
typedef struct {
    kctsb_chacha20_ctx_t chacha_ctx;
    kctsb_poly1305_ctx_t poly_ctx;
    uint64_t aad_len;
    uint64_t ct_len;
    int aad_finalized;
    int finalized;
} kctsb_chacha20_poly1305_ctx_t;
#endif

/**
 * @brief HMAC context (opaque)
 */
#ifndef KCTSB_HMAC_CTX_DEFINED
#define KCTSB_HMAC_CTX_DEFINED
typedef struct {
    void* internal;
} kctsb_hmac_ctx_t;
#endif

/**
 * @brief RSA public key container (3072/4096 bits)
 */
#ifndef KCTSB_RSA_PUBLIC_KEY_DEFINED
#define KCTSB_RSA_PUBLIC_KEY_DEFINED
typedef struct {
    uint32_t bits;
    uint32_t n_len;
    uint32_t e_len;
    uint8_t n[KCTSB_RSA_MAX_MODULUS_BYTES];
    uint8_t e[KCTSB_RSA_MAX_MODULUS_BYTES];
} kctsb_rsa_public_key_t;
#endif

/**
 * @brief RSA private key container (optional CRT parameters)
 */
#ifndef KCTSB_RSA_PRIVATE_KEY_DEFINED
#define KCTSB_RSA_PRIVATE_KEY_DEFINED
typedef struct {
    uint32_t bits;
    uint32_t n_len;
    uint32_t d_len;
    uint32_t p_len;
    uint32_t q_len;
    uint32_t dp_len;
    uint32_t dq_len;
    uint32_t qinv_len;
    uint8_t n[KCTSB_RSA_MAX_MODULUS_BYTES];
    uint8_t d[KCTSB_RSA_MAX_MODULUS_BYTES];
    uint8_t p[KCTSB_RSA_MAX_PRIME_BYTES];
    uint8_t q[KCTSB_RSA_MAX_PRIME_BYTES];
    uint8_t dp[KCTSB_RSA_MAX_PRIME_BYTES];
    uint8_t dq[KCTSB_RSA_MAX_PRIME_BYTES];
    uint8_t qinv[KCTSB_RSA_MAX_PRIME_BYTES];
    uint8_t has_crt;
} kctsb_rsa_private_key_t;
#endif

/* ============================================================================
 * Library Initialization
 * ============================================================================ */

/**
 * @brief Get library version string
 * @return Version string (e.g., "3.4.0")
 */
KCTSB_API const char* kctsb_version(void);

/**
 * @brief Get platform name string
 * @return Platform name (e.g., "Windows", "Linux", "macOS")
 */
KCTSB_API const char* kctsb_platform(void);

/**
 * @brief Initialize kctsb library
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_init(void);

/**
 * @brief Cleanup kctsb library resources
 */
KCTSB_API void kctsb_cleanup(void);

/**
 * @brief Get error description string
 * @param error Error code
 * @return Human-readable error message
 */
KCTSB_API const char* kctsb_error_string(kctsb_error_t error);

/* ============================================================================
 * Security Primitives
 * ============================================================================ */

/**
 * @brief Constant-time memory comparison
 * @param a First buffer
 * @param b Second buffer
 * @param len Bytes to compare
 * @return 0 if equal, non-zero if different
 */
KCTSB_API int kctsb_secure_compare(const void* a, const void* b, size_t len);

/**
 * @brief Secure memory zeroing (not optimized away)
 * @param ptr Memory to zero
 * @param size Bytes to zero
 */
KCTSB_API void kctsb_secure_zero(void* ptr, size_t size);

/**
 * @brief Generate cryptographically secure random bytes
 * @param buf Output buffer
 * @param len Number of bytes to generate
 * @return 0 on success, non-zero on error
 */
KCTSB_API int kctsb_random_bytes(void* buf, size_t len);

/**
 * @brief Generate random uint32_t
 * @return Cryptographically secure random value
 */
KCTSB_API uint32_t kctsb_random_uint32(void);

/**
 * @brief Generate random uint64_t
 * @return Cryptographically secure random value
 */
KCTSB_API uint64_t kctsb_random_uint64(void);

/* ============================================================================
 * AES (AES-128/192/256-CTR, AES-GCM)
 * ============================================================================ */

/**
 * @brief Initialize AES context with key
 * @param ctx Context to initialize
 * @param key Key (16, 24, or 32 bytes for AES-128/192/256)
 * @param key_len Key length in bytes
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_init(
    kctsb_aes_ctx_t* ctx,
    const uint8_t* key,
    size_t key_len);

/**
 * @brief Encrypt single AES block (16 bytes)
 * @param ctx Initialized context
 * @param input 16-byte input
 * @param output 16-byte output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_encrypt_block(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]);

/**
 * @brief Decrypt single AES block (16 bytes)
 * @param ctx Initialized context
 * @param input 16-byte input
 * @param output 16-byte output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_decrypt_block(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]);

/**
 * @brief AES-CTR encryption/decryption
 * @param ctx Initialized context
 * @param nonce 12-byte nonce
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer (same size as input)
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_ctr_crypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t nonce[12],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output);

/**
 * @brief AES-GCM authenticated encryption
 * @param ctx Initialized AES context
 * @param iv Initialization vector
 * @param iv_len IV length (12 bytes recommended)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param input Plaintext
 * @param input_len Plaintext length
 * @param output Ciphertext output
 * @param tag 16-byte authentication tag output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_encrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    uint8_t* output, uint8_t tag[16]);

/**
 * @brief AES-GCM authenticated decryption
 * @param ctx Initialized AES context
 * @param iv Initialization vector
 * @param iv_len IV length
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param input Ciphertext
 * @param input_len Ciphertext length
 * @param tag 16-byte authentication tag to verify
 * @param output Plaintext output (only written if tag verifies)
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_decrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    const uint8_t tag[16], uint8_t* output);

/**
 * @brief Clear AES context (secure zeroing)
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_aes_clear(kctsb_aes_ctx_t* ctx);

/* ============================================================================
 * AES-GCM Streaming API
 * ============================================================================ */

/**
 * @brief Initialize streaming GCM encryption context
 * @param ctx GCM context to initialize
 * @param key Encryption key
 * @param key_len Key length (16, 24, or 32)
 * @param iv Initialization vector
 * @param iv_len IV length (12 bytes recommended)
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_init(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* key, size_t key_len,
    const uint8_t* iv, size_t iv_len);

/**
 * @brief Process additional authenticated data (AAD)
 * @note Must be called before any update_encrypt/update_decrypt calls
 * @param ctx GCM context
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_update_aad(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* aad, size_t aad_len);

/**
 * @brief Encrypt data in streaming mode
 * @param ctx GCM context
 * @param input Plaintext input
 * @param input_len Input length
 * @param output Ciphertext output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_update_encrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* input, size_t input_len,
    uint8_t* output);

/**
 * @brief Finalize GCM encryption and get authentication tag
 * @param ctx GCM context
 * @param tag 16-byte authentication tag output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_final_encrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    uint8_t tag[16]);

/**
 * @brief Decrypt data in streaming mode
 * @param ctx GCM context
 * @param input Ciphertext input
 * @param input_len Input length
 * @param output Plaintext output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_update_decrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* input, size_t input_len,
    uint8_t* output);

/**
 * @brief Finalize GCM decryption and verify tag
 * @param ctx GCM context
 * @param tag 16-byte authentication tag to verify
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_final_decrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t tag[16]);

/**
 * @brief Clear GCM context (secure zeroing)
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_aes_gcm_clear(kctsb_aes_gcm_ctx_t* ctx);

/* ============================================================================
 * ChaCha20-Poly1305 AEAD
 * ============================================================================ */

/**
 * @brief ChaCha20 stream cipher
 * @param key 256-bit key
 * @param nonce 96-bit nonce
 * @param counter Initial counter (usually 0)
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_chacha20(
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output);

/**
 * @brief Initialize ChaCha20 context
 * @param ctx Context to initialize
 * @param key 256-bit key
 * @param nonce 96-bit nonce
 * @param counter Initial counter
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_chacha20_init(
    kctsb_chacha20_ctx_t* ctx,
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter);

/**
 * @brief ChaCha20 stream crypt (same for encrypt/decrypt)
 * @param ctx Initialized context
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_chacha20_crypt(
    kctsb_chacha20_ctx_t* ctx,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output);

/**
 * @brief Clear ChaCha20 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_chacha20_clear(kctsb_chacha20_ctx_t* ctx);

/**
 * @brief Poly1305 one-time MAC
 * @param key 256-bit one-time key
 * @param data Input data
 * @param len Data length
 * @param tag 16-byte output tag
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_poly1305(
    const uint8_t key[32],
    const uint8_t* data,
    size_t len,
    uint8_t tag[16]);

/**
 * @brief ChaCha20-Poly1305 AEAD encryption
 * @param key 256-bit key
 * @param nonce 96-bit nonce (MUST be unique per key)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext
 * @param tag 16-byte authentication tag output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext, uint8_t tag[16]);

/**
 * @brief ChaCha20-Poly1305 AEAD decryption
 * @param key 256-bit key
 * @param nonce 96-bit nonce
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param tag 16-byte authentication tag to verify
 * @param plaintext Output plaintext (only written if tag verifies)
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16], uint8_t* plaintext);

/**
 * @brief Clear ChaCha20-Poly1305 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_chacha20_poly1305_clear(kctsb_chacha20_poly1305_ctx_t* ctx);

/* ============================================================================
 * SHA-256
 * ============================================================================ */

/**
 * @brief Initialize SHA-256 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sha256_init(kctsb_sha256_ctx_t* ctx);

/**
 * @brief Update SHA-256 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length
 */
KCTSB_API void kctsb_sha256_update(kctsb_sha256_ctx_t* ctx,
                                    const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-256 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest 32-byte output buffer
 */
KCTSB_API void kctsb_sha256_final(kctsb_sha256_ctx_t* ctx,
                                   uint8_t digest[KCTSB_SHA256_DIGEST_SIZE]);

/**
 * @brief Compute SHA-256 hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest 32-byte output buffer
 */
KCTSB_API void kctsb_sha256(const uint8_t* data, size_t len,
                             uint8_t digest[KCTSB_SHA256_DIGEST_SIZE]);

/**
 * @brief Clear SHA-256 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha256_clear(kctsb_sha256_ctx_t* ctx);

/* ============================================================================
 * SHA-384/512
 * ============================================================================ */

/**
 * @brief Initialize SHA-384 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sha384_init(kctsb_sha384_ctx_t* ctx);

/**
 * @brief Update SHA-384 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length
 */
KCTSB_API void kctsb_sha384_update(kctsb_sha384_ctx_t* ctx,
                                    const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-384 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest 48-byte output buffer
 */
KCTSB_API void kctsb_sha384_final(kctsb_sha384_ctx_t* ctx,
                                   uint8_t digest[KCTSB_SHA384_DIGEST_SIZE]);

/**
 * @brief Compute SHA-384 hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest 48-byte output buffer
 */
KCTSB_API void kctsb_sha384(const uint8_t* data, size_t len,
                             uint8_t digest[KCTSB_SHA384_DIGEST_SIZE]);

/**
 * @brief Clear SHA-384 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha384_clear(kctsb_sha384_ctx_t* ctx);

/**
 * @brief Initialize SHA-512 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sha512_init(kctsb_sha512_ctx_t* ctx);

/**
 * @brief Update SHA-512 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length
 */
KCTSB_API void kctsb_sha512_update(kctsb_sha512_ctx_t* ctx,
                                    const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA-512 and produce digest
 * @param ctx Context (will be cleared after)
 * @param digest 64-byte output buffer
 */
KCTSB_API void kctsb_sha512_final(kctsb_sha512_ctx_t* ctx,
                                   uint8_t digest[KCTSB_SHA512_DIGEST_SIZE]);

/**
 * @brief Compute SHA-512 hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest 64-byte output buffer
 */
KCTSB_API void kctsb_sha512(const uint8_t* data, size_t len,
                             uint8_t digest[KCTSB_SHA512_DIGEST_SIZE]);

/**
 * @brief Clear SHA-512 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha512_clear(kctsb_sha512_ctx_t* ctx);

/* ============================================================================
 * SHA3-256/512
 * ============================================================================ */

/**
 * @brief Initialize SHA3-256 context
 * @param ctx Context to initialize
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256_init(kctsb_sha3_ctx_t* ctx);

/**
 * @brief Update SHA3-256 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256_update(kctsb_sha3_ctx_t* ctx,
                                               const uint8_t* data, size_t len);

/**
 * @brief Finalize SHA3-256 and produce digest
 * @param ctx Context
 * @param digest 32-byte output buffer
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256_final(kctsb_sha3_ctx_t* ctx,
                                              uint8_t digest[KCTSB_SHA3_256_DIGEST_SIZE]);

/**
 * @brief Compute SHA3-256 hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest 32-byte output buffer
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_256(const uint8_t* data, size_t len,
                                        uint8_t digest[KCTSB_SHA3_256_DIGEST_SIZE]);

/**
 * @brief Initialize SHA3-512 context
 * @param ctx Context to initialize
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_512_init(kctsb_sha3_ctx_t* ctx);

/**
 * @brief Compute SHA3-512 hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest 64-byte output buffer
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sha3_512(const uint8_t* data, size_t len,
                                        uint8_t digest[KCTSB_SHA3_512_DIGEST_SIZE]);

/**
 * @brief Compute SHAKE128 XOF
 * @param data Input data
 * @param len Input length
 * @param output Output buffer
 * @param output_len Desired output length
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_shake128(const uint8_t* data, size_t len,
                                        uint8_t* output, size_t output_len);

/**
 * @brief Compute SHAKE256 XOF
 * @param data Input data
 * @param len Input length
 * @param output Output buffer
 * @param output_len Desired output length
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_shake256(const uint8_t* data, size_t len,
                                        uint8_t* output, size_t output_len);

/**
 * @brief Clear SHA3 context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_sha3_clear(kctsb_sha3_ctx_t* ctx);

/* ============================================================================
 * BLAKE2b/s
 * ============================================================================ */

/**
 * @brief Initialize BLAKE2b context
 * @param ctx Context to initialize
 * @param outlen Output length (1-64 bytes)
 */
KCTSB_API void kctsb_blake2b_init(kctsb_blake2b_ctx_t* ctx, size_t outlen);

/**
 * @brief Initialize BLAKE2b with key (for MAC)
 * @param ctx Context to initialize
 * @param outlen Output length
 * @param key Key data
 * @param keylen Key length (1-64 bytes)
 */
KCTSB_API void kctsb_blake2b_init_key(kctsb_blake2b_ctx_t* ctx, size_t outlen,
                                       const uint8_t* key, size_t keylen);

/**
 * @brief Update BLAKE2b context
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length
 */
KCTSB_API void kctsb_blake2b_update(kctsb_blake2b_ctx_t* ctx,
                                     const uint8_t* data, size_t len);

/**
 * @brief Finalize BLAKE2b
 * @param ctx Context
 * @param digest Output buffer (outlen bytes)
 */
KCTSB_API void kctsb_blake2b_final(kctsb_blake2b_ctx_t* ctx, uint8_t* digest);

/**
 * @brief Compute BLAKE2b hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest Output buffer
 * @param outlen Output length (1-64 bytes)
 */
KCTSB_API void kctsb_blake2b(const uint8_t* data, size_t len,
                              uint8_t* digest, size_t outlen);

/**
 * @brief Clear BLAKE2b context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_blake2b_clear(kctsb_blake2b_ctx_t* ctx);

/**
 * @brief Initialize BLAKE2s context
 * @param ctx Context to initialize
 * @param outlen Output length (1-32 bytes)
 */
KCTSB_API void kctsb_blake2s_init(kctsb_blake2s_ctx_t* ctx, size_t outlen);

/**
 * @brief Compute BLAKE2s hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest Output buffer
 * @param outlen Output length (1-32 bytes)
 */
KCTSB_API void kctsb_blake2s(const uint8_t* data, size_t len,
                              uint8_t* digest, size_t outlen);

/**
 * @brief Clear BLAKE2s context
 * @param ctx Context to clear
 */
KCTSB_API void kctsb_blake2s_clear(kctsb_blake2s_ctx_t* ctx);

/* ============================================================================
 * SM3 (Chinese National Standard Hash)
 * ============================================================================ */

/**
 * @brief Initialize SM3 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sm3_init(kctsb_sm3_ctx_t* ctx);

/**
 * @brief Update SM3 context with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length
 */
KCTSB_API void kctsb_sm3_update(kctsb_sm3_ctx_t* ctx,
                                 const uint8_t* data, size_t len);

/**
 * @brief Finalize SM3 and produce digest
 * @param ctx Context
 * @param digest 32-byte output buffer
 */
KCTSB_API void kctsb_sm3_final(kctsb_sm3_ctx_t* ctx, uint8_t digest[32]);

/**
 * @brief Compute SM3 hash in one call
 * @param data Input data
 * @param len Input length
 * @param digest 32-byte output buffer
 * @return KCTSB_SUCCESS on success
 */
KCTSB_API kctsb_error_t kctsb_sm3(const uint8_t* data, size_t len,
                                   uint8_t digest[32]);

/* ============================================================================
 * SM4-GCM (Chinese National Standard AEAD)
 * ============================================================================ */

/**
 * @brief Initialize SM4-GCM context
 * @param ctx GCM context
 * @param key 16-byte key
 * @param iv 12-byte IV/nonce
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_init(
    kctsb_sm4_gcm_ctx_t* ctx,
    const uint8_t key[16],
    const uint8_t iv[12]);

/**
 * @brief SM4-GCM authenticated encryption
 * @param ctx Initialized GCM context
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext
 * @param tag 16-byte authentication tag output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_encrypt(
    kctsb_sm4_gcm_ctx_t* ctx,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext, uint8_t tag[16]);

/**
 * @brief SM4-GCM authenticated decryption
 * @param ctx Initialized GCM context
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param tag 16-byte authentication tag to verify
 * @param plaintext Output plaintext (only written if tag verifies)
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_decrypt(
    kctsb_sm4_gcm_ctx_t* ctx,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16], uint8_t* plaintext);

/**
 * @brief One-shot SM4-GCM encryption
 * @param key 16-byte key
 * @param iv 12-byte IV/nonce
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext
 * @param tag 16-byte authentication tag output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_encrypt_oneshot(
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* ciphertext, uint8_t tag[16]);

/**
 * @brief One-shot SM4-GCM decryption
 * @param key 16-byte key
 * @param iv 12-byte IV/nonce
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param tag 16-byte authentication tag to verify
 * @param plaintext Output plaintext
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_decrypt_oneshot(
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16], uint8_t* plaintext);

/* ============================================================================
 * RSA (PSS/OAEP, SHA-256 only)
 * ============================================================================ */

/**
 * @brief Initialize RSA public key
 * @param key Output public key
 * @param n Modulus (big-endian)
 * @param n_len Modulus length (384 or 512 bytes)
 * @param e Public exponent (big-endian)
 * @param e_len Exponent length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_rsa_public_key_init(
    kctsb_rsa_public_key_t* key,
    const uint8_t* n, size_t n_len,
    const uint8_t* e, size_t e_len);

/**
 * @brief Initialize RSA private key (non-CRT)
 * @param key Output private key
 * @param n Modulus (big-endian)
 * @param n_len Modulus length
 * @param d Private exponent (big-endian)
 * @param d_len Exponent length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_rsa_private_key_init(
    kctsb_rsa_private_key_t* key,
    const uint8_t* n, size_t n_len,
    const uint8_t* d, size_t d_len);

/**
 * @brief Initialize RSA private key with CRT parameters
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_rsa_private_key_init_crt(
    kctsb_rsa_private_key_t* key,
    const uint8_t* n, size_t n_len,
    const uint8_t* d, size_t d_len,
    const uint8_t* p, size_t p_len,
    const uint8_t* q, size_t q_len,
    const uint8_t* dp, size_t dp_len,
    const uint8_t* dq, size_t dq_len,
    const uint8_t* qinv, size_t qinv_len);

/**
 * @brief Generate RSA keypair (3072/4096 only)
 * @param bits Key size in bits (3072 or 4096)
 * @param pub Output public key
 * @param priv Output private key
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_rsa_generate_keypair(
    int bits,
    kctsb_rsa_public_key_t* pub,
    kctsb_rsa_private_key_t* priv);

/**
 * @brief RSAES-OAEP encryption (SHA-256)
 * @param pub RSA public key
 * @param message Plaintext
 * @param message_len Plaintext length
 * @param label Optional OAEP label (can be NULL)
 * @param label_len Label length
 * @param ciphertext Output ciphertext (size >= modulus length)
 * @param ciphertext_len In: buffer size; Out: actual size
 */
KCTSB_API kctsb_error_t kctsb_rsa_oaep_encrypt_sha256(
    const kctsb_rsa_public_key_t* pub,
    const uint8_t* message, size_t message_len,
    const uint8_t* label, size_t label_len,
    uint8_t* ciphertext, size_t* ciphertext_len);

/**
 * @brief RSAES-OAEP decryption (SHA-256)
 * @param priv RSA private key
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length (modulus length)
 * @param label Optional OAEP label (can be NULL)
 * @param label_len Label length
 * @param message Output plaintext
 * @param message_len In: buffer size; Out: plaintext length
 */
KCTSB_API kctsb_error_t kctsb_rsa_oaep_decrypt_sha256(
    const kctsb_rsa_private_key_t* priv,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* label, size_t label_len,
    uint8_t* message, size_t* message_len);

/**
 * @brief RSASSA-PSS signature (SHA-256)
 * @param priv RSA private key
 * @param mhash Message hash (32 bytes)
 * @param mhash_len Hash length
 * @param salt Optional salt (32 bytes). If NULL, uses CSPRNG.
 * @param salt_len Salt length (0 if salt is NULL)
 * @param signature Output signature (size >= modulus length)
 * @param signature_len In: buffer size; Out: signature length
 */
KCTSB_API kctsb_error_t kctsb_rsa_pss_sign_sha256(
    const kctsb_rsa_private_key_t* priv,
    const uint8_t* mhash, size_t mhash_len,
    const uint8_t* salt, size_t salt_len,
    uint8_t* signature, size_t* signature_len);

/**
 * @brief RSASSA-PSS verify (SHA-256)
 * @param pub RSA public key
 * @param mhash Message hash (32 bytes)
 * @param mhash_len Hash length
 * @param signature Input signature
 * @param signature_len Signature length
 */
KCTSB_API kctsb_error_t kctsb_rsa_pss_verify_sha256(
    const kctsb_rsa_public_key_t* pub,
    const uint8_t* mhash, size_t mhash_len,
    const uint8_t* signature, size_t signature_len);

/* ============================================================================
 * HMAC
 * ============================================================================ */

/**
 * @brief Initialize HMAC-SHA256 context
 * @param ctx Context to initialize
 * @param key Key data
 * @param key_len Key length
 */
KCTSB_API void kctsb_hmac_sha256_init(kctsb_hmac_ctx_t* ctx,
                                       const uint8_t* key, size_t key_len);

/**
 * @brief Update HMAC-SHA256 context
 * @param ctx Initialized context
 * @param data Input data
 * @param len Input length
 */
KCTSB_API void kctsb_hmac_sha256_update(kctsb_hmac_ctx_t* ctx,
                                         const uint8_t* data, size_t len);

/**
 * @brief Finalize HMAC-SHA256
 * @param ctx Context
 * @param mac 32-byte output MAC
 */
KCTSB_API void kctsb_hmac_sha256_final(kctsb_hmac_ctx_t* ctx, uint8_t mac[32]);

/**
 * @brief Compute HMAC-SHA256 in one call
 * @param key Key data
 * @param key_len Key length
 * @param data Input data
 * @param len Input length
 * @param mac 32-byte output MAC
 */
KCTSB_API void kctsb_hmac_sha256(const uint8_t* key, size_t key_len,
                                  const uint8_t* data, size_t len,
                                  uint8_t mac[32]);

/**
 * @brief Compute CMAC-AES in one call
 * @param key 16-byte AES key
 * @param data Input data
 * @param len Input length
 * @param mac 16-byte output MAC
 */
KCTSB_API void kctsb_cmac_aes(const uint8_t key[16],
                               const uint8_t* data, size_t len,
                               uint8_t mac[16]);

/**
 * @brief Compute HMAC-SHA512 in one call
 * @param key Key data
 * @param key_len Key length
 * @param data Input data
 * @param len Input length
 * @param mac 64-byte output MAC
 */
KCTSB_API void kctsb_hmac_sha512(const uint8_t* key, size_t key_len,
                                  const uint8_t* data, size_t len,
                                  uint8_t mac[64]);

/**
 * @brief Compute GMAC (GCM-based MAC) in one call
 * @param key 16-byte AES key
 * @param iv Initialization vector
 * @param iv_len IV length (typically 12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param tag 16-byte output tag
 */
KCTSB_API void kctsb_gmac(const uint8_t key[16],
                           const uint8_t* iv, size_t iv_len,
                           const uint8_t* aad, size_t aad_len,
                           uint8_t tag[16]);

#ifdef __cplusplus
} /* extern "C" */
#endif

/* ============================================================================
 * C++ Convenience Namespace (Optional)
 * ============================================================================ */

#ifdef __cplusplus
#include <vector>
#include <string>
#include <array>
#include <stdexcept>

namespace kctsb {

using ByteVec = std::vector<uint8_t>;

/**
 * @brief SHA-256 hash helper
 */
inline std::array<uint8_t, KCTSB_SHA256_DIGEST_SIZE> sha256(const ByteVec& data) {
    std::array<uint8_t, KCTSB_SHA256_DIGEST_SIZE> digest;
    kctsb_sha256(data.data(), data.size(), digest.data());
    return digest;
}

/**
 * @brief SHA3-256 hash helper
 */
inline std::array<uint8_t, KCTSB_SHA3_256_DIGEST_SIZE> sha3_256(const ByteVec& data) {
    std::array<uint8_t, KCTSB_SHA3_256_DIGEST_SIZE> digest;
    if (kctsb_sha3_256(data.data(), data.size(), digest.data()) != KCTSB_SUCCESS) {
        throw std::runtime_error("SHA3-256 failed");
    }
    return digest;
}

/**
 * @brief BLAKE2b hash helper
 */
inline ByteVec blake2b(const ByteVec& data, size_t outlen = 32) {
    ByteVec digest(outlen);
    kctsb_blake2b(data.data(), data.size(), digest.data(), outlen);
    return digest;
}

/**
 * @brief SM3 hash helper
 */
inline std::array<uint8_t, KCTSB_SM3_DIGEST_SIZE> sm3(const ByteVec& data) {
    std::array<uint8_t, KCTSB_SM3_DIGEST_SIZE> digest;
    kctsb_sm3(data.data(), data.size(), digest.data());
    return digest;
}

/**
 * @brief Generate secure random bytes
 */
inline ByteVec random_bytes(size_t len) {
    ByteVec buf(len);
    if (kctsb_random_bytes(buf.data(), len) != 0) {
        throw std::runtime_error("Random generation failed");
    }
    return buf;
}

} /* namespace kctsb */

#endif /* __cplusplus */

#endif /* KCTSB_API_H */
