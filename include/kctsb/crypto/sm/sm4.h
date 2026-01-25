/**
 * @file sm4.h
 * @brief SM4 block cipher (Chinese National Standard) - GCM mode only
 *
 * Implements GB/T 32907-2016 specification.
 * 128-bit block size, 128-bit key.
 *
 * SECURITY NOTE: Only GCM mode is supported for authenticated encryption.
 * CBC mode has been removed as it does not provide authentication.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_SM4_H
#define KCTSB_CRYPTO_SM4_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// SM4 constants
#define KCTSB_SM4_BLOCK_SIZE    16
#define KCTSB_SM4_KEY_SIZE      16
#define KCTSB_SM4_GCM_IV_SIZE   12
#define KCTSB_SM4_GCM_TAG_SIZE  16

// SM4 context structure (with guard for kctsb_api.h inclusion)
#ifndef KCTSB_SM4_CTX_DEFINED
#define KCTSB_SM4_CTX_DEFINED
typedef struct {
    uint32_t round_keys[32];
} kctsb_sm4_ctx_t;
#endif

// SM4-GCM context structure (with guard for kctsb_api.h inclusion)
#ifndef KCTSB_SM4_GCM_CTX_DEFINED
#define KCTSB_SM4_GCM_CTX_DEFINED
typedef struct {
    kctsb_sm4_ctx_t cipher_ctx;
    uint8_t h[16];          // GHASH subkey H = E(K, 0)
    uint8_t j0[16];         // Pre-counter block
    uint8_t ghash_state[16];
    size_t aad_len;
    size_t cipher_len;
} kctsb_sm4_gcm_ctx_t;
#endif

/**
 * @brief Initialize SM4 context for encryption
 * @param ctx Context to initialize
 * @param key 16-byte encryption key
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_set_encrypt_key(
    kctsb_sm4_ctx_t* ctx,
    const uint8_t key[16]
);

/**
 * @brief Initialize SM4 context for decryption
 * @param ctx Context to initialize
 * @param key 16-byte encryption key
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_set_decrypt_key(
    kctsb_sm4_ctx_t* ctx,
    const uint8_t key[16]
);

/**
 * @brief Encrypt single SM4 block (16 bytes)
 * @param ctx Initialized context
 * @param input 16-byte input block
 * @param output 16-byte output block
 */
KCTSB_API void kctsb_sm4_encrypt_block(
    const kctsb_sm4_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]
);

/**
 * @brief Decrypt single SM4 block (16 bytes)
 * @param ctx Initialized context
 * @param input 16-byte input block
 * @param output 16-byte output block
 */
KCTSB_API void kctsb_sm4_decrypt_block(
    const kctsb_sm4_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]
);

/**
 * @brief Initialize SM4-GCM context
 * @param ctx GCM context to initialize
 * @param key 16-byte encryption key
 * @param iv 12-byte initialization vector (nonce)
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_init(
    kctsb_sm4_gcm_ctx_t* ctx,
    const uint8_t key[16],
    const uint8_t iv[12]
);

/**
 * @brief SM4-GCM authenticated encryption
 * @param ctx Initialized GCM context
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext (same size as plaintext)
 * @param tag Output authentication tag (16 bytes)
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_encrypt(
    kctsb_sm4_gcm_ctx_t* ctx,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t tag[16]
);

/**
 * @brief SM4-GCM authenticated decryption
 * @param ctx Initialized GCM context
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param tag Authentication tag to verify (16 bytes)
 * @param plaintext Output plaintext (same size as ciphertext)
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_decrypt(
    kctsb_sm4_gcm_ctx_t* ctx,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t* plaintext
);

/**
 * @brief One-shot SM4-GCM encryption
 * @param key 16-byte key
 * @param iv 12-byte nonce
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext
 * @param tag Output 16-byte authentication tag
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_encrypt_oneshot(
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t tag[16]
);

/**
 * @brief One-shot SM4-GCM decryption
 * @param key 16-byte key
 * @param iv 12-byte nonce
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param tag 16-byte authentication tag
 * @param plaintext Output plaintext
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_sm4_gcm_decrypt_oneshot(
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t* plaintext
);

/**
 * @brief SM4 self test
 * @return KCTSB_SUCCESS if test passes
 */
KCTSB_API kctsb_error_t kctsb_sm4_self_test(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace kctsb {

/**
 * @brief SM4-GCM AEAD cipher
 */
class SM4GCM {
public:
    explicit SM4GCM(const uint8_t key[16]);
    ~SM4GCM();

    /**
     * @brief Encrypt with authentication
     * @param nonce 12-byte nonce
     * @param aad Additional authenticated data
     * @param plaintext Data to encrypt
     * @return Ciphertext || Tag (16 bytes)
     */
    ByteVec encrypt(const ByteVec& nonce, const ByteVec& aad, const ByteVec& plaintext);

    /**
     * @brief Decrypt with authentication
     * @param nonce 12-byte nonce
     * @param aad Additional authenticated data
     * @param ciphertext_with_tag Ciphertext || Tag
     * @return Plaintext or empty on auth failure
     */
    ByteVec decrypt(const ByteVec& nonce, const ByteVec& aad, const ByteVec& ciphertext_with_tag);

private:
    kctsb_sm4_ctx_t ctx_;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_SM4_H
