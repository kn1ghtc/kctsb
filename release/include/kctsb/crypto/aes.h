/**
 * @file aes.h
 * @brief AES (Advanced Encryption Standard) implementation - Production Grade
 * 
 * Provides AES-128/192/256 encryption with SECURE MODES ONLY:
 * - CTR (Counter Mode) - Streaming encryption
 * - GCM (Galois/Counter Mode) - AEAD with authentication
 * 
 * SECURITY NOTE: ECB and CBC modes are NOT supported as they are
 * considered insecure for most use cases. Use GCM for AEAD or CTR
 * with a separate MAC for authenticated encryption.
 * 
 * Features:
 * - Side-channel resistant implementation
 * - Secure memory handling
 * - Constant-time operations
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_AES_H
#define KCTSB_CRYPTO_AES_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief AES context structure
 * 
 * Internal structure - do not access fields directly.
 */
typedef struct {
    uint32_t round_keys[60];  // Expanded key schedule (max 14 rounds * 4 + 4)
    int key_bits;             // 128, 192, or 256
    int rounds;               // Number of rounds (10, 12, or 14)
} kctsb_aes_ctx_t;

/**
 * @brief AES-GCM context for streaming operations
 */
typedef struct {
    kctsb_aes_ctx_t aes_ctx;
    uint8_t h[16];            // H = AES(K, 0^128) for GHASH
    uint8_t j0[16];           // Initial counter block
    uint8_t counter[16];      // Current counter
    uint8_t tag[16];          // Running authentication tag
    uint64_t aad_len;         // Total AAD length processed
    uint64_t ct_len;          // Total ciphertext length processed
    int finalized;            // Whether finalized
} kctsb_aes_gcm_ctx_t;

/**
 * @brief Initialize AES context with key
 * 
 * @param ctx AES context to initialize
 * @param key Encryption key (16, 24, or 32 bytes for AES-128/192/256)
 * @param key_len Key length in bytes
 * @return KCTSB_SUCCESS or error code
 * 
 * @note Key material is securely handled and not stored in plaintext
 */
KCTSB_API kctsb_error_t kctsb_aes_init(
    kctsb_aes_ctx_t* ctx,
    const uint8_t* key,
    size_t key_len
);

/**
 * @brief Encrypt single AES block (INTERNAL USE - prefer CTR/GCM modes)
 * 
 * @warning Direct block cipher usage is discouraged. Use CTR or GCM mode.
 * 
 * @param ctx Initialized AES context
 * @param input 16-byte input block
 * @param output 16-byte output block
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_encrypt_block(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]
);

/**
 * @brief Decrypt single AES block (INTERNAL USE - prefer CTR/GCM modes)
 * 
 * @warning Direct block cipher usage is discouraged. Use CTR or GCM mode.
 */
KCTSB_API kctsb_error_t kctsb_aes_decrypt_block(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]
);

/**
 * @brief AES-CTR encryption/decryption
 * 
 * Counter mode provides streaming encryption. The same function is used
 * for both encryption and decryption.
 * 
 * @param ctx Initialized AES context
 * @param nonce 12-byte nonce (MUST be unique for each message with same key)
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer (same size as input)
 * @return KCTSB_SUCCESS or error code
 * 
 * @warning Never reuse a nonce with the same key!
 */
KCTSB_API kctsb_error_t kctsb_aes_ctr_crypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t nonce[12],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief AES-GCM authenticated encryption
 * 
 * GCM provides both confidentiality and authenticity (AEAD).
 * 
 * @param ctx Initialized AES context
 * @param iv Initialization vector (12 bytes recommended, other sizes processed per spec)
 * @param iv_len IV length (use 12 for best performance)
 * @param aad Additional authenticated data (authenticated but not encrypted)
 * @param aad_len AAD length (can be 0)
 * @param input Plaintext input
 * @param input_len Input length
 * @param output Ciphertext output (same size as input)
 * @param tag 16-byte authentication tag output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_encrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv,
    size_t iv_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output,
    uint8_t tag[16]
);

/**
 * @brief AES-GCM authenticated decryption
 * 
 * Verifies authentication tag before returning plaintext.
 * 
 * @param ctx Initialized AES context
 * @param iv Initialization vector
 * @param iv_len IV length
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param input Ciphertext input
 * @param input_len Input length
 * @param tag 16-byte authentication tag to verify
 * @param output Plaintext output (only written if verification succeeds)
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED if tag doesn't match
 * 
 * @note On authentication failure, output buffer is securely zeroed
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_decrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv,
    size_t iv_len,
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* input,
    size_t input_len,
    const uint8_t tag[16],
    uint8_t* output
);

/* ============================================================================
 * Streaming GCM API for large data
 * ============================================================================ */

/**
 * @brief Initialize streaming GCM encryption context
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_init(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* key,
    size_t key_len,
    const uint8_t* iv,
    size_t iv_len
);

/**
 * @brief Process additional authenticated data (AAD)
 * 
 * Must be called before any update_encrypt/update_decrypt calls.
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_update_aad(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* aad,
    size_t aad_len
);

/**
 * @brief Encrypt data in streaming mode
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_update_encrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief Finalize GCM encryption and get authentication tag
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_final_encrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    uint8_t tag[16]
);

/**
 * @brief Decrypt data in streaming mode
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_update_decrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief Finalize GCM decryption and verify tag
 * 
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_aes_gcm_final_decrypt(
    kctsb_aes_gcm_ctx_t* ctx,
    const uint8_t tag[16]
);

/**
 * @brief Clear AES context (secure zeroing)
 * 
 * Securely zeros all key material. Always call when done with context.
 * 
 * @param ctx AES context to clear
 */
KCTSB_API void kctsb_aes_clear(kctsb_aes_ctx_t* ctx);

/**
 * @brief Clear GCM context (secure zeroing)
 */
KCTSB_API void kctsb_aes_gcm_clear(kctsb_aes_gcm_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

// C++ interface
#ifdef __cplusplus

#include <vector>
#include <array>
#include <string>
#include <stdexcept>
#include <utility>

namespace kctsb {

/**
 * @brief AES encryption class - Secure modes only
 * 
 * Provides AES encryption with CTR and GCM modes only.
 * ECB and CBC are not supported for security reasons.
 */
class AES {
public:
    /**
     * @brief Construct AES instance with key
     * @param key Encryption key (128, 192, or 256 bits)
     * @throws std::invalid_argument if key size is invalid
     */
    explicit AES(const ByteVec& key);
    explicit AES(const uint8_t* key, size_t key_len);
    
    ~AES();
    
    // Disable copy (key security)
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;
    
    // Enable move
    AES(AES&& other) noexcept;
    AES& operator=(AES&& other) noexcept;
    
    /**
     * @brief CTR mode encryption/decryption
     * @param data Input data
     * @param nonce 12-byte nonce (MUST be unique per message)
     * @return Output data
     */
    ByteVec ctrCrypt(const ByteVec& data, const std::array<uint8_t, 12>& nonce) const;
    
    /**
     * @brief GCM mode authenticated encryption
     * @param plaintext Input data
     * @param iv IV (12 bytes recommended)
     * @param aad Additional authenticated data
     * @return Pair of (ciphertext, 16-byte tag)
     */
    std::pair<ByteVec, AESBlock> gcmEncrypt(
        const ByteVec& plaintext,
        const ByteVec& iv,
        const ByteVec& aad = {}
    ) const;
    
    /**
     * @brief GCM mode authenticated decryption
     * @param ciphertext Input data
     * @param iv IV
     * @param tag Authentication tag
     * @param aad Additional authenticated data
     * @return Plaintext
     * @throws std::runtime_error if authentication fails
     */
    ByteVec gcmDecrypt(
        const ByteVec& ciphertext,
        const ByteVec& iv,
        const AESBlock& tag,
        const ByteVec& aad = {}
    ) const;
    
    /**
     * @brief Generate random nonce for CTR mode
     * @return 12-byte cryptographically random nonce
     */
    static std::array<uint8_t, 12> generateNonce();
    
    /**
     * @brief Generate random IV for GCM mode
     * @return 12-byte cryptographically random IV
     */
    static ByteVec generateIV(size_t len = 12);
    
private:
    kctsb_aes_ctx_t ctx_;
    
    // Internal block operations (for mode implementations)
    AESBlock encryptBlock(const AESBlock& input) const;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_AES_H
