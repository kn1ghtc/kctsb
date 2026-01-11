/**
 * @file aes.h
 * @brief AES (Advanced Encryption Standard) implementation
 * 
 * Provides AES-128/192/256 encryption and decryption with multiple modes:
 * - ECB (Electronic Codebook)
 * - CBC (Cipher Block Chaining)
 * - CTR (Counter Mode)
 * - GCM (Galois/Counter Mode)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_AES_H
#define KCTSB_CRYPTO_AES_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// AES context structure
typedef struct {
    uint32_t round_keys[60];  // Expanded key schedule
    int key_bits;             // 128, 192, or 256
    int rounds;               // Number of rounds (10, 12, or 14)
} kctsb_aes_ctx_t;

/**
 * @brief Initialize AES context with key
 * @param ctx AES context to initialize
 * @param key Encryption key (16, 24, or 32 bytes)
 * @param key_len Key length in bytes
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_init(
    kctsb_aes_ctx_t* ctx,
    const uint8_t* key,
    size_t key_len
);

/**
 * @brief Encrypt single AES block (ECB mode, 16 bytes)
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
 * @brief Decrypt single AES block (ECB mode, 16 bytes)
 * @param ctx Initialized AES context
 * @param input 16-byte input block
 * @param output 16-byte output block
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_decrypt_block(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t input[16],
    uint8_t output[16]
);

/**
 * @brief AES-CBC encryption
 * @param ctx Initialized AES context
 * @param iv 16-byte initialization vector
 * @param input Input plaintext (must be multiple of 16 bytes)
 * @param input_len Input length
 * @param output Output ciphertext buffer
 * @param output_len Output buffer size
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_cbc_encrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t iv[16],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output,
    size_t* output_len
);

/**
 * @brief AES-CBC decryption
 * @param ctx Initialized AES context
 * @param iv 16-byte initialization vector
 * @param input Input ciphertext
 * @param input_len Input length
 * @param output Output plaintext buffer
 * @param output_len Output buffer size
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_cbc_decrypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t iv[16],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output,
    size_t* output_len
);

/**
 * @brief AES-CTR encryption/decryption
 * @param ctx Initialized AES context
 * @param nonce 12-byte nonce (counter uses remaining 4 bytes)
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_aes_ctr_crypt(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t nonce[12],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief AES-GCM encryption with authentication
 * @param ctx Initialized AES context
 * @param iv Initialization vector
 * @param iv_len IV length (recommended 12 bytes)
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param input Plaintext input
 * @param input_len Input length
 * @param output Ciphertext output
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
 * @brief AES-GCM decryption with authentication
 * @param ctx Initialized AES context
 * @param iv Initialization vector
 * @param iv_len IV length
 * @param aad Additional authenticated data
 * @param aad_len AAD length
 * @param input Ciphertext input
 * @param input_len Input length
 * @param tag 16-byte authentication tag
 * @param output Plaintext output
 * @return KCTSB_SUCCESS or KCTSB_ERROR_VERIFICATION_FAILED
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

/**
 * @brief Clear AES context (secure zeroing)
 * @param ctx AES context to clear
 */
KCTSB_API void kctsb_aes_clear(kctsb_aes_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

// C++ interface
#ifdef __cplusplus

#include <vector>
#include <array>
#include <string>
#include <stdexcept>

namespace kctsb {

/**
 * @brief AES encryption class
 */
class AES {
public:
    /**
     * @brief Construct AES instance with key
     * @param key Encryption key (128, 192, or 256 bits)
     */
    explicit AES(const ByteVec& key);
    explicit AES(const uint8_t* key, size_t key_len);
    
    ~AES();
    
    // Disable copy
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;
    
    // Enable move
    AES(AES&& other) noexcept;
    AES& operator=(AES&& other) noexcept;
    
    /**
     * @brief Encrypt single block (ECB mode)
     */
    AESBlock encryptBlock(const AESBlock& input) const;
    
    /**
     * @brief Decrypt single block (ECB mode)
     */
    AESBlock decryptBlock(const AESBlock& input) const;
    
    /**
     * @brief CBC mode encryption
     * @param plaintext Input data
     * @param iv 16-byte IV
     * @return Ciphertext
     */
    ByteVec cbcEncrypt(const ByteVec& plaintext, const AESBlock& iv) const;
    
    /**
     * @brief CBC mode decryption
     * @param ciphertext Input data
     * @param iv 16-byte IV
     * @return Plaintext
     */
    ByteVec cbcDecrypt(const ByteVec& ciphertext, const AESBlock& iv) const;
    
    /**
     * @brief CTR mode encryption/decryption
     * @param data Input data
     * @param nonce 12-byte nonce
     * @return Output data
     */
    ByteVec ctrCrypt(const ByteVec& data, const std::array<uint8_t, 12>& nonce) const;
    
    /**
     * @brief GCM mode authenticated encryption
     * @param plaintext Input data
     * @param iv IV (recommended 12 bytes)
     * @param aad Additional authenticated data
     * @return Pair of (ciphertext, tag)
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
    
private:
    kctsb_aes_ctx_t ctx_;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_AES_H
