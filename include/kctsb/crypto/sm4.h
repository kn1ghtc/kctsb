/**
 * @file sm4.h
 * @brief SM4 block cipher (Chinese National Standard)
 * 
 * Implements GB/T 32907-2016 specification.
 * 128-bit block size, 128-bit key.
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

// SM4 context structure
typedef struct {
    uint32_t round_keys[32];
} kctsb_sm4_ctx_t;

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
 * @brief SM4-CBC encryption
 * @param ctx Initialized encryption context
 * @param iv 16-byte initialization vector
 * @param input Input plaintext
 * @param input_len Input length (must be multiple of 16)
 * @param output Output ciphertext
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_cbc_encrypt(
    const kctsb_sm4_ctx_t* ctx,
    const uint8_t iv[16],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief SM4-CBC decryption
 * @param ctx Initialized decryption context
 * @param iv 16-byte initialization vector
 * @param input Input ciphertext
 * @param input_len Input length
 * @param output Output plaintext
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm4_cbc_decrypt(
    const kctsb_sm4_ctx_t* ctx,
    const uint8_t iv[16],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
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
 * @brief SM4 block cipher
 */
class SM4 {
public:
    explicit SM4(const SM4Key& key);
    explicit SM4(const uint8_t key[16]);
    
    ~SM4();
    
    SM4Block encryptBlock(const SM4Block& input) const;
    SM4Block decryptBlock(const SM4Block& input) const;
    
    ByteVec cbcEncrypt(const ByteVec& plaintext, const SM4Block& iv) const;
    ByteVec cbcDecrypt(const ByteVec& ciphertext, const SM4Block& iv) const;
    
private:
    kctsb_sm4_ctx_t enc_ctx_;
    kctsb_sm4_ctx_t dec_ctx_;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_SM4_H
