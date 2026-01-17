/**
 * @file chacha20_poly1305.h
 * @brief ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
 * 
 * Implementation of RFC 8439 (formerly RFC 7539):
 * - ChaCha20 stream cipher
 * - Poly1305 one-time authenticator
 * - Combined AEAD construction
 * 
 * Features:
 * - Side-channel resistant implementation
 * - Constant-time operations
 * - Secure memory handling
 * - High performance without hardware acceleration
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_CHACHA20_POLY1305_H
#define KCTSB_CRYPTO_CHACHA20_POLY1305_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ChaCha20 Stream Cipher
 * ============================================================================ */

/**
 * @brief ChaCha20 context
 */
typedef struct {
    uint32_t state[16];    // Current state
    uint8_t keystream[64]; // Current keystream block
    size_t remaining;      // Remaining bytes in keystream
} kctsb_chacha20_ctx_t;

/**
 * @brief Initialize ChaCha20 context
 * 
 * @param ctx ChaCha20 context to initialize
 * @param key 256-bit (32 byte) key
 * @param nonce 96-bit (12 byte) nonce
 * @param counter Initial counter value (usually 0 or 1)
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_chacha20_init(
    kctsb_chacha20_ctx_t* ctx,
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter
);

/**
 * @brief ChaCha20 encryption/decryption
 * 
 * The same function is used for both encryption and decryption.
 * 
 * @param ctx Initialized ChaCha20 context
 * @param input Input data
 * @param input_len Input length
 * @param output Output buffer (same size as input)
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_chacha20_crypt(
    kctsb_chacha20_ctx_t* ctx,
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
);

/**
 * @brief Stateless ChaCha20 encryption/decryption
 * 
 * @param key 256-bit key
 * @param nonce 96-bit nonce
 * @param counter Initial counter
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
    uint8_t* output
);

/**
 * @brief Clear ChaCha20 context
 */
KCTSB_API void kctsb_chacha20_clear(kctsb_chacha20_ctx_t* ctx);

/* ============================================================================
 * Poly1305 One-Time Authenticator
 * ============================================================================ */

/**
 * @brief Poly1305 context
 */
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

/**
 * @brief Initialize Poly1305 context with one-time key
 * 
 * @param ctx Poly1305 context
 * @param key 256-bit (32 byte) one-time key
 * @return KCTSB_SUCCESS or error code
 * 
 * @warning The key MUST be used only once! Use ChaCha20 derived key.
 */
KCTSB_API kctsb_error_t kctsb_poly1305_init(
    kctsb_poly1305_ctx_t* ctx,
    const uint8_t key[32]
);

/**
 * @brief Update Poly1305 with data
 * 
 * @param ctx Initialized Poly1305 context
 * @param data Input data
 * @param len Data length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_poly1305_update(
    kctsb_poly1305_ctx_t* ctx,
    const uint8_t* data,
    size_t len
);

/**
 * @brief Finalize Poly1305 and get tag
 * 
 * @param ctx Poly1305 context
 * @param tag 16-byte output tag
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_poly1305_final(
    kctsb_poly1305_ctx_t* ctx,
    uint8_t tag[16]
);

/**
 * @brief One-shot Poly1305 MAC
 * 
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
    uint8_t tag[16]
);

/**
 * @brief Verify Poly1305 tag (constant-time)
 * 
 * @param key 256-bit one-time key
 * @param data Input data
 * @param len Data length
 * @param tag Expected 16-byte tag
 * @return KCTSB_SUCCESS or KCTSB_ERROR_AUTH_FAILED
 */
KCTSB_API kctsb_error_t kctsb_poly1305_verify(
    const uint8_t key[32],
    const uint8_t* data,
    size_t len,
    const uint8_t tag[16]
);

/**
 * @brief Clear Poly1305 context
 */
KCTSB_API void kctsb_poly1305_clear(kctsb_poly1305_ctx_t* ctx);

/* ============================================================================
 * ChaCha20-Poly1305 AEAD
 * ============================================================================ */

/**
 * @brief ChaCha20-Poly1305 AEAD context for streaming operations
 */
typedef struct {
    kctsb_chacha20_ctx_t chacha_ctx;
    kctsb_poly1305_ctx_t poly_ctx;
    uint64_t aad_len;
    uint64_t ct_len;
    int aad_finalized;
    int finalized;
} kctsb_chacha20_poly1305_ctx_t;

/**
 * @brief ChaCha20-Poly1305 authenticated encryption
 * 
 * @param key 256-bit key
 * @param nonce 96-bit nonce (MUST be unique per key)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext (same size as plaintext)
 * @param tag 16-byte authentication tag output
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t tag[16]
);

/**
 * @brief ChaCha20-Poly1305 authenticated decryption
 * 
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
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t* plaintext
);

/* Streaming API */

/**
 * @brief Initialize streaming AEAD encryption context
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_init_encrypt(
    kctsb_chacha20_poly1305_ctx_t* ctx,
    const uint8_t key[32],
    const uint8_t nonce[12]
);

/**
 * @brief Initialize streaming AEAD decryption context
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_init_decrypt(
    kctsb_chacha20_poly1305_ctx_t* ctx,
    const uint8_t key[32],
    const uint8_t nonce[12]
);

/**
 * @brief Update with additional authenticated data
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_update_aad(
    kctsb_chacha20_poly1305_ctx_t* ctx,
    const uint8_t* aad,
    size_t aad_len
);

/**
 * @brief Encrypt data in streaming mode
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_update_encrypt(
    kctsb_chacha20_poly1305_ctx_t* ctx,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext
);

/**
 * @brief Decrypt data in streaming mode
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_update_decrypt(
    kctsb_chacha20_poly1305_ctx_t* ctx,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext
);

/**
 * @brief Finalize encryption and get tag
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_final_encrypt(
    kctsb_chacha20_poly1305_ctx_t* ctx,
    uint8_t tag[16]
);

/**
 * @brief Finalize decryption and verify tag
 */
KCTSB_API kctsb_error_t kctsb_chacha20_poly1305_final_decrypt(
    kctsb_chacha20_poly1305_ctx_t* ctx,
    const uint8_t tag[16]
);

/**
 * @brief Clear AEAD context
 */
KCTSB_API void kctsb_chacha20_poly1305_clear(kctsb_chacha20_poly1305_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

// C++ Interface
#ifdef __cplusplus

#include <vector>
#include <array>
#include <utility>
#include <stdexcept>

namespace kctsb {

/**
 * @brief ChaCha20-Poly1305 AEAD class
 * 
 * High-performance AEAD cipher suitable for software implementations.
 * Does not require AES hardware acceleration.
 */
class ChaCha20Poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;
    
    /**
     * @brief Construct with 256-bit key
     */
    explicit ChaCha20Poly1305(const ByteVec& key);
    explicit ChaCha20Poly1305(const uint8_t key[32]);
    
    ~ChaCha20Poly1305();
    
    // Disable copy
    ChaCha20Poly1305(const ChaCha20Poly1305&) = delete;
    ChaCha20Poly1305& operator=(const ChaCha20Poly1305&) = delete;
    
    // Enable move
    ChaCha20Poly1305(ChaCha20Poly1305&&) noexcept;
    ChaCha20Poly1305& operator=(ChaCha20Poly1305&&) noexcept;
    
    /**
     * @brief Authenticated encryption
     * @param plaintext Input data
     * @param nonce 12-byte nonce (MUST be unique per message)
     * @param aad Additional authenticated data
     * @return Pair of (ciphertext, 16-byte tag)
     */
    std::pair<ByteVec, std::array<uint8_t, 16>> encrypt(
        const ByteVec& plaintext,
        const std::array<uint8_t, 12>& nonce,
        const ByteVec& aad = {}
    ) const;
    
    /**
     * @brief Authenticated decryption
     * @param ciphertext Input data
     * @param nonce 12-byte nonce
     * @param tag Authentication tag
     * @param aad Additional authenticated data
     * @return Plaintext
     * @throws std::runtime_error if authentication fails
     */
    ByteVec decrypt(
        const ByteVec& ciphertext,
        const std::array<uint8_t, 12>& nonce,
        const std::array<uint8_t, 16>& tag,
        const ByteVec& aad = {}
    ) const;
    
    /**
     * @brief Generate random nonce
     */
    static std::array<uint8_t, 12> generateNonce();
    
    /**
     * @brief Generate random key
     */
    static ByteVec generateKey();
    
private:
    std::array<uint8_t, 32> key_;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_CHACHA20_POLY1305_H
