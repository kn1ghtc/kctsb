/**
 * @file sha.h
 * @brief SHA (Secure Hash Algorithm) family implementation
 * 
 * Provides SHA-256, SHA-384, SHA-512 hash functions.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_SHA_H
#define KCTSB_CRYPTO_SHA_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// SHA-256 context
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} kctsb_sha256_ctx_t;

// SHA-512 context (also used for SHA-384)
typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
} kctsb_sha512_ctx_t;

typedef kctsb_sha512_ctx_t kctsb_sha384_ctx_t;

// ============================================================================
// SHA-256
// ============================================================================

/**
 * @brief Initialize SHA-256 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sha256_init(kctsb_sha256_ctx_t* ctx);

/**
 * @brief Update SHA-256 with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Data length
 */
KCTSB_API void kctsb_sha256_update(kctsb_sha256_ctx_t* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize and get SHA-256 digest
 * @param ctx Context
 * @param digest 32-byte output buffer
 */
KCTSB_API void kctsb_sha256_final(kctsb_sha256_ctx_t* ctx, uint8_t digest[32]);

/**
 * @brief Compute SHA-256 hash in one call
 * @param data Input data
 * @param len Data length
 * @param digest 32-byte output buffer
 */
KCTSB_API void kctsb_sha256(const uint8_t* data, size_t len, uint8_t digest[32]);

// ============================================================================
// SHA-384
// ============================================================================

KCTSB_API void kctsb_sha384_init(kctsb_sha384_ctx_t* ctx);
KCTSB_API void kctsb_sha384_update(kctsb_sha384_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_sha384_final(kctsb_sha384_ctx_t* ctx, uint8_t digest[48]);
KCTSB_API void kctsb_sha384(const uint8_t* data, size_t len, uint8_t digest[48]);

// ============================================================================
// SHA-512
// ============================================================================

KCTSB_API void kctsb_sha512_init(kctsb_sha512_ctx_t* ctx);
KCTSB_API void kctsb_sha512_update(kctsb_sha512_ctx_t* ctx, const uint8_t* data, size_t len);
KCTSB_API void kctsb_sha512_final(kctsb_sha512_ctx_t* ctx, uint8_t digest[64]);
KCTSB_API void kctsb_sha512(const uint8_t* data, size_t len, uint8_t digest[64]);

#ifdef __cplusplus
}
#endif

// C++ interface
#ifdef __cplusplus

namespace kctsb {

/**
 * @brief SHA-256 hash computation
 */
class SHA256 {
public:
    SHA256();
    
    void update(const ByteVec& data);
    void update(const uint8_t* data, size_t len);
    void update(const std::string& str);
    
    SHA256Digest digest();
    void reset();
    
    // One-shot hashing
    static SHA256Digest hash(const ByteVec& data);
    static SHA256Digest hash(const std::string& str);
    static std::string hashHex(const ByteVec& data);
    static std::string hashHex(const std::string& str);
    
private:
    kctsb_sha256_ctx_t ctx_;
};

/**
 * @brief SHA-384 hash computation
 */
class SHA384 {
public:
    SHA384();
    
    void update(const ByteVec& data);
    void update(const uint8_t* data, size_t len);
    
    SHA384Digest digest();
    void reset();
    
    static SHA384Digest hash(const ByteVec& data);
    
private:
    kctsb_sha384_ctx_t ctx_;
};

/**
 * @brief SHA-512 hash computation
 */
class SHA512 {
public:
    SHA512();
    
    void update(const ByteVec& data);
    void update(const uint8_t* data, size_t len);
    
    SHA512Digest digest();
    void reset();
    
    static SHA512Digest hash(const ByteVec& data);
    
private:
    kctsb_sha512_ctx_t ctx_;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_SHA_H
