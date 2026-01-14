/**
 * @file sm3.h
 * @brief SM3 cryptographic hash function (Chinese National Standard)
 * 
 * Implements GB/T 32905-2016 specification.
 * 256-bit hash output, similar to SHA-256.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_SM3_H
#define KCTSB_CRYPTO_SM3_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// SM3 context structure
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} kctsb_sm3_ctx_t;

/**
 * @brief Initialize SM3 context
 * @param ctx Context to initialize
 */
KCTSB_API void kctsb_sm3_init(kctsb_sm3_ctx_t* ctx);

/**
 * @brief Update SM3 with data
 * @param ctx Initialized context
 * @param data Input data
 * @param len Data length
 */
KCTSB_API void kctsb_sm3_update(kctsb_sm3_ctx_t* ctx, const uint8_t* data, size_t len);

/**
 * @brief Finalize and get SM3 digest
 * @param ctx Context
 * @param digest 32-byte output buffer
 */
KCTSB_API void kctsb_sm3_final(kctsb_sm3_ctx_t* ctx, uint8_t digest[32]);

/**
 * @brief Compute SM3 hash in one call
 * @param data Input data
 * @param len Data length
 * @param digest 32-byte output buffer
 */
KCTSB_API void kctsb_sm3(const uint8_t* data, size_t len, uint8_t digest[32]);

/**
 * @brief SM3 self test
 * @return KCTSB_SUCCESS if test passes
 */
KCTSB_API kctsb_error_t kctsb_sm3_self_test(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace kctsb {

/**
 * @brief SM3 hash computation
 */
class SM3 {
public:
    SM3();
    
    void update(const ByteVec& data);
    void update(const uint8_t* data, size_t len);
    void update(const std::string& str);
    
    SM3Digest digest();
    void reset();
    
    // One-shot hashing
    static SM3Digest hash(const ByteVec& data);
    static SM3Digest hash(const std::string& str);
    static std::string hashHex(const ByteVec& data);
    static std::string hashHex(const std::string& str);
    
private:
    kctsb_sm3_ctx_t ctx_;
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_SM3_H
