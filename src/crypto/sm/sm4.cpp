/**
 * @file sm4.cpp
 * @brief SM4 Block Cipher Implementation - C++ Core + C ABI Export
 *
 * GB/T 32907-2016 compliant SM4 block cipher implementation.
 * Architecture: C++ internal implementation + extern "C" API export.
 *
 * Features:
 * - 128-bit block size, 128-bit key
 * - ECB (single block) encryption/decryption
 * - GCM authenticated encryption mode
 * - GHASH with PCLMUL acceleration (when available)
 * - 8-block parallel CTR encryption (optimized for large data)
 *
 * Optimization Hierarchy:
 * 1. PCLMUL-accelerated GHASH (8-block parallel, ~5-8x faster)
 * 2. 8-block parallel CTR mode encryption (128 bytes per batch)
 * 3. 4-block fallback for remaining data
 * 4. Software fallback for legacy systems
 *
 * Reference:
 * - GB/T 32907-2016: SM4 Block Cipher Algorithm
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm4.h"
#include "kctsb/core/common.h"
#include "kctsb/simd/simd.h"
#include <array>
#include <cstring>
#include <cstdint>

// PCLMUL detection for accelerated GHASH
#if defined(__PCLMUL__) || defined(KCTSB_HAS_PCLMUL)
    #define SM4_HAS_PCLMUL 1
#endif

// ============================================================================
// C++ Internal Implementation
// ============================================================================

namespace kctsb::internal {

/**
 * @brief SM4 S-box (exported for AESNI acceleration)
 */
alignas(64) const std::array<uint8_t, 256> SM4_SBOX = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

/**
 * @brief SM4 CK constants
 */
constexpr std::array<uint32_t, 32> SM4_CK = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/**
 * @brief SM4 FK constants
 */
constexpr std::array<uint32_t, 4> SM4_FK = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

// Helper macros
#define SM4_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/**
 * @brief SM4 T transformation (S-box + Linear transformation L)
 */
__attribute__((always_inline))
static inline uint32_t sm4_t(uint32_t x) noexcept {
    uint32_t buf = (static_cast<uint32_t>(SM4_SBOX[(x >> 24) & 0xFF]) << 24) |
                   (static_cast<uint32_t>(SM4_SBOX[(x >> 16) & 0xFF]) << 16) |
                   (static_cast<uint32_t>(SM4_SBOX[(x >> 8) & 0xFF]) << 8) |
                   (static_cast<uint32_t>(SM4_SBOX[x & 0xFF]));
    return buf ^ SM4_ROTL32(buf, 2) ^ SM4_ROTL32(buf, 10) ^
           SM4_ROTL32(buf, 18) ^ SM4_ROTL32(buf, 24);
}

/**
 * @brief SM4 T' transformation for key expansion
 */
__attribute__((always_inline))
static inline uint32_t sm4_t_prime(uint32_t x) noexcept {
    uint32_t buf = (static_cast<uint32_t>(SM4_SBOX[(x >> 24) & 0xFF]) << 24) |
                   (static_cast<uint32_t>(SM4_SBOX[(x >> 16) & 0xFF]) << 16) |
                   (static_cast<uint32_t>(SM4_SBOX[(x >> 8) & 0xFF]) << 8) |
                   (static_cast<uint32_t>(SM4_SBOX[x & 0xFF]));
    return buf ^ SM4_ROTL32(buf, 13) ^ SM4_ROTL32(buf, 23);
}

#undef SM4_ROTL32

/**
 * @brief SM4 core operations class
 */
class SM4Core {
public:
    /**
     * @brief Generate round keys
     */
    static void key_schedule(const uint8_t key[16], uint32_t rk[32]) noexcept {
        uint32_t K[36];

        // Initialize K with key XOR FK
        for (size_t i = 0; i < 4; i++) {
            K[i] = SM4_FK[i] ^ (
                (static_cast<uint32_t>(key[4*i]) << 24) |
                (static_cast<uint32_t>(key[4*i+1]) << 16) |
                (static_cast<uint32_t>(key[4*i+2]) << 8) |
                static_cast<uint32_t>(key[4*i+3])
            );
        }

        // Generate round keys
        for (size_t i = 0; i < 32; i++) {
            K[i+4] = K[i] ^ sm4_t_prime(K[i+1] ^ K[i+2] ^ K[i+3] ^ SM4_CK[i]);
            rk[i] = K[i+4];
        }
    }

    /**
     * @brief Encrypt/decrypt single block
     */
    static void process_block(const uint32_t rk[32], const uint8_t in[16],
                               uint8_t out[16], bool reverse_keys = false) noexcept {
        uint32_t X[36];

        // Load input block
        for (size_t i = 0; i < 4; i++) {
            X[i] = (static_cast<uint32_t>(in[4*i]) << 24) |
                   (static_cast<uint32_t>(in[4*i+1]) << 16) |
                   (static_cast<uint32_t>(in[4*i+2]) << 8) |
                   static_cast<uint32_t>(in[4*i+3]);
        }

        // 32 rounds
        for (int i = 0; i < 32; i++) {
            int ki = reverse_keys ? (31 - i) : i;
            X[i+4] = X[i] ^ sm4_t(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[ki]);
        }

        // Output block (reverse order)
        for (int i = 0; i < 4; i++) {
            out[4*i] = static_cast<uint8_t>(X[35-i] >> 24);
            out[4*i+1] = static_cast<uint8_t>(X[35-i] >> 16);
            out[4*i+2] = static_cast<uint8_t>(X[35-i] >> 8);
            out[4*i+3] = static_cast<uint8_t>(X[35-i]);
        }
    }

    /**
     * @brief Encrypt 8 blocks in parallel (software implementation)
     * 
     * Optimized for loop overhead reduction and better cache utilization.
     * Each block is processed independently with interleaved operations.
     */
    static void process_8blocks(const uint32_t rk[32],
                                 const uint8_t in[128], uint8_t out[128]) noexcept {
        uint32_t X0[36], X1[36], X2[36], X3[36];
        uint32_t X4[36], X5[36], X6[36], X7[36];

        // Load 8 input blocks
        #define LOAD_BLOCK(idx) do { \
            const uint8_t* p = in + (idx) * 16; \
            X##idx[0] = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | \
                        (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]); \
            X##idx[1] = (static_cast<uint32_t>(p[4]) << 24) | (static_cast<uint32_t>(p[5]) << 16) | \
                        (static_cast<uint32_t>(p[6]) << 8) | static_cast<uint32_t>(p[7]); \
            X##idx[2] = (static_cast<uint32_t>(p[8]) << 24) | (static_cast<uint32_t>(p[9]) << 16) | \
                        (static_cast<uint32_t>(p[10]) << 8) | static_cast<uint32_t>(p[11]); \
            X##idx[3] = (static_cast<uint32_t>(p[12]) << 24) | (static_cast<uint32_t>(p[13]) << 16) | \
                        (static_cast<uint32_t>(p[14]) << 8) | static_cast<uint32_t>(p[15]); \
        } while(0)
        
        LOAD_BLOCK(0); LOAD_BLOCK(1); LOAD_BLOCK(2); LOAD_BLOCK(3);
        LOAD_BLOCK(4); LOAD_BLOCK(5); LOAD_BLOCK(6); LOAD_BLOCK(7);
        #undef LOAD_BLOCK

        // 32 rounds - interleave operations for better pipelining
        for (int i = 0; i < 32; i++) {
            X0[i+4] = X0[i] ^ sm4_t(X0[i+1] ^ X0[i+2] ^ X0[i+3] ^ rk[i]);
            X1[i+4] = X1[i] ^ sm4_t(X1[i+1] ^ X1[i+2] ^ X1[i+3] ^ rk[i]);
            X2[i+4] = X2[i] ^ sm4_t(X2[i+1] ^ X2[i+2] ^ X2[i+3] ^ rk[i]);
            X3[i+4] = X3[i] ^ sm4_t(X3[i+1] ^ X3[i+2] ^ X3[i+3] ^ rk[i]);
            X4[i+4] = X4[i] ^ sm4_t(X4[i+1] ^ X4[i+2] ^ X4[i+3] ^ rk[i]);
            X5[i+4] = X5[i] ^ sm4_t(X5[i+1] ^ X5[i+2] ^ X5[i+3] ^ rk[i]);
            X6[i+4] = X6[i] ^ sm4_t(X6[i+1] ^ X6[i+2] ^ X6[i+3] ^ rk[i]);
            X7[i+4] = X7[i] ^ sm4_t(X7[i+1] ^ X7[i+2] ^ X7[i+3] ^ rk[i]);
        }

        // Store 8 output blocks (reverse order)
        #define STORE_BLOCK(idx) do { \
            uint8_t* p = out + (idx) * 16; \
            for (int j = 0; j < 4; j++) { \
                p[4*j] = static_cast<uint8_t>(X##idx[35-j] >> 24); \
                p[4*j+1] = static_cast<uint8_t>(X##idx[35-j] >> 16); \
                p[4*j+2] = static_cast<uint8_t>(X##idx[35-j] >> 8); \
                p[4*j+3] = static_cast<uint8_t>(X##idx[35-j]); \
            } \
        } while(0)
        
        STORE_BLOCK(0); STORE_BLOCK(1); STORE_BLOCK(2); STORE_BLOCK(3);
        STORE_BLOCK(4); STORE_BLOCK(5); STORE_BLOCK(6); STORE_BLOCK(7);
        #undef STORE_BLOCK
    }
};

// ============================================================================
// GCM Mode Implementation
// ============================================================================

/**
 * @brief XOR 16 bytes using uint64_t for performance
 */
__attribute__((always_inline))
static inline void xor_block(uint8_t* out, const uint8_t* a, const uint8_t* b) noexcept {
    auto o64 = reinterpret_cast<uint64_t*>(out);
    auto a64 = reinterpret_cast<const uint64_t*>(a);
    auto b64 = reinterpret_cast<const uint64_t*>(b);
    o64[0] = a64[0] ^ b64[0];
    o64[1] = a64[1] ^ b64[1];
}

/**
 * @brief XOR in place
 */
__attribute__((always_inline))
static inline void xor_block_inplace(uint8_t* out, const uint8_t* b) noexcept {
    auto o64 = reinterpret_cast<uint64_t*>(out);
    auto b64 = reinterpret_cast<const uint64_t*>(b);
    o64[0] ^= b64[0];
    o64[1] ^= b64[1];
}

/**
 * @brief Increment counter (big-endian)
 */
__attribute__((always_inline))
static inline void inc_counter(uint8_t* counter) noexcept {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0) break;
    }
}

/**
 * @brief GHASH multiply (software fallback, unused when PCLMUL available)
 */
[[maybe_unused]]
static void ghash_multiply(uint8_t* result, const uint8_t* h) noexcept {
    uint8_t v[16];
    uint8_t z[16] = {0};

    std::memcpy(v, h, 16);

    for (int i = 0; i < 16; i++) {
        uint8_t byte = result[i];
        for (int j = 0; j < 8; j++) {
            if (byte & (0x80 >> j)) {
                xor_block_inplace(z, v);
            }

            // Multiply v by x in GF(2^128)
            bool carry = v[15] & 1;
            for (int k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | ((v[k-1] & 1) << 7);
            }
            v[0] >>= 1;

            if (carry) {
                v[0] ^= 0xe1;  // x^128 + x^7 + x^2 + x + 1
            }
        }
    }

    std::memcpy(result, z, 16);
}

/**
 * @brief GHASH update - uses PCLMUL acceleration when available
 */
static void ghash_update(uint8_t* state, const uint8_t* h,
                          const uint8_t* data, size_t len) noexcept {
#ifdef SM4_HAS_PCLMUL
    // Use PCLMUL-accelerated GHASH from simd module
    kctsb::simd::ghash_pclmul(state, h, data, len);
#else
    // Software fallback
    while (len >= 16) {
        xor_block_inplace(state, data);
        ghash_multiply(state, h);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        uint8_t block[16] = {0};
        std::memcpy(block, data, len);
        xor_block_inplace(state, block);
        ghash_multiply(state, h);
    }
#endif
}

} // namespace kctsb::internal

// ============================================================================
// C ABI Export (extern "C")
// ============================================================================

extern "C" {

kctsb_error_t kctsb_sm4_set_encrypt_key(kctsb_sm4_ctx_t* ctx, const uint8_t key[16]) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    kctsb::internal::SM4Core::key_schedule(key, ctx->round_keys);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm4_set_decrypt_key(kctsb_sm4_ctx_t* ctx, const uint8_t key[16]) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    kctsb::internal::SM4Core::key_schedule(key, ctx->round_keys);
    return KCTSB_SUCCESS;
}

void kctsb_sm4_encrypt_block(const kctsb_sm4_ctx_t* ctx,
                              const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) return;
    kctsb::internal::SM4Core::process_block(ctx->round_keys, input, output, false);
}

void kctsb_sm4_decrypt_block(const kctsb_sm4_ctx_t* ctx,
                              const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) return;
    kctsb::internal::SM4Core::process_block(ctx->round_keys, input, output, true);
}

// ----------------------------------------------------------------------------
// SM4-GCM
// ----------------------------------------------------------------------------

kctsb_error_t kctsb_sm4_gcm_init(kctsb_sm4_gcm_ctx_t* ctx,
                                  const uint8_t key[16], const uint8_t iv[12]) {
    if (!ctx || !key || !iv) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    std::memset(ctx, 0, sizeof(*ctx));

    // Initialize cipher context
    kctsb_sm4_set_encrypt_key(&ctx->cipher_ctx, key);

    // Compute H = E(K, 0)
    uint8_t zero[16] = {0};
    kctsb_sm4_encrypt_block(&ctx->cipher_ctx, zero, ctx->h);

    // Compute J0 (pre-counter block)
    std::memcpy(ctx->j0, iv, 12);
    ctx->j0[15] = 1;

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm4_gcm_encrypt(kctsb_sm4_gcm_ctx_t* ctx,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* plaintext, size_t plaintext_len,
                                     uint8_t* ciphertext, uint8_t tag[16]) {
    if (!ctx || !tag) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if ((aad_len > 0 && !aad) || (plaintext_len > 0 && (!plaintext || !ciphertext))) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    alignas(16) uint8_t counter[16];
    alignas(32) uint8_t keystream[128]; // 8-block buffer for parallel processing
    alignas(32) uint8_t counters[128];  // 8 counters for parallel encryption

    // Reset GHASH state
    std::memset(ctx->ghash_state, 0, 16);
    ctx->aad_len = aad_len;
    ctx->cipher_len = plaintext_len;

    // Process AAD
    if (aad_len > 0) {
        kctsb::internal::ghash_update(ctx->ghash_state, ctx->h, aad, aad_len);
    }

    // Initialize counter = J0 + 1
    std::memcpy(counter, ctx->j0, 16);
    kctsb::internal::inc_counter(counter);

    // CTR encryption with 8-block parallelization
    size_t remaining = plaintext_len;
    const uint8_t* in = plaintext;
    uint8_t* out = ciphertext;

    // Process 8 blocks at a time (128 bytes)
    while (remaining >= 128) {
        // Prepare 8 counters
        for (int i = 0; i < 8; i++) {
            std::memcpy(counters + i * 16, counter, 16);
            kctsb::internal::inc_counter(counter);
        }

        // Encrypt 8 blocks using parallel implementation
        kctsb::internal::SM4Core::process_8blocks(ctx->cipher_ctx.round_keys,
                                                   counters, keystream);

        // XOR with plaintext using 64-bit operations (16 uint64_t for 128 bytes)
        auto in64 = reinterpret_cast<const uint64_t*>(in);
        auto out64 = reinterpret_cast<uint64_t*>(out);
        auto ks64 = reinterpret_cast<const uint64_t*>(keystream);
        for (int i = 0; i < 16; i++) {
            out64[i] = in64[i] ^ ks64[i];
        }

        in += 128;
        out += 128;
        remaining -= 128;
    }

    // Process 4 blocks at a time (64 bytes)
    while (remaining >= 64) {
        // Prepare 4 counters
        std::memcpy(counters, counter, 16);
        kctsb::internal::inc_counter(counter);
        std::memcpy(counters + 16, counter, 16);
        kctsb::internal::inc_counter(counter);
        std::memcpy(counters + 32, counter, 16);
        kctsb::internal::inc_counter(counter);
        std::memcpy(counters + 48, counter, 16);
        kctsb::internal::inc_counter(counter);

        // Encrypt 4 blocks
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters, keystream);
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters + 16, keystream + 16);
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters + 32, keystream + 32);
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters + 48, keystream + 48);

        // XOR with plaintext
        auto in64 = reinterpret_cast<const uint64_t*>(in);
        auto out64 = reinterpret_cast<uint64_t*>(out);
        auto ks64 = reinterpret_cast<const uint64_t*>(keystream);
        for (int i = 0; i < 8; i++) {
            out64[i] = in64[i] ^ ks64[i];
        }

        in += 64;
        out += 64;
        remaining -= 64;
    }

    // Process remaining full blocks
    while (remaining >= 16) {
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counter, keystream);
        kctsb::internal::xor_block(out, in, keystream);
        kctsb::internal::inc_counter(counter);
        in += 16;
        out += 16;
        remaining -= 16;
    }

    // Handle partial block
    if (remaining > 0) {
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counter, keystream);
        for (size_t i = 0; i < remaining; i++) {
            out[i] = in[i] ^ keystream[i];
        }
    }

    // GHASH ciphertext
    if (plaintext_len > 0) {
        kctsb::internal::ghash_update(ctx->ghash_state, ctx->h, ciphertext, plaintext_len);
    }

    // Append lengths block
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t cipher_bits = plaintext_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i] = static_cast<uint8_t>(aad_bits >> (56 - i * 8));
        len_block[i + 8] = static_cast<uint8_t>(cipher_bits >> (56 - i * 8));
    }
    kctsb::internal::ghash_update(ctx->ghash_state, ctx->h, len_block, 16);

    // Compute tag = E(K, J0) XOR S
    kctsb_sm4_encrypt_block(&ctx->cipher_ctx, ctx->j0, tag);
    kctsb::internal::xor_block_inplace(tag, ctx->ghash_state);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm4_gcm_decrypt(kctsb_sm4_gcm_ctx_t* ctx,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* ciphertext, size_t ciphertext_len,
                                     const uint8_t tag[16], uint8_t* plaintext) {
    if (!ctx || !tag) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if ((aad_len > 0 && !aad) || (ciphertext_len > 0 && (!ciphertext || !plaintext))) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    alignas(16) uint8_t counter[16];
    alignas(32) uint8_t keystream[128]; // 8-block buffer
    alignas(32) uint8_t counters[128];  // 8 counters
    uint8_t computed_tag[16];

    // Reset GHASH state
    std::memset(ctx->ghash_state, 0, 16);
    ctx->aad_len = aad_len;
    ctx->cipher_len = ciphertext_len;

    // Process AAD
    if (aad_len > 0) {
        kctsb::internal::ghash_update(ctx->ghash_state, ctx->h, aad, aad_len);
    }

    // GHASH ciphertext
    if (ciphertext_len > 0) {
        kctsb::internal::ghash_update(ctx->ghash_state, ctx->h, ciphertext, ciphertext_len);
    }

    // Append lengths block
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t cipher_bits = ciphertext_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[i] = static_cast<uint8_t>(aad_bits >> (56 - i * 8));
        len_block[i + 8] = static_cast<uint8_t>(cipher_bits >> (56 - i * 8));
    }
    kctsb::internal::ghash_update(ctx->ghash_state, ctx->h, len_block, 16);

    // Compute expected tag
    kctsb_sm4_encrypt_block(&ctx->cipher_ctx, ctx->j0, computed_tag);
    kctsb::internal::xor_block_inplace(computed_tag, ctx->ghash_state);

    // Constant-time tag comparison
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= computed_tag[i] ^ tag[i];
    }

    if (diff != 0) {
        return KCTSB_ERROR_AUTH_FAILED;
    }

    // CTR decryption with 8-block parallelization
    std::memcpy(counter, ctx->j0, 16);
    kctsb::internal::inc_counter(counter);

    size_t remaining = ciphertext_len;
    const uint8_t* in = ciphertext;
    uint8_t* out = plaintext;

    // Process 8 blocks at a time (128 bytes)
    while (remaining >= 128) {
        // Prepare 8 counters
        for (int i = 0; i < 8; i++) {
            std::memcpy(counters + i * 16, counter, 16);
            kctsb::internal::inc_counter(counter);
        }

        // Encrypt 8 blocks using parallel implementation
        kctsb::internal::SM4Core::process_8blocks(ctx->cipher_ctx.round_keys,
                                                   counters, keystream);

        // XOR with ciphertext
        auto in64 = reinterpret_cast<const uint64_t*>(in);
        auto out64 = reinterpret_cast<uint64_t*>(out);
        auto ks64 = reinterpret_cast<const uint64_t*>(keystream);
        for (int i = 0; i < 16; i++) {
            out64[i] = in64[i] ^ ks64[i];
        }

        in += 128;
        out += 128;
        remaining -= 128;
    }

    // Process 4 blocks at a time (64 bytes)
    while (remaining >= 64) {
        // Prepare 4 counters
        std::memcpy(counters, counter, 16);
        kctsb::internal::inc_counter(counter);
        std::memcpy(counters + 16, counter, 16);
        kctsb::internal::inc_counter(counter);
        std::memcpy(counters + 32, counter, 16);
        kctsb::internal::inc_counter(counter);
        std::memcpy(counters + 48, counter, 16);
        kctsb::internal::inc_counter(counter);

        // Encrypt 4 blocks
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters, keystream);
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters + 16, keystream + 16);
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters + 32, keystream + 32);
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counters + 48, keystream + 48);

        // XOR with ciphertext
        auto in64 = reinterpret_cast<const uint64_t*>(in);
        auto out64 = reinterpret_cast<uint64_t*>(out);
        auto ks64 = reinterpret_cast<const uint64_t*>(keystream);
        for (int i = 0; i < 8; i++) {
            out64[i] = in64[i] ^ ks64[i];
        }

        in += 64;
        out += 64;
        remaining -= 64;
    }

    // Process remaining full blocks
    while (remaining >= 16) {
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counter, keystream);
        kctsb::internal::xor_block(out, in, keystream);
        kctsb::internal::inc_counter(counter);
        in += 16;
        out += 16;
        remaining -= 16;
    }

    // Handle partial block
    if (remaining > 0) {
        kctsb_sm4_encrypt_block(&ctx->cipher_ctx, counter, keystream);
        for (size_t i = 0; i < remaining; i++) {
            out[i] = in[i] ^ keystream[i];
        }
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm4_gcm_seal(const uint8_t key[16], const uint8_t iv[12],
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  uint8_t* ciphertext, uint8_t tag[16]) {
    kctsb_sm4_gcm_ctx_t ctx;
    kctsb_error_t ret = kctsb_sm4_gcm_init(&ctx, key, iv);
    if (ret != KCTSB_SUCCESS) return ret;

    return kctsb_sm4_gcm_encrypt(&ctx, aad, aad_len, plaintext, plaintext_len, ciphertext, tag);
}

kctsb_error_t kctsb_sm4_gcm_open(const uint8_t key[16], const uint8_t iv[12],
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* ciphertext, size_t ciphertext_len,
                                  const uint8_t tag[16], uint8_t* plaintext) {
    kctsb_sm4_gcm_ctx_t ctx;
    kctsb_error_t ret = kctsb_sm4_gcm_init(&ctx, key, iv);
    if (ret != KCTSB_SUCCESS) return ret;

    return kctsb_sm4_gcm_decrypt(&ctx, aad, aad_len, ciphertext, ciphertext_len, tag, plaintext);
}

// One-shot API aliases for consistent naming with AES-GCM
kctsb_error_t kctsb_sm4_gcm_encrypt_oneshot(
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    uint8_t tag[16]) {
    return kctsb_sm4_gcm_seal(key, iv, aad, aad_len, plaintext, plaintext_len, ciphertext, tag);
}

kctsb_error_t kctsb_sm4_gcm_decrypt_oneshot(
    const uint8_t key[16],
    const uint8_t iv[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t* plaintext) {
    return kctsb_sm4_gcm_open(key, iv, aad, aad_len, ciphertext, ciphertext_len, tag, plaintext);
}

} // extern "C"
