/**
 * @file sm3.cpp
 * @brief SM3 Implementation - C++ Core + C ABI Export
 *
 * GB/T 32905-2016 compliant SM3 cryptographic hash implementation.
 * Architecture: C++ internal implementation + extern "C" API export.
 *
 * Features:
 * - 256-bit hash output (same as SHA-256)
 * - Chinese National Standard compliant
 * - Incremental hashing API (init/update/final)
 *
 * Reference:
 * - GB/T 32905-2016: SM3 Cryptographic Hash Algorithm
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm3.h"
#include "kctsb/core/common.h"
#include <array>
#include <cstring>
#include <cstdint>

// ============================================================================
// C++ Internal Implementation
// ============================================================================

namespace kctsb::internal {

/**
 * @brief SM3 constants
 */
constexpr uint32_t SM3_T1 = 0x79CC4519;
constexpr uint32_t SM3_T2 = 0x7A879D8A;

/**
 * @brief SM3 initial hash values
 */
constexpr std::array<uint32_t, 8> SM3_IV = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// Helper macros
#define SM3_ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// Boolean functions
#define SM3_FF0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SM3_GG0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// Permutation functions
#define SM3_P0(x) ((x) ^ SM3_ROTL32((x), 9) ^ SM3_ROTL32((x), 17))
#define SM3_P1(x) ((x) ^ SM3_ROTL32((x), 15) ^ SM3_ROTL32((x), 23))

/**
 * @brief Load 32-bit big-endian value
 */
__attribute__((always_inline))
static inline uint32_t load32_be(const uint8_t* p) noexcept {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/**
 * @brief Store 32-bit big-endian value
 */
__attribute__((always_inline))
static inline void store32_be(uint8_t* p, uint32_t v) noexcept {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/**
 * @brief SM3 compression class
 */
class SM3Compressor {
public:
    /**
     * @brief Expand message block to W and W'
     */
    static void expand_message(const uint32_t B[16], uint32_t W[68], uint32_t W1[64]) noexcept {
        // W[0..15] = B[0..15]
        for (int i = 0; i < 16; i++) {
            W[i] = B[i];
        }

        // W[16..67]
        for (int i = 16; i < 68; i++) {
            uint32_t tmp = W[i - 16] ^ W[i - 9] ^ SM3_ROTL32(W[i - 3], 15);
            W[i] = SM3_P1(tmp) ^ SM3_ROTL32(W[i - 13], 7) ^ W[i - 6];
        }

        // W'[0..63] = W[i] ^ W[i+4]
        for (int i = 0; i < 64; i++) {
            W1[i] = W[i] ^ W[i + 4];
        }
    }

    /**
     * @brief SM3 compression function
     */
    static void compress(kctsb_sm3_ctx_t* ctx, const uint8_t block[64]) noexcept {
        uint32_t B[16];
        uint32_t W[68], W1[64];
        uint32_t A, B_v, C, D, E, F, G, H;
        uint32_t SS1, SS2, TT1, TT2;
        uint32_t T;

        // Load message block as big-endian words
        for (int i = 0; i < 16; i++) {
            B[i] = load32_be(block + i * 4);
        }

        // Expand message
        expand_message(B, W, W1);

        // Initialize working variables
        A = ctx->state[0]; B_v = ctx->state[1];
        C = ctx->state[2]; D = ctx->state[3];
        E = ctx->state[4]; F = ctx->state[5];
        G = ctx->state[6]; H = ctx->state[7];

        // 64 rounds
        for (int j = 0; j < 64; j++) {
            // Calculate T_j
            if (j < 16) {
                T = SM3_T1;
            } else {
                T = SM3_T2;
            }
            T = SM3_ROTL32(T, j % 32);

            // SS1 = ((A <<< 12) + E + (T_j <<< j)) <<< 7
            SS1 = SM3_ROTL32((SM3_ROTL32(A, 12) + E + T), 7);

            // SS2 = SS1 ^ (A <<< 12)
            SS2 = SS1 ^ SM3_ROTL32(A, 12);

            // TT1 = FF_j(A, B, C) + D + SS2 + W'_j
            if (j < 16) {
                TT1 = SM3_FF0(A, B_v, C) + D + SS2 + W1[j];
            } else {
                TT1 = SM3_FF1(A, B_v, C) + D + SS2 + W1[j];
            }

            // TT2 = GG_j(E, F, G) + H + SS1 + W_j
            if (j < 16) {
                TT2 = SM3_GG0(E, F, G) + H + SS1 + W[j];
            } else {
                TT2 = SM3_GG1(E, F, G) + H + SS1 + W[j];
            }

            // Update working variables
            D = C;
            C = SM3_ROTL32(B_v, 9);
            B_v = A;
            A = TT1;
            H = G;
            G = SM3_ROTL32(F, 19);
            F = E;
            E = SM3_P0(TT2);
        }

        // Update state
        ctx->state[0] ^= A;
        ctx->state[1] ^= B_v;
        ctx->state[2] ^= C;
        ctx->state[3] ^= D;
        ctx->state[4] ^= E;
        ctx->state[5] ^= F;
        ctx->state[6] ^= G;
        ctx->state[7] ^= H;
    }
};

#undef SM3_ROTL32
#undef SM3_FF0
#undef SM3_FF1
#undef SM3_GG0
#undef SM3_GG1
#undef SM3_P0
#undef SM3_P1

} // namespace kctsb::internal

// ============================================================================
// C ABI Export (extern "C")
// ============================================================================

extern "C" {

void kctsb_sm3_init(kctsb_sm3_ctx_t* ctx) {
    if (!ctx) return;

    std::memcpy(ctx->state, kctsb::internal::SM3_IV.data(), sizeof(ctx->state));
    ctx->count = 0;
    std::memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void kctsb_sm3_update(kctsb_sm3_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || len == 0 || !data) return;

    size_t buffer_used = ctx->count & 0x3F;
    ctx->count += len;

    // If buffer has data and new data fills it
    if (buffer_used > 0) {
        size_t buffer_space = 64 - buffer_used;
        if (len < buffer_space) {
            std::memcpy(ctx->buffer + buffer_used, data, len);
            return;
        }

        std::memcpy(ctx->buffer + buffer_used, data, buffer_space);
        kctsb::internal::SM3Compressor::compress(ctx, ctx->buffer);
        data += buffer_space;
        len -= buffer_space;
    }

    // Process complete 64-byte blocks
    while (len >= 64) {
        kctsb::internal::SM3Compressor::compress(ctx, data);
        data += 64;
        len -= 64;
    }

    // Buffer remaining data
    if (len > 0) {
        std::memcpy(ctx->buffer, data, len);
    }
}

void kctsb_sm3_final(kctsb_sm3_ctx_t* ctx, uint8_t digest[32]) {
    if (!ctx || !digest) return;

    size_t used = ctx->count & 0x3F;
    uint64_t bit_len = ctx->count * 8;

    // Append 0x80
    ctx->buffer[used++] = 0x80;

    // If not enough space for length
    if (used > 56) {
        std::memset(ctx->buffer + used, 0, 64 - used);
        kctsb::internal::SM3Compressor::compress(ctx, ctx->buffer);
        used = 0;
    }

    // Pad with zeros
    std::memset(ctx->buffer + used, 0, 56 - used);

    // Append bit length (big-endian)
    kctsb::internal::store32_be(ctx->buffer + 56, static_cast<uint32_t>(bit_len >> 32));
    kctsb::internal::store32_be(ctx->buffer + 60, static_cast<uint32_t>(bit_len));

    kctsb::internal::SM3Compressor::compress(ctx, ctx->buffer);

    // Output digest
    for (int i = 0; i < 8; i++) {
        kctsb::internal::store32_be(digest + i * 4, ctx->state[i]);
    }

    // Clear sensitive data
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ctx);
    for (size_t i = 0; i < sizeof(*ctx); i++) {
        p[i] = 0;
    }
}

kctsb_error_t kctsb_sm3(const uint8_t* data, size_t len, uint8_t digest[32]) {
    if (!digest || (!data && len > 0)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    kctsb_sm3_ctx_t ctx;
    kctsb_sm3_init(&ctx);
    kctsb_sm3_update(&ctx, data, len);
    kctsb_sm3_final(&ctx, digest);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm3_self_test(void) {
    // Test vector from GB/T 32905-2016
    // Message: "abc"
    const uint8_t test_msg[] = {'a', 'b', 'c'};
    const uint8_t expected[] = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
        0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
        0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };

    uint8_t digest[32];
    kctsb_sm3(test_msg, sizeof(test_msg), digest);

    if (std::memcmp(digest, expected, 32) != 0) {
        return KCTSB_ERROR_VERIFICATION_FAILED;  // Self-test verification failed
    }

    return KCTSB_SUCCESS;
}

} // extern "C"

// ============================================================================
// C++ Class Implementation
// ============================================================================

namespace kctsb {

SM3::SM3() {
    kctsb_sm3_init(&ctx_);
}

void SM3::update(const ByteVec& data) {
    kctsb_sm3_update(&ctx_, data.data(), data.size());
}

void SM3::update(const uint8_t* data, size_t len) {
    kctsb_sm3_update(&ctx_, data, len);
}

void SM3::update(const std::string& str) {
    kctsb_sm3_update(&ctx_, reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

SM3Digest SM3::digest() {
    SM3Digest result;
    kctsb_sm3_ctx_t ctx_copy = ctx_;
    kctsb_sm3_final(&ctx_copy, result.data());
    return result;
}

void SM3::reset() {
    kctsb_sm3_init(&ctx_);
}

SM3Digest SM3::hash(const ByteVec& data) {
    SM3Digest result;
    kctsb_sm3(data.data(), data.size(), result.data());
    return result;
}

SM3Digest SM3::hash(const std::string& str) {
    SM3Digest result;
    kctsb_sm3(reinterpret_cast<const uint8_t*>(str.data()), str.size(), result.data());
    return result;
}

std::string SM3::hashHex(const ByteVec& data) {
    SM3Digest digest = hash(data);
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0F]);
    }
    return result;
}

std::string SM3::hashHex(const std::string& str) {
    ByteVec data(str.begin(), str.end());
    return hashHex(data);
}

} // namespace kctsb
