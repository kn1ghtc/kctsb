/**
 * @file blake2.cpp
 * @brief BLAKE2 Implementation - C++ Core + C ABI Export
 *
 * RFC 7693 compliant BLAKE2b and BLAKE2s implementation.
 * Architecture: C++ internal implementation + extern "C" API export.
 *
 * Features:
 * - BLAKE2b (64-bit optimized, up to 64 bytes output)
 * - BLAKE2s (32-bit optimized, up to 32 bytes output)
 * - Keyed hashing (MAC) support
 * - SIMD acceleration ready
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/blake2.h"
#include "kctsb/core/common.h"
#include <array>
#include <cstring>
#include <cstdint>

// ============================================================================
// C++ Internal Implementation
// ============================================================================

namespace kctsb::internal {

/**
 * @brief BLAKE2b initialization vector
 */
constexpr std::array<uint64_t, 8> BLAKE2B_IV = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/**
 * @brief BLAKE2s initialization vector
 */
constexpr std::array<uint32_t, 8> BLAKE2S_IV = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**
 * @brief BLAKE2b/s sigma table
 */
constexpr std::array<std::array<uint8_t, 16>, 12> SIGMA = {{
    {{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15}},
    {{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3}},
    {{11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4}},
    {{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8}},
    {{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13}},
    {{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9}},
    {{12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11}},
    {{13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10}},
    {{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5}},
    {{10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0}},
    {{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15}},
    {{14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3}}
}};

/**
 * @brief 64-bit rotate right
 */
__attribute__((always_inline))
static inline uint64_t rotr64(uint64_t x, unsigned int n) noexcept {
    return (x >> n) | (x << (64 - n));
}

/**
 * @brief 32-bit rotate right
 */
__attribute__((always_inline))
static inline uint32_t rotr32(uint32_t x, unsigned int n) noexcept {
    return (x >> n) | (x << (32 - n));
}

/**
 * @brief Load 64-bit little-endian value
 */
__attribute__((always_inline))
static inline uint64_t load64(const uint8_t* src) noexcept {
    uint64_t w;
    std::memcpy(&w, src, sizeof(w));
    return w;
}

/**
 * @brief Store 64-bit little-endian value
 */
__attribute__((always_inline))
static inline void store64(uint8_t* dst, uint64_t w) noexcept {
    std::memcpy(dst, &w, sizeof(w));
}

/**
 * @brief Load 32-bit little-endian value
 */
__attribute__((always_inline))
static inline uint32_t load32(const uint8_t* src) noexcept {
    uint32_t w;
    std::memcpy(&w, src, sizeof(w));
    return w;
}

/**
 * @brief Store 32-bit little-endian value
 */
__attribute__((always_inline))
static inline void store32(uint8_t* dst, uint32_t w) noexcept {
    std::memcpy(dst, &w, sizeof(w));
}

/**
 * @brief BLAKE2b G mixing function
 */
#define G_B(a, b, c, d, x, y) do { \
    a = a + b + x;              \
    d = rotr64(d ^ a, 32);      \
    c = c + d;                  \
    b = rotr64(b ^ c, 24);      \
    a = a + b + y;              \
    d = rotr64(d ^ a, 16);      \
    c = c + d;                  \
    b = rotr64(b ^ c, 63);      \
} while(0)

/**
 * @brief BLAKE2s G mixing function
 */
#define G_S(a, b, c, d, x, y) do { \
    a = a + b + x;              \
    d = rotr32(d ^ a, 16);      \
    c = c + d;                  \
    b = rotr32(b ^ c, 12);      \
    a = a + b + y;              \
    d = rotr32(d ^ a, 8);       \
    c = c + d;                  \
    b = rotr32(b ^ c, 7);       \
} while(0)

/**
 * @brief BLAKE2b compression function
 */
class BLAKE2b {
public:
    static void compress(kctsb_blake2b_ctx_t* ctx, const uint8_t block[128]) noexcept {
        std::array<uint64_t, 16> m;
        std::array<uint64_t, 16> v;

        // Load message block
        for (size_t i = 0; i < 16; ++i) {
            m[i] = load64(block + i * 8);
        }

        // Initialize working vector
        for (size_t i = 0; i < 8; ++i) {
            v[i] = ctx->h[i];
            v[i + 8] = BLAKE2B_IV[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];
        v[14] ^= ctx->f[0];
        v[15] ^= ctx->f[1];

        // 12 rounds
        for (size_t round = 0; round < 12; ++round) {
            const auto& s = SIGMA[round];

            G_B(v[0], v[4], v[ 8], v[12], m[s[ 0]], m[s[ 1]]);
            G_B(v[1], v[5], v[ 9], v[13], m[s[ 2]], m[s[ 3]]);
            G_B(v[2], v[6], v[10], v[14], m[s[ 4]], m[s[ 5]]);
            G_B(v[3], v[7], v[11], v[15], m[s[ 6]], m[s[ 7]]);
            G_B(v[0], v[5], v[10], v[15], m[s[ 8]], m[s[ 9]]);
            G_B(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
            G_B(v[2], v[7], v[ 8], v[13], m[s[12]], m[s[13]]);
            G_B(v[3], v[4], v[ 9], v[14], m[s[14]], m[s[15]]);
        }

        // Finalize
        for (size_t i = 0; i < 8; ++i) {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }
    }
};

/**
 * @brief BLAKE2s compression function
 */
class BLAKE2s {
public:
    static void compress(kctsb_blake2s_ctx_t* ctx, const uint8_t block[64]) noexcept {
        std::array<uint32_t, 16> m;
        std::array<uint32_t, 16> v;

        for (size_t i = 0; i < 16; ++i) {
            m[i] = load32(block + i * 4);
        }

        for (size_t i = 0; i < 8; ++i) {
            v[i] = ctx->h[i];
            v[i + 8] = BLAKE2S_IV[i];
        }

        v[12] ^= ctx->t[0];
        v[13] ^= ctx->t[1];
        v[14] ^= ctx->f[0];
        v[15] ^= ctx->f[1];

        // 10 rounds for BLAKE2s
        for (size_t round = 0; round < 10; ++round) {
            const auto& s = SIGMA[round];

            G_S(v[0], v[4], v[ 8], v[12], m[s[ 0]], m[s[ 1]]);
            G_S(v[1], v[5], v[ 9], v[13], m[s[ 2]], m[s[ 3]]);
            G_S(v[2], v[6], v[10], v[14], m[s[ 4]], m[s[ 5]]);
            G_S(v[3], v[7], v[11], v[15], m[s[ 6]], m[s[ 7]]);
            G_S(v[0], v[5], v[10], v[15], m[s[ 8]], m[s[ 9]]);
            G_S(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
            G_S(v[2], v[7], v[ 8], v[13], m[s[12]], m[s[13]]);
            G_S(v[3], v[4], v[ 9], v[14], m[s[14]], m[s[15]]);
        }

        for (size_t i = 0; i < 8; ++i) {
            ctx->h[i] ^= v[i] ^ v[i + 8];
        }
    }
};

#undef G_B
#undef G_S

} // namespace kctsb::internal

// ============================================================================
// C ABI Export (extern "C")
// ============================================================================

extern "C" {

// ----------------------------------------------------------------------------
// BLAKE2b
// ----------------------------------------------------------------------------

void kctsb_blake2b_init(kctsb_blake2b_ctx_t* ctx, size_t outlen) {
    if (!ctx || outlen == 0 || outlen > KCTSB_BLAKE2B_OUTBYTES) {
        return;
    }

    std::memset(ctx, 0, sizeof(*ctx));

    for (size_t i = 0; i < 8; ++i) {
        ctx->h[i] = kctsb::internal::BLAKE2B_IV[i];
    }

    // Parameter block: digest length = outlen, key length = 0, fanout = 1, depth = 1
    ctx->h[0] ^= 0x01010000ULL ^ outlen;
    ctx->outlen = outlen;
}

void kctsb_blake2b_init_key(kctsb_blake2b_ctx_t* ctx, size_t outlen,
                             const uint8_t* key, size_t keylen) {
    if (!ctx || outlen == 0 || outlen > KCTSB_BLAKE2B_OUTBYTES) {
        return;
    }
    if (keylen > KCTSB_BLAKE2B_KEYBYTES) {
        return;
    }

    std::memset(ctx, 0, sizeof(*ctx));

    for (size_t i = 0; i < 8; ++i) {
        ctx->h[i] = kctsb::internal::BLAKE2B_IV[i];
    }

    ctx->h[0] ^= 0x01010000ULL ^ (keylen << 8) ^ outlen;
    ctx->outlen = outlen;

    if (keylen > 0 && key) {
        uint8_t block[KCTSB_BLAKE2B_BLOCKBYTES] = {0};
        std::memcpy(block, key, keylen);
        kctsb_blake2b_update(ctx, block, KCTSB_BLAKE2B_BLOCKBYTES);
        // Secure clear key block
        volatile uint8_t* p = block;
        for (size_t i = 0; i < KCTSB_BLAKE2B_BLOCKBYTES; ++i) {
            p[i] = 0;
        }
    }
}

void kctsb_blake2b_update(kctsb_blake2b_ctx_t* ctx,
                           const uint8_t* data, size_t len) {
    if (!ctx || (!data && len > 0)) {
        return;
    }

    while (len > 0) {
        // If buffer has data and adding more would fill it
        if (ctx->buflen > 0 && ctx->buflen + len > KCTSB_BLAKE2B_BLOCKBYTES) {
            size_t remaining = KCTSB_BLAKE2B_BLOCKBYTES - ctx->buflen;
            std::memcpy(ctx->buf + ctx->buflen, data, remaining);

            ctx->t[0] += KCTSB_BLAKE2B_BLOCKBYTES;
            if (ctx->t[0] < KCTSB_BLAKE2B_BLOCKBYTES) {
                ctx->t[1]++;
            }

            kctsb::internal::BLAKE2b::compress(ctx, ctx->buf);
            ctx->buflen = 0;
            data += remaining;
            len -= remaining;
        }

        // Process full blocks
        while (len > KCTSB_BLAKE2B_BLOCKBYTES) {
            ctx->t[0] += KCTSB_BLAKE2B_BLOCKBYTES;
            if (ctx->t[0] < KCTSB_BLAKE2B_BLOCKBYTES) {
                ctx->t[1]++;
            }

            kctsb::internal::BLAKE2b::compress(ctx, data);
            data += KCTSB_BLAKE2B_BLOCKBYTES;
            len -= KCTSB_BLAKE2B_BLOCKBYTES;
        }

        // Buffer remaining
        if (len > 0) {
            std::memcpy(ctx->buf + ctx->buflen, data, len);
            ctx->buflen += len;
            len = 0;
        }
    }
}

void kctsb_blake2b_final(kctsb_blake2b_ctx_t* ctx, uint8_t* digest) {
    if (!ctx || !digest) {
        return;
    }

    // Update counter for final block
    ctx->t[0] += ctx->buflen;
    if (ctx->t[0] < ctx->buflen) {
        ctx->t[1]++;
    }

    // Set finalization flag
    ctx->f[0] = ~0ULL;

    // Pad final block
    std::memset(ctx->buf + ctx->buflen, 0, KCTSB_BLAKE2B_BLOCKBYTES - ctx->buflen);

    // Compress final block
    kctsb::internal::BLAKE2b::compress(ctx, ctx->buf);

    // Output digest
    for (size_t i = 0; i < ctx->outlen; ++i) {
        digest[i] = (ctx->h[i / 8] >> (8 * (i % 8))) & 0xFF;
    }

    // Secure clear
    kctsb_blake2b_clear(ctx);
}

void kctsb_blake2b(const uint8_t* data, size_t len,
                    uint8_t* digest, size_t outlen) {
    if (!digest || (!data && len > 0)) {
        return;
    }

    kctsb_blake2b_ctx_t ctx;
    kctsb_blake2b_init(&ctx, outlen);
    kctsb_blake2b_update(&ctx, data, len);
    kctsb_blake2b_final(&ctx, digest);
}

void kctsb_blake2b_clear(kctsb_blake2b_ctx_t* ctx) {
    if (ctx) {
        volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ctx);
        for (size_t i = 0; i < sizeof(*ctx); ++i) {
            p[i] = 0;
        }
    }
}

// ----------------------------------------------------------------------------
// BLAKE2s
// ----------------------------------------------------------------------------

void kctsb_blake2s_init(kctsb_blake2s_ctx_t* ctx, size_t outlen) {
    if (!ctx || outlen == 0 || outlen > KCTSB_BLAKE2S_OUTBYTES) {
        return;
    }

    std::memset(ctx, 0, sizeof(*ctx));

    for (size_t i = 0; i < 8; ++i) {
        ctx->h[i] = kctsb::internal::BLAKE2S_IV[i];
    }

    ctx->h[0] ^= 0x01010000UL ^ static_cast<uint32_t>(outlen);
    ctx->outlen = outlen;
}

void kctsb_blake2s_init_key(kctsb_blake2s_ctx_t* ctx, size_t outlen,
                             const uint8_t* key, size_t keylen) {
    if (!ctx || outlen == 0 || outlen > KCTSB_BLAKE2S_OUTBYTES) {
        return;
    }
    if (keylen > KCTSB_BLAKE2S_KEYBYTES) {
        return;
    }

    std::memset(ctx, 0, sizeof(*ctx));

    for (size_t i = 0; i < 8; ++i) {
        ctx->h[i] = kctsb::internal::BLAKE2S_IV[i];
    }

    ctx->h[0] ^= 0x01010000UL ^ (static_cast<uint32_t>(keylen) << 8) ^ static_cast<uint32_t>(outlen);
    ctx->outlen = outlen;

    if (keylen > 0 && key) {
        uint8_t block[KCTSB_BLAKE2S_BLOCKBYTES] = {0};
        std::memcpy(block, key, keylen);
        kctsb_blake2s_update(ctx, block, KCTSB_BLAKE2S_BLOCKBYTES);
        volatile uint8_t* p = block;
        for (size_t i = 0; i < KCTSB_BLAKE2S_BLOCKBYTES; ++i) {
            p[i] = 0;
        }
    }
}

void kctsb_blake2s_update(kctsb_blake2s_ctx_t* ctx,
                           const uint8_t* data, size_t len) {
    if (!ctx || (!data && len > 0)) {
        return;
    }

    while (len > 0) {
        if (ctx->buflen > 0 && ctx->buflen + len > KCTSB_BLAKE2S_BLOCKBYTES) {
            size_t remaining = KCTSB_BLAKE2S_BLOCKBYTES - ctx->buflen;
            std::memcpy(ctx->buf + ctx->buflen, data, remaining);

            ctx->t[0] += KCTSB_BLAKE2S_BLOCKBYTES;
            if (ctx->t[0] < KCTSB_BLAKE2S_BLOCKBYTES) {
                ctx->t[1]++;
            }

            kctsb::internal::BLAKE2s::compress(ctx, ctx->buf);
            ctx->buflen = 0;
            data += remaining;
            len -= remaining;
        }

        while (len > KCTSB_BLAKE2S_BLOCKBYTES) {
            ctx->t[0] += KCTSB_BLAKE2S_BLOCKBYTES;
            if (ctx->t[0] < KCTSB_BLAKE2S_BLOCKBYTES) {
                ctx->t[1]++;
            }

            kctsb::internal::BLAKE2s::compress(ctx, data);
            data += KCTSB_BLAKE2S_BLOCKBYTES;
            len -= KCTSB_BLAKE2S_BLOCKBYTES;
        }

        if (len > 0) {
            std::memcpy(ctx->buf + ctx->buflen, data, len);
            ctx->buflen += len;
            len = 0;
        }
    }
}

void kctsb_blake2s_final(kctsb_blake2s_ctx_t* ctx, uint8_t* digest) {
    if (!ctx || !digest) {
        return;
    }

    ctx->t[0] += static_cast<uint32_t>(ctx->buflen);
    if (ctx->t[0] < ctx->buflen) {
        ctx->t[1]++;
    }

    ctx->f[0] = UINT32_MAX;  // Set finalization flag

    std::memset(ctx->buf + ctx->buflen, 0, KCTSB_BLAKE2S_BLOCKBYTES - ctx->buflen);
    kctsb::internal::BLAKE2s::compress(ctx, ctx->buf);

    for (size_t i = 0; i < ctx->outlen; ++i) {
        digest[i] = (ctx->h[i / 4] >> (8 * (i % 4))) & 0xFF;
    }

    kctsb_blake2s_clear(ctx);
}

void kctsb_blake2s(const uint8_t* data, size_t len,
                    uint8_t* digest, size_t outlen) {
    if (!digest || (!data && len > 0)) {
        return;
    }

    kctsb_blake2s_ctx_t ctx;
    kctsb_blake2s_init(&ctx, outlen);
    kctsb_blake2s_update(&ctx, data, len);
    kctsb_blake2s_final(&ctx, digest);
}

void kctsb_blake2s_clear(kctsb_blake2s_ctx_t* ctx) {
    if (ctx) {
        volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ctx);
        for (size_t i = 0; i < sizeof(*ctx); ++i) {
            p[i] = 0;
        }
    }
}

} // extern "C"
