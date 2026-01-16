/**
 * @file sha256.cpp
 * @brief SHA-256 Implementation - C++ Core + C ABI Export
 *
 * FIPS 180-4 compliant SHA-256 implementation with Intel SHA-NI acceleration.
 * Architecture: C++ internal implementation + extern "C" API export.
 *
 * Features:
 * - Runtime SHA-NI detection with automatic fallback
 * - 2.5-3x speedup with SHA-NI on supported CPUs
 * - Incremental hashing API (init/update/final)
 * - Secure memory clearing on finalization
 *
 * Reference:
 * - [FIPS 180-4] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * - Intel SHA Extensions Programming Guide
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sha256.h"
#include "kctsb/core/common.h"
#include <array>
#include <cstring>
#include <cstdint>

// ============================================================================
// Platform-specific includes
// ============================================================================

#if defined(_MSC_VER)
#include <intrin.h>
#define KCTSB_PREFETCH(addr) _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
#else
#include <cpuid.h>
#define KCTSB_PREFETCH(addr) __builtin_prefetch(addr, 0, 3)
#endif

// ============================================================================
// Compile-time feature detection
// ============================================================================

#if defined(__SHA__) || (defined(_MSC_VER) && defined(__AVX2__))
#define KCTSB_HAS_SHA_NI 1
#include <immintrin.h>
#else
#define KCTSB_HAS_SHA_NI 0
#endif

// ============================================================================
// C++ Internal Implementation
// ============================================================================

namespace kctsb::internal {

/**
 * @brief SHA-256 round constants (cube roots of first 64 primes)
 */
alignas(16) constexpr std::array<uint32_t, 64> K256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * @brief SHA-256 initial hash values (square roots of first 8 primes)
 */
constexpr std::array<uint32_t, 8> H256_INIT = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Runtime feature flags
static bool g_has_sha_ni = false;
static bool g_sha_ni_checked = false;

/**
 * @brief Check SHA-NI availability at runtime
 */
inline bool check_sha_ni() noexcept {
    if (!g_sha_ni_checked) {
#if KCTSB_HAS_SHA_NI
#if defined(_MSC_VER)
        int info[4] = {0};
        __cpuid(info, 7);
        g_has_sha_ni = (info[1] & (1 << 29)) != 0;
#else
        unsigned int eax, ebx, ecx, edx;
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        g_has_sha_ni = (ebx & (1 << 29)) != 0;
#endif
#else
        g_has_sha_ni = false;
#endif
        g_sha_ni_checked = true;
    }
    return g_has_sha_ni;
}

// Helper functions
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

__attribute__((always_inline))
static inline uint32_t load32_be(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

__attribute__((always_inline))
static inline void store32_be(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

/**
 * @brief SHA-256 compression class
 */
class SHA256Compressor {
public:
    /**
     * @brief Scalar implementation of SHA-256 transform
     */
    __attribute__((always_inline))
    static void transform_scalar(kctsb_sha256_ctx_t* ctx, const uint8_t block[64]) noexcept {
        uint32_t W[64];
        uint32_t a, b, c, d, e, f, g, h;
        uint32_t t1 [[maybe_unused]], t2 [[maybe_unused]];

        // Prepare message schedule (load + expand)
        for (size_t i = 0; i < 16; i++) {
            W[i] = load32_be(block + i * 4);
        }
        for (size_t i = 16; i < 64; i++) {
            W[i] = W[i - 16];
            W[i] += SIG0(W[i - 15]) + W[i - 7] + SIG1(W[i - 2]);
        }

        // Initialize working variables
        a = ctx->state[0]; b = ctx->state[1];
        c = ctx->state[2]; d = ctx->state[3];
        e = ctx->state[4]; f = ctx->state[5];
        g = ctx->state[6]; h = ctx->state[7];

        // Main compression loop (optimized for register allocation)
        for (size_t i = 0; i < 64; i++) {
            h += EP1(e) + CH(e, f, g) + K256[i] + W[i];
            d += h;
            h += EP0(a) + MAJ(a, b, c);
            uint32_t tmp = h;
            h = g; g = f; f = e; e = d;
            d = c; c = b; b = a; a = tmp;
        }

        // Add compressed chunk to current hash value
        ctx->state[0] += a; ctx->state[1] += b;
        ctx->state[2] += c; ctx->state[3] += d;
        ctx->state[4] += e; ctx->state[5] += f;
        ctx->state[6] += g; ctx->state[7] += h;
    }

#if KCTSB_HAS_SHA_NI
    /**
     * @brief SHA-NI accelerated transform (Intel reference implementation)
     * @note Based on noloader/SHA-Intrinsics (public domain)
     * 
     * SHA-NI state layout after shuffle:
     *   STATE0 = ABEF, STATE1 = CDGH
     */
    __attribute__((always_inline))
    static void transform_shani(uint32_t state[8], const uint8_t block[64]) noexcept {
        __m128i STATE0, STATE1;
        __m128i MSG, TMP;
        __m128i MSG0, MSG1, MSG2, MSG3;
        __m128i ABEF_SAVE, CDGH_SAVE;
        const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
        
        // Load initial values
        TMP = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
        STATE1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
        
        TMP = _mm_shuffle_epi32(TMP, 0xB1);          // CDAB
        STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    // EFGH
        STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    // ABEF
        STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); // CDGH
        
        // Save current state
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;
        
        // Rounds 0-3
        MSG = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 0));
        MSG0 = _mm_shuffle_epi8(MSG, MASK);
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(static_cast<int64_t>(0xE9B5DBA5B5C0FBCFULL), static_cast<int64_t>(0x71374491428A2F98ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        
        // Rounds 4-7
        MSG1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 16));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(static_cast<int64_t>(0xAB1C5ED5923F82A4ULL), static_cast<int64_t>(0x59F111F13956C25BULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
        
        // Rounds 8-11
        MSG2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 32));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(static_cast<int64_t>(0x550C7DC3243185BEULL), static_cast<int64_t>(0x12835B01D807AA98ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
        
        // Rounds 12-15
        MSG3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + 48));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(static_cast<int64_t>(0xC19BF1749BDC06A7ULL), static_cast<int64_t>(0x80DEB1FE72BE5D74ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
        
        // Rounds 16-19
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(static_cast<int64_t>(0x240CA1CC0FC19DC6ULL), static_cast<int64_t>(0xEFBE4786E49B69C1ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
        
        // Rounds 20-23
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(static_cast<int64_t>(0x76F988DA5CB0A9DCULL), static_cast<int64_t>(0x4A7484AA2DE92C6FULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
        
        // Rounds 24-27
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(static_cast<int64_t>(0xBF597FC7B00327C8ULL), static_cast<int64_t>(0xA831C66D983E5152ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
        
        // Rounds 28-31
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(static_cast<int64_t>(0x1429296706CA6351ULL), static_cast<int64_t>(0xD5A79147C6E00BF3ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
        
        // Rounds 32-35
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(static_cast<int64_t>(0x53380D134D2C6DFCULL), static_cast<int64_t>(0x2E1B213827B70A85ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
        
        // Rounds 36-39
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(static_cast<int64_t>(0x92722C8581C2C92EULL), static_cast<int64_t>(0x766A0ABB650A7354ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epu32(MSG0, MSG1);
        
        // Rounds 40-43
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(static_cast<int64_t>(0xC76C51A3C24B8B70ULL), static_cast<int64_t>(0xA81A664BA2BFE8A1ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epu32(MSG1, MSG2);
        
        // Rounds 44-47
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(static_cast<int64_t>(0x106AA070F40E3585ULL), static_cast<int64_t>(0xD6990624D192E819ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epu32(MSG2, MSG3);
        
        // Rounds 48-51
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(static_cast<int64_t>(0x34B0BCB52748774CULL), static_cast<int64_t>(0x1E376C0819A4C116ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epu32(MSG3, MSG0);
        
        // Rounds 52-55
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(static_cast<int64_t>(0x682E6FF35B9CCA4FULL), static_cast<int64_t>(0x4ED8AA4A391C0CB3ULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        
        // Rounds 56-59
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(static_cast<int64_t>(0x8CC7020884C87814ULL), static_cast<int64_t>(0x78A5636F748F82EEULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        
        // Rounds 60-63
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(static_cast<int64_t>(0xC67178F2BEF9A3F7ULL), static_cast<int64_t>(0xA4506CEB90BEFFFAULL)));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        
        // Combine state
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
        
        // Shuffle back to standard state layout
        TMP = _mm_shuffle_epi32(STATE0, 0x1B);       // FEBA
        STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    // DCHG
        STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // DCBA
        STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    // HGFE
        
        // Save state
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), STATE0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), STATE1);
    }
#endif

    /**
     * @brief Auto-dispatch to best implementation
     * @note Uses SHA-NI when available for ~3x speedup
     */
    static void transform(kctsb_sha256_ctx_t* ctx, const uint8_t block[64]) noexcept {
#if KCTSB_HAS_SHA_NI
        if (check_sha_ni()) {
            transform_shani(ctx->state, block);
            return;
        }
#endif
        transform_scalar(ctx, block);
    }
};

#undef ROR
#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1

} // namespace kctsb::internal

// ============================================================================
// C ABI Export (extern "C")
// ============================================================================

extern "C" {

void kctsb_sha256_init(kctsb_sha256_ctx_t* ctx) {
    if (!ctx) {
        return;
    }

    std::memcpy(ctx->state, kctsb::internal::H256_INIT.data(), sizeof(ctx->state));
    ctx->count = 0;
    ctx->buflen = 0;
}

void kctsb_sha256_update(kctsb_sha256_ctx_t* ctx,
                          const uint8_t* data, size_t len) {
    if (!ctx) {
        return;
    }
    if (len == 0) {
        return;
    }
    if (!data) {
        return;
    }

    ctx->count += len;

    const bool use_shani =
#if KCTSB_HAS_SHA_NI
        kctsb::internal::check_sha_ni();
#else
        false;
#endif

    size_t buffer_space = KCTSB_SHA256_BLOCK_SIZE - ctx->buflen;

    if (buffer_space > len) {
        std::memcpy(ctx->buffer + ctx->buflen, data, len);
        ctx->buflen += len;
        return;
    }

    if (ctx->buflen > 0) {
        std::memcpy(ctx->buffer + ctx->buflen, data, buffer_space);
#if KCTSB_HAS_SHA_NI
        if (use_shani) {
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, ctx->buffer);
        } else {
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, ctx->buffer);
        }
#else
        kctsb::internal::SHA256Compressor::transform_scalar(ctx, ctx->buffer);
#endif
        data += buffer_space;
        len -= buffer_space;
        ctx->buflen = 0;
    }

    if (use_shani) {
#if KCTSB_HAS_SHA_NI
        while (len >= 8 * KCTSB_SHA256_BLOCK_SIZE) {
            KCTSB_PREFETCH(data + 8 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 2 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 3 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 4 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 5 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 6 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 7 * KCTSB_SHA256_BLOCK_SIZE);
            data += 8 * KCTSB_SHA256_BLOCK_SIZE;
            len -= 8 * KCTSB_SHA256_BLOCK_SIZE;
        }
        while (len >= 4 * KCTSB_SHA256_BLOCK_SIZE) {
            KCTSB_PREFETCH(data + 4 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 2 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data + 3 * KCTSB_SHA256_BLOCK_SIZE);
            data += 4 * KCTSB_SHA256_BLOCK_SIZE;
            len -= 4 * KCTSB_SHA256_BLOCK_SIZE;
        }
        while (len >= KCTSB_SHA256_BLOCK_SIZE) {
            kctsb::internal::SHA256Compressor::transform_shani(ctx->state, data);
            data += KCTSB_SHA256_BLOCK_SIZE;
            len -= KCTSB_SHA256_BLOCK_SIZE;
        }
#endif
    } else {
        while (len >= 8 * KCTSB_SHA256_BLOCK_SIZE) {
            KCTSB_PREFETCH(data + 8 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 2 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 3 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 4 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 5 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 6 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 7 * KCTSB_SHA256_BLOCK_SIZE);
            data += 8 * KCTSB_SHA256_BLOCK_SIZE;
            len -= 8 * KCTSB_SHA256_BLOCK_SIZE;
        }
        while (len >= 4 * KCTSB_SHA256_BLOCK_SIZE) {
            KCTSB_PREFETCH(data + 4 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 2 * KCTSB_SHA256_BLOCK_SIZE);
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data + 3 * KCTSB_SHA256_BLOCK_SIZE);
            data += 4 * KCTSB_SHA256_BLOCK_SIZE;
            len -= 4 * KCTSB_SHA256_BLOCK_SIZE;
        }
        while (len >= KCTSB_SHA256_BLOCK_SIZE) {
            kctsb::internal::SHA256Compressor::transform_scalar(ctx, data);
            data += KCTSB_SHA256_BLOCK_SIZE;
            len -= KCTSB_SHA256_BLOCK_SIZE;
        }
    }

    if (len > 0) {
        std::memcpy(ctx->buffer, data, len);
        ctx->buflen = len;
    }
}

void kctsb_sha256_final(kctsb_sha256_ctx_t* ctx,
                         uint8_t digest[KCTSB_SHA256_DIGEST_SIZE]) {
    if (!ctx || !digest) {
        return;
    }

    size_t used = ctx->count & 0x3F;
    uint64_t bit_len = ctx->count * 8;

    // Append 0x80 byte
    ctx->buffer[used++] = 0x80;

    // If not enough space for length, pad and process block
    if (used > 56) {
        std::memset(ctx->buffer + used, 0, KCTSB_SHA256_BLOCK_SIZE - used);
        kctsb::internal::SHA256Compressor::transform(ctx, ctx->buffer);
        used = 0;
    }

    // Pad with zeros
    std::memset(ctx->buffer + used, 0, 56 - used);

    // Append length in bits (big-endian 64-bit)
    kctsb::internal::store32_be(ctx->buffer + 56, static_cast<uint32_t>(bit_len >> 32));
    kctsb::internal::store32_be(ctx->buffer + 60, static_cast<uint32_t>(bit_len));

    kctsb::internal::SHA256Compressor::transform(ctx, ctx->buffer);

    // Extract hash value
    for (int i = 0; i < 8; i++) {
        kctsb::internal::store32_be(digest + i * 4, ctx->state[i]);
    }

    // Clear sensitive data
    kctsb_sha256_clear(ctx);
}

void kctsb_sha256(const uint8_t* data, size_t len,
                   uint8_t digest[KCTSB_SHA256_DIGEST_SIZE]) {
    if (!digest || (!data && len > 0)) {
        return;
    }

    kctsb_sha256_ctx_t ctx;
    kctsb_sha256_init(&ctx);
    kctsb_sha256_update(&ctx, data, len);
    kctsb_sha256_final(&ctx, digest);
}

void kctsb_sha256_clear(kctsb_sha256_ctx_t* ctx) {
    if (ctx) {
        volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(ctx);
        for (size_t i = 0; i < sizeof(*ctx); ++i) {
            p[i] = 0;
        }
    }
}

} // extern "C"

// ============================================================================
// C++ Namespace API (optional, for internal use)
// ============================================================================

namespace kctsb::crypto {

bool has_sha_ni() noexcept {
    return internal::check_sha_ni();
}

} // namespace kctsb::crypto
