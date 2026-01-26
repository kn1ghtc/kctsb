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
 * - AVX2/SSE4.1 acceleration for message expansion
 *
 * Optimizations (v3.4.0):
 * - SIMD-accelerated message loading with byte swap
 * - Precomputed T constants to eliminate runtime rotation
 * - Improved round function with reduced dependency chains
 *
 * Reference:
 * - GB/T 32905-2016: SM3 Cryptographic Hash Algorithm
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/core/common.h"
#include <array>
#include <cstring>
#include <cstdint>

// Platform-specific includes
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// SIMD detection
#if defined(__AVX2__)
#define KCTSB_SM3_HAS_AVX2 1
#include <immintrin.h>
#elif defined(__SSE4_1__)
#define KCTSB_SM3_HAS_SSE41 1
#include <smmintrin.h>
#endif

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
 * @brief Precomputed T[j] = ROTL32(T1/T2, j) to avoid runtime rotation
 * This eliminates 64 rotations per block processing
 */
alignas(64) constexpr std::array<uint32_t, 64> SM3_T_TABLE = {
    // T[0..15]: ROTL32(T1, j)
    0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB,
    0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
    0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
    0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
    // T[16..63]: ROTL32(T2, j % 32)
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
    0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
    0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
    0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
    0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53,
    0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
    0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4,
    0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
    0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
    0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
    0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
    0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5
};

/**
 * @brief SM3 initial hash values
 */
constexpr std::array<uint32_t, 8> SM3_IV = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// Helper macros - optimized rotation
// GCC and Clang both optimize this pattern to a single rotate instruction
#define SM3_ROTL32(x, n) (((x) << ((n) & 31)) | ((x) >> ((32 - (n)) & 31)))

// Boolean functions
#define SM3_FF0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SM3_GG0(x, y, z) ((x) ^ (y) ^ (z))
#define SM3_GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// Permutation functions
#define SM3_P0(x) ((x) ^ SM3_ROTL32((x), 9) ^ SM3_ROTL32((x), 17))
#define SM3_P1(x) ((x) ^ SM3_ROTL32((x), 15) ^ SM3_ROTL32((x), 23))

/**
 * @brief Load 32-bit big-endian value with SIMD optimization
 */
__attribute__((always_inline))
static inline uint32_t load32_be(const uint8_t* p) noexcept {
#if defined(__GNUC__)
    uint32_t v;
    std::memcpy(&v, p, 4);
    return __builtin_bswap32(v);
#else
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
#endif
}

/**
 * @brief Store 32-bit big-endian value
 */
__attribute__((always_inline))
static inline void store32_be(uint8_t* p, uint32_t v) noexcept {
#if defined(__GNUC__)
    v = __builtin_bswap32(v);
    std::memcpy(p, &v, 4);
#else
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
#endif
}

/**
 * @brief SM3 compression class with SIMD optimizations
 * 
 * Key optimizations:
 * - Precomputed T table eliminates 64 rotations per block
 * - SIMD byte swap for message loading
 * - Optimized message expansion with 4-way unrolling
 * - Reduced register pressure in round function
 */
class SM3Compressor {
public:
    /**
     * @brief Optimized message expansion
     * Uses 4-way parallel computation for better ILP
     */
    __attribute__((always_inline))
    static void expand_message(const uint32_t B[16], uint32_t W[68], uint32_t W1[64]) noexcept {
        // W[0..15] = B[0..15]
        for (int i = 0; i < 16; i++) {
            W[i] = B[i];
        }

        // W[16..67] with 4-way unrolling for better ILP
        for (size_t i = 16; i < 68; i += 4) {
            uint32_t tmp0 = W[i-16] ^ W[i-9] ^ SM3_ROTL32(W[i-3], 15);
            W[i] = SM3_P1(tmp0) ^ SM3_ROTL32(W[i-13], 7) ^ W[i-6];
            
            uint32_t tmp1 = W[i-15] ^ W[i-8] ^ SM3_ROTL32(W[i-2], 15);
            W[i+1] = SM3_P1(tmp1) ^ SM3_ROTL32(W[i-12], 7) ^ W[i-5];
            
            uint32_t tmp2 = W[i-14] ^ W[i-7] ^ SM3_ROTL32(W[i-1], 15);
            W[i+2] = SM3_P1(tmp2) ^ SM3_ROTL32(W[i-11], 7) ^ W[i-4];
            
            uint32_t tmp3 = W[i-13] ^ W[i-6] ^ SM3_ROTL32(W[i], 15);
            W[i+3] = SM3_P1(tmp3) ^ SM3_ROTL32(W[i-10], 7) ^ W[i-3];
        }

        // W'[0..63] = W[i] ^ W[i+4] with vectorization hint
        for (size_t i = 0; i < 64; i += 4) {
            W1[i]   = W[i]   ^ W[i+4];
            W1[i+1] = W[i+1] ^ W[i+5];
            W1[i+2] = W[i+2] ^ W[i+6];
            W1[i+3] = W[i+3] ^ W[i+7];
        }
    }

    /**
     * @brief Optimized SM3 compression function
     * 
     * Key changes:
     * - Use precomputed T table instead of runtime ROTL32(T, j)
     * - Separate loops for rounds 0-15 and 16-63 to eliminate branching
     * - 4-way round unrolling for better instruction pipelining
     */
    static void compress(kctsb_sm3_ctx_t* ctx, const uint8_t block[64]) noexcept {
        alignas(32) uint32_t B[16];
        alignas(32) uint32_t W[68], W1[64];
        uint32_t A, Bv, C, D, E, F, G, H;
        uint32_t SS1, SS2, TT1, TT2;

#if defined(KCTSB_SM3_HAS_AVX2)
        // AVX2 accelerated byte swap loading
        const __m256i bswap_mask = _mm256_set_epi8(
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
        );
        __m256i b0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(block));
        __m256i b1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(block + 32));
        b0 = _mm256_shuffle_epi8(b0, bswap_mask);
        b1 = _mm256_shuffle_epi8(b1, bswap_mask);
        _mm256_store_si256(reinterpret_cast<__m256i*>(B), b0);
        _mm256_store_si256(reinterpret_cast<__m256i*>(B + 8), b1);
#elif defined(KCTSB_SM3_HAS_SSE41)
        // SSE4.1 accelerated byte swap loading
        const __m128i bswap_mask = _mm_set_epi8(
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
        );
        for (int i = 0; i < 4; i++) {
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block + i * 16));
            v = _mm_shuffle_epi8(v, bswap_mask);
            _mm_store_si128(reinterpret_cast<__m128i*>(B + i * 4), v);
        }
#else
        // Scalar loading
        for (int i = 0; i < 16; i++) {
            B[i] = load32_be(block + i * 4);
        }
#endif

        // Expand message
        expand_message(B, W, W1);

        // Initialize working variables
        A = ctx->state[0]; Bv = ctx->state[1];
        C = ctx->state[2]; D = ctx->state[3];
        E = ctx->state[4]; F = ctx->state[5];
        G = ctx->state[6]; H = ctx->state[7];

        // Optimized round macro using precomputed T table
        #define SM3_ROUND_0_15(j) do { \
            SS1 = SM3_ROTL32((SM3_ROTL32(A, 12) + E + SM3_T_TABLE[j]), 7); \
            SS2 = SS1 ^ SM3_ROTL32(A, 12); \
            TT1 = SM3_FF0(A, Bv, C) + D + SS2 + W1[j]; \
            TT2 = SM3_GG0(E, F, G) + H + SS1 + W[j]; \
            D = C; C = SM3_ROTL32(Bv, 9); Bv = A; A = TT1; \
            H = G; G = SM3_ROTL32(F, 19); F = E; E = SM3_P0(TT2); \
        } while(0)

        #define SM3_ROUND_16_63(j) do { \
            SS1 = SM3_ROTL32((SM3_ROTL32(A, 12) + E + SM3_T_TABLE[j]), 7); \
            SS2 = SS1 ^ SM3_ROTL32(A, 12); \
            TT1 = SM3_FF1(A, Bv, C) + D + SS2 + W1[j]; \
            TT2 = SM3_GG1(E, F, G) + H + SS1 + W[j]; \
            D = C; C = SM3_ROTL32(Bv, 9); Bv = A; A = TT1; \
            H = G; G = SM3_ROTL32(F, 19); F = E; E = SM3_P0(TT2); \
        } while(0)

        // Rounds 0-15: FF0/GG0 path (4-way unrolled)
        SM3_ROUND_0_15(0);  SM3_ROUND_0_15(1);  SM3_ROUND_0_15(2);  SM3_ROUND_0_15(3);
        SM3_ROUND_0_15(4);  SM3_ROUND_0_15(5);  SM3_ROUND_0_15(6);  SM3_ROUND_0_15(7);
        SM3_ROUND_0_15(8);  SM3_ROUND_0_15(9);  SM3_ROUND_0_15(10); SM3_ROUND_0_15(11);
        SM3_ROUND_0_15(12); SM3_ROUND_0_15(13); SM3_ROUND_0_15(14); SM3_ROUND_0_15(15);

        // Rounds 16-63: FF1/GG1 path (4-way unrolled per iteration)
        for (size_t j = 16; j < 64; j += 4) {
            SM3_ROUND_16_63(j);
            SM3_ROUND_16_63(j + 1);
            SM3_ROUND_16_63(j + 2);
            SM3_ROUND_16_63(j + 3);
        }

        #undef SM3_ROUND_0_15
        #undef SM3_ROUND_16_63

        // Update state
        ctx->state[0] ^= A;
        ctx->state[1] ^= Bv;
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
        kctsb::internal::store32_be(digest + static_cast<size_t>(i) * 4, ctx->state[i]);
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

// ============================================================================
// Scalar compress function for AVX2 fallback
// ============================================================================

extern "C" void sm3_compress_scalar(kctsb_sm3_ctx_t* ctx, const uint8_t* block) {
    kctsb::internal::SM3Compressor::compress(ctx, block);
}

