/**
 * @file chacha20_poly1305.cpp
 * @brief ChaCha20-Poly1305 AEAD Implementation (Optimized)
 *
 * RFC 8439 compliant implementation with:
 * - ChaCha20: AVX2 8-block parallel with optimized memory layout
 * - Poly1305: 128-bit arithmetic with radix-2^44 and 4-block batch processing
 *
 * Optimization features:
 * - 8-block parallel ChaCha20 (512 bytes per batch)
 * - 4-block batch Poly1305 using sequential multiplications
 * - 128-bit integer arithmetic for fast modular multiplication
 * - Constant-time operations for side-channel resistance
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/chacha20_poly1305.h"
#include "kctsb/core/security.h"
#include <cstring>
#include <stdexcept>

// SIMD detection
#if defined(__AVX2__)
#include <immintrin.h>
#define KCTSB_HAS_AVX2 1
#endif

// 128-bit integer for Poly1305 optimization
#if defined(__SIZEOF_INT128__) && !defined(__STRICT_ANSI__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
using uint128_t = unsigned __int128;
#pragma GCC diagnostic pop
#define KCTSB_HAS_UINT128 1
#endif

// ============================================================================
// Utility Functions
// ============================================================================

static inline uint32_t load32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

static inline uint64_t load64_le(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
}

static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

static inline void store64_le(uint8_t* p, uint64_t v) {
    for (size_t i = 0; i < 8; i++) {
        p[i] = static_cast<uint8_t>(v >> (i * 8));
    }
}

// ChaCha20 constants: "expand 32-byte k"
static const uint32_t CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

// ============================================================================
// ChaCha20 Core
// ============================================================================

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA_QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7)

/**
 * @brief Generate one ChaCha20 block (64 bytes)
 */
static void chacha20_block(const uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, state, 64);

    for (int i = 0; i < 10; i++) {
        CHACHA_QR(x[0], x[4], x[8],  x[12]);
        CHACHA_QR(x[1], x[5], x[9],  x[13]);
        CHACHA_QR(x[2], x[6], x[10], x[14]);
        CHACHA_QR(x[3], x[7], x[11], x[15]);
        CHACHA_QR(x[0], x[5], x[10], x[15]);
        CHACHA_QR(x[1], x[6], x[11], x[12]);
        CHACHA_QR(x[2], x[7], x[8],  x[13]);
        CHACHA_QR(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; i++) {
        store32_le(&out[i * 4], x[i] + state[i]);
    }
    kctsb_secure_zero(x, sizeof(x));
}

#ifdef KCTSB_HAS_AVX2
/**
 * @brief AVX2 ChaCha20 quarter round for horizontal layout (2 blocks per register)
 * Each __m256i = [block0_row, block1_row] (2x 128-bit halves)
 */
#define CHACHA_QR_2B(a, b, c, d) \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); \
    d = _mm256_shuffle_epi8(d, rot16); \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); \
    b = _mm256_or_si256(_mm256_slli_epi32(b, 12), _mm256_srli_epi32(b, 20)); \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); \
    d = _mm256_shuffle_epi8(d, rot8); \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); \
    b = _mm256_or_si256(_mm256_slli_epi32(b, 7), _mm256_srli_epi32(b, 25))

/**
 * @brief Generate 2 ChaCha20 blocks using horizontal layout (128 bytes)
 * 
 * Horizontal layout: each __m256i holds 2 blocks' worth of same-row data
 * [block0.row_i, block1.row_i] - no transpose needed!
 */
static inline void chacha20_2blocks_xor_avx2(uint32_t state[16],
                                              const uint8_t* in, uint8_t* out) {
    // Rotation shuffle masks
    const __m256i rot16 = _mm256_set_epi8(
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m256i rot8 = _mm256_set_epi8(
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

    // Load state into horizontal layout: [block0, block1] per register
    // Row 0: [state0-3] for block0 and block1
    __m256i row0 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
        reinterpret_cast<const __m128i*>(&state[0])));
    __m256i row1 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
        reinterpret_cast<const __m128i*>(&state[4])));
    __m256i row2 = _mm256_broadcastsi128_si256(_mm_loadu_si128(
        reinterpret_cast<const __m128i*>(&state[8])));
    // Row 3: counter differs between blocks
    __m256i ctr_add = _mm256_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0);
    __m256i row3 = _mm256_add_epi32(
        _mm256_broadcastsi128_si256(_mm_loadu_si128(
            reinterpret_cast<const __m128i*>(&state[12]))),
        ctr_add);

    __m256i orig0 = row0, orig1 = row1, orig2 = row2, orig3 = row3;

    for (int i = 0; i < 10; i++) {
        // Column rounds
        CHACHA_QR_2B(row0, row1, row2, row3);
        // Shuffle for diagonal rounds
        row1 = _mm256_shuffle_epi32(row1, 0x39);  // 0,3,2,1
        row2 = _mm256_shuffle_epi32(row2, 0x4e);  // 1,0,3,2
        row3 = _mm256_shuffle_epi32(row3, 0x93);  // 2,1,0,3
        // Diagonal rounds
        CHACHA_QR_2B(row0, row1, row2, row3);
        // Unshuffle
        row1 = _mm256_shuffle_epi32(row1, 0x93);
        row2 = _mm256_shuffle_epi32(row2, 0x4e);
        row3 = _mm256_shuffle_epi32(row3, 0x39);
    }

    row0 = _mm256_add_epi32(row0, orig0);
    row1 = _mm256_add_epi32(row1, orig1);
    row2 = _mm256_add_epi32(row2, orig2);
    row3 = _mm256_add_epi32(row3, orig3);

    // Output directly - no transpose needed with horizontal layout!
    // Block 0 (low 128 bits)
    __m128i in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
    __m128i in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16));
    __m128i in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 32));
    __m128i in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 48));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out),
                     _mm_xor_si128(in0, _mm256_castsi256_si128(row0)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16),
                     _mm_xor_si128(in1, _mm256_castsi256_si128(row1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32),
                     _mm_xor_si128(in2, _mm256_castsi256_si128(row2)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48),
                     _mm_xor_si128(in3, _mm256_castsi256_si128(row3)));

    // Block 1 (high 128 bits)
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 64));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 80));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 96));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 112));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 64),
                     _mm_xor_si128(in0, _mm256_extracti128_si256(row0, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 80),
                     _mm_xor_si128(in1, _mm256_extracti128_si256(row1, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 96),
                     _mm_xor_si128(in2, _mm256_extracti128_si256(row2, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 112),
                     _mm_xor_si128(in3, _mm256_extracti128_si256(row3, 1)));

    state[12] += 2;
}

/**
 * @brief Generate 4 ChaCha20 blocks using two interleaved 2-block sets (256 bytes)
 *
 * Uses instruction-level parallelism by processing two independent 2-block
 * sets simultaneously, maximizing CPU pipeline utilization.
 */
static void chacha20_4blocks_xor_avx2(uint32_t state[16],
                                       const uint8_t* in, uint8_t* out) {
    // Rotation shuffle masks
    const __m256i rot16 = _mm256_set_epi8(
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m256i rot8 = _mm256_set_epi8(
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

    // Load base state
    __m128i base0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
    __m128i base1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
    __m128i base2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[8]));
    __m128i base3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[12]));

    // Set A: blocks 0,1 (counter +0, +1)
    __m256i a0 = _mm256_broadcastsi128_si256(base0);
    __m256i a1 = _mm256_broadcastsi128_si256(base1);
    __m256i a2 = _mm256_broadcastsi128_si256(base2);
    __m256i a3 = _mm256_add_epi32(_mm256_broadcastsi128_si256(base3),
                                  _mm256_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0));

    // Set B: blocks 2,3 (counter +2, +3)
    __m256i b0 = a0;
    __m256i b1 = a1;
    __m256i b2 = a2;
    __m256i b3 = _mm256_add_epi32(_mm256_broadcastsi128_si256(base3),
                                  _mm256_setr_epi32(2, 0, 0, 0, 3, 0, 0, 0));

    __m256i a0_orig = a0, a1_orig = a1, a2_orig = a2, a3_orig = a3;
    __m256i b0_orig = b0, b1_orig = b1, b2_orig = b2, b3_orig = b3;

    // 20 rounds - interleave A and B for better ILP
    for (int i = 0; i < 10; i++) {
        // Column rounds - A
        CHACHA_QR_2B(a0, a1, a2, a3);
        // Column rounds - B (interleaved)
        CHACHA_QR_2B(b0, b1, b2, b3);

        // Shuffle for diagonal - A
        a1 = _mm256_shuffle_epi32(a1, 0x39);
        a2 = _mm256_shuffle_epi32(a2, 0x4e);
        a3 = _mm256_shuffle_epi32(a3, 0x93);
        // Shuffle for diagonal - B
        b1 = _mm256_shuffle_epi32(b1, 0x39);
        b2 = _mm256_shuffle_epi32(b2, 0x4e);
        b3 = _mm256_shuffle_epi32(b3, 0x93);

        // Diagonal rounds - A
        CHACHA_QR_2B(a0, a1, a2, a3);
        // Diagonal rounds - B (interleaved)
        CHACHA_QR_2B(b0, b1, b2, b3);

        // Unshuffle - A
        a1 = _mm256_shuffle_epi32(a1, 0x93);
        a2 = _mm256_shuffle_epi32(a2, 0x4e);
        a3 = _mm256_shuffle_epi32(a3, 0x39);
        // Unshuffle - B
        b1 = _mm256_shuffle_epi32(b1, 0x93);
        b2 = _mm256_shuffle_epi32(b2, 0x4e);
        b3 = _mm256_shuffle_epi32(b3, 0x39);
    }

    // Add original state
    a0 = _mm256_add_epi32(a0, a0_orig); a1 = _mm256_add_epi32(a1, a1_orig);
    a2 = _mm256_add_epi32(a2, a2_orig); a3 = _mm256_add_epi32(a3, a3_orig);
    b0 = _mm256_add_epi32(b0, b0_orig); b1 = _mm256_add_epi32(b1, b1_orig);
    b2 = _mm256_add_epi32(b2, b2_orig); b3 = _mm256_add_epi32(b3, b3_orig);

    // Output blocks 0-3 directly (no transpose!)
    __m128i in0, in1, in2, in3;

    // Block 0
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 32));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 48));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out),
                     _mm_xor_si128(in0, _mm256_castsi256_si128(a0)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16),
                     _mm_xor_si128(in1, _mm256_castsi256_si128(a1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32),
                     _mm_xor_si128(in2, _mm256_castsi256_si128(a2)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48),
                     _mm_xor_si128(in3, _mm256_castsi256_si128(a3)));

    // Block 1
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 64));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 80));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 96));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 112));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 64),
                     _mm_xor_si128(in0, _mm256_extracti128_si256(a0, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 80),
                     _mm_xor_si128(in1, _mm256_extracti128_si256(a1, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 96),
                     _mm_xor_si128(in2, _mm256_extracti128_si256(a2, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 112),
                     _mm_xor_si128(in3, _mm256_extracti128_si256(a3, 1)));

    // Block 2
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 128));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 144));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 160));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 176));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 128),
                     _mm_xor_si128(in0, _mm256_castsi256_si128(b0)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 144),
                     _mm_xor_si128(in1, _mm256_castsi256_si128(b1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 160),
                     _mm_xor_si128(in2, _mm256_castsi256_si128(b2)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 176),
                     _mm_xor_si128(in3, _mm256_castsi256_si128(b3)));

    // Block 3
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 192));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 208));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 224));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 240));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 192),
                     _mm_xor_si128(in0, _mm256_extracti128_si256(b0, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 208),
                     _mm_xor_si128(in1, _mm256_extracti128_si256(b1, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 224),
                     _mm_xor_si128(in2, _mm256_extracti128_si256(b2, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 240),
                     _mm_xor_si128(in3, _mm256_extracti128_si256(b3, 1)));

    state[12] += 4;
}

/**
 * @brief Generate 8 ChaCha20 blocks using four interleaved 2-block sets (512 bytes)
 *
 * Maximum throughput version for large data using all available register pressure.
 */
static void chacha20_8blocks_xor_avx2(uint32_t state[16],
                                       const uint8_t* in, uint8_t* out) {
    const __m256i rot16 = _mm256_set_epi8(
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2,
        13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);
    const __m256i rot8 = _mm256_set_epi8(
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3,
        14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

    __m128i base0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
    __m128i base1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
    __m128i base2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[8]));
    __m128i base3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[12]));

    // Set A: blocks 0,1
    __m256i a0 = _mm256_broadcastsi128_si256(base0);
    __m256i a1 = _mm256_broadcastsi128_si256(base1);
    __m256i a2 = _mm256_broadcastsi128_si256(base2);
    __m256i a3 = _mm256_add_epi32(_mm256_broadcastsi128_si256(base3),
                                  _mm256_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0));

    // Set B: blocks 2,3
    __m256i b0 = a0, b1 = a1, b2 = a2;
    __m256i b3 = _mm256_add_epi32(_mm256_broadcastsi128_si256(base3),
                                  _mm256_setr_epi32(2, 0, 0, 0, 3, 0, 0, 0));

    // Set C: blocks 4,5
    __m256i c0 = a0, c1 = a1, c2 = a2;
    __m256i c3 = _mm256_add_epi32(_mm256_broadcastsi128_si256(base3),
                                  _mm256_setr_epi32(4, 0, 0, 0, 5, 0, 0, 0));

    // Set D: blocks 6,7
    __m256i d0 = a0, d1 = a1, d2 = a2;
    __m256i d3 = _mm256_add_epi32(_mm256_broadcastsi128_si256(base3),
                                  _mm256_setr_epi32(6, 0, 0, 0, 7, 0, 0, 0));

    __m256i a0o = a0, a1o = a1, a2o = a2, a3o = a3;
    __m256i b0o = b0, b1o = b1, b2o = b2, b3o = b3;
    __m256i c0o = c0, c1o = c1, c2o = c2, c3o = c3;
    __m256i d0o = d0, d1o = d1, d2o = d2, d3o = d3;

    for (int i = 0; i < 10; i++) {
        // Column rounds - all sets
        CHACHA_QR_2B(a0, a1, a2, a3);
        CHACHA_QR_2B(b0, b1, b2, b3);
        CHACHA_QR_2B(c0, c1, c2, c3);
        CHACHA_QR_2B(d0, d1, d2, d3);

        // Shuffle for diagonal
        a1 = _mm256_shuffle_epi32(a1, 0x39); a2 = _mm256_shuffle_epi32(a2, 0x4e); a3 = _mm256_shuffle_epi32(a3, 0x93);
        b1 = _mm256_shuffle_epi32(b1, 0x39); b2 = _mm256_shuffle_epi32(b2, 0x4e); b3 = _mm256_shuffle_epi32(b3, 0x93);
        c1 = _mm256_shuffle_epi32(c1, 0x39); c2 = _mm256_shuffle_epi32(c2, 0x4e); c3 = _mm256_shuffle_epi32(c3, 0x93);
        d1 = _mm256_shuffle_epi32(d1, 0x39); d2 = _mm256_shuffle_epi32(d2, 0x4e); d3 = _mm256_shuffle_epi32(d3, 0x93);

        // Diagonal rounds
        CHACHA_QR_2B(a0, a1, a2, a3);
        CHACHA_QR_2B(b0, b1, b2, b3);
        CHACHA_QR_2B(c0, c1, c2, c3);
        CHACHA_QR_2B(d0, d1, d2, d3);

        // Unshuffle
        a1 = _mm256_shuffle_epi32(a1, 0x93); a2 = _mm256_shuffle_epi32(a2, 0x4e); a3 = _mm256_shuffle_epi32(a3, 0x39);
        b1 = _mm256_shuffle_epi32(b1, 0x93); b2 = _mm256_shuffle_epi32(b2, 0x4e); b3 = _mm256_shuffle_epi32(b3, 0x39);
        c1 = _mm256_shuffle_epi32(c1, 0x93); c2 = _mm256_shuffle_epi32(c2, 0x4e); c3 = _mm256_shuffle_epi32(c3, 0x39);
        d1 = _mm256_shuffle_epi32(d1, 0x93); d2 = _mm256_shuffle_epi32(d2, 0x4e); d3 = _mm256_shuffle_epi32(d3, 0x39);
    }

    // Add original state
    a0 = _mm256_add_epi32(a0, a0o); a1 = _mm256_add_epi32(a1, a1o); a2 = _mm256_add_epi32(a2, a2o); a3 = _mm256_add_epi32(a3, a3o);
    b0 = _mm256_add_epi32(b0, b0o); b1 = _mm256_add_epi32(b1, b1o); b2 = _mm256_add_epi32(b2, b2o); b3 = _mm256_add_epi32(b3, b3o);
    c0 = _mm256_add_epi32(c0, c0o); c1 = _mm256_add_epi32(c1, c1o); c2 = _mm256_add_epi32(c2, c2o); c3 = _mm256_add_epi32(c3, c3o);
    d0 = _mm256_add_epi32(d0, d0o); d1 = _mm256_add_epi32(d1, d1o); d2 = _mm256_add_epi32(d2, d2o); d3 = _mm256_add_epi32(d3, d3o);

    // Output all 8 blocks
    __m128i in0, in1, in2, in3;

    // Block 0
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 32));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 48));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), _mm_xor_si128(in0, _mm256_castsi256_si128(a0)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16), _mm_xor_si128(in1, _mm256_castsi256_si128(a1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32), _mm_xor_si128(in2, _mm256_castsi256_si128(a2)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48), _mm_xor_si128(in3, _mm256_castsi256_si128(a3)));

    // Block 1
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 64));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 80));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 96));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 112));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 64), _mm_xor_si128(in0, _mm256_extracti128_si256(a0, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 80), _mm_xor_si128(in1, _mm256_extracti128_si256(a1, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 96), _mm_xor_si128(in2, _mm256_extracti128_si256(a2, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 112), _mm_xor_si128(in3, _mm256_extracti128_si256(a3, 1)));

    // Block 2
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 128));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 144));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 160));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 176));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 128), _mm_xor_si128(in0, _mm256_castsi256_si128(b0)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 144), _mm_xor_si128(in1, _mm256_castsi256_si128(b1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 160), _mm_xor_si128(in2, _mm256_castsi256_si128(b2)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 176), _mm_xor_si128(in3, _mm256_castsi256_si128(b3)));

    // Block 3
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 192));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 208));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 224));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 240));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 192), _mm_xor_si128(in0, _mm256_extracti128_si256(b0, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 208), _mm_xor_si128(in1, _mm256_extracti128_si256(b1, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 224), _mm_xor_si128(in2, _mm256_extracti128_si256(b2, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 240), _mm_xor_si128(in3, _mm256_extracti128_si256(b3, 1)));

    // Block 4
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 256));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 272));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 288));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 304));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 256), _mm_xor_si128(in0, _mm256_castsi256_si128(c0)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 272), _mm_xor_si128(in1, _mm256_castsi256_si128(c1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 288), _mm_xor_si128(in2, _mm256_castsi256_si128(c2)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 304), _mm_xor_si128(in3, _mm256_castsi256_si128(c3)));

    // Block 5
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 320));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 336));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 352));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 368));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 320), _mm_xor_si128(in0, _mm256_extracti128_si256(c0, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 336), _mm_xor_si128(in1, _mm256_extracti128_si256(c1, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 352), _mm_xor_si128(in2, _mm256_extracti128_si256(c2, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 368), _mm_xor_si128(in3, _mm256_extracti128_si256(c3, 1)));

    // Block 6
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 384));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 400));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 416));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 432));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 384), _mm_xor_si128(in0, _mm256_castsi256_si128(d0)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 400), _mm_xor_si128(in1, _mm256_castsi256_si128(d1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 416), _mm_xor_si128(in2, _mm256_castsi256_si128(d2)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 432), _mm_xor_si128(in3, _mm256_castsi256_si128(d3)));

    // Block 7
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 448));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 464));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 480));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 496));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 448), _mm_xor_si128(in0, _mm256_extracti128_si256(d0, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 464), _mm_xor_si128(in1, _mm256_extracti128_si256(d1, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 480), _mm_xor_si128(in2, _mm256_extracti128_si256(d2, 1)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 496), _mm_xor_si128(in3, _mm256_extracti128_si256(d3, 1)));

    state[12] += 8;
}
#endif // KCTSB_HAS_AVX2

// ============================================================================
// Poly1305 Core (Radix-2^44, 128-bit arithmetic)
// ============================================================================

#ifdef KCTSB_HAS_UINT128
static constexpr uint64_t MASK44 = (1ULL << 44) - 1;
static constexpr uint64_t MASK42 = (1ULL << 42) - 1;

/**
 * @brief Process 4 Poly1305 blocks sequentially with 128-bit arithmetic
 */
static void poly1305_4blocks(kctsb_poly1305_ctx_t* ctx, const uint8_t blocks[64]) {
    uint64_t h0 = ctx->h44[0], h1 = ctx->h44[1], h2 = ctx->h44[2];
    uint64_t r0 = ctx->r44[0], r1 = ctx->r44[1], r2 = ctx->r44[2];
    uint64_t s1 = ctx->s44[1], s2 = ctx->s44[2];
    
    for (int i = 0; i < 4; i++) {
        const uint8_t* blk = blocks + i * 16;
        uint64_t t0 = load64_le(blk);
        uint64_t t1 = load64_le(blk + 8);
        
        h0 += t0 & MASK44;
        h1 += ((t0 >> 44) | (t1 << 20)) & MASK44;
        h2 += ((t1 >> 24) & MASK42) + (1ULL << 40);
        
        uint128_t d0 = static_cast<uint128_t>(h0) * r0 +
                       static_cast<uint128_t>(h1) * s2 +
                       static_cast<uint128_t>(h2) * s1;
        uint128_t d1 = static_cast<uint128_t>(h0) * r1 +
                       static_cast<uint128_t>(h1) * r0 +
                       static_cast<uint128_t>(h2) * s2;
        uint128_t d2 = static_cast<uint128_t>(h0) * r2 +
                       static_cast<uint128_t>(h1) * r1 +
                       static_cast<uint128_t>(h2) * r0;
        
        uint64_t c;
        c = static_cast<uint64_t>(d0 >> 44); h0 = static_cast<uint64_t>(d0) & MASK44;
        d1 += c;
        c = static_cast<uint64_t>(d1 >> 44); h1 = static_cast<uint64_t>(d1) & MASK44;
        d2 += c;
        c = static_cast<uint64_t>(d2 >> 42); h2 = static_cast<uint64_t>(d2) & MASK42;
        h0 += c * 5;
        c = h0 >> 44; h0 &= MASK44;
        h1 += c;
    }
    
    ctx->h44[0] = h0; ctx->h44[1] = h1; ctx->h44[2] = h2;
}

/**
 * @brief Process single Poly1305 block
 */
static void poly1305_block(kctsb_poly1305_ctx_t* ctx, const uint8_t block[16], int is_final) {
    uint64_t t0 = load64_le(block);
    uint64_t t1 = load64_le(block + 8);
    
    uint64_t h0 = ctx->h44[0], h1 = ctx->h44[1], h2 = ctx->h44[2];
    
    h0 += t0 & MASK44;
    h1 += ((t0 >> 44) | (t1 << 20)) & MASK44;
    h2 += (t1 >> 24) & MASK42;
    if (!is_final) h2 += (1ULL << 40);
    
    uint64_t r0 = ctx->r44[0], r1 = ctx->r44[1], r2 = ctx->r44[2];
    uint64_t s1 = ctx->s44[1], s2 = ctx->s44[2];
    
    uint128_t d0 = static_cast<uint128_t>(h0) * r0 +
                   static_cast<uint128_t>(h1) * s2 +
                   static_cast<uint128_t>(h2) * s1;
    uint128_t d1 = static_cast<uint128_t>(h0) * r1 +
                   static_cast<uint128_t>(h1) * r0 +
                   static_cast<uint128_t>(h2) * s2;
    uint128_t d2 = static_cast<uint128_t>(h0) * r2 +
                   static_cast<uint128_t>(h1) * r1 +
                   static_cast<uint128_t>(h2) * r0;
    
    uint64_t c;
    c = static_cast<uint64_t>(d0 >> 44); ctx->h44[0] = static_cast<uint64_t>(d0) & MASK44;
    d1 += c;
    c = static_cast<uint64_t>(d1 >> 44); ctx->h44[1] = static_cast<uint64_t>(d1) & MASK44;
    d2 += c;
    c = static_cast<uint64_t>(d2 >> 42); ctx->h44[2] = static_cast<uint64_t>(d2) & MASK42;
    ctx->h44[0] += c * 5;
    c = ctx->h44[0] >> 44; ctx->h44[0] &= MASK44;
    ctx->h44[1] += c;
}
#else
// Fallback radix-2^26 implementation
static constexpr uint32_t MASK26 = (1U << 26) - 1;

static void poly1305_block(kctsb_poly1305_ctx_t* ctx, const uint8_t block[16], int is_final) {
    uint32_t t0 = load32_le(&block[0]);
    uint32_t t1 = load32_le(&block[4]);
    uint32_t t2 = load32_le(&block[8]);
    uint32_t t3 = load32_le(&block[12]);

    uint64_t h0 = ctx->h[0] + (t0 & MASK26);
    uint64_t h1 = ctx->h[1] + (((t0 >> 26) | (t1 << 6)) & MASK26);
    uint64_t h2 = ctx->h[2] + (((t1 >> 20) | (t2 << 12)) & MASK26);
    uint64_t h3 = ctx->h[3] + (((t2 >> 14) | (t3 << 18)) & MASK26);
    uint64_t h4 = ctx->h[4] + (t3 >> 8);
    if (!is_final) h4 += (1ULL << 24);

    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint64_t d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
    uint64_t d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
    uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
    uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
    uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

    uint64_t c;
    c = d0 >> 26; d1 += c; d0 &= MASK26;
    c = d1 >> 26; d2 += c; d1 &= MASK26;
    c = d2 >> 26; d3 += c; d2 &= MASK26;
    c = d3 >> 26; d4 += c; d3 &= MASK26;
    c = d4 >> 26; d0 += c * 5; d4 &= MASK26;
    c = d0 >> 26; d1 += c; d0 &= MASK26;

    ctx->h[0] = static_cast<uint32_t>(d0);
    ctx->h[1] = static_cast<uint32_t>(d1);
    ctx->h[2] = static_cast<uint32_t>(d2);
    ctx->h[3] = static_cast<uint32_t>(d3);
    ctx->h[4] = static_cast<uint32_t>(d4);
}
#endif // KCTSB_HAS_UINT128

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

kctsb_error_t kctsb_chacha20_init(kctsb_chacha20_ctx_t* ctx,
                                   const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   uint32_t counter) {
    if (!ctx || !key || !nonce) return KCTSB_ERROR_INVALID_PARAM;

    ctx->state[0] = CHACHA_CONSTANTS[0];
    ctx->state[1] = CHACHA_CONSTANTS[1];
    ctx->state[2] = CHACHA_CONSTANTS[2];
    ctx->state[3] = CHACHA_CONSTANTS[3];
    for (int i = 0; i < 8; i++) ctx->state[4 + i] = load32_le(&key[i * 4]);
    ctx->state[12] = counter;
    ctx->state[13] = load32_le(&nonce[0]);
    ctx->state[14] = load32_le(&nonce[4]);
    ctx->state[15] = load32_le(&nonce[8]);
    ctx->remaining = 0;
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_crypt(kctsb_chacha20_ctx_t* ctx,
                                    const uint8_t* input,
                                    size_t len,
                                    uint8_t* output) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    size_t offset = 0;

    // Use remaining keystream
    if (ctx->remaining > 0) {
        size_t use = (len < ctx->remaining) ? len : ctx->remaining;
        size_t ks_off = 64 - ctx->remaining;
        for (size_t i = 0; i < use; i++) output[i] = input[i] ^ ctx->keystream[ks_off + i];
        ctx->remaining -= use;
        offset = use;
    }

#ifdef KCTSB_HAS_AVX2
    // Process 512 bytes (8 blocks) at a time for maximum throughput
    while (offset + 512 <= len) {
        chacha20_8blocks_xor_avx2(ctx->state, &input[offset], &output[offset]);
        offset += 512;
    }
    // Process 256 bytes (4 blocks) at a time
    while (offset + 256 <= len) {
        chacha20_4blocks_xor_avx2(ctx->state, &input[offset], &output[offset]);
        offset += 256;
    }
#endif

    // Process remaining 64-byte blocks
    while (offset + 64 <= len) {
        chacha20_block(ctx->state, ctx->keystream);
        ctx->state[12]++;
        for (size_t i = 0; i < 64; i++) output[offset + i] = input[offset + i] ^ ctx->keystream[i];
        offset += 64;
    }

    // Handle tail
    if (offset < len) {
        chacha20_block(ctx->state, ctx->keystream);
        ctx->state[12]++;
        size_t rem = len - offset;
        for (size_t i = 0; i < rem; i++) output[offset + i] = input[offset + i] ^ ctx->keystream[i];
        ctx->remaining = 64 - rem;
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                             const uint8_t* input, size_t len, uint8_t* output) {
    kctsb_chacha20_ctx_t ctx;
    kctsb_error_t err = kctsb_chacha20_init(&ctx, key, nonce, counter);
    if (err != KCTSB_SUCCESS) return err;
    err = kctsb_chacha20_crypt(&ctx, input, len, output);
    kctsb_chacha20_clear(&ctx);
    return err;
}

void kctsb_chacha20_clear(kctsb_chacha20_ctx_t* ctx) {
    if (ctx) kctsb_secure_zero(ctx, sizeof(*ctx));
}

// ============================================================================
// Poly1305 C API
// ============================================================================

kctsb_error_t kctsb_poly1305_init(kctsb_poly1305_ctx_t* ctx, const uint8_t key[32]) {
    if (!ctx || !key) return KCTSB_ERROR_INVALID_PARAM;
    memset(ctx, 0, sizeof(*ctx));

    uint32_t t0 = load32_le(&key[0]);
    uint32_t t1 = load32_le(&key[4]);
    uint32_t t2 = load32_le(&key[8]);
    uint32_t t3 = load32_le(&key[12]);

    // Clamp r
    ctx->r[0] = t0 & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    ctx->r[4] = (t3 >> 8) & 0x00fffff;

#ifdef KCTSB_HAS_UINT128
    // Convert to radix-2^44
    ctx->r44[0] = (static_cast<uint64_t>(ctx->r[0]) | (static_cast<uint64_t>(ctx->r[1]) << 26)) & MASK44;
    ctx->r44[1] = ((static_cast<uint64_t>(ctx->r[1]) >> 18) | (static_cast<uint64_t>(ctx->r[2]) << 8) |
                   (static_cast<uint64_t>(ctx->r[3]) << 34)) & MASK44;
    ctx->r44[2] = ((static_cast<uint64_t>(ctx->r[3]) >> 10) | (static_cast<uint64_t>(ctx->r[4]) << 16)) & MASK42;
    
    // s = 5*r for reduction (since 2^130 mod (2^130-5) = 5)
    ctx->s44[0] = 0;
    ctx->s44[1] = ctx->r44[1] * 5;
    ctx->s44[2] = ctx->r44[2] * 5;
#endif

    ctx->s[0] = load32_le(&key[16]);
    ctx->s[1] = load32_le(&key[20]);
    ctx->s[2] = load32_le(&key[24]);
    ctx->s[3] = load32_le(&key[28]);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305_update(kctsb_poly1305_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx) return KCTSB_ERROR_INVALID_PARAM;
    if (ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;
    if (!data) return KCTSB_ERROR_INVALID_PARAM;

    size_t offset = 0;

    // Fill partial buffer
    if (ctx->buffer_len > 0) {
        size_t need = 16 - ctx->buffer_len;
        size_t use = (len < need) ? len : need;
        memcpy(&ctx->buffer[ctx->buffer_len], data, use);
        ctx->buffer_len += use;
        offset = use;
        if (ctx->buffer_len == 16) {
            poly1305_block(ctx, ctx->buffer, 0);
            ctx->buffer_len = 0;
        }
    }

#ifdef KCTSB_HAS_UINT128
    // Process 64 bytes (4 blocks) at a time
    while (offset + 64 <= len) {
        poly1305_4blocks(ctx, &data[offset]);
        offset += 64;
    }
#endif

    // Process remaining full blocks
    while (offset + 16 <= len) {
        poly1305_block(ctx, &data[offset], 0);
        offset += 16;
    }

    // Buffer remaining
    if (offset < len) {
        memcpy(ctx->buffer, &data[offset], len - offset);
        ctx->buffer_len = len - offset;
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305_final(kctsb_poly1305_ctx_t* ctx, uint8_t tag[16]) {
    if (!ctx || !tag) return KCTSB_ERROR_INVALID_PARAM;
    if (ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;

    // Process final partial block
    if (ctx->buffer_len > 0) {
        ctx->buffer[ctx->buffer_len] = 1;
        for (size_t i = ctx->buffer_len + 1; i < 16; i++) ctx->buffer[i] = 0;
        poly1305_block(ctx, ctx->buffer, 1);
    }

#ifdef KCTSB_HAS_UINT128
    // Convert from radix-2^44 to radix-2^26
    uint64_t h44_0 = ctx->h44[0], h44_1 = ctx->h44[1], h44_2 = ctx->h44[2];
    ctx->h[0] = static_cast<uint32_t>(h44_0) & 0x3ffffff;
    ctx->h[1] = static_cast<uint32_t>((h44_0 >> 26) | (h44_1 << 18)) & 0x3ffffff;
    ctx->h[2] = static_cast<uint32_t>(h44_1 >> 8) & 0x3ffffff;
    ctx->h[3] = static_cast<uint32_t>((h44_1 >> 34) | (h44_2 << 10)) & 0x3ffffff;
    ctx->h[4] = static_cast<uint32_t>(h44_2 >> 16);
#endif

    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

    // Final carry propagation
    uint32_t c;
    c = h1 >> 26; h2 += c; h1 &= 0x3ffffff;
    c = h2 >> 26; h3 += c; h2 &= 0x3ffffff;
    c = h3 >> 26; h4 += c; h3 &= 0x3ffffff;
    c = h4 >> 26; h0 += c * 5; h4 &= 0x3ffffff;
    c = h0 >> 26; h1 += c; h0 &= 0x3ffffff;

    // Compute h - p
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);

    // Select h or g
    uint32_t mask = (g4 >> 31) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // Add s and output
    uint64_t f0 = (h0 | (h1 << 26)) + static_cast<uint64_t>(ctx->s[0]);
    uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + static_cast<uint64_t>(ctx->s[1]);
    uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + static_cast<uint64_t>(ctx->s[2]);
    uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + static_cast<uint64_t>(ctx->s[3]);

    f1 += f0 >> 32; f2 += f1 >> 32; f3 += f2 >> 32;

    store32_le(&tag[0], static_cast<uint32_t>(f0));
    store32_le(&tag[4], static_cast<uint32_t>(f1));
    store32_le(&tag[8], static_cast<uint32_t>(f2));
    store32_le(&tag[12], static_cast<uint32_t>(f3));

    ctx->finalized = 1;
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305(const uint8_t key[32], const uint8_t* data, size_t len, uint8_t tag[16]) {
    kctsb_poly1305_ctx_t ctx;
    kctsb_error_t err = kctsb_poly1305_init(&ctx, key);
    if (err != KCTSB_SUCCESS) return err;
    err = kctsb_poly1305_update(&ctx, data, len);
    if (err != KCTSB_SUCCESS) { kctsb_poly1305_clear(&ctx); return err; }
    err = kctsb_poly1305_final(&ctx, tag);
    kctsb_poly1305_clear(&ctx);
    return err;
}

kctsb_error_t kctsb_poly1305_verify(const uint8_t key[32], const uint8_t* data, size_t len, const uint8_t tag[16]) {
    uint8_t computed[16];
    kctsb_error_t err = kctsb_poly1305(key, data, len, computed);
    if (err != KCTSB_SUCCESS) return err;
    if (!kctsb_secure_compare(tag, computed, 16)) {
        kctsb_secure_zero(computed, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }
    kctsb_secure_zero(computed, 16);
    return KCTSB_SUCCESS;
}

void kctsb_poly1305_clear(kctsb_poly1305_ctx_t* ctx) {
    if (ctx) kctsb_secure_zero(ctx, sizeof(*ctx));
}

// ============================================================================
// ChaCha20-Poly1305 AEAD
// ============================================================================

static void pad16(kctsb_poly1305_ctx_t* ctx, size_t len) {
    if (len % 16 != 0) {
        uint8_t z[16] = {0};
        kctsb_poly1305_update(ctx, z, 16 - (len % 16));
    }
}

kctsb_error_t kctsb_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                                               const uint8_t* aad, size_t aad_len,
                                               const uint8_t* pt, size_t pt_len,
                                               uint8_t* ct, uint8_t tag[16]) {
    if (!key || !nonce || !ct || !tag) return KCTSB_ERROR_INVALID_PARAM;
    if (pt_len > 0 && !pt) return KCTSB_ERROR_INVALID_PARAM;

    // Initialize ChaCha20 context once, reuse for poly key and encryption
    kctsb_chacha20_ctx_t chacha_ctx;
    kctsb_chacha20_init(&chacha_ctx, key, nonce, 0);

    // Generate Poly1305 key from block 0
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20_crypt(&chacha_ctx, zeros, 64, poly_key);

    kctsb_poly1305_ctx_t poly_ctx;
    kctsb_poly1305_init(&poly_ctx, poly_key);
    kctsb_secure_zero(poly_key, 64);

    // Auth AAD
    if (aad && aad_len > 0) kctsb_poly1305_update(&poly_ctx, aad, aad_len);
    pad16(&poly_ctx, aad_len);

    // Encrypt (chacha_ctx already at counter 1 after 64 bytes)
    kctsb_chacha20_crypt(&chacha_ctx, pt, pt_len, ct);
    kctsb_chacha20_clear(&chacha_ctx);

    // Auth ciphertext
    kctsb_poly1305_update(&poly_ctx, ct, pt_len);
    pad16(&poly_ctx, pt_len);

    // Append lengths
    uint8_t len_block[16];
    store64_le(len_block, aad_len);
    store64_le(len_block + 8, pt_len);
    kctsb_poly1305_update(&poly_ctx, len_block, 16);
    kctsb_poly1305_final(&poly_ctx, tag);
    kctsb_poly1305_clear(&poly_ctx);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                                               const uint8_t* aad, size_t aad_len,
                                               const uint8_t* ct, size_t ct_len,
                                               const uint8_t tag[16], uint8_t* pt) {
    if (!key || !nonce || !tag || !pt) return KCTSB_ERROR_INVALID_PARAM;
    if (ct_len > 0 && !ct) return KCTSB_ERROR_INVALID_PARAM;

    // Initialize ChaCha20 context once
    kctsb_chacha20_ctx_t chacha_ctx;
    kctsb_chacha20_init(&chacha_ctx, key, nonce, 0);

    // Generate Poly1305 key from block 0
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20_crypt(&chacha_ctx, zeros, 64, poly_key);

    kctsb_poly1305_ctx_t poly_ctx;
    kctsb_poly1305_init(&poly_ctx, poly_key);
    kctsb_secure_zero(poly_key, 64);

    // Verify
    if (aad && aad_len > 0) kctsb_poly1305_update(&poly_ctx, aad, aad_len);
    pad16(&poly_ctx, aad_len);
    kctsb_poly1305_update(&poly_ctx, ct, ct_len);
    pad16(&poly_ctx, ct_len);

    uint8_t len_block[16];
    store64_le(len_block, aad_len);
    store64_le(len_block + 8, ct_len);
    kctsb_poly1305_update(&poly_ctx, len_block, 16);

    uint8_t computed[16];
    kctsb_poly1305_final(&poly_ctx, computed);
    kctsb_poly1305_clear(&poly_ctx);

    if (!kctsb_secure_compare(tag, computed, 16)) {
        kctsb_secure_zero(computed, 16);
        kctsb_chacha20_clear(&chacha_ctx);
        return KCTSB_ERROR_AUTH_FAILED;
    }
    kctsb_secure_zero(computed, 16);

    // Decrypt (chacha_ctx already at counter 1)
    kctsb_chacha20_crypt(&chacha_ctx, ct, ct_len, pt);
    kctsb_chacha20_clear(&chacha_ctx);
    return KCTSB_SUCCESS;
}

// Streaming API
kctsb_error_t kctsb_chacha20_poly1305_init_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                    const uint8_t key[32],
                                                    const uint8_t nonce[12]) {
    if (!ctx || !key || !nonce) return KCTSB_ERROR_INVALID_PARAM;
    memset(ctx, 0, sizeof(*ctx));

    uint8_t poly_key[64], zeros[64] = {0};
    kctsb_chacha20(key, nonce, 0, zeros, 64, poly_key);
    kctsb_poly1305_init(&ctx->poly_ctx, poly_key);
    kctsb_secure_zero(poly_key, 64);
    kctsb_chacha20_init(&ctx->chacha_ctx, key, nonce, 1);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_init_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                    const uint8_t key[32],
                                                    const uint8_t nonce[12]) {
    return kctsb_chacha20_poly1305_init_encrypt(ctx, key, nonce);
}

kctsb_error_t kctsb_chacha20_poly1305_update_aad(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                  const uint8_t* aad, size_t aad_len) {
    if (!ctx) return KCTSB_ERROR_INVALID_PARAM;
    if (ctx->aad_finalized || ctx->ct_len > 0) return KCTSB_ERROR_INVALID_PARAM;
    if (aad && aad_len > 0) {
        kctsb_poly1305_update(&ctx->poly_ctx, aad, aad_len);
        ctx->aad_len += aad_len;
    }
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_update_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                      const uint8_t* pt, size_t pt_len,
                                                      uint8_t* ct) {
    if (!ctx || !pt || !ct) return KCTSB_ERROR_INVALID_PARAM;
    if (!ctx->aad_finalized) {
        pad16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    kctsb_chacha20_crypt(&ctx->chacha_ctx, pt, pt_len, ct);
    kctsb_poly1305_update(&ctx->poly_ctx, ct, pt_len);
    ctx->ct_len += pt_len;
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_update_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                      const uint8_t* ct, size_t ct_len,
                                                      uint8_t* pt) {
    if (!ctx || !ct || !pt) return KCTSB_ERROR_INVALID_PARAM;
    if (!ctx->aad_finalized) {
        pad16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    kctsb_poly1305_update(&ctx->poly_ctx, ct, ct_len);
    ctx->ct_len += ct_len;
    kctsb_chacha20_crypt(&ctx->chacha_ctx, ct, ct_len, pt);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_final_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx, uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;
    if (!ctx->aad_finalized) {
        pad16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    pad16(&ctx->poly_ctx, ctx->ct_len);
    uint8_t len_block[16];
    store64_le(len_block, ctx->aad_len);
    store64_le(len_block + 8, ctx->ct_len);
    kctsb_poly1305_update(&ctx->poly_ctx, len_block, 16);
    kctsb_poly1305_final(&ctx->poly_ctx, tag);
    ctx->finalized = 1;
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_final_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx, const uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;
    if (!ctx->aad_finalized) {
        pad16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    pad16(&ctx->poly_ctx, ctx->ct_len);
    uint8_t len_block[16];
    store64_le(len_block, ctx->aad_len);
    store64_le(len_block + 8, ctx->ct_len);
    kctsb_poly1305_update(&ctx->poly_ctx, len_block, 16);
    
    uint8_t computed[16];
    kctsb_poly1305_final(&ctx->poly_ctx, computed);
    ctx->finalized = 1;
    
    if (!kctsb_secure_compare(tag, computed, 16)) {
        kctsb_secure_zero(computed, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }
    kctsb_secure_zero(computed, 16);
    return KCTSB_SUCCESS;
}

void kctsb_chacha20_poly1305_clear(kctsb_chacha20_poly1305_ctx_t* ctx) {
    if (ctx) {
        kctsb_chacha20_clear(&ctx->chacha_ctx);
        kctsb_poly1305_clear(&ctx->poly_ctx);
        kctsb_secure_zero(ctx, sizeof(*ctx));
    }
}

} // extern "C"

// ============================================================================
// C++ Wrapper
// ============================================================================

namespace kctsb {

ChaCha20Poly1305::ChaCha20Poly1305(const ByteVec& key) {
    if (key.size() != KEY_SIZE) throw std::invalid_argument("Key must be 32 bytes");
    memcpy(key_.data(), key.data(), KEY_SIZE);
}

ChaCha20Poly1305::ChaCha20Poly1305(const uint8_t key[32]) {
    if (!key) throw std::invalid_argument("Key cannot be null");
    memcpy(key_.data(), key, KEY_SIZE);
}

ChaCha20Poly1305::~ChaCha20Poly1305() { kctsb_secure_zero(key_.data(), KEY_SIZE); }

ChaCha20Poly1305::ChaCha20Poly1305(ChaCha20Poly1305&& o) noexcept : key_(o.key_) {
    kctsb_secure_zero(o.key_.data(), KEY_SIZE);
}

ChaCha20Poly1305& ChaCha20Poly1305::operator=(ChaCha20Poly1305&& o) noexcept {
    if (this != &o) {
        kctsb_secure_zero(key_.data(), KEY_SIZE);
        key_ = o.key_;
        kctsb_secure_zero(o.key_.data(), KEY_SIZE);
    }
    return *this;
}

std::pair<ByteVec, std::array<uint8_t, 16>> ChaCha20Poly1305::encrypt(
    const ByteVec& pt, const std::array<uint8_t, 12>& nonce, const ByteVec& aad) const {
    ByteVec ct(pt.size());
    std::array<uint8_t, 16> tag;
    kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
        key_.data(), nonce.data(), aad.empty() ? nullptr : aad.data(), aad.size(),
        pt.data(), pt.size(), ct.data(), tag.data());
    if (err != KCTSB_SUCCESS) throw std::runtime_error("Encryption failed");
    return {std::move(ct), tag};
}

ByteVec ChaCha20Poly1305::decrypt(const ByteVec& ct, const std::array<uint8_t, 12>& nonce,
                                   const std::array<uint8_t, 16>& tag, const ByteVec& aad) const {
    ByteVec pt(ct.size());
    kctsb_error_t err = kctsb_chacha20_poly1305_decrypt(
        key_.data(), nonce.data(), aad.empty() ? nullptr : aad.data(), aad.size(),
        ct.data(), ct.size(), tag.data(), pt.data());
    if (err == KCTSB_ERROR_AUTH_FAILED) throw std::runtime_error("Authentication failed");
    if (err != KCTSB_SUCCESS) throw std::runtime_error("Decryption failed");
    return pt;
}

std::array<uint8_t, 12> ChaCha20Poly1305::generateNonce() {
    std::array<uint8_t, 12> nonce;
    if (kctsb_random_bytes(nonce.data(), 12) != KCTSB_SUCCESS) throw std::runtime_error("RNG failed");
    return nonce;
}

ByteVec ChaCha20Poly1305::generateKey() {
    ByteVec key(KEY_SIZE);
    if (kctsb_random_bytes(key.data(), KEY_SIZE) != KCTSB_SUCCESS) throw std::runtime_error("RNG failed");
    return key;
}

} // namespace kctsb
