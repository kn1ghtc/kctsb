/**
 * @file chacha20_poly1305.cpp
 * @brief ChaCha20-Poly1305 AEAD Implementation (AVX2 Optimized)
 *
 * RFC 8439 compliant implementation with:
 * - ChaCha20 quarter-round based stream cipher (AVX2: 4-block parallel)
 * - Poly1305 polynomial MAC with 130-bit field (128-bit multiplication)
 * - Combined AEAD construction
 *
 * Optimization levels:
 * - AVX2: 4-block (256 bytes) parallel ChaCha20
 * - 128-bit arithmetic for Poly1305 multiplication
 *
 * Security features:
 * - Constant-time operations
 * - No table lookups with secret-dependent indices
 * - Secure memory cleanup
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
// Use GCC extension pragma to suppress pedantic warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
using uint128_t = unsigned __int128;
#pragma GCC diagnostic pop
#define KCTSB_HAS_UINT128 1
#endif

// ============================================================================
// ChaCha20 Implementation
// ============================================================================

/**
 * @brief ChaCha20 quarter round
 *
 * The core mixing function of ChaCha20
 */
static inline void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

/**
 * @brief Load 32-bit little-endian value
 */
static inline uint32_t load32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

/**
 * @brief Load 64-bit little-endian value
 */
static inline uint64_t load64_le(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
}

/**
 * @brief Store 32-bit little-endian value
 */
static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

/**
 * @brief Store 64-bit little-endian value
 */
static inline void store64_le(uint8_t* p, uint64_t v) {
    for (size_t i = 0; i < 8; i++) {
        p[i] = static_cast<uint8_t>(v >> (i * 8));
    }
}

/**
 * @brief Generate one ChaCha20 block
 *
 * @param state 16-word state (key, counter, nonce)
 * @param output 64-byte output block
 */
static void chacha20_block(const uint32_t state[16], uint8_t output[64]) {
    uint32_t working[16];

    // Copy state to working array
    for (int i = 0; i < 16; i++) {
        working[i] = state[i];
    }

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        chacha_quarter_round(working[0], working[4], working[8],  working[12]);
        chacha_quarter_round(working[1], working[5], working[9],  working[13]);
        chacha_quarter_round(working[2], working[6], working[10], working[14]);
        chacha_quarter_round(working[3], working[7], working[11], working[15]);

        // Diagonal rounds
        chacha_quarter_round(working[0], working[5], working[10], working[15]);
        chacha_quarter_round(working[1], working[6], working[11], working[12]);
        chacha_quarter_round(working[2], working[7], working[8],  working[13]);
        chacha_quarter_round(working[3], working[4], working[9],  working[14]);
    }

    // Add original state and serialize to output
    for (int i = 0; i < 16; i++) {
        uint32_t result = working[i] + state[i];
        store32_le(&output[i * 4], result);
    }

    kctsb_secure_zero(working, sizeof(working));
}

#ifdef KCTSB_HAS_AVX2
/**
 * @brief AVX2 ChaCha20 quarter round macro
 * Using shift/or for rotations (faster on most CPUs than shuffle)
 */
#define CHACHA_QR_AVX2(a, b, c, d) \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); \
    d = _mm256_or_si256(_mm256_slli_epi32(d, 16), _mm256_srli_epi32(d, 16)); \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); \
    b = _mm256_or_si256(_mm256_slli_epi32(b, 12), _mm256_srli_epi32(b, 20)); \
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); \
    d = _mm256_or_si256(_mm256_slli_epi32(d, 8), _mm256_srli_epi32(d, 24)); \
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); \
    b = _mm256_or_si256(_mm256_slli_epi32(b, 7), _mm256_srli_epi32(b, 25))

/**
 * @brief Generate 4 ChaCha20 blocks in parallel using AVX2 and XOR with input
 *
 * This optimized version generates keystream and XORs with input in one pass,
 * avoiding the memory-intensive transpose operation.
 *
 * @param state Base state (counter at position 12)
 * @param input Input buffer (256 bytes)
 * @param output Output buffer (256 bytes)
 */
static void chacha20_4block_xor_avx2(const uint32_t state[16], 
                                      const uint8_t input[256], 
                                      uint8_t output[256]) {
    // Load state into AVX2 registers (each lane = one block)
    __m256i row0 = _mm256_set1_epi32(static_cast<int32_t>(state[0]));
    __m256i row1 = _mm256_set1_epi32(static_cast<int32_t>(state[1]));
    __m256i row2 = _mm256_set1_epi32(static_cast<int32_t>(state[2]));
    __m256i row3 = _mm256_set1_epi32(static_cast<int32_t>(state[3]));
    __m256i row4 = _mm256_set1_epi32(static_cast<int32_t>(state[4]));
    __m256i row5 = _mm256_set1_epi32(static_cast<int32_t>(state[5]));
    __m256i row6 = _mm256_set1_epi32(static_cast<int32_t>(state[6]));
    __m256i row7 = _mm256_set1_epi32(static_cast<int32_t>(state[7]));
    __m256i row8 = _mm256_set1_epi32(static_cast<int32_t>(state[8]));
    __m256i row9 = _mm256_set1_epi32(static_cast<int32_t>(state[9]));
    __m256i row10 = _mm256_set1_epi32(static_cast<int32_t>(state[10]));
    __m256i row11 = _mm256_set1_epi32(static_cast<int32_t>(state[11]));
    // Counter: block 0,1,2,3 in first 128-bit lane, 4,5,6,7 in second
    __m256i row12 = _mm256_add_epi32(
        _mm256_set1_epi32(static_cast<int32_t>(state[12])),
        _mm256_setr_epi32(0, 1, 2, 3, 0, 1, 2, 3)
    );
    __m256i row13 = _mm256_set1_epi32(static_cast<int32_t>(state[13]));
    __m256i row14 = _mm256_set1_epi32(static_cast<int32_t>(state[14]));
    __m256i row15 = _mm256_set1_epi32(static_cast<int32_t>(state[15]));

    // Save original for final addition
    __m256i orig0 = row0, orig1 = row1, orig2 = row2, orig3 = row3;
    __m256i orig4 = row4, orig5 = row5, orig6 = row6, orig7 = row7;
    __m256i orig8 = row8, orig9 = row9, orig10 = row10, orig11 = row11;
    __m256i orig12 = row12, orig13 = row13, orig14 = row14, orig15 = row15;

    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        CHACHA_QR_AVX2(row0, row4, row8, row12);
        CHACHA_QR_AVX2(row1, row5, row9, row13);
        CHACHA_QR_AVX2(row2, row6, row10, row14);
        CHACHA_QR_AVX2(row3, row7, row11, row15);
        // Diagonal rounds
        CHACHA_QR_AVX2(row0, row5, row10, row15);
        CHACHA_QR_AVX2(row1, row6, row11, row12);
        CHACHA_QR_AVX2(row2, row7, row8, row13);
        CHACHA_QR_AVX2(row3, row4, row9, row14);
    }

    // Add original state
    row0 = _mm256_add_epi32(row0, orig0);
    row1 = _mm256_add_epi32(row1, orig1);
    row2 = _mm256_add_epi32(row2, orig2);
    row3 = _mm256_add_epi32(row3, orig3);
    row4 = _mm256_add_epi32(row4, orig4);
    row5 = _mm256_add_epi32(row5, orig5);
    row6 = _mm256_add_epi32(row6, orig6);
    row7 = _mm256_add_epi32(row7, orig7);
    row8 = _mm256_add_epi32(row8, orig8);
    row9 = _mm256_add_epi32(row9, orig9);
    row10 = _mm256_add_epi32(row10, orig10);
    row11 = _mm256_add_epi32(row11, orig11);
    row12 = _mm256_add_epi32(row12, orig12);
    row13 = _mm256_add_epi32(row13, orig13);
    row14 = _mm256_add_epi32(row14, orig14);
    row15 = _mm256_add_epi32(row15, orig15);

    // Fast in-register transpose and XOR
    // Each row register contains 8 uint32_t values from 8 blocks
    // We need block-interleaved output: block0[0..15], block1[0..15], etc.
    
    // Extract lower and upper 128-bit lanes, transpose 4x4 blocks
    // Block 0: row[0-15].lane0, Block 1: row[0-15].lane1, etc.
    
    // Use shuffle to create proper block order
    // Transpose 4x4 within each 128-bit lane using unpack instructions
    __m256i t0, t1, t2, t3;
    
    // Rows 0-3
    t0 = _mm256_unpacklo_epi32(row0, row1);  // 0a,1a,0b,1b | 0e,1e,0f,1f
    t1 = _mm256_unpackhi_epi32(row0, row1);  // 0c,1c,0d,1d | 0g,1g,0h,1h
    t2 = _mm256_unpacklo_epi32(row2, row3);  // 2a,3a,2b,3b | 2e,3e,2f,3f
    t3 = _mm256_unpackhi_epi32(row2, row3);  // 2c,3c,2d,3d | 2g,3g,2h,3h
    
    __m256i b0_03 = _mm256_unpacklo_epi64(t0, t2);  // 0a,1a,2a,3a | 0e,1e,2e,3e
    __m256i b1_03 = _mm256_unpackhi_epi64(t0, t2);  // 0b,1b,2b,3b | 0f,1f,2f,3f
    __m256i b2_03 = _mm256_unpacklo_epi64(t1, t3);  // 0c,1c,2c,3c | 0g,1g,2g,3g
    __m256i b3_03 = _mm256_unpackhi_epi64(t1, t3);  // 0d,1d,2d,3d | 0h,1h,2h,3h
    
    // Rows 4-7
    t0 = _mm256_unpacklo_epi32(row4, row5);
    t1 = _mm256_unpackhi_epi32(row4, row5);
    t2 = _mm256_unpacklo_epi32(row6, row7);
    t3 = _mm256_unpackhi_epi32(row6, row7);
    
    __m256i b0_47 = _mm256_unpacklo_epi64(t0, t2);
    __m256i b1_47 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b2_47 = _mm256_unpacklo_epi64(t1, t3);
    __m256i b3_47 = _mm256_unpackhi_epi64(t1, t3);
    
    // Rows 8-11
    t0 = _mm256_unpacklo_epi32(row8, row9);
    t1 = _mm256_unpackhi_epi32(row8, row9);
    t2 = _mm256_unpacklo_epi32(row10, row11);
    t3 = _mm256_unpackhi_epi32(row10, row11);
    
    __m256i b0_811 = _mm256_unpacklo_epi64(t0, t2);
    __m256i b1_811 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b2_811 = _mm256_unpacklo_epi64(t1, t3);
    __m256i b3_811 = _mm256_unpackhi_epi64(t1, t3);
    
    // Rows 12-15
    t0 = _mm256_unpacklo_epi32(row12, row13);
    t1 = _mm256_unpackhi_epi32(row12, row13);
    t2 = _mm256_unpacklo_epi32(row14, row15);
    t3 = _mm256_unpackhi_epi32(row14, row15);
    
    __m256i b0_1215 = _mm256_unpacklo_epi64(t0, t2);
    __m256i b1_1215 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b2_1215 = _mm256_unpacklo_epi64(t1, t3);
    __m256i b3_1215 = _mm256_unpackhi_epi64(t1, t3);
    
    // Now extract 128-bit halves to form complete blocks
    // Block 0: lower halves of b0_*, Block 1: upper halves of b0_*
    // Block 2: lower halves of b1_*, Block 3: upper halves of b1_*
    
    // Block 0 (words 0-15)
    __m128i blk0_a = _mm256_castsi256_si128(b0_03);
    __m128i blk0_b = _mm256_castsi256_si128(b0_47);
    __m128i blk0_c = _mm256_castsi256_si128(b0_811);
    __m128i blk0_d = _mm256_castsi256_si128(b0_1215);
    
    // Block 1
    __m128i blk1_a = _mm256_castsi256_si128(b1_03);
    __m128i blk1_b = _mm256_castsi256_si128(b1_47);
    __m128i blk1_c = _mm256_castsi256_si128(b1_811);
    __m128i blk1_d = _mm256_castsi256_si128(b1_1215);
    
    // Block 2
    __m128i blk2_a = _mm256_castsi256_si128(b2_03);
    __m128i blk2_b = _mm256_castsi256_si128(b2_47);
    __m128i blk2_c = _mm256_castsi256_si128(b2_811);
    __m128i blk2_d = _mm256_castsi256_si128(b2_1215);
    
    // Block 3
    __m128i blk3_a = _mm256_castsi256_si128(b3_03);
    __m128i blk3_b = _mm256_castsi256_si128(b3_47);
    __m128i blk3_c = _mm256_castsi256_si128(b3_811);
    __m128i blk3_d = _mm256_castsi256_si128(b3_1215);
    
    // Load input, XOR, store output - Block 0
    __m128i in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 0));
    __m128i in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 16));
    __m128i in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 32));
    __m128i in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 48));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 0), _mm_xor_si128(in0, blk0_a));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 16), _mm_xor_si128(in1, blk0_b));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 32), _mm_xor_si128(in2, blk0_c));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 48), _mm_xor_si128(in3, blk0_d));
    
    // Block 1
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 64));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 80));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 96));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 112));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 64), _mm_xor_si128(in0, blk1_a));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 80), _mm_xor_si128(in1, blk1_b));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 96), _mm_xor_si128(in2, blk1_c));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 112), _mm_xor_si128(in3, blk1_d));
    
    // Block 2
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 128));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 144));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 160));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 176));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 128), _mm_xor_si128(in0, blk2_a));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 144), _mm_xor_si128(in1, blk2_b));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 160), _mm_xor_si128(in2, blk2_c));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 176), _mm_xor_si128(in3, blk2_d));
    
    // Block 3
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 192));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 208));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 224));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 240));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 192), _mm_xor_si128(in0, blk3_a));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 208), _mm_xor_si128(in1, blk3_b));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 224), _mm_xor_si128(in2, blk3_c));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 240), _mm_xor_si128(in3, blk3_d));
}

/**
 * @brief Generate 8 ChaCha20 blocks in parallel using AVX2 and XOR with input
 *
 * Uses two interleaved sets of AVX2 registers to process 8 blocks (512 bytes)
 * simultaneously for maximum throughput on large data.
 *
 * @param state Base state (counter at position 12)
 * @param input Input buffer (512 bytes)
 * @param output Output buffer (512 bytes)
 */
static void chacha20_8block_xor_avx2(const uint32_t state[16], 
                                      const uint8_t input[512], 
                                      uint8_t output[512]) {
    // Process blocks 0-3 and 4-7 in parallel using instruction-level parallelism
    
    // === Set A: Blocks 0-3 ===
    __m256i a_row0 = _mm256_set1_epi32(static_cast<int32_t>(state[0]));
    __m256i a_row1 = _mm256_set1_epi32(static_cast<int32_t>(state[1]));
    __m256i a_row2 = _mm256_set1_epi32(static_cast<int32_t>(state[2]));
    __m256i a_row3 = _mm256_set1_epi32(static_cast<int32_t>(state[3]));
    __m256i a_row4 = _mm256_set1_epi32(static_cast<int32_t>(state[4]));
    __m256i a_row5 = _mm256_set1_epi32(static_cast<int32_t>(state[5]));
    __m256i a_row6 = _mm256_set1_epi32(static_cast<int32_t>(state[6]));
    __m256i a_row7 = _mm256_set1_epi32(static_cast<int32_t>(state[7]));
    __m256i a_row8 = _mm256_set1_epi32(static_cast<int32_t>(state[8]));
    __m256i a_row9 = _mm256_set1_epi32(static_cast<int32_t>(state[9]));
    __m256i a_row10 = _mm256_set1_epi32(static_cast<int32_t>(state[10]));
    __m256i a_row11 = _mm256_set1_epi32(static_cast<int32_t>(state[11]));
    __m256i a_row12 = _mm256_add_epi32(
        _mm256_set1_epi32(static_cast<int32_t>(state[12])),
        _mm256_setr_epi32(0, 1, 2, 3, 0, 1, 2, 3)
    );
    __m256i a_row13 = _mm256_set1_epi32(static_cast<int32_t>(state[13]));
    __m256i a_row14 = _mm256_set1_epi32(static_cast<int32_t>(state[14]));
    __m256i a_row15 = _mm256_set1_epi32(static_cast<int32_t>(state[15]));
    
    // === Set B: Blocks 4-7 ===
    __m256i b_row0 = a_row0, b_row1 = a_row1, b_row2 = a_row2, b_row3 = a_row3;
    __m256i b_row4 = a_row4, b_row5 = a_row5, b_row6 = a_row6, b_row7 = a_row7;
    __m256i b_row8 = a_row8, b_row9 = a_row9, b_row10 = a_row10, b_row11 = a_row11;
    __m256i b_row12 = _mm256_add_epi32(
        _mm256_set1_epi32(static_cast<int32_t>(state[12])),
        _mm256_setr_epi32(4, 5, 6, 7, 4, 5, 6, 7)
    );
    __m256i b_row13 = a_row13, b_row14 = a_row14, b_row15 = a_row15;

    // Save originals
    __m256i a_orig0 = a_row0, a_orig1 = a_row1, a_orig2 = a_row2, a_orig3 = a_row3;
    __m256i a_orig4 = a_row4, a_orig5 = a_row5, a_orig6 = a_row6, a_orig7 = a_row7;
    __m256i a_orig8 = a_row8, a_orig9 = a_row9, a_orig10 = a_row10, a_orig11 = a_row11;
    __m256i a_orig12 = a_row12, a_orig13 = a_row13, a_orig14 = a_row14, a_orig15 = a_row15;
    
    __m256i b_orig0 = b_row0, b_orig1 = b_row1, b_orig2 = b_row2, b_orig3 = b_row3;
    __m256i b_orig4 = b_row4, b_orig5 = b_row5, b_orig6 = b_row6, b_orig7 = b_row7;
    __m256i b_orig8 = b_row8, b_orig9 = b_row9, b_orig10 = b_row10, b_orig11 = b_row11;
    __m256i b_orig12 = b_row12, b_orig13 = b_row13, b_orig14 = b_row14, b_orig15 = b_row15;

    // 20 rounds - interleave A and B operations for better ILP
    for (int i = 0; i < 10; i++) {
        // Column rounds - Set A
        CHACHA_QR_AVX2(a_row0, a_row4, a_row8, a_row12);
        CHACHA_QR_AVX2(a_row1, a_row5, a_row9, a_row13);
        // Column rounds - Set B (interleaved)
        CHACHA_QR_AVX2(b_row0, b_row4, b_row8, b_row12);
        CHACHA_QR_AVX2(b_row1, b_row5, b_row9, b_row13);
        
        CHACHA_QR_AVX2(a_row2, a_row6, a_row10, a_row14);
        CHACHA_QR_AVX2(a_row3, a_row7, a_row11, a_row15);
        CHACHA_QR_AVX2(b_row2, b_row6, b_row10, b_row14);
        CHACHA_QR_AVX2(b_row3, b_row7, b_row11, b_row15);
        
        // Diagonal rounds - Set A
        CHACHA_QR_AVX2(a_row0, a_row5, a_row10, a_row15);
        CHACHA_QR_AVX2(a_row1, a_row6, a_row11, a_row12);
        // Diagonal rounds - Set B (interleaved)
        CHACHA_QR_AVX2(b_row0, b_row5, b_row10, b_row15);
        CHACHA_QR_AVX2(b_row1, b_row6, b_row11, b_row12);
        
        CHACHA_QR_AVX2(a_row2, a_row7, a_row8, a_row13);
        CHACHA_QR_AVX2(a_row3, a_row4, a_row9, a_row14);
        CHACHA_QR_AVX2(b_row2, b_row7, b_row8, b_row13);
        CHACHA_QR_AVX2(b_row3, b_row4, b_row9, b_row14);
    }

    // Add original state - Set A
    a_row0 = _mm256_add_epi32(a_row0, a_orig0);
    a_row1 = _mm256_add_epi32(a_row1, a_orig1);
    a_row2 = _mm256_add_epi32(a_row2, a_orig2);
    a_row3 = _mm256_add_epi32(a_row3, a_orig3);
    a_row4 = _mm256_add_epi32(a_row4, a_orig4);
    a_row5 = _mm256_add_epi32(a_row5, a_orig5);
    a_row6 = _mm256_add_epi32(a_row6, a_orig6);
    a_row7 = _mm256_add_epi32(a_row7, a_orig7);
    a_row8 = _mm256_add_epi32(a_row8, a_orig8);
    a_row9 = _mm256_add_epi32(a_row9, a_orig9);
    a_row10 = _mm256_add_epi32(a_row10, a_orig10);
    a_row11 = _mm256_add_epi32(a_row11, a_orig11);
    a_row12 = _mm256_add_epi32(a_row12, a_orig12);
    a_row13 = _mm256_add_epi32(a_row13, a_orig13);
    a_row14 = _mm256_add_epi32(a_row14, a_orig14);
    a_row15 = _mm256_add_epi32(a_row15, a_orig15);
    
    // Add original state - Set B
    b_row0 = _mm256_add_epi32(b_row0, b_orig0);
    b_row1 = _mm256_add_epi32(b_row1, b_orig1);
    b_row2 = _mm256_add_epi32(b_row2, b_orig2);
    b_row3 = _mm256_add_epi32(b_row3, b_orig3);
    b_row4 = _mm256_add_epi32(b_row4, b_orig4);
    b_row5 = _mm256_add_epi32(b_row5, b_orig5);
    b_row6 = _mm256_add_epi32(b_row6, b_orig6);
    b_row7 = _mm256_add_epi32(b_row7, b_orig7);
    b_row8 = _mm256_add_epi32(b_row8, b_orig8);
    b_row9 = _mm256_add_epi32(b_row9, b_orig9);
    b_row10 = _mm256_add_epi32(b_row10, b_orig10);
    b_row11 = _mm256_add_epi32(b_row11, b_orig11);
    b_row12 = _mm256_add_epi32(b_row12, b_orig12);
    b_row13 = _mm256_add_epi32(b_row13, b_orig13);
    b_row14 = _mm256_add_epi32(b_row14, b_orig14);
    b_row15 = _mm256_add_epi32(b_row15, b_orig15);

    // === Transpose and XOR Set A (blocks 0-3) ===
    __m256i t0, t1, t2, t3;
    
    t0 = _mm256_unpacklo_epi32(a_row0, a_row1);
    t1 = _mm256_unpackhi_epi32(a_row0, a_row1);
    t2 = _mm256_unpacklo_epi32(a_row2, a_row3);
    t3 = _mm256_unpackhi_epi32(a_row2, a_row3);
    __m256i a_b0_03 = _mm256_unpacklo_epi64(t0, t2);
    __m256i a_b1_03 = _mm256_unpackhi_epi64(t0, t2);
    __m256i a_b2_03 = _mm256_unpacklo_epi64(t1, t3);
    __m256i a_b3_03 = _mm256_unpackhi_epi64(t1, t3);
    
    t0 = _mm256_unpacklo_epi32(a_row4, a_row5);
    t1 = _mm256_unpackhi_epi32(a_row4, a_row5);
    t2 = _mm256_unpacklo_epi32(a_row6, a_row7);
    t3 = _mm256_unpackhi_epi32(a_row6, a_row7);
    __m256i a_b0_47 = _mm256_unpacklo_epi64(t0, t2);
    __m256i a_b1_47 = _mm256_unpackhi_epi64(t0, t2);
    __m256i a_b2_47 = _mm256_unpacklo_epi64(t1, t3);
    __m256i a_b3_47 = _mm256_unpackhi_epi64(t1, t3);
    
    t0 = _mm256_unpacklo_epi32(a_row8, a_row9);
    t1 = _mm256_unpackhi_epi32(a_row8, a_row9);
    t2 = _mm256_unpacklo_epi32(a_row10, a_row11);
    t3 = _mm256_unpackhi_epi32(a_row10, a_row11);
    __m256i a_b0_811 = _mm256_unpacklo_epi64(t0, t2);
    __m256i a_b1_811 = _mm256_unpackhi_epi64(t0, t2);
    __m256i a_b2_811 = _mm256_unpacklo_epi64(t1, t3);
    __m256i a_b3_811 = _mm256_unpackhi_epi64(t1, t3);
    
    t0 = _mm256_unpacklo_epi32(a_row12, a_row13);
    t1 = _mm256_unpackhi_epi32(a_row12, a_row13);
    t2 = _mm256_unpacklo_epi32(a_row14, a_row15);
    t3 = _mm256_unpackhi_epi32(a_row14, a_row15);
    __m256i a_b0_1215 = _mm256_unpacklo_epi64(t0, t2);
    __m256i a_b1_1215 = _mm256_unpackhi_epi64(t0, t2);
    __m256i a_b2_1215 = _mm256_unpacklo_epi64(t1, t3);
    __m256i a_b3_1215 = _mm256_unpackhi_epi64(t1, t3);

    // XOR blocks 0-3
    __m128i in0, in1, in2, in3;
    
    // Block 0
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 0));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 16));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 32));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 48));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 0), _mm_xor_si128(in0, _mm256_castsi256_si128(a_b0_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 16), _mm_xor_si128(in1, _mm256_castsi256_si128(a_b0_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 32), _mm_xor_si128(in2, _mm256_castsi256_si128(a_b0_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 48), _mm_xor_si128(in3, _mm256_castsi256_si128(a_b0_1215)));
    
    // Block 1
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 64));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 80));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 96));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 112));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 64), _mm_xor_si128(in0, _mm256_castsi256_si128(a_b1_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 80), _mm_xor_si128(in1, _mm256_castsi256_si128(a_b1_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 96), _mm_xor_si128(in2, _mm256_castsi256_si128(a_b1_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 112), _mm_xor_si128(in3, _mm256_castsi256_si128(a_b1_1215)));
    
    // Block 2
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 128));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 144));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 160));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 176));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 128), _mm_xor_si128(in0, _mm256_castsi256_si128(a_b2_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 144), _mm_xor_si128(in1, _mm256_castsi256_si128(a_b2_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 160), _mm_xor_si128(in2, _mm256_castsi256_si128(a_b2_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 176), _mm_xor_si128(in3, _mm256_castsi256_si128(a_b2_1215)));
    
    // Block 3
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 192));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 208));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 224));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 240));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 192), _mm_xor_si128(in0, _mm256_castsi256_si128(a_b3_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 208), _mm_xor_si128(in1, _mm256_castsi256_si128(a_b3_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 224), _mm_xor_si128(in2, _mm256_castsi256_si128(a_b3_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 240), _mm_xor_si128(in3, _mm256_castsi256_si128(a_b3_1215)));

    // === Transpose and XOR Set B (blocks 4-7) ===
    t0 = _mm256_unpacklo_epi32(b_row0, b_row1);
    t1 = _mm256_unpackhi_epi32(b_row0, b_row1);
    t2 = _mm256_unpacklo_epi32(b_row2, b_row3);
    t3 = _mm256_unpackhi_epi32(b_row2, b_row3);
    __m256i b_b0_03 = _mm256_unpacklo_epi64(t0, t2);
    __m256i b_b1_03 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b_b2_03 = _mm256_unpacklo_epi64(t1, t3);
    __m256i b_b3_03 = _mm256_unpackhi_epi64(t1, t3);
    
    t0 = _mm256_unpacklo_epi32(b_row4, b_row5);
    t1 = _mm256_unpackhi_epi32(b_row4, b_row5);
    t2 = _mm256_unpacklo_epi32(b_row6, b_row7);
    t3 = _mm256_unpackhi_epi32(b_row6, b_row7);
    __m256i b_b0_47 = _mm256_unpacklo_epi64(t0, t2);
    __m256i b_b1_47 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b_b2_47 = _mm256_unpacklo_epi64(t1, t3);
    __m256i b_b3_47 = _mm256_unpackhi_epi64(t1, t3);
    
    t0 = _mm256_unpacklo_epi32(b_row8, b_row9);
    t1 = _mm256_unpackhi_epi32(b_row8, b_row9);
    t2 = _mm256_unpacklo_epi32(b_row10, b_row11);
    t3 = _mm256_unpackhi_epi32(b_row10, b_row11);
    __m256i b_b0_811 = _mm256_unpacklo_epi64(t0, t2);
    __m256i b_b1_811 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b_b2_811 = _mm256_unpacklo_epi64(t1, t3);
    __m256i b_b3_811 = _mm256_unpackhi_epi64(t1, t3);
    
    t0 = _mm256_unpacklo_epi32(b_row12, b_row13);
    t1 = _mm256_unpackhi_epi32(b_row12, b_row13);
    t2 = _mm256_unpacklo_epi32(b_row14, b_row15);
    t3 = _mm256_unpackhi_epi32(b_row14, b_row15);
    __m256i b_b0_1215 = _mm256_unpacklo_epi64(t0, t2);
    __m256i b_b1_1215 = _mm256_unpackhi_epi64(t0, t2);
    __m256i b_b2_1215 = _mm256_unpacklo_epi64(t1, t3);
    __m256i b_b3_1215 = _mm256_unpackhi_epi64(t1, t3);

    // XOR blocks 4-7
    // Block 4
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 256));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 272));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 288));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 304));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 256), _mm_xor_si128(in0, _mm256_castsi256_si128(b_b0_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 272), _mm_xor_si128(in1, _mm256_castsi256_si128(b_b0_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 288), _mm_xor_si128(in2, _mm256_castsi256_si128(b_b0_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 304), _mm_xor_si128(in3, _mm256_castsi256_si128(b_b0_1215)));
    
    // Block 5
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 320));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 336));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 352));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 368));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 320), _mm_xor_si128(in0, _mm256_castsi256_si128(b_b1_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 336), _mm_xor_si128(in1, _mm256_castsi256_si128(b_b1_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 352), _mm_xor_si128(in2, _mm256_castsi256_si128(b_b1_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 368), _mm_xor_si128(in3, _mm256_castsi256_si128(b_b1_1215)));
    
    // Block 6
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 384));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 400));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 416));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 432));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 384), _mm_xor_si128(in0, _mm256_castsi256_si128(b_b2_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 400), _mm_xor_si128(in1, _mm256_castsi256_si128(b_b2_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 416), _mm_xor_si128(in2, _mm256_castsi256_si128(b_b2_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 432), _mm_xor_si128(in3, _mm256_castsi256_si128(b_b2_1215)));
    
    // Block 7
    in0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 448));
    in1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 464));
    in2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 480));
    in3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + 496));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 448), _mm_xor_si128(in0, _mm256_castsi256_si128(b_b3_03)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 464), _mm_xor_si128(in1, _mm256_castsi256_si128(b_b3_47)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 480), _mm_xor_si128(in2, _mm256_castsi256_si128(b_b3_811)));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 496), _mm_xor_si128(in3, _mm256_castsi256_si128(b_b3_1215)));
}
#endif // KCTSB_HAS_AVX2

// ChaCha20 constants: "expand 32-byte k"
static const uint32_t CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

extern "C" {

kctsb_error_t kctsb_chacha20_init(kctsb_chacha20_ctx_t* ctx,
                                   const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   uint32_t counter) {
    if (!ctx || !key || !nonce) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Initialize state
    // Constants
    ctx->state[0] = CHACHA_CONSTANTS[0];
    ctx->state[1] = CHACHA_CONSTANTS[1];
    ctx->state[2] = CHACHA_CONSTANTS[2];
    ctx->state[3] = CHACHA_CONSTANTS[3];

    // Key (8 words)
    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = load32_le(&key[i * 4]);
    }

    // Counter (1 word)
    ctx->state[12] = counter;

    // Nonce (3 words)
    ctx->state[13] = load32_le(&nonce[0]);
    ctx->state[14] = load32_le(&nonce[4]);
    ctx->state[15] = load32_le(&nonce[8]);

    ctx->remaining = 0;

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_crypt(kctsb_chacha20_ctx_t* ctx,
                                    const uint8_t* input,
                                    size_t input_len,
                                    uint8_t* output) {
    if (!ctx || !input || !output) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    // Use any remaining keystream first
    if (ctx->remaining > 0) {
        size_t use = (input_len < ctx->remaining) ? input_len : ctx->remaining;
        size_t ks_offset = 64 - ctx->remaining;

        for (size_t i = 0; i < use; i++) {
            output[i] = input[i] ^ ctx->keystream[ks_offset + i];
        }

        ctx->remaining -= use;
        offset = use;
    }

#ifdef KCTSB_HAS_AVX2
    // Process 8 blocks (512 bytes) at a time with AVX2 for maximum throughput
    while (offset + 512 <= input_len) {
        chacha20_8block_xor_avx2(ctx->state, &input[offset], &output[offset]);
        ctx->state[12] += 8;  // Increment counter by 8
        offset += 512;
    }
    
    // Process remaining 4 blocks (256 bytes) if available
    while (offset + 256 <= input_len) {
        chacha20_4block_xor_avx2(ctx->state, &input[offset], &output[offset]);
        ctx->state[12] += 4;  // Increment counter by 4
        offset += 256;
    }
#endif

    // Process remaining full 64-byte blocks
    while (offset + 64 <= input_len) {
        chacha20_block(ctx->state, ctx->keystream);
        ctx->state[12]++;  // Increment counter

        for (size_t i = 0; i < 64; i++) {
            output[offset + i] = input[offset + i] ^ ctx->keystream[i];
        }

        offset += 64;
    }

    // Handle remaining bytes
    if (offset < input_len) {
        chacha20_block(ctx->state, ctx->keystream);
        ctx->state[12]++;

        size_t remaining = input_len - offset;
        for (size_t i = 0; i < remaining; i++) {
            output[offset + i] = input[offset + i] ^ ctx->keystream[i];
        }

        ctx->remaining = 64 - remaining;
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20(const uint8_t key[32],
                             const uint8_t nonce[12],
                             uint32_t counter,
                             const uint8_t* input,
                             size_t input_len,
                             uint8_t* output) {
    kctsb_chacha20_ctx_t ctx;
    kctsb_error_t err;

    err = kctsb_chacha20_init(&ctx, key, nonce, counter);
    if (err != KCTSB_SUCCESS) {
        return err;
    }

    err = kctsb_chacha20_crypt(&ctx, input, input_len, output);

    kctsb_chacha20_clear(&ctx);
    return err;
}

void kctsb_chacha20_clear(kctsb_chacha20_ctx_t* ctx) {
    if (ctx) {
        kctsb_secure_zero(ctx, sizeof(kctsb_chacha20_ctx_t));
    }
}

// ============================================================================
// Poly1305 Implementation
// ============================================================================

// Mask constants for radix-2^26
static constexpr uint32_t MASK26 = (1U << 26) - 1;

#ifdef KCTSB_HAS_UINT128
/**
 * @brief Multiply two values in radix-2^44 representation
 * 
 * Computes out = a * b mod (2^130 - 5) in radix-2^44
 * @param out Output (3 limbs)
 * @param a First operand (3 limbs)
 * @param b Second operand (3 limbs) 
 */
static void poly1305_mul_r44(uint64_t out[3], const uint64_t a[3], const uint64_t b[3]) {
    const uint64_t MASK44 = (1ULL << 44) - 1;
    const uint64_t MASK42 = (1ULL << 42) - 1;
    
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2];
    uint64_t b0 = b[0], b1 = b[1], b2 = b[2];
    
    // Pre-compute 5*b for reduction
    // In radix-2^44: 2^130 ≡ 5 (mod 2^130-5), so overflow wraps with factor 5
    uint64_t s1 = b1 * 5;
    uint64_t s2 = b2 * 5;
    
    // Schoolbook multiplication with modular reduction
    uint128_t d0 = static_cast<uint128_t>(a0) * b0 + 
                   static_cast<uint128_t>(a1) * s2 + 
                   static_cast<uint128_t>(a2) * s1;
    uint128_t d1 = static_cast<uint128_t>(a0) * b1 + 
                   static_cast<uint128_t>(a1) * b0 + 
                   static_cast<uint128_t>(a2) * s2;
    uint128_t d2 = static_cast<uint128_t>(a0) * b2 + 
                   static_cast<uint128_t>(a1) * b1 + 
                   static_cast<uint128_t>(a2) * b0;
    
    // Carry propagation
    uint64_t c;
    c = static_cast<uint64_t>(d0 >> 44);
    out[0] = static_cast<uint64_t>(d0) & MASK44;
    d1 += c;
    c = static_cast<uint64_t>(d1 >> 44);
    out[1] = static_cast<uint64_t>(d1) & MASK44;
    d2 += c;
    c = static_cast<uint64_t>(d2 >> 42);
    out[2] = static_cast<uint64_t>(d2) & MASK42;
    out[0] += c * 5;
    c = out[0] >> 44;
    out[0] &= MASK44;
    out[1] += c;
}
/**
 * @brief Process 4 blocks using parallel Horner method with delayed carry
 * 
 * Computes: h' = (h + m0)*r^4 + m1*r^3 + m2*r^2 + m3*r
 * 
 * Key optimization: All 5 multiplications are computed in parallel (no data dependency),
 * then accumulated together with only ONE carry propagation at the end.
 * This maximizes instruction-level parallelism (ILP).
 * 
 * @param ctx Poly1305 context with precomputed r^2, r^3, r^4
 * @param blocks 64 bytes (4 consecutive 16-byte blocks)
 */
static void poly1305_4blocks_128(kctsb_poly1305_ctx_t* ctx, const uint8_t blocks[64]) {
    const uint64_t MASK44 = (1ULL << 44) - 1;
    const uint64_t MASK42 = (1ULL << 42) - 1;
    
    // Load r powers (precomputed in init)
    // r^1
    uint64_t r10 = ctx->r44[0], r11 = ctx->r44[1], r12 = ctx->r44[2];
    uint64_t s11 = ctx->s44[1], s12 = ctx->s44[2];
    // r^2
    uint64_t r20 = ctx->r2_44[0], r21 = ctx->r2_44[1], r22 = ctx->r2_44[2];
    uint64_t s21 = ctx->s2_44[1], s22 = ctx->s2_44[2];
    // r^3
    uint64_t r30 = ctx->r3_44[0], r31 = ctx->r3_44[1], r32 = ctx->r3_44[2];
    uint64_t s31 = ctx->s3_44[1], s32 = ctx->s3_44[2];
    // r^4
    uint64_t r40 = ctx->r4_44[0], r41 = ctx->r4_44[1], r42 = ctx->r4_44[2];
    uint64_t s41 = ctx->s4_44[1], s42 = ctx->s4_44[2];
    
    // Load accumulator h
    uint64_t h0 = ctx->h44[0];
    uint64_t h1 = ctx->h44[1];
    uint64_t h2 = ctx->h44[2];
    
    // Load 4 message blocks and convert to radix-2^44
    uint64_t m0_0, m0_1, m0_2;  // m[0]
    uint64_t m1_0, m1_1, m1_2;  // m[1]
    uint64_t m2_0, m2_1, m2_2;  // m[2]
    uint64_t m3_0, m3_1, m3_2;  // m[3]
    
    #define LOAD_BLOCK_44(blk, m_0, m_1, m_2) do { \
        uint64_t t0 = load64_le(&(blk)[0]); \
        uint64_t t1 = load64_le(&(blk)[8]); \
        m_0 = t0 & MASK44; \
        m_1 = ((t0 >> 44) | (t1 << 20)) & MASK44; \
        m_2 = ((t1 >> 24) & MASK42) + (1ULL << 40); \
    } while(0)
    
    LOAD_BLOCK_44(&blocks[0], m0_0, m0_1, m0_2);
    LOAD_BLOCK_44(&blocks[16], m1_0, m1_1, m1_2);
    LOAD_BLOCK_44(&blocks[32], m2_0, m2_1, m2_2);
    LOAD_BLOCK_44(&blocks[48], m3_0, m3_1, m3_2);
    #undef LOAD_BLOCK_44
    
    // === Parallel computation: all 5 products computed independently ===
    // Product 0: (h + m0) * r^4
    uint64_t a0 = h0 + m0_0;
    uint64_t a1 = h1 + m0_1;
    uint64_t a2 = h2 + m0_2;
    
    uint128_t d0_0 = static_cast<uint128_t>(a0) * r40 + 
                     static_cast<uint128_t>(a1) * s42 + 
                     static_cast<uint128_t>(a2) * s41;
    uint128_t d0_1 = static_cast<uint128_t>(a0) * r41 + 
                     static_cast<uint128_t>(a1) * r40 + 
                     static_cast<uint128_t>(a2) * s42;
    uint128_t d0_2 = static_cast<uint128_t>(a0) * r42 + 
                     static_cast<uint128_t>(a1) * r41 + 
                     static_cast<uint128_t>(a2) * r40;
    
    // Product 1: m1 * r^3
    uint128_t d1_0 = static_cast<uint128_t>(m1_0) * r30 + 
                     static_cast<uint128_t>(m1_1) * s32 + 
                     static_cast<uint128_t>(m1_2) * s31;
    uint128_t d1_1 = static_cast<uint128_t>(m1_0) * r31 + 
                     static_cast<uint128_t>(m1_1) * r30 + 
                     static_cast<uint128_t>(m1_2) * s32;
    uint128_t d1_2 = static_cast<uint128_t>(m1_0) * r32 + 
                     static_cast<uint128_t>(m1_1) * r31 + 
                     static_cast<uint128_t>(m1_2) * r30;
    
    // Product 2: m2 * r^2
    uint128_t d2_0 = static_cast<uint128_t>(m2_0) * r20 + 
                     static_cast<uint128_t>(m2_1) * s22 + 
                     static_cast<uint128_t>(m2_2) * s21;
    uint128_t d2_1 = static_cast<uint128_t>(m2_0) * r21 + 
                     static_cast<uint128_t>(m2_1) * r20 + 
                     static_cast<uint128_t>(m2_2) * s22;
    uint128_t d2_2 = static_cast<uint128_t>(m2_0) * r22 + 
                     static_cast<uint128_t>(m2_1) * r21 + 
                     static_cast<uint128_t>(m2_2) * r20;
    
    // Product 3: m3 * r^1
    uint128_t d3_0 = static_cast<uint128_t>(m3_0) * r10 + 
                     static_cast<uint128_t>(m3_1) * s12 + 
                     static_cast<uint128_t>(m3_2) * s11;
    uint128_t d3_1 = static_cast<uint128_t>(m3_0) * r11 + 
                     static_cast<uint128_t>(m3_1) * r10 + 
                     static_cast<uint128_t>(m3_2) * s12;
    uint128_t d3_2 = static_cast<uint128_t>(m3_0) * r12 + 
                     static_cast<uint128_t>(m3_1) * r11 + 
                     static_cast<uint128_t>(m3_2) * r10;
    
    // === Accumulate all products ===
    uint128_t sum0 = d0_0 + d1_0 + d2_0 + d3_0;
    uint128_t sum1 = d0_1 + d1_1 + d2_1 + d3_1;
    uint128_t sum2 = d0_2 + d1_2 + d2_2 + d3_2;
    
    // === Single carry propagation ===
    uint64_t c;
    c = static_cast<uint64_t>(sum0 >> 44);
    h0 = static_cast<uint64_t>(sum0) & MASK44;
    sum1 += c;
    c = static_cast<uint64_t>(sum1 >> 44);
    h1 = static_cast<uint64_t>(sum1) & MASK44;
    sum2 += c;
    c = static_cast<uint64_t>(sum2 >> 42);
    h2 = static_cast<uint64_t>(sum2) & MASK42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= MASK44;
    h1 += c;
    
    // Store back
    ctx->h44[0] = h0;
    ctx->h44[1] = h1;
    ctx->h44[2] = h2;
}

/**
 * @brief Process 8 blocks using two rounds of parallel Horner method
 * 
 * Processes 8 consecutive 16-byte blocks by calling poly1305_4blocks_128 twice.
 * This leverages the parallel Horner optimization for both sets of 4 blocks.
 */
static void poly1305_8blocks_128(kctsb_poly1305_ctx_t* ctx, const uint8_t blocks[128]) {
    poly1305_4blocks_128(ctx, &blocks[0]);
    poly1305_4blocks_128(ctx, &blocks[64]);
}
#endif // KCTSB_HAS_UINT128

#ifdef KCTSB_HAS_AVX2
/**
 * @brief Multiply two values in radix-2^26 representation
 * 
 * Computes out = a * b mod (2^130 - 5) in radix-2^26
 * @param out Output (5 limbs)
 * @param a First operand (5 limbs)
 * @param b Second operand (5 limbs) 
 */
static void poly1305_mul_r26(uint32_t out[5], const uint32_t a[5], const uint32_t b[5]) {
    // Pre-compute 5*b for reduction
    uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4];
    uint64_t s1 = b1 * 5, s2 = b2 * 5, s3 = b3 * 5, s4 = b4 * 5;
    
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    
    // Schoolbook multiplication with modular reduction
    uint64_t d0 = a0*b0 + a1*s4 + a2*s3 + a3*s2 + a4*s1;
    uint64_t d1 = a0*b1 + a1*b0 + a2*s4 + a3*s3 + a4*s2;
    uint64_t d2 = a0*b2 + a1*b1 + a2*b0 + a3*s4 + a4*s3;
    uint64_t d3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + a4*s4;
    uint64_t d4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
    
    // Carry propagation
    uint64_t c;
    c = d0 >> 26; d1 += c; d0 &= MASK26;
    c = d1 >> 26; d2 += c; d1 &= MASK26;
    c = d2 >> 26; d3 += c; d2 &= MASK26;
    c = d3 >> 26; d4 += c; d3 &= MASK26;
    c = d4 >> 26; d0 += c * 5; d4 &= MASK26;
    c = d0 >> 26; d1 += c; d0 &= MASK26;
    
    out[0] = static_cast<uint32_t>(d0);
    out[1] = static_cast<uint32_t>(d1);
    out[2] = static_cast<uint32_t>(d2);
    out[3] = static_cast<uint32_t>(d3);
    out[4] = static_cast<uint32_t>(d4);
}

/**
 * @brief AVX2 SIMD vectorized Poly1305 (true 4-lane parallel)
 * 
 * Uses AVX2 _mm256_mul_epu32 to process 4 blocks truly in parallel.
 * Each lane handles one message block with its corresponding r power.
 */
static void poly1305_blocks_avx2_simd(kctsb_poly1305_ctx_t* ctx, const uint8_t blocks[64]) {
    // Load precomputed r powers into vectors
    // r_vec[i] = (r^4, r^3, r^2, r^1)[limb i] for each limb
    __m256i r_vec[5], s_vec[5];
    
    // Pack r^4, r^3, r^2, r^1 into vectors (one per limb)
    for (int limb = 0; limb < 5; limb++) {
        r_vec[limb] = _mm256_setr_epi32(
            static_cast<int32_t>(ctx->r4_26[limb]), static_cast<int32_t>(ctx->r3_26[limb]),
            static_cast<int32_t>(ctx->r2_26[limb]), static_cast<int32_t>(ctx->r26[limb]),
            0, 0, 0, 0  // Upper half unused in mul_epu32
        );
        // Pre-compute 5*r for modular reduction
        s_vec[limb] = _mm256_setr_epi32(
            static_cast<int32_t>(ctx->s4_26[limb]), static_cast<int32_t>(ctx->s3_26[limb]),
            static_cast<int32_t>(ctx->s2_26[limb]), static_cast<int32_t>(ctx->s1_26[limb]),
            0, 0, 0, 0
        );
    }
    
    // Load 4 message blocks and convert to radix-2^26
    __m256i m_vec[5];
    uint32_t m_arr[4][5];
    
    for (int i = 0; i < 4; i++) {
        const uint8_t* blk = &blocks[i * 16];
        uint32_t t0 = load32_le(&blk[0]);
        uint32_t t1 = load32_le(&blk[4]);
        uint32_t t2 = load32_le(&blk[8]);
        uint32_t t3 = load32_le(&blk[12]);
        
        m_arr[i][0] = t0 & MASK26;
        m_arr[i][1] = ((t0 >> 26) | (t1 << 6)) & MASK26;
        m_arr[i][2] = ((t1 >> 20) | (t2 << 12)) & MASK26;
        m_arr[i][3] = ((t2 >> 14) | (t3 << 18)) & MASK26;
        m_arr[i][4] = (t3 >> 8) | (1U << 24);
    }
    
    // Pack messages: m_vec[limb] = (m0[limb], m1[limb], m2[limb], m3[limb])
    for (int limb = 0; limb < 5; limb++) {
        m_vec[limb] = _mm256_setr_epi32(
            static_cast<int32_t>(m_arr[0][limb]), static_cast<int32_t>(m_arr[1][limb]),
            static_cast<int32_t>(m_arr[2][limb]), static_cast<int32_t>(m_arr[3][limb]),
            0, 0, 0, 0
        );
    }
    
    // Parallel multiplication: d = m * r (4 lanes, each with its own r power)
    // d0 = m0*r0 + m1*s4 + m2*s3 + m3*s2 + m4*s1
    __m256i d0 = _mm256_add_epi64(
        _mm256_add_epi64(
            _mm256_mul_epu32(m_vec[0], r_vec[0]),
            _mm256_mul_epu32(m_vec[1], s_vec[4])
        ),
        _mm256_add_epi64(
            _mm256_add_epi64(
                _mm256_mul_epu32(m_vec[2], s_vec[3]),
                _mm256_mul_epu32(m_vec[3], s_vec[2])
            ),
            _mm256_mul_epu32(m_vec[4], s_vec[1])
        )
    );
    
    __m256i d1 = _mm256_add_epi64(
        _mm256_add_epi64(
            _mm256_mul_epu32(m_vec[0], r_vec[1]),
            _mm256_mul_epu32(m_vec[1], r_vec[0])
        ),
        _mm256_add_epi64(
            _mm256_add_epi64(
                _mm256_mul_epu32(m_vec[2], s_vec[4]),
                _mm256_mul_epu32(m_vec[3], s_vec[3])
            ),
            _mm256_mul_epu32(m_vec[4], s_vec[2])
        )
    );
    
    __m256i d2 = _mm256_add_epi64(
        _mm256_add_epi64(
            _mm256_mul_epu32(m_vec[0], r_vec[2]),
            _mm256_mul_epu32(m_vec[1], r_vec[1])
        ),
        _mm256_add_epi64(
            _mm256_add_epi64(
                _mm256_mul_epu32(m_vec[2], r_vec[0]),
                _mm256_mul_epu32(m_vec[3], s_vec[4])
            ),
            _mm256_mul_epu32(m_vec[4], s_vec[3])
        )
    );
    
    __m256i d3 = _mm256_add_epi64(
        _mm256_add_epi64(
            _mm256_mul_epu32(m_vec[0], r_vec[3]),
            _mm256_mul_epu32(m_vec[1], r_vec[2])
        ),
        _mm256_add_epi64(
            _mm256_add_epi64(
                _mm256_mul_epu32(m_vec[2], r_vec[1]),
                _mm256_mul_epu32(m_vec[3], r_vec[0])
            ),
            _mm256_mul_epu32(m_vec[4], s_vec[4])
        )
    );
    
    __m256i d4 = _mm256_add_epi64(
        _mm256_add_epi64(
            _mm256_mul_epu32(m_vec[0], r_vec[4]),
            _mm256_mul_epu32(m_vec[1], r_vec[3])
        ),
        _mm256_add_epi64(
            _mm256_add_epi64(
                _mm256_mul_epu32(m_vec[2], r_vec[2]),
                _mm256_mul_epu32(m_vec[3], r_vec[1])
            ),
            _mm256_mul_epu32(m_vec[4], r_vec[0])
        )
    );
    
    // Extract and sum horizontally (reduce 4 lanes to single result)
    // Then add to accumulator and apply carry propagation
    
    // Sum all 4 lanes for each limb
    auto hsum = [](const __m256i& v) -> uint64_t {
        alignas(32) uint64_t arr[4];
        _mm256_store_si256(reinterpret_cast<__m256i*>(arr), v);
        return arr[0] + arr[1] + arr[2] + arr[3];
    };
    
    uint64_t sum0 = hsum(d0);
    uint64_t sum1 = hsum(d1);
    uint64_t sum2 = hsum(d2);
    uint64_t sum3 = hsum(d3);
    uint64_t sum4 = hsum(d4);
    
    // Add previous accumulator * r^4
    uint64_t h44_0 = ctx->h44[0];
    uint64_t h44_1 = ctx->h44[1];
    uint64_t h44_2 = ctx->h44[2];
    
    uint32_t h_prev[5];
    h_prev[0] = static_cast<uint32_t>(h44_0) & MASK26;
    h_prev[1] = static_cast<uint32_t>((h44_0 >> 26) | (h44_1 << 18)) & MASK26;
    h_prev[2] = static_cast<uint32_t>(h44_1 >> 8) & MASK26;
    h_prev[3] = static_cast<uint32_t>((h44_1 >> 34) | (h44_2 << 10)) & MASK26;
    h_prev[4] = static_cast<uint32_t>(h44_2 >> 16);
    
    // h_prev * r^4
    uint32_t h_r4[5];
    poly1305_mul_r26(h_r4, h_prev, ctx->r4_26);
    
    // Add everything together
    sum0 += h_r4[0];
    sum1 += h_r4[1];
    sum2 += h_r4[2];
    sum3 += h_r4[3];
    sum4 += h_r4[4];
    
    // Carry propagation
    uint64_t c;
    c = sum0 >> 26; sum1 += c; sum0 &= MASK26;
    c = sum1 >> 26; sum2 += c; sum1 &= MASK26;
    c = sum2 >> 26; sum3 += c; sum2 &= MASK26;
    c = sum3 >> 26; sum4 += c; sum3 &= MASK26;
    c = sum4 >> 26; sum0 += c * 5; sum4 &= MASK26;
    c = sum0 >> 26; sum1 += c; sum0 &= MASK26;
    
    // Convert back to radix-2^44 and store
    const uint64_t MASK44 = (1ULL << 44) - 1;
    const uint64_t MASK42 = (1ULL << 42) - 1;
    
    ctx->h44[0] = (sum0 | (sum1 << 26)) & MASK44;
    ctx->h44[1] = ((sum1 >> 18) | (sum2 << 8) | (sum3 << 34)) & MASK44;
    ctx->h44[2] = ((sum3 >> 10) | (sum4 << 16)) & MASK42;
}
#endif // KCTSB_HAS_AVX2

#ifdef KCTSB_HAS_UINT128
/**
 * @brief Optimized Poly1305 block using 128-bit arithmetic
 *
 * Uses native 128-bit multiplication for better performance.
 * State is kept in radix-2^44 format (ctx->h44) to avoid conversion overhead.
 * Uses pre-computed r44[] and s44[] from context.
 */
static void poly1305_block_opt(kctsb_poly1305_ctx_t* ctx, const uint8_t block[16], int is_final_block) {
    // Load block as 64-bit little-endian
    uint64_t t0 = load64_le(&block[0]);
    uint64_t t1 = load64_le(&block[8]);

    // Mask for 44 bits and 42 bits
    const uint64_t MASK44 = (1ULL << 44) - 1;
    const uint64_t MASK42 = (1ULL << 42) - 1;

    // Use h44 directly (already in radix-2^44 format)
    uint64_t h0 = ctx->h44[0];
    uint64_t h1 = ctx->h44[1];
    uint64_t h2 = ctx->h44[2];

    // Add message block
    h0 += t0 & MASK44;
    h1 += ((t0 >> 44) | (t1 << 20)) & MASK44;
    h2 += (t1 >> 24) & MASK42;

    // Add padding bit
    if (!is_final_block) {
        h2 += (1ULL << 40);
    }

    // Use pre-computed r values (radix-2^44) from context
    uint64_t r0 = ctx->r44[0];
    uint64_t r1 = ctx->r44[1];
    uint64_t r2 = ctx->r44[2];
    uint64_t s1 = ctx->s44[1];
    uint64_t s2 = ctx->s44[2];

    // Multiplication using 128-bit arithmetic
    // d = h * r mod (2^130 - 5)
    uint128_t d0 = static_cast<uint128_t>(h0) * r0 + 
                   static_cast<uint128_t>(h1) * s2 + 
                   static_cast<uint128_t>(h2) * s1;
    uint128_t d1 = static_cast<uint128_t>(h0) * r1 + 
                   static_cast<uint128_t>(h1) * r0 + 
                   static_cast<uint128_t>(h2) * s2;
    uint128_t d2 = static_cast<uint128_t>(h0) * r2 + 
                   static_cast<uint128_t>(h1) * r1 + 
                   static_cast<uint128_t>(h2) * r0;

    // Carry propagation
    uint64_t c;
    c = static_cast<uint64_t>(d0 >> 44);
    h0 = static_cast<uint64_t>(d0) & MASK44;
    d1 += c;
    c = static_cast<uint64_t>(d1 >> 44);
    h1 = static_cast<uint64_t>(d1) & MASK44;
    d2 += c;
    c = static_cast<uint64_t>(d2 >> 42);
    h2 = static_cast<uint64_t>(d2) & MASK42;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= MASK44;
    h1 += c;

    // Store back to h44
    ctx->h44[0] = h0;
    ctx->h44[1] = h1;
    ctx->h44[2] = h2;
}
#endif // KCTSB_HAS_UINT128

/**
 * @brief Process one 16-byte block in Poly1305
 *
 * Uses 64-bit arithmetic for the 130-bit field multiplication
 */
static void poly1305_block(kctsb_poly1305_ctx_t* ctx, const uint8_t block[16], int is_final_block) {
#ifdef KCTSB_HAS_UINT128
    poly1305_block_opt(ctx, block, is_final_block);
#else
    // Load block as little-endian limbs
    uint32_t t0 = load32_le(&block[0]);
    uint32_t t1 = load32_le(&block[4]);
    uint32_t t2 = load32_le(&block[8]);
    uint32_t t3 = load32_le(&block[12]);

    // Add block to accumulator
    uint64_t h0 = ctx->h[0] + (t0 & 0x3ffffff);
    uint64_t h1 = ctx->h[1] + (((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
    uint64_t h2 = ctx->h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
    uint64_t h3 = ctx->h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
    uint64_t h4 = ctx->h[4] + (t3 >> 8);

    // Add padding bit (1 for non-final, 0 for final)
    if (!is_final_block) {
        h4 += (1ULL << 24);
    }

    // Multiply by r (mod 2^130 - 5)
    uint32_t r0 = ctx->r[0];
    uint32_t r1 = ctx->r[1];
    uint32_t r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3];
    uint32_t r4 = ctx->r[4];

    // Pre-compute 5*r for reduction
    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;

    // Multiplication with partial reduction
    uint64_t d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
    uint64_t d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
    uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
    uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
    uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

    // Carry propagation
    uint64_t c;
    c = d0 >> 26; d1 += c; d0 &= 0x3ffffff;
    c = d1 >> 26; d2 += c; d1 &= 0x3ffffff;
    c = d2 >> 26; d3 += c; d2 &= 0x3ffffff;
    c = d3 >> 26; d4 += c; d3 &= 0x3ffffff;
    c = d4 >> 26; d0 += c * 5; d4 &= 0x3ffffff;
    c = d0 >> 26; d1 += c; d0 &= 0x3ffffff;

    ctx->h[0] = (uint32_t)d0;
    ctx->h[1] = (uint32_t)d1;
    ctx->h[2] = (uint32_t)d2;
    ctx->h[3] = (uint32_t)d3;
    ctx->h[4] = (uint32_t)d4;
#endif // KCTSB_HAS_UINT128
}

kctsb_error_t kctsb_poly1305_init(kctsb_poly1305_ctx_t* ctx, const uint8_t key[32]) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(kctsb_poly1305_ctx_t));

    // Load and clamp r (first 16 bytes)
    uint32_t t0 = load32_le(&key[0]);
    uint32_t t1 = load32_le(&key[4]);
    uint32_t t2 = load32_le(&key[8]);
    uint32_t t3 = load32_le(&key[12]);

    // Clamp r: clear bits 4,8,12,13,14,15 of each 32-bit word
    ctx->r[0] = (t0) & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    ctx->r[4] = (t3 >> 8) & 0x00fffff;

    // Pre-compute r in radix-2^44 format for optimized block processing
    const uint64_t MASK44 = (1ULL << 44) - 1;
    const uint64_t MASK42 = (1ULL << 42) - 1;
    
    ctx->r44[0] = (static_cast<uint64_t>(ctx->r[0]) | 
                   (static_cast<uint64_t>(ctx->r[1]) << 26)) & MASK44;
    ctx->r44[1] = ((static_cast<uint64_t>(ctx->r[1]) >> 18) | 
                   (static_cast<uint64_t>(ctx->r[2]) << 8) |
                   (static_cast<uint64_t>(ctx->r[3]) << 34)) & MASK44;
    ctx->r44[2] = ((static_cast<uint64_t>(ctx->r[3]) >> 10) | 
                   (static_cast<uint64_t>(ctx->r[4]) << 16)) & MASK42;
    
    // Pre-compute 5*r for reduction (radix-2^44)
    ctx->s44[0] = 0;  // Not used in multiplication
    ctx->s44[1] = ctx->r44[1] * 5;
    ctx->s44[2] = ctx->r44[2] * 5;

#ifdef KCTSB_HAS_UINT128
    // === Pre-compute r powers for 128-bit parallel Horner method ===
    // r^2 = r * r
    poly1305_mul_r44(ctx->r2_44, ctx->r44, ctx->r44);
    // r^3 = r^2 * r
    poly1305_mul_r44(ctx->r3_44, ctx->r2_44, ctx->r44);
    // r^4 = r^2 * r^2
    poly1305_mul_r44(ctx->r4_44, ctx->r2_44, ctx->r2_44);
    
    // Pre-compute s values (5*r^k) for parallel Horner reduction
    for (int i = 0; i < 3; i++) {
        ctx->s2_44[i] = ctx->r2_44[i] * 5;
        ctx->s3_44[i] = ctx->r3_44[i] * 5;
        ctx->s4_44[i] = ctx->r4_44[i] * 5;
    }
#endif

#ifdef KCTSB_HAS_AVX2
    // === Pre-compute r powers for AVX2 vectorized processing ===
    // Store r^1 in radix-2^26 format
    for (int i = 0; i < 5; i++) {
        ctx->r26[i] = ctx->r[i];
    }
    
    // Compute r^2 = r * r
    poly1305_mul_r26(ctx->r2_26, ctx->r26, ctx->r26);
    
    // Compute r^3 = r^2 * r
    poly1305_mul_r26(ctx->r3_26, ctx->r2_26, ctx->r26);
    
    // Compute r^4 = r^2 * r^2
    poly1305_mul_r26(ctx->r4_26, ctx->r2_26, ctx->r2_26);
    
    // Pre-compute 5*r values for modular reduction
    // s[i] = 5 * r[i] (for i >= 1, used in reduction)
    for (int i = 0; i < 5; i++) {
        ctx->s1_26[i] = ctx->r26[i] * 5;
        ctx->s2_26[i] = ctx->r2_26[i] * 5;
        ctx->s3_26[i] = ctx->r3_26[i] * 5;
        ctx->s4_26[i] = ctx->r4_26[i] * 5;
    }
    
    ctx->use_avx2 = 1;  // Enable AVX2 path for Poly1305
#endif

    // Load s (last 16 bytes) - used for final addition
    ctx->s[0] = load32_le(&key[16]);
    ctx->s[1] = load32_le(&key[20]);
    ctx->s[2] = load32_le(&key[24]);
    ctx->s[3] = load32_le(&key[28]);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305_update(kctsb_poly1305_ctx_t* ctx,
                                     const uint8_t* data,
                                     size_t len) {
    if (!ctx) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (len == 0) {
        return KCTSB_SUCCESS;
    }
    if (!data) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    // Fill buffer if partial
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
    // === 128-bit Batch Processing: Process 8 blocks (128 bytes) at a time ===
    // Uses radix-2^44 format throughout, avoiding format conversion overhead
    while (offset + 128 <= len) {
        poly1305_8blocks_128(ctx, &data[offset]);
        offset += 128;
    }
    
    // Process remaining 4 blocks (64 bytes)
    while (offset + 64 <= len) {
        poly1305_4blocks_128(ctx, &data[offset]);
        offset += 64;
    }
#elif defined(KCTSB_HAS_AVX2)
    // === AVX2 Vectorized Path: Process 4 blocks (64 bytes) in parallel ===
    // Uses batched Horner method with precomputed r^2, r^3, r^4
    if (ctx->use_avx2) {
        // Process 8 blocks (128 bytes) using two rounds of 4-block vectorized processing
        while (offset + 128 <= len) {
            poly1305_blocks_avx2_simd(ctx, &data[offset]);
            poly1305_blocks_avx2_simd(ctx, &data[offset + 64]);
            offset += 128;
        }
        
        // Process remaining 4 blocks (64 bytes)
        while (offset + 64 <= len) {
            poly1305_blocks_avx2_simd(ctx, &data[offset]);
            offset += 64;
        }
    } else
#endif
    {
        // Scalar fallback: Process 8 blocks for cache efficiency
        while (offset + 128 <= len) {
            poly1305_block(ctx, &data[offset], 0);
            poly1305_block(ctx, &data[offset + 16], 0);
            poly1305_block(ctx, &data[offset + 32], 0);
            poly1305_block(ctx, &data[offset + 48], 0);
            poly1305_block(ctx, &data[offset + 64], 0);
            poly1305_block(ctx, &data[offset + 80], 0);
            poly1305_block(ctx, &data[offset + 96], 0);
            poly1305_block(ctx, &data[offset + 112], 0);
            offset += 128;
        }
        
        // Remaining 4 blocks
        while (offset + 64 <= len) {
            poly1305_block(ctx, &data[offset], 0);
            poly1305_block(ctx, &data[offset + 16], 0);
            poly1305_block(ctx, &data[offset + 32], 0);
            poly1305_block(ctx, &data[offset + 48], 0);
            offset += 64;
        }
    }

    // Process remaining full blocks (1-3 blocks, use scalar)
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
    if (!ctx || !tag) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Process final partial block
    if (ctx->buffer_len > 0) {
        // Pad with 1 followed by zeros
        ctx->buffer[ctx->buffer_len] = 1;
        for (size_t i = ctx->buffer_len + 1; i < 16; i++) {
            ctx->buffer[i] = 0;
        }
        poly1305_block(ctx, ctx->buffer, 1);
    }

#ifdef KCTSB_HAS_UINT128
    // Convert from radix-2^44 (h44) to radix-2^26 (h) for final processing
    uint64_t h44_0 = ctx->h44[0];
    uint64_t h44_1 = ctx->h44[1];
    uint64_t h44_2 = ctx->h44[2];
    
    ctx->h[0] = static_cast<uint32_t>(h44_0) & 0x3ffffff;
    ctx->h[1] = static_cast<uint32_t>((h44_0 >> 26) | (h44_1 << 18)) & 0x3ffffff;
    ctx->h[2] = static_cast<uint32_t>(h44_1 >> 8) & 0x3ffffff;
    ctx->h[3] = static_cast<uint32_t>((h44_1 >> 34) | (h44_2 << 10)) & 0x3ffffff;
    ctx->h[4] = static_cast<uint32_t>(h44_2 >> 16);
#endif

    // Final reduction modulo 2^130 - 5
    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];

    // Fully carry
    uint32_t c;
    c = h1 >> 26; h2 += c; h1 &= 0x3ffffff;
    c = h2 >> 26; h3 += c; h2 &= 0x3ffffff;
    c = h3 >> 26; h4 += c; h3 &= 0x3ffffff;
    c = h4 >> 26; h0 += c * 5; h4 &= 0x3ffffff;
    c = h0 >> 26; h1 += c; h0 &= 0x3ffffff;

    // Compute h - p (mod 2^130)
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);

    // Select h or g based on sign of h - p
    uint32_t mask = (g4 >> 31) - 1;  // 0 if h >= p, -1 if h < p
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // Convert to 128-bit value and add s
    uint64_t f0 = ((h0) | (h1 << 26)) + (uint64_t)ctx->s[0];
    uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + (uint64_t)ctx->s[1];
    uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + (uint64_t)ctx->s[2];
    uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + (uint64_t)ctx->s[3];

    // Carry propagation
    f1 += f0 >> 32;
    f2 += f1 >> 32;
    f3 += f2 >> 32;

    // Store result
    store32_le(&tag[0], (uint32_t)f0);
    store32_le(&tag[4], (uint32_t)f1);
    store32_le(&tag[8], (uint32_t)f2);
    store32_le(&tag[12], (uint32_t)f3);

    ctx->finalized = 1;

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305(const uint8_t key[32],
                              const uint8_t* data,
                              size_t len,
                              uint8_t tag[16]) {
    kctsb_poly1305_ctx_t ctx;
    kctsb_error_t err;

    err = kctsb_poly1305_init(&ctx, key);
    if (err != KCTSB_SUCCESS) {
        return err;
    }

    err = kctsb_poly1305_update(&ctx, data, len);
    if (err != KCTSB_SUCCESS) {
        kctsb_poly1305_clear(&ctx);
        return err;
    }

    err = kctsb_poly1305_final(&ctx, tag);
    kctsb_poly1305_clear(&ctx);

    return err;
}

kctsb_error_t kctsb_poly1305_verify(const uint8_t key[32],
                                     const uint8_t* data,
                                     size_t len,
                                     const uint8_t tag[16]) {
    uint8_t computed_tag[16];

    kctsb_error_t err = kctsb_poly1305(key, data, len, computed_tag);
    if (err != KCTSB_SUCCESS) {
        return err;
    }

    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(computed_tag, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    kctsb_secure_zero(computed_tag, 16);
    return KCTSB_SUCCESS;
}

void kctsb_poly1305_clear(kctsb_poly1305_ctx_t* ctx) {
    if (ctx) {
        kctsb_secure_zero(ctx, sizeof(kctsb_poly1305_ctx_t));
    }
}

// ============================================================================
// ChaCha20-Poly1305 AEAD
// ============================================================================

/**
 * @brief Pad to 16-byte boundary for Poly1305
 */
static void pad_to_16(kctsb_poly1305_ctx_t* ctx, size_t len) {
    if (len % 16 != 0) {
        uint8_t zeros[16] = {0};
        kctsb_poly1305_update(ctx, zeros, 16 - (len % 16));
    }
}

kctsb_error_t kctsb_chacha20_poly1305_encrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const uint8_t* plaintext,
                                               size_t plaintext_len,
                                               uint8_t* ciphertext,
                                               uint8_t tag[16]) {
    if (!key || !nonce || !ciphertext || !tag) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (plaintext_len > 0 && !plaintext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Initialize ChaCha20 context once
    kctsb_chacha20_ctx_t chacha_ctx;
    kctsb_chacha20_init(&chacha_ctx, key, nonce, 0);

    // Generate Poly1305 one-time key using ChaCha20 with counter 0
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20_crypt(&chacha_ctx, zeros, 64, poly_key);
    // Counter is now 1 after generating poly_key

    // Initialize Poly1305 with the generated key
    kctsb_poly1305_ctx_t poly_ctx;
    kctsb_poly1305_init(&poly_ctx, poly_key);
    kctsb_secure_zero(poly_key, 64);

    // Process AAD
    if (aad && aad_len > 0) {
        kctsb_poly1305_update(&poly_ctx, aad, aad_len);
        pad_to_16(&poly_ctx, aad_len);
    }

    // Encrypt plaintext and update Poly1305 with ciphertext
    if (plaintext_len > 0) {
        // Use standard sequential processing for correctness
        // The internal functions are already optimized with batch processing
        kctsb_chacha20_crypt(&chacha_ctx, plaintext, plaintext_len, ciphertext);
        kctsb_poly1305_update(&poly_ctx, ciphertext, plaintext_len);
        pad_to_16(&poly_ctx, plaintext_len);
    }

    // Lengths (little-endian 64-bit)
    uint8_t len_block[16];
    store64_le(&len_block[0], aad_len);
    store64_le(&len_block[8], plaintext_len);
    kctsb_poly1305_update(&poly_ctx, len_block, 16);

    kctsb_poly1305_final(&poly_ctx, tag);

    // Cleanup
    kctsb_chacha20_clear(&chacha_ctx);
    kctsb_poly1305_clear(&poly_ctx);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_decrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const uint8_t* ciphertext,
                                               size_t ciphertext_len,
                                               const uint8_t tag[16],
                                               uint8_t* plaintext) {
    if (!key || !nonce || !tag || !plaintext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ciphertext_len > 0 && !ciphertext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Initialize ChaCha20 context once
    kctsb_chacha20_ctx_t chacha_ctx;
    kctsb_chacha20_init(&chacha_ctx, key, nonce, 0);

    // Generate Poly1305 one-time key
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20_crypt(&chacha_ctx, zeros, 64, poly_key);
    // Counter is now 1 after generating poly_key

    // Initialize Poly1305
    kctsb_poly1305_ctx_t poly_ctx;
    kctsb_poly1305_init(&poly_ctx, poly_key);
    kctsb_secure_zero(poly_key, 64);

    // Process AAD
    if (aad && aad_len > 0) {
        kctsb_poly1305_update(&poly_ctx, aad, aad_len);
        pad_to_16(&poly_ctx, aad_len);
    }

    // Process ciphertext for authentication
    if (ciphertext_len > 0) {
        kctsb_poly1305_update(&poly_ctx, ciphertext, ciphertext_len);
        pad_to_16(&poly_ctx, ciphertext_len);
    }

    // Lengths
    uint8_t len_block[16];
    store64_le(&len_block[0], aad_len);
    store64_le(&len_block[8], ciphertext_len);
    kctsb_poly1305_update(&poly_ctx, len_block, 16);

    uint8_t computed_tag[16];
    kctsb_poly1305_final(&poly_ctx, computed_tag);

    // Constant-time tag verification
    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(computed_tag, 16);
        kctsb_chacha20_clear(&chacha_ctx);
        kctsb_poly1305_clear(&poly_ctx);
        kctsb_secure_zero(plaintext, ciphertext_len);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    // Decrypt ciphertext using the same context (counter already at 1)
    if (ciphertext_len > 0) {
        kctsb_chacha20_crypt(&chacha_ctx, ciphertext, ciphertext_len, plaintext);
    }

    // Cleanup
    kctsb_secure_zero(computed_tag, 16);
    kctsb_chacha20_clear(&chacha_ctx);
    kctsb_poly1305_clear(&poly_ctx);

    return KCTSB_SUCCESS;
}

// Streaming API

kctsb_error_t kctsb_chacha20_poly1305_init_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                    const uint8_t key[32],
                                                    const uint8_t nonce[12]) {
    if (!ctx || !key || !nonce) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(kctsb_chacha20_poly1305_ctx_t));

    // Generate Poly1305 key
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20(key, nonce, 0, zeros, 64, poly_key);

    // Initialize Poly1305
    kctsb_poly1305_init(&ctx->poly_ctx, poly_key);
    kctsb_secure_zero(poly_key, 64);

    // Initialize ChaCha20 with counter 1
    kctsb_chacha20_init(&ctx->chacha_ctx, key, nonce, 1);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_init_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                    const uint8_t key[32],
                                                    const uint8_t nonce[12]) {
    // Same initialization as encrypt
    return kctsb_chacha20_poly1305_init_encrypt(ctx, key, nonce);
}

kctsb_error_t kctsb_chacha20_poly1305_update_aad(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                  const uint8_t* aad,
                                                  size_t aad_len) {
    if (!ctx) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ctx->aad_finalized || ctx->ct_len > 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    if (aad && aad_len > 0) {
        kctsb_poly1305_update(&ctx->poly_ctx, aad, aad_len);
        ctx->aad_len += aad_len;
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_update_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                      const uint8_t* plaintext,
                                                      size_t plaintext_len,
                                                      uint8_t* ciphertext) {
    if (!ctx || !plaintext || !ciphertext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Finalize AAD if not done
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }

    // Encrypt
    kctsb_chacha20_crypt(&ctx->chacha_ctx, plaintext, plaintext_len, ciphertext);

    // Update Poly1305 with ciphertext
    kctsb_poly1305_update(&ctx->poly_ctx, ciphertext, plaintext_len);
    ctx->ct_len += plaintext_len;

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_update_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                      const uint8_t* ciphertext,
                                                      size_t ciphertext_len,
                                                      uint8_t* plaintext) {
    if (!ctx || !ciphertext || !plaintext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Finalize AAD if not done
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }

    // Update Poly1305 with ciphertext (before decryption)
    kctsb_poly1305_update(&ctx->poly_ctx, ciphertext, ciphertext_len);
    ctx->ct_len += ciphertext_len;

    // Decrypt
    kctsb_chacha20_crypt(&ctx->chacha_ctx, ciphertext, ciphertext_len, plaintext);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_final_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                     uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Finalize AAD if needed
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }

    // Pad ciphertext
    pad_to_16(&ctx->poly_ctx, ctx->ct_len);

    // Append lengths
    uint8_t len_block[16];
    store64_le(&len_block[0], ctx->aad_len);
    store64_le(&len_block[8], ctx->ct_len);
    kctsb_poly1305_update(&ctx->poly_ctx, len_block, 16);

    // Get tag
    kctsb_poly1305_final(&ctx->poly_ctx, tag);
    ctx->finalized = 1;

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_final_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                     const uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Finalize AAD if needed
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }

    // Pad ciphertext
    pad_to_16(&ctx->poly_ctx, ctx->ct_len);

    // Append lengths
    uint8_t len_block[16];
    store64_le(&len_block[0], ctx->aad_len);
    store64_le(&len_block[8], ctx->ct_len);
    kctsb_poly1305_update(&ctx->poly_ctx, len_block, 16);

    // Get computed tag
    uint8_t computed_tag[16];
    kctsb_poly1305_final(&ctx->poly_ctx, computed_tag);
    ctx->finalized = 1;

    // Verify
    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(computed_tag, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    kctsb_secure_zero(computed_tag, 16);
    return KCTSB_SUCCESS;
}

void kctsb_chacha20_poly1305_clear(kctsb_chacha20_poly1305_ctx_t* ctx) {
    if (ctx) {
        kctsb_chacha20_clear(&ctx->chacha_ctx);
        kctsb_poly1305_clear(&ctx->poly_ctx);
        kctsb_secure_zero(ctx, sizeof(kctsb_chacha20_poly1305_ctx_t));
    }
}

} // extern "C"

// ============================================================================
// C++ Implementation
// ============================================================================

namespace kctsb {

ChaCha20Poly1305::ChaCha20Poly1305(const ByteVec& key) {
    if (key.size() != KEY_SIZE) {
        throw std::invalid_argument("ChaCha20-Poly1305 requires 256-bit (32 byte) key");
    }
    memcpy(key_.data(), key.data(), KEY_SIZE);
}

ChaCha20Poly1305::ChaCha20Poly1305(const uint8_t key[32]) {
    if (!key) {
        throw std::invalid_argument("Key cannot be null");
    }
    memcpy(key_.data(), key, KEY_SIZE);
}

ChaCha20Poly1305::~ChaCha20Poly1305() {
    kctsb_secure_zero(key_.data(), KEY_SIZE);
}

ChaCha20Poly1305::ChaCha20Poly1305(ChaCha20Poly1305&& other) noexcept {
    key_ = other.key_;
    kctsb_secure_zero(other.key_.data(), KEY_SIZE);
}

ChaCha20Poly1305& ChaCha20Poly1305::operator=(ChaCha20Poly1305&& other) noexcept {
    if (this != &other) {
        kctsb_secure_zero(key_.data(), KEY_SIZE);
        key_ = other.key_;
        kctsb_secure_zero(other.key_.data(), KEY_SIZE);
    }
    return *this;
}

std::pair<ByteVec, std::array<uint8_t, 16>> ChaCha20Poly1305::encrypt(
    const ByteVec& plaintext,
    const std::array<uint8_t, 12>& nonce,
    const ByteVec& aad) const {

    ByteVec ciphertext(plaintext.size());
    std::array<uint8_t, 16> tag;

    kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
        key_.data(), nonce.data(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        plaintext.data(), plaintext.size(),
        ciphertext.data(), tag.data()
    );

    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
    }

    return {std::move(ciphertext), tag};
}

ByteVec ChaCha20Poly1305::decrypt(
    const ByteVec& ciphertext,
    const std::array<uint8_t, 12>& nonce,
    const std::array<uint8_t, 16>& tag,
    const ByteVec& aad) const {

    ByteVec plaintext(ciphertext.size());

    kctsb_error_t err = kctsb_chacha20_poly1305_decrypt(
        key_.data(), nonce.data(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        tag.data(), plaintext.data()
    );

    if (err == KCTSB_ERROR_AUTH_FAILED) {
        throw std::runtime_error("ChaCha20-Poly1305 authentication failed");
    }
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("ChaCha20-Poly1305 decryption failed");
    }

    return plaintext;
}

std::array<uint8_t, 12> ChaCha20Poly1305::generateNonce() {
    std::array<uint8_t, 12> nonce;
    if (kctsb_random_bytes(nonce.data(), 12) != KCTSB_SUCCESS) {
        throw std::runtime_error("Failed to generate random nonce");
    }
    return nonce;
}

ByteVec ChaCha20Poly1305::generateKey() {
    ByteVec key(KEY_SIZE);
    if (kctsb_random_bytes(key.data(), KEY_SIZE) != KCTSB_SUCCESS) {
        throw std::runtime_error("Failed to generate random key");
    }
    return key;
}

} // namespace kctsb
