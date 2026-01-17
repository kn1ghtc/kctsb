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
    // Process 4 blocks (256 bytes) at a time with AVX2
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
    uint64_t t0 = static_cast<uint64_t>(load32_le(&block[0])) | 
                  (static_cast<uint64_t>(load32_le(&block[4])) << 32);
    uint64_t t1 = static_cast<uint64_t>(load32_le(&block[8])) | 
                  (static_cast<uint64_t>(load32_le(&block[12])) << 32);

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
    
    // Pre-compute 5*r for reduction
    ctx->s44[0] = 0;  // Not used in multiplication
    ctx->s44[1] = ctx->r44[1] * 5;
    ctx->s44[2] = ctx->r44[2] * 5;

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

    // Process full blocks - unroll loop for better performance
    while (offset + 64 <= len) {
        poly1305_block(ctx, &data[offset], 0);
        poly1305_block(ctx, &data[offset + 16], 0);
        poly1305_block(ctx, &data[offset + 32], 0);
        poly1305_block(ctx, &data[offset + 48], 0);
        offset += 64;
    }

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
