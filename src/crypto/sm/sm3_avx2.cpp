/**
 * @file sm3_avx2.cpp
 * @brief SM3 AVX2 SIMD Acceleration
 * 
 * Parallel SM3 compression using AVX2 intrinsics.
 * Processes 4 message blocks simultaneously using 256-bit vectors.
 * 
 * Performance Target: 500 MB/s (vs 150 MB/s baseline)
 * 
 * Key Optimizations:
 * - 4-way parallel message expansion (_mm256_xor_si256)
 * - SIMD rotation using _mm256_or_si256 + shifts
 * - Interleaved round processing to hide latency
 * - 32-byte aligned data structures
 * 
 * Reference:
 * - GmSSL's sm3_compress_blocks_avx2
 * - Intel Optimization Manual (AVX2 vectorization)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/core/cpu_features.h"
#include <immintrin.h>  // AVX2 intrinsics
#include <cstring>
#include <array>

namespace kctsb {
namespace internal {

#if defined(__AVX2__)

// SM3 constants (shared with scalar version)
extern const std::array<uint32_t, 64> SM3_T_TABLE;
extern const std::array<uint32_t, 8> SM3_IV;

/**
 * @brief AVX2 rotate left for 256-bit vectors
 */
static inline __m256i mm256_rotl_epi32(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n)
    );
}

/**
 * @brief SM3 permutation P0 using AVX2
 */
static inline __m256i mm256_sm3_p0(__m256i x) {
    __m256i r9 = mm256_rotl_epi32(x, 9);
    __m256i r17 = mm256_rotl_epi32(x, 17);
    return _mm256_xor_si256(_mm256_xor_si256(x, r9), r17);
}

/**
 * @brief SM3 permutation P1 using AVX2
 */
static inline __m256i mm256_sm3_p1(__m256i x) {
    __m256i r15 = mm256_rotl_epi32(x, 15);
    __m256i r23 = mm256_rotl_epi32(x, 23);
    return _mm256_xor_si256(_mm256_xor_si256(x, r15), r23);
}

/**
 * @brief SM3 FF0 boolean function (rounds 0-15)
 */
static inline __m256i mm256_sm3_ff0(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

/**
 * @brief SM3 FF1 boolean function (rounds 16-63)
 */
static inline __m256i mm256_sm3_ff1(__m256i x, __m256i y, __m256i z) {
    __m256i xy = _mm256_and_si256(x, y);
    __m256i xz = _mm256_and_si256(x, z);
    __m256i yz = _mm256_and_si256(y, z);
    return _mm256_or_si256(_mm256_or_si256(xy, xz), yz);
}

/**
 * @brief SM3 GG0 boolean function (rounds 0-15)
 */
static inline __m256i mm256_sm3_gg0(__m256i x, __m256i y, __m256i z) {
    return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
}

/**
 * @brief SM3 GG1 boolean function (rounds 16-63)
 */
static inline __m256i mm256_sm3_gg1(__m256i x, __m256i y, __m256i z) {
    __m256i xy = _mm256_and_si256(x, y);
    __m256i not_x = _mm256_andnot_si256(x, _mm256_set1_epi32(-1));
    __m256i not_xz = _mm256_and_si256(not_x, z);
    return _mm256_or_si256(xy, not_xz);
}

/**
 * @brief AVX2-accelerated SM3 compression (4 blocks in parallel)
 * 
 * Processes 4x 64-byte blocks simultaneously using 256-bit SIMD.
 * 
 * @param state Input/output: 4 parallel digest states (32 uint32_t)
 * @param data Input: 4 blocks × 64 bytes = 256 bytes
 */
void sm3_compress_blocks_avx2(
    uint32_t state[8][4],  // 4 parallel states (interleaved for SIMD)
    const uint8_t* data,
    size_t num_blocks)
{
    // Process 4 blocks at a time
    for (size_t blk_idx = 0; blk_idx < num_blocks; blk_idx += 4) {
        // Aligned message expansion buffers (32-byte aligned)
        alignas(32) uint32_t W[68][4];   // 68 rounds × 4 lanes
        alignas(32) uint32_t W1[64][4];  // W' array
        
        // Load 4 blocks with byte swapping (big-endian)
        const __m256i bswap_mask = _mm256_set_epi8(
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
        );
        
        for (size_t i = 0; i < 16; i++) {
            // Load 4 words from 4 different blocks
            // Block 0: data[0..63], Block 1: data[64..127], etc.
            __m128i w0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + i * 4));
            __m128i w1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 64 + i * 4));
            __m128i w2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 128 + i * 4));
            __m128i w3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 192 + i * 4));
            
            // Interleave for SIMD processing
            __m256i w01 = _mm256_insertf128_si256(_mm256_castsi128_si256(w0), w1, 1);
            __m256i w23 = _mm256_insertf128_si256(_mm256_castsi128_si256(w2), w3, 1);
            
            // Byte swap
            w01 = _mm256_shuffle_epi8(w01, bswap_mask);
            w23 = _mm256_shuffle_epi8(w23, bswap_mask);
            
            _mm256_store_si256(reinterpret_cast<__m256i*>(&W[i][0]), w01);
            _mm256_store_si256(reinterpret_cast<__m256i*>(&W[i][2]), w23);
        }
        
        // Message expansion (W[16..67])
        for (size_t i = 16; i < 68; i++) {
            __m256i w_i_16 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[i - 16][0]));
            __m256i w_i_9 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[i - 9][0]));
            __m256i w_i_3 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[i - 3][0]));
            __m256i w_i_13 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[i - 13][0]));
            __m256i w_i_6 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[i - 6][0]));
            
            __m256i tmp = _mm256_xor_si256(w_i_16, w_i_9);
            tmp = _mm256_xor_si256(tmp, mm256_rotl_epi32(w_i_3, 15));
            tmp = mm256_sm3_p1(tmp);
            tmp = _mm256_xor_si256(tmp, mm256_rotl_epi32(w_i_13, 7));
            tmp = _mm256_xor_si256(tmp, w_i_6);
            
            _mm256_store_si256(reinterpret_cast<__m256i*>(&W[i][0]), tmp);
        }
        
        // Compute W'[0..63] = W[i] XOR W[i+4]
        for (size_t i = 0; i < 64; i++) {
            __m256i w_i = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[i][0]));
            __m256i w_i_4 = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[i + 4][0]));
            __m256i w1_i = _mm256_xor_si256(w_i, w_i_4);
            _mm256_store_si256(reinterpret_cast<__m256i*>(&W1[i][0]), w1_i);
        }
        
        // Load initial state
        __m256i A = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[0][0]));
        __m256i B = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[1][0]));
        __m256i C = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[2][0]));
        __m256i D = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[3][0]));
        __m256i E = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[4][0]));
        __m256i F = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[5][0]));
        __m256i G = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[6][0]));
        __m256i H = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[7][0]));
        
        // Compression function: 64 rounds
        for (size_t j = 0; j < 16; j++) {
            // Broadcast T constant to all lanes
            __m256i T_j = _mm256_set1_epi32(SM3_T_TABLE[j]);
            __m256i W_j = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[j][0]));
            __m256i W1_j = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W1[j][0]));
            
            // SS1 = ROTL(ROTL(A, 12) + E + T_j, 7)
            __m256i SS1 = mm256_rotl_epi32(A, 12);
            SS1 = _mm256_add_epi32(SS1, E);
            SS1 = _mm256_add_epi32(SS1, T_j);
            SS1 = mm256_rotl_epi32(SS1, 7);
            
            // SS2 = SS1 XOR ROTL(A, 12)
            __m256i SS2 = _mm256_xor_si256(SS1, mm256_rotl_epi32(A, 12));
            
            // TT1 = FF0(A, B, C) + D + SS2 + W1[j]
            __m256i TT1 = mm256_sm3_ff0(A, B, C);
            TT1 = _mm256_add_epi32(TT1, D);
            TT1 = _mm256_add_epi32(TT1, SS2);
            TT1 = _mm256_add_epi32(TT1, W1_j);
            
            // TT2 = GG0(E, F, G) + H + SS1 + W[j]
            __m256i TT2 = mm256_sm3_gg0(E, F, G);
            TT2 = _mm256_add_epi32(TT2, H);
            TT2 = _mm256_add_epi32(TT2, SS1);
            TT2 = _mm256_add_epi32(TT2, W_j);
            
            // Update state
            D = C;
            C = mm256_rotl_epi32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = mm256_rotl_epi32(F, 19);
            F = E;
            E = mm256_sm3_p0(TT2);
        }
        
        // Rounds 16-63 (FF1/GG1)
        for (size_t j = 16; j < 64; j++) {
            __m256i T_j = _mm256_set1_epi32(SM3_T_TABLE[j]);
            __m256i W_j = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W[j][0]));
            __m256i W1_j = _mm256_load_si256(reinterpret_cast<const __m256i*>(&W1[j][0]));
            
            __m256i SS1 = mm256_rotl_epi32(A, 12);
            SS1 = _mm256_add_epi32(SS1, E);
            SS1 = _mm256_add_epi32(SS1, T_j);
            SS1 = mm256_rotl_epi32(SS1, 7);
            
            __m256i SS2 = _mm256_xor_si256(SS1, mm256_rotl_epi32(A, 12));
            
            __m256i TT1 = mm256_sm3_ff1(A, B, C);  // FF1 for rounds 16-63
            TT1 = _mm256_add_epi32(TT1, D);
            TT1 = _mm256_add_epi32(TT1, SS2);
            TT1 = _mm256_add_epi32(TT1, W1_j);
            
            __m256i TT2 = mm256_sm3_gg1(E, F, G);  // GG1 for rounds 16-63
            TT2 = _mm256_add_epi32(TT2, H);
            TT2 = _mm256_add_epi32(TT2, SS1);
            TT2 = _mm256_add_epi32(TT2, W_j);
            
            D = C;
            C = mm256_rotl_epi32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = mm256_rotl_epi32(F, 19);
            F = E;
            E = mm256_sm3_p0(TT2);
        }
        
        // Update state (XOR with input)
        __m256i old_A = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[0][0]));
        __m256i old_B = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[1][0]));
        __m256i old_C = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[2][0]));
        __m256i old_D = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[3][0]));
        __m256i old_E = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[4][0]));
        __m256i old_F = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[5][0]));
        __m256i old_G = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[6][0]));
        __m256i old_H = _mm256_load_si256(reinterpret_cast<const __m256i*>(&state[7][0]));
        
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[0][0]), _mm256_xor_si256(A, old_A));
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[1][0]), _mm256_xor_si256(B, old_B));
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[2][0]), _mm256_xor_si256(C, old_C));
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[3][0]), _mm256_xor_si256(D, old_D));
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[4][0]), _mm256_xor_si256(E, old_E));
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[5][0]), _mm256_xor_si256(F, old_F));
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[6][0]), _mm256_xor_si256(G, old_G));
        _mm256_store_si256(reinterpret_cast<__m256i*>(&state[7][0]), _mm256_xor_si256(H, old_H));
        
        data += 256;  // Advance to next 4 blocks
    }
}

/**
 * @brief Runtime dispatcher: select AVX2 or scalar implementation
 * 
 * Called once during sm3_init() to detect CPU capabilities.
 */
static void (*sm3_compress_ptr)(kctsb_sm3_ctx_t*, const uint8_t*) = nullptr;

extern "C" void sm3_init_dispatch(kctsb_sm3_ctx_t* ctx) {
    if (sm3_compress_ptr == nullptr) {
        auto features = cpu::CPUFeatures::detect();
        
        if (features.has_avx2) {
            // Use AVX2 accelerated path
            // Note: We need a wrapper to convert single-block to 4-block interface
            // For now, fall back to scalar (TODO: implement batch interface)
        }
        
        // Fallback to scalar implementation
        extern void sm3_compress_scalar(kctsb_sm3_ctx_t*, const uint8_t*);
        sm3_compress_ptr = sm3_compress_scalar;
    }
}

#endif // __AVX2__

} // namespace internal
} // namespace kctsb
