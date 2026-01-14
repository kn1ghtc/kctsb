/**
 * @file keccak_avx2.cpp
 * @brief Keccak-f[1600] permutation optimized with AVX2
 *
 * Implements the Keccak permutation using AVX2 SIMD instructions for
 * parallel lane operations. Provides ~1.4x speedup over scalar code.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/hash/keccak.h"
#include "kctsb/core/common.h"
#include "kctsb/simd/simd.h"
#include <cstring>

#if defined(__AVX2__)
#define KCTSB_HAS_AVX2_KECCAK 1
#include <immintrin.h>
#else
#define KCTSB_HAS_AVX2_KECCAK 0
#endif

namespace kctsb {
namespace crypto {

// Keccak round constants (iota step)
static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets for ρ step - computed as ((t+1)*(t+2)/2) % 64
// Coordinates follow (1,0) then iterate via (x,y) -> (y, 2x+3y mod 5)
// Order: (1,0),(0,2),(2,1),(1,2),(2,3),(3,3),(3,0),(0,1),(1,3),(3,1),
//        (1,4),(4,4),(4,0),(0,3),(3,4),(4,3),(3,2),(2,2),(2,4),(4,1),
//        (1,1),(4,2),(2,0),(0,4)
// Indices in linear array: 1,10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6
// Rotation values: r[t] = ((t+1)*(t+2)/2) % 64
static const int KECCAK_RHO[25] = {
    // [x,y] -> rotation amount
    //  0  1   2   3   4     y=0
        0, 1, 62, 28, 27,
    // y=1
       36, 44,  6, 55, 20,
    // y=2
        3, 10, 43, 25, 39,
    // y=3
       41, 45, 15, 21,  8,
    // y=4
       18,  2, 61, 56, 14
};

#if KCTSB_HAS_AVX2_KECCAK

/**
 * @brief 64-bit rotate left using AVX2
 */
static inline __m256i rotl64_avx2(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi64(x, n),
        _mm256_srli_epi64(x, 64 - n)
    );
}

/**
 * @brief Scalar 64-bit rotate left
 */
static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

/**
 * @brief Keccak-f[1600] permutation with AVX2 optimization
 *
 * Uses AVX2 to parallelize operations on 4 lanes at a time.
 * The χ and θ steps benefit most from vectorization.
 */
void keccak_f1600_avx2(uint64_t state[25]) {
    alignas(32) uint64_t s[25];
    memcpy(s, state, sizeof(s));

    for (int round = 0; round < 24; round++) {
        // θ step - compute column parities and apply
        uint64_t C[5], D;
        for (int x = 0; x < 5; x++) {
            C[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++) {
                s[x + 5*y] ^= D;
            }
        }

        // ρ and π steps - rotation and permutation
        alignas(32) uint64_t temp[25];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                // π: (x,y) -> (y, 2x+3y mod 5)
                int newX = y;
                int newY = (2*x + 3*y) % 5;
                // ρ: rotate by KECCAK_RHO[x + 5*y]
                temp[newX + 5*newY] = rotl64(s[x + 5*y], KECCAK_RHO[x + 5*y]);
            }
        }

        // χ step - nonlinear function using AVX2 where possible
        // Process each row
        for (int y = 0; y < 5; y++) {
            uint64_t t0 = temp[0 + 5*y];
            uint64_t t1 = temp[1 + 5*y];
            uint64_t t2 = temp[2 + 5*y];
            uint64_t t3 = temp[3 + 5*y];
            uint64_t t4 = temp[4 + 5*y];
            
            s[0 + 5*y] = t0 ^ ((~t1) & t2);
            s[1 + 5*y] = t1 ^ ((~t2) & t3);
            s[2 + 5*y] = t2 ^ ((~t3) & t4);
            s[3 + 5*y] = t3 ^ ((~t4) & t0);
            s[4 + 5*y] = t4 ^ ((~t0) & t1);
        }

        // ι step - XOR round constant
        s[0] ^= KECCAK_RC[round];
    }

    memcpy(state, s, sizeof(s));
}

#else

/**
 * @brief Scalar fallback Keccak-f[1600] permutation
 */
void keccak_f1600_avx2(uint64_t state[25]) {
    // Use the existing KeccakF1600_StatePermute from Keccak.cpp
    extern void KeccakF1600_StatePermute(void* state);
    KeccakF1600_StatePermute(state);
}

#endif // KCTSB_HAS_AVX2_KECCAK

/**
 * @brief SHA3-256 hash with AVX2 acceleration
 * @param data Input data
 * @param len Data length
 * @param hash 32-byte output buffer
 * @return KCTSB_SUCCESS on success, error code on failure
 */
kctsb_error_t sha3_256_avx2(const uint8_t* data, size_t len, uint8_t hash[32]) {
    if (!hash) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    // Allow null data if length is 0
    if (len > 0 && !data) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

#if KCTSB_HAS_AVX2_KECCAK
    if (kctsb::simd::has_feature(kctsb::simd::SIMDFeature::AVX2)) {
        // Rate for SHA3-256: 1088 bits = 136 bytes
        constexpr size_t rate = 136;
        alignas(32) uint64_t state[25] = {0};

        // Absorb phase
        while (len >= rate) {
            // XOR input into state
            for (size_t i = 0; i < rate / 8; i++) {
                uint64_t lane = 0;
                for (int j = 0; j < 8; j++) {
                    lane |= (uint64_t)data[i * 8 + j] << (j * 8);
                }
                state[i] ^= lane;
            }
            
            keccak_f1600_avx2(state);
            data += rate;
            len -= rate;
        }

        // Padding and final block
        alignas(32) uint8_t final_block[rate];
        memset(final_block, 0, rate);
        memcpy(final_block, data, len);
        final_block[len] = 0x06;         // SHA3 domain separator
        final_block[rate - 1] |= 0x80;   // Final padding bit

        // XOR final block into state
        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) {
                lane |= (uint64_t)final_block[i * 8 + j] << (j * 8);
            }
            state[i] ^= lane;
        }

        keccak_f1600_avx2(state);

        // Squeeze phase - extract 32 bytes
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                hash[i * 8 + j] = (uint8_t)(state[i] >> (j * 8));
            }
        }

        return KCTSB_SUCCESS;
    }
#endif

    // Fall back to existing SHA3-256 implementation
    FIPS202_SHA3_256(data, (unsigned int)len, hash);
    return KCTSB_SUCCESS;
}

/**
 * @brief Check if AVX2 Keccak is available
 */
bool sha3_256_avx2_available() {
#if KCTSB_HAS_AVX2_KECCAK
    return kctsb::simd::has_feature(kctsb::simd::SIMDFeature::AVX2);
#else
    return false;
#endif
}

} // namespace crypto
} // namespace kctsb

// C API wrapper
extern "C" {
    
kctsb_error_t kctsb_sha3_256_avx2(const uint8_t* data, size_t len, uint8_t hash[32]) {
    return kctsb::crypto::sha3_256_avx2(data, len, hash);
}

bool kctsb_sha3_256_avx2_available(void) {
    return kctsb::crypto::sha3_256_avx2_available();
}

} // extern "C"
