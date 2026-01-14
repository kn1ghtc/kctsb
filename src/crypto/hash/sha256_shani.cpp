/**
 * @file sha256_shani.cpp
 * @brief SHA-256 hardware acceleration using Intel SHA-NI
 *
 * Implements SHA-256 using Intel SHA Extensions (SHA-NI) intrinsics:
 * - SHA256RNDS2: Two rounds of SHA-256 message schedule
 * - SHA256MSG1/MSG2: Message expansion
 *
 * Provides 2.5-3x speedup over software implementation on supported CPUs.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/sha.h"
#include "kctsb/core/common.h"
#include "kctsb/simd/simd.h"
#include <cstring>

// Platform-specific CPUID includes
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// SHA-NI availability detection
#if defined(__SHA__) || (defined(_MSC_VER) && defined(__AVX2__))
#define KCTSB_HAS_SHA_NI 1
#include <immintrin.h>
#else
#define KCTSB_HAS_SHA_NI 0
#endif

namespace kctsb {
namespace crypto {

// SHA-256 round constants (K)
static const uint32_t K256[64] = {
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

// SHA-256 initial hash values
static const uint32_t H256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/**
 * @brief Check if SHA-NI is available at runtime
 */
bool has_sha_ni() {
#if KCTSB_HAS_SHA_NI
#if defined(_MSC_VER)
    int info[4] = {0};
    __cpuid(info, 7);
    return (info[1] & (1 << 29)) != 0;  // SHA bit in EBX
#else
    unsigned int eax, ebx, ecx, edx;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1 << 29)) != 0;
#endif
#else
    return false;
#endif
}

#if KCTSB_HAS_SHA_NI

/**
 * @brief SHA-256 transform using SHA-NI intrinsics
 *
 * Processes a single 64-byte block using hardware acceleration.
 * This implementation follows Intel's SHA-NI Programming Guide.
 */
static void sha256_transform_shani(uint32_t state[8], const uint8_t block[64]) {
    // Load state (swapped for Intel byte ordering)
    __m128i STATE0 = _mm_loadu_si128((const __m128i*)&state[0]);
    __m128i STATE1 = _mm_loadu_si128((const __m128i*)&state[4]);

    // Rearrange state words for SHA-NI
    __m128i TMP = _mm_shuffle_epi32(STATE0, 0xB1);  // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);       // EFGH
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);       // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);    // CDGH

    // Save current state for later addition
    __m128i ABEF_SAVE = STATE0;
    __m128i CDGH_SAVE = STATE1;

    // Load message block (big-endian to little-endian conversion)
    __m128i MSG0 = _mm_shuffle_epi8(
        _mm_loadu_si128((const __m128i*)&block[0]),
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
    __m128i MSG1 = _mm_shuffle_epi8(
        _mm_loadu_si128((const __m128i*)&block[16]),
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
    __m128i MSG2 = _mm_shuffle_epi8(
        _mm_loadu_si128((const __m128i*)&block[32]),
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
    __m128i MSG3 = _mm_shuffle_epi8(
        _mm_loadu_si128((const __m128i*)&block[48]),
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));

    __m128i MSG, TMP0;

    // Rounds 0-3
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128((const __m128i*)&K256[0]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMP0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 4-7
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128((const __m128i*)&K256[4]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG2, MSG1, 4)), MSG3);
    TMP0 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 8-11
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128((const __m128i*)&K256[8]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG3, MSG2, 4)), MSG0);
    TMP0 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 12-15
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128((const __m128i*)&K256[12]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG0, MSG3, 4)), MSG1);
    TMP0 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 16-19
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128((const __m128i*)&K256[16]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG1, MSG0, 4)), MSG2);
    TMP0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 20-23
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128((const __m128i*)&K256[20]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG2, MSG1, 4)), MSG3);
    TMP0 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 24-27
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128((const __m128i*)&K256[24]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG3, MSG2, 4)), MSG0);
    TMP0 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 28-31
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128((const __m128i*)&K256[28]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG0, MSG3, 4)), MSG1);
    TMP0 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 32-35
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128((const __m128i*)&K256[32]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG1, MSG0, 4)), MSG2);
    TMP0 = _mm_sha256msg1_epu32(MSG0, MSG1);

    // Rounds 36-39
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128((const __m128i*)&K256[36]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG2, MSG1, 4)), MSG3);
    TMP0 = _mm_sha256msg1_epu32(MSG1, MSG2);

    // Rounds 40-43
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128((const __m128i*)&K256[40]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG3, MSG2, 4)), MSG0);
    TMP0 = _mm_sha256msg1_epu32(MSG2, MSG3);

    // Rounds 44-47
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128((const __m128i*)&K256[44]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG0, MSG3, 4)), MSG1);
    TMP0 = _mm_sha256msg1_epu32(MSG3, MSG0);

    // Rounds 48-51
    MSG = _mm_add_epi32(MSG0, _mm_loadu_si128((const __m128i*)&K256[48]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3 = _mm_sha256msg2_epu32(_mm_add_epi32(TMP0, _mm_alignr_epi8(MSG1, MSG0, 4)), MSG2);

    // Rounds 52-55
    MSG = _mm_add_epi32(MSG1, _mm_loadu_si128((const __m128i*)&K256[52]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 56-59
    MSG = _mm_add_epi32(MSG2, _mm_loadu_si128((const __m128i*)&K256[56]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 60-63
    MSG = _mm_add_epi32(MSG3, _mm_loadu_si128((const __m128i*)&K256[60]));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Add saved state
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    // Rearrange state for output
    TMP = _mm_shuffle_epi32(STATE0, 0x1B);  // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1); // DCHG
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // DCBA
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    // ABEF

    // Store state
    _mm_storeu_si128((__m128i*)&state[0], STATE0);
    _mm_storeu_si128((__m128i*)&state[4], STATE1);
}

#endif // KCTSB_HAS_SHA_NI

/**
 * @brief SHA-256 hash computation using SHA-NI when available
 *
 * Falls back to software implementation on unsupported CPUs.
 */
extern "C" kctsb_error_t kctsb_sha256_shani(const uint8_t* data, size_t len,
                                            uint8_t hash[32]) {
    if (!data || !hash) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

#if KCTSB_HAS_SHA_NI
    if (has_sha_ni()) {
        uint32_t state[8];
        memcpy(state, H256_INIT, sizeof(H256_INIT));

        // Process complete 64-byte blocks
        while (len >= 64) {
            sha256_transform_shani(state, data);
            data += 64;
            len -= 64;
        }

        // Handle padding and final block
        uint8_t final_block[128];
        memset(final_block, 0, 128);
        memcpy(final_block, data, len);
        final_block[len] = 0x80;

        size_t pad_len = (len < 56) ? 64 : 128;
        uint64_t bit_len = (uint64_t)(len + ((data - (const uint8_t*)0) % 64 == 0 ? 0 : 64)) * 8;
        
        // Big-endian length at end
        for (int i = 0; i < 8; i++) {
            final_block[pad_len - 1 - i] = (uint8_t)(bit_len >> (i * 8));
        }

        sha256_transform_shani(state, final_block);
        if (pad_len > 64) {
            sha256_transform_shani(state, final_block + 64);
        }

        // Output hash (big-endian)
        for (int i = 0; i < 8; i++) {
            hash[i * 4 + 0] = (uint8_t)(state[i] >> 24);
            hash[i * 4 + 1] = (uint8_t)(state[i] >> 16);
            hash[i * 4 + 2] = (uint8_t)(state[i] >> 8);
            hash[i * 4 + 3] = (uint8_t)(state[i]);
        }

        return KCTSB_SUCCESS;
    }
#endif

    // Fall back to software implementation
    kctsb_sha256(data, len, hash);
    return KCTSB_SUCCESS;
}

} // namespace crypto
} // namespace kctsb
