/**
 * @file simd.cpp
 * @brief SIMD Acceleration Implementation - AVX2/AVX-512/AES-NI
 *
 * Hardware-accelerated cryptographic primitives with runtime detection
 * and automatic fallback to scalar implementations.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/simd/simd.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

// SIMD intrinsics - must be included in correct order
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #if defined(__SSE2__) || defined(_M_X64) || defined(_M_AMD64)
        #include <emmintrin.h>  // SSE2
    #endif
    #if defined(__SSSE3__) || (defined(_MSC_VER) && _MSC_VER >= 1500)
        #include <tmmintrin.h>  // SSSE3 (_mm_shuffle_epi8)
    #endif
    #if defined(__SSE4_1__) || (defined(_MSC_VER) && _MSC_VER >= 1500)
        #include <smmintrin.h>  // SSE4.1
    #endif
    #if defined(__AES__) || defined(__PCLMUL__) || (defined(_MSC_VER) && defined(__AVX__))
        #include <wmmintrin.h>  // AES-NI, PCLMUL
    #endif
    #if defined(__AVX__)
        #include <immintrin.h>  // AVX, AVX2, AVX-512
    #endif
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <malloc.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace kctsb {
namespace simd {

// ============================================================================
// CPUID Detection
// ============================================================================

static void cpuid(int info[4], int function_id) {
#if defined(_MSC_VER)
    __cpuid(info, function_id);
#elif defined(__GNUC__) || defined(__clang__)
    __cpuid(function_id, info[0], info[1], info[2], info[3]);
#else
    info[0] = info[1] = info[2] = info[3] = 0;
#endif
}

static void cpuid_ex(int info[4], int function_id, int subfunction_id) {
#if defined(_MSC_VER)
    __cpuidex(info, function_id, subfunction_id);
#elif defined(__GNUC__) || defined(__clang__)
    __cpuid_count(function_id, subfunction_id, info[0], info[1], info[2], info[3]);
#else
    info[0] = info[1] = info[2] = info[3] = 0;
#endif
}

static uint32_t g_simd_features = 0;
static bool g_features_detected = false;

uint32_t detect_features() {
    if (g_features_detected) {
        return g_simd_features;
    }

    uint32_t features = 0;
    int info[4] = {0};

    // Get highest function ID
    cpuid(info, 0);
    int max_func = info[0];

    if (max_func >= 1) {
        cpuid(info, 1);

        // EDX features
        if (info[3] & (1 << 26)) features |= static_cast<uint32_t>(SIMDFeature::SSE2);

        // ECX features
        if (info[2] & (1 << 19)) features |= static_cast<uint32_t>(SIMDFeature::SSE41);
        if (info[2] & (1 << 28)) features |= static_cast<uint32_t>(SIMDFeature::AVX);
    }

    if (max_func >= 7) {
        cpuid_ex(info, 7, 0);

        // EBX features
        if (info[1] & (1 << 5)) features |= static_cast<uint32_t>(SIMDFeature::AVX2);
        if (info[1] & (1 << 16)) features |= static_cast<uint32_t>(SIMDFeature::AVX512F);
        if (info[1] & (1 << 31)) features |= static_cast<uint32_t>(SIMDFeature::AVX512VL);
        if (info[1] & (1 << 30)) features |= static_cast<uint32_t>(SIMDFeature::AVX512BW);
    }

#if defined(KCTSB_HAS_NEON)
    features |= static_cast<uint32_t>(SIMDFeature::NEON);
#endif

    g_simd_features = features;
    g_features_detected = true;

    return features;
}

bool has_feature(SIMDFeature feature) {
    return (detect_features() & static_cast<uint32_t>(feature)) != 0;
}

const char* get_simd_info() {
    static char info[256] = {0};

    if (info[0] == 0) {
        uint32_t features = detect_features();
        char* p = info;
        size_t remaining = sizeof(info);
        int written;

        written = snprintf(p, remaining, "SIMD: ");
        if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }

        if (features & static_cast<uint32_t>(SIMDFeature::AVX512F)) {
            written = snprintf(p, remaining, "AVX-512F ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }
        if (features & static_cast<uint32_t>(SIMDFeature::AVX512VL)) {
            written = snprintf(p, remaining, "AVX-512VL ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }
        if (features & static_cast<uint32_t>(SIMDFeature::AVX512BW)) {
            written = snprintf(p, remaining, "AVX-512BW ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }
        if (features & static_cast<uint32_t>(SIMDFeature::AVX2)) {
            written = snprintf(p, remaining, "AVX2 ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }
        if (features & static_cast<uint32_t>(SIMDFeature::AVX)) {
            written = snprintf(p, remaining, "AVX ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }
        if (features & static_cast<uint32_t>(SIMDFeature::SSE41)) {
            written = snprintf(p, remaining, "SSE4.1 ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }
        if (features & static_cast<uint32_t>(SIMDFeature::SSE2)) {
            written = snprintf(p, remaining, "SSE2 ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }
        if (features & static_cast<uint32_t>(SIMDFeature::NEON)) {
            written = snprintf(p, remaining, "NEON ");
            if (written > 0) { p += written; remaining -= static_cast<size_t>(written); }
        }

        if (features == 0) {
            snprintf(p, remaining, "None");
        }
    }

    return info;
}

// ============================================================================
// Memory Operations
// ============================================================================

void* aligned_alloc(size_t size, size_t alignment) {
#if defined(_MSC_VER) || defined(__MINGW32__)
    return _aligned_malloc(size, alignment);
#elif defined(__APPLE__)
    void* ptr = nullptr;
    posix_memalign(&ptr, alignment, size);
    return ptr;
#else
    void* ptr = nullptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return nullptr;
    }
    return ptr;
#endif
}

void aligned_free(void* ptr) {
#if defined(_MSC_VER) || defined(__MINGW32__)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

// ============================================================================
// XOR Operations
// ============================================================================

void xor_blocks(uint8_t* dst, const uint8_t* src, size_t len) {
#if defined(KCTSB_HAS_AVX512)
    if (has_feature(SIMDFeature::AVX512F)) {
        while (len >= 64) {
            __m512i a = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(dst));
            __m512i b = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(src));
            __m512i r = _mm512_xor_si512(a, b);
            _mm512_storeu_si512(reinterpret_cast<__m512i*>(dst), r);
            dst += 64;
            src += 64;
            len -= 64;
        }
    }
#endif

#if defined(KCTSB_HAS_AVX2)
    if (has_feature(SIMDFeature::AVX2)) {
        while (len >= 32) {
            __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(dst));
            __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src));
            __m256i r = _mm256_xor_si256(a, b);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst), r);
            dst += 32;
            src += 32;
            len -= 32;
        }
    }
#endif

#if defined(KCTSB_HAS_SSE2)
    if (has_feature(SIMDFeature::SSE2)) {
        while (len >= 16) {
            __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(dst));
            __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src));
            __m128i r = _mm_xor_si128(a, b);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(dst), r);
            dst += 16;
            src += 16;
            len -= 16;
        }
    }
#endif

    // Scalar fallback
    while (len >= 8) {
        uint64_t* d64 = reinterpret_cast<uint64_t*>(dst);
        const uint64_t* s64 = reinterpret_cast<const uint64_t*>(src);
        *d64 ^= *s64;
        dst += 8;
        src += 8;
        len -= 8;
    }

    while (len > 0) {
        *dst++ ^= *src++;
        --len;
    }
}

void xor_blocks_3way(uint8_t* dst, const uint8_t* a, const uint8_t* b, size_t len) {
#if defined(KCTSB_HAS_AVX2)
    if (has_feature(SIMDFeature::AVX2)) {
        while (len >= 32) {
            __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a));
            __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b));
            __m256i r = _mm256_xor_si256(va, vb);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst), r);
            dst += 32;
            a += 32;
            b += 32;
            len -= 32;
        }
    }
#endif

    while (len > 0) {
        *dst++ = *a++ ^ *b++;
        --len;
    }
}

// ============================================================================
// ChaCha20 SIMD
// ============================================================================

void chacha_quarter_round_simd(ChaChaState& state, int a, int b, int c, int d) {
    state.state[a] += state.state[b];
    state.state[d] ^= state.state[a];
    state.state[d] = rotl32(state.state[d], 16);

    state.state[c] += state.state[d];
    state.state[b] ^= state.state[c];
    state.state[b] = rotl32(state.state[b], 12);

    state.state[a] += state.state[b];
    state.state[d] ^= state.state[a];
    state.state[d] = rotl32(state.state[d], 8);

    state.state[c] += state.state[d];
    state.state[b] ^= state.state[c];
    state.state[b] = rotl32(state.state[b], 7);
}

void chacha20_block_simd(uint8_t output[64], const ChaChaState& input) {
    ChaChaState working = input;

#if defined(KCTSB_HAS_AVX2)
    if (has_feature(SIMDFeature::AVX2)) {
        // AVX2 vectorized double round
        __m256i row0 = _mm256_setr_epi32(
            static_cast<int32_t>(working.state[0]), static_cast<int32_t>(working.state[1]), static_cast<int32_t>(working.state[2]), static_cast<int32_t>(working.state[3]),
            static_cast<int32_t>(working.state[0]), static_cast<int32_t>(working.state[1]), static_cast<int32_t>(working.state[2]), static_cast<int32_t>(working.state[3])
        );
        __m256i row1 = _mm256_setr_epi32(
            static_cast<int32_t>(working.state[4]), static_cast<int32_t>(working.state[5]), static_cast<int32_t>(working.state[6]), static_cast<int32_t>(working.state[7]),
            static_cast<int32_t>(working.state[4]), static_cast<int32_t>(working.state[5]), static_cast<int32_t>(working.state[6]), static_cast<int32_t>(working.state[7])
        );
        __m256i row2 = _mm256_setr_epi32(
            static_cast<int32_t>(working.state[8]), static_cast<int32_t>(working.state[9]), static_cast<int32_t>(working.state[10]), static_cast<int32_t>(working.state[11]),
            static_cast<int32_t>(working.state[8]), static_cast<int32_t>(working.state[9]), static_cast<int32_t>(working.state[10]), static_cast<int32_t>(working.state[11])
        );
        __m256i row3 = _mm256_setr_epi32(
            static_cast<int32_t>(working.state[12]), static_cast<int32_t>(working.state[13]), static_cast<int32_t>(working.state[14]), static_cast<int32_t>(working.state[15]),
            static_cast<int32_t>(working.state[12]), static_cast<int32_t>(working.state[13]), static_cast<int32_t>(working.state[14]), static_cast<int32_t>(working.state[15])
        );

        // 10 double rounds
        for (int i = 0; i < 10; ++i) {
            // Column round
            row0 = _mm256_add_epi32(row0, row1);
            row3 = _mm256_xor_si256(row3, row0);
            row3 = _mm256_or_si256(_mm256_slli_epi32(row3, 16), _mm256_srli_epi32(row3, 16));

            row2 = _mm256_add_epi32(row2, row3);
            row1 = _mm256_xor_si256(row1, row2);
            row1 = _mm256_or_si256(_mm256_slli_epi32(row1, 12), _mm256_srli_epi32(row1, 20));

            row0 = _mm256_add_epi32(row0, row1);
            row3 = _mm256_xor_si256(row3, row0);
            row3 = _mm256_or_si256(_mm256_slli_epi32(row3, 8), _mm256_srli_epi32(row3, 24));

            row2 = _mm256_add_epi32(row2, row3);
            row1 = _mm256_xor_si256(row1, row2);
            row1 = _mm256_or_si256(_mm256_slli_epi32(row1, 7), _mm256_srli_epi32(row1, 25));

            // Diagonal shuffle
            row1 = _mm256_shuffle_epi32(row1, _MM_SHUFFLE(0, 3, 2, 1));
            row2 = _mm256_shuffle_epi32(row2, _MM_SHUFFLE(1, 0, 3, 2));
            row3 = _mm256_shuffle_epi32(row3, _MM_SHUFFLE(2, 1, 0, 3));

            // Diagonal round
            row0 = _mm256_add_epi32(row0, row1);
            row3 = _mm256_xor_si256(row3, row0);
            row3 = _mm256_or_si256(_mm256_slli_epi32(row3, 16), _mm256_srli_epi32(row3, 16));

            row2 = _mm256_add_epi32(row2, row3);
            row1 = _mm256_xor_si256(row1, row2);
            row1 = _mm256_or_si256(_mm256_slli_epi32(row1, 12), _mm256_srli_epi32(row1, 20));

            row0 = _mm256_add_epi32(row0, row1);
            row3 = _mm256_xor_si256(row3, row0);
            row3 = _mm256_or_si256(_mm256_slli_epi32(row3, 8), _mm256_srli_epi32(row3, 24));

            row2 = _mm256_add_epi32(row2, row3);
            row1 = _mm256_xor_si256(row1, row2);
            row1 = _mm256_or_si256(_mm256_slli_epi32(row1, 7), _mm256_srli_epi32(row1, 25));

            // Undo diagonal shuffle
            row1 = _mm256_shuffle_epi32(row1, _MM_SHUFFLE(2, 1, 0, 3));
            row2 = _mm256_shuffle_epi32(row2, _MM_SHUFFLE(1, 0, 3, 2));
            row3 = _mm256_shuffle_epi32(row3, _MM_SHUFFLE(0, 3, 2, 1));
        }

        // Extract results
        alignas(32) uint32_t tmp[8];
        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp), row0);
        for (int i = 0; i < 4; ++i) working.state[i] = tmp[i];

        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp), row1);
        for (int i = 0; i < 4; ++i) working.state[4+i] = tmp[i];

        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp), row2);
        for (int i = 0; i < 4; ++i) working.state[8+i] = tmp[i];

        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp), row3);
        for (int i = 0; i < 4; ++i) working.state[12+i] = tmp[i];
    } else
#endif
    {
        // Scalar fallback
        for (int i = 0; i < 10; ++i) {
            // Column rounds
            chacha_quarter_round_simd(working, 0, 4, 8, 12);
            chacha_quarter_round_simd(working, 1, 5, 9, 13);
            chacha_quarter_round_simd(working, 2, 6, 10, 14);
            chacha_quarter_round_simd(working, 3, 7, 11, 15);

            // Diagonal rounds
            chacha_quarter_round_simd(working, 0, 5, 10, 15);
            chacha_quarter_round_simd(working, 1, 6, 11, 12);
            chacha_quarter_round_simd(working, 2, 7, 8, 13);
            chacha_quarter_round_simd(working, 3, 4, 9, 14);
        }
    }

    // Add input state
    for (int i = 0; i < 16; ++i) {
        working.state[i] += input.state[i];
    }

    // Output
    for (int i = 0; i < 16; ++i) {
        store32_le(output + i * 4, working.state[i]);
    }
}

void chacha20_blocks_parallel(uint8_t* output, const ChaChaState& input, size_t num_blocks) {
    ChaChaState state = input;

    for (size_t i = 0; i < num_blocks; ++i) {
        chacha20_block_simd(output + i * 64, state);
        ++state.state[12];  // Increment counter
        if (state.state[12] == 0) {
            ++state.state[13];  // Handle overflow
        }
    }
}

// ============================================================================
// AES-NI Operations
// ============================================================================

bool has_aesni() {
#if defined(KCTSB_HAS_AESNI)
    int info[4] = {0};
    cpuid(info, 1);
    return (info[2] & (1 << 25)) != 0;  // Check AES bit
#else
    return false;
#endif
}

#if defined(KCTSB_HAS_AESNI)

// AES key expansion helper
static __m128i aes_key_expand_128(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

void aes128_expand_key_ni(const uint8_t key[16], uint8_t round_keys[176]) {
    __m128i* rk = reinterpret_cast<__m128i*>(round_keys);

    rk[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    rk[1] = aes_key_expand_128(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
    rk[2] = aes_key_expand_128(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
    rk[3] = aes_key_expand_128(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
    rk[4] = aes_key_expand_128(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
    rk[5] = aes_key_expand_128(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
    rk[6] = aes_key_expand_128(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
    rk[7] = aes_key_expand_128(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
    rk[8] = aes_key_expand_128(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
    rk[9] = aes_key_expand_128(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1b));
    rk[10] = aes_key_expand_128(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

void aes128_encrypt_block_ni(const uint8_t in[16], uint8_t out[16],
                              const uint8_t round_keys[176]) {
    const __m128i* rk = reinterpret_cast<const __m128i*>(round_keys);

    __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));

    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenclast_si128(block, rk[10]);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), block);
}

void aes128_ecb_encrypt_ni(const uint8_t* in, uint8_t* out,
                            size_t num_blocks, const uint8_t round_keys[176]) {
    const __m128i* rk = reinterpret_cast<const __m128i*>(round_keys);

    // Process 4 blocks in parallel
    while (num_blocks >= 4) {
        __m128i b0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
        __m128i b1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16));
        __m128i b2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 32));
        __m128i b3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 48));

        b0 = _mm_xor_si128(b0, rk[0]);
        b1 = _mm_xor_si128(b1, rk[0]);
        b2 = _mm_xor_si128(b2, rk[0]);
        b3 = _mm_xor_si128(b3, rk[0]);

        for (int i = 1; i < 10; ++i) {
            b0 = _mm_aesenc_si128(b0, rk[i]);
            b1 = _mm_aesenc_si128(b1, rk[i]);
            b2 = _mm_aesenc_si128(b2, rk[i]);
            b3 = _mm_aesenc_si128(b3, rk[i]);
        }

        b0 = _mm_aesenclast_si128(b0, rk[10]);
        b1 = _mm_aesenclast_si128(b1, rk[10]);
        b2 = _mm_aesenclast_si128(b2, rk[10]);
        b3 = _mm_aesenclast_si128(b3, rk[10]);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), b0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16), b1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32), b2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48), b3);

        in += 64;
        out += 64;
        num_blocks -= 4;
    }

    // Remaining blocks
    while (num_blocks > 0) {
        aes128_encrypt_block_ni(in, out, round_keys);
        in += 16;
        out += 16;
        --num_blocks;
    }
}

void aes128_ctr_ni(const uint8_t* in, uint8_t* out, size_t len,
                   const uint8_t round_keys[176], uint8_t nonce[16]) {
    const __m128i* rk = reinterpret_cast<const __m128i*>(round_keys);
    __m128i counter = _mm_loadu_si128(reinterpret_cast<const __m128i*>(nonce));
    __m128i one = _mm_set_epi64x(0, 1);

    while (len >= 16) {
        __m128i keystream = _mm_xor_si128(counter, rk[0]);

        for (int i = 1; i < 10; ++i) {
            keystream = _mm_aesenc_si128(keystream, rk[i]);
        }
        keystream = _mm_aesenclast_si128(keystream, rk[10]);

        __m128i plaintext = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
        __m128i ciphertext = _mm_xor_si128(plaintext, keystream);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), ciphertext);

        counter = _mm_add_epi64(counter, one);

        in += 16;
        out += 16;
        len -= 16;
    }

    // Handle remaining bytes
    if (len > 0) {
        __m128i keystream = _mm_xor_si128(counter, rk[0]);
        for (int i = 1; i < 10; ++i) {
            keystream = _mm_aesenc_si128(keystream, rk[i]);
        }
        keystream = _mm_aesenclast_si128(keystream, rk[10]);

        uint8_t ks[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ks), keystream);

        for (size_t i = 0; i < len; ++i) {
            out[i] = in[i] ^ ks[i];
        }
    }

    // Update nonce
    _mm_storeu_si128(reinterpret_cast<__m128i*>(nonce), counter);
}

// AES-256 key expansion helper
static __m128i aes_key_expand_256_1(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

static __m128i aes_key_expand_256_2(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(2, 2, 2, 2));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

void aes256_expand_key_ni(const uint8_t key[32], uint8_t round_keys[240]) {
    __m128i* rk = reinterpret_cast<__m128i*>(round_keys);

    rk[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    rk[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));

    rk[2] = aes_key_expand_256_1(rk[0], _mm_aeskeygenassist_si128(rk[1], 0x01));
    rk[3] = aes_key_expand_256_2(rk[1], _mm_aeskeygenassist_si128(rk[2], 0x00));
    rk[4] = aes_key_expand_256_1(rk[2], _mm_aeskeygenassist_si128(rk[3], 0x02));
    rk[5] = aes_key_expand_256_2(rk[3], _mm_aeskeygenassist_si128(rk[4], 0x00));
    rk[6] = aes_key_expand_256_1(rk[4], _mm_aeskeygenassist_si128(rk[5], 0x04));
    rk[7] = aes_key_expand_256_2(rk[5], _mm_aeskeygenassist_si128(rk[6], 0x00));
    rk[8] = aes_key_expand_256_1(rk[6], _mm_aeskeygenassist_si128(rk[7], 0x08));
    rk[9] = aes_key_expand_256_2(rk[7], _mm_aeskeygenassist_si128(rk[8], 0x00));
    rk[10] = aes_key_expand_256_1(rk[8], _mm_aeskeygenassist_si128(rk[9], 0x10));
    rk[11] = aes_key_expand_256_2(rk[9], _mm_aeskeygenassist_si128(rk[10], 0x00));
    rk[12] = aes_key_expand_256_1(rk[10], _mm_aeskeygenassist_si128(rk[11], 0x20));
    rk[13] = aes_key_expand_256_2(rk[11], _mm_aeskeygenassist_si128(rk[12], 0x00));
    rk[14] = aes_key_expand_256_1(rk[12], _mm_aeskeygenassist_si128(rk[13], 0x40));
}

void aes256_encrypt_block_ni(const uint8_t in[16], uint8_t out[16],
                              const uint8_t round_keys[240]) {
    const __m128i* rk = reinterpret_cast<const __m128i*>(round_keys);

    __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));

    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenc_si128(block, rk[10]);
    block = _mm_aesenc_si128(block, rk[11]);
    block = _mm_aesenc_si128(block, rk[12]);
    block = _mm_aesenc_si128(block, rk[13]);
    block = _mm_aesenclast_si128(block, rk[14]);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), block);
}

void aes256_ecb_encrypt_ni(const uint8_t* in, uint8_t* out,
                            size_t num_blocks, const uint8_t round_keys[240]) {
    const __m128i* rk = reinterpret_cast<const __m128i*>(round_keys);

    // Process 4 blocks in parallel for ILP
    while (num_blocks >= 4) {
        __m128i b0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
        __m128i b1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16));
        __m128i b2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 32));
        __m128i b3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 48));

        b0 = _mm_xor_si128(b0, rk[0]);
        b1 = _mm_xor_si128(b1, rk[0]);
        b2 = _mm_xor_si128(b2, rk[0]);
        b3 = _mm_xor_si128(b3, rk[0]);

        for (int i = 1; i < 14; ++i) {
            b0 = _mm_aesenc_si128(b0, rk[i]);
            b1 = _mm_aesenc_si128(b1, rk[i]);
            b2 = _mm_aesenc_si128(b2, rk[i]);
            b3 = _mm_aesenc_si128(b3, rk[i]);
        }

        b0 = _mm_aesenclast_si128(b0, rk[14]);
        b1 = _mm_aesenclast_si128(b1, rk[14]);
        b2 = _mm_aesenclast_si128(b2, rk[14]);
        b3 = _mm_aesenclast_si128(b3, rk[14]);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(out), b0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16), b1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32), b2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48), b3);

        in += 64;
        out += 64;
        num_blocks -= 4;
    }

    // Remaining blocks
    while (num_blocks > 0) {
        aes256_encrypt_block_ni(in, out, round_keys);
        in += 16;
        out += 16;
        --num_blocks;
    }
}

#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
// GHASH using PCLMUL for GCM mode
// Based on Intel's optimized carry-less multiplication approach

static inline __m128i gf128_reduce(__m128i H, __m128i X) {
    // Perform carry-less multiplication
    __m128i tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;

    tmp3 = _mm_clmulepi64_si128(H, X, 0x00);  // Low * Low
    tmp4 = _mm_clmulepi64_si128(H, X, 0x10);  // High * Low
    tmp5 = _mm_clmulepi64_si128(H, X, 0x01);  // Low * High
    tmp6 = _mm_clmulepi64_si128(H, X, 0x11);  // High * High

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);

    // Reduction polynomial for GF(2^128): x^128 + x^7 + x^2 + x + 1
    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp3, 30);
    tmp9 = _mm_srli_epi32(tmp3, 25);

    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);

    tmp8 = _mm_shuffle_epi32(tmp7, 0x93);
    tmp7 = _mm_and_si128(tmp8, _mm_set_epi32(0, static_cast<int32_t>(0xffffffff), static_cast<int32_t>(0xffffffff), static_cast<int32_t>(0xffffffff)));
    tmp8 = _mm_and_si128(tmp8, _mm_set_epi32(static_cast<int32_t>(0xffffffff), 0, 0, 0));

    tmp3 = _mm_xor_si128(tmp3, tmp7);
    tmp6 = _mm_xor_si128(tmp6, tmp8);

    tmp2 = _mm_slli_epi32(tmp3, 1);
    tmp4 = _mm_slli_epi32(tmp3, 2);
    tmp5 = _mm_slli_epi32(tmp3, 7);

    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp3);

    tmp7 = _mm_srli_si128(tmp2, 4);
    tmp2 = _mm_slli_si128(tmp2, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp2);

    tmp4 = _mm_srli_epi32(tmp3, 1);
    tmp5 = _mm_srli_epi32(tmp3, 2);
    tmp7 = _mm_xor_si128(tmp7, _mm_srli_epi32(tmp3, 7));

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp4 = _mm_xor_si128(tmp4, tmp7);
    tmp4 = _mm_xor_si128(tmp4, tmp3);

    tmp6 = _mm_xor_si128(tmp6, tmp4);

    return tmp6;
}

// ============================================================================
// Optimized Karatsuba GHASH Multiplication (Deferred Reduction)
// ============================================================================

/**
 * @brief Karatsuba carry-less multiplication WITHOUT reduction
 * Returns 256-bit product split into lo128/hi128
 * Reduction is deferred to amortize cost across multiple multiplications
 */
static inline void gf128_mul_karatsuba(
    __m128i H, __m128i X,
    __m128i& lo, __m128i& hi, __m128i& mid)
{
    // Karatsuba: (a*c, b*d, (a+b)*(c+d) - a*c - b*d)
    __m128i a = _mm_clmulepi64_si128(H, X, 0x00);  // H_lo * X_lo
    __m128i b = _mm_clmulepi64_si128(H, X, 0x11);  // H_hi * X_hi
    
    __m128i H_xor = _mm_xor_si128(H, _mm_shuffle_epi32(H, 0x4E)); // H_lo ^ H_hi
    __m128i X_xor = _mm_xor_si128(X, _mm_shuffle_epi32(X, 0x4E)); // X_lo ^ X_hi
    __m128i c = _mm_clmulepi64_si128(H_xor, X_xor, 0x00);
    
    lo = a;
    hi = b;
    mid = _mm_xor_si128(_mm_xor_si128(c, a), b);
}

/**
 * @brief Final reduction of accumulated 256-bit product
 */
static inline __m128i gf128_reduce_accumulated(__m128i lo, __m128i hi, __m128i mid) {
    // Combine mid into lo/hi
    __m128i mid_lo = _mm_slli_si128(mid, 8);
    __m128i mid_hi = _mm_srli_si128(mid, 8);
    lo = _mm_xor_si128(lo, mid_lo);
    hi = _mm_xor_si128(hi, mid_hi);
    
    // Reduction polynomial: x^128 + x^7 + x^2 + x + 1
    // Standard Barrett reduction
    __m128i tmp1 = _mm_srli_epi32(lo, 31);
    __m128i tmp2 = _mm_srli_epi32(lo, 30);
    __m128i tmp3 = _mm_srli_epi32(lo, 25);
    
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    
    __m128i tmp4 = _mm_shuffle_epi32(tmp1, 0x93);
    tmp1 = _mm_and_si128(tmp4, _mm_set_epi32(0, -1, -1, -1));
    tmp4 = _mm_and_si128(tmp4, _mm_set_epi32(-1, 0, 0, 0));
    
    lo = _mm_xor_si128(lo, tmp1);
    hi = _mm_xor_si128(hi, tmp4);
    
    __m128i tmp5 = _mm_slli_epi32(lo, 1);
    __m128i tmp6 = _mm_slli_epi32(lo, 2);
    __m128i tmp7 = _mm_slli_epi32(lo, 7);
    
    tmp5 = _mm_xor_si128(tmp5, tmp6);
    tmp5 = _mm_xor_si128(tmp5, tmp7);
    tmp5 = _mm_xor_si128(tmp5, lo);
    
    __m128i tmp8 = _mm_srli_si128(tmp5, 4);
    tmp5 = _mm_slli_si128(tmp5, 12);
    lo = _mm_xor_si128(lo, tmp5);
    
    __m128i tmp9 = _mm_srli_epi32(lo, 1);
    __m128i tmp10 = _mm_srli_epi32(lo, 2);
    tmp8 = _mm_xor_si128(tmp8, _mm_srli_epi32(lo, 7));
    
    tmp9 = _mm_xor_si128(tmp9, tmp10);
    tmp9 = _mm_xor_si128(tmp9, tmp8);
    tmp9 = _mm_xor_si128(tmp9, lo);
    
    return _mm_xor_si128(hi, tmp9);
}

void ghash_pclmul(uint8_t tag[16], const uint8_t h[16], const uint8_t* data, size_t len) {
    const __m128i bswap_mask = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);

    __m128i H = _mm_loadu_si128(reinterpret_cast<const __m128i*>(h));
    H = _mm_shuffle_epi8(H, bswap_mask);

    __m128i Y = _mm_loadu_si128(reinterpret_cast<const __m128i*>(tag));
    Y = _mm_shuffle_epi8(Y, bswap_mask);

    // Precompute H powers for 8-block parallelization: H^1 to H^8
    __m128i H2 = gf128_reduce(H, H);
    __m128i H3 = gf128_reduce(H2, H);
    __m128i H4 = gf128_reduce(H2, H2);
    __m128i H5 = gf128_reduce(H4, H);
    __m128i H6 = gf128_reduce(H3, H3);
    __m128i H7 = gf128_reduce(H6, H);
    __m128i H8 = gf128_reduce(H4, H4);

    // Process 8 blocks in parallel (128 bytes at a time) with deferred reduction
    while (len >= 128) {
        // Load 8 data blocks
        __m128i X0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data)), bswap_mask);
        __m128i X1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16)), bswap_mask);
        __m128i X2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 32)), bswap_mask);
        __m128i X3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 48)), bswap_mask);
        __m128i X4 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 64)), bswap_mask);
        __m128i X5 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 80)), bswap_mask);
        __m128i X6 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 96)), bswap_mask);
        __m128i X7 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 112)), bswap_mask);

        // XOR first block with running tag
        X0 = _mm_xor_si128(X0, Y);

        // Karatsuba multiplication with deferred reduction (8 parallel)
        __m128i lo0, hi0, mid0, lo1, hi1, mid1, lo2, hi2, mid2, lo3, hi3, mid3;
        __m128i lo4, hi4, mid4, lo5, hi5, mid5, lo6, hi6, mid6, lo7, hi7, mid7;

        gf128_mul_karatsuba(H8, X0, lo0, hi0, mid0);
        gf128_mul_karatsuba(H7, X1, lo1, hi1, mid1);
        gf128_mul_karatsuba(H6, X2, lo2, hi2, mid2);
        gf128_mul_karatsuba(H5, X3, lo3, hi3, mid3);
        gf128_mul_karatsuba(H4, X4, lo4, hi4, mid4);
        gf128_mul_karatsuba(H3, X5, lo5, hi5, mid5);
        gf128_mul_karatsuba(H2, X6, lo6, hi6, mid6);
        gf128_mul_karatsuba(H,  X7, lo7, hi7, mid7);

        // Accumulate all partial products
        __m128i lo_acc = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(lo0, lo1), _mm_xor_si128(lo2, lo3)),
                                        _mm_xor_si128(_mm_xor_si128(lo4, lo5), _mm_xor_si128(lo6, lo7)));
        __m128i hi_acc = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(hi0, hi1), _mm_xor_si128(hi2, hi3)),
                                        _mm_xor_si128(_mm_xor_si128(hi4, hi5), _mm_xor_si128(hi6, hi7)));
        __m128i mid_acc = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(mid0, mid1), _mm_xor_si128(mid2, mid3)),
                                         _mm_xor_si128(_mm_xor_si128(mid4, mid5), _mm_xor_si128(mid6, mid7)));

        // Single reduction for all 8 blocks
        Y = gf128_reduce_accumulated(lo_acc, hi_acc, mid_acc);

        data += 128;
        len -= 128;
    }

    // Process 4 blocks at a time
    while (len >= 64) {
        __m128i X0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data)), bswap_mask);
        __m128i X1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16)), bswap_mask);
        __m128i X2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 32)), bswap_mask);
        __m128i X3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 48)), bswap_mask);

        X0 = _mm_xor_si128(X0, Y);

        __m128i lo0, hi0, mid0, lo1, hi1, mid1, lo2, hi2, mid2, lo3, hi3, mid3;
        gf128_mul_karatsuba(H4, X0, lo0, hi0, mid0);
        gf128_mul_karatsuba(H3, X1, lo1, hi1, mid1);
        gf128_mul_karatsuba(H2, X2, lo2, hi2, mid2);
        gf128_mul_karatsuba(H,  X3, lo3, hi3, mid3);

        __m128i lo_acc = _mm_xor_si128(_mm_xor_si128(lo0, lo1), _mm_xor_si128(lo2, lo3));
        __m128i hi_acc = _mm_xor_si128(_mm_xor_si128(hi0, hi1), _mm_xor_si128(hi2, hi3));
        __m128i mid_acc = _mm_xor_si128(_mm_xor_si128(mid0, mid1), _mm_xor_si128(mid2, mid3));

        Y = gf128_reduce_accumulated(lo_acc, hi_acc, mid_acc);

        data += 64;
        len -= 64;
    }

    // Process remaining full blocks serially
    while (len >= 16) {
        __m128i X = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data)), bswap_mask);
        Y = _mm_xor_si128(Y, X);
        Y = gf128_reduce(H, Y);
        data += 16;
        len -= 16;
    }

    // Handle partial block
    if (len > 0) {
        uint8_t block[16] = {0};
        memcpy(block, data, len);
        __m128i X = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block)), bswap_mask);
        Y = _mm_xor_si128(Y, X);
        Y = gf128_reduce(H, Y);
    }

    Y = _mm_shuffle_epi8(Y, bswap_mask);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(tag), Y);
}
#endif // KCTSB_HAS_PCLMUL

#else

// Stubs when AES-NI not available
void aes128_expand_key_ni(const uint8_t key[16], uint8_t round_keys[176]) {
    (void)key; (void)round_keys;
}
void aes256_expand_key_ni(const uint8_t key[32], uint8_t round_keys[240]) {
    (void)key; (void)round_keys;
}
void aes128_encrypt_block_ni(const uint8_t in[16], uint8_t out[16],
                              const uint8_t round_keys[176]) {
    (void)in; (void)out; (void)round_keys;
}
void aes256_encrypt_block_ni(const uint8_t in[16], uint8_t out[16],
                              const uint8_t round_keys[240]) {
    (void)in; (void)out; (void)round_keys;
}
void aes128_ecb_encrypt_ni(const uint8_t* in, uint8_t* out,
                            size_t num_blocks, const uint8_t round_keys[176]) {
    (void)in; (void)out; (void)num_blocks; (void)round_keys;
}
void aes128_ctr_ni(const uint8_t* in, uint8_t* out, size_t len,
                   const uint8_t round_keys[176], uint8_t nonce[16]) {
    (void)in; (void)out; (void)len; (void)round_keys; (void)nonce;
}

#endif // KCTSB_HAS_AESNI

// ============================================================================
// Polynomial Operations
// ============================================================================

void poly_add_simd(uint32_t* result, const uint32_t* a, const uint32_t* b,
                   size_t n, uint32_t q) {
#if defined(KCTSB_HAS_AVX2)
    if (has_feature(SIMDFeature::AVX2) && n >= 8) {
        __m256i vq = _mm256_set1_epi32(static_cast<int32_t>(q));

        size_t i = 0;
        for (; i + 8 <= n; i += 8) {
            __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a + i));
            __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b + i));
            __m256i sum = _mm256_add_epi32(va, vb);

            // Conditional subtraction of q
            __m256i mask = _mm256_cmpgt_epi32(sum, vq);
            sum = _mm256_sub_epi32(sum, _mm256_and_si256(mask, vq));

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(result + i), sum);
        }

        // Handle remaining elements
        for (; i < n; ++i) {
            uint32_t sum = a[i] + b[i];
            result[i] = (sum >= q) ? (sum - q) : sum;
        }
        return;
    }
#endif

    // Scalar fallback
    for (size_t i = 0; i < n; ++i) {
        uint32_t sum = a[i] + b[i];
        result[i] = (sum >= q) ? (sum - q) : sum;
    }
}

void poly_sub_simd(uint32_t* result, const uint32_t* a, const uint32_t* b,
                   size_t n, uint32_t q) {
#if defined(KCTSB_HAS_AVX2)
    if (has_feature(SIMDFeature::AVX2) && n >= 8) {
        __m256i vq = _mm256_set1_epi32(static_cast<int32_t>(q));

        size_t i = 0;
        for (; i + 8 <= n; i += 8) {
            __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(a + i));
            __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(b + i));
            __m256i diff = _mm256_sub_epi32(va, vb);

            // Add q if negative (underflow)
            __m256i mask = _mm256_cmpgt_epi32(vb, va);
            diff = _mm256_add_epi32(diff, _mm256_and_si256(mask, vq));

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(result + i), diff);
        }

        for (; i < n; ++i) {
            result[i] = (a[i] >= b[i]) ? (a[i] - b[i]) : (q + a[i] - b[i]);
        }
        return;
    }
#endif

    for (size_t i = 0; i < n; ++i) {
        result[i] = (a[i] >= b[i]) ? (a[i] - b[i]) : (q + a[i] - b[i]);
    }
}

// ============================================================================
// Constant-Time Operations
// ============================================================================

uint64_t ct_select(uint64_t a, uint64_t b, uint64_t selector) {
    uint64_t mask = (selector == 0) ? 0 : ~0ULL;
    return (a & ~mask) | (b & mask);
}

int ct_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff;
}

void ct_cmov(uint8_t* dst, const uint8_t* src, size_t len, int condition) {
    uint8_t mask = (condition == 0) ? 0 : 0xFF;
    for (size_t i = 0; i < len; ++i) {
        dst[i] = (dst[i] & ~mask) | (src[i] & mask);
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

void secure_zero(void* ptr, size_t len) {
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
#endif
}

} // namespace simd
} // namespace kctsb
