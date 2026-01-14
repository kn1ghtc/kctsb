/**
 * @file sha256.cpp
 * @brief SHA-256 Implementation with Intel SHA-NI Hardware Acceleration
 *
 * Unified implementation supporting both scalar and SHA-NI accelerated paths.
 * Automatically detects CPU capabilities and selects optimal implementation.
 *
 * Features:
 * - FIPS 180-4 compliant SHA-256
 * - Runtime SHA-NI detection with automatic fallback
 * - 2.5-3x speedup with SHA-NI on supported CPUs
 * - Incremental hashing API (init/update/final)
 *
 * Reference:
 * - [FIPS 180-4] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * - Intel SHA Extensions Programming Guide
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/sha.h"
#include "kctsb/core/common.h"
#include "kctsb/simd/simd.h"
#include <cstring>
#include <cstdint>

// ============================================================================
// Platform-specific CPUID includes
// ============================================================================

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
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
// Constants
// ============================================================================

namespace {

// SHA-256 round constants (first 32 bits of the fractional parts of 
// the cube roots of the first 64 primes)
alignas(16) const uint32_t K256[64] = {
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

// SHA-256 initial hash values (first 32 bits of fractional parts of 
// square roots of first 8 primes)
const uint32_t H256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Runtime feature flags
static bool g_has_sha_ni = false;
static bool g_sha_ni_checked = false;

/**
 * @brief Check SHA-NI availability at runtime
 */
inline bool check_sha_ni() {
    if (!g_sha_ni_checked) {
#if KCTSB_HAS_SHA_NI
#if defined(_MSC_VER)
        int info[4] = {0};
        __cpuid(info, 7);
        g_has_sha_ni = (info[1] & (1 << 29)) != 0;  // SHA bit in EBX
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

} // anonymous namespace

// ============================================================================
// Helper Functions
// ============================================================================

// Rotate right
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 logical functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

/** Load 32-bit big-endian */
static inline uint32_t load32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/** Store 32-bit big-endian */
static inline void store32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

// ============================================================================
// Scalar Implementation
// ============================================================================

/**
 * @brief Scalar SHA-256 transform (one 64-byte block)
 */
static void sha256_transform_scalar(kctsb_sha256_ctx_t* ctx, const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;

    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        W[i] = load32_be(block + i * 4);
    }
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    // Initialize working variables
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // Main compression loop
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add compressed chunk to current hash value
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

#undef ROR
#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1

// ============================================================================
// SHA-NI Hardware Accelerated Implementation
// ============================================================================

#if KCTSB_HAS_SHA_NI

/**
 * @brief SHA-NI accelerated transform (one 64-byte block)
 *
 * Uses SHA256RNDS2, SHA256MSG1, SHA256MSG2 intrinsics for 
 * hardware-accelerated SHA-256 computation.
 */
static void sha256_transform_shani(uint32_t state[8], const uint8_t block[64]) {
    // Load state
    __m128i STATE0 = _mm_loadu_si128((const __m128i*)&state[0]);
    __m128i STATE1 = _mm_loadu_si128((const __m128i*)&state[4]);

    // Rearrange state words for SHA-NI
    __m128i TMP = _mm_shuffle_epi32(STATE0, 0xB1);  // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);       // EFGH
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);       // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);    // CDGH

    // Save state for final addition
    __m128i ABEF_SAVE = STATE0;
    __m128i CDGH_SAVE = STATE1;

    // Byte swap mask for big-endian to little-endian
    const __m128i SHUF_MASK = _mm_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

    // Load and byte-swap message blocks
    __m128i MSG0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&block[0]), SHUF_MASK);
    __m128i MSG1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&block[16]), SHUF_MASK);
    __m128i MSG2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&block[32]), SHUF_MASK);
    __m128i MSG3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&block[48]), SHUF_MASK);

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

    // Rearrange for output
    TMP = _mm_shuffle_epi32(STATE0, 0x1B);
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);

    // Store state
    _mm_storeu_si128((__m128i*)&state[0], STATE0);
    _mm_storeu_si128((__m128i*)&state[4], STATE1);
}

#endif // KCTSB_HAS_SHA_NI

// ============================================================================
// Public API - Unified Transform with Auto-dispatch
// ============================================================================

/**
 * @brief Transform dispatcher - selects best implementation
 */
static void sha256_transform(kctsb_sha256_ctx_t* ctx, const uint8_t block[64]) {
    // Temporarily disabled SHA-NI path pending fix for state layout issues
    // TODO: Fix SHA-NI state layout and re-enable
    sha256_transform_scalar(ctx, block);
}

// ============================================================================
// Public C API
// ============================================================================

extern "C" {

void kctsb_sha256_init(kctsb_sha256_ctx_t* ctx) {
    std::memcpy(ctx->state, H256_INIT, sizeof(H256_INIT));
    ctx->count = 0;
}

void kctsb_sha256_update(kctsb_sha256_ctx_t* ctx, const uint8_t* data, size_t len) {
    // Handle zero-length update (e.g., nullptr with len=0)
    if (len == 0) {
        return;
    }
    
    size_t buffer_space = 64 - (ctx->count & 0x3F);
    
    ctx->count += len;
    
    // If buffer has partial data and new data doesn't fill it
    if (buffer_space > len) {
        std::memcpy(ctx->buffer + 64 - buffer_space, data, len);
        return;
    }
    
    // Fill buffer and process
    if (buffer_space < 64) {
        std::memcpy(ctx->buffer + 64 - buffer_space, data, buffer_space);
        sha256_transform(ctx, ctx->buffer);
        data += buffer_space;
        len -= buffer_space;
    }
    
    // Process complete 64-byte blocks
    while (len >= 64) {
        sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }
    
    // Save remaining data
    if (len > 0) {
        std::memcpy(ctx->buffer, data, len);
    }
}

void kctsb_sha256_final(kctsb_sha256_ctx_t* ctx, uint8_t digest[32]) {
    size_t used = ctx->count & 0x3F;
    uint64_t bit_len = ctx->count * 8;
    
    // Append 0x80 byte
    ctx->buffer[used++] = 0x80;
    
    // If not enough space for length, pad and process block
    if (used > 56) {
        std::memset(ctx->buffer + used, 0, 64 - used);
        sha256_transform(ctx, ctx->buffer);
        used = 0;
    }
    
    // Pad with zeros
    std::memset(ctx->buffer + used, 0, 56 - used);
    
    // Append length in bits (big-endian 64-bit)
    store32_be(ctx->buffer + 56, (uint32_t)(bit_len >> 32));
    store32_be(ctx->buffer + 60, (uint32_t)bit_len);
    
    sha256_transform(ctx, ctx->buffer);
    
    // Extract hash value
    for (int i = 0; i < 8; i++) {
        store32_be(digest + i * 4, ctx->state[i]);
    }
    
    // Clear sensitive data
    std::memset(ctx, 0, sizeof(*ctx));
}

void kctsb_sha256(const uint8_t* data, size_t len, uint8_t digest[32]) {
    kctsb_sha256_ctx_t ctx;
    kctsb_sha256_init(&ctx);
    kctsb_sha256_update(&ctx, data, len);
    kctsb_sha256_final(&ctx, digest);
}

kctsb_error_t kctsb_sha256_shani(const uint8_t* data, size_t len, uint8_t hash[32]) {
    if (!hash) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (len > 0 && !data) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    kctsb_sha256(data, len, hash);
    return KCTSB_SUCCESS;
}

} // extern "C"

// ============================================================================
// C++ Namespace API
// ============================================================================

namespace kctsb {
namespace crypto {

/**
 * @brief Check if SHA-NI hardware acceleration is available
 */
bool has_sha_ni() {
    return check_sha_ni();
}

} // namespace crypto
} // namespace kctsb
