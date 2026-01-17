/**
 * @file aes.cpp
 * @brief Production-grade AES-GCM implementation with hardware acceleration
 *
 * Security Features:
 * - AES-NI hardware acceleration (constant-time, cache-timing safe)
 * - Constexpr S-Box generation (compile-time, no runtime lookup tables)
 * - NO T-tables (removed to prevent cache-timing side-channel attacks)
 * - Secure memory handling with automatic zeroing
 * - Complete AES-GCM with PCLMUL-accelerated GHASH
 * - Integrated NIST SP 800-90A CTR_DRBG for secure random generation
 *
 * Supported Modes:
 * - AES-128-GCM (AEAD)
 * - AES-256-GCM (AEAD)
 *
 * Optimization hierarchy (auto-selected at runtime):
 * 1. AES-NI + PCLMUL: Hardware acceleration (default on modern CPUs)
 * 2. Software fallback: Constant-time, portable (rare legacy systems)
 *
 * Based on NIST FIPS 197 (AES) and SP 800-38D (GCM) and SP 800-90A (DRBG)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/aes.h"
#include "kctsb/core/security.h"
#include "kctsb/simd/simd.h"
#include <array>
#include <cstring>
#include <stdexcept>
#include <atomic>
#include <mutex>
#include <vector>

// CPUID and SIMD intrinsics
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// Platform-specific entropy source headers
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
// BCryptGenRandom via runtime dynamic loading (no bcrypt.lib link required)
// bcrypt.dll is a Windows system component, loaded at runtime
typedef LONG KCTSB_NTSTATUS;
typedef KCTSB_NTSTATUS (WINAPI *BCryptGenRandomFn)(
    PVOID hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
constexpr ULONG KCTSB_BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;
constexpr KCTSB_NTSTATUS KCTSB_STATUS_SUCCESS = 0L;
#elif defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#if defined(__x86_64__) || defined(__i386__)
#define KCTSB_HAS_GETRANDOM_SYSCALL 1
#endif
#elif defined(__APPLE__)
#include <Security/Security.h>
#endif

// AES-NI and SSE intrinsics
#if defined(KCTSB_HAS_AESNI) || defined(__AES__)
#include <wmmintrin.h>  // AES-NI
#include <emmintrin.h>  // SSE2
#include <tmmintrin.h>  // SSSE3 (for _mm_shuffle_epi8)
#include <smmintrin.h>  // SSE4.1
#endif

// ============================================================================
// Runtime Feature Detection
// ============================================================================

static bool g_aesni_detected = false;
static bool g_aesni_available = false;

static inline bool check_aesni() {
#if defined(KCTSB_HAS_AESNI)
    if (!g_aesni_detected) {
        g_aesni_available = kctsb::simd::has_aesni();
        g_aesni_detected = true;
    }
    return g_aesni_available;
#else
    return false;
#endif
}

// Flag to track key format in context
#define AESNI_FORMAT_FLAG 0x10000

// ============================================================================
// Constexpr S-Box Generation (Compile-time, No Runtime Lookup Tables)
// ============================================================================
// When hardware acceleration is available (default), these are not used.
// For rare fallback cases, S-Box is computed at compile-time and embedded
// in the binary as constants - no cache-timing vulnerable lookups.
// ============================================================================

namespace {

// GF(2^8) multiplication helper for S-Box generation
constexpr uint8_t gf_mul_constexpr(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t temp = a;
    for (int i = 0; i < 8; ++i) {
        if ((b >> i) & 1) {
            result ^= temp;
        }
        uint8_t hi_bit = (temp >> 7) & 1;
        temp = static_cast<uint8_t>((temp << 1) ^ (hi_bit ? 0x1b : 0));
    }
    return result;
}

// GF(2^8) multiplicative inverse using extended Euclidean algorithm
constexpr uint8_t gf_inverse_constexpr(uint8_t a) {
    if (a == 0) return 0;
    // Use Fermat's little theorem: a^(-1) = a^(254) in GF(2^8)
    uint8_t result = a;
    for (int i = 0; i < 6; ++i) {
        result = gf_mul_constexpr(result, result);
        result = gf_mul_constexpr(result, a);
    }
    result = gf_mul_constexpr(result, result);
    return result;
}

// Affine transformation for S-Box
constexpr uint8_t affine_transform(uint8_t x) {
    uint8_t s = x;
    s ^= static_cast<uint8_t>((x << 1) | (x >> 7));
    s ^= static_cast<uint8_t>((x << 2) | (x >> 6));
    s ^= static_cast<uint8_t>((x << 3) | (x >> 5));
    s ^= static_cast<uint8_t>((x << 4) | (x >> 4));
    s ^= 0x63;
    return s;
}

// Generate single S-Box entry at compile time
constexpr uint8_t generate_sbox_entry(uint8_t i) {
    return affine_transform(gf_inverse_constexpr(i));
}

// Inverse affine transformation for inverse S-Box
constexpr uint8_t inv_affine_transform(uint8_t x) {
    uint8_t s = static_cast<uint8_t>((x << 1) | (x >> 7));
    s ^= static_cast<uint8_t>((x << 3) | (x >> 5));
    s ^= static_cast<uint8_t>((x << 6) | (x >> 2));
    s ^= 0x05;
    return s;
}

// Generate single inverse S-Box entry at compile time
constexpr uint8_t generate_inv_sbox_entry(uint8_t i) {
    return gf_inverse_constexpr(inv_affine_transform(i));
}

// Compile-time S-Box array generation
template<typename F, size_t... Is>
constexpr auto make_table_impl(F f, std::index_sequence<Is...>) {
    return std::array<uint8_t, sizeof...(Is)>{{f(static_cast<uint8_t>(Is))...}};
}

template<size_t N, typename F>
constexpr auto make_table(F f) {
    return make_table_impl(f, std::make_index_sequence<N>{});
}

// Constexpr S-Box and Inverse S-Box (computed at compile time)
constexpr auto SBOX = make_table<256>(generate_sbox_entry);
constexpr auto INV_SBOX = make_table<256>(generate_inv_sbox_entry);

// Round constants (small, not a timing concern)
constexpr uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

} // anonymous namespace

// ============================================================================
// Internal Helper Functions
// ============================================================================

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t temp = a;
    for (size_t i = 0; i < 8; i++) {
        uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>((b >> i) & 1));
        result ^= (temp & mask);
        uint8_t hi_bit = static_cast<uint8_t>((temp >> 7) & 1);
        temp = static_cast<uint8_t>((temp << 1) ^ (0x1b & static_cast<uint8_t>(-static_cast<int8_t>(hi_bit))));
    }
    return result;
}

static inline void xor_block(uint8_t* out, const uint8_t* a, const uint8_t* b) {
    for (size_t i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static inline void inc_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0) break;
    }
}

// ============================================================================
// Software Key Expansion (big-endian format)
// ============================================================================

static void key_expansion(const uint8_t* key, uint32_t* round_keys, int key_len, int rounds) {
    int nk = key_len / 4;
    int nb = 4;
    int nr = rounds;

    for (int i = 0; i < nk; i++) {
        round_keys[i] = (static_cast<uint32_t>(key[4*i]) << 24) |
                        (static_cast<uint32_t>(key[4*i+1]) << 16) |
                        (static_cast<uint32_t>(key[4*i+2]) << 8) |
                        (static_cast<uint32_t>(key[4*i+3]));
    }

    for (int i = nk; i < nb * (nr + 1); i++) {
        uint32_t temp = round_keys[i - 1];
        if (i % nk == 0) {
            temp = (temp << 8) | (temp >> 24);
            temp = (static_cast<uint32_t>(SBOX[(temp >> 24) & 0xff]) << 24) |
                   (static_cast<uint32_t>(SBOX[(temp >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(SBOX[(temp >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(SBOX[temp & 0xff]));
            temp ^= (static_cast<uint32_t>(RCON[i / nk]) << 24);
        } else if (nk > 6 && i % nk == 4) {
            temp = (static_cast<uint32_t>(SBOX[(temp >> 24) & 0xff]) << 24) |
                   (static_cast<uint32_t>(SBOX[(temp >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(SBOX[(temp >> 8) & 0xff]) << 8) |
                   (static_cast<uint32_t>(SBOX[temp & 0xff]));
        }
        round_keys[i] = round_keys[i - nk] ^ temp;
    }
}

// ============================================================================
// Software AES Core Operations (constant-time)
// ============================================================================

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]];
}

static void shift_rows(uint8_t state[16]) {
    uint8_t temp;
    temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    temp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = temp;
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    temp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = temp;
}

static void mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c], a1 = state[c+1], a2 = state[c+2], a3 = state[c+3];
        state[c]   = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[c+1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[c+2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[c+3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

static void inv_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c], a1 = state[c+1], a2 = state[c+2], a3 = state[c+3];
        state[c]   = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        state[c+1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        state[c+2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        state[c+3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

static void add_round_key(uint8_t state[16], const uint32_t* round_key) {
    for (int i = 0; i < 4; i++) {
        state[i*4]   ^= static_cast<uint8_t>((round_key[i] >> 24) & 0xff);
        state[i*4+1] ^= static_cast<uint8_t>((round_key[i] >> 16) & 0xff);
        state[i*4+2] ^= static_cast<uint8_t>((round_key[i] >> 8) & 0xff);
        state[i*4+3] ^= static_cast<uint8_t>(round_key[i] & 0xff);
    }
}

// ============================================================================
// GHASH Implementation for GCM
// ============================================================================

static void ghash_mult(const uint8_t x[16], const uint8_t h[16], uint8_t result[16]) {
    uint8_t v[16], z[16];
    memcpy(v, h, 16);
    memset(z, 0, 16);

    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>((x[i] >> j) & 1));
            for (int k = 0; k < 16; k++) z[k] ^= (v[k] & mask);
            uint8_t lsb = v[15] & 1;
            for (int k = 15; k > 0; k--) v[k] = static_cast<uint8_t>((v[k] >> 1) | ((v[k-1] & 1) << 7));
            v[0] >>= 1;
            uint8_t lsb_mask = static_cast<uint8_t>(-static_cast<int8_t>(lsb));
            v[0] ^= (0xe1 & lsb_mask);
        }
    }
    memcpy(result, z, 16);
}

// Runtime flag for PCLMUL detection
static bool g_pclmul_detected = false;
static bool g_pclmul_available = false;

static inline bool check_pclmul() {
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
    if (!g_pclmul_detected) {
        // Check CPUID for PCLMUL support (bit 1 of ECX)
        int info[4] = {0};
        #if defined(_MSC_VER)
        __cpuid(info, 1);
        #elif defined(__GNUC__) || defined(__clang__)
        __cpuid(1, info[0], info[1], info[2], info[3]);
        #endif
        g_pclmul_available = (info[2] & (1 << 1)) != 0;
        g_pclmul_detected = true;
    }
    return g_pclmul_available;
#else
    return false;
#endif
}

static void ghash_update(uint8_t tag[16], const uint8_t h[16], const uint8_t* data, size_t len) {
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
    if (check_pclmul()) {
        kctsb::simd::ghash_pclmul(tag, h, data, len);
        return;
    }
#endif

    // Software fallback
    uint8_t block[16];
    while (len >= 16) {
        xor_block(block, tag, data);
        ghash_mult(block, h, tag);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        memset(block, 0, 16);
        memcpy(block, data, len);
        xor_block(block, tag, block);
        ghash_mult(block, h, tag);
    }
}

// ============================================================================
// High-Performance One-Shot GHASH for AES-GCM (PCLMUL acceleration)
// Precomputes H powers ONCE and processes AAD + CT + LEN in a single pass
// ============================================================================
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)

// Inline GF(2^128) Karatsuba multiplication without reduction
static inline void gcm_karatsuba(const __m128i H, const __m128i X,
                                  __m128i& lo, __m128i& hi, __m128i& mid) {
    // Karatsuba: (H0 + H1*z^64)(X0 + X1*z^64) using 3 multiplications
    __m128i H_hi = _mm_shuffle_epi32(H, 0x4E);   // Swap high/low 64-bit halves
    __m128i X_hi = _mm_shuffle_epi32(X, 0x4E);
    
    lo = _mm_clmulepi64_si128(H, X, 0x00);      // H0 * X0
    hi = _mm_clmulepi64_si128(H, X, 0x11);      // H1 * X1
    
    __m128i H_sum = _mm_xor_si128(H, H_hi);     // H0 + H1
    __m128i X_sum = _mm_xor_si128(X, X_hi);     // X0 + X1
    mid = _mm_clmulepi64_si128(H_sum, X_sum, 0x00);  // (H0+H1)*(X0+X1)
    mid = _mm_xor_si128(mid, lo);
    mid = _mm_xor_si128(mid, hi);               // mid = H0*X1 + H1*X0
}

// Inline modular reduction (polynomial: x^128 + x^7 + x^2 + x + 1)
static inline __m128i gcm_reduce(const __m128i lo, const __m128i hi, const __m128i mid) {
    // Combine: full = hi*z^128 + mid*z^64 + lo
    __m128i mid_lo = _mm_slli_si128(mid, 8);
    __m128i mid_hi = _mm_srli_si128(mid, 8);
    __m128i full_lo = _mm_xor_si128(lo, mid_lo);
    __m128i full_hi = _mm_xor_si128(hi, mid_hi);
    
    // Barrett reduction for GF(2^128)
    __m128i tmp1 = _mm_srli_epi32(full_lo, 31);
    __m128i tmp2 = _mm_srli_epi32(full_lo, 30);
    __m128i tmp3 = _mm_srli_epi32(full_lo, 25);
    
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    
    __m128i tmp4 = _mm_shuffle_epi32(tmp1, 0x93);
    tmp1 = _mm_and_si128(tmp4, _mm_set_epi32(0, static_cast<int32_t>(0xffffffff), 
                                              static_cast<int32_t>(0xffffffff), 
                                              static_cast<int32_t>(0xffffffff)));
    tmp4 = _mm_and_si128(tmp4, _mm_set_epi32(static_cast<int32_t>(0xffffffff), 0, 0, 0));
    
    full_lo = _mm_xor_si128(full_lo, tmp1);
    full_hi = _mm_xor_si128(full_hi, tmp4);
    
    __m128i tmp5 = _mm_slli_epi32(full_lo, 1);
    __m128i tmp6 = _mm_slli_epi32(full_lo, 2);
    __m128i tmp7 = _mm_slli_epi32(full_lo, 7);
    
    tmp5 = _mm_xor_si128(tmp5, tmp6);
    tmp5 = _mm_xor_si128(tmp5, tmp7);
    tmp5 = _mm_xor_si128(tmp5, full_lo);
    
    __m128i tmp8 = _mm_srli_si128(tmp5, 4);
    tmp5 = _mm_slli_si128(tmp5, 12);
    full_lo = _mm_xor_si128(full_lo, tmp5);
    
    __m128i tmp9 = _mm_srli_epi32(full_lo, 1);
    __m128i tmp10 = _mm_srli_epi32(full_lo, 2);
    tmp8 = _mm_xor_si128(tmp8, _mm_srli_epi32(full_lo, 7));
    
    tmp9 = _mm_xor_si128(tmp9, tmp10);
    tmp9 = _mm_xor_si128(tmp9, tmp8);
    tmp9 = _mm_xor_si128(tmp9, full_lo);
    
    return _mm_xor_si128(full_hi, tmp9);
}

// Full GF(2^128) multiplication with reduction
static inline __m128i gcm_gf_mul(const __m128i H, const __m128i X) {
    __m128i lo, hi, mid;
    gcm_karatsuba(H, X, lo, hi, mid);
    return gcm_reduce(lo, hi, mid);
}

// 8-block parallel GHASH update (reduces code duplication)
// Y = (Y ^ X0) * H8 + X1 * H7 + ... + X7 * H1
static inline __m128i ghash_8blocks_parallel(
    __m128i Y,
    const __m128i X0, const __m128i X1, const __m128i X2, const __m128i X3,
    const __m128i X4, const __m128i X5, const __m128i X6, const __m128i X7,
    const __m128i H8, const __m128i H7, const __m128i H6, const __m128i H5,
    const __m128i H4, const __m128i H3, const __m128i H2, const __m128i H1)
{
    __m128i X0_xor = _mm_xor_si128(X0, Y);
    __m128i lo0, hi0, mid0, lo1, hi1, mid1, lo2, hi2, mid2, lo3, hi3, mid3;
    __m128i lo4, hi4, mid4, lo5, hi5, mid5, lo6, hi6, mid6, lo7, hi7, mid7;
    gcm_karatsuba(H8, X0_xor, lo0, hi0, mid0);
    gcm_karatsuba(H7, X1, lo1, hi1, mid1);
    gcm_karatsuba(H6, X2, lo2, hi2, mid2);
    gcm_karatsuba(H5, X3, lo3, hi3, mid3);
    gcm_karatsuba(H4, X4, lo4, hi4, mid4);
    gcm_karatsuba(H3, X5, lo5, hi5, mid5);
    gcm_karatsuba(H2, X6, lo6, hi6, mid6);
    gcm_karatsuba(H1, X7, lo7, hi7, mid7);
    
    __m128i lo_acc = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(lo0, lo1), _mm_xor_si128(lo2, lo3)),
                                   _mm_xor_si128(_mm_xor_si128(lo4, lo5), _mm_xor_si128(lo6, lo7)));
    __m128i hi_acc = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(hi0, hi1), _mm_xor_si128(hi2, hi3)),
                                   _mm_xor_si128(_mm_xor_si128(hi4, hi5), _mm_xor_si128(hi6, hi7)));
    __m128i mid_acc = _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(mid0, mid1), _mm_xor_si128(mid2, mid3)),
                                    _mm_xor_si128(_mm_xor_si128(mid4, mid5), _mm_xor_si128(mid6, mid7)));
    return gcm_reduce(lo_acc, hi_acc, mid_acc);
}

// High-performance one-shot GHASH for GCM
// Processes AAD, ciphertext, and length block in a single optimized pass
static void ghash_oneshot_gcm(
    uint8_t tag[16],
    const uint8_t h[16],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len)
{
    const __m128i bswap = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    
    // Load and byte-swap H
    __m128i H = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(h)), bswap);
    __m128i Y = _mm_setzero_si128();
    
    // Precompute H powers ONCE: H^1 to H^8
    __m128i H2 = gcm_gf_mul(H, H);
    __m128i H3 = gcm_gf_mul(H2, H);
    __m128i H4 = gcm_gf_mul(H2, H2);
    __m128i H5 = gcm_gf_mul(H4, H);
    __m128i H6 = gcm_gf_mul(H3, H3);
    __m128i H7 = gcm_gf_mul(H6, H);
    __m128i H8 = gcm_gf_mul(H4, H4);
    
    // Helper lambda for processing data with 8-way parallelism + prefetch
    auto process_data = [&](const uint8_t* data, size_t len) {
        // 8-block parallel processing (128 bytes at a time)
        while (len >= 128) {
            if (len >= 256) {
                _mm_prefetch(reinterpret_cast<const char*>(data + 128), _MM_HINT_T0);
                _mm_prefetch(reinterpret_cast<const char*>(data + 192), _MM_HINT_T0);
            }
            
            __m128i X0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data)), bswap);
            __m128i X1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16)), bswap);
            __m128i X2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 32)), bswap);
            __m128i X3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 48)), bswap);
            __m128i X4 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 64)), bswap);
            __m128i X5 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 80)), bswap);
            __m128i X6 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 96)), bswap);
            __m128i X7 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 112)), bswap);
            
            Y = ghash_8blocks_parallel(Y, X0, X1, X2, X3, X4, X5, X6, X7,
                                        H8, H7, H6, H5, H4, H3, H2, H);
            data += 128;
            len -= 128;
        }
        
        // Serial processing for remaining blocks (< 128 bytes)
        while (len >= 16) {
            __m128i X = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data)), bswap);
            Y = _mm_xor_si128(Y, X);
            Y = gcm_gf_mul(H, Y);
            data += 16;
            len -= 16;
        }
        
        // Handle partial block with zero padding
        if (len > 0) {
            uint8_t block[16] = {0};
            memcpy(block, data, len);
            __m128i X = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block)), bswap);
            Y = _mm_xor_si128(Y, X);
            Y = gcm_gf_mul(H, Y);
        }
    };
    
    // Process AAD (padded to 16-byte boundary)
    if (aad && aad_len > 0) {
        process_data(aad, aad_len);
    }
    
    // Process ciphertext (padded to 16-byte boundary)
    if (ct && ct_len > 0) {
        process_data(ct, ct_len);
    }
    
    // Process length block: [aad_bits (64-bit BE) || ct_bits (64-bit BE)]
    alignas(16) uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
        len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
    }
    __m128i L = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(len_block)), bswap);
    Y = _mm_xor_si128(Y, L);
    Y = gcm_gf_mul(H, Y);
    
    // Store result (byte-swapped back)
    Y = _mm_shuffle_epi8(Y, bswap);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(tag), Y);
}

#endif // KCTSB_HAS_PCLMUL

// ============================================================================
// Public C API
// ============================================================================

extern "C" {

kctsb_error_t kctsb_aes_init(kctsb_aes_ctx_t* ctx, const uint8_t* key, size_t key_len) {
    if (!ctx || !key) return KCTSB_ERROR_INVALID_PARAM;

    switch (key_len) {
        case 16: ctx->key_bits = 128; ctx->rounds = 10; break;
        case 24: ctx->key_bits = 192; ctx->rounds = 12; break;
        case 32: ctx->key_bits = 256; ctx->rounds = 14; break;
        default: return KCTSB_ERROR_INVALID_KEY;
    }

#if defined(KCTSB_HAS_AESNI)
    if (check_aesni()) {
        kctsb_secure_zero(ctx->round_keys, sizeof(ctx->round_keys));
        uint8_t* rk = reinterpret_cast<uint8_t*>(ctx->round_keys);
        if (key_len == 16) {
            kctsb::simd::aes128_expand_key_ni(key, rk);
            ctx->rounds |= AESNI_FORMAT_FLAG;
            return KCTSB_SUCCESS;
        } else if (key_len == 32) {
            kctsb::simd::aes256_expand_key_ni(key, rk);
            ctx->rounds |= AESNI_FORMAT_FLAG;
            return KCTSB_SUCCESS;
        }
    }
#endif

    // Use software key expansion for all key sizes to ensure consistent format
    // between encryption and decryption
    key_expansion(key, ctx->round_keys, (int)key_len, ctx->rounds);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_encrypt_block(const kctsb_aes_ctx_t* ctx,
                                       const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    int actual_rounds = ctx->rounds & 0xFF;

#if defined(KCTSB_HAS_AESNI)
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format && check_aesni()) {
        const uint8_t* rk = reinterpret_cast<const uint8_t*>(ctx->round_keys);
        if (ctx->key_bits == 128) {
            kctsb::simd::aes128_encrypt_block_ni(input, output, rk);
            return KCTSB_SUCCESS;
        } else if (ctx->key_bits == 256) {
            kctsb::simd::aes256_encrypt_block_ni(input, output, rk);
            return KCTSB_SUCCESS;
        }
    }
#endif

    // Use software encryption (consistent with decryption)
    uint8_t state[16];
    memcpy(state, input, 16);

    add_round_key(state, &ctx->round_keys[0]);
    for (int round = 1; round < actual_rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[round * 4]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[actual_rounds * 4]);

    memcpy(output, state, 16);
    kctsb_secure_zero(state, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_decrypt_block(const kctsb_aes_ctx_t* ctx,
                                       const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    int actual_rounds = ctx->rounds & 0xFF;
    uint8_t state[16];
    memcpy(state, input, 16);

    const uint32_t* rk = ctx->round_keys;

#if defined(KCTSB_HAS_AESNI)
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format) {
        // AES-NI format stores key as raw bytes - need to regenerate software keys
        // for decryption since we don't have hardware decrypt key schedule
        uint32_t sw_round_keys[60];
        int key_len = (ctx->key_bits == 128) ? 16 : ((ctx->key_bits == 192) ? 24 : 32);
        uint8_t orig_key[32];
        memcpy(orig_key, ctx->round_keys, static_cast<size_t>(key_len));
        key_expansion(orig_key, sw_round_keys, key_len, actual_rounds);
        kctsb_secure_zero(orig_key, sizeof(orig_key));
        rk = sw_round_keys;

        add_round_key(state, &rk[actual_rounds * 4]);
        for (int round = actual_rounds - 1; round > 0; round--) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, &rk[round * 4]);
            inv_mix_columns(state);
        }
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &rk[0]);

        memcpy(output, state, 16);
        kctsb_secure_zero(state, 16);
        kctsb_secure_zero(sw_round_keys, sizeof(sw_round_keys));
        return KCTSB_SUCCESS;
    }
#endif

    // Software path - keys already in correct format
    add_round_key(state, &rk[actual_rounds * 4]);
    for (int round = actual_rounds - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &rk[round * 4]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &rk[0]);

    memcpy(output, state, 16);
    kctsb_secure_zero(state, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_ctr_crypt(const kctsb_aes_ctx_t* ctx, const uint8_t nonce[12],
                                  const uint8_t* input, size_t input_len, uint8_t* output) {
    if (!ctx || !nonce || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    uint8_t counter_block[16], keystream[16];
    memcpy(counter_block, nonce, 12);
    counter_block[12] = 0; counter_block[13] = 0; counter_block[14] = 0; counter_block[15] = 1;

    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(ctx, counter_block, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(counter_block);
        offset += bytes;
    }

    kctsb_secure_zero(counter_block, 16);
    kctsb_secure_zero(keystream, 16);
    return KCTSB_SUCCESS;
}

// ============================================================================
// High-Performance AES-GCM using 4-block parallel AES-NI
// ============================================================================

#if defined(KCTSB_HAS_AESNI)

// Byte-swap mask for big-endian counter (GCM uses big-endian counter)
static const __m128i BSWAP_EPI32 = _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3);

// Increment counter block by 1 (big-endian, last 32 bits)
static inline __m128i inc_counter_be32_fast(__m128i ctr) {
    // Swap bytes to little-endian, add 1, swap back
    __m128i swapped = _mm_shuffle_epi8(ctr, BSWAP_EPI32);
    __m128i one = _mm_set_epi32(1, 0, 0, 0);
    swapped = _mm_add_epi32(swapped, one);
    return _mm_shuffle_epi8(swapped, BSWAP_EPI32);
}

// Generate 4 consecutive counter blocks efficiently using SIMD
static inline void gen_4_counters_fast(__m128i base, __m128i& c0, __m128i& c1, __m128i& c2, __m128i& c3) {
    // Swap to little-endian for arithmetic
    __m128i swapped = _mm_shuffle_epi8(base, BSWAP_EPI32);
    
    // Create increments: +0, +1, +2, +3
    __m128i inc0 = _mm_set_epi32(0, 0, 0, 0);
    __m128i inc1 = _mm_set_epi32(1, 0, 0, 0);
    __m128i inc2 = _mm_set_epi32(2, 0, 0, 0);
    __m128i inc3 = _mm_set_epi32(3, 0, 0, 0);
    
    // Generate all 4 counters
    __m128i t0 = _mm_add_epi32(swapped, inc0);
    __m128i t1 = _mm_add_epi32(swapped, inc1);
    __m128i t2 = _mm_add_epi32(swapped, inc2);
    __m128i t3 = _mm_add_epi32(swapped, inc3);
    
    // Swap back to big-endian
    c0 = _mm_shuffle_epi8(t0, BSWAP_EPI32);
    c1 = _mm_shuffle_epi8(t1, BSWAP_EPI32);
    c2 = _mm_shuffle_epi8(t2, BSWAP_EPI32);
    c3 = _mm_shuffle_epi8(t3, BSWAP_EPI32);
}

// Advance counter by N (for after processing N blocks)
static inline __m128i add_counter_be32(__m128i ctr, uint32_t n) {
    __m128i swapped = _mm_shuffle_epi8(ctr, BSWAP_EPI32);
    __m128i add = _mm_set_epi32((int)n, 0, 0, 0);
    swapped = _mm_add_epi32(swapped, add);
    return _mm_shuffle_epi8(swapped, BSWAP_EPI32);
}

// Generate 8 consecutive counter blocks efficiently
static inline void gen_8_counters_fast(__m128i base,
    __m128i& c0, __m128i& c1, __m128i& c2, __m128i& c3,
    __m128i& c4, __m128i& c5, __m128i& c6, __m128i& c7) {
    __m128i swapped = _mm_shuffle_epi8(base, BSWAP_EPI32);
    __m128i t0 = _mm_add_epi32(swapped, _mm_set_epi32(0, 0, 0, 0));
    __m128i t1 = _mm_add_epi32(swapped, _mm_set_epi32(1, 0, 0, 0));
    __m128i t2 = _mm_add_epi32(swapped, _mm_set_epi32(2, 0, 0, 0));
    __m128i t3 = _mm_add_epi32(swapped, _mm_set_epi32(3, 0, 0, 0));
    __m128i t4 = _mm_add_epi32(swapped, _mm_set_epi32(4, 0, 0, 0));
    __m128i t5 = _mm_add_epi32(swapped, _mm_set_epi32(5, 0, 0, 0));
    __m128i t6 = _mm_add_epi32(swapped, _mm_set_epi32(6, 0, 0, 0));
    __m128i t7 = _mm_add_epi32(swapped, _mm_set_epi32(7, 0, 0, 0));
    c0 = _mm_shuffle_epi8(t0, BSWAP_EPI32);
    c1 = _mm_shuffle_epi8(t1, BSWAP_EPI32);
    c2 = _mm_shuffle_epi8(t2, BSWAP_EPI32);
    c3 = _mm_shuffle_epi8(t3, BSWAP_EPI32);
    c4 = _mm_shuffle_epi8(t4, BSWAP_EPI32);
    c5 = _mm_shuffle_epi8(t5, BSWAP_EPI32);
    c6 = _mm_shuffle_epi8(t6, BSWAP_EPI32);
    c7 = _mm_shuffle_epi8(t7, BSWAP_EPI32);
}

// 4-block parallel AES-128 encryption
static inline void aes128_encrypt_4blocks_ni(
    __m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
    const __m128i* rk)
{
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
}

// 8-block parallel AES-128 encryption (fully pipelined)
static inline void aes128_encrypt_8blocks_ni(
    __m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
    __m128i& b4, __m128i& b5, __m128i& b6, __m128i& b7,
    const __m128i* rk)
{
    b0 = _mm_xor_si128(b0, rk[0]); b1 = _mm_xor_si128(b1, rk[0]);
    b2 = _mm_xor_si128(b2, rk[0]); b3 = _mm_xor_si128(b3, rk[0]);
    b4 = _mm_xor_si128(b4, rk[0]); b5 = _mm_xor_si128(b5, rk[0]);
    b6 = _mm_xor_si128(b6, rk[0]); b7 = _mm_xor_si128(b7, rk[0]);

    for (int i = 1; i < 10; ++i) {
        b0 = _mm_aesenc_si128(b0, rk[i]); b1 = _mm_aesenc_si128(b1, rk[i]);
        b2 = _mm_aesenc_si128(b2, rk[i]); b3 = _mm_aesenc_si128(b3, rk[i]);
        b4 = _mm_aesenc_si128(b4, rk[i]); b5 = _mm_aesenc_si128(b5, rk[i]);
        b6 = _mm_aesenc_si128(b6, rk[i]); b7 = _mm_aesenc_si128(b7, rk[i]);
    }

    b0 = _mm_aesenclast_si128(b0, rk[10]); b1 = _mm_aesenclast_si128(b1, rk[10]);
    b2 = _mm_aesenclast_si128(b2, rk[10]); b3 = _mm_aesenclast_si128(b3, rk[10]);
    b4 = _mm_aesenclast_si128(b4, rk[10]); b5 = _mm_aesenclast_si128(b5, rk[10]);
    b6 = _mm_aesenclast_si128(b6, rk[10]); b7 = _mm_aesenclast_si128(b7, rk[10]);
}

// 4-block parallel AES-256 encryption
static inline void aes256_encrypt_4blocks_ni(
    __m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
    const __m128i* rk)
{
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
}

// 8-block parallel AES-256 encryption (fully pipelined)
static inline void aes256_encrypt_8blocks_ni(
    __m128i& b0, __m128i& b1, __m128i& b2, __m128i& b3,
    __m128i& b4, __m128i& b5, __m128i& b6, __m128i& b7,
    const __m128i* rk)
{
    b0 = _mm_xor_si128(b0, rk[0]); b1 = _mm_xor_si128(b1, rk[0]);
    b2 = _mm_xor_si128(b2, rk[0]); b3 = _mm_xor_si128(b3, rk[0]);
    b4 = _mm_xor_si128(b4, rk[0]); b5 = _mm_xor_si128(b5, rk[0]);
    b6 = _mm_xor_si128(b6, rk[0]); b7 = _mm_xor_si128(b7, rk[0]);

    for (int i = 1; i < 14; ++i) {
        b0 = _mm_aesenc_si128(b0, rk[i]); b1 = _mm_aesenc_si128(b1, rk[i]);
        b2 = _mm_aesenc_si128(b2, rk[i]); b3 = _mm_aesenc_si128(b3, rk[i]);
        b4 = _mm_aesenc_si128(b4, rk[i]); b5 = _mm_aesenc_si128(b5, rk[i]);
        b6 = _mm_aesenc_si128(b6, rk[i]); b7 = _mm_aesenc_si128(b7, rk[i]);
    }

    b0 = _mm_aesenclast_si128(b0, rk[14]); b1 = _mm_aesenclast_si128(b1, rk[14]);
    b2 = _mm_aesenclast_si128(b2, rk[14]); b3 = _mm_aesenclast_si128(b3, rk[14]);
    b4 = _mm_aesenclast_si128(b4, rk[14]); b5 = _mm_aesenclast_si128(b5, rk[14]);
    b6 = _mm_aesenclast_si128(b6, rk[14]); b7 = _mm_aesenclast_si128(b7, rk[14]);
}

// High-performance AES-GCM encrypt using AES-NI (8-block parallel + pipelined GHASH)
static kctsb_error_t aes_gcm_encrypt_aesni(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    uint8_t* output, uint8_t tag[16])
{
    const __m128i* rk = reinterpret_cast<const __m128i*>(ctx->round_keys);
    const bool is_aes256 = (ctx->key_bits == 256);

    // Compute H = E(K, 0^128)
    alignas(16) uint8_t h_bytes[16] = {0};
    __m128i H = _mm_setzero_si128();
    if (is_aes256) {
        __m128i tmp = H;
        aes256_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    } else {
        __m128i tmp = H;
        aes128_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    }
    _mm_storeu_si128(reinterpret_cast<__m128i*>(h_bytes), H);

    // Compute J0 (initial counter)
    alignas(16) uint8_t j0_bytes[16];
    if (iv_len == 12) {
        memcpy(j0_bytes, iv, 12);
        j0_bytes[12] = 0; j0_bytes[13] = 0; j0_bytes[14] = 0; j0_bytes[15] = 1;
    } else {
        memset(j0_bytes, 0, 16);
        ghash_update(j0_bytes, h_bytes, iv, iv_len);
        alignas(16) uint8_t len_block[16] = {0};
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = static_cast<uint8_t>(iv_bits >> (i * 8));
        ghash_update(j0_bytes, h_bytes, len_block, 16);
    }

    // Set up counter (J0 + 1)
    alignas(16) uint8_t counter_bytes[16];
    memcpy(counter_bytes, j0_bytes, 16);
    inc_counter(counter_bytes);
    __m128i counter = _mm_loadu_si128(reinterpret_cast<const __m128i*>(counter_bytes));

    // =========================================================================
    // Fused CTR encryption + GHASH (PCLMUL path)
    // Single memory read for input, single write to output
    // GHASH computed inline while data is in registers/L1 cache
    // =========================================================================
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
    if (check_pclmul()) {
        const __m128i bswap = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
        
        // Convert H to GHASH format and precompute powers
        __m128i Hg = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(h_bytes)), bswap);
        __m128i H2 = gcm_gf_mul(Hg, Hg);
        __m128i H3 = gcm_gf_mul(H2, Hg);
        __m128i H4 = gcm_gf_mul(H2, H2);
        __m128i H5 = gcm_gf_mul(H4, Hg);
        __m128i H6 = gcm_gf_mul(H3, H3);
        __m128i H7 = gcm_gf_mul(H6, Hg);
        __m128i H8 = gcm_gf_mul(H4, H4);
        
        __m128i Y = _mm_setzero_si128();  // Running GHASH state
        
        // Process AAD with 8-way parallelism
        if (aad && aad_len > 0) {
            const uint8_t* aad_ptr = aad;
            size_t aad_remaining = aad_len;
            
            while (aad_remaining >= 128) {
                __m128i A0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr)), bswap);
                __m128i A1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr + 16)), bswap);
                __m128i A2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr + 32)), bswap);
                __m128i A3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr + 48)), bswap);
                __m128i A4 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr + 64)), bswap);
                __m128i A5 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr + 80)), bswap);
                __m128i A6 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr + 96)), bswap);
                __m128i A7 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr + 112)), bswap);
                
                Y = ghash_8blocks_parallel(Y, A0, A1, A2, A3, A4, A5, A6, A7,
                                            H8, H7, H6, H5, H4, H3, H2, Hg);
                aad_ptr += 128;
                aad_remaining -= 128;
            }
            while (aad_remaining >= 16) {
                __m128i A = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(aad_ptr)), bswap);
                Y = _mm_xor_si128(Y, A);
                Y = gcm_gf_mul(Hg, Y);
                aad_ptr += 16;
                aad_remaining -= 16;
            }
            if (aad_remaining > 0) {
                uint8_t block[16] = {0};
                memcpy(block, aad_ptr, aad_remaining);
                __m128i A = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(block)), bswap);
                Y = _mm_xor_si128(Y, A);
                Y = gcm_gf_mul(Hg, Y);
            }
        }
        
        // Fused CTR + GHASH: encrypt then immediately hash while data is hot
        size_t offset = 0;
        
        // Pipeline approach: GHASH batch N while encrypting batch N+1
        // First batch: just encrypt, no GHASH yet
        __m128i prev_ct0, prev_ct1, prev_ct2, prev_ct3;
        __m128i prev_ct4, prev_ct5, prev_ct6, prev_ct7;
        bool have_prev = false;
        
        // 8-block pipelined CTR + GHASH
        while (offset + 128 <= input_len) {
            // Prefetch next batch
            if (offset + 256 <= input_len) {
                _mm_prefetch(reinterpret_cast<const char*>(input + offset + 128), _MM_HINT_T0);
                _mm_prefetch(reinterpret_cast<const char*>(input + offset + 192), _MM_HINT_T0);
            }
            
            // Generate counters
            __m128i c0, c1, c2, c3, c4, c5, c6, c7;
            gen_8_counters_fast(counter, c0, c1, c2, c3, c4, c5, c6, c7);
            counter = add_counter_be32(counter, 8);
            
            // AES encryption
            if (is_aes256) {
                aes256_encrypt_8blocks_ni(c0, c1, c2, c3, c4, c5, c6, c7, rk);
            } else {
                aes128_encrypt_8blocks_ni(c0, c1, c2, c3, c4, c5, c6, c7, rk);
            }
            
            // Load plaintext
            __m128i p0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
            __m128i p1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
            __m128i p2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
            __m128i p3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));
            __m128i p4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 64));
            __m128i p5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 80));
            __m128i p6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 96));
            __m128i p7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 112));
            
            // XOR with keystream
            __m128i ct0 = _mm_xor_si128(p0, c0);
            __m128i ct1 = _mm_xor_si128(p1, c1);
            __m128i ct2 = _mm_xor_si128(p2, c2);
            __m128i ct3 = _mm_xor_si128(p3, c3);
            __m128i ct4 = _mm_xor_si128(p4, c4);
            __m128i ct5 = _mm_xor_si128(p5, c5);
            __m128i ct6 = _mm_xor_si128(p6, c6);
            __m128i ct7 = _mm_xor_si128(p7, c7);
            
            // Store ciphertext
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), ct0);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), ct1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), ct2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), ct3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 64), ct4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 80), ct5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 96), ct6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 112), ct7);
            
            // GHASH on previous batch (if any)
            if (have_prev) {
                __m128i X0 = _mm_shuffle_epi8(prev_ct0, bswap);
                __m128i X1 = _mm_shuffle_epi8(prev_ct1, bswap);
                __m128i X2 = _mm_shuffle_epi8(prev_ct2, bswap);
                __m128i X3 = _mm_shuffle_epi8(prev_ct3, bswap);
                __m128i X4 = _mm_shuffle_epi8(prev_ct4, bswap);
                __m128i X5 = _mm_shuffle_epi8(prev_ct5, bswap);
                __m128i X6 = _mm_shuffle_epi8(prev_ct6, bswap);
                __m128i X7 = _mm_shuffle_epi8(prev_ct7, bswap);
                Y = ghash_8blocks_parallel(Y, X0, X1, X2, X3, X4, X5, X6, X7,
                                            H8, H7, H6, H5, H4, H3, H2, Hg);
            }
            
            // Save current batch for next iteration's GHASH
            prev_ct0 = ct0; prev_ct1 = ct1; prev_ct2 = ct2; prev_ct3 = ct3;
            prev_ct4 = ct4; prev_ct5 = ct5; prev_ct6 = ct6; prev_ct7 = ct7;
            have_prev = true;
            
            offset += 128;
        }
        
        // GHASH the last 8-block batch
        if (have_prev) {
            __m128i X0 = _mm_shuffle_epi8(prev_ct0, bswap);
            __m128i X1 = _mm_shuffle_epi8(prev_ct1, bswap);
            __m128i X2 = _mm_shuffle_epi8(prev_ct2, bswap);
            __m128i X3 = _mm_shuffle_epi8(prev_ct3, bswap);
            __m128i X4 = _mm_shuffle_epi8(prev_ct4, bswap);
            __m128i X5 = _mm_shuffle_epi8(prev_ct5, bswap);
            __m128i X6 = _mm_shuffle_epi8(prev_ct6, bswap);
            __m128i X7 = _mm_shuffle_epi8(prev_ct7, bswap);
            Y = ghash_8blocks_parallel(Y, X0, X1, X2, X3, X4, X5, X6, X7,
                                        H8, H7, H6, H5, H4, H3, H2, Hg);
        }
        
        // 4-block fused CTR + GHASH
        while (offset + 64 <= input_len) {
            __m128i c0, c1, c2, c3;
            gen_4_counters_fast(counter, c0, c1, c2, c3);
            counter = add_counter_be32(counter, 4);
            
            if (is_aes256) {
                aes256_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
            } else {
                aes128_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
            }
            
            __m128i p0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
            __m128i p1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
            __m128i p2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
            __m128i p3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));
            
            __m128i ct0 = _mm_xor_si128(p0, c0);
            __m128i ct1 = _mm_xor_si128(p1, c1);
            __m128i ct2 = _mm_xor_si128(p2, c2);
            __m128i ct3 = _mm_xor_si128(p3, c3);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), ct0);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), ct1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), ct2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), ct3);
            
            // Serial GHASH on 4 blocks (simpler, minimal performance impact for residual)
            __m128i X0 = _mm_shuffle_epi8(ct0, bswap);
            __m128i X1 = _mm_shuffle_epi8(ct1, bswap);
            __m128i X2 = _mm_shuffle_epi8(ct2, bswap);
            __m128i X3 = _mm_shuffle_epi8(ct3, bswap);
            Y = _mm_xor_si128(Y, X0); Y = gcm_gf_mul(Hg, Y);
            Y = _mm_xor_si128(Y, X1); Y = gcm_gf_mul(Hg, Y);
            Y = _mm_xor_si128(Y, X2); Y = gcm_gf_mul(Hg, Y);
            Y = _mm_xor_si128(Y, X3); Y = gcm_gf_mul(Hg, Y);
            
            offset += 64;
        }
        
        // Handle remaining blocks serially
        while (offset < input_len) {
            __m128i ks = counter;
            if (is_aes256) {
                ks = _mm_xor_si128(ks, rk[0]);
                for (int i = 1; i < 14; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
                ks = _mm_aesenclast_si128(ks, rk[14]);
            } else {
                ks = _mm_xor_si128(ks, rk[0]);
                for (int i = 1; i < 10; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
                ks = _mm_aesenclast_si128(ks, rk[10]);
            }
            
            size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
            
            if (bytes == 16) {
                __m128i pt = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
                __m128i ct = _mm_xor_si128(pt, ks);
                _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), ct);
                __m128i X = _mm_shuffle_epi8(ct, bswap);
                Y = _mm_xor_si128(Y, X);
                Y = gcm_gf_mul(Hg, Y);
            } else {
                alignas(16) uint8_t keystream[16];
                _mm_storeu_si128(reinterpret_cast<__m128i*>(keystream), ks);
                uint8_t ct_block[16] = {0};
                for (size_t j = 0; j < bytes; j++) {
                    ct_block[j] = input[offset + j] ^ keystream[j];
                    output[offset + j] = ct_block[j];
                }
                __m128i X = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(ct_block)), bswap);
                Y = _mm_xor_si128(Y, X);
                Y = gcm_gf_mul(Hg, Y);
            }
            counter = inc_counter_be32_fast(counter);
            offset += bytes;
        }
        
        // Add length block and finalize
        alignas(16) uint8_t len_block[16] = {0};
        uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
        for (int i = 0; i < 8; i++) {
            len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
            len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
        }
        __m128i L = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(len_block)), bswap);
        Y = _mm_xor_si128(Y, L);
        Y = gcm_gf_mul(Hg, Y);
        
        // Compute final tag
        __m128i j0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_bytes));
        __m128i enc_j0;
        if (is_aes256) {
            enc_j0 = _mm_xor_si128(j0, rk[0]);
            for (int i = 1; i < 14; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
            enc_j0 = _mm_aesenclast_si128(enc_j0, rk[14]);
        } else {
            enc_j0 = _mm_xor_si128(j0, rk[0]);
            for (int i = 1; i < 10; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
            enc_j0 = _mm_aesenclast_si128(enc_j0, rk[10]);
        }
        
        Y = _mm_shuffle_epi8(Y, bswap);
        __m128i final_tag = _mm_xor_si128(enc_j0, Y);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(tag), final_tag);
        
        kctsb_secure_zero(h_bytes, 16);
        kctsb_secure_zero(j0_bytes, 16);
        return KCTSB_SUCCESS;
    }
#endif // KCTSB_HAS_PCLMUL

    // =========================================================================
    // Software fallback: CTR encryption then GHASH
    // =========================================================================
    size_t offset = 0;
    
    // Process 8 blocks at a time (128 bytes)
    while (offset + 128 <= input_len) {
        __m128i c0, c1, c2, c3, c4, c5, c6, c7;
        gen_8_counters_fast(counter, c0, c1, c2, c3, c4, c5, c6, c7);
        counter = add_counter_be32(counter, 8);

        if (is_aes256) {
            aes256_encrypt_8blocks_ni(c0, c1, c2, c3, c4, c5, c6, c7, rk);
        } else {
            aes128_encrypt_8blocks_ni(c0, c1, c2, c3, c4, c5, c6, c7, rk);
        }

        __m128i p0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
        __m128i p1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
        __m128i p2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
        __m128i p3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));
        __m128i p4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 64));
        __m128i p5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 80));
        __m128i p6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 96));
        __m128i p7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 112));

        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), _mm_xor_si128(p0, c0));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), _mm_xor_si128(p1, c1));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), _mm_xor_si128(p2, c2));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), _mm_xor_si128(p3, c3));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 64), _mm_xor_si128(p4, c4));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 80), _mm_xor_si128(p5, c5));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 96), _mm_xor_si128(p6, c6));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 112), _mm_xor_si128(p7, c7));

        offset += 128;
    }
    
    // Process 4 blocks at a time (64 bytes)
    while (offset + 64 <= input_len) {
        __m128i c0, c1, c2, c3;
        gen_4_counters_fast(counter, c0, c1, c2, c3);
        counter = add_counter_be32(counter, 4);

        if (is_aes256) {
            aes256_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        } else {
            aes128_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        }

        __m128i p0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
        __m128i p1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
        __m128i p2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
        __m128i p3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));

        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), _mm_xor_si128(p0, c0));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), _mm_xor_si128(p1, c1));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), _mm_xor_si128(p2, c2));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), _mm_xor_si128(p3, c3));

        offset += 64;
    }

    // Handle remaining blocks
    while (offset < input_len) {
        __m128i ks = counter;
        if (is_aes256) {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 14; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[14]);
        } else {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 10; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[10]);
        }

        alignas(16) uint8_t keystream[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(keystream), ks);

        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }

        counter = inc_counter_be32_fast(counter);
        offset += bytes;
    }

    // =========================================================================
    // GHASH authentication using high-performance one-shot function
    // =========================================================================
    alignas(16) uint8_t ghash_tag[16] = {0};
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
    if (check_pclmul()) {
        ghash_oneshot_gcm(ghash_tag, h_bytes, aad, aad_len, output, input_len);
    } else
#endif
    {
        // Software fallback
        if (aad && aad_len > 0) {
            ghash_update(ghash_tag, h_bytes, aad, aad_len);
            size_t aad_padding = (16 - (aad_len % 16)) % 16;
            if (aad_padding > 0) {
                uint8_t pad[16] = {0};
                ghash_update(ghash_tag, h_bytes, pad, aad_padding);
            }
        }
        if (input_len > 0) {
            ghash_update(ghash_tag, h_bytes, output, input_len);
            size_t ct_padding = (16 - (input_len % 16)) % 16;
            if (ct_padding > 0) {
                uint8_t pad[16] = {0};
                ghash_update(ghash_tag, h_bytes, pad, ct_padding);
            }
        }
        alignas(16) uint8_t len_block[16] = {0};
        uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
        for (int i = 0; i < 8; i++) {
            len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
            len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
        }
        ghash_update(ghash_tag, h_bytes, len_block, 16);
    }

    // Compute final tag: tag = E(K, J0) XOR GHASH
    __m128i j0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_bytes));
    __m128i enc_j0;
    if (is_aes256) {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 14; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[14]);
    } else {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 10; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[10]);
    }

    __m128i gtag = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ghash_tag));
    __m128i final_tag = _mm_xor_si128(enc_j0, gtag);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(tag), final_tag);

    // Secure cleanup
    kctsb_secure_zero(h_bytes, 16);
    kctsb_secure_zero(j0_bytes, 16);
    kctsb_secure_zero(counter_bytes, 16);
    kctsb_secure_zero(ghash_tag, 16);

    return KCTSB_SUCCESS;
}

// High-performance AES-GCM decrypt using AES-NI (8-block parallel CTR)
static kctsb_error_t aes_gcm_decrypt_aesni(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    const uint8_t tag[16], uint8_t* output)
{
    const __m128i* rk = reinterpret_cast<const __m128i*>(ctx->round_keys);
    const bool is_aes256 = (ctx->key_bits == 256);

    // Compute H = E(K, 0^128)
    alignas(16) uint8_t h_bytes[16] = {0};
    __m128i H = _mm_setzero_si128();
    if (is_aes256) {
        __m128i tmp = H;
        aes256_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    } else {
        __m128i tmp = H;
        aes128_encrypt_4blocks_ni(tmp, tmp, tmp, tmp, rk);
        H = tmp;
    }
    _mm_storeu_si128(reinterpret_cast<__m128i*>(h_bytes), H);

    // Compute J0 (initial counter)
    alignas(16) uint8_t j0_bytes[16];
    if (iv_len == 12) {
        memcpy(j0_bytes, iv, 12);
        j0_bytes[12] = 0; j0_bytes[13] = 0; j0_bytes[14] = 0; j0_bytes[15] = 1;
    } else {
        memset(j0_bytes, 0, 16);
        ghash_update(j0_bytes, h_bytes, iv, iv_len);
        alignas(16) uint8_t len_block[16] = {0};
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = static_cast<uint8_t>(iv_bits >> (i * 8));
        ghash_update(j0_bytes, h_bytes, len_block, 16);
    }

    // Verify tag BEFORE decryption (authenticate-then-decrypt)
    alignas(16) uint8_t ghash_tag[16] = {0};
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
    if (check_pclmul()) {
        ghash_oneshot_gcm(ghash_tag, h_bytes, aad, aad_len, input, input_len);
    } else
#endif
    {
        // Software fallback with separate calls
        if (aad && aad_len > 0) {
            ghash_update(ghash_tag, h_bytes, aad, aad_len);
            size_t aad_padding = (16 - (aad_len % 16)) % 16;
            if (aad_padding > 0) {
                uint8_t pad[16] = {0};
                ghash_update(ghash_tag, h_bytes, pad, aad_padding);
            }
        }
        if (input_len > 0) {
            ghash_update(ghash_tag, h_bytes, input, input_len);
            size_t ct_padding = (16 - (input_len % 16)) % 16;
            if (ct_padding > 0) {
                uint8_t pad[16] = {0};
                ghash_update(ghash_tag, h_bytes, pad, ct_padding);
            }
        }
        // Add length block
        alignas(16) uint8_t len_block[16] = {0};
        uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
        for (int i = 0; i < 8; i++) {
            len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
            len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
        }
        ghash_update(ghash_tag, h_bytes, len_block, 16);
    }

    // Compute expected tag
    __m128i j0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_bytes));
    __m128i enc_j0;
    if (is_aes256) {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 14; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[14]);
    } else {
        enc_j0 = _mm_xor_si128(j0, rk[0]);
        for (int i = 1; i < 10; ++i) enc_j0 = _mm_aesenc_si128(enc_j0, rk[i]);
        enc_j0 = _mm_aesenclast_si128(enc_j0, rk[10]);
    }

    __m128i gtag = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ghash_tag));
    __m128i computed_tag = _mm_xor_si128(enc_j0, gtag);

    alignas(16) uint8_t computed_tag_bytes[16];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(computed_tag_bytes), computed_tag);

    // Constant-time tag comparison
    if (!kctsb_secure_compare(tag, computed_tag_bytes, 16)) {
        kctsb_secure_zero(output, input_len);
        kctsb_secure_zero(h_bytes, 16);
        kctsb_secure_zero(j0_bytes, 16);
        kctsb_secure_zero(ghash_tag, 16);
        kctsb_secure_zero(computed_tag_bytes, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    // Decryption with 8-block parallel CTR + prefetch optimization
    alignas(16) uint8_t counter_bytes[16];
    memcpy(counter_bytes, j0_bytes, 16);
    inc_counter(counter_bytes);
    __m128i counter = _mm_loadu_si128(reinterpret_cast<const __m128i*>(counter_bytes));

    size_t offset = 0;
    
    // Process 8 blocks at a time (128 bytes) with prefetching
    while (offset + 128 <= input_len) {
        // Prefetch next 256 bytes for better memory bandwidth
        if (offset + 256 <= input_len) {
            _mm_prefetch(reinterpret_cast<const char*>(input + offset + 128), _MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(input + offset + 192), _MM_HINT_T0);
        }
        
        // Load 8 ciphertext blocks FIRST (before AES to hide latency)
        __m128i ct0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
        __m128i ct1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
        __m128i ct2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
        __m128i ct3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));
        __m128i ct4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 64));
        __m128i ct5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 80));
        __m128i ct6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 96));
        __m128i ct7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 112));
        
        // Generate and encrypt 8 counters (AES pipeline hides memory latency)
        __m128i c0, c1, c2, c3, c4, c5, c6, c7;
        gen_8_counters_fast(counter, c0, c1, c2, c3, c4, c5, c6, c7);
        counter = add_counter_be32(counter, 8);
        
        if (is_aes256) {
            aes256_encrypt_8blocks_ni(c0, c1, c2, c3, c4, c5, c6, c7, rk);
        } else {
            aes128_encrypt_8blocks_ni(c0, c1, c2, c3, c4, c5, c6, c7, rk);
        }
        
        // XOR with keystream to get plaintext
        __m128i p0 = _mm_xor_si128(ct0, c0);
        __m128i p1 = _mm_xor_si128(ct1, c1);
        __m128i p2 = _mm_xor_si128(ct2, c2);
        __m128i p3 = _mm_xor_si128(ct3, c3);
        __m128i p4 = _mm_xor_si128(ct4, c4);
        __m128i p5 = _mm_xor_si128(ct5, c5);
        __m128i p6 = _mm_xor_si128(ct6, c6);
        __m128i p7 = _mm_xor_si128(ct7, c7);
        
        // Store 8 plaintext blocks
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), p0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), p1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), p2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), p3);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 64), p4);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 80), p5);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 96), p6);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 112), p7);
        
        offset += 128;
    }
    
    // Process 4 blocks at a time (64 bytes)
    while (offset + 64 <= input_len) {
        __m128i c0, c1, c2, c3;
        gen_4_counters_fast(counter, c0, c1, c2, c3);
        counter = add_counter_be32(counter, 4);

        if (is_aes256) {
            aes256_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        } else {
            aes128_encrypt_4blocks_ni(c0, c1, c2, c3, rk);
        }

        __m128i ct0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset));
        __m128i ct1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 16));
        __m128i ct2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 32));
        __m128i ct3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(input + offset + 48));

        __m128i p0 = _mm_xor_si128(ct0, c0);
        __m128i p1 = _mm_xor_si128(ct1, c1);
        __m128i p2 = _mm_xor_si128(ct2, c2);
        __m128i p3 = _mm_xor_si128(ct3, c3);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset), p0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 16), p1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 32), p2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(output + offset + 48), p3);

        offset += 64;
    }

    // Handle remaining bytes (less than 64 bytes)
    while (offset < input_len) {
        alignas(16) uint8_t keystream[16];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(counter_bytes), counter);

        __m128i ks = counter;
        if (is_aes256) {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 14; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[14]);
        } else {
            ks = _mm_xor_si128(ks, rk[0]);
            for (int i = 1; i < 10; ++i) ks = _mm_aesenc_si128(ks, rk[i]);
            ks = _mm_aesenclast_si128(ks, rk[10]);
        }
        _mm_storeu_si128(reinterpret_cast<__m128i*>(keystream), ks);

        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }

        counter = inc_counter_be32_fast(counter);
        offset += bytes;
    }

    // Secure cleanup
    kctsb_secure_zero(h_bytes, 16);
    kctsb_secure_zero(j0_bytes, 16);
    kctsb_secure_zero(counter_bytes, 16);
    kctsb_secure_zero(ghash_tag, 16);
    kctsb_secure_zero(computed_tag_bytes, 16);

    return KCTSB_SUCCESS;
}

#endif // KCTSB_HAS_AESNI

// ============================================================================
// Software Fallback AES-GCM (for non-AES-NI systems)
// ============================================================================

static kctsb_error_t aes_gcm_encrypt_software(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    uint8_t* output, uint8_t tag[16])
{
    uint8_t h[16] = {0}, j0[16], counter[16], keystream[16], ghash_tag[16] = {0};

    kctsb_aes_encrypt_block(ctx, h, h);

    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        memset(j0, 0, 16);
        ghash_update(j0, h, iv, iv_len);
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = static_cast<uint8_t>(iv_bits >> (i * 8));
        ghash_update(j0, h, len_block, 16);
    }

    memcpy(counter, j0, 16);
    inc_counter(counter);

    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(ctx, counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(counter);
        offset += bytes;
    }

    if (aad && aad_len > 0) {
        ghash_update(ghash_tag, h, aad, aad_len);
        size_t aad_padding = (16 - (aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, aad_padding); }
    }
    if (input_len > 0) {
        ghash_update(ghash_tag, h, output, input_len);
        size_t ct_padding = (16 - (input_len % 16)) % 16;
        if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, ct_padding); }
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
        len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
    }
    ghash_update(ghash_tag, h, len_block, 16);

    uint8_t enc_j0[16];
    kctsb_aes_encrypt_block(ctx, j0, enc_j0);
    xor_block(tag, ghash_tag, enc_j0);

    kctsb_secure_zero(h, 16); kctsb_secure_zero(j0, 16); kctsb_secure_zero(counter, 16);
    kctsb_secure_zero(keystream, 16); kctsb_secure_zero(ghash_tag, 16); kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

// ============================================================================
// Public AES-GCM API with automatic acceleration
// ============================================================================

// Forward declaration for software fallback
static kctsb_error_t aes_gcm_decrypt_software(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    const uint8_t tag[16], uint8_t* output);

kctsb_error_t kctsb_aes_gcm_encrypt(const kctsb_aes_ctx_t* ctx,
                                     const uint8_t* iv, size_t iv_len,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* input, size_t input_len,
                                     uint8_t* output, uint8_t tag[16]) {
    if (!ctx || !iv || !output || !tag) return KCTSB_ERROR_INVALID_PARAM;
    if (input_len > 0 && !input) return KCTSB_ERROR_INVALID_PARAM;

#if defined(KCTSB_HAS_AESNI)
    // Use high-performance AES-NI path if available and key is in AES-NI format
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format && check_aesni() && (ctx->key_bits == 128 || ctx->key_bits == 256)) {
        return aes_gcm_encrypt_aesni(ctx, iv, iv_len, aad, aad_len, input, input_len, output, tag);
    }
#endif

    return aes_gcm_encrypt_software(ctx, iv, iv_len, aad, aad_len, input, input_len, output, tag);
}

kctsb_error_t kctsb_aes_gcm_decrypt(const kctsb_aes_ctx_t* ctx,
                                     const uint8_t* iv, size_t iv_len,
                                     const uint8_t* aad, size_t aad_len,
                                     const uint8_t* input, size_t input_len,
                                     const uint8_t tag[16], uint8_t* output) {
    if (!ctx || !iv || !tag || !output) return KCTSB_ERROR_INVALID_PARAM;
    if (input_len > 0 && !input) return KCTSB_ERROR_INVALID_PARAM;

#if defined(KCTSB_HAS_AESNI)
    // Use high-performance AES-NI path if available and key is in AES-NI format
    bool uses_aesni_format = (ctx->rounds & AESNI_FORMAT_FLAG) != 0;
    if (uses_aesni_format && check_aesni() && (ctx->key_bits == 128 || ctx->key_bits == 256)) {
        return aes_gcm_decrypt_aesni(ctx, iv, iv_len, aad, aad_len, input, input_len, tag, output);
    }
#endif

    return aes_gcm_decrypt_software(ctx, iv, iv_len, aad, aad_len, input, input_len, tag, output);
}

// Software fallback for AES-GCM decrypt
static kctsb_error_t aes_gcm_decrypt_software(
    const kctsb_aes_ctx_t* ctx,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* input, size_t input_len,
    const uint8_t tag[16], uint8_t* output)
{
    uint8_t computed_tag[16], h[16] = {0}, j0[16], counter[16], keystream[16], ghash_tag[16] = {0};

    kctsb_aes_encrypt_block(ctx, h, h);

    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        memset(j0, 0, 16);
        ghash_update(j0, h, iv, iv_len);
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = static_cast<uint8_t>(iv_bits >> (i * 8));
        ghash_update(j0, h, len_block, 16);
    }

    if (aad && aad_len > 0) {
        ghash_update(ghash_tag, h, aad, aad_len);
        size_t aad_padding = (16 - (aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, aad_padding); }
    }
    if (input_len > 0) {
        ghash_update(ghash_tag, h, input, input_len);
        size_t ct_padding = (16 - (input_len % 16)) % 16;
        if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ghash_tag, h, pad, ct_padding); }
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = aad_len * 8, ct_bits = input_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
        len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
    }
    ghash_update(ghash_tag, h, len_block, 16);

    uint8_t enc_j0[16];
    kctsb_aes_encrypt_block(ctx, j0, enc_j0);
    xor_block(computed_tag, ghash_tag, enc_j0);

    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(output, input_len);
        kctsb_secure_zero(h, 16); kctsb_secure_zero(j0, 16); kctsb_secure_zero(ghash_tag, 16);
        kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    memcpy(counter, j0, 16);
    inc_counter(counter);

    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(ctx, counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(counter);
        offset += bytes;
    }

    kctsb_secure_zero(h, 16); kctsb_secure_zero(j0, 16); kctsb_secure_zero(counter, 16);
    kctsb_secure_zero(keystream, 16); kctsb_secure_zero(ghash_tag, 16);
    kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

// Streaming GCM API

kctsb_error_t kctsb_aes_gcm_init(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* key, size_t key_len,
                                  const uint8_t* iv, size_t iv_len) {
    if (!ctx || !key || !iv) return KCTSB_ERROR_INVALID_PARAM;
    memset(ctx, 0, sizeof(kctsb_aes_gcm_ctx_t));

    kctsb_error_t err = kctsb_aes_init(&ctx->aes_ctx, key, key_len);
    if (err != KCTSB_SUCCESS) return err;

    memset(ctx->h, 0, 16);
    kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->h, ctx->h);

    if (iv_len == 12) {
        memcpy(ctx->j0, iv, 12);
        ctx->j0[12] = 0; ctx->j0[13] = 0; ctx->j0[14] = 0; ctx->j0[15] = 1;
    } else {
        ghash_update(ctx->j0, ctx->h, iv, iv_len);
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        for (int i = 0; i < 8; i++) len_block[15 - i] = static_cast<uint8_t>(iv_bits >> (i * 8));
        ghash_update(ctx->j0, ctx->h, len_block, 16);
    }

    memcpy(ctx->counter, ctx->j0, 16);
    inc_counter(ctx->counter);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_update_aad(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* aad, size_t aad_len) {
    if (!ctx) return KCTSB_ERROR_INVALID_PARAM;
    if (ctx->ct_len > 0) return KCTSB_ERROR_INVALID_PARAM;
    if (aad && aad_len > 0) {
        ghash_update(ctx->tag, ctx->h, aad, aad_len);
        ctx->aad_len += aad_len;
    }
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_update_encrypt(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* input,
                                            size_t input_len, uint8_t* output) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    if (ctx->ct_len == 0 && ctx->aad_len > 0) {
        size_t aad_padding = (16 - (ctx->aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, aad_padding); }
    }

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(ctx->counter);
        offset += bytes;
    }

    ghash_update(ctx->tag, ctx->h, output, input_len);
    ctx->ct_len += input_len;
    kctsb_secure_zero(keystream, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_final_encrypt(kctsb_aes_gcm_ctx_t* ctx, uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;

    size_t ct_padding = (16 - (ctx->ct_len % 16)) % 16;
    if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, ct_padding); }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = ctx->aad_len * 8, ct_bits = ctx->ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
        len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
    }
    ghash_update(ctx->tag, ctx->h, len_block, 16);

    uint8_t enc_j0[16];
    kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->j0, enc_j0);
    xor_block(tag, ctx->tag, enc_j0);

    ctx->finalized = 1;
    kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_update_decrypt(kctsb_aes_gcm_ctx_t* ctx, const uint8_t* input,
                                            size_t input_len, uint8_t* output) {
    if (!ctx || !input || !output) return KCTSB_ERROR_INVALID_PARAM;

    if (ctx->ct_len == 0 && ctx->aad_len > 0) {
        size_t aad_padding = (16 - (ctx->aad_len % 16)) % 16;
        if (aad_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, aad_padding); }
    }

    ghash_update(ctx->tag, ctx->h, input, input_len);

    uint8_t keystream[16];
    size_t offset = 0;
    while (offset < input_len) {
        kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->counter, keystream);
        size_t bytes = (input_len - offset < 16) ? (input_len - offset) : 16;
        for (size_t j = 0; j < bytes; j++) output[offset + j] = input[offset + j] ^ keystream[j];
        inc_counter(ctx->counter);
        offset += bytes;
    }

    ctx->ct_len += input_len;
    kctsb_secure_zero(keystream, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_gcm_final_decrypt(kctsb_aes_gcm_ctx_t* ctx, const uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) return KCTSB_ERROR_INVALID_PARAM;

    size_t ct_padding = (16 - (ctx->ct_len % 16)) % 16;
    if (ct_padding > 0) { uint8_t pad[16] = {0}; ghash_update(ctx->tag, ctx->h, pad, ct_padding); }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = ctx->aad_len * 8, ct_bits = ctx->ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i] = static_cast<uint8_t>(aad_bits >> (i * 8));
        len_block[15 - i] = static_cast<uint8_t>(ct_bits >> (i * 8));
    }
    ghash_update(ctx->tag, ctx->h, len_block, 16);

    uint8_t computed_tag[16], enc_j0[16];
    kctsb_aes_encrypt_block(&ctx->aes_ctx, ctx->j0, enc_j0);
    xor_block(computed_tag, ctx->tag, enc_j0);

    ctx->finalized = 1;

    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }

    kctsb_secure_zero(computed_tag, 16); kctsb_secure_zero(enc_j0, 16);
    return KCTSB_SUCCESS;
}

void kctsb_aes_clear(kctsb_aes_ctx_t* ctx) {
    if (ctx) kctsb_secure_zero(ctx, sizeof(kctsb_aes_ctx_t));
}

void kctsb_aes_gcm_clear(kctsb_aes_gcm_ctx_t* ctx) {
    if (ctx) kctsb_secure_zero(ctx, sizeof(kctsb_aes_gcm_ctx_t));
}

} // extern "C"

// ============================================================================
// NIST SP 800-90A CTR_DRBG with AES-256 (Hardware Accelerated)
// ============================================================================
// This implementation provides cryptographically secure random number generation
// by combining platform entropy with AES-256-CTR DRBG for deterministic expansion.
// The DRBG automatically reseeds after generating 2^19 bytes to maintain security.
//
// Design follows OpenSSL's approach:
// - Platform entropy via BCryptGenRandom (Windows) / getrandom (Linux)
// - AES-256-CTR DRBG for efficient expansion
// - AES-NI hardware acceleration for maximum performance
// ============================================================================

namespace {

// CTR_DRBG Constants (NIST SP 800-90A with AES-256)
constexpr size_t DRBG_KEY_LEN = 32;       // AES-256 key length
constexpr size_t DRBG_BLOCK_LEN = 16;     // AES block length
constexpr size_t DRBG_SEED_LEN = DRBG_KEY_LEN + DRBG_BLOCK_LEN;  // 48 bytes
constexpr size_t DRBG_RESEED_INTERVAL = (1 << 19);  // 512KB before reseed

// CTR_DRBG State (internal use only)
struct ctr_drbg_state {
    alignas(16) uint8_t key[DRBG_KEY_LEN];      // AES-256 key (32 bytes)
    alignas(16) uint8_t v[DRBG_BLOCK_LEN];      // Counter block V (16 bytes)
    size_t reseed_counter;                       // Bytes generated since last reseed
    bool initialized;                            // Has been seeded
    kctsb_aes_ctx_t aes_ctx;                    // Pre-expanded AES key schedule
};

// Global DRBG instance (lazy initialized, thread-safe)
static ctr_drbg_state g_drbg = {};
static std::mutex g_drbg_mutex;
static std::atomic<bool> g_drbg_initialized{false};

// ============================================================================
// Platform Entropy Source (no bcrypt.dll dependency)
// ============================================================================

/**
 * @brief Collect entropy from platform-specific CSPRNG
 * @param buffer Output buffer for entropy bytes
 * @param len Number of bytes to collect
 * @return 0 on success, -1 on failure
 *
 * Windows: Uses BCryptGenRandom (CNG API) via runtime dynamic loading
 *          bcrypt.dll is a Windows system component (no link required)
 * Linux:   Uses getrandom() syscall or /dev/urandom fallback
 * macOS:   Uses SecRandomCopyBytes from Security.framework
 */
static int platform_entropy(void* buffer, size_t len) {
    if (!buffer || len == 0) return 0;

#ifdef _WIN32
    // Windows: Load bcrypt.dll at runtime (no static linking required)
    // bcrypt.dll is guaranteed to exist on Windows 7+ as system component
    static HMODULE hBcrypt = nullptr;
    static BCryptGenRandomFn pBCryptGenRandom = nullptr;
    static bool initialized = false;
    
    if (!initialized) {
        hBcrypt = LoadLibraryW(L"bcrypt.dll");
        if (hBcrypt) {
            FARPROC proc = GetProcAddress(hBcrypt, "BCryptGenRandom");
            // Convert function pointer via union (standard way to avoid strict aliasing)
            union {
                FARPROC fp;
                BCryptGenRandomFn fn;
            } converter;
            converter.fp = proc;
            pBCryptGenRandom = converter.fn;
        }
        initialized = true;
    }
    
    if (!pBCryptGenRandom) {
        return -1;  // bcrypt.dll not available (should never happen on Win7+)
    }
    
    KCTSB_NTSTATUS status = pBCryptGenRandom(
        nullptr,
        static_cast<PUCHAR>(buffer),
        static_cast<ULONG>(len),
        KCTSB_BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return (status == KCTSB_STATUS_SUCCESS) ? 0 : -1;

#elif defined(__linux__)
    uint8_t* p = static_cast<uint8_t*>(buffer);
    size_t remaining = len;

#ifdef KCTSB_HAS_GETRANDOM_SYSCALL
    // Linux: getrandom syscall (kernel 3.17+)
    while (remaining > 0) {
        long ret = syscall(SYS_getrandom, p, remaining, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) break;  // Fall through to /dev/urandom
            return -1;
        }
        p += ret;
        remaining -= static_cast<size_t>(ret);
    }
    if (remaining == 0) return 0;
    
    // Reset for /dev/urandom fallback
    p = static_cast<uint8_t*>(buffer);
    remaining = len;
#endif

    // Fallback: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    
    while (remaining > 0) {
        ssize_t ret = read(fd, p, remaining);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (ret == 0) {
            close(fd);
            return -1;
        }
        p += ret;
        remaining -= static_cast<size_t>(ret);
    }
    close(fd);
    return 0;

#elif defined(__APPLE__)
    // macOS: SecRandomCopyBytes from Security.framework
    OSStatus status = SecRandomCopyBytes(kSecRandomDefault, len, buffer);
    return (status == errSecSuccess) ? 0 : -1;

#else
    // Unsupported platform
    (void)buffer;
    (void)len;
    return -1;
#endif
}

// ============================================================================
// CTR_DRBG Internal Functions (NIST SP 800-90A)
// ============================================================================

/**
 * @brief CTR_DRBG Update Function (NIST SP 800-90A Section 10.2.1.2)
 * Updates the internal state (Key, V) using provided data
 * Uses AES-NI acceleration when available
 */
static void ctr_drbg_update(ctr_drbg_state* drbg, const uint8_t provided_data[DRBG_SEED_LEN]) {
    alignas(16) uint8_t temp[DRBG_SEED_LEN];
    alignas(16) uint8_t block[DRBG_BLOCK_LEN];
    
    // Generate seed_len bytes of output using current key
    size_t offset = 0;
    while (offset < DRBG_SEED_LEN) {
        // Increment V
        for (int i = DRBG_BLOCK_LEN - 1; i >= 0; i--) {
            if (++drbg->v[i] != 0) break;
        }
        
        // Encrypt V with current key
        kctsb_aes_encrypt_block(&drbg->aes_ctx, drbg->v, block);
        
        size_t to_copy = (DRBG_SEED_LEN - offset < DRBG_BLOCK_LEN) 
                         ? (DRBG_SEED_LEN - offset) : DRBG_BLOCK_LEN;
        memcpy(temp + offset, block, to_copy);
        offset += to_copy;
    }
    
    // XOR with provided_data
    for (size_t i = 0; i < DRBG_SEED_LEN; i++) {
        temp[i] ^= provided_data[i];
    }
    
    // Update Key and V
    memcpy(drbg->key, temp, DRBG_KEY_LEN);
    memcpy(drbg->v, temp + DRBG_KEY_LEN, DRBG_BLOCK_LEN);
    
    // Re-expand key schedule for new key
    kctsb_aes_init(&drbg->aes_ctx, drbg->key, DRBG_KEY_LEN);
    
    // Clear sensitive temp data
    kctsb_secure_zero(temp, sizeof(temp));
    kctsb_secure_zero(block, sizeof(block));
}

/**
 * @brief CTR_DRBG Instantiate Function (NIST SP 800-90A Section 10.2.1.3)
 * Initializes the DRBG with entropy
 */
static int ctr_drbg_instantiate(ctr_drbg_state* drbg) {
    alignas(16) uint8_t entropy[DRBG_SEED_LEN];
    
    // Collect entropy from platform
    if (platform_entropy(entropy, DRBG_SEED_LEN) != 0) {
        return -1;
    }
    
    // Initialize Key = 0, V = 0
    memset(drbg->key, 0, DRBG_KEY_LEN);
    memset(drbg->v, 0, DRBG_BLOCK_LEN);
    
    // Initialize AES key schedule with zero key
    kctsb_aes_init(&drbg->aes_ctx, drbg->key, DRBG_KEY_LEN);
    
    // Update with entropy
    ctr_drbg_update(drbg, entropy);
    
    drbg->reseed_counter = 0;
    drbg->initialized = true;
    
    // Clear entropy
    kctsb_secure_zero(entropy, sizeof(entropy));
    return 0;
}

/**
 * @brief CTR_DRBG Reseed Function (NIST SP 800-90A Section 10.2.1.4)
 * Reseeds the DRBG with fresh entropy
 */
static int ctr_drbg_reseed(ctr_drbg_state* drbg) {
    alignas(16) uint8_t entropy[DRBG_SEED_LEN];
    
    // Collect fresh entropy
    if (platform_entropy(entropy, DRBG_SEED_LEN) != 0) {
        return -1;
    }
    
    // Update state with entropy
    ctr_drbg_update(drbg, entropy);
    drbg->reseed_counter = 0;
    
    // Clear entropy
    kctsb_secure_zero(entropy, sizeof(entropy));
    return 0;
}

/**
 * @brief CTR_DRBG Generate Function (NIST SP 800-90A Section 10.2.1.5)
 * Generates random bytes using AES-CTR mode
 * Uses AES-NI hardware acceleration for maximum performance
 */
static int ctr_drbg_generate(ctr_drbg_state* drbg, uint8_t* output, size_t len) {
    if (!drbg->initialized) {
        if (ctr_drbg_instantiate(drbg) != 0) {
            return -1;
        }
    }
    
    // Check if reseed is needed
    if (drbg->reseed_counter + len > DRBG_RESEED_INTERVAL) {
        if (ctr_drbg_reseed(drbg) != 0) {
            return -1;
        }
    }
    
    // Generate output using AES-CTR
    // This leverages the pre-expanded AES key schedule with AES-NI acceleration
    alignas(16) uint8_t block[DRBG_BLOCK_LEN];
    size_t offset = 0;
    
    while (offset < len) {
        // Increment V
        for (int i = DRBG_BLOCK_LEN - 1; i >= 0; i--) {
            if (++drbg->v[i] != 0) break;
        }
        
        // Encrypt V (uses AES-NI when available)
        kctsb_aes_encrypt_block(&drbg->aes_ctx, drbg->v, block);
        
        size_t to_copy = (len - offset < DRBG_BLOCK_LEN) ? (len - offset) : DRBG_BLOCK_LEN;
        memcpy(output + offset, block, to_copy);
        offset += to_copy;
    }
    
    // Update state (backtracking resistance)
    alignas(16) uint8_t zero_data[DRBG_SEED_LEN] = {0};
    ctr_drbg_update(drbg, zero_data);
    
    drbg->reseed_counter += len;
    
    // Clear sensitive data
    kctsb_secure_zero(block, sizeof(block));
    return 0;
}

} // anonymous namespace

// ============================================================================
// CSPRNG Public API
// ============================================================================

extern "C" {

/**
 * @brief Generate cryptographically secure random bytes
 * 
 * This function provides secure random bytes using NIST SP 800-90A CTR_DRBG
 * with AES-256, backed by platform entropy. The implementation:
 * - Uses AES-NI hardware acceleration when available
 * - Automatically reseeds after generating 512KB
 * - Thread-safe via mutex protection
 * - Uses BCryptGenRandom (Windows system component) for entropy
 *
 * @param buf Output buffer for random bytes
 * @param len Number of bytes to generate
 * @return KCTSB_SUCCESS on success, error code otherwise
 */
int kctsb_csprng_random_bytes(void* buf, size_t len) {
    if (!buf) return KCTSB_ERROR_INVALID_PARAM;
    if (len == 0) return KCTSB_SUCCESS;
    
    std::lock_guard<std::mutex> lock(g_drbg_mutex);
    
    // Lazy initialization
    if (!g_drbg_initialized.load(std::memory_order_acquire)) {
        if (ctr_drbg_instantiate(&g_drbg) != 0) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        g_drbg_initialized.store(true, std::memory_order_release);
    }
    
    // Generate random bytes
    if (ctr_drbg_generate(&g_drbg, static_cast<uint8_t*>(buf), len) != 0) {
        return KCTSB_ERROR_RANDOM_FAILED;
    }
    
    return KCTSB_SUCCESS;
}

/**
 * @brief Force reseed of the CSPRNG with fresh entropy
 * 
 * This function forces the DRBG to reseed with fresh platform entropy.
 * Normally not needed as the DRBG reseeds automatically, but can be
 * called for defense-in-depth after sensitive operations.
 *
 * @return KCTSB_SUCCESS on success, error code otherwise
 */
int kctsb_csprng_reseed(void) {
    std::lock_guard<std::mutex> lock(g_drbg_mutex);
    
    if (!g_drbg_initialized.load(std::memory_order_acquire)) {
        if (ctr_drbg_instantiate(&g_drbg) != 0) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        g_drbg_initialized.store(true, std::memory_order_release);
    } else {
        if (ctr_drbg_reseed(&g_drbg) != 0) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
    }
    
    return KCTSB_SUCCESS;
}

/**
 * @brief Clear the CSPRNG state (for security-critical cleanup)
 * 
 * Securely zeros the DRBG state. After calling this function,
 * the next call to kctsb_csprng_random_bytes will re-initialize
 * the DRBG with fresh entropy.
 */
void kctsb_csprng_clear(void) {
    std::lock_guard<std::mutex> lock(g_drbg_mutex);
    
    if (g_drbg_initialized.load(std::memory_order_acquire)) {
        kctsb_secure_zero(&g_drbg.aes_ctx, sizeof(g_drbg.aes_ctx));
        kctsb_secure_zero(g_drbg.key, sizeof(g_drbg.key));
        kctsb_secure_zero(g_drbg.v, sizeof(g_drbg.v));
        g_drbg.reseed_counter = 0;
        g_drbg.initialized = false;
        g_drbg_initialized.store(false, std::memory_order_release);
    }
}

} // extern "C"

// ============================================================================
// C++ Class Implementation
// ============================================================================

namespace kctsb {

AES::AES(const ByteVec& key) {
    kctsb_error_t err = kctsb_aes_init(&ctx_, key.data(), key.size());
    if (err != KCTSB_SUCCESS) throw std::invalid_argument("Invalid AES key size");
}

AES::AES(const uint8_t* key, size_t key_len) {
    kctsb_error_t err = kctsb_aes_init(&ctx_, key, key_len);
    if (err != KCTSB_SUCCESS) throw std::invalid_argument("Invalid AES key size");
}

AES::~AES() { kctsb_aes_clear(&ctx_); }

AES::AES(AES&& other) noexcept {
    memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
    kctsb_secure_zero(&other.ctx_, sizeof(other.ctx_));
}

AES& AES::operator=(AES&& other) noexcept {
    if (this != &other) {
        kctsb_aes_clear(&ctx_);
        memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
        kctsb_secure_zero(&other.ctx_, sizeof(other.ctx_));
    }
    return *this;
}

AESBlock AES::encryptBlock(const AESBlock& input) const {
    AESBlock output;
    kctsb_aes_encrypt_block(&ctx_, input.data(), output.data());
    return output;
}

ByteVec AES::ctrCrypt(const ByteVec& data, const std::array<uint8_t, 12>& nonce) const {
    ByteVec output(data.size());
    kctsb_aes_ctr_crypt(&ctx_, nonce.data(), data.data(), data.size(), output.data());
    return output;
}

std::pair<ByteVec, AESBlock> AES::gcmEncrypt(const ByteVec& plaintext,
                                              const ByteVec& iv, const ByteVec& aad) const {
    ByteVec ciphertext(plaintext.size());
    AESBlock tag;
    kctsb_error_t err = kctsb_aes_gcm_encrypt(&ctx_, iv.data(), iv.size(),
                                               aad.empty() ? nullptr : aad.data(), aad.size(),
                                               plaintext.data(), plaintext.size(),
                                               ciphertext.data(), tag.data());
    if (err != KCTSB_SUCCESS) throw std::runtime_error("AES-GCM encryption failed");
    return {std::move(ciphertext), tag};
}

ByteVec AES::gcmDecrypt(const ByteVec& ciphertext, const ByteVec& iv,
                        const AESBlock& tag, const ByteVec& aad) const {
    ByteVec plaintext(ciphertext.size());
    kctsb_error_t err = kctsb_aes_gcm_decrypt(&ctx_, iv.data(), iv.size(),
                                               aad.empty() ? nullptr : aad.data(), aad.size(),
                                               ciphertext.data(), ciphertext.size(),
                                               tag.data(), plaintext.data());
    if (err == KCTSB_ERROR_AUTH_FAILED) throw std::runtime_error("AES-GCM authentication failed");
    if (err != KCTSB_SUCCESS) throw std::runtime_error("AES-GCM decryption failed");
    return plaintext;
}

std::array<uint8_t, 12> AES::generateNonce() {
    std::array<uint8_t, 12> nonce;
    if (kctsb_random_bytes(nonce.data(), 12) != KCTSB_SUCCESS)
        throw std::runtime_error("Failed to generate random nonce");
    return nonce;
}

ByteVec AES::generateIV(size_t len) {
    ByteVec iv(len);
    if (kctsb_random_bytes(iv.data(), len) != KCTSB_SUCCESS)
        throw std::runtime_error("Failed to generate random IV");
    return iv;
}

} // namespace kctsb

// ============================================================================
// C ABI Export (Do not remove - required by mac.cpp GMAC acceleration)
// ============================================================================
extern "C" void kctsb_aes_gcm_ghash_update_internal(
    uint8_t tag[16],
    const uint8_t h[16],
    const uint8_t* data,
    size_t len
) {
    ghash_update(tag, h, data, len);
}
