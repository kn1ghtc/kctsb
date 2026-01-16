/**
 * @file sha3.cpp
 * @brief SHA3/Keccak Implementation - C++ Core + C ABI Export
 *
 * FIPS 202 compliant SHA3 implementation with AVX2 acceleration.
 * Architecture: C++ internal implementation + extern "C" API export.
 *
 * Features:
 * - SHA3-224/256/384/512 hash functions
 * - SHAKE128/256 extendable output functions
 * - AVX2 SIMD acceleration (runtime detection)
 * - Zero-copy processing where possible
 * - Memory-aligned state for optimal cache performance
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sha3.h"
#include "kctsb/core/common.h"
#include "kctsb/simd/simd.h"
#include <array>
#include <cstring>
#include <cstdint>

// 预取宏（编译器/平台自适应）
#if defined(__GNUC__) || defined(__clang__)
#define KCTSB_PREFETCH(addr) __builtin_prefetch((addr))
#else
#include <xmmintrin.h>
#define KCTSB_PREFETCH(addr) _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0)
#endif

#if defined(_MSC_VER)
#define KCTSB_RESTRICT __restrict
#elif defined(__GNUC__) || defined(__clang__)
#define KCTSB_RESTRICT __restrict__
#else
#define KCTSB_RESTRICT
#endif

// ============================================================================
// Compile-time feature detection
// ============================================================================

#if defined(__AVX2__)
#define KCTSB_HAS_AVX2_KECCAK 1
#include <immintrin.h>
#else
#define KCTSB_HAS_AVX2_KECCAK 0
#endif

// ============================================================================
// C++ Internal Implementation
// ============================================================================

namespace kctsb::internal {

/**
 * @brief Keccak round constants
 */
alignas(32) constexpr std::array<uint64_t, 24> KECCAK_RC = {
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

/**
 * @brief Rotation offsets for ρ step
 */
constexpr std::array<int, 25> KECCAK_RHO = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/**
 * @brief Runtime AVX2 detection
 */
class SIMDDetector {
public:
    [[nodiscard]] static bool has_avx2() noexcept {
        static const bool result = detect_avx2();
        return result;
    }

private:
    static bool detect_avx2() noexcept {
#if KCTSB_HAS_AVX2_KECCAK
        return kctsb::simd::has_feature(kctsb::simd::SIMDFeature::AVX2);
#else
        return false;
#endif
    }
};

/**
 * @brief 64-bit rotate left (force inline for hot path)
 */
__attribute__((always_inline))
static inline uint64_t rotl64(uint64_t x, int n) noexcept {
    // 使用内联并让编译器尽可能生成单条ROL指令；
    // 在GCC/Clang上，常量旋转通常可被识别为单条指令。
    return (x << n) | (x >> (64 - n));
}

/**
 * @brief Keccak-f[1600] state transformation class
 * 
 * Optimized implementation with:
 * - In-place theta/chi computation
 * - Lane-based rho_pi (single-pass)
 * - Inlined round functions
 */
class KeccakState {
public:
    alignas(32) std::array<uint64_t, 25> state{};

    /**
     * @brief Reset state to zero
     */
    void reset() noexcept {
        state.fill(0);
    }

    /**
     * @brief Apply Keccak-f[1600] permutation (fully unrolled 24 rounds)
     * 
     * Uses in-place computation to minimize temporary storage.
     * All 24 rounds fully unrolled for maximum performance.
     */
    __attribute__((hot, flatten))
    void permute() noexcept {
        uint64_t* A = state.data();
        
        // Temporary variables for theta and chi
        uint64_t C0, C1, C2, C3, C4, D0, D1, D2, D3, D4;
        uint64_t B0, B1, B2, B3, B4, B5, B6, B7, B8, B9;
        uint64_t B10, B11, B12, B13, B14, B15, B16, B17, B18, B19;
        uint64_t B20, B21, B22, B23, B24;
        
        // Macro for one complete round
        #define KECCAK_ROUND(rc) do { \
            C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20]; \
            C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21]; \
            C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22]; \
            C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23]; \
            C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24]; \
            D0 = C4 ^ rotl64(C1, 1); \
            D1 = C0 ^ rotl64(C2, 1); \
            D2 = C1 ^ rotl64(C3, 1); \
            D3 = C2 ^ rotl64(C4, 1); \
            D4 = C3 ^ rotl64(C0, 1); \
            A[0] ^= D0;  A[1] ^= D1;  A[2] ^= D2;  A[3] ^= D3;  A[4] ^= D4; \
            A[5] ^= D0;  A[6] ^= D1;  A[7] ^= D2;  A[8] ^= D3;  A[9] ^= D4; \
            A[10] ^= D0; A[11] ^= D1; A[12] ^= D2; A[13] ^= D3; A[14] ^= D4; \
            A[15] ^= D0; A[16] ^= D1; A[17] ^= D2; A[18] ^= D3; A[19] ^= D4; \
            A[20] ^= D0; A[21] ^= D1; A[22] ^= D2; A[23] ^= D3; A[24] ^= D4; \
            B0  = A[0]; \
            B1  = rotl64(A[6],  44); \
            B2  = rotl64(A[12], 43); \
            B3  = rotl64(A[18], 21); \
            B4  = rotl64(A[24], 14); \
            B5  = rotl64(A[3],  28); \
            B6  = rotl64(A[9],  20); \
            B7  = rotl64(A[10], 3); \
            B8  = rotl64(A[16], 45); \
            B9  = rotl64(A[22], 61); \
            B10 = rotl64(A[1],  1); \
            B11 = rotl64(A[7],  6); \
            B12 = rotl64(A[13], 25); \
            B13 = rotl64(A[19], 8); \
            B14 = rotl64(A[20], 18); \
            B15 = rotl64(A[4],  27); \
            B16 = rotl64(A[5],  36); \
            B17 = rotl64(A[11], 10); \
            B18 = rotl64(A[17], 15); \
            B19 = rotl64(A[23], 56); \
            B20 = rotl64(A[2],  62); \
            B21 = rotl64(A[8],  55); \
            B22 = rotl64(A[14], 39); \
            B23 = rotl64(A[15], 41); \
            B24 = rotl64(A[21], 2); \
            A[0]  = B0  ^ ((~B1)  & B2);  A[1]  = B1  ^ ((~B2)  & B3); \
            A[2]  = B2  ^ ((~B3)  & B4);  A[3]  = B3  ^ ((~B4)  & B0); \
            A[4]  = B4  ^ ((~B0)  & B1); \
            A[5]  = B5  ^ ((~B6)  & B7);  A[6]  = B6  ^ ((~B7)  & B8); \
            A[7]  = B7  ^ ((~B8)  & B9);  A[8]  = B8  ^ ((~B9)  & B5); \
            A[9]  = B9  ^ ((~B5)  & B6); \
            A[10] = B10 ^ ((~B11) & B12); A[11] = B11 ^ ((~B12) & B13); \
            A[12] = B12 ^ ((~B13) & B14); A[13] = B13 ^ ((~B14) & B10); \
            A[14] = B14 ^ ((~B10) & B11); \
            A[15] = B15 ^ ((~B16) & B17); A[16] = B16 ^ ((~B17) & B18); \
            A[17] = B17 ^ ((~B18) & B19); A[18] = B18 ^ ((~B19) & B15); \
            A[19] = B19 ^ ((~B15) & B16); \
            A[20] = B20 ^ ((~B21) & B22); A[21] = B21 ^ ((~B22) & B23); \
            A[22] = B22 ^ ((~B23) & B24); A[23] = B23 ^ ((~B24) & B20); \
            A[24] = B24 ^ ((~B20) & B21); \
            A[0] ^= (rc); \
        } while(0)

        // Fully unrolled 24 rounds with inline round constants
        KECCAK_ROUND(0x0000000000000001ULL);  // Round 0
        KECCAK_ROUND(0x0000000000008082ULL);  // Round 1
        KECCAK_ROUND(0x800000000000808aULL);  // Round 2
        KECCAK_ROUND(0x8000000080008000ULL);  // Round 3
        KECCAK_ROUND(0x000000000000808bULL);  // Round 4
        KECCAK_ROUND(0x0000000080000001ULL);  // Round 5
        KECCAK_ROUND(0x8000000080008081ULL);  // Round 6
        KECCAK_ROUND(0x8000000000008009ULL);  // Round 7
        KECCAK_ROUND(0x000000000000008aULL);  // Round 8
        KECCAK_ROUND(0x0000000000000088ULL);  // Round 9
        KECCAK_ROUND(0x0000000080008009ULL);  // Round 10
        KECCAK_ROUND(0x000000008000000aULL);  // Round 11
        KECCAK_ROUND(0x000000008000808bULL);  // Round 12
        KECCAK_ROUND(0x800000000000008bULL);  // Round 13
        KECCAK_ROUND(0x8000000000008089ULL);  // Round 14
        KECCAK_ROUND(0x8000000000008003ULL);  // Round 15
        KECCAK_ROUND(0x8000000000008002ULL);  // Round 16
        KECCAK_ROUND(0x8000000000000080ULL);  // Round 17
        KECCAK_ROUND(0x000000000000800aULL);  // Round 18
        KECCAK_ROUND(0x800000008000000aULL);  // Round 19
        KECCAK_ROUND(0x8000000080008081ULL);  // Round 20
        KECCAK_ROUND(0x8000000000008080ULL);  // Round 21
        KECCAK_ROUND(0x0000000080000001ULL);  // Round 22
        KECCAK_ROUND(0x8000000080008008ULL);  // Round 23

        #undef KECCAK_ROUND
    }

    /**
     * @brief XOR data into state (absorb)
     */
    void xor_block(const uint8_t* data, size_t rate_bytes) noexcept {
        // 优先采用64位lane批量XOR；在AVX2可用时，使用向量化memxor加速。
#if KCTSB_HAS_AVX2_KECCAK
        if (SIMDDetector::has_avx2()) {
            // 以32字节为单位进行向量化XOR；尽量覆盖rate区域。
            const size_t vec_bytes = 32;
            size_t offset = 0;
            // 注意：state按uint64_t[25]布局，此处按字节视图处理，确保不越界。
            while (rate_bytes - offset >= vec_bytes) {
                __m256i vdst = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(reinterpret_cast<const uint8_t*>(state.data()) + offset));
                __m256i vsrc = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + offset));
                __m256i vx = _mm256_xor_si256(vdst, vsrc);
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(reinterpret_cast<uint8_t*>(state.data()) + offset), vx);
                offset += vec_bytes;
            }
            // 处理剩余部分（按64位lane）
            for (; offset + 8 <= rate_bytes; offset += 8) {
                uint64_t lane;
                std::memcpy(&lane, data + offset, 8);
                state[offset / 8] ^= lane;
            }
            // 处理尾部字节
            for (; offset < rate_bytes; ++offset) {
                reinterpret_cast<uint8_t*>(state.data())[offset] ^= data[offset];
            }
            return;
        }
#endif
        // 无AVX2时采用64位lane批量XOR
        for (size_t i = 0; i < rate_bytes / 8; ++i) {
            uint64_t lane;
            std::memcpy(&lane, data + i * 8, 8);
            state[i] ^= lane;
        }
        // 处理尾部字节
        for (size_t i = (rate_bytes / 8) * 8; i < rate_bytes; ++i) {
            reinterpret_cast<uint8_t*>(state.data())[i] ^= data[i];
        }
    }

    /**
     * @brief Extract data from state (squeeze)
     */
    void extract(uint8_t* out, size_t len) const noexcept {
        std::memcpy(out, state.data(), len);
    }
};

/**
 * @brief SHA3 hasher class
 */
class SHA3Hasher {
public:
    SHA3Hasher(size_t digest_bits, uint8_t suffix) noexcept
        : rate_((1600 - 2 * digest_bits) / 8)
        , digest_size_(digest_bits / 8)
        , suffix_(suffix)
        , absorbed_(0) {
        state_.reset();
    }

    void update(const uint8_t* data, size_t len) noexcept {
        uint8_t* state_bytes = reinterpret_cast<uint8_t*>(state_.state.data());
        
        while (len > 0) {
            size_t to_absorb = std::min(len, rate_ - absorbed_);
            
            // Fast path: use 64-bit XOR when aligned
            if (absorbed_ == 0 && to_absorb >= 32) {
                // 预取下一块数据以提升吞吐
                KCTSB_PREFETCH(data + 64);
                size_t consume = to_absorb; // 尽可能一次性吸收rate内的可用字节
                state_.xor_block(data, consume);
                absorbed_ += consume;
                data += consume;
                len -= consume;
                to_absorb = 0;
            }
            
            // Handle remaining bytes
            for (size_t i = 0; i < to_absorb; ++i) {
                state_bytes[absorbed_ + i] ^= data[i];
            }

            absorbed_ += to_absorb;
            data += to_absorb;
            len -= to_absorb;

            if (absorbed_ == rate_) {
                state_.permute();
                absorbed_ = 0;
            }
        }
    }

    void finalize(uint8_t* digest) noexcept {
        // Apply padding
        uint8_t* state_bytes = reinterpret_cast<uint8_t*>(state_.state.data());
        state_bytes[absorbed_] ^= suffix_;
        state_bytes[rate_ - 1] ^= 0x80;

        state_.permute();

        // Squeeze output
        state_.extract(digest, digest_size_);
    }

    void reset() noexcept {
        state_.reset();
        absorbed_ = 0;
    }

private:
    KeccakState state_;
    size_t rate_;
    size_t digest_size_;
    uint8_t suffix_;
    size_t absorbed_;
};

} // namespace kctsb::internal

namespace {

/**
 * @brief XOR a full-rate block into the state with AVX2 (no runtime check).
 * @param state_bytes State as byte pointer
 * @param data Input block
 * @param rate_bytes Rate in bytes
 */
inline void xor_block_avx2(uint8_t* KCTSB_RESTRICT state_bytes,
                           const uint8_t* KCTSB_RESTRICT data,
                           size_t rate_bytes) noexcept {
#if KCTSB_HAS_AVX2_KECCAK
    const size_t vec_bytes = 32;
    size_t offset = 0;
    const bool data_aligned = (reinterpret_cast<uintptr_t>(data) & (vec_bytes - 1U)) == 0U;
    auto* state_words = reinterpret_cast<uint64_t*>(state_bytes);
    while (rate_bytes - offset >= vec_bytes) {
        __m256i vdst = _mm256_load_si256(reinterpret_cast<const __m256i*>(state_bytes + offset));
        __m256i vsrc = data_aligned
            ? _mm256_load_si256(reinterpret_cast<const __m256i*>(data + offset))
            : _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + offset));
        __m256i vx = _mm256_xor_si256(vdst, vsrc);
        _mm256_store_si256(reinterpret_cast<__m256i*>(state_bytes + offset), vx);
        offset += vec_bytes;
    }
    for (; offset + 8 <= rate_bytes; offset += 8) {
        uint64_t lane;
        std::memcpy(&lane, data + offset, 8);
        state_words[offset / 8] ^= lane;
    }
    for (; offset < rate_bytes; ++offset) {
        state_bytes[offset] ^= data[offset];
    }
#else
    (void)state_bytes;
    (void)data;
    (void)rate_bytes;
#endif
}

/**
 * @brief XOR a full-rate block into the state using 64-bit lanes.
 * @param state_words State as 64-bit lanes
 * @param data Input block
 * @param rate_bytes Rate in bytes
 */
inline void xor_block_lanes(uint64_t* KCTSB_RESTRICT state_words,
                            const uint8_t* KCTSB_RESTRICT data,
                            size_t rate_bytes) noexcept {
    const size_t lanes = rate_bytes / 8;
    const bool aligned = (reinterpret_cast<uintptr_t>(data) & 7U) == 0U;

    if (aligned) {
        const auto* data_words = reinterpret_cast<const uint64_t*>(data);
        switch (lanes) {
            case 17:
                state_words[0] ^= data_words[0];
                state_words[1] ^= data_words[1];
                state_words[2] ^= data_words[2];
                state_words[3] ^= data_words[3];
                state_words[4] ^= data_words[4];
                state_words[5] ^= data_words[5];
                state_words[6] ^= data_words[6];
                state_words[7] ^= data_words[7];
                state_words[8] ^= data_words[8];
                state_words[9] ^= data_words[9];
                state_words[10] ^= data_words[10];
                state_words[11] ^= data_words[11];
                state_words[12] ^= data_words[12];
                state_words[13] ^= data_words[13];
                state_words[14] ^= data_words[14];
                state_words[15] ^= data_words[15];
                state_words[16] ^= data_words[16];
                return;
            case 21:
                state_words[0] ^= data_words[0];
                state_words[1] ^= data_words[1];
                state_words[2] ^= data_words[2];
                state_words[3] ^= data_words[3];
                state_words[4] ^= data_words[4];
                state_words[5] ^= data_words[5];
                state_words[6] ^= data_words[6];
                state_words[7] ^= data_words[7];
                state_words[8] ^= data_words[8];
                state_words[9] ^= data_words[9];
                state_words[10] ^= data_words[10];
                state_words[11] ^= data_words[11];
                state_words[12] ^= data_words[12];
                state_words[13] ^= data_words[13];
                state_words[14] ^= data_words[14];
                state_words[15] ^= data_words[15];
                state_words[16] ^= data_words[16];
                state_words[17] ^= data_words[17];
                state_words[18] ^= data_words[18];
                state_words[19] ^= data_words[19];
                state_words[20] ^= data_words[20];
                return;
            case 9:
                state_words[0] ^= data_words[0];
                state_words[1] ^= data_words[1];
                state_words[2] ^= data_words[2];
                state_words[3] ^= data_words[3];
                state_words[4] ^= data_words[4];
                state_words[5] ^= data_words[5];
                state_words[6] ^= data_words[6];
                state_words[7] ^= data_words[7];
                state_words[8] ^= data_words[8];
                return;
            default:
                for (size_t i = 0; i < lanes; ++i) {
                    state_words[i] ^= data_words[i];
                }
                return;
        }
    }

    for (size_t i = 0; i < lanes; ++i) {
        uint64_t lane;
        std::memcpy(&lane, data + i * 8, 8);
        state_words[i] ^= lane;
    }
}

/**
 * @brief Absorb full-rate blocks directly into the Keccak state.
 * @param ctx SHA3 context
 * @param data Input data pointer (advanced)
 * @param len Remaining input length (reduced)
 */
inline void absorb_full_blocks(kctsb_sha3_ctx_t* KCTSB_RESTRICT ctx,
                               const uint8_t*& data,
                               size_t& len) noexcept {
    if (ctx->absorbed != 0 || len < ctx->rate) {
        return;
    }

    auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx->state);
    auto* KCTSB_RESTRICT state_bytes = reinterpret_cast<uint8_t*>(keccak_state->state.data());
    auto* KCTSB_RESTRICT state_words = keccak_state->state.data();
    const size_t rate = ctx->rate;
    static const bool has_avx2 = kctsb::internal::SIMDDetector::has_avx2();
    const bool use_avx2 = has_avx2 && rate >= 96 && len >= (rate * 8U);

    while (len >= rate) {
        KCTSB_PREFETCH(data + 64);
        if (use_avx2) {
            xor_block_avx2(state_bytes, data, rate);
        } else {
            xor_block_lanes(state_words, data, rate);
        }
        keccak_state->permute();
        data += rate;
        len -= rate;
    }
}

/**
 * @brief XOR a partial block into the state with 64-bit lanes when aligned.
 * @param state_bytes State byte view
 * @param offset Offset within the state
 * @param data Input data
 * @param len Bytes to absorb
 */
inline void xor_partial_block(uint8_t* KCTSB_RESTRICT state_bytes,
                              size_t offset,
                              const uint8_t* KCTSB_RESTRICT data,
                              size_t len) noexcept {
    size_t i = 0;

    while (i < len && ((offset + i) & 7U) != 0U) {
        state_bytes[offset + i] ^= data[i];
        ++i;
    }

    for (; i + 8 <= len; i += 8) {
        uint64_t lane;
        std::memcpy(&lane, data + i, 8);
        auto* dst = reinterpret_cast<uint64_t*>(state_bytes + offset + i);
        *dst ^= lane;
    }

    for (; i < len; ++i) {
        state_bytes[offset + i] ^= data[i];
    }
}

} // namespace

// ============================================================================
// C ABI Export (extern "C")
// ============================================================================

extern "C" {

// ----------------------------------------------------------------------------
// SHA3-256
// ----------------------------------------------------------------------------

kctsb_error_t kctsb_sha3_256_init(kctsb_sha3_ctx_t* ctx) {
    if (!ctx) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    std::memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136;           // (1600 - 512) / 8
    ctx->capacity = 64;        // 512 / 8
    ctx->digest_size = 32;
    ctx->suffix = 0x06;        // SHA3 domain separator
    ctx->absorbed = 0;

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sha3_256_update(kctsb_sha3_ctx_t* ctx,
                                     const uint8_t* data, size_t len) {
    if (!ctx || (!data && len > 0)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx->state);

    while (len > 0) {
        absorb_full_blocks(ctx, data, len);
        if (len == 0) {
            break;
        }

        const size_t to_absorb = (len < ctx->rate - ctx->absorbed)
            ? len
            : (ctx->rate - ctx->absorbed);
        xor_partial_block(state_bytes, ctx->absorbed, data, to_absorb);

        ctx->absorbed += to_absorb;
        data += to_absorb;
        len -= to_absorb;

        if (ctx->absorbed == ctx->rate) {
            auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx->state);
            keccak_state->permute();
            ctx->absorbed = 0;
        }
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sha3_256_final(kctsb_sha3_ctx_t* ctx,
                                    uint8_t digest[KCTSB_SHA3_256_DIGEST_SIZE]) {
    if (!ctx || !digest) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Apply SHA3 padding
    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx->state);
    state_bytes[ctx->absorbed] ^= ctx->suffix;
    state_bytes[ctx->rate - 1] ^= 0x80;

    // Final permutation
    auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx->state);
    keccak_state->permute();

    // Extract digest
    std::memcpy(digest, ctx->state, ctx->digest_size);

    // Secure clear
    kctsb_sha3_clear(ctx);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sha3_256(const uint8_t* data, size_t len,
                              uint8_t digest[KCTSB_SHA3_256_DIGEST_SIZE]) {
    if (!digest || (!data && len > 0)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    kctsb_sha3_ctx_t ctx;
    kctsb_sha3_256_init(&ctx);
    kctsb_sha3_256_update(&ctx, data, len);
    return kctsb_sha3_256_final(&ctx, digest);
}

// ----------------------------------------------------------------------------
// SHA3-512
// ----------------------------------------------------------------------------

kctsb_error_t kctsb_sha3_512_init(kctsb_sha3_ctx_t* ctx) {
    if (!ctx) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    std::memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 72;            // (1600 - 1024) / 8
    ctx->capacity = 128;       // 1024 / 8
    ctx->digest_size = 64;
    ctx->suffix = 0x06;        // SHA3 domain separator
    ctx->absorbed = 0;

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sha3_512_update(kctsb_sha3_ctx_t* ctx,
                                     const uint8_t* data, size_t len) {
    // Same implementation as SHA3-256, just different rate
    return kctsb_sha3_256_update(ctx, data, len);
}

kctsb_error_t kctsb_sha3_512_final(kctsb_sha3_ctx_t* ctx,
                                    uint8_t digest[KCTSB_SHA3_512_DIGEST_SIZE]) {
    if (!ctx || !digest) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx->state);
    state_bytes[ctx->absorbed] ^= ctx->suffix;
    state_bytes[ctx->rate - 1] ^= 0x80;

    auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx->state);
    keccak_state->permute();

    std::memcpy(digest, ctx->state, ctx->digest_size);
    kctsb_sha3_clear(ctx);

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sha3_512(const uint8_t* data, size_t len,
                              uint8_t digest[KCTSB_SHA3_512_DIGEST_SIZE]) {
    if (!digest || (!data && len > 0)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    kctsb_sha3_ctx_t ctx;
    kctsb_sha3_512_init(&ctx);
    kctsb_sha3_512_update(&ctx, data, len);
    return kctsb_sha3_512_final(&ctx, digest);
}

// ----------------------------------------------------------------------------
// SHAKE Functions
// ----------------------------------------------------------------------------

kctsb_error_t kctsb_shake128(const uint8_t* data, size_t len,
                              uint8_t* output, size_t output_len) {
    if (!output || (!data && len > 0)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    kctsb_sha3_ctx_t ctx;
    std::memset(&ctx, 0, sizeof(ctx));
    ctx.rate = 168;            // (1600 - 256) / 8
    ctx.suffix = 0x1F;         // SHAKE domain separator
    ctx.absorbed = 0;

    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx.state);
    auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx.state);

    while (len > 0) {
        const uint8_t* input_ptr = data;
        size_t input_len = len;
        absorb_full_blocks(&ctx, input_ptr, input_len);
        data = input_ptr;
        len = input_len;
        if (len == 0) {
            break;
        }

        const size_t to_absorb = (len < (ctx.rate - ctx.absorbed))
            ? len
            : (ctx.rate - ctx.absorbed);
        xor_partial_block(state_bytes, ctx.absorbed, data, to_absorb);
        ctx.absorbed += to_absorb;
        data += to_absorb;
        len -= to_absorb;

        if (ctx.absorbed == ctx.rate) {
            keccak_state->permute();
            ctx.absorbed = 0;
        }
    }

    // Padding - apply at current absorbed position
    state_bytes[ctx.absorbed] ^= ctx.suffix;
    state_bytes[ctx.rate - 1] ^= 0x80;

    keccak_state->permute();

    // Squeeze
    while (output_len > 0) {
        size_t to_squeeze = (output_len < ctx.rate) ? output_len : ctx.rate;
        std::memcpy(output, ctx.state, to_squeeze);
        output += to_squeeze;
        output_len -= to_squeeze;

        if (output_len > 0) {
            keccak_state->permute();
        }
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_shake256(const uint8_t* data, size_t len,
                              uint8_t* output, size_t output_len) {
    if (!output || (!data && len > 0)) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    kctsb_sha3_ctx_t ctx;
    std::memset(&ctx, 0, sizeof(ctx));
    ctx.rate = 136;            // (1600 - 512) / 8
    ctx.suffix = 0x1F;         // SHAKE domain separator
    ctx.absorbed = 0;

    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx.state);
    auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx.state);

    while (len > 0) {
        const uint8_t* input_ptr = data;
        size_t input_len = len;
        absorb_full_blocks(&ctx, input_ptr, input_len);
        data = input_ptr;
        len = input_len;
        if (len == 0) {
            break;
        }

        const size_t to_absorb = (len < (ctx.rate - ctx.absorbed))
            ? len
            : (ctx.rate - ctx.absorbed);
        xor_partial_block(state_bytes, ctx.absorbed, data, to_absorb);
        ctx.absorbed += to_absorb;
        data += to_absorb;
        len -= to_absorb;

        if (ctx.absorbed == ctx.rate) {
            keccak_state->permute();
            ctx.absorbed = 0;
        }
    }

    // Padding - apply at current absorbed position
    state_bytes[ctx.absorbed] ^= ctx.suffix;
    state_bytes[ctx.rate - 1] ^= 0x80;

    keccak_state->permute();

    // Squeeze
    while (output_len > 0) {
        size_t to_squeeze = (output_len < ctx.rate) ? output_len : ctx.rate;
        std::memcpy(output, ctx.state, to_squeeze);
        output += to_squeeze;
        output_len -= to_squeeze;

        if (output_len > 0) {
            keccak_state->permute();
        }
    }

    return KCTSB_SUCCESS;
}

// ----------------------------------------------------------------------------
// Context Management
// ----------------------------------------------------------------------------

void kctsb_sha3_clear(kctsb_sha3_ctx_t* ctx) {
    if (ctx) {
        // Secure memory zeroing
        volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ctx);
        for (size_t i = 0; i < sizeof(*ctx); ++i) {
            p[i] = 0;
        }
    }
}

} // extern "C"
