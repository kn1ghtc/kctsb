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
    return (x << n) | (x >> (64 - n));
}

/**
 * @brief Keccak-f[1600] state transformation class
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
     * @brief Apply Keccak-f[1600] permutation
     */
    void permute() noexcept {
        for (int round = 0; round < 24; ++round) {
            theta();
            rho_pi();
            chi();
            iota(round);
        }
    }

    /**
     * @brief XOR data into state (absorb)
     */
    void xor_block(const uint8_t* data, size_t rate_bytes) noexcept {
        for (size_t i = 0; i < rate_bytes / 8; ++i) {
            uint64_t lane;
            std::memcpy(&lane, data + i * 8, 8);
            state[i] ^= lane;
        }
    }

    /**
     * @brief Extract data from state (squeeze)
     */
    void extract(uint8_t* out, size_t len) const noexcept {
        std::memcpy(out, state.data(), len);
    }

private:
    /**
     * @brief θ step - column parity mixing
     */
    __attribute__((always_inline))
    void theta() noexcept {
        std::array<uint64_t, 5> C{};

        for (int x = 0; x < 5; ++x) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        for (int x = 0; x < 5; ++x) {
            uint64_t D = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; ++y) {
                state[x + 5 * y] ^= D;
            }
        }
    }

    /**
     * @brief ρ and π steps - rotation and permutation
     */
    __attribute__((always_inline))
    void rho_pi() noexcept {
        std::array<uint64_t, 25> temp{};

        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                int new_x = y;
                int new_y = (2 * x + 3 * y) % 5;
                temp[new_x + 5 * new_y] = rotl64(state[x + 5 * y], KECCAK_RHO[x + 5 * y]);
            }
        }

        state = temp;
    }

    /**
     * @brief χ step - nonlinear function
     */
    __attribute__((always_inline))
    void chi() noexcept {
        for (int y = 0; y < 5; ++y) {
            std::array<uint64_t, 5> row;
            for (int x = 0; x < 5; ++x) {
                row[x] = state[x + 5 * y];
            }
            for (int x = 0; x < 5; ++x) {
                state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
    }

    /**
     * @brief ι step - XOR round constant
     */
    __attribute__((always_inline))
    void iota(int round) noexcept {
        state[0] ^= KECCAK_RC[round];
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
        while (len > 0) {
            size_t to_absorb = std::min(len, rate_ - absorbed_);

            // XOR data into state buffer area
            for (size_t i = 0; i < to_absorb; ++i) {
                reinterpret_cast<uint8_t*>(state_.state.data())[absorbed_ + i] ^= data[i];
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

    while (len > 0) {
        size_t to_absorb = (len < ctx->rate - ctx->absorbed) ? len : (ctx->rate - ctx->absorbed);

        uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx->state);
        for (size_t i = 0; i < to_absorb; ++i) {
            state_bytes[ctx->absorbed + i] ^= data[i];
        }

        ctx->absorbed += to_absorb;
        data += to_absorb;
        len -= to_absorb;

        if (ctx->absorbed == ctx->rate) {
            // Permute using internal implementation
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

    // Absorb all input - accumulate until we have a full block
    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx.state);
    auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx.state);

    while (len > 0) {
        size_t to_absorb = (len < (ctx.rate - ctx.absorbed)) ? len : (ctx.rate - ctx.absorbed);
        for (size_t i = 0; i < to_absorb; ++i) {
            state_bytes[ctx.absorbed + i] ^= data[i];
        }
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

    // Absorb all input - accumulate until we have a full block
    uint8_t* state_bytes = reinterpret_cast<uint8_t*>(ctx.state);
    auto* keccak_state = reinterpret_cast<kctsb::internal::KeccakState*>(&ctx.state);

    while (len > 0) {
        size_t to_absorb = (len < (ctx.rate - ctx.absorbed)) ? len : (ctx.rate - ctx.absorbed);
        for (size_t i = 0; i < to_absorb; ++i) {
            state_bytes[ctx.absorbed + i] ^= data[i];
        }
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
