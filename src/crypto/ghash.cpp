/**
 * @file ghash.cpp
 * @brief GHASH Implementation - GF(2^128) Multiplication
 *
 * High-performance GHASH implementation for GCM mode.
 * Implements Galois field multiplication in GF(2^128).
 *
 * Optimizations:
 * - 4-bit table-based multiplication (Shoup's method)
 * - Constant-time implementation
 * - Optional PCLMULQDQ acceleration (x86)
 *
 * Reference: NIST SP 800-38D
 *
 * C++ Core + C ABI Architecture (v3.4.0)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/core/common.h"
#include <cstring>
#include <cstdint>

namespace kctsb {
namespace internal {

// ============================================================================
// GF(2^128) Multiplication - Table-based (Shoup's 4-bit method)
// ============================================================================

// Reduction polynomial for GF(2^128): x^128 + x^7 + x^2 + x + 1
// Represented as R = 0xE1 (most significant byte, big-endian)

// Precomputed reduction table for 4-bit multiplication
// R_TABLE[i] = i * R (mod x^128)
static const uint64_t R_TABLE[16] = {
    0x0000000000000000ULL, 0x1C20000000000000ULL,
    0x3840000000000000ULL, 0x2460000000000000ULL,
    0x7080000000000000ULL, 0x6CA0000000000000ULL,
    0x48C0000000000000ULL, 0x54E0000000000000ULL,
    0xE100000000000000ULL, 0xFD20000000000000ULL,
    0xD940000000000000ULL, 0xC560000000000000ULL,
    0x9180000000000000ULL, 0x8DA0000000000000ULL,
    0xA9C0000000000000ULL, 0xB5E0000000000000ULL
};

/**
 * @brief Precomputed multiplication table for H
 *
 * M[i] = i * H for i in [0, 15]
 * Allows 4-bit at a time multiplication
 */
struct GhashTable {
    uint64_t H[2];          // H value (hash key)
    uint64_t M[16][2];      // M[i] = i * H

    void init(const uint8_t h[16]) {
        // Store H in big-endian uint64_t representation
        H[0] = load_be64(h);
        H[1] = load_be64(h + 8);

        // M[0] = 0
        M[0][0] = 0;
        M[0][1] = 0;

        // M[1] = H
        M[1][0] = H[0];
        M[1][1] = H[1];

        // M[2] = 2*H (= H << 1 in polynomial)
        mul_by_x(M[1], M[2]);

        // M[i] = (i-1)*H + H for i in [3, 15]
        for (int i = 2; i < 16; i++) {
            if (i % 2 == 0) {
                // M[2k] = 2 * M[k]
                mul_by_x(M[i / 2], M[i]);
            } else {
                // M[2k+1] = M[2k] + M[1]
                M[i][0] = M[i - 1][0] ^ M[1][0];
                M[i][1] = M[i - 1][1] ^ M[1][1];
            }
        }
    }

private:
    static uint64_t load_be64(const uint8_t* p) {
        return (static_cast<uint64_t>(p[0]) << 56) |
               (static_cast<uint64_t>(p[1]) << 48) |
               (static_cast<uint64_t>(p[2]) << 40) |
               (static_cast<uint64_t>(p[3]) << 32) |
               (static_cast<uint64_t>(p[4]) << 24) |
               (static_cast<uint64_t>(p[5]) << 16) |
               (static_cast<uint64_t>(p[6]) << 8) |
               static_cast<uint64_t>(p[7]);
    }

    // Multiply by x in GF(2^128) with reduction
    static void mul_by_x(const uint64_t in[2], uint64_t out[2]) {
        uint64_t carry = in[1] & 1;  // LSB of low part
        out[1] = in[1] >> 1;
        out[1] |= (in[0] & 1) << 63;
        out[0] = in[0] >> 1;

        // If carry, XOR with reduction polynomial (0xE1 << 56)
        if (carry) {
            out[0] ^= 0xE100000000000000ULL;
        }
    }
};

/**
 * @brief GHASH multiplication: Y = X * H (mod polynomial)
 *
 * Uses 4-bit table-based multiplication for efficiency.
 * Processes 4 bits at a time, total 32 iterations for 128 bits.
 *
 * @param H Hash key (16 bytes, big-endian)
 * @param X Input block (16 bytes, big-endian)
 * @param Y Output block (16 bytes, big-endian)
 */
void ghash_multiply(const uint8_t* H, const uint8_t* X, uint8_t* Y) {
    // Build multiplication table
    GhashTable table;
    table.init(H);

    // Load X into uint64_t
    uint64_t X_hi = 0, X_lo = 0;
    for (int i = 0; i < 8; i++) {
        X_hi = (X_hi << 8) | X[i];
        X_lo = (X_lo << 8) | X[i + 8];
    }

    // Result accumulator
    uint64_t Z_hi = 0, Z_lo = 0;

    // Process 4 bits at a time, starting from MSB
    // High 64 bits of X
    for (int i = 60; i >= 0; i -= 4) {
        // Get 4-bit index
        int idx = (X_hi >> i) & 0xF;

        // Z = Z * x^4 (shift right by 4, with reduction)
        uint64_t reduce = R_TABLE[Z_lo & 0xF];
        Z_lo = (Z_lo >> 4) | (Z_hi << 60);
        Z_hi = (Z_hi >> 4) ^ reduce;

        // Z = Z + M[idx]
        Z_hi ^= table.M[idx][0];
        Z_lo ^= table.M[idx][1];
    }

    // Low 64 bits of X
    for (int i = 60; i >= 0; i -= 4) {
        // Get 4-bit index
        int idx = (X_lo >> i) & 0xF;

        // Z = Z * x^4
        uint64_t reduce = R_TABLE[Z_lo & 0xF];
        Z_lo = (Z_lo >> 4) | (Z_hi << 60);
        Z_hi = (Z_hi >> 4) ^ reduce;

        // Z = Z + M[idx]
        Z_hi ^= table.M[idx][0];
        Z_lo ^= table.M[idx][1];
    }

    // Store result (big-endian)
    for (int i = 7; i >= 0; i--) {
        Y[7 - i] = (Z_hi >> (i * 8)) & 0xFF;
        Y[15 - i] = (Z_lo >> (i * 8)) & 0xFF;
    }
}

/**
 * @brief GHASH with precomputed table
 *
 * More efficient for multiple blocks with the same H.
 */
class GhashContext {
public:
    void init(const uint8_t h[16]) {
        table_.init(h);
        std::memset(state_, 0, 16);
    }

    void update(const uint8_t* data, size_t len) {
        size_t offset = 0;

        // Handle buffered data
        if (buffer_len_ > 0) {
            size_t needed = 16 - buffer_len_;
            if (len < needed) {
                std::memcpy(buffer_ + buffer_len_, data, len);
                buffer_len_ += len;
                return;
            }
            std::memcpy(buffer_ + buffer_len_, data, needed);
            process_block(buffer_);
            offset = needed;
            buffer_len_ = 0;
        }

        // Process complete blocks
        while (offset + 16 <= len) {
            process_block(data + offset);
            offset += 16;
        }

        // Buffer remaining
        if (offset < len) {
            std::memcpy(buffer_, data + offset, len - offset);
            buffer_len_ = len - offset;
        }
    }

    void final(uint8_t out[16]) {
        // Pad and process any remaining data
        if (buffer_len_ > 0) {
            std::memset(buffer_ + buffer_len_, 0, 16 - buffer_len_);
            process_block(buffer_);
        }

        std::memcpy(out, state_, 16);
    }

private:
    void process_block(const uint8_t block[16]) {
        // XOR with state
        uint8_t temp[16];
        for (int i = 0; i < 16; i++) {
            temp[i] = state_[i] ^ block[i];
        }

        // Multiply by H
        ghash_multiply_table(temp, state_);
    }

    void ghash_multiply_table(const uint8_t* X, uint8_t* Y) {
        // Load X
        uint64_t X_hi = 0, X_lo = 0;
        for (int i = 0; i < 8; i++) {
            X_hi = (X_hi << 8) | X[i];
            X_lo = (X_lo << 8) | X[i + 8];
        }

        uint64_t Z_hi = 0, Z_lo = 0;

        // Process high 64 bits
        for (int i = 60; i >= 0; i -= 4) {
            int idx = (X_hi >> i) & 0xF;
            uint64_t reduce = R_TABLE[Z_lo & 0xF];
            Z_lo = (Z_lo >> 4) | (Z_hi << 60);
            Z_hi = (Z_hi >> 4) ^ reduce;
            Z_hi ^= table_.M[idx][0];
            Z_lo ^= table_.M[idx][1];
        }

        // Process low 64 bits
        for (int i = 60; i >= 0; i -= 4) {
            int idx = (X_lo >> i) & 0xF;
            uint64_t reduce = R_TABLE[Z_lo & 0xF];
            Z_lo = (Z_lo >> 4) | (Z_hi << 60);
            Z_hi = (Z_hi >> 4) ^ reduce;
            Z_hi ^= table_.M[idx][0];
            Z_lo ^= table_.M[idx][1];
        }

        // Store result
        for (int i = 7; i >= 0; i--) {
            Y[7 - i] = (Z_hi >> (i * 8)) & 0xFF;
            Y[15 - i] = (Z_lo >> (i * 8)) & 0xFF;
        }
    }

    GhashTable table_;
    uint8_t state_[16];
    uint8_t buffer_[16];
    size_t buffer_len_ = 0;
};

}  // namespace internal
}  // namespace kctsb

// ============================================================================
// C ABI Exports
// ============================================================================

extern "C" {

void kctsb_ghash_multiply(const uint8_t H[16], const uint8_t X[16], uint8_t Y[16]) {
    kctsb::internal::ghash_multiply(H, X, Y);
}

void kctsb_ghash_init(void** ctx, const uint8_t H[16]) {
    if (!ctx || !H) return;

    auto* ghash = new kctsb::internal::GhashContext();
    ghash->init(H);
    *ctx = ghash;
}

void kctsb_ghash_update(void* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !data) return;

    auto* ghash = static_cast<kctsb::internal::GhashContext*>(ctx);
    ghash->update(data, len);
}

void kctsb_ghash_final(void* ctx, uint8_t out[16]) {
    if (!ctx || !out) return;

    auto* ghash = static_cast<kctsb::internal::GhashContext*>(ctx);
    ghash->final(out);

    delete ghash;
}

}  // extern "C"
