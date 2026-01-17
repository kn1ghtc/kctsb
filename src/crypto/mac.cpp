/**
 * @file mac.cpp
 * @brief Message Authentication Code Implementations
 *
 * Provides HMAC, CMAC, and GMAC implementations for message authentication.
 *
 * Algorithms:
 * - HMAC-SHA256: RFC 2104 + FIPS 198-1
 * - CMAC-AES128: NIST SP 800-38B (cipher-based MAC)
 * - GMAC: NIST SP 800-38D (GCM-based MAC)
 *
 * C++ Core + C ABI Architecture (v3.4.0)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/mac.h"
#include "kctsb/crypto/sha256.h"
#include "kctsb/crypto/sha512.h"
#include "kctsb/crypto/aes.h"
#include "kctsb/core/common.h"
#include "kctsb/core/security.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <new>
#include <type_traits>

extern "C" void kctsb_aes_gcm_ghash_update_internal(
    uint8_t tag[16],
    const uint8_t h[16],
    const uint8_t* data,
    size_t len
);

namespace kctsb {
namespace internal {

namespace {

constexpr size_t HMAC256_POOL_SIZE = 32;
constexpr size_t HMAC512_POOL_SIZE = 32;
constexpr size_t CMAC_POOL_SIZE = 16;
constexpr size_t GMAC_POOL_SIZE = 16;

template <typename T, size_t N>
class ObjectPool {
public:
    ObjectPool()
        : free_count_(N) {
        for (size_t i = 0; i < N; ++i) {
            free_list_[i] = reinterpret_cast<T*>(&storage_[i]);
        }
    }

    T* acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (free_count_ > 0) {
            T* slot = free_list_[--free_count_];
            return new (slot) T();
        }
        return new T();
    }

    void release(T* obj) {
        if (!obj) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        if (owns(obj)) {
            obj->~T();
            free_list_[free_count_++] = obj;
        } else {
            delete obj;
        }
    }

private:
    bool owns(const T* obj) const {
        const uintptr_t start = reinterpret_cast<uintptr_t>(&storage_[0]);
        const uintptr_t end = reinterpret_cast<uintptr_t>(&storage_[N - 1]) +
            sizeof(storage_[0]);
        const uintptr_t ptr = reinterpret_cast<uintptr_t>(obj);
        return ptr >= start && ptr < end;
    }

    std::mutex mutex_;
    std::array<std::aligned_storage_t<sizeof(T), alignof(T)>, N> storage_;
    std::array<T*, N> free_list_;
    size_t free_count_;
};

}  // namespace

// ============================================================================
// HMAC-SHA256 Implementation (RFC 2104)
// ============================================================================

static constexpr size_t HMAC_SHA256_BLOCK_SIZE = 64;  // SHA-256 block size
static constexpr size_t HMAC_SHA256_DIGEST_SIZE = 32; // SHA-256 output size

class HMAC_SHA256 {
public:
    HMAC_SHA256()
        : initialized_(false) {
    }

    ~HMAC_SHA256() {
        clear();
    }

    void init(const uint8_t* key, size_t key_len) {
        uint8_t key_block[HMAC_SHA256_BLOCK_SIZE];
        std::memset(key_block, 0, HMAC_SHA256_BLOCK_SIZE);

        // If key > block size, hash it first
        if (key_len > HMAC_SHA256_BLOCK_SIZE) {
            kctsb_sha256_ctx_t hash_ctx;
            kctsb_sha256_init(&hash_ctx);
            kctsb_sha256_update(&hash_ctx, key, key_len);
            kctsb_sha256_final(&hash_ctx, key_block);
        } else {
            std::memcpy(key_block, key, key_len);
        }

        // Compute i_key_pad and o_key_pad
        for (size_t i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
            i_key_pad_[i] = key_block[i] ^ 0x36;
            o_key_pad_[i] = key_block[i] ^ 0x5C;
        }

        // Initialize inner hash with i_key_pad
        kctsb_sha256_init(&inner_ctx_);
        kctsb_sha256_update(&inner_ctx_, i_key_pad_, HMAC_SHA256_BLOCK_SIZE);

        // Initialize outer hash base with o_key_pad
        kctsb_sha256_init(&outer_ctx_);
        kctsb_sha256_update(&outer_ctx_, o_key_pad_, HMAC_SHA256_BLOCK_SIZE);

        inner_base_ = inner_ctx_;
        outer_base_ = outer_ctx_;
        initialized_ = true;

        kctsb_secure_zero(key_block, sizeof(key_block));
    }

    void update(const uint8_t* data, size_t len) {
        if (!initialized_) return;
        kctsb_sha256_update(&inner_ctx_, data, len);
    }

    void final(uint8_t mac[32]) {
        if (!initialized_) return;
        uint8_t inner_digest[HMAC_SHA256_DIGEST_SIZE];

        // Finalize inner hash
        kctsb_sha256_final(&inner_ctx_, inner_digest);

        // Compute outer hash: H(o_key_pad || inner_digest)
        kctsb_sha256_ctx_t outer_ctx = outer_base_;
        kctsb_sha256_update(&outer_ctx, inner_digest, HMAC_SHA256_DIGEST_SIZE);
        kctsb_sha256_final(&outer_ctx, mac);

        inner_ctx_ = inner_base_;
        kctsb_secure_zero(inner_digest, sizeof(inner_digest));
    }

private:
    void clear() {
        kctsb_secure_zero(&inner_ctx_, sizeof(inner_ctx_));
        kctsb_secure_zero(&outer_ctx_, sizeof(outer_ctx_));
        kctsb_secure_zero(&inner_base_, sizeof(inner_base_));
        kctsb_secure_zero(&outer_base_, sizeof(outer_base_));
        kctsb_secure_zero(i_key_pad_, sizeof(i_key_pad_));
        kctsb_secure_zero(o_key_pad_, sizeof(o_key_pad_));
        initialized_ = false;
    }

    kctsb_sha256_ctx_t inner_ctx_;
    kctsb_sha256_ctx_t outer_ctx_;
    kctsb_sha256_ctx_t inner_base_;
    kctsb_sha256_ctx_t outer_base_;
    uint8_t i_key_pad_[HMAC_SHA256_BLOCK_SIZE];
    uint8_t o_key_pad_[HMAC_SHA256_BLOCK_SIZE];
    bool initialized_;
};

// ============================================================================
// HMAC-SHA512 Implementation (RFC 2104)
// ============================================================================

static constexpr size_t HMAC_SHA512_BLOCK_SIZE = 128;  // SHA-512 block size
static constexpr size_t HMAC_SHA512_DIGEST_SIZE = 64;  // SHA-512 output size

class HMAC_SHA512 {
public:
    HMAC_SHA512()
        : initialized_(false) {
    }

    ~HMAC_SHA512() {
        clear();
    }

    void init(const uint8_t* key, size_t key_len) {
        uint8_t key_block[HMAC_SHA512_BLOCK_SIZE];
        std::memset(key_block, 0, HMAC_SHA512_BLOCK_SIZE);

        // If key > block size, hash it first
        if (key_len > HMAC_SHA512_BLOCK_SIZE) {
            kctsb_sha512_ctx_t hash_ctx;
            kctsb_sha512_init(&hash_ctx);
            kctsb_sha512_update(&hash_ctx, key, key_len);
            kctsb_sha512_final(&hash_ctx, key_block);
        } else {
            std::memcpy(key_block, key, key_len);
        }

        // Compute i_key_pad and o_key_pad
        for (size_t i = 0; i < HMAC_SHA512_BLOCK_SIZE; i++) {
            i_key_pad_[i] = key_block[i] ^ 0x36;
            o_key_pad_[i] = key_block[i] ^ 0x5C;
        }

        // Initialize inner hash with i_key_pad
        kctsb_sha512_init(&inner_ctx_);
        kctsb_sha512_update(&inner_ctx_, i_key_pad_, HMAC_SHA512_BLOCK_SIZE);

        // Initialize outer hash base with o_key_pad
        kctsb_sha512_init(&outer_ctx_);
        kctsb_sha512_update(&outer_ctx_, o_key_pad_, HMAC_SHA512_BLOCK_SIZE);

        inner_base_ = inner_ctx_;
        outer_base_ = outer_ctx_;
        initialized_ = true;

        kctsb_secure_zero(key_block, sizeof(key_block));
    }

    void update(const uint8_t* data, size_t len) {
        if (!initialized_) return;
        kctsb_sha512_update(&inner_ctx_, data, len);
    }

    void final(uint8_t mac[64]) {
        if (!initialized_) return;
        uint8_t inner_digest[HMAC_SHA512_DIGEST_SIZE];

        // Finalize inner hash
        kctsb_sha512_final(&inner_ctx_, inner_digest);

        // Compute outer hash: H(o_key_pad || inner_digest)
        kctsb_sha512_ctx_t outer_ctx = outer_base_;
        kctsb_sha512_update(&outer_ctx, inner_digest, HMAC_SHA512_DIGEST_SIZE);
        kctsb_sha512_final(&outer_ctx, mac);

        inner_ctx_ = inner_base_;
        kctsb_secure_zero(inner_digest, sizeof(inner_digest));
    }

private:
    void clear() {
        kctsb_secure_zero(&inner_ctx_, sizeof(inner_ctx_));
        kctsb_secure_zero(&outer_ctx_, sizeof(outer_ctx_));
        kctsb_secure_zero(&inner_base_, sizeof(inner_base_));
        kctsb_secure_zero(&outer_base_, sizeof(outer_base_));
        kctsb_secure_zero(i_key_pad_, sizeof(i_key_pad_));
        kctsb_secure_zero(o_key_pad_, sizeof(o_key_pad_));
        initialized_ = false;
    }

    kctsb_sha512_ctx_t inner_ctx_;
    kctsb_sha512_ctx_t outer_ctx_;
    kctsb_sha512_ctx_t inner_base_;
    kctsb_sha512_ctx_t outer_base_;
    uint8_t i_key_pad_[HMAC_SHA512_BLOCK_SIZE];
    uint8_t o_key_pad_[HMAC_SHA512_BLOCK_SIZE];
    bool initialized_;
};

// ============================================================================
// CMAC-AES128 Implementation (NIST SP 800-38B)
// ============================================================================

static constexpr size_t AES_BLOCK_SIZE = 16;

class CMAC_AES128 {
public:
    CMAC_AES128()
        : buffer_len_(0)
        , aes_ready_(false) {
    }

    ~CMAC_AES128() {
        clear();
    }

    void init(const uint8_t key[16]) {
        // Store key for AES operations
        std::memcpy(key_, key, 16);

        kctsb_aes_init(&aes_ctx_, key_, 16);
        aes_ready_ = true;

        // Generate subkeys K1 and K2
        generate_subkeys();

        // Initialize state
        std::memset(state_, 0, AES_BLOCK_SIZE);
        buffer_len_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        size_t offset = 0;

        // Process any buffered data first
        if (buffer_len_ > 0) {
            size_t needed = AES_BLOCK_SIZE - buffer_len_;
            if (len < needed) {
                std::memcpy(buffer_ + buffer_len_, data, len);
                buffer_len_ += len;
                return;
            }
            std::memcpy(buffer_ + buffer_len_, data, needed);
            xor_block(state_, buffer_);
            aes_encrypt_block(state_, state_);
            offset = needed;
            buffer_len_ = 0;
        }

        // Process complete blocks (except possibly last)
        while (offset + AES_BLOCK_SIZE < len) {
            xor_block(state_, data + offset);
            aes_encrypt_block(state_, state_);
            offset += AES_BLOCK_SIZE;
        }

        // Buffer remaining data
        size_t remaining = len - offset;
        if (remaining > 0) {
            std::memcpy(buffer_, data + offset, remaining);
            buffer_len_ = remaining;
        }
    }

    void final(uint8_t mac[16]) {
        uint8_t last_block[AES_BLOCK_SIZE];

        if (buffer_len_ == AES_BLOCK_SIZE) {
            // Complete block: XOR with K1
            xor_block_copy(last_block, buffer_, k1_);
        } else {
            // Incomplete block: pad and XOR with K2
            std::memcpy(last_block, buffer_, buffer_len_);
            last_block[buffer_len_] = 0x80;  // Padding
            std::memset(last_block + buffer_len_ + 1, 0, AES_BLOCK_SIZE - buffer_len_ - 1);
            xor_block(last_block, k2_);
        }

        xor_block(state_, last_block);
        aes_encrypt_block(state_, mac);

        // Clear sensitive state
        kctsb_secure_zero(state_, sizeof(state_));
        kctsb_secure_zero(buffer_, sizeof(buffer_));
        buffer_len_ = 0;
    }

private:
    void clear() {
        if (aes_ready_) {
            kctsb_aes_clear(&aes_ctx_);
        }
        kctsb_secure_zero(key_, sizeof(key_));
        kctsb_secure_zero(k1_, sizeof(k1_));
        kctsb_secure_zero(k2_, sizeof(k2_));
        kctsb_secure_zero(state_, sizeof(state_));
        kctsb_secure_zero(buffer_, sizeof(buffer_));
        buffer_len_ = 0;
        aes_ready_ = false;
    }

    void generate_subkeys() {
        uint8_t L[AES_BLOCK_SIZE];
        uint8_t zero[AES_BLOCK_SIZE] = {0};

        // L = AES_K(0^128)
        aes_encrypt_block(zero, L);

        // K1 = L << 1 (with conditional XOR)
        left_shift(L, k1_);
        if (L[0] & 0x80) {
            k1_[AES_BLOCK_SIZE - 1] ^= 0x87;  // R_128 constant
        }

        // K2 = K1 << 1 (with conditional XOR)
        left_shift(k1_, k2_);
        if (k1_[0] & 0x80) {
            k2_[AES_BLOCK_SIZE - 1] ^= 0x87;
        }
    }

    void left_shift(const uint8_t in[16], uint8_t out[16]) {
        uint8_t carry = 0;
        for (int i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
            uint8_t next_carry = (in[i] & 0x80) ? 1 : 0;
            out[i] = (in[i] << 1) | carry;
            carry = next_carry;
        }
    }

    void xor_block(uint8_t* dst, const uint8_t* src) {
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
            dst[i] ^= src[i];
        }
    }

    void xor_block_copy(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
        for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
            dst[i] = a[i] ^ b[i];
        }
    }

    void aes_encrypt_block(const uint8_t in[16], uint8_t out[16]) {
        // Use cached AES context
        kctsb_aes_encrypt_block(&aes_ctx_, in, out);
    }

    uint8_t key_[16];
    uint8_t k1_[AES_BLOCK_SIZE];
    uint8_t k2_[AES_BLOCK_SIZE];
    uint8_t state_[AES_BLOCK_SIZE];
    uint8_t buffer_[AES_BLOCK_SIZE];
    size_t buffer_len_;
    kctsb_aes_ctx_t aes_ctx_;
    bool aes_ready_;
};

// ============================================================================
// GMAC Implementation (NIST SP 800-38D)
// ============================================================================

class GMAC {
public:
    GMAC()
        : buffer_len_(0)
        , aad_len_(0) {
    }

    ~GMAC() {
        clear();
    }

    void init(const uint8_t key[16], const uint8_t* iv, size_t iv_len) {
        // Compute H = AES_K(0^128)
        uint8_t zero[16] = {0};
        kctsb_aes_ctx_t aes_ctx;
        kctsb_aes_init(&aes_ctx, key, 16);  // 16 bytes = 128-bit key
        kctsb_aes_encrypt_block(&aes_ctx, zero, H_);

        // Compute J0 (initial counter)
        if (iv_len == 12) {
            // Standard 96-bit IV: J0 = IV || 0^31 || 1
            std::memcpy(J0_, iv, 12);
            J0_[12] = 0x00;
            J0_[13] = 0x00;
            J0_[14] = 0x00;
            J0_[15] = 0x01;
        } else {
            // Non-standard IV: J0 = GHASH_H(IV || 0^s || len(IV))
            compute_j0_from_iv(iv, iv_len);
        }

        // Store AES key for final tag computation
        std::memcpy(key_, key, 16);

        // Initialize GHASH state
        std::memset(ghash_state_, 0, 16);
        aad_len_ = 0;
        buffer_len_ = 0;
    }

    void update_aad(const uint8_t* aad, size_t len) {
        ghash_update(aad, len);
        aad_len_ += len * 8;  // Length in bits
    }

    void final(uint8_t tag[16]) {
        // Pad AAD to block boundary
        if (buffer_len_ > 0) {
            std::memset(buffer_ + buffer_len_, 0, 16 - buffer_len_);
            kctsb_aes_gcm_ghash_update_internal(ghash_state_, H_, buffer_, 16);
            buffer_len_ = 0;
        }

        // Append length block: [len(A)]_64 || [0]_64
        uint8_t len_block[16] = {0};
        // AAD length in bits (big-endian)
        len_block[0] = static_cast<uint8_t>((aad_len_ >> 56) & 0xFF);
        len_block[1] = static_cast<uint8_t>((aad_len_ >> 48) & 0xFF);
        len_block[2] = static_cast<uint8_t>((aad_len_ >> 40) & 0xFF);
        len_block[3] = static_cast<uint8_t>((aad_len_ >> 32) & 0xFF);
        len_block[4] = static_cast<uint8_t>((aad_len_ >> 24) & 0xFF);
        len_block[5] = static_cast<uint8_t>((aad_len_ >> 16) & 0xFF);
        len_block[6] = static_cast<uint8_t>((aad_len_ >> 8) & 0xFF);
        len_block[7] = static_cast<uint8_t>(aad_len_ & 0xFF);
        // Ciphertext length = 0 for GMAC

        kctsb_aes_gcm_ghash_update_internal(ghash_state_, H_, len_block, 16);

        // Compute tag: GCTR_K(J0, S)
        kctsb_aes_ctx_t aes_ctx;
        kctsb_aes_init(&aes_ctx, key_, 16);  // 16 bytes = 128-bit key
        uint8_t E_J0[16];
        kctsb_aes_encrypt_block(&aes_ctx, J0_, E_J0);

        for (size_t i = 0; i < 16; i++) {
            tag[i] = ghash_state_[i] ^ E_J0[i];
        }
    }

private:
    void compute_j0_from_iv(const uint8_t* iv, size_t iv_len) {
        // GHASH(H, IV || 0^s || len(IV))
        std::memset(J0_, 0, 16);

        // Process IV blocks
        size_t offset = 0;
        while (offset + 16 <= iv_len) {
            kctsb_aes_gcm_ghash_update_internal(J0_, H_, iv + offset, 16);
            offset += 16;
        }

        // Handle remaining bytes
        if (offset < iv_len) {
            uint8_t block[16] = {0};
            std::memcpy(block, iv + offset, iv_len - offset);
            kctsb_aes_gcm_ghash_update_internal(J0_, H_, block, 16);
        }

        // Append length block
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = iv_len * 8;
        len_block[8] = static_cast<uint8_t>((iv_bits >> 56) & 0xFF);
        len_block[9] = static_cast<uint8_t>((iv_bits >> 48) & 0xFF);
        len_block[10] = static_cast<uint8_t>((iv_bits >> 40) & 0xFF);
        len_block[11] = static_cast<uint8_t>((iv_bits >> 32) & 0xFF);
        len_block[12] = static_cast<uint8_t>((iv_bits >> 24) & 0xFF);
        len_block[13] = static_cast<uint8_t>((iv_bits >> 16) & 0xFF);
        len_block[14] = static_cast<uint8_t>((iv_bits >> 8) & 0xFF);
        len_block[15] = static_cast<uint8_t>(iv_bits & 0xFF);

        kctsb_aes_gcm_ghash_update_internal(J0_, H_, len_block, 16);
    }

    void ghash_update(const uint8_t* data, size_t len) {
        size_t offset = 0;

        // Handle buffered data first
        if (buffer_len_ > 0) {
            size_t needed = 16 - buffer_len_;
            if (len < needed) {
                std::memcpy(buffer_ + buffer_len_, data, len);
                buffer_len_ += len;
                return;
            }
            std::memcpy(buffer_ + buffer_len_, data, needed);
            kctsb_aes_gcm_ghash_update_internal(ghash_state_, H_, buffer_, 16);
            offset = needed;
            buffer_len_ = 0;
        }

        // CRITICAL: Pass ALL complete blocks at once to enable 8-block parallel GHASH
        // The internal function uses PCLMUL with H^1~H^8 precomputation and deferred reduction
        size_t complete_blocks = ((len - offset) / 16) * 16;
        if (complete_blocks > 0) {
            kctsb_aes_gcm_ghash_update_internal(ghash_state_, H_, data + offset, complete_blocks);
            offset += complete_blocks;
        }

        // Buffer remaining partial block
        if (offset < len) {
            std::memcpy(buffer_, data + offset, len - offset);
            buffer_len_ = len - offset;
        }
    }

    void clear() {
        kctsb_secure_zero(key_, sizeof(key_));
        kctsb_secure_zero(H_, sizeof(H_));
        kctsb_secure_zero(J0_, sizeof(J0_));
        kctsb_secure_zero(ghash_state_, sizeof(ghash_state_));
        kctsb_secure_zero(buffer_, sizeof(buffer_));
        buffer_len_ = 0;
        aad_len_ = 0;
    }

    uint8_t key_[16];
    uint8_t H_[16];
    uint8_t J0_[16];
    uint8_t ghash_state_[16];
    uint8_t buffer_[16];
    size_t buffer_len_;
    uint64_t aad_len_;
};

static ObjectPool<HMAC_SHA256, HMAC256_POOL_SIZE> g_hmac256_pool;
static ObjectPool<HMAC_SHA512, HMAC512_POOL_SIZE> g_hmac512_pool;
static ObjectPool<CMAC_AES128, CMAC_POOL_SIZE> g_cmac_pool;
static ObjectPool<GMAC, GMAC_POOL_SIZE> g_gmac_pool;

}  // namespace internal
}  // namespace kctsb

// ============================================================================
// C ABI Exports
// ============================================================================

extern "C" {

// HMAC-SHA256

void kctsb_hmac_sha256_init(kctsb_hmac_ctx_t* ctx, const uint8_t* key, size_t key_len) {
    if (!ctx || !key) return;

    if (ctx->internal) {
        auto* old = static_cast<kctsb::internal::HMAC_SHA256*>(ctx->internal);
        kctsb::internal::g_hmac256_pool.release(old);
        ctx->internal = nullptr;
    }

    auto* hmac = kctsb::internal::g_hmac256_pool.acquire();
    hmac->init(key, key_len);
    ctx->internal = hmac;
}

void kctsb_hmac_sha256_update(kctsb_hmac_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !ctx->internal || !data) return;

    auto* hmac = static_cast<kctsb::internal::HMAC_SHA256*>(ctx->internal);
    hmac->update(data, len);
}

void kctsb_hmac_sha256_final(kctsb_hmac_ctx_t* ctx, uint8_t mac[32]) {
    if (!ctx || !ctx->internal || !mac) return;

    auto* hmac = static_cast<kctsb::internal::HMAC_SHA256*>(ctx->internal);
    hmac->final(mac);

    kctsb::internal::g_hmac256_pool.release(hmac);
    ctx->internal = nullptr;
}

void kctsb_hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t mac[32]) {
    if (!key || !data || !mac) return;

    kctsb::internal::HMAC_SHA256 hmac;
    hmac.init(key, key_len);
    hmac.update(data, len);
    hmac.final(mac);
}

// HMAC-SHA512

void kctsb_hmac_sha512_init(kctsb_hmac512_ctx_t* ctx, const uint8_t* key, size_t key_len) {
    if (!ctx || !key) return;

    if (ctx->internal) {
        auto* old = static_cast<kctsb::internal::HMAC_SHA512*>(ctx->internal);
        kctsb::internal::g_hmac512_pool.release(old);
        ctx->internal = nullptr;
    }

    auto* hmac = kctsb::internal::g_hmac512_pool.acquire();
    hmac->init(key, key_len);
    ctx->internal = hmac;
}

void kctsb_hmac_sha512_update(kctsb_hmac512_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !ctx->internal || !data) return;

    auto* hmac = static_cast<kctsb::internal::HMAC_SHA512*>(ctx->internal);
    hmac->update(data, len);
}

void kctsb_hmac_sha512_final(kctsb_hmac512_ctx_t* ctx, uint8_t mac[64]) {
    if (!ctx || !ctx->internal || !mac) return;

    auto* hmac = static_cast<kctsb::internal::HMAC_SHA512*>(ctx->internal);
    hmac->final(mac);

    kctsb::internal::g_hmac512_pool.release(hmac);
    ctx->internal = nullptr;
}

void kctsb_hmac_sha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t len, uint8_t mac[64]) {
    if (!key || !data || !mac) return;

    kctsb::internal::HMAC_SHA512 hmac;
    hmac.init(key, key_len);
    hmac.update(data, len);
    hmac.final(mac);
}

// CMAC-AES

void kctsb_cmac_aes_init(kctsb_cmac_ctx_t* ctx, const uint8_t key[16]) {
    if (!ctx || !key) return;

    if (ctx->internal) {
        auto* old = static_cast<kctsb::internal::CMAC_AES128*>(ctx->internal);
        kctsb::internal::g_cmac_pool.release(old);
        ctx->internal = nullptr;
    }

    auto* cmac = kctsb::internal::g_cmac_pool.acquire();
    cmac->init(key);
    ctx->internal = cmac;
}

void kctsb_cmac_aes_update(kctsb_cmac_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !ctx->internal || !data) return;

    auto* cmac = static_cast<kctsb::internal::CMAC_AES128*>(ctx->internal);
    cmac->update(data, len);
}

void kctsb_cmac_aes_final(kctsb_cmac_ctx_t* ctx, uint8_t mac[16]) {
    if (!ctx || !ctx->internal || !mac) return;

    auto* cmac = static_cast<kctsb::internal::CMAC_AES128*>(ctx->internal);
    cmac->final(mac);

    kctsb::internal::g_cmac_pool.release(cmac);
    ctx->internal = nullptr;
}

void kctsb_cmac_aes(const uint8_t key[16], const uint8_t* data, size_t len, uint8_t mac[16]) {
    if (!key || !data || !mac) return;

    kctsb::internal::CMAC_AES128 cmac;
    cmac.init(key);
    cmac.update(data, len);
    cmac.final(mac);
}

// GMAC

void kctsb_gmac_init(kctsb_gmac_ctx_t* ctx, const uint8_t key[16], const uint8_t* iv, size_t iv_len) {
    if (!ctx || !key || !iv) return;

    if (ctx->internal) {
        auto* old = static_cast<kctsb::internal::GMAC*>(ctx->internal);
        kctsb::internal::g_gmac_pool.release(old);
        ctx->internal = nullptr;
    }

    auto* gmac = kctsb::internal::g_gmac_pool.acquire();
    gmac->init(key, iv, iv_len);
    ctx->internal = gmac;
}

void kctsb_gmac_update(kctsb_gmac_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (!ctx || !ctx->internal || !data) return;

    auto* gmac = static_cast<kctsb::internal::GMAC*>(ctx->internal);
    gmac->update_aad(data, len);
}

void kctsb_gmac_final(kctsb_gmac_ctx_t* ctx, uint8_t tag[16]) {
    if (!ctx || !ctx->internal || !tag) return;

    auto* gmac = static_cast<kctsb::internal::GMAC*>(ctx->internal);
    gmac->final(tag);

    kctsb::internal::g_gmac_pool.release(gmac);
    ctx->internal = nullptr;
}

void kctsb_gmac(const uint8_t key[16], const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len, uint8_t tag[16]) {
    if (!key || !iv || !tag) return;

    kctsb::internal::GMAC gmac;
    gmac.init(key, iv, iv_len);
    if (aad && aad_len > 0) {
        gmac.update_aad(aad, aad_len);
    }
    gmac.final(tag);
}

}  // extern "C"
