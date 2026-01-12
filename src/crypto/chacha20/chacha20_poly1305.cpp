/**
 * @file chacha20_poly1305.cpp
 * @brief ChaCha20-Poly1305 AEAD Implementation
 * 
 * RFC 8439 compliant implementation with:
 * - ChaCha20 quarter-round based stream cipher
 * - Poly1305 polynomial MAC with 130-bit field
 * - Combined AEAD construction
 * 
 * Security features:
 * - Constant-time operations
 * - No table lookups with secret-dependent indices
 * - Secure memory cleanup
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/chacha20_poly1305.h"
#include "kctsb/core/security.h"
#include <cstring>
#include <stdexcept>

// ============================================================================
// ChaCha20 Implementation
// ============================================================================

/**
 * @brief ChaCha20 quarter round
 * 
 * The core mixing function of ChaCha20
 */
static inline void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

/**
 * @brief Load 32-bit little-endian value
 */
static inline uint32_t load32_le(const uint8_t* p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | 
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * @brief Store 32-bit little-endian value
 */
static inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/**
 * @brief Store 64-bit little-endian value
 */
static inline void store64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (i * 8));
    }
}

/**
 * @brief Generate one ChaCha20 block
 * 
 * @param state 16-word state (key, counter, nonce)
 * @param output 64-byte output block
 */
static void chacha20_block(const uint32_t state[16], uint8_t output[64]) {
    uint32_t working[16];
    
    // Copy state to working array
    for (int i = 0; i < 16; i++) {
        working[i] = state[i];
    }
    
    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        chacha_quarter_round(working[0], working[4], working[8],  working[12]);
        chacha_quarter_round(working[1], working[5], working[9],  working[13]);
        chacha_quarter_round(working[2], working[6], working[10], working[14]);
        chacha_quarter_round(working[3], working[7], working[11], working[15]);
        
        // Diagonal rounds
        chacha_quarter_round(working[0], working[5], working[10], working[15]);
        chacha_quarter_round(working[1], working[6], working[11], working[12]);
        chacha_quarter_round(working[2], working[7], working[8],  working[13]);
        chacha_quarter_round(working[3], working[4], working[9],  working[14]);
    }
    
    // Add original state and serialize to output
    for (int i = 0; i < 16; i++) {
        uint32_t result = working[i] + state[i];
        store32_le(&output[i * 4], result);
    }
    
    kctsb_secure_zero(working, sizeof(working));
}

// ChaCha20 constants: "expand 32-byte k"
static const uint32_t CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

extern "C" {

kctsb_error_t kctsb_chacha20_init(kctsb_chacha20_ctx_t* ctx,
                                   const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   uint32_t counter) {
    if (!ctx || !key || !nonce) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Initialize state
    // Constants
    ctx->state[0] = CHACHA_CONSTANTS[0];
    ctx->state[1] = CHACHA_CONSTANTS[1];
    ctx->state[2] = CHACHA_CONSTANTS[2];
    ctx->state[3] = CHACHA_CONSTANTS[3];
    
    // Key (8 words)
    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = load32_le(&key[i * 4]);
    }
    
    // Counter (1 word)
    ctx->state[12] = counter;
    
    // Nonce (3 words)
    ctx->state[13] = load32_le(&nonce[0]);
    ctx->state[14] = load32_le(&nonce[4]);
    ctx->state[15] = load32_le(&nonce[8]);
    
    ctx->remaining = 0;
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_crypt(kctsb_chacha20_ctx_t* ctx,
                                    const uint8_t* input,
                                    size_t input_len,
                                    uint8_t* output) {
    if (!ctx || !input || !output) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    size_t offset = 0;
    
    // Use any remaining keystream first
    if (ctx->remaining > 0) {
        size_t use = (input_len < ctx->remaining) ? input_len : ctx->remaining;
        size_t ks_offset = 64 - ctx->remaining;
        
        for (size_t i = 0; i < use; i++) {
            output[i] = input[i] ^ ctx->keystream[ks_offset + i];
        }
        
        ctx->remaining -= use;
        offset = use;
    }
    
    // Process full blocks
    while (offset + 64 <= input_len) {
        chacha20_block(ctx->state, ctx->keystream);
        ctx->state[12]++;  // Increment counter
        
        for (int i = 0; i < 64; i++) {
            output[offset + i] = input[offset + i] ^ ctx->keystream[i];
        }
        
        offset += 64;
    }
    
    // Handle remaining bytes
    if (offset < input_len) {
        chacha20_block(ctx->state, ctx->keystream);
        ctx->state[12]++;
        
        size_t remaining = input_len - offset;
        for (size_t i = 0; i < remaining; i++) {
            output[offset + i] = input[offset + i] ^ ctx->keystream[i];
        }
        
        ctx->remaining = 64 - remaining;
    }
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20(const uint8_t key[32],
                             const uint8_t nonce[12],
                             uint32_t counter,
                             const uint8_t* input,
                             size_t input_len,
                             uint8_t* output) {
    kctsb_chacha20_ctx_t ctx;
    kctsb_error_t err;
    
    err = kctsb_chacha20_init(&ctx, key, nonce, counter);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    err = kctsb_chacha20_crypt(&ctx, input, input_len, output);
    
    kctsb_chacha20_clear(&ctx);
    return err;
}

void kctsb_chacha20_clear(kctsb_chacha20_ctx_t* ctx) {
    if (ctx) {
        kctsb_secure_zero(ctx, sizeof(kctsb_chacha20_ctx_t));
    }
}

// ============================================================================
// Poly1305 Implementation
// ============================================================================

/**
 * @brief Process one 16-byte block in Poly1305
 * 
 * Uses 64-bit arithmetic for the 130-bit field multiplication
 */
static void poly1305_block(kctsb_poly1305_ctx_t* ctx, const uint8_t block[16], int is_final_block) {
    // Load block as little-endian limbs
    uint32_t t0 = load32_le(&block[0]);
    uint32_t t1 = load32_le(&block[4]);
    uint32_t t2 = load32_le(&block[8]);
    uint32_t t3 = load32_le(&block[12]);
    
    // Add block to accumulator
    uint64_t h0 = ctx->h[0] + (t0 & 0x3ffffff);
    uint64_t h1 = ctx->h[1] + (((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
    uint64_t h2 = ctx->h[2] + (((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
    uint64_t h3 = ctx->h[3] + (((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
    uint64_t h4 = ctx->h[4] + (t3 >> 8);
    
    // Add padding bit (1 for non-final, 0 for final)
    if (!is_final_block) {
        h4 += (1ULL << 24);
    }
    
    // Multiply by r (mod 2^130 - 5)
    uint32_t r0 = ctx->r[0];
    uint32_t r1 = ctx->r[1];
    uint32_t r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3];
    uint32_t r4 = ctx->r[4];
    
    // Pre-compute 5*r for reduction
    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;
    
    // Multiplication with partial reduction
    uint64_t d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
    uint64_t d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
    uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
    uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
    uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;
    
    // Carry propagation
    uint64_t c;
    c = d0 >> 26; d1 += c; d0 &= 0x3ffffff;
    c = d1 >> 26; d2 += c; d1 &= 0x3ffffff;
    c = d2 >> 26; d3 += c; d2 &= 0x3ffffff;
    c = d3 >> 26; d4 += c; d3 &= 0x3ffffff;
    c = d4 >> 26; d0 += c * 5; d4 &= 0x3ffffff;
    c = d0 >> 26; d1 += c; d0 &= 0x3ffffff;
    
    ctx->h[0] = (uint32_t)d0;
    ctx->h[1] = (uint32_t)d1;
    ctx->h[2] = (uint32_t)d2;
    ctx->h[3] = (uint32_t)d3;
    ctx->h[4] = (uint32_t)d4;
}

kctsb_error_t kctsb_poly1305_init(kctsb_poly1305_ctx_t* ctx, const uint8_t key[32]) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(kctsb_poly1305_ctx_t));
    
    // Load and clamp r (first 16 bytes)
    uint32_t t0 = load32_le(&key[0]);
    uint32_t t1 = load32_le(&key[4]);
    uint32_t t2 = load32_le(&key[8]);
    uint32_t t3 = load32_le(&key[12]);
    
    // Clamp r: clear bits 4,8,12,13,14,15 of each 32-bit word
    ctx->r[0] = (t0) & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    ctx->r[4] = (t3 >> 8) & 0x00fffff;
    
    // Load s (last 16 bytes) - used for final addition
    ctx->s[0] = load32_le(&key[16]);
    ctx->s[1] = load32_le(&key[20]);
    ctx->s[2] = load32_le(&key[24]);
    ctx->s[3] = load32_le(&key[28]);
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305_update(kctsb_poly1305_ctx_t* ctx,
                                     const uint8_t* data,
                                     size_t len) {
    if (!ctx) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (len == 0) {
        return KCTSB_SUCCESS;
    }
    if (!data) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    size_t offset = 0;
    
    // Fill buffer if partial
    if (ctx->buffer_len > 0) {
        size_t need = 16 - ctx->buffer_len;
        size_t use = (len < need) ? len : need;
        
        memcpy(&ctx->buffer[ctx->buffer_len], data, use);
        ctx->buffer_len += use;
        offset = use;
        
        if (ctx->buffer_len == 16) {
            poly1305_block(ctx, ctx->buffer, 0);
            ctx->buffer_len = 0;
        }
    }
    
    // Process full blocks
    while (offset + 16 <= len) {
        poly1305_block(ctx, &data[offset], 0);
        offset += 16;
    }
    
    // Buffer remaining
    if (offset < len) {
        memcpy(ctx->buffer, &data[offset], len - offset);
        ctx->buffer_len = len - offset;
    }
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305_final(kctsb_poly1305_ctx_t* ctx, uint8_t tag[16]) {
    if (!ctx || !tag) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Process final partial block
    if (ctx->buffer_len > 0) {
        // Pad with 1 followed by zeros
        ctx->buffer[ctx->buffer_len] = 1;
        for (size_t i = ctx->buffer_len + 1; i < 16; i++) {
            ctx->buffer[i] = 0;
        }
        poly1305_block(ctx, ctx->buffer, 1);
    }
    
    // Final reduction modulo 2^130 - 5
    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];
    
    // Fully carry
    uint32_t c;
    c = h1 >> 26; h2 += c; h1 &= 0x3ffffff;
    c = h2 >> 26; h3 += c; h2 &= 0x3ffffff;
    c = h3 >> 26; h4 += c; h3 &= 0x3ffffff;
    c = h4 >> 26; h0 += c * 5; h4 &= 0x3ffffff;
    c = h0 >> 26; h1 += c; h0 &= 0x3ffffff;
    
    // Compute h - p (mod 2^130)
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);
    
    // Select h or g based on sign of h - p
    uint32_t mask = (g4 >> 31) - 1;  // 0 if h >= p, -1 if h < p
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);
    
    // Convert to 128-bit value and add s
    uint64_t f0 = ((h0) | (h1 << 26)) + (uint64_t)ctx->s[0];
    uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + (uint64_t)ctx->s[1];
    uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + (uint64_t)ctx->s[2];
    uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + (uint64_t)ctx->s[3];
    
    // Carry propagation
    f1 += f0 >> 32;
    f2 += f1 >> 32;
    f3 += f2 >> 32;
    
    // Store result
    store32_le(&tag[0], (uint32_t)f0);
    store32_le(&tag[4], (uint32_t)f1);
    store32_le(&tag[8], (uint32_t)f2);
    store32_le(&tag[12], (uint32_t)f3);
    
    ctx->finalized = 1;
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_poly1305(const uint8_t key[32],
                              const uint8_t* data,
                              size_t len,
                              uint8_t tag[16]) {
    kctsb_poly1305_ctx_t ctx;
    kctsb_error_t err;
    
    err = kctsb_poly1305_init(&ctx, key);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    err = kctsb_poly1305_update(&ctx, data, len);
    if (err != KCTSB_SUCCESS) {
        kctsb_poly1305_clear(&ctx);
        return err;
    }
    
    err = kctsb_poly1305_final(&ctx, tag);
    kctsb_poly1305_clear(&ctx);
    
    return err;
}

kctsb_error_t kctsb_poly1305_verify(const uint8_t key[32],
                                     const uint8_t* data,
                                     size_t len,
                                     const uint8_t tag[16]) {
    uint8_t computed_tag[16];
    
    kctsb_error_t err = kctsb_poly1305(key, data, len, computed_tag);
    if (err != KCTSB_SUCCESS) {
        return err;
    }
    
    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(computed_tag, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }
    
    kctsb_secure_zero(computed_tag, 16);
    return KCTSB_SUCCESS;
}

void kctsb_poly1305_clear(kctsb_poly1305_ctx_t* ctx) {
    if (ctx) {
        kctsb_secure_zero(ctx, sizeof(kctsb_poly1305_ctx_t));
    }
}

// ============================================================================
// ChaCha20-Poly1305 AEAD
// ============================================================================

/**
 * @brief Pad to 16-byte boundary for Poly1305
 */
static void pad_to_16(kctsb_poly1305_ctx_t* ctx, size_t len) {
    if (len % 16 != 0) {
        uint8_t zeros[16] = {0};
        kctsb_poly1305_update(ctx, zeros, 16 - (len % 16));
    }
}

kctsb_error_t kctsb_chacha20_poly1305_encrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const uint8_t* plaintext,
                                               size_t plaintext_len,
                                               uint8_t* ciphertext,
                                               uint8_t tag[16]) {
    if (!key || !nonce || !ciphertext || !tag) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (plaintext_len > 0 && !plaintext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Generate Poly1305 one-time key using ChaCha20 with counter 0
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20(key, nonce, 0, zeros, 64, poly_key);
    
    // Encrypt plaintext using ChaCha20 with counter 1
    if (plaintext_len > 0) {
        kctsb_chacha20(key, nonce, 1, plaintext, plaintext_len, ciphertext);
    }
    
    // Compute Poly1305 tag over AAD || padding || ciphertext || padding || lengths
    kctsb_poly1305_ctx_t poly_ctx;
    kctsb_poly1305_init(&poly_ctx, poly_key);
    
    // AAD
    if (aad && aad_len > 0) {
        kctsb_poly1305_update(&poly_ctx, aad, aad_len);
        pad_to_16(&poly_ctx, aad_len);
    }
    
    // Ciphertext
    if (plaintext_len > 0) {
        kctsb_poly1305_update(&poly_ctx, ciphertext, plaintext_len);
        pad_to_16(&poly_ctx, plaintext_len);
    }
    
    // Lengths (little-endian 64-bit)
    uint8_t len_block[16];
    store64_le(&len_block[0], aad_len);
    store64_le(&len_block[8], plaintext_len);
    kctsb_poly1305_update(&poly_ctx, len_block, 16);
    
    kctsb_poly1305_final(&poly_ctx, tag);
    
    // Cleanup
    kctsb_secure_zero(poly_key, 64);
    kctsb_poly1305_clear(&poly_ctx);
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_decrypt(const uint8_t key[32],
                                               const uint8_t nonce[12],
                                               const uint8_t* aad,
                                               size_t aad_len,
                                               const uint8_t* ciphertext,
                                               size_t ciphertext_len,
                                               const uint8_t tag[16],
                                               uint8_t* plaintext) {
    if (!key || !nonce || !tag || !plaintext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ciphertext_len > 0 && !ciphertext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Generate Poly1305 one-time key
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20(key, nonce, 0, zeros, 64, poly_key);
    
    // Compute expected tag
    kctsb_poly1305_ctx_t poly_ctx;
    kctsb_poly1305_init(&poly_ctx, poly_key);
    
    if (aad && aad_len > 0) {
        kctsb_poly1305_update(&poly_ctx, aad, aad_len);
        pad_to_16(&poly_ctx, aad_len);
    }
    
    if (ciphertext_len > 0) {
        kctsb_poly1305_update(&poly_ctx, ciphertext, ciphertext_len);
        pad_to_16(&poly_ctx, ciphertext_len);
    }
    
    uint8_t len_block[16];
    store64_le(&len_block[0], aad_len);
    store64_le(&len_block[8], ciphertext_len);
    kctsb_poly1305_update(&poly_ctx, len_block, 16);
    
    uint8_t computed_tag[16];
    kctsb_poly1305_final(&poly_ctx, computed_tag);
    
    // Constant-time tag verification
    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(poly_key, 64);
        kctsb_secure_zero(computed_tag, 16);
        kctsb_poly1305_clear(&poly_ctx);
        kctsb_secure_zero(plaintext, ciphertext_len);
        return KCTSB_ERROR_AUTH_FAILED;
    }
    
    // Decrypt ciphertext
    if (ciphertext_len > 0) {
        kctsb_chacha20(key, nonce, 1, ciphertext, ciphertext_len, plaintext);
    }
    
    // Cleanup
    kctsb_secure_zero(poly_key, 64);
    kctsb_secure_zero(computed_tag, 16);
    kctsb_poly1305_clear(&poly_ctx);
    
    return KCTSB_SUCCESS;
}

// Streaming API

kctsb_error_t kctsb_chacha20_poly1305_init_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                    const uint8_t key[32],
                                                    const uint8_t nonce[12]) {
    if (!ctx || !key || !nonce) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(kctsb_chacha20_poly1305_ctx_t));
    
    // Generate Poly1305 key
    uint8_t poly_key[64];
    uint8_t zeros[64] = {0};
    kctsb_chacha20(key, nonce, 0, zeros, 64, poly_key);
    
    // Initialize Poly1305
    kctsb_poly1305_init(&ctx->poly_ctx, poly_key);
    kctsb_secure_zero(poly_key, 64);
    
    // Initialize ChaCha20 with counter 1
    kctsb_chacha20_init(&ctx->chacha_ctx, key, nonce, 1);
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_init_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                    const uint8_t key[32],
                                                    const uint8_t nonce[12]) {
    // Same initialization as encrypt
    return kctsb_chacha20_poly1305_init_encrypt(ctx, key, nonce);
}

kctsb_error_t kctsb_chacha20_poly1305_update_aad(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                  const uint8_t* aad,
                                                  size_t aad_len) {
    if (!ctx) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (ctx->aad_finalized || ctx->ct_len > 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    if (aad && aad_len > 0) {
        kctsb_poly1305_update(&ctx->poly_ctx, aad, aad_len);
        ctx->aad_len += aad_len;
    }
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_update_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                      const uint8_t* plaintext,
                                                      size_t plaintext_len,
                                                      uint8_t* ciphertext) {
    if (!ctx || !plaintext || !ciphertext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Finalize AAD if not done
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    
    // Encrypt
    kctsb_chacha20_crypt(&ctx->chacha_ctx, plaintext, plaintext_len, ciphertext);
    
    // Update Poly1305 with ciphertext
    kctsb_poly1305_update(&ctx->poly_ctx, ciphertext, plaintext_len);
    ctx->ct_len += plaintext_len;
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_update_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                      const uint8_t* ciphertext,
                                                      size_t ciphertext_len,
                                                      uint8_t* plaintext) {
    if (!ctx || !ciphertext || !plaintext) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Finalize AAD if not done
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    
    // Update Poly1305 with ciphertext (before decryption)
    kctsb_poly1305_update(&ctx->poly_ctx, ciphertext, ciphertext_len);
    ctx->ct_len += ciphertext_len;
    
    // Decrypt
    kctsb_chacha20_crypt(&ctx->chacha_ctx, ciphertext, ciphertext_len, plaintext);
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_final_encrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                     uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Finalize AAD if needed
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    
    // Pad ciphertext
    pad_to_16(&ctx->poly_ctx, ctx->ct_len);
    
    // Append lengths
    uint8_t len_block[16];
    store64_le(&len_block[0], ctx->aad_len);
    store64_le(&len_block[8], ctx->ct_len);
    kctsb_poly1305_update(&ctx->poly_ctx, len_block, 16);
    
    // Get tag
    kctsb_poly1305_final(&ctx->poly_ctx, tag);
    ctx->finalized = 1;
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_chacha20_poly1305_final_decrypt(kctsb_chacha20_poly1305_ctx_t* ctx,
                                                     const uint8_t tag[16]) {
    if (!ctx || !tag || ctx->finalized) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Finalize AAD if needed
    if (!ctx->aad_finalized) {
        pad_to_16(&ctx->poly_ctx, ctx->aad_len);
        ctx->aad_finalized = 1;
    }
    
    // Pad ciphertext
    pad_to_16(&ctx->poly_ctx, ctx->ct_len);
    
    // Append lengths
    uint8_t len_block[16];
    store64_le(&len_block[0], ctx->aad_len);
    store64_le(&len_block[8], ctx->ct_len);
    kctsb_poly1305_update(&ctx->poly_ctx, len_block, 16);
    
    // Get computed tag
    uint8_t computed_tag[16];
    kctsb_poly1305_final(&ctx->poly_ctx, computed_tag);
    ctx->finalized = 1;
    
    // Verify
    if (!kctsb_secure_compare(tag, computed_tag, 16)) {
        kctsb_secure_zero(computed_tag, 16);
        return KCTSB_ERROR_AUTH_FAILED;
    }
    
    kctsb_secure_zero(computed_tag, 16);
    return KCTSB_SUCCESS;
}

void kctsb_chacha20_poly1305_clear(kctsb_chacha20_poly1305_ctx_t* ctx) {
    if (ctx) {
        kctsb_chacha20_clear(&ctx->chacha_ctx);
        kctsb_poly1305_clear(&ctx->poly_ctx);
        kctsb_secure_zero(ctx, sizeof(kctsb_chacha20_poly1305_ctx_t));
    }
}

} // extern "C"

// ============================================================================
// C++ Implementation
// ============================================================================

namespace kctsb {

ChaCha20Poly1305::ChaCha20Poly1305(const ByteVec& key) {
    if (key.size() != KEY_SIZE) {
        throw std::invalid_argument("ChaCha20-Poly1305 requires 256-bit (32 byte) key");
    }
    memcpy(key_.data(), key.data(), KEY_SIZE);
}

ChaCha20Poly1305::ChaCha20Poly1305(const uint8_t key[32]) {
    if (!key) {
        throw std::invalid_argument("Key cannot be null");
    }
    memcpy(key_.data(), key, KEY_SIZE);
}

ChaCha20Poly1305::~ChaCha20Poly1305() {
    kctsb_secure_zero(key_.data(), KEY_SIZE);
}

ChaCha20Poly1305::ChaCha20Poly1305(ChaCha20Poly1305&& other) noexcept {
    key_ = other.key_;
    kctsb_secure_zero(other.key_.data(), KEY_SIZE);
}

ChaCha20Poly1305& ChaCha20Poly1305::operator=(ChaCha20Poly1305&& other) noexcept {
    if (this != &other) {
        kctsb_secure_zero(key_.data(), KEY_SIZE);
        key_ = other.key_;
        kctsb_secure_zero(other.key_.data(), KEY_SIZE);
    }
    return *this;
}

std::pair<ByteVec, std::array<uint8_t, 16>> ChaCha20Poly1305::encrypt(
    const ByteVec& plaintext,
    const std::array<uint8_t, 12>& nonce,
    const ByteVec& aad) const {
    
    ByteVec ciphertext(plaintext.size());
    std::array<uint8_t, 16> tag;
    
    kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
        key_.data(), nonce.data(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        plaintext.data(), plaintext.size(),
        ciphertext.data(), tag.data()
    );
    
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
    }
    
    return {std::move(ciphertext), tag};
}

ByteVec ChaCha20Poly1305::decrypt(
    const ByteVec& ciphertext,
    const std::array<uint8_t, 12>& nonce,
    const std::array<uint8_t, 16>& tag,
    const ByteVec& aad) const {
    
    ByteVec plaintext(ciphertext.size());
    
    kctsb_error_t err = kctsb_chacha20_poly1305_decrypt(
        key_.data(), nonce.data(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        tag.data(), plaintext.data()
    );
    
    if (err == KCTSB_ERROR_AUTH_FAILED) {
        throw std::runtime_error("ChaCha20-Poly1305 authentication failed");
    }
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("ChaCha20-Poly1305 decryption failed");
    }
    
    return plaintext;
}

std::array<uint8_t, 12> ChaCha20Poly1305::generateNonce() {
    std::array<uint8_t, 12> nonce;
    if (kctsb_random_bytes(nonce.data(), 12) != KCTSB_SUCCESS) {
        throw std::runtime_error("Failed to generate random nonce");
    }
    return nonce;
}

ByteVec ChaCha20Poly1305::generateKey() {
    ByteVec key(KEY_SIZE);
    if (kctsb_random_bytes(key.data(), KEY_SIZE) != KCTSB_SUCCESS) {
        throw std::runtime_error("Failed to generate random key");
    }
    return key;
}

} // namespace kctsb
