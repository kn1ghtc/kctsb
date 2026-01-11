/**
 * @file chacha20.c
 * @brief ChaCha20 stream cipher implementation
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * Pure C implementation of ChaCha20 based on RFC 8439.
 */

#include "chacha20.h"
#include <string.h>

/* ChaCha20 constants "expand 32-byte k" */
static const uint32_t CHACHA_CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t w) {
    p[0] = (uint8_t)w;
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

/* ChaCha20 quarter round */
#define QUARTERROUND(a, b, c, d)    \
    do {                            \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d, 8);  \
        c += d; b ^= c; b = rotl32(b, 7);  \
    } while (0)

int chacha20_init(chacha20_ctx_t *ctx, const uint8_t key[32],
                  const uint8_t nonce[12], uint32_t counter) {
    if (!ctx || !key || !nonce) return -1;
    
    /* Set constants */
    ctx->state[0] = CHACHA_CONSTANTS[0];
    ctx->state[1] = CHACHA_CONSTANTS[1];
    ctx->state[2] = CHACHA_CONSTANTS[2];
    ctx->state[3] = CHACHA_CONSTANTS[3];
    
    /* Set key */
    ctx->state[4]  = load32_le(key + 0);
    ctx->state[5]  = load32_le(key + 4);
    ctx->state[6]  = load32_le(key + 8);
    ctx->state[7]  = load32_le(key + 12);
    ctx->state[8]  = load32_le(key + 16);
    ctx->state[9]  = load32_le(key + 20);
    ctx->state[10] = load32_le(key + 24);
    ctx->state[11] = load32_le(key + 28);
    
    /* Set counter */
    ctx->state[12] = counter;
    
    /* Set nonce */
    ctx->state[13] = load32_le(nonce + 0);
    ctx->state[14] = load32_le(nonce + 4);
    ctx->state[15] = load32_le(nonce + 8);
    
    ctx->available = 0;
    ctx->counter = counter;
    
    return 0;
}

void chacha20_block(chacha20_ctx_t *ctx, uint8_t out[64]) {
    uint32_t x[16];
    
    /* Copy state */
    for (int i = 0; i < 16; i++) {
        x[i] = ctx->state[i];
    }
    
    /* 20 rounds (10 double rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QUARTERROUND(x[0], x[4], x[8],  x[12]);
        QUARTERROUND(x[1], x[5], x[9],  x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8],  x[13]);
        QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }
    
    /* Add original state */
    for (int i = 0; i < 16; i++) {
        x[i] += ctx->state[i];
    }
    
    /* Serialize output */
    for (int i = 0; i < 16; i++) {
        store32_le(out + i * 4, x[i]);
    }
    
    /* Increment counter */
    ctx->state[12]++;
}

int chacha20_crypt(chacha20_ctx_t *ctx, const uint8_t *in, uint8_t *out, size_t len) {
    if (!ctx) return -1;
    if (len == 0) return 0;
    if (!in || !out) return -1;
    
    size_t pos = 0;
    
    /* Use any remaining keystream */
    if (ctx->available > 0) {
        size_t use = (len < ctx->available) ? len : ctx->available;
        size_t offset = CHACHA20_BLOCKSIZE - ctx->available;
        
        for (size_t i = 0; i < use; i++) {
            out[i] = in[i] ^ ctx->keystream[offset + i];
        }
        
        ctx->available -= use;
        pos += use;
    }
    
    /* Process full blocks */
    while (pos + CHACHA20_BLOCKSIZE <= len) {
        uint8_t block[64];
        chacha20_block(ctx, block);
        
        for (int i = 0; i < 64; i++) {
            out[pos + i] = in[pos + i] ^ block[i];
        }
        
        pos += 64;
    }
    
    /* Handle remaining bytes */
    if (pos < len) {
        chacha20_block(ctx, ctx->keystream);
        ctx->available = CHACHA20_BLOCKSIZE;
        
        size_t remaining = len - pos;
        for (size_t i = 0; i < remaining; i++) {
            out[pos + i] = in[pos + i] ^ ctx->keystream[i];
        }
        ctx->available -= remaining;
    }
    
    return 0;
}

int chacha20(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
             const uint8_t *in, uint8_t *out, size_t len) {
    chacha20_ctx_t ctx;
    
    if (chacha20_init(&ctx, key, nonce, counter) < 0) return -1;
    return chacha20_crypt(&ctx, in, out, len);
}
