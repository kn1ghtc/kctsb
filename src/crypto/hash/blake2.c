/**
 * @file blake2.c
 * @brief BLAKE2 hash function implementation
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * Pure C implementation of BLAKE2b and BLAKE2s.
 * Based on RFC 7693 specification.
 */

#include "blake2.h"
#include <string.h>

/* ============================================================================
 * BLAKE2b Implementation
 * ============================================================================ */

/* BLAKE2b initialization vector */
static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* BLAKE2b sigma table */
static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static inline uint64_t rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[0]      ) | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void store64(void *dst, uint64_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
    p[4] = (uint8_t)(w >> 32); p[5] = (uint8_t)(w >> 40);
    p[6] = (uint8_t)(w >> 48); p[7] = (uint8_t)(w >> 56);
}

#define B2B_G(a, b, c, d, x, y)         \
    do {                                \
        a = a + b + x;                  \
        d = rotr64(d ^ a, 32);          \
        c = c + d;                      \
        b = rotr64(b ^ c, 24);          \
        a = a + b + y;                  \
        d = rotr64(d ^ a, 16);          \
        c = c + d;                      \
        b = rotr64(b ^ c, 63);          \
    } while (0)

static void blake2b_compress(blake2b_ctx_t *ctx, const uint8_t block[128]) {
    uint64_t m[16], v[16];
    
    for (int i = 0; i < 16; i++) {
        m[i] = load64(block + i * 8);
    }
    
    for (int i = 0; i < 8; i++) {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_IV[i];
    }
    
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= ctx->f[0];
    v[15] ^= ctx->f[1];
    
    for (int i = 0; i < 12; i++) {
        B2B_G(v[0], v[4], v[ 8], v[12], m[blake2b_sigma[i][ 0]], m[blake2b_sigma[i][ 1]]);
        B2B_G(v[1], v[5], v[ 9], v[13], m[blake2b_sigma[i][ 2]], m[blake2b_sigma[i][ 3]]);
        B2B_G(v[2], v[6], v[10], v[14], m[blake2b_sigma[i][ 4]], m[blake2b_sigma[i][ 5]]);
        B2B_G(v[3], v[7], v[11], v[15], m[blake2b_sigma[i][ 6]], m[blake2b_sigma[i][ 7]]);
        B2B_G(v[0], v[5], v[10], v[15], m[blake2b_sigma[i][ 8]], m[blake2b_sigma[i][ 9]]);
        B2B_G(v[1], v[6], v[11], v[12], m[blake2b_sigma[i][10]], m[blake2b_sigma[i][11]]);
        B2B_G(v[2], v[7], v[ 8], v[13], m[blake2b_sigma[i][12]], m[blake2b_sigma[i][13]]);
        B2B_G(v[3], v[4], v[ 9], v[14], m[blake2b_sigma[i][14]], m[blake2b_sigma[i][15]]);
    }
    
    for (int i = 0; i < 8; i++) {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

int blake2b_init(blake2b_ctx_t *ctx, size_t outlen) {
    if (!ctx || outlen == 0 || outlen > BLAKE2B_OUTBYTES) return -1;
    
    memset(ctx, 0, sizeof(blake2b_ctx_t));
    for (int i = 0; i < 8; i++) ctx->h[i] = blake2b_IV[i];
    ctx->h[0] ^= 0x01010000 ^ outlen;
    ctx->outlen = outlen;
    
    return 0;
}

int blake2b_init_key(blake2b_ctx_t *ctx, size_t outlen, const void *key, size_t keylen) {
    if (!ctx || outlen == 0 || outlen > BLAKE2B_OUTBYTES) return -1;
    if (keylen > BLAKE2B_KEYBYTES) return -1;
    
    memset(ctx, 0, sizeof(blake2b_ctx_t));
    for (int i = 0; i < 8; i++) ctx->h[i] = blake2b_IV[i];
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    ctx->outlen = outlen;
    
    if (keylen > 0) {
        uint8_t block[BLAKE2B_BLOCKBYTES] = {0};
        memcpy(block, key, keylen);
        blake2b_update(ctx, block, BLAKE2B_BLOCKBYTES);
        memset(block, 0, sizeof(block));
    }
    
    return 0;
}

int blake2b_update(blake2b_ctx_t *ctx, const void *in, size_t inlen) {
    if (!ctx || (!in && inlen > 0)) return -1;
    
    const uint8_t *pin = (const uint8_t *)in;
    
    while (inlen > 0) {
        size_t left = ctx->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;
        
        if (inlen > fill) {
            memcpy(ctx->buf + left, pin, fill);
            ctx->t[0] += BLAKE2B_BLOCKBYTES;
            if (ctx->t[0] < BLAKE2B_BLOCKBYTES) ctx->t[1]++;
            blake2b_compress(ctx, ctx->buf);
            ctx->buflen = 0;
            pin += fill;
            inlen -= fill;
        } else {
            memcpy(ctx->buf + left, pin, inlen);
            ctx->buflen += inlen;
            break;
        }
    }
    
    return 0;
}

int blake2b_final(blake2b_ctx_t *ctx, void *out, size_t outlen) {
    if (!ctx || !out || outlen < ctx->outlen) return -1;
    
    ctx->t[0] += ctx->buflen;
    if (ctx->t[0] < ctx->buflen) ctx->t[1]++;
    ctx->f[0] = (uint64_t)-1;
    
    memset(ctx->buf + ctx->buflen, 0, BLAKE2B_BLOCKBYTES - ctx->buflen);
    blake2b_compress(ctx, ctx->buf);
    
    uint8_t buffer[BLAKE2B_OUTBYTES];
    for (int i = 0; i < 8; i++) {
        store64(buffer + i * 8, ctx->h[i]);
    }
    memcpy(out, buffer, ctx->outlen);
    
    return 0;
}

int blake2b(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen) {
    blake2b_ctx_t ctx;
    
    if (key && keylen > 0) {
        if (blake2b_init_key(&ctx, outlen, key, keylen) < 0) return -1;
    } else {
        if (blake2b_init(&ctx, outlen) < 0) return -1;
    }
    
    if (blake2b_update(&ctx, in, inlen) < 0) return -1;
    return blake2b_final(&ctx, out, outlen);
}

/* ============================================================================
 * BLAKE2s Implementation
 * ============================================================================ */

static const uint32_t blake2s_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 }
};

static inline uint32_t rotr32(uint32_t x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t load32(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}

#define B2S_G(a, b, c, d, x, y)         \
    do {                                \
        a = a + b + x;                  \
        d = rotr32(d ^ a, 16);          \
        c = c + d;                      \
        b = rotr32(b ^ c, 12);          \
        a = a + b + y;                  \
        d = rotr32(d ^ a, 8);           \
        c = c + d;                      \
        b = rotr32(b ^ c, 7);           \
    } while (0)

static void blake2s_compress(blake2s_ctx_t *ctx, const uint8_t block[64]) {
    uint32_t m[16], v[16];
    
    for (int i = 0; i < 16; i++) {
        m[i] = load32(block + i * 4);
    }
    
    for (int i = 0; i < 8; i++) {
        v[i] = ctx->h[i];
        v[i + 8] = blake2s_IV[i];
    }
    
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    v[14] ^= ctx->f[0];
    v[15] ^= ctx->f[1];
    
    for (int i = 0; i < 10; i++) {
        B2S_G(v[0], v[4], v[ 8], v[12], m[blake2s_sigma[i][ 0]], m[blake2s_sigma[i][ 1]]);
        B2S_G(v[1], v[5], v[ 9], v[13], m[blake2s_sigma[i][ 2]], m[blake2s_sigma[i][ 3]]);
        B2S_G(v[2], v[6], v[10], v[14], m[blake2s_sigma[i][ 4]], m[blake2s_sigma[i][ 5]]);
        B2S_G(v[3], v[7], v[11], v[15], m[blake2s_sigma[i][ 6]], m[blake2s_sigma[i][ 7]]);
        B2S_G(v[0], v[5], v[10], v[15], m[blake2s_sigma[i][ 8]], m[blake2s_sigma[i][ 9]]);
        B2S_G(v[1], v[6], v[11], v[12], m[blake2s_sigma[i][10]], m[blake2s_sigma[i][11]]);
        B2S_G(v[2], v[7], v[ 8], v[13], m[blake2s_sigma[i][12]], m[blake2s_sigma[i][13]]);
        B2S_G(v[3], v[4], v[ 9], v[14], m[blake2s_sigma[i][14]], m[blake2s_sigma[i][15]]);
    }
    
    for (int i = 0; i < 8; i++) {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

int blake2s_init(blake2s_ctx_t *ctx, size_t outlen) {
    if (!ctx || outlen == 0 || outlen > BLAKE2S_OUTBYTES) return -1;
    
    memset(ctx, 0, sizeof(blake2s_ctx_t));
    for (int i = 0; i < 8; i++) ctx->h[i] = blake2s_IV[i];
    ctx->h[0] ^= 0x01010000 ^ outlen;
    ctx->outlen = outlen;
    
    return 0;
}

int blake2s_init_key(blake2s_ctx_t *ctx, size_t outlen, const void *key, size_t keylen) {
    if (!ctx || outlen == 0 || outlen > BLAKE2S_OUTBYTES) return -1;
    if (keylen > BLAKE2S_KEYBYTES) return -1;
    
    memset(ctx, 0, sizeof(blake2s_ctx_t));
    for (int i = 0; i < 8; i++) ctx->h[i] = blake2s_IV[i];
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    ctx->outlen = outlen;
    
    if (keylen > 0) {
        uint8_t block[BLAKE2S_BLOCKBYTES] = {0};
        memcpy(block, key, keylen);
        blake2s_update(ctx, block, BLAKE2S_BLOCKBYTES);
        memset(block, 0, sizeof(block));
    }
    
    return 0;
}

int blake2s_update(blake2s_ctx_t *ctx, const void *in, size_t inlen) {
    if (!ctx || (!in && inlen > 0)) return -1;
    
    const uint8_t *pin = (const uint8_t *)in;
    
    while (inlen > 0) {
        size_t left = ctx->buflen;
        size_t fill = BLAKE2S_BLOCKBYTES - left;
        
        if (inlen > fill) {
            memcpy(ctx->buf + left, pin, fill);
            ctx->t[0] += BLAKE2S_BLOCKBYTES;
            if (ctx->t[0] < BLAKE2S_BLOCKBYTES) ctx->t[1]++;
            blake2s_compress(ctx, ctx->buf);
            ctx->buflen = 0;
            pin += fill;
            inlen -= fill;
        } else {
            memcpy(ctx->buf + left, pin, inlen);
            ctx->buflen += inlen;
            break;
        }
    }
    
    return 0;
}

int blake2s_final(blake2s_ctx_t *ctx, void *out, size_t outlen) {
    if (!ctx || !out || outlen < ctx->outlen) return -1;
    
    ctx->t[0] += ctx->buflen;
    if (ctx->t[0] < ctx->buflen) ctx->t[1]++;
    ctx->f[0] = (uint32_t)-1;
    
    memset(ctx->buf + ctx->buflen, 0, BLAKE2S_BLOCKBYTES - ctx->buflen);
    blake2s_compress(ctx, ctx->buf);
    
    uint8_t buffer[BLAKE2S_OUTBYTES];
    for (int i = 0; i < 8; i++) {
        store32(buffer + i * 4, ctx->h[i]);
    }
    memcpy(out, buffer, ctx->outlen);
    
    return 0;
}

int blake2s(void *out, size_t outlen, const void *in, size_t inlen,
            const void *key, size_t keylen) {
    blake2s_ctx_t ctx;
    
    if (key && keylen > 0) {
        if (blake2s_init_key(&ctx, outlen, key, keylen) < 0) return -1;
    } else {
        if (blake2s_init(&ctx, outlen) < 0) return -1;
    }
    
    if (blake2s_update(&ctx, in, inlen) < 0) return -1;
    return blake2s_final(&ctx, out, outlen);
}
