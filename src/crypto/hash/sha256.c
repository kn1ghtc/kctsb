/**
 * @file sha256.c
 * @brief SHA-256 implementation (FIPS 180-4)
 * 
 * Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/sha.h"
#include <string.h>

// SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
static const uint32_t K256[64] = {
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

// Rotate right
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 logical functions
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define EP1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

// Load 32-bit big-endian
static uint32_t load32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

// Store 32-bit big-endian
static void store32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

// Process one 512-bit block
static void sha256_transform(kctsb_sha256_ctx_t* ctx, const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    // Prepare message schedule
    for (i = 0; i < 16; i++) {
        W[i] = load32_be(block + i * 4);
    }
    for (i = 16; i < 64; i++) {
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
    for (i = 0; i < 64; i++) {
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

void kctsb_sha256_init(kctsb_sha256_ctx_t* ctx) {
    // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void kctsb_sha256_update(kctsb_sha256_ctx_t* ctx, const uint8_t* data, size_t len) {
    size_t buffer_space = 64 - (ctx->count & 0x3F);
    
    ctx->count += len;
    
    // If buffer has partial data and new data fills it
    if (buffer_space > len) {
        memcpy(ctx->buffer + 64 - buffer_space, data, len);
        return;
    }
    
    // Fill buffer and process
    if (buffer_space < 64) {
        memcpy(ctx->buffer + 64 - buffer_space, data, buffer_space);
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
        memcpy(ctx->buffer, data, len);
    }
}

void kctsb_sha256_final(kctsb_sha256_ctx_t* ctx, uint8_t digest[32]) {
    size_t used = ctx->count & 0x3F;
    uint64_t bit_len = ctx->count * 8;
    
    // Append 0x80 byte
    ctx->buffer[used++] = 0x80;
    
    // If not enough space for length, pad and process block
    if (used > 56) {
        memset(ctx->buffer + used, 0, 64 - used);
        sha256_transform(ctx, ctx->buffer);
        used = 0;
    }
    
    // Pad with zeros
    memset(ctx->buffer + used, 0, 56 - used);
    
    // Append length in bits (big-endian 64-bit)
    store32_be(ctx->buffer + 56, (uint32_t)(bit_len >> 32));
    store32_be(ctx->buffer + 60, (uint32_t)bit_len);
    
    sha256_transform(ctx, ctx->buffer);
    
    // Extract hash value
    for (int i = 0; i < 8; i++) {
        store32_be(digest + i * 4, ctx->state[i]);
    }
    
    // Clear sensitive data
    memset(ctx, 0, sizeof(*ctx));
}

void kctsb_sha256(const uint8_t* data, size_t len, uint8_t digest[32]) {
    kctsb_sha256_ctx_t ctx;
    kctsb_sha256_init(&ctx);
    kctsb_sha256_update(&ctx, data, len);
    kctsb_sha256_final(&ctx, digest);
}
