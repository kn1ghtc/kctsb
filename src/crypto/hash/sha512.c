/**
 * @file sha512.c
 * @brief SHA-384 and SHA-512 implementation (FIPS 180-4)
 * 
 * SHA-384 is a truncated version of SHA-512 with different initial values.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/sha.h"
#include <string.h>

// SHA-512 constants (first 64 bits of the fractional parts of the cube roots of the first 80 primes)
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// Rotate right (64-bit)
#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// SHA-512 logical functions
#define CH64(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_512(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define EP1_512(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define SIG0_512(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define SIG1_512(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

// Load 64-bit big-endian
static uint64_t load64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | p[7];
}

// Store 64-bit big-endian
static void store64_be(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

// Process one 1024-bit block
static void sha512_transform(kctsb_sha512_ctx_t* ctx, const uint8_t block[128]) {
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    int i;

    // Prepare message schedule
    for (i = 0; i < 16; i++) {
        W[i] = load64_be(block + i * 8);
    }
    for (i = 16; i < 80; i++) {
        W[i] = SIG1_512(W[i - 2]) + W[i - 7] + SIG0_512(W[i - 15]) + W[i - 16];
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
    for (i = 0; i < 80; i++) {
        t1 = h + EP1_512(e) + CH64(e, f, g) + K512[i] + W[i];
        t2 = EP0_512(a) + MAJ64(a, b, c);
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

// Common initialization logic
static void sha512_init_common(kctsb_sha512_ctx_t* ctx, const uint64_t iv[8]) {
    for (int i = 0; i < 8; i++) {
        ctx->state[i] = iv[i];
    }
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

void kctsb_sha512_init(kctsb_sha512_ctx_t* ctx) {
    // SHA-512 initial hash values
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    sha512_init_common(ctx, iv);
}

void kctsb_sha384_init(kctsb_sha384_ctx_t* ctx) {
    // SHA-384 initial hash values (different from SHA-512)
    static const uint64_t iv[8] = {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
        0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
        0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
    };
    sha512_init_common(ctx, iv);
}

void kctsb_sha512_update(kctsb_sha512_ctx_t* ctx, const uint8_t* data, size_t len) {
    size_t buffer_space = 128 - (size_t)(ctx->count[0] & 0x7F);
    
    // Update bit count (128-bit counter)
    uint64_t old_count = ctx->count[0];
    ctx->count[0] += len;
    if (ctx->count[0] < old_count) {
        ctx->count[1]++; // Carry
    }
    
    // If buffer has partial data and new data fills it
    if (buffer_space > len) {
        memcpy(ctx->buffer + 128 - buffer_space, data, len);
        return;
    }
    
    // Fill buffer and process
    if (buffer_space < 128) {
        memcpy(ctx->buffer + 128 - buffer_space, data, buffer_space);
        sha512_transform(ctx, ctx->buffer);
        data += buffer_space;
        len -= buffer_space;
    }
    
    // Process complete 128-byte blocks
    while (len >= 128) {
        sha512_transform(ctx, data);
        data += 128;
        len -= 128;
    }
    
    // Save remaining data
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

void kctsb_sha384_update(kctsb_sha384_ctx_t* ctx, const uint8_t* data, size_t len) {
    kctsb_sha512_update(ctx, data, len);
}

void kctsb_sha512_final(kctsb_sha512_ctx_t* ctx, uint8_t digest[64]) {
    size_t used = (size_t)(ctx->count[0] & 0x7F);
    uint64_t bit_len_low = ctx->count[0] * 8;
    uint64_t bit_len_high = (ctx->count[1] * 8) | (ctx->count[0] >> 61);
    
    // Append 0x80 byte
    ctx->buffer[used++] = 0x80;
    
    // If not enough space for length, pad and process block
    if (used > 112) {
        memset(ctx->buffer + used, 0, 128 - used);
        sha512_transform(ctx, ctx->buffer);
        used = 0;
    }
    
    // Pad with zeros
    memset(ctx->buffer + used, 0, 112 - used);
    
    // Append length in bits (big-endian 128-bit)
    store64_be(ctx->buffer + 112, bit_len_high);
    store64_be(ctx->buffer + 120, bit_len_low);
    
    sha512_transform(ctx, ctx->buffer);
    
    // Extract hash value (full 64 bytes for SHA-512)
    for (int i = 0; i < 8; i++) {
        store64_be(digest + i * 8, ctx->state[i]);
    }
    
    // Clear sensitive data
    memset(ctx, 0, sizeof(*ctx));
}

void kctsb_sha384_final(kctsb_sha384_ctx_t* ctx, uint8_t digest[48]) {
    uint8_t full_digest[64];
    kctsb_sha512_final(ctx, full_digest);
    memcpy(digest, full_digest, 48); // SHA-384 is truncated to 48 bytes
    memset(full_digest, 0, sizeof(full_digest));
}

void kctsb_sha512(const uint8_t* data, size_t len, uint8_t digest[64]) {
    kctsb_sha512_ctx_t ctx;
    kctsb_sha512_init(&ctx);
    kctsb_sha512_update(&ctx, data, len);
    kctsb_sha512_final(&ctx, digest);
}

void kctsb_sha384(const uint8_t* data, size_t len, uint8_t digest[48]) {
    kctsb_sha384_ctx_t ctx;
    kctsb_sha384_init(&ctx);
    kctsb_sha384_update(&ctx, data, len);
    kctsb_sha384_final(&ctx, digest);
}
