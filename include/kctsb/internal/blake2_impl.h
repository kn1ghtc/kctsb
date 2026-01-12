/**
 * @file blake2_impl.h
 * @brief BLAKE2 Internal Implementation - RFC 7693
 * 
 * Internal header for BLAKE2b and BLAKE2s hash functions.
 * This file contains implementation details not intended for public API.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_INTERNAL_BLAKE2_IMPL_H
#define KCTSB_INTERNAL_BLAKE2_IMPL_H

#include "kctsb/core/common.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BLAKE2b constants */
#define BLAKE2B_BLOCKBYTES    128
#define BLAKE2B_OUTBYTES      64
#define BLAKE2B_KEYBYTES      64
#define BLAKE2B_SALTBYTES     16
#define BLAKE2B_PERSONALBYTES 16

/* BLAKE2s constants */
#define BLAKE2S_BLOCKBYTES    64
#define BLAKE2S_OUTBYTES      32
#define BLAKE2S_KEYBYTES      32
#define BLAKE2S_SALTBYTES     8
#define BLAKE2S_PERSONALBYTES 8

/* Internal state structures */
typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
} kctsb_blake2b_state_internal_t;

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
} kctsb_blake2s_state_internal_t;

/* BLAKE2b initialization vectors (IV) */
static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* BLAKE2s initialization vectors (IV) */
static const uint32_t blake2s_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

/* BLAKE2b sigma (message schedule permutation) */
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
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

/* Rotation constants for BLAKE2b */
#define BLAKE2B_R1 32
#define BLAKE2B_R2 24
#define BLAKE2B_R3 16
#define BLAKE2B_R4 63

/* Rotation constants for BLAKE2s */
#define BLAKE2S_R1 16
#define BLAKE2S_R2 12
#define BLAKE2S_R3 8
#define BLAKE2S_R4 7

/* Helper macros */
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline uint64_t load64_le(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | 
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline uint32_t load32_le(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | 
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store32_le(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
}

static inline void store64_le(void *dst, uint64_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)w; p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16); p[3] = (uint8_t)(w >> 24);
    p[4] = (uint8_t)(w >> 32); p[5] = (uint8_t)(w >> 40);
    p[6] = (uint8_t)(w >> 48); p[7] = (uint8_t)(w >> 56);
}

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_INTERNAL_BLAKE2_IMPL_H */
