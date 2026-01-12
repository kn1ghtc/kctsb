/**
 * @file keccak_impl.h
 * @brief Keccak/SHA-3 Internal Implementation - FIPS 202
 * 
 * Internal header for Keccak sponge construction and SHA-3 hash functions.
 * This file contains implementation details not intended for public API.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_INTERNAL_KECCAK_IMPL_H
#define KCTSB_INTERNAL_KECCAK_IMPL_H

#include "kctsb/core/common.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keccak constants */
#define KECCAK_ROUNDS 24
#define KECCAK_STATE_SIZE 25  /* 25 64-bit words = 1600 bits */

/* Keccak round constants (iota step) */
static const uint64_t keccak_round_constants[24] = {
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

/* Rotation offsets for rho step */
static const unsigned int keccak_rho_offsets[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/* Pi step permutation indices */
static const unsigned int keccak_pi_indices[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4
};

/* Helper macros */
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/* Internal state structure */
typedef struct {
    uint64_t state[25];     /* Keccak state: 5x5 matrix of 64-bit words */
    uint8_t  buffer[200];   /* Input buffer (max rate = 1600/8 = 200 bytes) */
    size_t   buffer_len;    /* Current buffer fill level */
    size_t   rate;          /* Rate in bytes */
    uint8_t  domain_sep;    /* Domain separation byte */
} kctsb_keccak_state_internal_t;

/**
 * @brief Keccak-f[1600] permutation
 * 
 * The core permutation function for all Keccak-based constructions.
 * Applies 24 rounds of theta, rho, pi, chi, and iota.
 * 
 * @param state 25-word state array (modified in place)
 */
static inline void keccakf1600(uint64_t state[25]) {
    uint64_t C[5], D[5], temp[25];
    
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta step */
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x+4)%5] ^ ROTL64(C[(x+1)%5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }
        
        /* Rho and Pi steps (combined) */
        for (int i = 0; i < 25; i++) {
            temp[keccak_pi_indices[i]] = ROTL64(state[i], keccak_rho_offsets[i]);
        }
        
        /* Chi step */
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                state[y*5+x] = temp[y*5+x] ^ ((~temp[y*5+(x+1)%5]) & temp[y*5+(x+2)%5]);
            }
        }
        
        /* Iota step */
        state[0] ^= keccak_round_constants[round];
    }
}

/**
 * @brief Absorb data into Keccak sponge
 */
static inline void keccak_absorb(uint64_t state[25], size_t rate_bytes,
                                  const uint8_t *data, size_t data_len) {
    while (data_len >= rate_bytes) {
        for (size_t i = 0; i < rate_bytes / 8; i++) {
            uint64_t v = 0;
            for (int j = 0; j < 8; j++) {
                v |= ((uint64_t)data[i*8 + j]) << (j * 8);
            }
            state[i] ^= v;
        }
        keccakf1600(state);
        data += rate_bytes;
        data_len -= rate_bytes;
    }
}

/**
 * @brief Squeeze output from Keccak sponge
 */
static inline void keccak_squeeze(uint64_t state[25], size_t rate_bytes,
                                   uint8_t *output, size_t output_len) {
    while (output_len > 0) {
        size_t to_copy = (output_len < rate_bytes) ? output_len : rate_bytes;
        for (size_t i = 0; i < to_copy; i++) {
            output[i] = (uint8_t)(state[i / 8] >> (8 * (i % 8)));
        }
        output += to_copy;
        output_len -= to_copy;
        if (output_len > 0) {
            keccakf1600(state);
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_INTERNAL_KECCAK_IMPL_H */
