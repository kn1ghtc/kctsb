/**
 * @file whitebox_aes.c
 * @brief White-box AES implementation
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * 
 * Implements Chow et al.'s white-box AES construction.
 * Reference: "White-Box Cryptography and an AES Implementation" (SAC 2002)
 * 
 * This is an educational implementation demonstrating white-box concepts.
 */

#include "kctsb/advanced/whitebox/whitebox_aes.h"
#include <string.h>
#include <stdlib.h>

/* AES S-box */
static const u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Round constants */
static const u8 rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* GF(2^8) multiplication */
static u8 gf_mul(u8 a, u8 b) {
    u8 p = 0;
    u8 hi_bit;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
        b >>= 1;
    }
    return p;
}

/* Key expansion */
static void key_expansion(const u8 key[16], u8 round_keys[11][16]) {
    memcpy(round_keys[0], key, 16);
    
    for (int i = 1; i <= 10; i++) {
        /* RotWord + SubWord + Rcon */
        round_keys[i][0] = round_keys[i-1][0] ^ sbox[round_keys[i-1][13]] ^ rcon[i];
        round_keys[i][1] = round_keys[i-1][1] ^ sbox[round_keys[i-1][14]];
        round_keys[i][2] = round_keys[i-1][2] ^ sbox[round_keys[i-1][15]];
        round_keys[i][3] = round_keys[i-1][3] ^ sbox[round_keys[i-1][12]];
        
        for (int j = 4; j < 16; j++) {
            round_keys[i][j] = round_keys[i-1][j] ^ round_keys[i][j-4];
        }
    }
}

/* Generate T-Box tables */
static void generate_tbox(wbox_aes_ctx_t *ctx, u8 round_keys[11][16]) {
    /* T-Box: T_i(x) = S-box(x XOR k_i) */
    for (int round = 0; round < 10; round++) {
        for (int byte_idx = 0; byte_idx < 16; byte_idx++) {
            for (int x = 0; x < 256; x++) {
                ctx->TBoxes[round][byte_idx][x] = sbox[(u8)(x ^ round_keys[round][byte_idx])];
            }
        }
    }
}

/* Generate Tyi tables (MixColumns incorporated) */
static void generate_tyi_tables(wbox_aes_ctx_t *ctx) {
    /* Tyi tables encode MixColumns operation */
    for (int x = 0; x < 256; x++) {
        u8 x_u8 = (u8)x;  /* Convert loop counter to u8 once */
        ctx->TyiTables[0][x] = ((u32)gf_mul(2, x_u8) << 24) | ((u32)x_u8 << 16) | 
                               ((u32)x_u8 << 8) | (u32)gf_mul(3, x_u8);
        ctx->TyiTables[1][x] = ((u32)gf_mul(3, x_u8) << 24) | ((u32)gf_mul(2, x_u8) << 16) | 
                               ((u32)x_u8 << 8) | (u32)x_u8;
        ctx->TyiTables[2][x] = ((u32)x_u8 << 24) | ((u32)gf_mul(3, x_u8) << 16) | 
                               ((u32)gf_mul(2, x_u8) << 8) | (u32)x_u8;
        ctx->TyiTables[3][x] = ((u32)x_u8 << 24) | ((u32)x_u8 << 16) | 
                               ((u32)gf_mul(3, x_u8) << 8) | (u32)gf_mul(2, x_u8);
    }
}

/* Generate TyiBox tables (T-Box + MixColumns) */
static void generate_tyibox(wbox_aes_ctx_t *ctx, u8 round_keys[11][16]) {
    /* TyiBox combines T-Box with Tyi for rounds 1-9 */
    for (int round = 0; round < 9; round++) {
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                int byte_idx = col * 4 + row;
                for (int x = 0; x < 256; x++) {
                    u8 tbox_out = ctx->TBoxes[round][byte_idx][x];
                    ctx->TyiBoxes[round][byte_idx][x] = ctx->TyiTables[row][tbox_out];
                }
            }
        }
    }
}

/* Generate simple XOR tables (for demonstration) */
static void generate_xor_tables(wbox_aes_ctx_t *ctx) {
    /* XOR tables: xorTable[a][b] = a XOR b */
    for (int round = 0; round < 9; round++) {
        for (int tbl = 0; tbl < 96; tbl++) {
            for (int a = 0; a < 16; a++) {
                for (int b = 0; b < 16; b++) {
                    ctx->xorTable[round][tbl][a][b] = (u8)(a ^ b);
                }
            }
        }
    }
}

/* Public API implementation */

void wbox_generate_tables(wbox_aes_ctx_t *ctx, const u8 key[16]) {
    u8 round_keys[11][16];
    
    key_expansion(key, round_keys);
    generate_tbox(ctx, round_keys);
    generate_tyi_tables(ctx);
    generate_tyibox(ctx, round_keys);
    generate_xor_tables(ctx);
    
    /* Store final round key in last TBox */
    for (int i = 0; i < 16; i++) {
        for (int x = 0; x < 256; x++) {
            ctx->TBoxes[9][i][x] = sbox[x ^ round_keys[9][i]] ^ round_keys[10][i];
        }
    }
}

int wbox_aes_init(wbox_aes_ctx_t *ctx, const u8 key[16]) {
    if (!ctx || !key) return -1;
    
    memset(ctx, 0, sizeof(wbox_aes_ctx_t));
    wbox_generate_tables(ctx, key);
    ctx->initialized = 1;
    
    return 0;
}

/* ShiftRows operation */
static void shift_rows(u8 state[16]) {
    u8 temp;
    
    /* Row 1: shift left by 1 */
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    /* Row 2: shift left by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    /* Row 3: shift left by 3 */
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

int wbox_aes_encrypt(const wbox_aes_ctx_t *ctx, const u8 input[16], u8 output[16]) {
    if (!ctx || !ctx->initialized || !input || !output) return -1;
    
    u8 state[16];
    u32 temp[4];
    
    memcpy(state, input, 16);
    
    /* Rounds 1-9: SubBytes (via TyiBox) + ShiftRows + MixColumns */
    for (int round = 0; round < 9; round++) {
        shift_rows(state);
        
        for (int col = 0; col < 4; col++) {
            temp[col] = ctx->TyiBoxes[round][col * 4 + 0][state[col * 4 + 0]] ^
                        ctx->TyiBoxes[round][col * 4 + 1][state[col * 4 + 1]] ^
                        ctx->TyiBoxes[round][col * 4 + 2][state[col * 4 + 2]] ^
                        ctx->TyiBoxes[round][col * 4 + 3][state[col * 4 + 3]];
            
            state[col * 4 + 0] = (u8)((temp[col] >> 24) & 0xFF);
            state[col * 4 + 1] = (u8)((temp[col] >> 16) & 0xFF);
            state[col * 4 + 2] = (u8)((temp[col] >> 8) & 0xFF);
            state[col * 4 + 3] = (u8)(temp[col] & 0xFF);
        }
    }
    
    /* Final round: SubBytes (via TBox) + ShiftRows (no MixColumns) */
    shift_rows(state);
    for (int i = 0; i < 16; i++) {
        state[i] = ctx->TBoxes[9][i][state[i]];
    }
    
    memcpy(output, state, 16);
    return 0;
}

void wbox_aes_cleanup(wbox_aes_ctx_t *ctx) {
    if (ctx) {
        /* Secure cleanup */
        volatile unsigned char *p = (volatile unsigned char *)ctx;
        for (size_t i = 0; i < sizeof(wbox_aes_ctx_t); i++) {
            p[i] = 0;
        }
    }
}
