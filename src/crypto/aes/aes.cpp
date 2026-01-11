/**
 * @file aes.cpp
 * @brief AES implementation
 * 
 * Based on the Rijndael reference implementation with optimizations.
 * Supports AES-128, AES-192, and AES-256.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/aes.h"
#include <cstring>

// AES S-Box
static const uint8_t SBOX[256] = {
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

// Inverse S-Box
static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants
static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// GF(2^8) multiplication
static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t hi_bit;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) {
            a ^= 0x1b;  // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return result;
}

// Key expansion
static void key_expansion(const uint8_t* key, uint32_t* round_keys, int key_len, int rounds) {
    int nk = key_len / 4;
    int nb = 4;
    int nr = rounds;
    
    // Copy original key
    for (int i = 0; i < nk; i++) {
        round_keys[i] = ((uint32_t)key[4*i] << 24) |
                        ((uint32_t)key[4*i+1] << 16) |
                        ((uint32_t)key[4*i+2] << 8) |
                        ((uint32_t)key[4*i+3]);
    }
    
    // Generate remaining round keys
    for (int i = nk; i < nb * (nr + 1); i++) {
        uint32_t temp = round_keys[i - 1];
        
        if (i % nk == 0) {
            // RotWord
            temp = (temp << 8) | (temp >> 24);
            // SubWord
            temp = ((uint32_t)SBOX[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)SBOX[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)SBOX[(temp >> 8) & 0xff] << 8) |
                   ((uint32_t)SBOX[temp & 0xff]);
            // XOR with Rcon
            temp ^= ((uint32_t)RCON[i / nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            // SubWord for AES-256
            temp = ((uint32_t)SBOX[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)SBOX[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)SBOX[(temp >> 8) & 0xff] << 8) |
                   ((uint32_t)SBOX[temp & 0xff]);
        }
        
        round_keys[i] = round_keys[i - nk] ^ temp;
    }
}

// SubBytes
static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = SBOX[state[i]];
    }
}

// InvSubBytes
static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = INV_SBOX[state[i]];
    }
}

// ShiftRows
static void shift_rows(uint8_t state[16]) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// InvShiftRows
static void inv_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    
    // Row 1: shift right by 1
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    
    // Row 2: shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift right by 3
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// MixColumns
static void mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c];
        uint8_t a1 = state[c + 1];
        uint8_t a2 = state[c + 2];
        uint8_t a3 = state[c + 3];
        
        state[c]     = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[c + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[c + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[c + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

// InvMixColumns
static void inv_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        int c = i * 4;
        uint8_t a0 = state[c];
        uint8_t a1 = state[c + 1];
        uint8_t a2 = state[c + 2];
        uint8_t a3 = state[c + 3];
        
        state[c]     = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        state[c + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        state[c + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        state[c + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

// AddRoundKey
static void add_round_key(uint8_t state[16], const uint32_t* round_key) {
    for (int i = 0; i < 4; i++) {
        state[i * 4]     ^= (round_key[i] >> 24) & 0xff;
        state[i * 4 + 1] ^= (round_key[i] >> 16) & 0xff;
        state[i * 4 + 2] ^= (round_key[i] >> 8) & 0xff;
        state[i * 4 + 3] ^= round_key[i] & 0xff;
    }
}

// Public API implementations

extern "C" {

kctsb_error_t kctsb_aes_init(kctsb_aes_ctx_t* ctx, const uint8_t* key, size_t key_len) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    switch (key_len) {
        case 16:  // AES-128
            ctx->key_bits = 128;
            ctx->rounds = 10;
            break;
        case 24:  // AES-192
            ctx->key_bits = 192;
            ctx->rounds = 12;
            break;
        case 32:  // AES-256
            ctx->key_bits = 256;
            ctx->rounds = 14;
            break;
        default:
            return KCTSB_ERROR_INVALID_KEY;
    }
    
    key_expansion(key, ctx->round_keys, (int)key_len, ctx->rounds);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_encrypt_block(const kctsb_aes_ctx_t* ctx, const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    uint8_t state[16];
    memcpy(state, input, 16);
    
    add_round_key(state, &ctx->round_keys[0]);
    
    for (int round = 1; round < ctx->rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[round * 4]);
    }
    
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[ctx->rounds * 4]);
    
    memcpy(output, state, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_decrypt_block(const kctsb_aes_ctx_t* ctx, const uint8_t input[16], uint8_t output[16]) {
    if (!ctx || !input || !output) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    uint8_t state[16];
    memcpy(state, input, 16);
    
    add_round_key(state, &ctx->round_keys[ctx->rounds * 4]);
    
    for (int round = ctx->rounds - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ctx->round_keys[round * 4]);
        inv_mix_columns(state);
    }
    
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &ctx->round_keys[0]);
    
    memcpy(output, state, 16);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_cbc_encrypt(const kctsb_aes_ctx_t* ctx, const uint8_t iv[16],
                                    const uint8_t* input, size_t input_len,
                                    uint8_t* output, size_t* output_len) {
    if (!ctx || !iv || !input || !output || !output_len) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    if (input_len % 16 != 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    if (*output_len < input_len) {
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);
    
    for (size_t i = 0; i < input_len; i += 16) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) {
            block[j] = input[i + j] ^ prev_block[j];
        }
        
        kctsb_aes_encrypt_block(ctx, block, &output[i]);
        memcpy(prev_block, &output[i], 16);
    }
    
    *output_len = input_len;
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_cbc_decrypt(const kctsb_aes_ctx_t* ctx, const uint8_t iv[16],
                                    const uint8_t* input, size_t input_len,
                                    uint8_t* output, size_t* output_len) {
    if (!ctx || !iv || !input || !output || !output_len) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    if (input_len % 16 != 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    if (*output_len < input_len) {
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);
    
    for (size_t i = 0; i < input_len; i += 16) {
        uint8_t decrypted[16];
        kctsb_aes_decrypt_block(ctx, &input[i], decrypted);
        
        for (int j = 0; j < 16; j++) {
            output[i + j] = decrypted[j] ^ prev_block[j];
        }
        
        memcpy(prev_block, &input[i], 16);
    }
    
    *output_len = input_len;
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_aes_ctr_crypt(const kctsb_aes_ctx_t* ctx, const uint8_t nonce[12],
                                  const uint8_t* input, size_t input_len, uint8_t* output) {
    if (!ctx || !nonce || !input || !output) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    uint8_t counter_block[16];
    memcpy(counter_block, nonce, 12);
    counter_block[12] = 0;
    counter_block[13] = 0;
    counter_block[14] = 0;
    counter_block[15] = 1;
    
    uint8_t keystream[16];
    
    for (size_t i = 0; i < input_len; i += 16) {
        kctsb_aes_encrypt_block(ctx, counter_block, keystream);
        
        size_t bytes_to_process = (input_len - i < 16) ? (input_len - i) : 16;
        for (size_t j = 0; j < bytes_to_process; j++) {
            output[i + j] = input[i + j] ^ keystream[j];
        }
        
        // Increment counter
        for (int j = 15; j >= 12; j--) {
            if (++counter_block[j] != 0) break;
        }
    }
    
    return KCTSB_SUCCESS;
}

void kctsb_aes_clear(kctsb_aes_ctx_t* ctx) {
    if (ctx) {
        kctsb_secure_zero(ctx, sizeof(kctsb_aes_ctx_t));
    }
}

} // extern "C"

// C++ class implementation
namespace kctsb {

AES::AES(const ByteVec& key) {
    kctsb_error_t err = kctsb_aes_init(&ctx_, key.data(), key.size());
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("Failed to initialize AES");
    }
}

AES::AES(const uint8_t* key, size_t key_len) {
    kctsb_error_t err = kctsb_aes_init(&ctx_, key, key_len);
    if (err != KCTSB_SUCCESS) {
        throw std::runtime_error("Failed to initialize AES");
    }
}

AES::~AES() {
    kctsb_aes_clear(&ctx_);
}

AES::AES(AES&& other) noexcept {
    memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
    memset(&other.ctx_, 0, sizeof(other.ctx_));
}

AES& AES::operator=(AES&& other) noexcept {
    if (this != &other) {
        kctsb_aes_clear(&ctx_);
        memcpy(&ctx_, &other.ctx_, sizeof(ctx_));
        memset(&other.ctx_, 0, sizeof(other.ctx_));
    }
    return *this;
}

AESBlock AES::encryptBlock(const AESBlock& input) const {
    AESBlock output;
    kctsb_aes_encrypt_block(&ctx_, input.data(), output.data());
    return output;
}

AESBlock AES::decryptBlock(const AESBlock& input) const {
    AESBlock output;
    kctsb_aes_decrypt_block(&ctx_, input.data(), output.data());
    return output;
}

ByteVec AES::cbcEncrypt(const ByteVec& plaintext, const AESBlock& iv) const {
    // Add PKCS7 padding
    size_t padded_len = ((plaintext.size() / 16) + 1) * 16;
    ByteVec padded(padded_len);
    memcpy(padded.data(), plaintext.data(), plaintext.size());
    uint8_t pad_value = (uint8_t)(padded_len - plaintext.size());
    for (size_t i = plaintext.size(); i < padded_len; i++) {
        padded[i] = pad_value;
    }
    
    ByteVec ciphertext(padded_len);
    size_t out_len = padded_len;
    kctsb_aes_cbc_encrypt(&ctx_, iv.data(), padded.data(), padded_len, ciphertext.data(), &out_len);
    return ciphertext;
}

ByteVec AES::cbcDecrypt(const ByteVec& ciphertext, const AESBlock& iv) const {
    ByteVec plaintext(ciphertext.size());
    size_t out_len = ciphertext.size();
    kctsb_aes_cbc_decrypt(&ctx_, iv.data(), ciphertext.data(), ciphertext.size(), plaintext.data(), &out_len);
    
    // Remove PKCS7 padding
    if (out_len > 0) {
        uint8_t pad_value = plaintext[out_len - 1];
        if (pad_value > 0 && pad_value <= 16) {
            plaintext.resize(out_len - pad_value);
        }
    }
    return plaintext;
}

ByteVec AES::ctrCrypt(const ByteVec& data, const std::array<uint8_t, 12>& nonce) const {
    ByteVec output(data.size());
    kctsb_aes_ctr_crypt(&ctx_, nonce.data(), data.data(), data.size(), output.data());
    return output;
}

} // namespace kctsb
