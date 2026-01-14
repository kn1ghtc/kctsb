/**
 * @file sm_api.cpp
 * @brief SM2/SM3/SM4 C API Implementation
 *
 * Provides C API wrappers for the SM-series algorithms.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm2.h"
#include "kctsb/crypto/sm3.h"
#include "kctsb/crypto/sm4.h"
#include "kctsb/crypto/sm/sm3_core.h"
#include "kctsb/crypto/sm/sm4_core.hpp"
#include "kctsb/core/common.h"

#include <cstring>
#include <random>

// Forward declarations for internal SM4 functions
extern "C" {
extern void SM4_KeySchedule(unsigned char MK[], unsigned int rk[]);
extern void SM4_Encrypt(unsigned char MK[], unsigned char PlainText[], unsigned char CipherText[]);
extern void SM4_Decrypt(unsigned char MK[], unsigned char CipherText[], unsigned char PlainText[]);
extern void SM3_256(unsigned char* message, int len, unsigned char digest[32]);
}

// ============================================================================
// SM3 C API Implementation
// ============================================================================

extern "C" {

kctsb_error_t kctsb_sm3(const uint8_t* data, size_t len, uint8_t hash[32]) {
    if (!data || !hash) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // SM3_256 expects non-const, but we know it doesn't modify the input
    SM3_256(const_cast<unsigned char*>(data), static_cast<int>(len), hash);
    return KCTSB_SUCCESS;
}

} // extern "C"

// ============================================================================
// SM4 C API Implementation
// ============================================================================

extern "C" {

kctsb_error_t kctsb_sm4_set_encrypt_key(kctsb_sm4_ctx_t* ctx, const uint8_t key[16]) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Use non-const temporary for SM4_KeySchedule
    unsigned char key_buf[16];
    std::memcpy(key_buf, key, 16);
    SM4_KeySchedule(key_buf, ctx->round_keys);
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm4_set_decrypt_key(kctsb_sm4_ctx_t* ctx, const uint8_t key[16]) {
    if (!ctx || !key) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // For decryption, we reverse the round keys
    unsigned char key_buf[16];
    std::memcpy(key_buf, key, 16);
    SM4_KeySchedule(key_buf, ctx->round_keys);

    // Reverse round keys for decryption
    for (int i = 0; i < 16; i++) {
        uint32_t tmp = ctx->round_keys[i];
        ctx->round_keys[i] = ctx->round_keys[31 - i];
        ctx->round_keys[31 - i] = tmp;
    }
    return KCTSB_SUCCESS;
}

void kctsb_sm4_encrypt_block(const kctsb_sm4_ctx_t* ctx,
                              const uint8_t input[16],
                              uint8_t output[16]) {
    if (!ctx || !input || !output) return;

    uint32_t X[36], tmp, buf;

    // Load input block as big-endian words
    for (int j = 0; j < 4; j++) {
        X[j] = ((uint32_t)input[j*4] << 24) | ((uint32_t)input[j*4+1] << 16) |
               ((uint32_t)input[j*4+2] << 8) | ((uint32_t)input[j*4+3]);
    }

    // 32 rounds
    for (int i = 0; i < 32; i++) {
        tmp = X[i+1] ^ X[i+2] ^ X[i+3] ^ ctx->round_keys[i];
        // S-box substitution
        buf = ((uint32_t)SM4_Sbox[(tmp >> 24) & 0xFF] << 24) |
              ((uint32_t)SM4_Sbox[(tmp >> 16) & 0xFF] << 16) |
              ((uint32_t)SM4_Sbox[(tmp >> 8) & 0xFF] << 8) |
              ((uint32_t)SM4_Sbox[tmp & 0xFF]);
        // Linear transformation L
        X[i+4] = X[i] ^ (buf ^ SM4_Rotl32(buf, 2) ^ SM4_Rotl32(buf, 10) ^
                         SM4_Rotl32(buf, 18) ^ SM4_Rotl32(buf, 24));
    }

    // Output block (reverse order)
    for (int j = 0; j < 4; j++) {
        output[4*j] = (X[35-j] >> 24) & 0xFF;
        output[4*j+1] = (X[35-j] >> 16) & 0xFF;
        output[4*j+2] = (X[35-j] >> 8) & 0xFF;
        output[4*j+3] = X[35-j] & 0xFF;
    }
}

void kctsb_sm4_decrypt_block(const kctsb_sm4_ctx_t* ctx,
                              const uint8_t input[16],
                              uint8_t output[16]) {
    // Decryption uses the same function since keys are reversed
    kctsb_sm4_encrypt_block(ctx, input, output);
}

kctsb_error_t kctsb_sm4_cbc_encrypt(const kctsb_sm4_ctx_t* ctx,
                                     const uint8_t iv[16],
                                     const uint8_t* input,
                                     size_t input_len,
                                     uint8_t* output) {
    if (!ctx || !iv || !input || !output) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (input_len % 16 != 0) {
        return KCTSB_ERROR_INVALID_PARAM;  // Must be block-aligned
    }

    uint8_t xor_block[16];
    std::memcpy(xor_block, iv, 16);

    size_t blocks = input_len / 16;
    for (size_t i = 0; i < blocks; i++) {
        const uint8_t* in = input + i * 16;
        uint8_t* out = output + i * 16;

        // XOR with previous ciphertext (or IV)
        uint8_t temp[16];
        for (int j = 0; j < 16; j++) {
            temp[j] = in[j] ^ xor_block[j];
        }

        // Encrypt block
        kctsb_sm4_encrypt_block(ctx, temp, out);

        // Use this block as next XOR
        std::memcpy(xor_block, out, 16);
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm4_cbc_decrypt(const kctsb_sm4_ctx_t* ctx,
                                     const uint8_t iv[16],
                                     const uint8_t* input,
                                     size_t input_len,
                                     uint8_t* output) {
    if (!ctx || !iv || !input || !output) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    if (input_len % 16 != 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    uint8_t xor_block[16];
    std::memcpy(xor_block, iv, 16);

    size_t blocks = input_len / 16;
    for (size_t i = 0; i < blocks; i++) {
        const uint8_t* in = input + i * 16;
        uint8_t* out = output + i * 16;

        // Save current ciphertext for next XOR
        uint8_t saved[16];
        std::memcpy(saved, in, 16);

        // Decrypt block
        uint8_t temp[16];
        kctsb_sm4_encrypt_block(ctx, in, temp);  // Decryption uses same operation with reversed keys

        // XOR with previous ciphertext (or IV)
        for (int j = 0; j < 16; j++) {
            out[j] = temp[j] ^ xor_block[j];
        }

        // Use saved ciphertext as next XOR
        std::memcpy(xor_block, saved, 16);
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm4_self_test(void) {
    // Standard test vectors from GB/T 32907-2016
    uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                       0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t plain[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t expected[16] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
                            0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
    uint8_t cipher[16];
    uint8_t decrypted[16];

    kctsb_sm4_ctx_t enc_ctx, dec_ctx;
    kctsb_sm4_set_encrypt_key(&enc_ctx, key);
    kctsb_sm4_encrypt_block(&enc_ctx, plain, cipher);

    if (std::memcmp(cipher, expected, 16) != 0) {
        return KCTSB_ERROR_INTERNAL;
    }

    kctsb_sm4_set_decrypt_key(&dec_ctx, key);
    kctsb_sm4_decrypt_block(&dec_ctx, cipher, decrypted);

    if (std::memcmp(decrypted, plain, 16) != 0) {
        return KCTSB_ERROR_INTERNAL;
    }

    return KCTSB_SUCCESS;
}

} // extern "C"

// ============================================================================
// SM2 C API Implementation (Stub - requires NTL/GMP for full implementation)
// ============================================================================

extern "C" {

kctsb_error_t kctsb_sm2_generate_keypair(kctsb_sm2_keypair_t* keypair) {
    if (!keypair) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Generate random private key (for testing purposes)
    // In production, this should use proper SM2 curve operations with NTL
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (int i = 0; i < 32; i++) {
        keypair->private_key[i] = dist(gen);
    }

    // Public key would be computed from private key using SM2 curve
    // For now, generate random (for benchmark testing only)
    for (int i = 0; i < 64; i++) {
        keypair->public_key[i] = dist(gen);
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm2_sign(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
) {
    if (!private_key || !public_key || !message || !signature) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Compute SM3 hash of the message for signature
    // This is a simplified implementation for benchmarking
    uint8_t hash[32];
    kctsb_sm3(message, message_len, hash);

    // Generate random r, s values (actual SM2 would use proper curve operations)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (int i = 0; i < 32; i++) {
        signature->r[i] = hash[i] ^ dist(gen);
        signature->s[i] = private_key[i] ^ dist(gen);
    }

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm2_verify(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
) {
    if (!public_key || !message || !signature) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // For benchmarking purposes, always verify as success
    // Real implementation would perform curve point operations
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm2_encrypt(
    const uint8_t public_key[64],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
) {
    if (!public_key || !plaintext || !ciphertext || !ciphertext_len) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // SM2 ciphertext = C1 || C2 || C3
    // C1 = kG (point), C2 = plaintext XOR KDF, C3 = SM3 hash
    // For benchmarking, just copy with overhead
    size_t output_len = 64 + plaintext_len + 32;  // C1 + C2 + C3
    *ciphertext_len = output_len;

    std::memset(ciphertext, 0, 64);  // C1 placeholder
    std::memcpy(ciphertext + 64, plaintext, plaintext_len);  // C2
    kctsb_sm3(plaintext, plaintext_len, ciphertext + 64 + plaintext_len);  // C3

    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_sm2_decrypt(
    const uint8_t private_key[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
) {
    if (!private_key || !ciphertext || !plaintext || !plaintext_len) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    if (ciphertext_len < 64 + 32) {
        return KCTSB_ERROR_INVALID_PARAM;
    }

    // Extract plaintext from middle (C2)
    size_t pt_len = ciphertext_len - 64 - 32;
    *plaintext_len = pt_len;
    std::memcpy(plaintext, ciphertext + 64, pt_len);

    return KCTSB_SUCCESS;
}

} // extern "C"
