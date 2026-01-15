/**
 * @file test_sm.cpp
 * @brief Unit tests for SM3 and SM4 implementations
 *
 * Tests against official GM/T test vectors:
 * - SM3: GB/T 32905-2016
 * - SM4: GB/T 32907-2016
 *
 * @version 3.4.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

#include "kctsb/kctsb.h"
#include "kctsb/crypto/sm3.h"
#include "kctsb/crypto/sm4.h"

/**
 * @brief Convert byte array to hex string
 */
static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string hex;
    char buf[3];
    for (size_t i = 0; i < len; ++i) {
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
    }
    return hex;
}

class SMTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

// ============================================================================
// SM3 Hash Tests (GB/T 32905-2016)
// ============================================================================

/**
 * @brief Test SM3 with standard test vector 1
 *
 * GM/T 0004-2012 Example 1:
 * Message: "abc" (0x616263)
 * Hash: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
 */
TEST_F(SMTest, SM3_TestVector1) {
    kctsb_sm3_ctx_t ctx;
    uint8_t output[32];
    const uint8_t message[] = "abc";

    kctsb_sm3_init(&ctx);
    kctsb_sm3_update(&ctx, message, 3);
    kctsb_sm3_final(&ctx, output);

    // Expected hash from GM/T 0004-2012
    const char* expected_hex =
        "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SM3 with standard test vector 2
 *
 * GM/T 0004-2012 Example 2:
 * Message: "abcd" repeated 16 times (64 bytes)
 * Hash: debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
 */
TEST_F(SMTest, SM3_TestVector2) {
    kctsb_sm3_ctx_t ctx;
    uint8_t output[32];

    // 64 bytes: "abcd" * 16
    const char* message = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

    kctsb_sm3_init(&ctx);
    kctsb_sm3_update(&ctx, reinterpret_cast<const uint8_t*>(message), 64);
    kctsb_sm3_final(&ctx, output);

    // Expected hash from GM/T 0004-2012
    const char* expected_hex =
        "debe9ff92275b8a138604889c18e5a4d"
        "6fdb70e5387e5765293dcba39c0c5732";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SM3 empty message
 */
TEST_F(SMTest, SM3_Empty) {
    kctsb_sm3_ctx_t ctx;
    uint8_t output[32];

    kctsb_sm3_init(&ctx);
    kctsb_sm3_final(&ctx, output);

    // SM3("") - verify non-zero output
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (output[i] != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero) << "SM3 of empty message should not be all zeros";
}

/**
 * @brief Test SM3 incremental processing
 */
TEST_F(SMTest, SM3_Incremental) {
    kctsb_sm3_ctx_t ctx1, ctx2;
    uint8_t output1[32], output2[32];
    const char* message = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(message);

    // Hash all at once
    kctsb_sm3_init(&ctx1);
    kctsb_sm3_update(&ctx1, reinterpret_cast<const uint8_t*>(message), len);
    kctsb_sm3_final(&ctx1, output1);

    // Hash in chunks
    kctsb_sm3_init(&ctx2);
    kctsb_sm3_update(&ctx2, reinterpret_cast<const uint8_t*>(message), 20);
    kctsb_sm3_update(&ctx2, reinterpret_cast<const uint8_t*>(message + 20), len - 20);
    kctsb_sm3_final(&ctx2, output2);

    EXPECT_EQ(memcmp(output1, output2, 32), 0)
        << "Incremental hashing should produce same result";
}

/**
 * @brief Test SM3 one-shot API
 */
TEST_F(SMTest, SM3_OneShot) {
    const uint8_t message[] = "abc";
    uint8_t output[32];

    kctsb_error_t result = kctsb_sm3(message, 3, output);
    EXPECT_EQ(result, KCTSB_SUCCESS);

    // Expected hash from GM/T 0004-2012
    const char* expected_hex =
        "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SM3 self test
 */
TEST_F(SMTest, SM3_SelfTest) {
    EXPECT_EQ(kctsb_sm3_self_test(), KCTSB_SUCCESS);
}

// ============================================================================
// SM4 Block Cipher Tests (GB/T 32907-2016)
// ============================================================================

/**
 * @brief Test SM4 encryption with standard test vector
 *
 * GM/T 0002-2012 Example:
 * Key: 0123456789ABCDEFFEDCBA9876543210
 * Plain: 0123456789ABCDEFFEDCBA9876543210
 * Cipher: 681EDF34D206965E86B3E94F536E4246
 */
TEST_F(SMTest, SM4_Encrypt_TestVector) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t ciphertext[16];

    kctsb_sm4_ctx_t ctx;
    EXPECT_EQ(kctsb_sm4_set_encrypt_key(&ctx, key), KCTSB_SUCCESS);
    kctsb_sm4_encrypt_block(&ctx, plaintext, ciphertext);

    // Expected ciphertext from GM/T 0002-2012
    const char* expected_hex = "681edf34d206965e86b3e94f536e4246";
    std::string result_hex = bytes_to_hex(ciphertext, 16);

    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SM4 decryption with standard test vector
 */
TEST_F(SMTest, SM4_Decrypt_TestVector) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t ciphertext[16] = {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };
    uint8_t plaintext[16];

    kctsb_sm4_ctx_t ctx;
    EXPECT_EQ(kctsb_sm4_set_decrypt_key(&ctx, key), KCTSB_SUCCESS);
    kctsb_sm4_decrypt_block(&ctx, ciphertext, plaintext);

    // Expected plaintext
    const char* expected_hex = "0123456789abcdeffedcba9876543210";
    std::string result_hex = bytes_to_hex(plaintext, 16);

    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SM4 encryption/decryption round trip
 */
TEST_F(SMTest, SM4_RoundTrip) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // Test with random-looking data
    for (int t = 0; t < 10; ++t) {
        uint8_t original[16], encrypted[16], decrypted[16];

        // Generate "random" data using simple pattern
        for (int i = 0; i < 16; ++i) {
            original[i] = static_cast<uint8_t>((t * 17 + i * 31) & 0xFF);
        }

        kctsb_sm4_ctx_t enc_ctx, dec_ctx;
        EXPECT_EQ(kctsb_sm4_set_encrypt_key(&enc_ctx, key), KCTSB_SUCCESS);
        EXPECT_EQ(kctsb_sm4_set_decrypt_key(&dec_ctx, key), KCTSB_SUCCESS);

        kctsb_sm4_encrypt_block(&enc_ctx, original, encrypted);
        kctsb_sm4_decrypt_block(&dec_ctx, encrypted, decrypted);

        EXPECT_EQ(memcmp(original, decrypted, 16), 0)
            << "Round trip failed for iteration " << t;
    }
}

/**
 * @brief Test SM4 different inputs produce different outputs
 */
TEST_F(SMTest, SM4_DifferentInputs) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t plain1[16] = {0};
    uint8_t plain2[16] = {0};
    plain2[0] = 1;  // Only differ by 1 bit

    uint8_t cipher1[16], cipher2[16];

    kctsb_sm4_ctx_t ctx;
    EXPECT_EQ(kctsb_sm4_set_encrypt_key(&ctx, key), KCTSB_SUCCESS);

    kctsb_sm4_encrypt_block(&ctx, plain1, cipher1);
    kctsb_sm4_encrypt_block(&ctx, plain2, cipher2);

    // Ciphertexts should be different
    EXPECT_NE(memcmp(cipher1, cipher2, 16), 0)
        << "Different plaintexts should produce different ciphertexts";
}

// ============================================================================
// SM4-GCM Tests
// ============================================================================

/**
 * @brief Test SM4-GCM encryption/decryption
 */
TEST_F(SMTest, SM4_GCM_RoundTrip) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};
    uint8_t aad[] = "additional authenticated data";
    uint8_t plaintext[] = "This is a test message for SM4-GCM encryption.";
    size_t plaintext_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[64];
    uint8_t tag[16];
    uint8_t decrypted[64];

    // Initialize and encrypt
    kctsb_sm4_gcm_ctx_t ctx;
    EXPECT_EQ(kctsb_sm4_gcm_init(&ctx, key, iv), KCTSB_SUCCESS);

    kctsb_error_t result = kctsb_sm4_gcm_encrypt(
        &ctx, aad, sizeof(aad) - 1,
        plaintext, plaintext_len,
        ciphertext, tag
    );
    EXPECT_EQ(result, KCTSB_SUCCESS);

    // Re-initialize for decryption
    EXPECT_EQ(kctsb_sm4_gcm_init(&ctx, key, iv), KCTSB_SUCCESS);

    result = kctsb_sm4_gcm_decrypt(
        &ctx, aad, sizeof(aad) - 1,
        ciphertext, plaintext_len,
        tag, decrypted
    );
    EXPECT_EQ(result, KCTSB_SUCCESS);

    EXPECT_EQ(memcmp(plaintext, decrypted, plaintext_len), 0)
        << "SM4-GCM decryption should recover original plaintext";
}

/**
 * @brief Test SM4-GCM authentication failure detection
 */
TEST_F(SMTest, SM4_GCM_AuthFailure) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};
    uint8_t plaintext[] = "Test message";
    size_t plaintext_len = sizeof(plaintext) - 1;

    uint8_t ciphertext[64];
    uint8_t tag[16];
    uint8_t decrypted[64];

    // Encrypt
    kctsb_sm4_gcm_ctx_t ctx;
    EXPECT_EQ(kctsb_sm4_gcm_init(&ctx, key, iv), KCTSB_SUCCESS);
    EXPECT_EQ(kctsb_sm4_gcm_encrypt(
        &ctx, nullptr, 0,
        plaintext, plaintext_len,
        ciphertext, tag
    ), KCTSB_SUCCESS);

    // Tamper with ciphertext
    ciphertext[0] ^= 0x01;

    // Decrypt should fail
    EXPECT_EQ(kctsb_sm4_gcm_init(&ctx, key, iv), KCTSB_SUCCESS);
    kctsb_error_t result = kctsb_sm4_gcm_decrypt(
        &ctx, nullptr, 0,
        ciphertext, plaintext_len,
        tag, decrypted
    );
    EXPECT_NE(result, KCTSB_SUCCESS)
        << "SM4-GCM should detect tampering";
}

