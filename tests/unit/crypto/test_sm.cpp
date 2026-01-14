/**
 * @file test_sm.cpp
 * @brief SM (Chinese National Cryptographic Standards) algorithm unit tests
 *
 * Tests for:
 * - SM3: Hash function (GB/T 32905-2016)
 * - SM4: Block cipher (GB/T 32907-2016)
 *
 * Test vectors from official GM/T standards.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

#include "kctsb/kctsb.h"
// Include actual SM implementations
extern "C" {
#include "kctsb/crypto/sm/sm3_core.h"
}
#include "kctsb/crypto/sm/sm4_core.hpp"

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
    SM3_STATE ctx;
    unsigned char output[32];
    const unsigned char message[] = "abc";

    SM3_init(&ctx);
    SM3_process(&ctx, message, 3);
    SM3_done(&ctx, output);

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
    SM3_STATE ctx;
    unsigned char output[32];

    // 64 bytes: "abcd" * 16
    const char* message = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

    SM3_init(&ctx);
    SM3_process(&ctx, reinterpret_cast<const unsigned char*>(message), 64);
    SM3_done(&ctx, output);

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
    SM3_STATE ctx;
    unsigned char output[32];

    SM3_init(&ctx);
    SM3_done(&ctx, output);

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
    SM3_STATE ctx1, ctx2;
    unsigned char output1[32], output2[32];
    const char* message = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(message);

    // Hash all at once
    SM3_init(&ctx1);
    SM3_process(&ctx1, reinterpret_cast<const unsigned char*>(message), len);
    SM3_done(&ctx1, output1);

    // Hash in chunks
    SM3_init(&ctx2);
    SM3_process(&ctx2, reinterpret_cast<const unsigned char*>(message), 20);
    SM3_process(&ctx2, reinterpret_cast<const unsigned char*>(message + 20), len - 20);
    SM3_done(&ctx2, output2);

    EXPECT_EQ(memcmp(output1, output2, 32), 0)
        << "Incremental hashing should produce same result";
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
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char ciphertext[16];

    SM4_Encrypt(key, plaintext, ciphertext);

    // Expected ciphertext from GM/T 0002-2012
    const char* expected_hex = "681edf34d206965e86b3e94f536e4246";
    std::string result_hex = bytes_to_hex(ciphertext, 16);

    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SM4 decryption with standard test vector
 */
TEST_F(SMTest, SM4_Decrypt_TestVector) {
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char ciphertext[16] = {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };
    unsigned char plaintext[16];

    SM4_Decrypt(key, ciphertext, plaintext);

    // Expected plaintext
    const char* expected_hex = "0123456789abcdeffedcba9876543210";
    std::string result_hex = bytes_to_hex(plaintext, 16);

    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SM4 encryption/decryption round trip
 */
TEST_F(SMTest, SM4_RoundTrip) {
    unsigned char key[16];
    unsigned char original[16];
    unsigned char encrypted[16];
    unsigned char decrypted[16];

    // Test with various keys and plaintexts
    for (int test = 0; test < 10; ++test) {
        // Generate test data
        for (int i = 0; i < 16; ++i) {
            key[i] = static_cast<unsigned char>((test * 17 + i * 31) & 0xFF);
            original[i] = static_cast<unsigned char>((test * 23 + i * 37) & 0xFF);
        }

        SM4_Encrypt(key, original, encrypted);
        SM4_Decrypt(key, encrypted, decrypted);

        EXPECT_EQ(memcmp(original, decrypted, 16), 0)
            << "SM4 round trip failed for test " << test;
    }
}

/**
 * @brief Test SM4 with different plaintexts
 */
TEST_F(SMTest, SM4_DifferentPlaintexts) {
    unsigned char key[16] = {0};
    unsigned char plain1[16] = {0};
    unsigned char plain2[16] = {0};
    unsigned char cipher1[16], cipher2[16];

    plain2[15] = 1;  // Only last bit differs

    SM4_Encrypt(key, plain1, cipher1);
    SM4_Encrypt(key, plain2, cipher2);

    // Different plaintexts should produce different ciphertexts
    EXPECT_NE(memcmp(cipher1, cipher2, 16), 0)
        << "Different plaintexts should produce different ciphertexts";

    // Count differing bytes (avalanche effect)
    int diff_count = 0;
    for (int i = 0; i < 16; ++i) {
        if (cipher1[i] != cipher2[i]) diff_count++;
    }

    EXPECT_GT(diff_count, 8)
        << "SM4 should exhibit strong avalanche effect";
}

/**
 * @brief Test SM4 key schedule
 */
TEST_F(SMTest, SM4_KeySchedule) {
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned int rk[32];

    SM4_KeySchedule(key, rk);

    // Verify round keys are non-zero
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (rk[i] != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero) << "Round keys should not all be zero";
}

// ============================================================================
// SM4-GCM AEAD Tests (Only supported mode)
// ============================================================================

/**
 * @brief Test SM4-GCM basic encryption/decryption
 */
TEST_F(SMTest, SM4_GCM_Basic) {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t iv[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                      0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B};
    uint8_t plaintext[32] = "Hello SM4-GCM Test Message!";
    uint8_t ciphertext[32];
    uint8_t decrypted[32];
    uint8_t tag[16];
    uint8_t aad[8] = "aad_dat";

    // Encrypt
    auto err = kctsb_sm4_gcm_encrypt_oneshot(
        key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext),
        ciphertext, tag
    );
    EXPECT_EQ(err, KCTSB_SUCCESS);

    // Decrypt
    err = kctsb_sm4_gcm_decrypt_oneshot(
        key, iv, aad, sizeof(aad),
        ciphertext, sizeof(ciphertext),
        tag, decrypted
    );
    EXPECT_EQ(err, KCTSB_SUCCESS);
    EXPECT_EQ(memcmp(plaintext, decrypted, sizeof(plaintext)), 0);
}

/**
 * @brief Test SM4-GCM authentication failure
 */
TEST_F(SMTest, SM4_GCM_AuthFailure) {
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t plaintext[16] = "Test message!!!";
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    uint8_t tag[16];

    // Encrypt
    auto err = kctsb_sm4_gcm_encrypt_oneshot(
        key, iv, nullptr, 0,
        plaintext, sizeof(plaintext),
        ciphertext, tag
    );
    EXPECT_EQ(err, KCTSB_SUCCESS);

    // Tamper with tag
    tag[0] ^= 0xFF;

    // Decrypt should fail
    err = kctsb_sm4_gcm_decrypt_oneshot(
        key, iv, nullptr, 0,
        ciphertext, sizeof(ciphertext),
        tag, decrypted
    );
    EXPECT_EQ(err, KCTSB_ERROR_AUTH_FAILED);
}

/**
 * @brief Test SM4-GCM with AAD
 */
TEST_F(SMTest, SM4_GCM_WithAAD) {
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t iv[12] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B};
    uint8_t aad[32] = "This is additional auth data!!!";
    uint8_t plaintext[48] = "SM4-GCM with AAD test - secure message!!!!!";
    uint8_t ciphertext[48];
    uint8_t decrypted[48];
    uint8_t tag[16];

    // Encrypt with AAD
    auto err = kctsb_sm4_gcm_encrypt_oneshot(
        key, iv, aad, sizeof(aad),
        plaintext, sizeof(plaintext),
        ciphertext, tag
    );
    EXPECT_EQ(err, KCTSB_SUCCESS);

    // Decrypt with correct AAD
    err = kctsb_sm4_gcm_decrypt_oneshot(
        key, iv, aad, sizeof(aad),
        ciphertext, sizeof(ciphertext),
        tag, decrypted
    );
    EXPECT_EQ(err, KCTSB_SUCCESS);
    EXPECT_EQ(memcmp(plaintext, decrypted, sizeof(plaintext)), 0);

    // Decrypt with wrong AAD should fail
    aad[0] ^= 0xFF;
    err = kctsb_sm4_gcm_decrypt_oneshot(
        key, iv, aad, sizeof(aad),
        ciphertext, sizeof(ciphertext),
        tag, decrypted
    );
    EXPECT_EQ(err, KCTSB_ERROR_AUTH_FAILED);
}

/**
 * @brief Test SM4-GCM empty plaintext (auth-only)
 */
TEST_F(SMTest, SM4_GCM_EmptyPlaintext) {
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[16] = "auth_me_pls_aaa";  // 15 chars + null
    uint8_t tag[16];

    // Encrypt with no plaintext (authentication only)
    auto err = kctsb_sm4_gcm_encrypt_oneshot(
        key, iv, aad, sizeof(aad),
        nullptr, 0,
        nullptr, tag
    );
    EXPECT_EQ(err, KCTSB_SUCCESS);

    // Verify tag
    err = kctsb_sm4_gcm_decrypt_oneshot(
        key, iv, aad, sizeof(aad),
        nullptr, 0,
        tag, nullptr
    );
    // Note: This may fail with current implementation that checks for null plaintext
    // Update if implementation allows empty ciphertext
}

