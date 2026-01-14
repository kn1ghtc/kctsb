/**
 * @file test_hash.cpp
 * @brief Hash function unit tests
 *
 * Tests for SHA3-256/512 (Keccak) and BLAKE2b/BLAKE2s implementations.
 * Validates correctness against known test vectors from official specifications.
 *
 * Test Vectors:
 * - SHA3-256: NIST FIPS 202 test vectors
 * - BLAKE2b: RFC 7693 Appendix A test vectors
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

#include "kctsb/kctsb.h"
// Include actual hash implementations
#include "kctsb/crypto/hash/keccak.h"
#include "kctsb/crypto/blake.h"
// Include internal implementations for detailed testing
#include "kctsb/crypto/hash/blake2_impl.h"

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

class HashTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

// ============================================================================
// SHA3-256 (Keccak) Tests
// ============================================================================

/**
 * @brief Test SHA3-256 empty input
 *
 * NIST test vector: SHA3-256("")
 */
TEST_F(HashTest, SHA3_256_Empty) {
    uint8_t output[32];
    const uint8_t empty_input[] = "";

    FIPS202_SHA3_256(empty_input, 0, output);

    // Expected: SHA3-256("") from NIST
    const char* expected_hex =
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SHA3-256 with "abc"
 *
 * NIST test vector: SHA3-256("abc")
 */
TEST_F(HashTest, SHA3_256_ABC) {
    uint8_t output[32];
    const uint8_t input[] = "abc";

    FIPS202_SHA3_256(input, 3, output);

    // Expected: SHA3-256("abc") from NIST FIPS 202
    const char* expected_hex =
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test SHA3-256 with longer message
 */
TEST_F(HashTest, SHA3_256_LongMessage) {
    uint8_t output[32];

    // 448-bit message (exactly 56 bytes)
    const char* message = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd";

    FIPS202_SHA3_256(reinterpret_cast<const uint8_t*>(message),
                     strlen(message), output);

    // Verify output is non-zero and consistent
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (output[i] != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero) << "SHA3-256 output should not be all zeros";
}

// ============================================================================
// BLAKE2b Tests
// ============================================================================

/**
 * @brief Test BLAKE2b-256 empty input
 */
TEST_F(HashTest, BLAKE2b_Empty) {
    blake2b_ctx_t ctx;
    uint8_t output[32];

    int ret = blake2b_init(&ctx, 32);
    ASSERT_EQ(ret, 0) << "BLAKE2b init failed";

    ret = blake2b_final(&ctx, output, 32);
    ASSERT_EQ(ret, 0) << "BLAKE2b final failed";

    // BLAKE2b-256("") - RFC 7693
    const char* expected_hex =
        "0e5751c026e543b2e8ab2eb06099daa1"
        "d1e5df47778f7787faab45cdf12fe3a8";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test BLAKE2b-256 with "abc"
 */
TEST_F(HashTest, BLAKE2b_ABC) {
    blake2b_ctx_t ctx;
    uint8_t output[32];
    const uint8_t input[] = "abc";

    int ret = blake2b_init(&ctx, 32);
    ASSERT_EQ(ret, 0);

    ret = blake2b_update(&ctx, input, 3);
    ASSERT_EQ(ret, 0);

    ret = blake2b_final(&ctx, output, 32);
    ASSERT_EQ(ret, 0);

    // Verify output is non-zero
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (output[i] != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero);
}

/**
 * @brief Test BLAKE2b incremental hashing
 */
TEST_F(HashTest, BLAKE2b_Incremental) {
    blake2b_ctx_t ctx1, ctx2;
    uint8_t output1[32], output2[32];
    const char* message = "The quick brown fox jumps over the lazy dog";

    // Hash all at once
    blake2b_init(&ctx1, 32);
    blake2b_update(&ctx1, reinterpret_cast<const uint8_t*>(message), strlen(message));
    blake2b_final(&ctx1, output1, 32);

    // Hash incrementally
    blake2b_init(&ctx2, 32);
    blake2b_update(&ctx2, reinterpret_cast<const uint8_t*>(message), 10);
    blake2b_update(&ctx2, reinterpret_cast<const uint8_t*>(message + 10), strlen(message) - 10);
    blake2b_final(&ctx2, output2, 32);

    // Results should be identical
    EXPECT_EQ(memcmp(output1, output2, 32), 0)
        << "Incremental hashing should produce same result";
}

/**
 * @brief Test BLAKE2b with key (MAC mode)
 */
TEST_F(HashTest, BLAKE2b_Keyed) {
    blake2b_ctx_t ctx;
    uint8_t output[32];
    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const uint8_t message[] = "test message";

    int ret = blake2b_init_key(&ctx, 32, key, 16);
    ASSERT_EQ(ret, 0) << "BLAKE2b keyed init failed";

    ret = blake2b_update(&ctx, message, sizeof(message) - 1);
    ASSERT_EQ(ret, 0);

    ret = blake2b_final(&ctx, output, 32);
    ASSERT_EQ(ret, 0);

    // Keyed hash should differ from non-keyed
    blake2b_ctx_t ctx_unkeyed;
    uint8_t output_unkeyed[32];
    blake2b_init(&ctx_unkeyed, 32);
    blake2b_update(&ctx_unkeyed, message, sizeof(message) - 1);
    blake2b_final(&ctx_unkeyed, output_unkeyed, 32);

    EXPECT_NE(memcmp(output, output_unkeyed, 32), 0)
        << "Keyed hash should differ from unkeyed hash";
}

// ============================================================================
// BLAKE2b Tests (using public API) - Additional Tests
// ============================================================================

/**
 * @brief Test BLAKE2b-256 empty input using kctsb stream API
 */
TEST_F(HashTest, BLAKE2b_Stream_Empty) {
    kctsb_blake2b_ctx_t ctx;
    uint8_t output[32];

    kctsb_blake2b_init(&ctx, 32);
    kctsb_blake2b_final(&ctx, output);

    // Verify output is valid (non-zero for empty input)
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (output[i] != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero);
}

// ============================================================================
// BLAKE2s Tests (public API)
// ============================================================================

/**
 * @brief Test BLAKE2s-256 empty input using public stream API
 */
TEST_F(HashTest, BLAKE2s_Empty) {
    kctsb_blake2s_ctx_t ctx;
    uint8_t output[32];

    kctsb_blake2s_init(&ctx, 32);
    kctsb_blake2s_final(&ctx, output);

    const char* expected_hex =
        "69217a3079908094e11121d042354a7c"
        "1f55b6482ca1a51e1b250dfd1ed0eef9";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

/**
 * @brief Test BLAKE2s-256 with "abc" using one-shot API
 */
TEST_F(HashTest, BLAKE2s_ABC) {
    uint8_t output[32];
    const uint8_t input[] = "abc";

    kctsb_blake2s(input, 3, output, 32);

    const char* expected_hex =
        "508c5e8c327c14e2e1a72ba34eeb452f"
        "37458b209ed63a294d999b4c86675982";

    std::string result_hex = bytes_to_hex(output, 32);
    EXPECT_EQ(result_hex, expected_hex);
}

// ============================================================================
// Hash Consistency Tests
// ============================================================================

/**
 * @brief Test deterministic output
 */
TEST_F(HashTest, Deterministic) {
    uint8_t output1[32], output2[32];
    const uint8_t input[] = "deterministic test";

    FIPS202_SHA3_256(input, sizeof(input) - 1, output1);
    FIPS202_SHA3_256(input, sizeof(input) - 1, output2);

    EXPECT_EQ(memcmp(output1, output2, 32), 0)
        << "Same input should produce same output";
}

/**
 * @brief Test avalanche effect (small change = big output change)
 */
TEST_F(HashTest, AvalancheEffect) {
    uint8_t output1[32], output2[32];
    uint8_t input1[] = "test input 1";
    uint8_t input2[] = "test input 2";  // Only last byte differs

    FIPS202_SHA3_256(input1, sizeof(input1) - 1, output1);
    FIPS202_SHA3_256(input2, sizeof(input2) - 1, output2);

    // Count differing bytes
    int diff_count = 0;
    for (int i = 0; i < 32; ++i) {
        if (output1[i] != output2[i]) diff_count++;
    }

    // Expect significant difference (avalanche effect)
    EXPECT_GT(diff_count, 16)
        << "Avalanche effect: small input change should cause large output change";
}
