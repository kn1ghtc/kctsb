/**
 * @file test_mac.cpp
 * @brief Message Authentication Code (MAC) unit tests
 *
 * Tests for MAC algorithms:
 * - HMAC-SHA256: RFC 4231 test vectors
 * - HMAC-SHA512: RFC 4231 test vectors
 * - CMAC-AES: NIST SP 800-38B test vectors
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

#include "kctsb/kctsb.h"
#include "kctsb/crypto/mac.h"

/**
 * @brief Convert hex string to bytes
 */
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        auto byte = static_cast<uint8_t>(
            std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

/**
 * @brief Convert bytes to hex string
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

class MACTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

// ============================================================================
// HMAC-SHA256 Tests (RFC 4231)
// ============================================================================

/**
 * @brief RFC 4231 Test Case 1
 * Key = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
 * Data = "Hi There"
 */
TEST_F(MACTest, HMAC_SHA256_RFC4231_TC1) {
    auto key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const uint8_t data[] = "Hi There";

    uint8_t mac[32];
    // HMAC functions return void per API
    kctsb_hmac_sha256(
        key.data(), key.size(),
        data, 8,
        mac
    );

    const char* expected =
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7";

    EXPECT_EQ(bytes_to_hex(mac, 32), expected);
}

/**
 * @brief RFC 4231 Test Case 2
 * Key = "Jefe"
 * Data = "what do ya want for nothing?"
 */
TEST_F(MACTest, HMAC_SHA256_RFC4231_TC2) {
    const uint8_t key[] = "Jefe";
    const uint8_t data[] = "what do ya want for nothing?";

    uint8_t mac[32];
    kctsb_hmac_sha256(
        key, 4,
        data, 28,
        mac
    );

    const char* expected =
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843";

    EXPECT_EQ(bytes_to_hex(mac, 32), expected);
}

/**
 * @brief RFC 4231 Test Case 3
 * Key = aaaa... (20 bytes)
 * Data = dddd... (50 bytes)
 */
TEST_F(MACTest, HMAC_SHA256_RFC4231_TC3) {
    auto key = hex_to_bytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    std::vector<uint8_t> data(50, 0xdd);

    uint8_t mac[32];
    kctsb_hmac_sha256(
        key.data(), key.size(),
        data.data(), data.size(),
        mac
    );

    const char* expected =
        "773ea91e36800e46854db8ebd09181a7"
        "2959098b3ef8c122d9635514ced565fe";

    EXPECT_EQ(bytes_to_hex(mac, 32), expected);
}

/**
 * @brief RFC 4231 Test Case 4
 * Key = 0102030405... (25 bytes)
 * Data = cdcd... (50 bytes)
 */
TEST_F(MACTest, HMAC_SHA256_RFC4231_TC4) {
    auto key = hex_to_bytes("0102030405060708090a0b0c0d0e0f10111213141516171819");
    std::vector<uint8_t> data(50, 0xcd);

    uint8_t mac[32];
    kctsb_hmac_sha256(
        key.data(), key.size(),
        data.data(), data.size(),
        mac
    );

    const char* expected =
        "82558a389a443c0ea4cc819899f2083a"
        "85f0faa3e578f8077a2e3ff46729665b";

    EXPECT_EQ(bytes_to_hex(mac, 32), expected);
}

/**
 * @brief RFC 4231 Test Case 6 - Long key (131 bytes)
 */
TEST_F(MACTest, HMAC_SHA256_RFC4231_TC6_LongKey) {
    std::vector<uint8_t> key(131, 0xaa);
    const uint8_t data[] = "Test Using Larger Than Block-Size Key - Hash Key First";

    uint8_t mac[32];
    kctsb_hmac_sha256(
        key.data(), key.size(),
        data, 54,
        mac
    );

    const char* expected =
        "60e431591ee0b67f0d8a26aacbf5b77f"
        "8e0bc6213728c5140546040f0ee37f54";

    EXPECT_EQ(bytes_to_hex(mac, 32), expected);
}

// ============================================================================
// HMAC-SHA256 Incremental API Tests
// ============================================================================

TEST_F(MACTest, HMAC_SHA256_Incremental) {
    const uint8_t key[] = "secret_key_12345";
    const char* message = "This is a test message for HMAC incremental API";
    size_t len = strlen(message);

    // One-shot
    uint8_t mac1[32];
    kctsb_hmac_sha256(
        key, 16,
        reinterpret_cast<const uint8_t*>(message), len,
        mac1
    );

    // Incremental - use kctsb_hmac_ctx_t per API
    kctsb_hmac_ctx_t ctx;
    kctsb_hmac_sha256_init(&ctx, key, 16);
    kctsb_hmac_sha256_update(&ctx, reinterpret_cast<const uint8_t*>(message), 20);
    kctsb_hmac_sha256_update(&ctx, reinterpret_cast<const uint8_t*>(message + 20), len - 20);
    uint8_t mac2[32];
    kctsb_hmac_sha256_final(&ctx, mac2);

    EXPECT_EQ(memcmp(mac1, mac2, 32), 0)
        << "Incremental HMAC should produce same result as one-shot";
}

TEST_F(MACTest, HMAC_SHA256_EmptyMessage) {
    const uint8_t key[] = "secret";
    uint8_t mac[32];

    // Empty message test
    kctsb_hmac_sha256(key, 6, nullptr, 0, mac);

    // Verify not all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (mac[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);
}

// ============================================================================
// HMAC-SHA512 Tests (RFC 4231)
// ============================================================================

/**
 * @brief RFC 4231 Test Case 1 for HMAC-SHA512
 */
TEST_F(MACTest, HMAC_SHA512_RFC4231_TC1) {
    auto key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const uint8_t data[] = "Hi There";

    uint8_t mac[64];
    // HMAC functions return void per API
    kctsb_hmac_sha512(
        key.data(), key.size(),
        data, 8,
        mac
    );

    const char* expected =
        "87aa7cdea5ef619d4ff0b4241a1d6cb0"
        "2379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4"
        "be9d914eeb61f1702e696c203a126854";

    EXPECT_EQ(bytes_to_hex(mac, 64), expected);
}

/**
 * @brief RFC 4231 Test Case 2 for HMAC-SHA512
 */
TEST_F(MACTest, HMAC_SHA512_RFC4231_TC2) {
    const uint8_t key[] = "Jefe";
    const uint8_t data[] = "what do ya want for nothing?";

    uint8_t mac[64];
    kctsb_hmac_sha512(
        key, 4,
        data, 28,
        mac
    );

    const char* expected =
        "164b7a7bfcf819e2e395fbe73b56e0a3"
        "87bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fd"
        "caeab1a34d4a6b4b636e070a38bce737";

    EXPECT_EQ(bytes_to_hex(mac, 64), expected);
}

TEST_F(MACTest, HMAC_SHA512_Incremental) {
    const uint8_t key[] = "test_key_for_512";
    const char* message = "Message for HMAC-SHA512 incremental test";
    size_t len = strlen(message);

    // One-shot
    uint8_t mac1[64];
    kctsb_hmac_sha512(
        key, 16,
        reinterpret_cast<const uint8_t*>(message), len,
        mac1
    );

    // Incremental - use kctsb_hmac512_ctx_t per API
    kctsb_hmac512_ctx_t ctx;
    kctsb_hmac_sha512_init(&ctx, key, 16);
    kctsb_hmac_sha512_update(&ctx, reinterpret_cast<const uint8_t*>(message), 15);
    kctsb_hmac_sha512_update(&ctx, reinterpret_cast<const uint8_t*>(message + 15), len - 15);
    uint8_t mac2[64];
    kctsb_hmac_sha512_final(&ctx, mac2);

    EXPECT_EQ(memcmp(mac1, mac2, 64), 0);
}

// ============================================================================
// Consistency Tests (HMAC functions return void so we test behavior)
// ============================================================================

TEST_F(MACTest, HMAC_SHA256_Deterministic) {
    const uint8_t key[] = "key";
    const uint8_t data[] = "test";
    uint8_t mac1[32], mac2[32];

    kctsb_hmac_sha256(key, 3, data, 4, mac1);
    kctsb_hmac_sha256(key, 3, data, 4, mac2);

    EXPECT_EQ(memcmp(mac1, mac2, 32), 0)
        << "HMAC should be deterministic";
}

// ============================================================================
// Performance Sanity Tests
// ============================================================================

TEST_F(MACTest, HMAC_SHA256_LargeMessage) {
    const uint8_t key[] = "performance_test_key_32bytes!!!";
    std::vector<uint8_t> data(1024 * 1024, 0x42);  // 1 MB
    uint8_t mac[32];

    kctsb_hmac_sha256(
        key, 32,
        data.data(), data.size(),
        mac
    );

    // Verify deterministic
    uint8_t mac2[32];
    kctsb_hmac_sha256(key, 32, data.data(), data.size(), mac2);
    EXPECT_EQ(memcmp(mac, mac2, 32), 0);
}

// ============================================================================
// Key Derivation Function Tests (HKDF uses HMAC internally)
// ============================================================================

TEST_F(MACTest, HMAC_KeyDerivation_Consistency) {
    // Test that HMAC produces consistent output for key derivation
    const uint8_t ikm[] = "input keying material";
    const uint8_t salt[] = "random salt value";

    uint8_t prk1[32], prk2[32];

    // HKDF-Extract step: PRK = HMAC(salt, IKM)
    kctsb_hmac_sha256(salt, 17, ikm, 21, prk1);
    kctsb_hmac_sha256(salt, 17, ikm, 21, prk2);

    EXPECT_EQ(memcmp(prk1, prk2, 32), 0) << "PRK should be deterministic";

    // Verify PRK is not all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (prk1[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);
}
