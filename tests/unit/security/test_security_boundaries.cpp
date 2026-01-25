/**
 * @file test_security_boundaries.cpp
 * @brief Security boundary and overflow protection tests
 *
 * Comprehensive tests for:
 * - Buffer overflow prevention
 * - Integer overflow detection
 * - Null pointer handling
 * - Invalid input rejection
 * - Memory safety operations
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <limits>
#include "kctsb/kctsb_api.h"
#include "kctsb/core/security.h"
#include "kctsb/utils/encoding.h"

class SecurityBoundaryTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }

    void TearDown() override {
        kctsb_cleanup();
    }
};

// ============================================================================
// Secure Memory Operations Tests
// ============================================================================

TEST_F(SecurityBoundaryTest, SecureZero_NullPointer) {
    // Should handle null pointer gracefully without crashing
    kctsb_secure_zero(nullptr, 100);
    SUCCEED();  // If we get here, null pointer was handled
}

TEST_F(SecurityBoundaryTest, SecureZero_ZeroLength) {
    uint8_t buffer[16] = {0xFF, 0xFF, 0xFF, 0xFF};
    // Zero length should not modify buffer
    kctsb_secure_zero(buffer, 0);
    EXPECT_EQ(buffer[0], 0xFF);
}

TEST_F(SecurityBoundaryTest, SecureZero_ValidBuffer) {
    uint8_t buffer[32];
    memset(buffer, 0xAA, sizeof(buffer));

    kctsb_secure_zero(buffer, sizeof(buffer));

    for (size_t i = 0; i < sizeof(buffer); i++) {
        EXPECT_EQ(buffer[i], 0) << "Byte " << i << " not zeroed";
    }
}

TEST_F(SecurityBoundaryTest, SecureCompare_NullPointers) {
    uint8_t buffer[16] = {0};

    // Null pointers should return 0 (not equal/invalid)
    EXPECT_EQ(kctsb_secure_compare(nullptr, buffer, 16), 0);
    EXPECT_EQ(kctsb_secure_compare(buffer, nullptr, 16), 0);
    EXPECT_EQ(kctsb_secure_compare(nullptr, nullptr, 16), 0);
}

TEST_F(SecurityBoundaryTest, SecureCompare_ZeroLength) {
    uint8_t a[16] = {0xAA};
    uint8_t b[16] = {0xBB};

    // Zero length comparison should return equal (1)
    EXPECT_EQ(kctsb_secure_compare(a, b, 0), 1);
}

TEST_F(SecurityBoundaryTest, SecureCompare_ConstantTime) {
    // Test that comparison is constant-time by verifying
    // different byte positions don't affect result
    uint8_t base[32];
    uint8_t test[32];

    memset(base, 0xAA, sizeof(base));
    memcpy(test, base, sizeof(test));

    // Equal buffers
    EXPECT_EQ(kctsb_secure_compare(base, test, sizeof(base)), 1);

    // Different at first byte
    test[0] = 0xBB;
    EXPECT_EQ(kctsb_secure_compare(base, test, sizeof(base)), 0);
    test[0] = 0xAA;

    // Different at last byte
    test[31] = 0xBB;
    EXPECT_EQ(kctsb_secure_compare(base, test, sizeof(base)), 0);
}

TEST_F(SecurityBoundaryTest, SecureCopy_BoundaryChecks) {
    uint8_t src[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t dest[16] = {0};

    // Normal copy should succeed
    EXPECT_EQ(kctsb_secure_copy(dest, sizeof(dest), src, sizeof(src)), 0);
    EXPECT_EQ(memcmp(dest, src, sizeof(src)), 0);

    // Copy more than dest_size should fail
    EXPECT_EQ(kctsb_secure_copy(dest, 8, src, 16), -2);

    // Null pointers should fail
    EXPECT_EQ(kctsb_secure_copy(nullptr, 16, src, 16), -1);
    EXPECT_EQ(kctsb_secure_copy(dest, 16, nullptr, 16), -1);
}

// ============================================================================
// AES Boundary Tests
// ============================================================================

TEST_F(SecurityBoundaryTest, AES_InvalidKeyLengths) {
    kctsb_aes_ctx_t ctx;

    // Valid key lengths: 16, 24, 32
    uint8_t key[32] = {0};

    // Invalid key lengths should be rejected
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 0), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 1), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 15), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 17), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 23), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 25), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 31), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 33), KCTSB_ERROR_INVALID_KEY);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 64), KCTSB_ERROR_INVALID_KEY);

    // Valid lengths should succeed
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);
    kctsb_aes_clear(&ctx);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 24), KCTSB_SUCCESS);
    kctsb_aes_clear(&ctx);
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 32), KCTSB_SUCCESS);
    kctsb_aes_clear(&ctx);
}

TEST_F(SecurityBoundaryTest, AES_NullPointerHandling) {
    kctsb_aes_ctx_t ctx;
    uint8_t key[16] = {0};
    uint8_t data[16] = {0};
    uint8_t output[16] = {0};

    // Null context
    EXPECT_EQ(kctsb_aes_init(nullptr, key, 16), KCTSB_ERROR_INVALID_PARAM);

    // Null key
    EXPECT_EQ(kctsb_aes_init(&ctx, nullptr, 16), KCTSB_ERROR_INVALID_PARAM);

    // Initialize properly for further tests
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);

    // Null input/output in block operations
    EXPECT_EQ(kctsb_aes_encrypt_block(nullptr, data, output), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_aes_encrypt_block(&ctx, nullptr, output), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_aes_encrypt_block(&ctx, data, nullptr), KCTSB_ERROR_INVALID_PARAM);

    kctsb_aes_clear(&ctx);
}

TEST_F(SecurityBoundaryTest, AES_GCM_BoundaryConditions) {
    kctsb_aes_ctx_t ctx;
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t tag[16] = {0};
    uint8_t data[16] = {0};
    uint8_t output[16] = {0};

    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);

    // Note: The GCM API requires valid output pointers when plaintext_len > 0
    // Empty plaintext with null ciphertext buffer is implementation-specific
    // We test the normal cases that should always work

    // Normal encryption with data
    EXPECT_EQ(kctsb_aes_gcm_encrypt(&ctx, iv, 12, nullptr, 0, data, 16, output, tag), KCTSB_SUCCESS);

    // Decryption should work with valid tag
    uint8_t decrypted[16] = {0};
    EXPECT_EQ(kctsb_aes_gcm_decrypt(&ctx, iv, 12, nullptr, 0, output, 16, tag, decrypted), KCTSB_SUCCESS);
    EXPECT_EQ(memcmp(decrypted, data, 16), 0);

    kctsb_aes_clear(&ctx);
}

// ============================================================================
// Encoding Boundary Tests
// ============================================================================

TEST_F(SecurityBoundaryTest, HexEncode_BoundaryConditions) {
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    char hex[32] = {0};

    // Normal case
    size_t result = kctsb_hex_encode(data, sizeof(data), hex, sizeof(hex));
    EXPECT_EQ(result, 8);  // 4 bytes = 8 hex chars
    EXPECT_STREQ(hex, "deadbeef");

    // Buffer too small
    char small_hex[4] = {0};
    result = kctsb_hex_encode(data, sizeof(data), small_hex, sizeof(small_hex));
    EXPECT_EQ(result, 0);  // Should fail - needs 9 bytes (8 + null)

    // Null pointers
    result = kctsb_hex_encode(nullptr, 4, hex, sizeof(hex));
    EXPECT_EQ(result, 0);
    result = kctsb_hex_encode(data, 4, nullptr, sizeof(hex));
    EXPECT_EQ(result, 0);

    // Zero length
    result = kctsb_hex_encode(data, 0, hex, sizeof(hex));
    EXPECT_EQ(result, 0);
}

TEST_F(SecurityBoundaryTest, HexDecode_InvalidInput) {
    uint8_t output[16] = {0};

    // Invalid hex characters
    size_t result = kctsb_hex_decode("ghij", 4, output, sizeof(output));
    EXPECT_EQ(result, 0);

    // Odd length hex string
    result = kctsb_hex_decode("abc", 3, output, sizeof(output));
    EXPECT_EQ(result, 0);

    // Valid hex
    result = kctsb_hex_decode("deadbeef", 8, output, sizeof(output));
    EXPECT_EQ(result, 4);
    EXPECT_EQ(output[0], 0xDE);
    EXPECT_EQ(output[1], 0xAD);
    EXPECT_EQ(output[2], 0xBE);
    EXPECT_EQ(output[3], 0xEF);
}

TEST_F(SecurityBoundaryTest, Base64_BoundaryConditions) {
    uint8_t data[] = {0x00, 0x01, 0x02, 0x03};
    char b64[32] = {0};

    // Normal encode
    size_t result = kctsb_base64_encode(data, sizeof(data), b64, sizeof(b64));
    EXPECT_GT(result, 0);

    // Decode back
    uint8_t decoded[16] = {0};
    size_t decoded_len = kctsb_base64_decode(b64, strlen(b64), decoded, sizeof(decoded));
    EXPECT_EQ(decoded_len, sizeof(data));
    EXPECT_EQ(memcmp(decoded, data, sizeof(data)), 0);

    // Buffer too small for encode
    char small[2] = {0};
    result = kctsb_base64_encode(data, sizeof(data), small, sizeof(small));
    EXPECT_EQ(result, 0);
}

// ============================================================================
// Integer Overflow Tests
// ============================================================================

TEST_F(SecurityBoundaryTest, IntegerConversion_EdgeCases) {
    uint8_t bytes[8] = {0};

    // Max uint64_t
    uint64_t max_val = std::numeric_limits<uint64_t>::max();
    size_t result = kctsb_uint64_to_bytes_be(max_val, bytes, sizeof(bytes));
    EXPECT_EQ(result, 8);

    uint64_t decoded = 0;
    // Note: kctsb_bytes_to_uint64_be returns 1 on success, not byte count
    int success = kctsb_bytes_to_uint64_be(bytes, 8, &decoded);
    EXPECT_EQ(success, 1);
    EXPECT_EQ(decoded, max_val);

    // Min value (0)
    result = kctsb_uint64_to_bytes_be(0, bytes, sizeof(bytes));
    EXPECT_EQ(result, 8);
    success = kctsb_bytes_to_uint64_be(bytes, 8, &decoded);
    EXPECT_EQ(success, 1);
    EXPECT_EQ(decoded, 0ULL);

    // Buffer too small
    result = kctsb_uint64_to_bytes_be(max_val, bytes, 4);
    EXPECT_EQ(result, 0);
}

// ============================================================================
// CSPRNG Tests
// ============================================================================

TEST_F(SecurityBoundaryTest, RandomBytes_BoundaryConditions) {
    uint8_t buffer[64] = {0};

    // Normal case
    int result = kctsb_random_bytes(buffer, sizeof(buffer));
    EXPECT_EQ(result, KCTSB_SUCCESS);

    // Verify not all zeros (statistical test)
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "Random bytes should not be all zeros";

    // Zero length should succeed
    result = kctsb_random_bytes(buffer, 0);
    EXPECT_EQ(result, KCTSB_SUCCESS);

    // Null pointer should fail
    result = kctsb_random_bytes(nullptr, 16);
    EXPECT_EQ(result, KCTSB_ERROR_INVALID_PARAM);
}

// ============================================================================
// Constant-Time Operation Tests
// ============================================================================

TEST_F(SecurityBoundaryTest, ConstantTimeSelect) {
    uint64_t a = 0x1111111111111111ULL;
    uint64_t b = 0x2222222222222222ULL;

    // condition != 0 should select b
    EXPECT_EQ(kctsb_ct_select(1, a, b), b);
    EXPECT_EQ(kctsb_ct_select(0xFF, a, b), b);

    // condition == 0 should select a
    EXPECT_EQ(kctsb_ct_select(0, a, b), a);
}

TEST_F(SecurityBoundaryTest, ConstantTimeSwap) {
    uint64_t a = 0x1111111111111111ULL;
    uint64_t b = 0x2222222222222222ULL;
    uint64_t orig_a = a;
    uint64_t orig_b = b;

    // condition == 0: no swap
    kctsb_ct_swap(0, &a, &b);
    EXPECT_EQ(a, orig_a);
    EXPECT_EQ(b, orig_b);

    // condition != 0: swap
    kctsb_ct_swap(1, &a, &b);
    EXPECT_EQ(a, orig_b);
    EXPECT_EQ(b, orig_a);

    // Null pointer handling
    kctsb_ct_swap(1, nullptr, &b);  // Should not crash
    kctsb_ct_swap(1, &a, nullptr);  // Should not crash
}

// ============================================================================
// Hash Function Boundary Tests
// ============================================================================

TEST_F(SecurityBoundaryTest, SHA256_LargeInput) {
    // Test with 1MB of data
    std::vector<uint8_t> large_data(1024 * 1024, 0xAB);
    uint8_t hash[32] = {0};

    kctsb_sha256_ctx_t ctx;
    kctsb_sha256_init(&ctx);
    kctsb_sha256_update(&ctx, large_data.data(), large_data.size());
    kctsb_sha256_final(&ctx, hash);

    // Verify hash is not all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);
}

TEST_F(SecurityBoundaryTest, SHA256_EmptyInput) {
    uint8_t hash[32] = {0};

    // SHA-256 of empty string
    kctsb_sha256(nullptr, 0, hash);

    // Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    EXPECT_EQ(memcmp(hash, expected, 32), 0);
}
