/**
 * @file test_hash.cpp
 * @brief Hash function unit tests (v3.4.0 - Complete coverage)
 *
 * Tests for all hash algorithms in kctsb:
 * - SHA-256: FIPS 180-4 test vectors
 * - SHA-512/384: FIPS 180-4 test vectors
 * - SHA3-256/512: FIPS 202 test vectors
 * - SHAKE128/256: FIPS 202 XOF test vectors
 * - BLAKE2b/BLAKE2s: RFC 7693 test vectors
 * - SM3: GB/T 32905-2016 test vectors
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

// v3.4.0 refactored headers (include before kctsb.h to avoid conflicts)
#include "kctsb/crypto/sha256.h"
#include "kctsb/crypto/sha512.h"
#include "kctsb/crypto/sha3.h"
#include "kctsb/crypto/blake2.h"
#include "kctsb/crypto/sm/sm3.h"
#include "kctsb/kctsb.h"  // For kctsb_init()

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
// SHA-256 Tests (FIPS 180-4)
// ============================================================================

TEST_F(HashTest, SHA256_Empty) {
    uint8_t digest[KCTSB_SHA256_DIGEST_SIZE];
    kctsb_sha256(nullptr, 0, digest);

    const char* expected_hex =
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

TEST_F(HashTest, SHA256_ABC) {
    uint8_t digest[KCTSB_SHA256_DIGEST_SIZE];
    const uint8_t msg[] = "abc";
    kctsb_sha256(msg, 3, digest);

    const char* expected_hex =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

TEST_F(HashTest, SHA256_TwoBlocks) {
    uint8_t digest[KCTSB_SHA256_DIGEST_SIZE];
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    kctsb_sha256(reinterpret_cast<const uint8_t*>(msg), strlen(msg), digest);

    const char* expected_hex =
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

TEST_F(HashTest, SHA256_Incremental) {
    kctsb_sha256_ctx_t ctx;
    uint8_t digest1[32], digest2[32];
    const char* msg = "The quick brown fox jumps over the lazy dog";

    // One-shot
    kctsb_sha256(reinterpret_cast<const uint8_t*>(msg), strlen(msg), digest1);

    // Incremental
    kctsb_sha256_init(&ctx);
    kctsb_sha256_update(&ctx, reinterpret_cast<const uint8_t*>(msg), 10);
    kctsb_sha256_update(&ctx, reinterpret_cast<const uint8_t*>(msg + 10), strlen(msg) - 10);
    kctsb_sha256_final(&ctx, digest2);

    EXPECT_EQ(memcmp(digest1, digest2, 32), 0);
}

// ============================================================================
// SHA-512 Tests (FIPS 180-4)
// ============================================================================

TEST_F(HashTest, SHA512_Empty) {
    uint8_t digest[KCTSB_SHA512_DIGEST_SIZE];
    kctsb_sha512(nullptr, 0, digest);

    const char* expected_hex =
        "cf83e1357eefb8bdf1542850d66d8007"
        "d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e";

    EXPECT_EQ(bytes_to_hex(digest, 64), expected_hex);
}

TEST_F(HashTest, SHA512_ABC) {
    uint8_t digest[KCTSB_SHA512_DIGEST_SIZE];
    const uint8_t msg[] = "abc";
    kctsb_sha512(msg, 3, digest);

    const char* expected_hex =
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f";

    EXPECT_EQ(bytes_to_hex(digest, 64), expected_hex);
}

// ============================================================================
// SHA-384 Tests
// ============================================================================

TEST_F(HashTest, SHA384_ABC) {
    uint8_t digest[KCTSB_SHA384_DIGEST_SIZE];
    const uint8_t msg[] = "abc";
    kctsb_sha384(msg, 3, digest);

    const char* expected_hex =
        "cb00753f45a35e8bb5a03d699ac65007"
        "272c32ab0eded1631a8b605a43ff5bed"
        "8086072ba1e7cc2358baeca134c825a7";

    EXPECT_EQ(bytes_to_hex(digest, 48), expected_hex);
}

// ============================================================================
// SHA3-256 Tests (FIPS 202)
// ============================================================================

TEST_F(HashTest, SHA3_256_Empty) {
    uint8_t digest[32];
    kctsb_sha3_256(nullptr, 0, digest);

    const char* expected_hex =
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

TEST_F(HashTest, SHA3_256_ABC) {
    uint8_t digest[32];
    const uint8_t msg[] = "abc";
    kctsb_sha3_256(msg, 3, digest);

    const char* expected_hex =
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

// ============================================================================
// SHA3-512 Tests (FIPS 202)
// ============================================================================

TEST_F(HashTest, SHA3_512_ABC) {
    uint8_t digest[64];
    const uint8_t msg[] = "abc";
    kctsb_sha3_512(msg, 3, digest);

    const char* expected_hex =
        "b751850b1a57168a5693cd924b6b096e"
        "08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e39340"
        "57340b4cf408d5a56592f8274eec53f0";

    EXPECT_EQ(bytes_to_hex(digest, 64), expected_hex);
}

// ============================================================================
// SHAKE128/256 Tests (FIPS 202 XOF)
// ============================================================================

TEST_F(HashTest, SHAKE128_Empty) {
    uint8_t output[32];
    kctsb_shake128(nullptr, 0, output, 32);

    // SHAKE128("", 256) first 32 bytes
    const char* expected_hex =
        "7f9c2ba4e88f827d616045507605853e"
        "d73b8093f6efbc88eb1a6eacfa66ef26";

    EXPECT_EQ(bytes_to_hex(output, 32), expected_hex);
}

TEST_F(HashTest, SHAKE256_ABC) {
    uint8_t output[64];
    const uint8_t msg[] = "abc";
    kctsb_shake256(msg, 3, output, 64);

    // SHAKE256("abc", 512)
    const char* expected_hex =
        "483366601360a8771c6863080cc4114d"
        "8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa"
        "9f8726e462a12a4feb06bd8801e751e4";

    EXPECT_EQ(bytes_to_hex(output, 64), expected_hex);
}

// ============================================================================
// BLAKE2b Tests (RFC 7693)
// ============================================================================

TEST_F(HashTest, BLAKE2b_Empty) {
    kctsb_blake2b_ctx_t ctx;
    uint8_t output[64];

    kctsb_blake2b_init(&ctx, 64);
    kctsb_blake2b_final(&ctx, output);

    // BLAKE2b-512 empty input
    const char* expected_hex =
        "786a02f742015903c6c6fd852552d272"
        "912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b"
        "903a685b1448b755d56f701afe9be2ce";

    EXPECT_EQ(bytes_to_hex(output, 64), expected_hex);
}

TEST_F(HashTest, BLAKE2b_ABC) {
    uint8_t output[64];
    const uint8_t input[] = "abc";

    kctsb_blake2b(input, 3, output, 64);

    // BLAKE2b-512("abc")
    const char* expected_hex =
        "ba80a53f981c4d0d6a2797b69f12f6e9"
        "4c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc95"
        "18d38aa8dbf1925ab92386edd4009923";

    EXPECT_EQ(bytes_to_hex(output, 64), expected_hex);
}

TEST_F(HashTest, BLAKE2b_256) {
    uint8_t output[32];
    const uint8_t input[] = "abc";

    kctsb_blake2b(input, 3, output, 32);

    // BLAKE2b-256("abc")
    const char* expected_hex =
        "bddd813c634239723171ef3fee98579b"
        "94964e3bb1cb3e427262c8c068d52319";

    EXPECT_EQ(bytes_to_hex(output, 32), expected_hex);
}

TEST_F(HashTest, BLAKE2b_Incremental) {
    kctsb_blake2b_ctx_t ctx;
    uint8_t digest1[64], digest2[64];
    const char* msg = "The quick brown fox jumps over the lazy dog";

    // One-shot
    kctsb_blake2b(reinterpret_cast<const uint8_t*>(msg), strlen(msg), digest1, 64);

    // Incremental
    kctsb_blake2b_init(&ctx, 64);
    kctsb_blake2b_update(&ctx, reinterpret_cast<const uint8_t*>(msg), 20);
    kctsb_blake2b_update(&ctx, reinterpret_cast<const uint8_t*>(msg + 20), strlen(msg) - 20);
    kctsb_blake2b_final(&ctx, digest2);

    EXPECT_EQ(memcmp(digest1, digest2, 64), 0);
}

// ============================================================================
// BLAKE2s Tests (RFC 7693)
// ============================================================================

TEST_F(HashTest, BLAKE2s_Empty) {
    kctsb_blake2s_ctx_t ctx;
    uint8_t output[32];

    kctsb_blake2s_init(&ctx, 32);
    kctsb_blake2s_final(&ctx, output);

    // BLAKE2s-256 empty input
    const char* expected_hex =
        "69217a3079908094e11121d042354a7c"
        "1f55b6482ca1a51e1b250dfd1ed0eef9";

    EXPECT_EQ(bytes_to_hex(output, 32), expected_hex);
}

TEST_F(HashTest, BLAKE2s_ABC) {
    uint8_t output[32];
    const uint8_t input[] = "abc";

    kctsb_blake2s(input, 3, output, 32);

    // BLAKE2s-256("abc")
    const char* expected_hex =
        "508c5e8c327c14e2e1a72ba34eeb452f"
        "37458b209ed63a294d999b4c86675982";

    EXPECT_EQ(bytes_to_hex(output, 32), expected_hex);
}

// ============================================================================
// SM3 Tests (GB/T 32905-2016)
// ============================================================================

TEST_F(HashTest, SM3_Empty) {
    uint8_t digest[32];
    kctsb_sm3(nullptr, 0, digest);

    // SM3("") - Chinese national standard test vector
    const char* expected_hex =
        "1ab21d8355cfa17f8e61194831e81a8f"
        "22bec8c728fefb747ed035eb5082aa2b";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

TEST_F(HashTest, SM3_ABC) {
    uint8_t digest[32];
    const uint8_t msg[] = "abc";
    kctsb_sm3(msg, 3, digest);

    // SM3("abc") - GB/T 32905-2016 Appendix A.1
    const char* expected_hex =
        "66c7f0f462eeedd9d1f2d46bdc10e4e2"
        "4167c4875cf2f7a2297da02b8f4ba8e0";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

TEST_F(HashTest, SM3_StandardVector) {
    uint8_t digest[32];
    // GB/T 32905-2016 Appendix A.2: "abcd" repeated 16 times (64 bytes)
    const char* msg = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    kctsb_sm3(reinterpret_cast<const uint8_t*>(msg), 64, digest);

    const char* expected_hex =
        "debe9ff92275b8a138604889c18e5a4d"
        "6fdb70e5387e5765293dcba39c0c5732";

    EXPECT_EQ(bytes_to_hex(digest, 32), expected_hex);
}

TEST_F(HashTest, SM3_Incremental) {
    kctsb_sm3_ctx_t ctx;
    uint8_t digest1[32], digest2[32];
    const char* msg = "The quick brown fox jumps over the lazy dog";

    // One-shot
    kctsb_sm3(reinterpret_cast<const uint8_t*>(msg), strlen(msg), digest1);

    // Incremental
    kctsb_sm3_init(&ctx);
    kctsb_sm3_update(&ctx, reinterpret_cast<const uint8_t*>(msg), 15);
    kctsb_sm3_update(&ctx, reinterpret_cast<const uint8_t*>(msg + 15), strlen(msg) - 15);
    kctsb_sm3_final(&ctx, digest2);

    EXPECT_EQ(memcmp(digest1, digest2, 32), 0);
}

TEST_F(HashTest, SM3_SelfTest) {
    // Built-in self-test using standard vector
    int result = kctsb_sm3_self_test();
    EXPECT_EQ(result, 0) << "SM3 self-test failed";
}

// ============================================================================
// Hash Consistency Tests
// ============================================================================

TEST_F(HashTest, Deterministic_SHA256) {
    uint8_t output1[32], output2[32];
    const uint8_t input[] = "deterministic test";

    kctsb_sha256(input, sizeof(input) - 1, output1);
    kctsb_sha256(input, sizeof(input) - 1, output2);

    EXPECT_EQ(memcmp(output1, output2, 32), 0)
        << "Same input should produce same output";
}

TEST_F(HashTest, Deterministic_SHA3) {
    uint8_t output1[32], output2[32];
    const uint8_t input[] = "deterministic test";

    kctsb_sha3_256(input, sizeof(input) - 1, output1);
    kctsb_sha3_256(input, sizeof(input) - 1, output2);

    EXPECT_EQ(memcmp(output1, output2, 32), 0)
        << "Same input should produce same output";
}

TEST_F(HashTest, Deterministic_BLAKE2b) {
    uint8_t output1[64], output2[64];
    const uint8_t input[] = "deterministic test";

    kctsb_blake2b(input, sizeof(input) - 1, output1, 64);
    kctsb_blake2b(input, sizeof(input) - 1, output2, 64);

    EXPECT_EQ(memcmp(output1, output2, 64), 0)
        << "Same input should produce same output";
}

TEST_F(HashTest, Deterministic_SM3) {
    uint8_t output1[32], output2[32];
    const uint8_t input[] = "deterministic test";

    kctsb_sm3(input, sizeof(input) - 1, output1);
    kctsb_sm3(input, sizeof(input) - 1, output2);

    EXPECT_EQ(memcmp(output1, output2, 32), 0)
        << "Same input should produce same output";
}

TEST_F(HashTest, AvalancheEffect_SHA256) {
    uint8_t output1[32], output2[32];
    uint8_t input1[] = "test input 1";
    uint8_t input2[] = "test input 2";  // Only last byte differs

    kctsb_sha256(input1, sizeof(input1) - 1, output1);
    kctsb_sha256(input2, sizeof(input2) - 1, output2);

    // Count differing bytes
    int diff_count = 0;
    for (int i = 0; i < 32; ++i) {
        if (output1[i] != output2[i]) diff_count++;
    }

    // Expect significant difference (avalanche effect)
    EXPECT_GT(diff_count, 16)
        << "Avalanche effect: small input change should cause large output change";
}

TEST_F(HashTest, AvalancheEffect_SHA3) {
    uint8_t output1[32], output2[32];
    uint8_t input1[] = "test input 1";
    uint8_t input2[] = "test input 2";

    kctsb_sha3_256(input1, sizeof(input1) - 1, output1);
    kctsb_sha3_256(input2, sizeof(input2) - 1, output2);

    int diff_count = 0;
    for (int i = 0; i < 32; ++i) {
        if (output1[i] != output2[i]) diff_count++;
    }

    EXPECT_GT(diff_count, 16)
        << "Avalanche effect: small input change should cause large output change";
}

// ============================================================================
// Cross-Algorithm Comparison Tests
// ============================================================================

TEST_F(HashTest, DifferentAlgorithms_ProduceDifferentOutputs) {
    const uint8_t input[] = "same input for all algorithms";
    const size_t input_len = sizeof(input) - 1;

    uint8_t sha256_out[32];
    uint8_t sha3_256_out[32];
    uint8_t blake2s_out[32];
    uint8_t sm3_out[32];

    kctsb_sha256(input, input_len, sha256_out);
    kctsb_sha3_256(input, input_len, sha3_256_out);
    kctsb_blake2s(input, input_len, blake2s_out, 32);
    kctsb_sm3(input, input_len, sm3_out);

    // All should produce different outputs
    EXPECT_NE(memcmp(sha256_out, sha3_256_out, 32), 0);
    EXPECT_NE(memcmp(sha256_out, blake2s_out, 32), 0);
    EXPECT_NE(memcmp(sha256_out, sm3_out, 32), 0);
    EXPECT_NE(memcmp(sha3_256_out, blake2s_out, 32), 0);
    EXPECT_NE(memcmp(sha3_256_out, sm3_out, 32), 0);
    EXPECT_NE(memcmp(blake2s_out, sm3_out, 32), 0);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST_F(HashTest, LargeInput) {
    std::vector<uint8_t> large_input(1024 * 1024);  // 1 MB
    for (size_t i = 0; i < large_input.size(); ++i) {
        large_input[i] = static_cast<uint8_t>(i & 0xFF);
    }

    uint8_t sha256_out[32];
    uint8_t sha3_out[32];
    uint8_t blake2b_out[64];
    uint8_t sm3_out[32];

    // Should not crash or hang
    kctsb_sha256(large_input.data(), large_input.size(), sha256_out);
    kctsb_sha3_256(large_input.data(), large_input.size(), sha3_out);
    kctsb_blake2b(large_input.data(), large_input.size(), blake2b_out, 64);
    kctsb_sm3(large_input.data(), large_input.size(), sm3_out);

    // Verify outputs are non-trivial
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (sha256_out[i] != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero) << "SHA-256 output should not be all zeros";
}

TEST_F(HashTest, SingleByteInputs) {
    uint8_t out1[32], out2[32];
    uint8_t byte1 = 0x00;
    uint8_t byte2 = 0x01;

    kctsb_sha256(&byte1, 1, out1);
    kctsb_sha256(&byte2, 1, out2);

    EXPECT_NE(memcmp(out1, out2, 32), 0)
        << "Different single-byte inputs should produce different outputs";
}
