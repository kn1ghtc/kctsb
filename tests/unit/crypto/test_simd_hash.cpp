/**
 * @file test_simd_hash.cpp
 * @brief Unit tests for SIMD-optimized hash functions
 *
 * Tests for SHA-NI accelerated SHA-256 and AVX2 optimized Keccak/SHA3
 * implementations. Validates correctness against NIST test vectors and
 * verifies SIMD vs scalar consistency.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

#include "kctsb/kctsb.h"
#include "kctsb/simd/simd.h"
#include "kctsb/crypto/sha256.h"
#include "kctsb/crypto/sha512.h"
#include "kctsb/crypto/sha3.h"

// Forward declarations for SIMD-optimized functions
extern "C" {
    // SHA-NI functions (if available)
    #if defined(KCTSB_HAS_SHANI)
    void sha256_transform_shani(uint32_t state[8], const uint8_t data[64]);
    void kctsb_sha256_shani(const uint8_t* data, size_t len, uint8_t* digest);
    bool kctsb_sha256_shani_available(void);
    #endif

    // AVX2 Keccak functions (if available)
    #if defined(KCTSB_HAS_AVX2)
    void keccak_f1600_avx2(uint64_t state[25]);
    void kctsb_sha3_256_avx2(const uint8_t* data, size_t len, uint8_t* digest);
    bool kctsb_sha3_256_avx2_available(void);
    #endif
}

// Helper: Convert bytes to hex string
static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string hex;
    char buf[3];
    for (size_t i = 0; i < len; ++i) {
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex += buf;
    }
    return hex;
}

// ============================================================================
// SHA-256 SIMD Tests
// ============================================================================

class SHA256SIMDTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

/**
 * @brief Test SHA-256 SIMD vs scalar consistency
 *
 * Ensures SIMD implementation produces identical results to scalar
 */
TEST_F(SHA256SIMDTest, SIMDScalarConsistency) {
    // Test data of various sizes
    const std::vector<size_t> sizes = {0, 1, 55, 56, 64, 100, 1000, 4096};

    for (size_t size : sizes) {
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i * 17);
        }

        uint8_t scalar_digest[32];
        uint8_t simd_digest[32];

        // Compute with scalar implementation
        kctsb_sha256(data.data(), size, scalar_digest);

#if defined(KCTSB_HAS_SHANI)
        // If SHA-NI available, test it
        if (kctsb_sha256_shani_available()) {
            kctsb_sha256_shani(data.data(), size, simd_digest);
            EXPECT_EQ(memcmp(scalar_digest, simd_digest, 32), 0)
                << "SHA-256 SIMD/scalar mismatch for size " << size;
        }
#endif
    }
}

/**
 * @brief Test SHA-256 empty string
 */
TEST_F(SHA256SIMDTest, EmptyString) {
    uint8_t digest[32];
    kctsb_sha256((const uint8_t*)"", 0, digest);

    // NIST FIPS 180-4 test vector
    EXPECT_EQ(bytes_to_hex(digest, 32),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

/**
 * @brief Test SHA-256 "abc" vector
 */
TEST_F(SHA256SIMDTest, ABC) {
    uint8_t digest[32];
    kctsb_sha256((const uint8_t*)"abc", 3, digest);

    EXPECT_EQ(bytes_to_hex(digest, 32),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

/**
 * @brief Test SHA-256 with 56-byte message (padding boundary)
 */
TEST_F(SHA256SIMDTest, PaddingBoundary56) {
    // 56-byte message is exactly at padding boundary
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t digest[32];

    kctsb_sha256((const uint8_t*)msg, 56, digest);

    EXPECT_EQ(bytes_to_hex(digest, 32),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

/**
 * @brief Test SHA-256 with 1 million 'a' characters
 */
TEST_F(SHA256SIMDTest, MillionAs) {
    kctsb_sha256_ctx_t ctx;
    uint8_t digest[32];
    uint8_t block[1000];

    memset(block, 'a', sizeof(block));
    kctsb_sha256_init(&ctx);
    for (int i = 0; i < 1000; i++) {
        kctsb_sha256_update(&ctx, block, sizeof(block));
    }
    kctsb_sha256_final(&ctx, digest);

    EXPECT_EQ(bytes_to_hex(digest, 32),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// ============================================================================
// SHA3-256 (Keccak) SIMD Tests
// ============================================================================

class SHA3SIMDTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

/**
 * @brief Test SHA3-256 SIMD vs scalar consistency
 */
TEST_F(SHA3SIMDTest, SIMDScalarConsistency) {
    const std::vector<size_t> sizes = {0, 1, 135, 136, 200, 1000, 4096};

    for (size_t size : sizes) {
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(i * 23);
        }

        uint8_t scalar_digest[32];
        uint8_t simd_digest[32];

        // Use empty string for size=0 to avoid null pointer
        const uint8_t* data_ptr = (size == 0) ? reinterpret_cast<const uint8_t*>("") : data.data();

        // Compute with scalar implementation
        FIPS202_SHA3_256(data_ptr, size, scalar_digest);

#if defined(KCTSB_HAS_AVX2)
        // If AVX2 available, test it
        if (kctsb_sha3_256_avx2_available()) {
            kctsb_sha3_256_avx2(data_ptr, size, simd_digest);
            EXPECT_EQ(memcmp(scalar_digest, simd_digest, 32), 0)
                << "SHA3-256 SIMD/scalar mismatch for size " << size;
        }
#endif
    }
}

/**
 * @brief Test SHA3-256 empty input
 */
TEST_F(SHA3SIMDTest, Empty) {
    uint8_t digest[32];
    FIPS202_SHA3_256((const uint8_t*)"", 0, digest);

    // NIST FIPS 202 test vector
    EXPECT_EQ(bytes_to_hex(digest, 32),
              "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

/**
 * @brief Test SHA3-256 "abc" vector
 */
TEST_F(SHA3SIMDTest, ABC) {
    uint8_t digest[32];
    FIPS202_SHA3_256((const uint8_t*)"abc", 3, digest);

    // NIST FIPS 202 test vector
    EXPECT_EQ(bytes_to_hex(digest, 32),
              "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

/**
 * @brief Test SHA3-256 at rate boundary (136 bytes for SHA3-256)
 */
TEST_F(SHA3SIMDTest, RateBoundary136) {
    // SHA3-256 rate is 136 bytes (1088 bits)
    std::vector<uint8_t> data(136, 'a');
    uint8_t digest[32];

    FIPS202_SHA3_256(data.data(), data.size(), digest);

    // Verify output is not all zeros
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (digest[i] != 0) all_zero = false;
    }
    EXPECT_FALSE(all_zero);
}

/**
 * @brief Test SHA3-256 longer message
 */
TEST_F(SHA3SIMDTest, LongMessage) {
    // 448-bit message
    const char* msg = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd";
    uint8_t digest[32];

    FIPS202_SHA3_256((const uint8_t*)msg, strlen(msg), digest);

    // Verify deterministic output
    uint8_t digest2[32];
    FIPS202_SHA3_256((const uint8_t*)msg, strlen(msg), digest2);
    EXPECT_EQ(memcmp(digest, digest2, 32), 0);
}

// ============================================================================
// AES-NI Integration Tests
// ============================================================================

class AESNIIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

/**
 * @brief Test AES-128 with AES-NI acceleration
 */
TEST_F(AESNIIntegrationTest, AES128_AESNI) {
    // NIST FIPS 197 test vector
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    uint8_t expected[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };

    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);

    uint8_t ciphertext[16];
    ASSERT_EQ(kctsb_aes_encrypt_block(&ctx, plaintext, ciphertext), KCTSB_SUCCESS);

    // Verify encryption result
    EXPECT_EQ(memcmp(ciphertext, expected, 16), 0)
        << "AES-128 encryption mismatch (may use AES-NI)";

    // Test decryption roundtrip
    uint8_t decrypted[16];
    ASSERT_EQ(kctsb_aes_decrypt_block(&ctx, ciphertext, decrypted), KCTSB_SUCCESS);

    EXPECT_EQ(memcmp(decrypted, plaintext, 16), 0)
        << "AES-128 decryption roundtrip failed";

    kctsb_aes_clear(&ctx);
}

/**
 * @brief Test AES-GCM with AES-NI acceleration
 */
TEST_F(AESNIIntegrationTest, AES128_GCM_AESNI) {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };

    uint8_t aad[] = "Additional authenticated data";

    uint8_t plaintext[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };

    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);

    uint8_t ciphertext[32];
    uint8_t tag[16];
    ASSERT_EQ(kctsb_aes_gcm_encrypt(&ctx, iv, 12, aad, sizeof(aad)-1,
                                     plaintext, 32, ciphertext, tag), KCTSB_SUCCESS);

    // Verify decryption with authentication
    uint8_t decrypted[32];
    ASSERT_EQ(kctsb_aes_gcm_decrypt(&ctx, iv, 12, aad, sizeof(aad)-1,
                                     ciphertext, 32, tag, decrypted), KCTSB_SUCCESS);

    EXPECT_EQ(memcmp(decrypted, plaintext, 32), 0)
        << "AES-128-GCM roundtrip failed (may use AES-NI)";

    kctsb_aes_clear(&ctx);
}

/**
 * @brief Test AES-CTR with AES-NI acceleration
 */
TEST_F(AESNIIntegrationTest, AES128_CTR_AESNI) {
    uint8_t key[16] = {0};
    uint8_t nonce[12] = {0};

    // Generate test data
    std::vector<uint8_t> plaintext(1024);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i);
    }

    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);

    std::vector<uint8_t> ciphertext(1024);
    ASSERT_EQ(kctsb_aes_ctr_crypt(&ctx, nonce, plaintext.data(), 1024, ciphertext.data()),
              KCTSB_SUCCESS);

    // CTR mode: encrypt again to decrypt
    std::vector<uint8_t> decrypted(1024);
    ASSERT_EQ(kctsb_aes_ctr_crypt(&ctx, nonce, ciphertext.data(), 1024, decrypted.data()),
              KCTSB_SUCCESS);

    EXPECT_EQ(memcmp(decrypted.data(), plaintext.data(), 1024), 0)
        << "AES-128-CTR roundtrip failed (may use AES-NI)";

    kctsb_aes_clear(&ctx);
}

// ============================================================================
// SIMD Feature Detection Tests
// ============================================================================

TEST(SIMDFeatureTest, FeatureDetection) {
    using namespace kctsb::simd;

    // Just verify detection doesn't crash
    uint32_t features = detect_features();

    // Log available features
    const char* info = get_simd_info();
    ASSERT_NE(info, nullptr);

    // If AVX2 is available, SSE2 must also be available
    if (features & static_cast<uint32_t>(SIMDFeature::AVX2)) {
        EXPECT_TRUE(has_feature(SIMDFeature::SSE2));
    }

    // Check AES-NI availability
    bool aesni = has_aesni();
    // Just log, don't fail - not all CPUs have AES-NI
    if (aesni) {
        std::cout << "AES-NI: Available" << std::endl;
    } else {
        std::cout << "AES-NI: Not available" << std::endl;
    }
}
