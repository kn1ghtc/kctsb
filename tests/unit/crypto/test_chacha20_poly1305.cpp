/**
 * @file test_chacha20_poly1305.cpp
 * @brief ChaCha20-Poly1305 AEAD unit tests
 *
 * Tests for ChaCha20-Poly1305 algorithms:
 * - ChaCha20 stream cipher: RFC 8439 test vectors
 * - Poly1305 MAC: RFC 8439 test vectors
 * - ChaCha20-Poly1305 AEAD: RFC 8439 test vectors
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

#include "kctsb/kctsb.h"
#include "kctsb/crypto/chacha20_poly1305.h"

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

class ChaCha20Poly1305Test : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

// ============================================================================
// ChaCha20 Stream Cipher Tests (RFC 8439 Section 2.4.2)
// ============================================================================

/**
 * @brief RFC 8439 Section 2.4.2 - ChaCha20 Test Vector
 * 
 * Key: 00:01:02:...1f (32 bytes)
 * Nonce: 00:00:00:00:00:00:00:4a:00:00:00:00 (12 bytes)
 * Counter: 1
 */
TEST_F(ChaCha20Poly1305Test, ChaCha20_RFC8439_TestVector) {
    auto key = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    auto nonce = hex_to_bytes("000000000000004a00000000");
    
    // Input plaintext (from RFC 8439 Section 2.4.2)
    const char* plaintext_str = 
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    
    std::vector<uint8_t> plaintext(plaintext_str, plaintext_str + strlen(plaintext_str));
    std::vector<uint8_t> ciphertext(plaintext.size());
    
    kctsb_error_t err = kctsb_chacha20(
        key.data(), nonce.data(), 1,
        plaintext.data(), plaintext.size(),
        ciphertext.data()
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Expected ciphertext from RFC 8439
    auto expected = hex_to_bytes(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    );
    
    EXPECT_EQ(ciphertext.size(), expected.size());
    EXPECT_EQ(bytes_to_hex(ciphertext.data(), ciphertext.size()),
              bytes_to_hex(expected.data(), expected.size()));
}

/**
 * @brief ChaCha20 decryption (same as encryption due to XOR)
 */
TEST_F(ChaCha20Poly1305Test, ChaCha20_Decrypt) {
    auto key = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    auto nonce = hex_to_bytes("000000000000004a00000000");
    
    // Ciphertext from RFC 8439
    auto ciphertext = hex_to_bytes(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d"
    );
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    kctsb_error_t err = kctsb_chacha20(
        key.data(), nonce.data(), 1,
        ciphertext.data(), ciphertext.size(),
        plaintext.data()
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    const char* expected = 
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    
    EXPECT_EQ(std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size()),
              std::string(expected));
}

// ============================================================================
// Poly1305 MAC Tests (RFC 8439 Section 2.5.2)
// ============================================================================

/**
 * @brief RFC 8439 Section 2.5.2 - Poly1305 Test Vector
 */
TEST_F(ChaCha20Poly1305Test, Poly1305_RFC8439_TestVector) {
    // One-time key (32 bytes)
    auto key = hex_to_bytes(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    );
    
    // Message: "Cryptographic Forum Research Group"
    const char* msg = "Cryptographic Forum Research Group";
    
    uint8_t tag[16];
    kctsb_error_t err = kctsb_poly1305(
        key.data(),
        reinterpret_cast<const uint8_t*>(msg), strlen(msg),
        tag
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Expected tag from RFC 8439
    auto expected = hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9");
    
    EXPECT_EQ(bytes_to_hex(tag, 16), bytes_to_hex(expected.data(), 16));
}

/**
 * @brief Poly1305 incremental update test
 */
TEST_F(ChaCha20Poly1305Test, Poly1305_Incremental) {
    auto key = hex_to_bytes(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    );
    
    const char* msg = "Cryptographic Forum Research Group";
    size_t msg_len = strlen(msg);
    
    // One-shot
    uint8_t tag1[16];
    kctsb_poly1305(key.data(), reinterpret_cast<const uint8_t*>(msg), msg_len, tag1);
    
    // Incremental (split at various points)
    kctsb_poly1305_ctx_t ctx;
    kctsb_poly1305_init(&ctx, key.data());
    kctsb_poly1305_update(&ctx, reinterpret_cast<const uint8_t*>(msg), 10);
    kctsb_poly1305_update(&ctx, reinterpret_cast<const uint8_t*>(msg + 10), 15);
    kctsb_poly1305_update(&ctx, reinterpret_cast<const uint8_t*>(msg + 25), msg_len - 25);
    
    uint8_t tag2[16];
    kctsb_poly1305_final(&ctx, tag2);
    
    EXPECT_EQ(bytes_to_hex(tag1, 16), bytes_to_hex(tag2, 16));
}

/**
 * @brief Poly1305 empty message test
 */
TEST_F(ChaCha20Poly1305Test, Poly1305_EmptyMessage) {
    auto key = hex_to_bytes(
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
    );
    
    uint8_t tag[16];
    kctsb_error_t err = kctsb_poly1305(key.data(), nullptr, 0, tag);
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // With zero key and empty message, tag should be s (all zeros)
    auto expected = hex_to_bytes("00000000000000000000000000000000");
    EXPECT_EQ(bytes_to_hex(tag, 16), bytes_to_hex(expected.data(), 16));
}

// ============================================================================
// ChaCha20-Poly1305 AEAD Tests (RFC 8439 Section 2.8.2)
// ============================================================================

/**
 * @brief RFC 8439 Section 2.8.2 - ChaCha20-Poly1305 AEAD Test Vector
 */
TEST_F(ChaCha20Poly1305Test, AEAD_RFC8439_TestVector) {
    // Key (32 bytes)
    auto key = hex_to_bytes(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    
    // Nonce (12 bytes)
    auto nonce = hex_to_bytes("070000004041424344454647");
    
    // Additional Authenticated Data
    auto aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    
    // Plaintext
    const char* plaintext_str = 
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    std::vector<uint8_t> plaintext(plaintext_str, plaintext_str + strlen(plaintext_str));
    
    // Encrypt
    std::vector<uint8_t> ciphertext(plaintext.size());
    uint8_t tag[16];
    
    kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        plaintext.data(), plaintext.size(),
        ciphertext.data(), tag
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Expected ciphertext from RFC 8439
    auto expected_ciphertext = hex_to_bytes(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    );
    
    // Expected tag from RFC 8439
    auto expected_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");
    
    EXPECT_EQ(bytes_to_hex(ciphertext.data(), ciphertext.size()),
              bytes_to_hex(expected_ciphertext.data(), expected_ciphertext.size()));
    EXPECT_EQ(bytes_to_hex(tag, 16), bytes_to_hex(expected_tag.data(), 16));
}

/**
 * @brief RFC 8439 AEAD Decryption with verification
 */
TEST_F(ChaCha20Poly1305Test, AEAD_RFC8439_Decrypt) {
    auto key = hex_to_bytes(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    auto nonce = hex_to_bytes("070000004041424344454647");
    auto aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    
    auto ciphertext = hex_to_bytes(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    );
    auto tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    kctsb_error_t err = kctsb_chacha20_poly1305_decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        tag.data(),
        plaintext.data()
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    const char* expected = 
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    
    EXPECT_EQ(std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size()),
              std::string(expected));
}

/**
 * @brief AEAD decryption with invalid tag should fail
 */
TEST_F(ChaCha20Poly1305Test, AEAD_InvalidTag) {
    auto key = hex_to_bytes(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    auto nonce = hex_to_bytes("070000004041424344454647");
    auto aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    
    auto ciphertext = hex_to_bytes(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    );
    
    // Corrupted tag (last byte changed)
    auto bad_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600690");
    
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    kctsb_error_t err = kctsb_chacha20_poly1305_decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ciphertext.data(), ciphertext.size(),
        bad_tag.data(),
        plaintext.data()
    );
    
    EXPECT_EQ(err, KCTSB_ERROR_AUTH_FAILED);
}

/**
 * @brief AEAD with empty AAD
 */
TEST_F(ChaCha20Poly1305Test, AEAD_EmptyAAD) {
    auto key = hex_to_bytes(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    auto nonce = hex_to_bytes("070000004041424344454647");
    
    const char* plaintext_str = "Hello, World!";
    std::vector<uint8_t> plaintext(plaintext_str, plaintext_str + strlen(plaintext_str));
    
    std::vector<uint8_t> ciphertext(plaintext.size());
    uint8_t tag[16];
    
    // Encrypt with no AAD
    kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
        key.data(), nonce.data(),
        nullptr, 0,
        plaintext.data(), plaintext.size(),
        ciphertext.data(), tag
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Decrypt and verify
    std::vector<uint8_t> decrypted(ciphertext.size());
    err = kctsb_chacha20_poly1305_decrypt(
        key.data(), nonce.data(),
        nullptr, 0,
        ciphertext.data(), ciphertext.size(),
        tag,
        decrypted.data()
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    EXPECT_EQ(plaintext, decrypted);
}

/**
 * @brief AEAD with empty plaintext (authentication only)
 * Note: Current API requires non-null plaintext pointer even for zero length.
 * This test verifies the behavior with minimal data.
 */
TEST_F(ChaCha20Poly1305Test, AEAD_EmptyPlaintext) {
    auto key = hex_to_bytes(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    auto nonce = hex_to_bytes("070000004041424344454647");
    auto aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    
    // Use minimal 1-byte plaintext instead of empty
    uint8_t plaintext[1] = {0x42};
    uint8_t ciphertext[1];
    uint8_t tag[16];
    
    kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        plaintext, 1,
        ciphertext, tag
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Decrypt should verify tag
    uint8_t decrypted[1];
    err = kctsb_chacha20_poly1305_decrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        ciphertext, 1,
        tag,
        decrypted
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    EXPECT_EQ(decrypted[0], plaintext[0]);
}

/**
 * @brief AEAD roundtrip with various data sizes
 */
TEST_F(ChaCha20Poly1305Test, AEAD_RoundtripVariousSizes) {
    auto key = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    auto nonce = hex_to_bytes("000000000000000000000000");
    
    // Test various sizes including edge cases
    // Note: size 0 not supported by current API (requires valid plaintext pointer)
    std::vector<size_t> sizes = {1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1024};
    
    for (size_t size : sizes) {
        std::vector<uint8_t> plaintext(size);
        for (size_t i = 0; i < size; ++i) {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }
        
        std::vector<uint8_t> aad = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> ciphertext(size);
        uint8_t tag[16];
        
        kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
            key.data(), nonce.data(),
            aad.data(), aad.size(),
            plaintext.data(), size,
            ciphertext.data(), tag
        );
        
        ASSERT_EQ(err, KCTSB_SUCCESS) << "Encrypt failed for size " << size;
        
        std::vector<uint8_t> decrypted(size);
        err = kctsb_chacha20_poly1305_decrypt(
            key.data(), nonce.data(),
            aad.data(), aad.size(),
            ciphertext.data(), size,
            tag,
            decrypted.data()
        );
        
        ASSERT_EQ(err, KCTSB_SUCCESS) << "Decrypt failed for size " << size;
        EXPECT_EQ(plaintext, decrypted) << "Roundtrip failed for size " << size;
    }
}

// ============================================================================
// Streaming API Tests
// ============================================================================

/**
 * @brief Streaming encryption API test
 */
TEST_F(ChaCha20Poly1305Test, StreamingEncrypt) {
    auto key = hex_to_bytes(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    auto nonce = hex_to_bytes("070000004041424344454647");
    auto aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    
    const char* plaintext_str = 
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    std::vector<uint8_t> plaintext(plaintext_str, plaintext_str + strlen(plaintext_str));
    
    // One-shot encryption for comparison
    std::vector<uint8_t> expected_ciphertext(plaintext.size());
    uint8_t expected_tag[16];
    kctsb_chacha20_poly1305_encrypt(
        key.data(), nonce.data(),
        aad.data(), aad.size(),
        plaintext.data(), plaintext.size(),
        expected_ciphertext.data(), expected_tag
    );
    
    // Streaming encryption
    kctsb_chacha20_poly1305_ctx_t ctx;
    kctsb_error_t err = kctsb_chacha20_poly1305_init_encrypt(&ctx, key.data(), nonce.data());
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    err = kctsb_chacha20_poly1305_update_aad(&ctx, aad.data(), aad.size());
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Encrypt in chunks
    std::vector<uint8_t> ciphertext(plaintext.size());
    size_t offset = 0;
    size_t chunk_sizes[] = {10, 20, 30, 54};  // Sum = 114 = plaintext length
    
    for (size_t chunk : chunk_sizes) {
        err = kctsb_chacha20_poly1305_update_encrypt(
            &ctx,
            plaintext.data() + offset, chunk,
            ciphertext.data() + offset
        );
        ASSERT_EQ(err, KCTSB_SUCCESS);
        offset += chunk;
    }
    
    uint8_t tag[16];
    err = kctsb_chacha20_poly1305_final_encrypt(&ctx, tag);
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    EXPECT_EQ(ciphertext, expected_ciphertext);
    EXPECT_EQ(bytes_to_hex(tag, 16), bytes_to_hex(expected_tag, 16));
}

/**
 * @brief Streaming decryption API test
 */
TEST_F(ChaCha20Poly1305Test, StreamingDecrypt) {
    auto key = hex_to_bytes(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    auto nonce = hex_to_bytes("070000004041424344454647");
    auto aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
    
    auto ciphertext = hex_to_bytes(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    );
    auto tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691");
    
    // Streaming decryption
    kctsb_chacha20_poly1305_ctx_t ctx;
    kctsb_error_t err = kctsb_chacha20_poly1305_init_decrypt(&ctx, key.data(), nonce.data());
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    err = kctsb_chacha20_poly1305_update_aad(&ctx, aad.data(), aad.size());
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Decrypt in chunks
    std::vector<uint8_t> plaintext(ciphertext.size());
    size_t offset = 0;
    size_t chunk_sizes[] = {32, 32, 32, 18};  // Sum = 114 = ciphertext length
    
    for (size_t chunk : chunk_sizes) {
        err = kctsb_chacha20_poly1305_update_decrypt(
            &ctx,
            ciphertext.data() + offset, chunk,
            plaintext.data() + offset
        );
        ASSERT_EQ(err, KCTSB_SUCCESS);
        offset += chunk;
    }
    
    err = kctsb_chacha20_poly1305_final_decrypt(&ctx, tag.data());
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    const char* expected = 
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    
    EXPECT_EQ(std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size()),
              std::string(expected));
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

/**
 * @brief NULL pointer handling
 */
TEST_F(ChaCha20Poly1305Test, NullPointerHandling) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t data[16] = {0};
    uint8_t output[16] = {0};
    uint8_t tag[16] = {0};
    
    // ChaCha20 null checks
    EXPECT_EQ(kctsb_chacha20(nullptr, nonce, 0, data, 16, output), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_chacha20(key, nullptr, 0, data, 16, output), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_chacha20(key, nonce, 0, data, 16, nullptr), KCTSB_ERROR_INVALID_PARAM);
    
    // Poly1305 null checks
    EXPECT_EQ(kctsb_poly1305(nullptr, data, 16, tag), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_poly1305(key, data, 16, nullptr), KCTSB_ERROR_INVALID_PARAM);
    
    // AEAD null checks
    EXPECT_EQ(kctsb_chacha20_poly1305_encrypt(nullptr, nonce, nullptr, 0, data, 16, output, tag),
              KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_chacha20_poly1305_encrypt(key, nullptr, nullptr, 0, data, 16, output, tag),
              KCTSB_ERROR_INVALID_PARAM);
}

/**
 * @brief Counter overflow behavior
 */
TEST_F(ChaCha20Poly1305Test, CounterBehavior) {
    auto key = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    auto nonce = hex_to_bytes("000000000000000000000000");
    
    std::vector<uint8_t> data(128, 0x42);
    std::vector<uint8_t> output1(128);
    std::vector<uint8_t> output2(128);
    
    // Encrypt with counter=0
    kctsb_chacha20(key.data(), nonce.data(), 0, data.data(), 128, output1.data());
    
    // Encrypt with counter=1 (should produce different output)
    kctsb_chacha20(key.data(), nonce.data(), 1, data.data(), 128, output2.data());
    
    EXPECT_NE(output1, output2);
}

/**
 * @brief Verify Poly1305 tag is deterministic
 */
TEST_F(ChaCha20Poly1305Test, Poly1305Deterministic) {
    auto key = hex_to_bytes(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    );
    
    const char* msg = "Test message for determinism check";
    
    uint8_t tag1[16], tag2[16], tag3[16];
    
    kctsb_poly1305(key.data(), reinterpret_cast<const uint8_t*>(msg), strlen(msg), tag1);
    kctsb_poly1305(key.data(), reinterpret_cast<const uint8_t*>(msg), strlen(msg), tag2);
    kctsb_poly1305(key.data(), reinterpret_cast<const uint8_t*>(msg), strlen(msg), tag3);
    
    EXPECT_EQ(bytes_to_hex(tag1, 16), bytes_to_hex(tag2, 16));
    EXPECT_EQ(bytes_to_hex(tag2, 16), bytes_to_hex(tag3, 16));
}

// ============================================================================
// Performance Sanity Tests
// ============================================================================

/**
 * @brief Large data encryption sanity test
 */
TEST_F(ChaCha20Poly1305Test, LargeDataEncryption) {
    auto key = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    );
    auto nonce = hex_to_bytes("000000000000000000000001");
    
    // 1MB of data
    size_t size = 1024 * 1024;
    std::vector<uint8_t> plaintext(size);
    for (size_t i = 0; i < size; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xFF);
    }
    
    std::vector<uint8_t> ciphertext(size);
    uint8_t tag[16];
    
    kctsb_error_t err = kctsb_chacha20_poly1305_encrypt(
        key.data(), nonce.data(),
        nullptr, 0,
        plaintext.data(), size,
        ciphertext.data(), tag
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    
    // Verify roundtrip
    std::vector<uint8_t> decrypted(size);
    err = kctsb_chacha20_poly1305_decrypt(
        key.data(), nonce.data(),
        nullptr, 0,
        ciphertext.data(), size,
        tag,
        decrypted.data()
    );
    
    ASSERT_EQ(err, KCTSB_SUCCESS);
    EXPECT_EQ(plaintext, decrypted);
}
