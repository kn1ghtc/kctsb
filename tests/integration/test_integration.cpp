/**
 * @file test_integration.cpp
 * @brief Integration tests for kctsb cryptographic library
 *
 * Tests cross-module interactions and real-world usage scenarios:
 * - Library lifecycle (init/cleanup)
 * - AES-GCM encrypt-then-decrypt workflow
 * - Hash chaining and verification
 * - Key generation and cryptographic operations
 * - Error handling and edge cases
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <string>

#include "kctsb/kctsb.h"

// ============================================================================
// Library Lifecycle Tests
// ============================================================================

TEST(IntegrationTest, LibraryInitialization) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    const char* version = kctsb_version();
    EXPECT_NE(version, nullptr);
    EXPECT_STREQ(version, "3.4.0");

    const char* platform = kctsb_platform();
    EXPECT_NE(platform, nullptr);

    kctsb_cleanup();
}

TEST(IntegrationTest, MultipleInitCleanup) {
    // Should handle multiple init/cleanup cycles
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);
        kctsb_cleanup();
    }
}

// ============================================================================
// Secure Random Integration Tests
// ============================================================================

TEST(IntegrationTest, SecureRandom) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    uint8_t buffer[32];
    // kctsb_random_bytes returns int: 0 = success
    EXPECT_EQ(kctsb_random_bytes(buffer, 32), 0);

    // Check that random bytes are not all zero
    bool all_zero = true;
    for (int i = 0; i < 32; i++) {
        if (buffer[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);

    kctsb_cleanup();
}

TEST(IntegrationTest, SecureCompare) {
    uint8_t a[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t b[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t c[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11};

    // kctsb_secure_compare returns 1 if equal (true), 0 if different (false)
    // This is opposite to memcmp but more intuitive for boolean comparison
    EXPECT_EQ(kctsb_secure_compare(a, b, 16), 1);  // Equal -> returns 1 (true)
    EXPECT_EQ(kctsb_secure_compare(a, c, 16), 0);  // Different -> returns 0 (false)
}

TEST(IntegrationTest, ErrorStrings) {
    EXPECT_STREQ(kctsb_error_string(KCTSB_SUCCESS), "Success");
    EXPECT_STREQ(kctsb_error_string(KCTSB_ERROR_INVALID_PARAM), "Invalid parameter");
    EXPECT_STREQ(kctsb_error_string(KCTSB_ERROR_INVALID_KEY), "Invalid key");
}

// ============================================================================
// AES-GCM Encrypt/Decrypt Workflow Tests (using one-shot API)
// ============================================================================

TEST(IntegrationTest, AES256GCM_EncryptDecrypt) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    // Generate random key and IV
    uint8_t key[32];
    uint8_t iv[12];
    kctsb_random_bytes(key, sizeof(key));
    kctsb_random_bytes(iv, sizeof(iv));

    // Test message
    const char* message = "This is a secret message for AES-256-GCM encryption test!";
    size_t msg_len = strlen(message);

    // Additional authenticated data
    const uint8_t aad[] = "header data";
    size_t aad_len = sizeof(aad) - 1;

    // Initialize AES context
    kctsb_aes_ctx_t aes_ctx;
    EXPECT_EQ(kctsb_aes_init(&aes_ctx, key, 32), KCTSB_SUCCESS);

    // Encrypt using one-shot API
    std::vector<uint8_t> ciphertext(msg_len);
    uint8_t tag[16];

    EXPECT_EQ(kctsb_aes_gcm_encrypt(
        &aes_ctx,
        iv, 12,
        aad, aad_len,
        reinterpret_cast<const uint8_t*>(message), msg_len,
        ciphertext.data(),
        tag
    ), KCTSB_SUCCESS);

    // Decrypt using one-shot API
    std::vector<uint8_t> plaintext(msg_len);

    EXPECT_EQ(kctsb_aes_gcm_decrypt(
        &aes_ctx,
        iv, 12,
        aad, aad_len,
        ciphertext.data(), msg_len,
        tag,
        plaintext.data()
    ), KCTSB_SUCCESS);

    // Verify decrypted message
    EXPECT_EQ(memcmp(plaintext.data(), message, msg_len), 0);

    kctsb_aes_clear(&aes_ctx);
    kctsb_cleanup();
}

TEST(IntegrationTest, AES256GCM_TamperedCiphertext) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    uint8_t key[32];
    uint8_t iv[12];
    kctsb_random_bytes(key, sizeof(key));
    kctsb_random_bytes(iv, sizeof(iv));

    const char* message = "Secret message";
    size_t msg_len = strlen(message);

    // Initialize AES context
    kctsb_aes_ctx_t aes_ctx;
    kctsb_aes_init(&aes_ctx, key, 32);

    // Encrypt
    std::vector<uint8_t> ciphertext(msg_len);
    uint8_t tag[16];

    kctsb_aes_gcm_encrypt(&aes_ctx, iv, 12, nullptr, 0,
                          reinterpret_cast<const uint8_t*>(message), msg_len,
                          ciphertext.data(), tag);

    // Tamper with ciphertext
    ciphertext[0] ^= 0x01;

    // Decrypt should fail authentication
    std::vector<uint8_t> plaintext(msg_len);

    kctsb_error_t result = kctsb_aes_gcm_decrypt(
        &aes_ctx, iv, 12, nullptr, 0,
        ciphertext.data(), msg_len, tag, plaintext.data());

    EXPECT_NE(result, KCTSB_SUCCESS) << "Tampered ciphertext should fail authentication";

    kctsb_aes_clear(&aes_ctx);
    kctsb_cleanup();
}

TEST(IntegrationTest, AES256GCM_StreamingAPI) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    uint8_t key[32];
    uint8_t iv[12];
    kctsb_random_bytes(key, sizeof(key));
    kctsb_random_bytes(iv, sizeof(iv));

    const char* message = "Streaming encryption test message for AES-GCM!";
    size_t msg_len = strlen(message);
    const uint8_t aad[] = "associated data";

    // Streaming Encrypt
    kctsb_aes_gcm_ctx_t enc_ctx;
    EXPECT_EQ(kctsb_aes_gcm_init(&enc_ctx, key, 32, iv, 12), KCTSB_SUCCESS);
    EXPECT_EQ(kctsb_aes_gcm_update_aad(&enc_ctx, aad, sizeof(aad) - 1), KCTSB_SUCCESS);

    std::vector<uint8_t> ciphertext(msg_len);
    EXPECT_EQ(kctsb_aes_gcm_update_encrypt(&enc_ctx,
        reinterpret_cast<const uint8_t*>(message), msg_len,
        ciphertext.data()), KCTSB_SUCCESS);

    uint8_t tag[16];
    EXPECT_EQ(kctsb_aes_gcm_final_encrypt(&enc_ctx, tag), KCTSB_SUCCESS);

    // Streaming Decrypt
    kctsb_aes_gcm_ctx_t dec_ctx;
    EXPECT_EQ(kctsb_aes_gcm_init(&dec_ctx, key, 32, iv, 12), KCTSB_SUCCESS);
    EXPECT_EQ(kctsb_aes_gcm_update_aad(&dec_ctx, aad, sizeof(aad) - 1), KCTSB_SUCCESS);

    std::vector<uint8_t> plaintext(msg_len);
    EXPECT_EQ(kctsb_aes_gcm_update_decrypt(&dec_ctx,
        ciphertext.data(), msg_len, plaintext.data()), KCTSB_SUCCESS);

    EXPECT_EQ(kctsb_aes_gcm_final_decrypt(&dec_ctx, tag), KCTSB_SUCCESS);

    // Verify
    EXPECT_EQ(memcmp(plaintext.data(), message, msg_len), 0);

    kctsb_aes_gcm_clear(&enc_ctx);
    kctsb_aes_gcm_clear(&dec_ctx);
    kctsb_cleanup();
}

// ============================================================================
// Hash Chaining Tests (SHA functions return void)
// ============================================================================

TEST(IntegrationTest, HashChaining_SHA256) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    // Hash a message
    const uint8_t msg1[] = "First message";
    uint8_t hash1[32];
    kctsb_sha256(msg1, sizeof(msg1) - 1, hash1);

    // Hash the hash (chaining)
    uint8_t hash2[32];
    kctsb_sha256(hash1, 32, hash2);

    // Verify different from original
    EXPECT_NE(memcmp(hash1, hash2, 32), 0);

    // Verify deterministic
    uint8_t hash2_repeat[32];
    kctsb_sha256(hash1, 32, hash2_repeat);
    EXPECT_EQ(memcmp(hash2, hash2_repeat, 32), 0);

    kctsb_cleanup();
}

TEST(IntegrationTest, HashVerification_SM3) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    // Create a "password" hash
    const uint8_t password[] = "MySecretPassword123!";
    uint8_t stored_hash[32];
    kctsb_sm3(password, sizeof(password) - 1, stored_hash);

    // Verify correct password
    uint8_t verify_hash[32];
    kctsb_sm3(password, sizeof(password) - 1, verify_hash);
    EXPECT_EQ(kctsb_secure_compare(stored_hash, verify_hash, 32), 1);

    // Verify wrong password fails
    const uint8_t wrong_password[] = "WrongPassword!";
    kctsb_sm3(wrong_password, sizeof(wrong_password) - 1, verify_hash);
    EXPECT_EQ(kctsb_secure_compare(stored_hash, verify_hash, 32), 0);

    kctsb_cleanup();
}

// ============================================================================
// SM4-GCM Integration Tests
// ============================================================================

TEST(IntegrationTest, SM4GCM_EncryptDecrypt) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    uint8_t key[16];
    uint8_t iv[12];
    kctsb_random_bytes(key, sizeof(key));
    kctsb_random_bytes(iv, sizeof(iv));

    const char* message = "SM4-GCM test message for Chinese national standard cipher!";
    size_t msg_len = strlen(message);
    const uint8_t aad[] = "additional data";

    // Encrypt
    kctsb_sm4_gcm_ctx_t enc_ctx;
    EXPECT_EQ(kctsb_sm4_gcm_init(&enc_ctx, key, iv), KCTSB_SUCCESS);

    std::vector<uint8_t> ciphertext(msg_len);
    uint8_t tag[16];
    EXPECT_EQ(kctsb_sm4_gcm_encrypt(&enc_ctx,
        aad, sizeof(aad) - 1,
        reinterpret_cast<const uint8_t*>(message), msg_len,
        ciphertext.data(), tag), KCTSB_SUCCESS);

    // Decrypt
    kctsb_sm4_gcm_ctx_t dec_ctx;
    EXPECT_EQ(kctsb_sm4_gcm_init(&dec_ctx, key, iv), KCTSB_SUCCESS);

    std::vector<uint8_t> plaintext(msg_len);
    EXPECT_EQ(kctsb_sm4_gcm_decrypt(&dec_ctx,
        aad, sizeof(aad) - 1,
        ciphertext.data(), msg_len,
        tag,
        plaintext.data()), KCTSB_SUCCESS);

    EXPECT_EQ(memcmp(plaintext.data(), message, msg_len), 0);

    kctsb_cleanup();
}

// ============================================================================
// ChaCha20-Poly1305 Integration Tests
// ============================================================================

TEST(IntegrationTest, ChaCha20Poly1305_EncryptDecrypt) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    uint8_t key[32];
    uint8_t nonce[12];
    kctsb_random_bytes(key, sizeof(key));
    kctsb_random_bytes(nonce, sizeof(nonce));

    const char* message = "ChaCha20-Poly1305 AEAD test message!";
    size_t msg_len = strlen(message);
    const uint8_t aad[] = "Additional data";

    // Encrypt
    std::vector<uint8_t> ciphertext(msg_len);
    uint8_t tag[16];

    EXPECT_EQ(kctsb_chacha20_poly1305_encrypt(
        key, nonce,
        aad, sizeof(aad) - 1,
        reinterpret_cast<const uint8_t*>(message), msg_len,
        ciphertext.data(), tag
    ), KCTSB_SUCCESS);

    // Decrypt
    std::vector<uint8_t> plaintext(msg_len);

    EXPECT_EQ(kctsb_chacha20_poly1305_decrypt(
        key, nonce,
        aad, sizeof(aad) - 1,
        ciphertext.data(), msg_len,
        tag,
        plaintext.data()
    ), KCTSB_SUCCESS);

    EXPECT_EQ(memcmp(plaintext.data(), message, msg_len), 0);

    kctsb_cleanup();
}

// ============================================================================
// HMAC Integration Tests (HMAC functions return void)
// ============================================================================

TEST(IntegrationTest, HMAC_MessageAuthentication) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    // Simulate message authentication workflow
    uint8_t key[32];
    kctsb_random_bytes(key, sizeof(key));

    const char* message = "Important message to authenticate";
    size_t msg_len = strlen(message);

    // Generate MAC (void return)
    uint8_t mac[32];
    kctsb_hmac_sha256(key, 32,
        reinterpret_cast<const uint8_t*>(message), msg_len, mac);

    // Verify MAC
    uint8_t verify_mac[32];
    kctsb_hmac_sha256(key, 32,
        reinterpret_cast<const uint8_t*>(message), msg_len, verify_mac);

    EXPECT_EQ(kctsb_secure_compare(mac, verify_mac, 32), 1);

    // Modified message should produce different MAC
    char modified_message[64];
    strcpy(modified_message, message);
    modified_message[0] = 'X';  // Modify first character

    kctsb_hmac_sha256(key, 32,
        reinterpret_cast<const uint8_t*>(modified_message), msg_len, verify_mac);

    EXPECT_EQ(kctsb_secure_compare(mac, verify_mac, 32), 0);

    kctsb_cleanup();
}

// ============================================================================
// Cross-Algorithm Tests
// ============================================================================

TEST(IntegrationTest, KeyDerivation_HashThenEncrypt) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    // Derive key from password using SHA-256
    const char* password = "user_password_123";
    uint8_t derived_key[32];
    kctsb_sha256(reinterpret_cast<const uint8_t*>(password), strlen(password), derived_key);

    // Use derived key for AES encryption
    uint8_t iv[12];
    kctsb_random_bytes(iv, sizeof(iv));

    const char* secret = "Secret data to protect";
    size_t secret_len = strlen(secret);

    // Initialize AES context
    kctsb_aes_ctx_t aes_ctx;
    EXPECT_EQ(kctsb_aes_init(&aes_ctx, derived_key, 32), KCTSB_SUCCESS);

    std::vector<uint8_t> ciphertext(secret_len);
    uint8_t tag[16];
    EXPECT_EQ(kctsb_aes_gcm_encrypt(&aes_ctx,
        iv, 12, nullptr, 0,
        reinterpret_cast<const uint8_t*>(secret), secret_len,
        ciphertext.data(), tag), KCTSB_SUCCESS);

    // Clear sensitive key material
    kctsb_secure_zero(derived_key, sizeof(derived_key));
    kctsb_aes_clear(&aes_ctx);

    kctsb_cleanup();
}

// ============================================================================
// Memory Safety Tests
// ============================================================================

TEST(IntegrationTest, SecureZero) {
    uint8_t sensitive_data[64];
    kctsb_random_bytes(sensitive_data, sizeof(sensitive_data));

    // Verify data is non-zero
    bool has_nonzero = false;
    for (size_t i = 0; i < sizeof(sensitive_data); ++i) {
        if (sensitive_data[i] != 0) {
            has_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(has_nonzero);

    // Zero the data
    kctsb_secure_zero(sensitive_data, sizeof(sensitive_data));

    // Verify all zeros
    for (size_t i = 0; i < sizeof(sensitive_data); ++i) {
        EXPECT_EQ(sensitive_data[i], 0) << "Byte " << i << " should be zeroed";
    }
}

TEST(IntegrationTest, LargeDataProcessing) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);

    // Test with 10 MB data
    constexpr size_t DATA_SIZE = 10 * 1024 * 1024;
    std::vector<uint8_t> large_data(DATA_SIZE);
    kctsb_random_bytes(large_data.data(), DATA_SIZE);

    // Hash large data (void return)
    uint8_t hash[32];
    kctsb_sha256(large_data.data(), DATA_SIZE, hash);

    // Verify hash is deterministic
    uint8_t hash2[32];
    kctsb_sha256(large_data.data(), DATA_SIZE, hash2);
    EXPECT_EQ(memcmp(hash, hash2, 32), 0);

    kctsb_cleanup();
}
