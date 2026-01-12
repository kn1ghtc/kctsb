/**
 * @file test_aes.cpp
 * @brief AES algorithm unit tests
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>
#include "kctsb/kctsb.h"
#include <cstring>
#include <array>

// Test vectors from FIPS 197

class AESTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Library initialization handled by main
    }
};

// AES-128 test vector from FIPS 197 Appendix B
TEST_F(AESTest, AES128_FIPS197_Test) {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t expected_ciphertext[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);
    
    uint8_t ciphertext[16];
    ASSERT_EQ(kctsb_aes_encrypt_block(&ctx, plaintext, ciphertext), KCTSB_SUCCESS);
    
    EXPECT_EQ(memcmp(ciphertext, expected_ciphertext, 16), 0);
    
    // Test decryption
    uint8_t decrypted[16];
    ASSERT_EQ(kctsb_aes_decrypt_block(&ctx, ciphertext, decrypted), KCTSB_SUCCESS);
    
    EXPECT_EQ(memcmp(decrypted, plaintext, 16), 0);
    
    kctsb_aes_clear(&ctx);
}

// AES-192 test
TEST_F(AESTest, AES192_Test) {
    uint8_t key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 24), KCTSB_SUCCESS);
    
    uint8_t ciphertext[16];
    ASSERT_EQ(kctsb_aes_encrypt_block(&ctx, plaintext, ciphertext), KCTSB_SUCCESS);
    
    uint8_t decrypted[16];
    ASSERT_EQ(kctsb_aes_decrypt_block(&ctx, ciphertext, decrypted), KCTSB_SUCCESS);
    
    EXPECT_EQ(memcmp(decrypted, plaintext, 16), 0);
    
    kctsb_aes_clear(&ctx);
}

// AES-256 test
TEST_F(AESTest, AES256_Test) {
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    
    uint8_t plaintext[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 32), KCTSB_SUCCESS);
    
    uint8_t ciphertext[16];
    ASSERT_EQ(kctsb_aes_encrypt_block(&ctx, plaintext, ciphertext), KCTSB_SUCCESS);
    
    uint8_t decrypted[16];
    ASSERT_EQ(kctsb_aes_decrypt_block(&ctx, ciphertext, decrypted), KCTSB_SUCCESS);
    
    EXPECT_EQ(memcmp(decrypted, plaintext, 16), 0);
    
    kctsb_aes_clear(&ctx);
}

// GCM mode test (replaces CBC - CBC has been removed as insecure in v3.0.0)
TEST_F(AESTest, AES128_GCM_Test) {
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
    
    uint8_t decrypted[32];
    ASSERT_EQ(kctsb_aes_gcm_decrypt(&ctx, iv, 12, aad, sizeof(aad)-1,
                                     ciphertext, 32, tag, decrypted), KCTSB_SUCCESS);
    
    EXPECT_EQ(memcmp(decrypted, plaintext, 32), 0);
    
    kctsb_aes_clear(&ctx);
}

// CTR mode test
TEST_F(AESTest, AES128_CTR_Test) {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t nonce[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };
    
    uint8_t plaintext[48] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
    };
    
    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);
    
    uint8_t ciphertext[48];
    ASSERT_EQ(kctsb_aes_ctr_crypt(&ctx, nonce, plaintext, 48, ciphertext), KCTSB_SUCCESS);
    
    // CTR mode encryption and decryption are the same operation
    uint8_t decrypted[48];
    ASSERT_EQ(kctsb_aes_ctr_crypt(&ctx, nonce, ciphertext, 48, decrypted), KCTSB_SUCCESS);
    
    EXPECT_EQ(memcmp(decrypted, plaintext, 48), 0);
    
    kctsb_aes_clear(&ctx);
}

// C++ API test - TODO: Implement C++ AES class
// TEST_F(AESTest, CppAPI_Test) {
//     kctsb::ByteVec key = {
//         0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
//     };
//     
//     kctsb::AES aes(key);
//     
//     kctsb::AESBlock input = {
//         0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//         0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
//     };
//     
//     auto encrypted = aes.encryptBlock(input);
//     auto decrypted = aes.decryptBlock(encrypted);
//     
//     EXPECT_EQ(input, decrypted);
// }

// Invalid key length test
TEST_F(AESTest, InvalidKeyLength_Test) {
    uint8_t key[15] = {0};  // Invalid key length
    
    kctsb_aes_ctx_t ctx;
    EXPECT_EQ(kctsb_aes_init(&ctx, key, 15), KCTSB_ERROR_INVALID_KEY);
}

// Null pointer tests
TEST_F(AESTest, NullPointer_Tests) {
    uint8_t key[16] = {0};
    kctsb_aes_ctx_t ctx;
    
    EXPECT_EQ(kctsb_aes_init(nullptr, key, 16), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_aes_init(&ctx, nullptr, 16), KCTSB_ERROR_INVALID_PARAM);
    
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);
    
    uint8_t block[16] = {0};
    EXPECT_EQ(kctsb_aes_encrypt_block(nullptr, block, block), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_aes_encrypt_block(&ctx, nullptr, block), KCTSB_ERROR_INVALID_PARAM);
    EXPECT_EQ(kctsb_aes_encrypt_block(&ctx, block, nullptr), KCTSB_ERROR_INVALID_PARAM);
}
