/**
 * @file test_integration.cpp
 * @brief Integration tests
 */

#include <gtest/gtest.h>
#include "kctsb/kctsb.h"

TEST(IntegrationTest, LibraryInitialization) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);
    
    const char* version = kctsb_version();
    EXPECT_NE(version, nullptr);
    EXPECT_STREQ(version, "3.2.0");
    
    const char* platform = kctsb_platform();
    EXPECT_NE(platform, nullptr);
    
    kctsb_cleanup();
}

TEST(IntegrationTest, SecureRandom) {
    EXPECT_EQ(kctsb_init(), KCTSB_SUCCESS);
    
    uint8_t buffer[32];
    EXPECT_EQ(kctsb_random_bytes(buffer, 32), KCTSB_SUCCESS);
    
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
