/**
 * @file test_psi_pir.cpp
 * @brief Comprehensive PSI/PIR Test Suite
 * 
 * @details Tests for Piano-PSI, OT-PSI, Native-PIR
 * 
 * @author kn1ghtc
 * @version 4.13.0
 * @date 2026-01-25
 * 
 * @note Native-PIR tests are disabled pending V5.0 FHE module reimplementation
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/psi/psi.h"
// #include "kctsb/advanced/psi/native_pir.h"  // Disabled: requires FHE modules
#include "kctsb/advanced/psi/ot_psi.h"

#include <cstring>
#include <vector>
#include <algorithm>
#include <random>

class PSIPIRTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Generate test datasets
        std::mt19937_64 rng(12345);
        std::uniform_int_distribution<int64_t> dist(1, 10000);
        
        // Client set: 100 elements
        for (size_t i = 0; i < 100; ++i) {
            client_set_.push_back(dist(rng));
        }
        
        // Server set: 150 elements (50% overlap)
        for (size_t i = 0; i < 50; ++i) {
            server_set_.push_back(client_set_[i]);  // Common elements
        }
        for (size_t i = 0; i < 100; ++i) {
            server_set_.push_back(dist(rng));  // Unique elements
        }
    }
    
    std::vector<int64_t> client_set_;
    std::vector<int64_t> server_set_;
};

/* ============================================================================
 * Piano-PSI Tests
 * ============================================================================ */

TEST_F(PSIPIRTest, PianoPSI_Basic) {
    kctsb_psi_config_t config;
    kctsb_psi_config_init(&config);
    
    kctsb_psi_ctx_t* ctx = kctsb_piano_psi_create(&config);
    ASSERT_NE(ctx, nullptr);
    
    kctsb_psi_result_t result;
    int ret = kctsb_piano_psi_compute(ctx, 
                                     client_set_.data(), client_set_.size(),
                                     server_set_.data(), server_set_.size(),
                                     &result);
    
    EXPECT_EQ(ret, 0);
    EXPECT_GT(result.intersection_size, 0);
    EXPECT_TRUE(result.is_correct);
    
    kctsb_piano_psi_destroy(ctx);
}

/* ============================================================================
 * OT-PSI Tests
 * ============================================================================ */

TEST_F(PSIPIRTest, OTPSI_Extension) {
    kctsb_ot_psi_config_t config;
    kctsb_ot_psi_config_init(&config, KCTSB_OT_EXTENSION);
    
    kctsb_ot_psi_ctx_t* ctx = kctsb_ot_psi_create(&config);
    ASSERT_NE(ctx, nullptr);
    
    kctsb_ot_psi_result_t result;
    int ret = kctsb_ot_psi_compute(ctx,
                                   client_set_.data(), client_set_.size(),
                                   server_set_.data(), server_set_.size(),
                                   &result);
    
    EXPECT_EQ(ret, 0);
    EXPECT_GT(result.intersection_size, 0);
    EXPECT_GT(result.ot_count, 0);
    EXPECT_TRUE(result.is_correct);
    
    kctsb_ot_psi_result_free(&result);
    kctsb_ot_psi_destroy(ctx);
}

/* ============================================================================
 * Native PIR Tests
 * NOTE: Disabled pending V5.0 FHE module reimplementation
 * The native_pir module requires FHE (BGV/BFV/CKKS) which needs V5 reimplementation
 * ============================================================================ */

#if 0  // Disabled: requires FHE modules (BGV/BFV/CKKS)

TEST_F(PSIPIRTest, NativePIR_BGV_IntDB) {
    // Create integer database
    std::vector<int64_t> database = {10, 20, 30, 40, 50};
    
    kctsb_native_pir_config_t config;
    kctsb_native_pir_config_init(&config, KCTSB_PIR_BGV, database.size());
    
    kctsb_native_pir_ctx_t* ctx = kctsb_native_pir_create_int(&config,
                                                              database.data(),
                                                              database.size());
    ASSERT_NE(ctx, nullptr);
    
    // Query index 2 (should retrieve 30)
    kctsb_native_pir_result_t result;
    int ret = kctsb_native_pir_query(ctx, 2, &result);
    
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(result.query_index, 2);
    EXPECT_TRUE(result.is_correct);
    
    // Verify retrieved value
    if (result.retrieved_data && result.data_size == sizeof(int64_t)) {
        int64_t value;
        std::memcpy(&value, result.retrieved_data, sizeof(int64_t));
        EXPECT_EQ(value, 30);
    }
    
    kctsb_native_pir_result_free(&result);
    kctsb_native_pir_destroy(ctx);
}

TEST_F(PSIPIRTest, NativePIR_CKKS_DoubleDB) {
    // Create double database
    std::vector<double> database = {1.1, 2.2, 3.3, 4.4, 5.5};
    
    kctsb_native_pir_config_t config;
    kctsb_native_pir_config_init(&config, KCTSB_PIR_CKKS, database.size());
    
    kctsb_native_pir_ctx_t* ctx = kctsb_native_pir_create_double(&config,
                                                                database.data(),
                                                                database.size());
    ASSERT_NE(ctx, nullptr);
    
    // Query index 3 (should retrieve 4.4)
    kctsb_native_pir_result_t result;
    int ret = kctsb_native_pir_query(ctx, 3, &result);
    
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(result.is_correct);
    EXPECT_NEAR(result.retrieved_double, 4.4, 0.01);
    
    kctsb_native_pir_result_free(&result);
    kctsb_native_pir_destroy(ctx);
}

#endif  // Disabled: requires FHE modules

/* ============================================================================
 * Performance Tests
 * ============================================================================ */

TEST_F(PSIPIRTest, DISABLED_PianoPSI_Performance) {
    // Large dataset test (disabled by default)
    std::vector<int64_t> large_client(1000), large_server(1000);
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<int64_t> dist(1, 100000);
    
    for (auto& v : large_client) v = dist(rng);
    for (auto& v : large_server) v = dist(rng);
    
    kctsb_psi_config_t config;
    kctsb_psi_config_init(&config);
    
    kctsb_psi_ctx_t* ctx = kctsb_piano_psi_create(&config);
    kctsb_psi_result_t result;
    
    int ret = kctsb_piano_psi_compute(ctx,
                                     large_client.data(), large_client.size(),
                                     large_server.data(), large_server.size(),
                                     &result);
    
    EXPECT_EQ(ret, 0);
    EXPECT_LT(result.execution_time_ms, 1000.0);  // < 1 second
    
    kctsb_piano_psi_destroy(ctx);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
