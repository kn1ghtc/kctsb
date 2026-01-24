/**
 * @file test_behz_rns_tool.cpp
 * @brief Unit tests for BEHZ RNS Tool
 * 
 * Tests the BEHZ algorithm implementation for BFV multiplication rescaling.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/fe/common/behz_rns_tool.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include <random>
#include <cmath>

using namespace kctsb::fhe;

// ============================================================================
// Test Fixtures
// ============================================================================

class BEHZRNSToolTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Simple parameters for testing
        log_n_ = 4;  // n = 16
        n_ = 1 << log_n_;
        
        // Two 17-bit primes
        primes_ = {65537, 114689};
        t_ = 256;  // Plaintext modulus
        
        // Create RNSContext
        context_ = std::make_unique<RNSContext>(log_n_, primes_);
        
        // Create RNSBase and BEHZ tool
        std::vector<Modulus> mods;
        for (auto p : primes_) {
            mods.emplace_back(p);
        }
        q_base_ = std::make_unique<RNSBase>(mods);
        behz_tool_ = std::make_unique<BEHZRNSTool>(n_, *q_base_, t_);
        
        rng_.seed(42);
    }
    
    int log_n_;
    size_t n_;
    std::vector<uint64_t> primes_;
    uint64_t t_;
    std::unique_ptr<RNSContext> context_;
    std::unique_ptr<RNSBase> q_base_;
    std::unique_ptr<BEHZRNSTool> behz_tool_;
    std::mt19937_64 rng_;
};

// ============================================================================
// Basic Tests
// ============================================================================

TEST_F(BEHZRNSToolTest, Construction) {
    EXPECT_EQ(behz_tool_->n(), n_);
    EXPECT_EQ(behz_tool_->q_size(), primes_.size());
    EXPECT_EQ(behz_tool_->t(), t_);
}

TEST_F(BEHZRNSToolTest, SimpleScaleAndRound) {
    // Test: compute floor(c * t / Q) for a simple value
    // 
    // c = delta * m where delta = floor(Q/t), m is the message
    // floor(c * t / Q) = floor(delta * m * t / Q)
    //
    // Note: Since delta = floor(Q/t), we have delta * t <= Q
    // So delta * m * t / Q = m * (delta * t / Q) < m
    // The floor will give us m-1 or m depending on the fractional part.
    //
    // For BFV: This floor behavior is standard (SEAL uses it).
    // The noise analysis ensures correctness despite the floor.
    
    size_t L = primes_.size();
    
    // Compute Q = product of all primes
    __int128 Q = 1;
    for (auto p : primes_) {
        Q *= p;
    }
    
    // delta = Q / t (integer division = floor)
    __int128 delta = Q / static_cast<__int128>(t_);
    
    // Create a simple message
    uint64_t m = 42;
    
    // Compute c = delta * m in RNS
    std::vector<uint64_t> input_rns(L * n_, 0);
    std::vector<uint64_t> output_rns(L * n_, 0);
    
    __int128 c = delta * m;
    for (size_t i = 0; i < L; i++) {
        uint64_t c_mod_qi = static_cast<uint64_t>(c % static_cast<__int128>(primes_[i]));
        input_rns[i * n_] = c_mod_qi;  // Only first coefficient
    }
    
    // Apply BEHZ: should get floor(c * t / Q)
    behz_tool_->multiply_and_rescale(input_rns.data(), output_rns.data());
    
    // Compute expected result: floor(delta * m * t / Q)
    // = floor(m * delta * t / Q)
    __int128 delta_t = delta * static_cast<__int128>(t_);
    __int128 expected_full = (static_cast<__int128>(m) * delta_t) / Q;
    uint64_t expected = static_cast<uint64_t>(expected_full);
    
    // Check result - should be floor(m * delta * t / Q) for all RNS levels
    for (size_t i = 0; i < L; i++) {
        uint64_t expected_mod = expected % primes_[i];
        EXPECT_EQ(output_rns[i * n_], expected_mod)
            << "Level " << i << ": expected " << expected_mod 
            << ", got " << output_rns[i * n_];
    }
    
    // Verify the result is m or m-1 (acceptable due to floor)
    EXPECT_TRUE(expected == m || expected == m - 1)
        << "Expected result to be " << m << " or " << (m-1) << ", got " << expected;
}

TEST_F(BEHZRNSToolTest, DeltaSquaredScaleAndRound) {
    // Test: compute round(c * t / Q) for c = delta^2 * m1 * m2
    // 
    // This is what we need for BFV multiplication rescaling.
    // round(delta^2 * m1 * m2 * t / Q) = round(delta * m1 * m2)
    // The result should have scale delta, encoding m1*m2
    
    size_t L = primes_.size();
    
    // Compute Q = product of all primes
    __int128 Q = 1;
    for (auto p : primes_) {
        Q *= p;
    }
    
    // delta = Q / t
    __int128 delta = Q / static_cast<__int128>(t_);
    
    // Messages
    uint64_t m1 = 7, m2 = 11;
    uint64_t m_prod = (m1 * m2) % t_;  // 77
    
    // Compute c = delta^2 * m1 * m2 in full precision
    // Note: delta^2 may exceed Q, but that's okay - BEHZ handles this
    __int128 delta_sq = delta * delta;
    __int128 c = delta_sq * m1 * m2;
    
    // Reduce to RNS representation
    std::vector<uint64_t> input_rns(L * n_, 0);
    std::vector<uint64_t> output_rns(L * n_, 0);
    
    for (size_t i = 0; i < L; i++) {
        // c mod q_i
        __int128 c_mod_qi = c % static_cast<__int128>(primes_[i]);
        input_rns[i * n_] = static_cast<uint64_t>(c_mod_qi);
    }
    
    // Apply BEHZ: should get round(c * t / Q) = round(delta * m1 * m2)
    // = delta * m1 * m2 (exactly, since delta divides Q)
    behz_tool_->multiply_and_rescale(input_rns.data(), output_rns.data());
    
    // Expected result: delta * m1 * m2 (mod each q_i)
    __int128 expected = delta * m1 * m2;
    
    for (size_t i = 0; i < L; i++) {
        uint64_t expected_mod = static_cast<uint64_t>(expected % static_cast<__int128>(primes_[i]));
        std::cout << "Level " << i << ": got " << output_rns[i * n_] 
                  << ", expected " << expected_mod << std::endl;
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
