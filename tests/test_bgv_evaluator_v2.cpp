/**
 * @file test_bgv_evaluator_v2.cpp
 * @brief Unit Tests for BGV EvaluatorV2 (Pure RNS)
 * 
 * Tests all operations of the high-performance RNS-based BGV evaluator.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.10.0
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/fe/bgv/bgv_evaluator_v2.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include <random>

using namespace kctsb::fhe;
using namespace kctsb::fhe::bgv;

// ============================================================================
// Test Fixture
// ============================================================================

class BGVEvaluatorV2Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Use small parameters for fast testing
        log_n_ = 4;  // n = 16
        primes_ = {65537, 114689};  // Two 17-bit primes
        
        context_ = std::make_unique<RNSContext>(log_n_, primes_);
        evaluator_ = std::make_unique<BGVEvaluatorV2>(context_.get(), 256);
        
        rng_.seed(12345);
    }
    
    int log_n_;
    std::vector<uint64_t> primes_;
    std::unique_ptr<RNSContext> context_;
    std::unique_ptr<BGVEvaluatorV2> evaluator_;
    std::mt19937_64 rng_;
};

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST_F(BGVEvaluatorV2Test, SecretKeyGeneration) {
    auto sk = evaluator_->generate_secret_key(rng_);
    
    EXPECT_TRUE(sk.is_ntt_form);
    EXPECT_FALSE(sk.s.empty());
    EXPECT_EQ(sk.s.current_level(), 2);  // Two primes
    EXPECT_TRUE(sk.s.is_ntt_form());
}

TEST_F(BGVEvaluatorV2Test, PublicKeyGeneration) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    EXPECT_TRUE(pk.is_ntt_form);
    EXPECT_FALSE(pk.pk0.empty());
    EXPECT_FALSE(pk.pk1.empty());
    EXPECT_TRUE(pk.pk0.is_ntt_form());
    EXPECT_TRUE(pk.pk1.is_ntt_form());
}

TEST_F(BGVEvaluatorV2Test, RelinKeyGeneration) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto rk = evaluator_->generate_relin_key(sk, rng_);
    
    EXPECT_TRUE(rk.is_ntt_form);
    EXPECT_GT(rk.ksk0.size(), 0);
    EXPECT_EQ(rk.ksk0.size(), rk.ksk1.size());
    EXPECT_EQ(rk.decomp_base, 65536);
    
    // All components should be in NTT form
    for (const auto& k : rk.ksk0) {
        EXPECT_TRUE(k.is_ntt_form());
    }
}

// ============================================================================
// Encryption / Decryption Tests
// ============================================================================

TEST_F(BGVEvaluatorV2Test, EncryptDecryptZero) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    // Encrypt zero plaintext
    BGVPlaintextV2 pt_zero(16, 0);
    auto ct = evaluator_->encrypt(pt_zero, pk, rng_);
    
    EXPECT_TRUE(ct.is_ntt_form);
    EXPECT_EQ(ct.size(), 2);
    
    // Decrypt
    auto pt_decrypted = evaluator_->decrypt(ct, sk);
    
    // Should decrypt to zero (or very close due to noise)
    EXPECT_EQ(pt_decrypted.size(), 16);
    
    // Most coefficients should be zero or very small
    int zero_count = 0;
    for (auto coeff : pt_decrypted) {
        if (coeff == 0) zero_count++;
    }
    EXPECT_GT(zero_count, 10);  // At least 10/16 should be zero
}

TEST_F(BGVEvaluatorV2Test, EncryptDecryptSimple) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    // Simple plaintext: [1, 2, 3, 4, ...]
    BGVPlaintextV2 pt(16);
    for (size_t i = 0; i < 16; ++i) {
        pt[i] = i + 1;
    }
    
    auto ct = evaluator_->encrypt(pt, pk, rng_);
    auto pt_decrypted = evaluator_->decrypt(ct, sk);
    
    EXPECT_EQ(pt_decrypted.size(), 16);
    
    // Check first few coefficients
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_decrypted[i], pt[i]) << "Mismatch at index " << i;
    }
}

// ============================================================================
// Homomorphic Addition Tests
// ============================================================================

TEST_F(BGVEvaluatorV2Test, Addition) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    // Encrypt two plaintexts
    BGVPlaintextV2 pt1(16, 5);   // [5, 5, 5, ...]
    BGVPlaintextV2 pt2(16, 3);   // [3, 3, 3, ...]
    
    auto ct1 = evaluator_->encrypt(pt1, pk, rng_);
    auto ct2 = evaluator_->encrypt(pt2, pk, rng_);
    
    // Add ciphertexts
    auto ct_sum = evaluator_->add(ct1, ct2);
    
    EXPECT_TRUE(ct_sum.is_ntt_form);
    EXPECT_EQ(ct_sum.size(), 2);
    
    // Decrypt
    auto pt_sum = evaluator_->decrypt(ct_sum, sk);
    
    // Should be [8, 8, 8, ...]
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_sum[i], 8) << "Addition failed at index " << i;
    }
}

TEST_F(BGVEvaluatorV2Test, AdditionInplace) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    BGVPlaintextV2 pt1(16, 7);
    BGVPlaintextV2 pt2(16, 4);
    
    auto ct1 = evaluator_->encrypt(pt1, pk, rng_);
    auto ct2 = evaluator_->encrypt(pt2, pk, rng_);
    
    evaluator_->add_inplace(ct1, ct2);
    
    auto pt_result = evaluator_->decrypt(ct1, sk);
    
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_result[i], 11);
    }
}

// ============================================================================
// Homomorphic Subtraction Tests
// ============================================================================

TEST_F(BGVEvaluatorV2Test, Subtraction) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    BGVPlaintextV2 pt1(16, 10);
    BGVPlaintextV2 pt2(16, 3);
    
    auto ct1 = evaluator_->encrypt(pt1, pk, rng_);
    auto ct2 = evaluator_->encrypt(pt2, pk, rng_);
    
    auto ct_diff = evaluator_->sub(ct1, ct2);
    auto pt_diff = evaluator_->decrypt(ct_diff, sk);
    
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_diff[i], 7);
    }
}

// ============================================================================
// Homomorphic Multiplication Tests
// ============================================================================

TEST_F(BGVEvaluatorV2Test, Multiplication) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    // Small values to avoid overflow
    BGVPlaintextV2 pt1(16, 3);
    BGVPlaintextV2 pt2(16, 4);
    
    auto ct1 = evaluator_->encrypt(pt1, pk, rng_);
    auto ct2 = evaluator_->encrypt(pt2, pk, rng_);
    
    auto ct_prod = evaluator_->multiply(ct1, ct2);
    
    EXPECT_TRUE(ct_prod.is_ntt_form);
    EXPECT_EQ(ct_prod.size(), 3);  // After multiply, size = 3
    
    // For decryption, we need size 2, so relinearize first
    auto rk = evaluator_->generate_relin_key(sk, rng_);
    evaluator_->relinearize_inplace(ct_prod, rk);
    
    EXPECT_EQ(ct_prod.size(), 2);
    
    auto pt_prod = evaluator_->decrypt(ct_prod, sk);
    
    // Should be [12, 12, 12, ...] (3 * 4 = 12)
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_prod[i], 12) << "Multiplication failed at index " << i;
    }
}

TEST_F(BGVEvaluatorV2Test, MultiplyAndRelinearize) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    auto rk = evaluator_->generate_relin_key(sk, rng_);
    
    BGVPlaintextV2 pt1(16, 5);
    BGVPlaintextV2 pt2(16, 2);
    
    auto ct1 = evaluator_->encrypt(pt1, pk, rng_);
    auto ct2 = evaluator_->encrypt(pt2, pk, rng_);
    
    evaluator_->multiply_inplace(ct1, ct2);
    EXPECT_EQ(ct1.size(), 3);
    
    evaluator_->relinearize_inplace(ct1, rk);
    EXPECT_EQ(ct1.size(), 2);
    
    auto pt_result = evaluator_->decrypt(ct1, sk);
    
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_result[i], 10);
    }
}

// ============================================================================
// Complex Operation Tests
// ============================================================================

TEST_F(BGVEvaluatorV2Test, MultipleOperations) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    auto rk = evaluator_->generate_relin_key(sk, rng_);
    
    // Compute (a + b) * c where a=2, b=3, c=4
    BGVPlaintextV2 pt_a(16, 2);
    BGVPlaintextV2 pt_b(16, 3);
    BGVPlaintextV2 pt_c(16, 4);
    
    auto ct_a = evaluator_->encrypt(pt_a, pk, rng_);
    auto ct_b = evaluator_->encrypt(pt_b, pk, rng_);
    auto ct_c = evaluator_->encrypt(pt_c, pk, rng_);
    
    // a + b
    auto ct_sum = evaluator_->add(ct_a, ct_b);
    
    // (a + b) * c
    auto ct_result = evaluator_->multiply(ct_sum, ct_c);
    evaluator_->relinearize_inplace(ct_result, rk);
    
    auto pt_result = evaluator_->decrypt(ct_result, sk);
    
    // Expected: (2 + 3) * 4 = 20
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_result[i], 20) << "Complex operation failed at index " << i;
    }
}

TEST_F(BGVEvaluatorV2Test, Negation) {
    auto sk = evaluator_->generate_secret_key(rng_);
    auto pk = evaluator_->generate_public_key(sk, rng_);
    
    BGVPlaintextV2 pt(16, 7);
    auto ct = evaluator_->encrypt(pt, pk, rng_);
    
    evaluator_->negate_inplace(ct);
    
    auto pt_neg = evaluator_->decrypt(ct, sk);
    
    // Should be -7 mod 256 = 249
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(pt_neg[i], 249);
    }
}

// ============================================================================
// Performance Indicator Test (Not Strict)
// ============================================================================

TEST_F(BGVEvaluatorV2Test, PerformanceIndicator) {
    // Use slightly larger parameters to get meaningful timing
    RNSContext ctx_perf(8, {65537, 114689});  // n = 256
    BGVEvaluatorV2 eval_perf(&ctx_perf, 256);
    
    std::mt19937_64 rng_perf(54321);
    
    auto sk = eval_perf.generate_secret_key(rng_perf);
    auto pk = eval_perf.generate_public_key(sk, rng_perf);
    auto rk = eval_perf.generate_relin_key(sk, rng_perf);
    
    BGVPlaintextV2 pt1(256, 5);
    BGVPlaintextV2 pt2(256, 3);
    
    auto ct1 = eval_perf.encrypt(pt1, pk, rng_perf);
    auto ct2 = eval_perf.encrypt(pt2, pk, rng_perf);
    
    // Multiply (should be fast)
    auto start = std::chrono::high_resolution_clock::now();
    auto ct_prod = eval_perf.multiply(ct1, ct2);
    eval_perf.relinearize_inplace(ct_prod, rk);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Just check it completes successfully
    // Performance will be tested in benchmark suite
    EXPECT_LT(duration, 1000);  // Should be < 1 second even for n=256
    
    std::cout << "Multiply+Relin time (n=256): " << duration << " ms\n";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
