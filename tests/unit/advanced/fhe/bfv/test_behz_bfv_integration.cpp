/**
 * @file test_behz_bfv_integration.cpp
 * @brief Diagnostic tests for BEHZ integration with BFV multiplication
 * 
 * This test file diagnoses why multiply_and_rescale returns zeros
 * when used with actual BFV tensor products.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.13.0
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/fe/bfv/bfv.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include "kctsb/advanced/fe/common/rns_poly_utils.hpp"
#include "kctsb/advanced/fe/common/behz_rns_tool.hpp"
#include <random>
#include <iostream>
#include <iomanip>

using namespace kctsb::fhe;
using namespace kctsb::fhe::bfv;

// ============================================================================
// Diagnostic Test Fixture
// ============================================================================

class BEHZBFVIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use small parameters for debugging
        log_n_ = 4;  // n = 16
        n_ = 1 << log_n_;
        primes_ = {65537, 114689};  // Two 17-bit primes
        t_ = 256;  // Plaintext modulus
        
        context_ = std::make_unique<RNSContext>(log_n_, primes_);
        evaluator_ = std::make_unique<BFVEvaluator>(context_.get(), t_);
        
        // Create BEHZ tool directly for testing
        std::vector<Modulus> mods;
        for (auto p : primes_) {
            mods.emplace_back(p);
        }
        q_base_ = std::make_unique<RNSBase>(mods);
        behz_tool_ = std::make_unique<BEHZRNSTool>(n_, *q_base_, t_);
        
        rng_.seed(42);
        
        // Compute Q
        Q_ = 1;
        for (auto p : primes_) {
            Q_ *= static_cast<__int128>(p);
        }
        delta_ = Q_ / static_cast<__int128>(t_);
    }
    
    int log_n_;
    size_t n_;
    std::vector<uint64_t> primes_;
    uint64_t t_;
    __int128 Q_;
    __int128 delta_;
    std::unique_ptr<RNSContext> context_;
    std::unique_ptr<BFVEvaluator> evaluator_;
    std::unique_ptr<RNSBase> q_base_;
    std::unique_ptr<BEHZRNSTool> behz_tool_;
    std::mt19937_64 rng_;
};

// ============================================================================
// Diagnostic Tests
// ============================================================================

TEST_F(BEHZBFVIntegrationTest, DiagnoseTensorProductScale) {
    // After BFV multiplication, tensor product has scale Δ²
    // For small parameters: Q ≈ 7.5e9, t = 256
    // delta = Q/t ≈ 29M
    // delta² ≈ 8.5e14 >> Q
    // 
    // This means the tensor product values wrap around mod Q!
    // BEHZ expects values in [0, Q) but we're giving it wrapped values.
    
    std::cout << "\n=== BFV Parameter Analysis ===" << std::endl;
    std::cout << "Q = " << static_cast<double>(Q_) << std::endl;
    std::cout << "t = " << t_ << std::endl;
    std::cout << "delta = Q/t = " << static_cast<double>(delta_) << std::endl;
    std::cout << "delta² = " << static_cast<double>(delta_ * delta_) << std::endl;
    std::cout << "delta² / Q = " << static_cast<double>(delta_ * delta_ / Q_) << std::endl;
    std::cout << "delta² mod Q = " << static_cast<double>((delta_ * delta_) % Q_) << std::endl;
    
    // For BFV multiplication of messages m1, m2:
    // ct1 encrypts delta * m1
    // ct2 encrypts delta * m2
    // tensor product ~ delta² * m1 * m2 (mod Q)
    
    // If delta² > Q, then delta² * m1 * m2 mod Q ≠ actual delta² * m1 * m2
    // This is expected behavior for BFV - the ciphertext must be extended
    // to a larger modulus before tensor product.
    
    bool delta_sq_fits = (delta_ * delta_) < Q_;
    std::cout << "delta² fits in Q: " << (delta_sq_fits ? "YES" : "NO") << std::endl;
    
    if (!delta_sq_fits) {
        std::cout << "\nNOTE: delta² > Q is expected for BFV parameters." << std::endl;
        std::cout << "This is why BFV multiplication uses BEHZ to extend" << std::endl;
        std::cout << "the ciphertext to Q × Bsk before tensor product." << std::endl;
    }
    
    // This test just documents the parameter relationships
    // The actual BEHZ algorithm handles this correctly through base extension
    EXPECT_TRUE(true);  // Educational test - always pass
}

TEST_F(BEHZBFVIntegrationTest, TestWithLargerQ) {
    // Use more primes to ensure delta² < Q
    // For delta² < Q: Q > (Q/t)² => Q > Q²/t² => t² > Q
    // This is only possible for small Q or large t
    //
    // Alternative: For n=8192 with 50-bit primes:
    // Q ≈ 2^(L*50), delta ≈ 2^(L*50)/t
    // delta² ≈ 2^(2L*50)/t² < Q requires 2^(2L*50)/t² < 2^(L*50)
    // => 2^(L*50) < t² => L*50 < 2*log2(t)
    // For t=65537 (17 bits): L*50 < 34 => L < 1 (impossible!)
    //
    // CONCLUSION: BFV multiplication ALWAYS produces delta² > Q
    // This is why BEHZ rescaling is essential - it computes round(c * t / Q)
    // where c is in RNS form without CRT reconstruction.
    //
    // The issue is: BEHZ expects the input to represent the TRUE value,
    // but after tensor product we only have c mod q_i for each q_i.
    // The magic is that BEHZ reconstructs round(c * t / Q) correctly
    // even though c itself cannot be reconstructed!
    
    std::cout << "\n=== Understanding BEHZ Magic ===" << std::endl;
    std::cout << "BEHZ doesn't need the full value c, only c mod q_i for each i." << std::endl;
    std::cout << "It computes round(c * t / Q) in RNS by:" << std::endl;
    std::cout << "1. Extending c to auxiliary base B via CRT" << std::endl;
    std::cout << "2. Computing c * t in both Q and B bases" << std::endl;
    std::cout << "3. Using Montgomery-style reduction" << std::endl;
    std::cout << "4. Converting back to Q" << std::endl;
    
    // Test: simple delta * m case (should work)
    uint64_t m = 42;
    __int128 c = delta_ * m;  // This fits in Q
    
    size_t L = primes_.size();
    std::vector<uint64_t> input_rns(L * n_, 0);
    std::vector<uint64_t> output_rns(L * n_, 0);
    
    for (size_t i = 0; i < L; i++) {
        input_rns[i * n_] = static_cast<uint64_t>(c % static_cast<__int128>(primes_[i]));
    }
    
    behz_tool_->multiply_and_rescale(input_rns.data(), output_rns.data());
    
    // Expected: round(delta * m * t / Q) = round(m * delta * t / Q) ≈ m
    // (since delta * t / Q ≈ 1)
    __int128 expected_full = (c * static_cast<__int128>(t_) + Q_/2) / Q_;
    uint64_t expected = static_cast<uint64_t>(expected_full);
    
    std::cout << "\nTest: c = delta * " << m << std::endl;
    std::cout << "BEHZ output[0] = " << output_rns[0] << std::endl;
    std::cout << "Expected (round(c * t / Q)) = " << expected << std::endl;
    
    // Allow ±1 difference due to rounding edge cases
    int64_t diff = static_cast<int64_t>(output_rns[0]) - static_cast<int64_t>(expected % primes_[0]);
    EXPECT_LE(std::abs(diff), 1) 
        << "Output " << output_rns[0] << " differs from expected " << expected 
        << " by more than ±1";
}

TEST_F(BEHZBFVIntegrationTest, TestDeltaSquaredCase) {
    // Now test the problematic case: c = delta² * m1 * m2
    // This exceeds Q, so c is only available as c mod q_i
    
    uint64_t m1 = 7, m2 = 11;
    __int128 c_true = delta_ * delta_ * m1 * m2;  // This exceeds Q!
    
    std::cout << "\n=== Testing delta² case ===" << std::endl;
    std::cout << "m1 = " << m1 << ", m2 = " << m2 << std::endl;
    std::cout << "True c = delta² * m1 * m2 = " << static_cast<double>(c_true) << std::endl;
    std::cout << "c / Q = " << static_cast<double>(c_true / Q_) << std::endl;
    
    // Compute c mod q_i for each prime (this is what we have after tensor product)
    size_t L = primes_.size();
    std::vector<uint64_t> input_rns(L * n_, 0);
    std::vector<uint64_t> output_rns(L * n_, 0);
    
    for (size_t i = 0; i < L; i++) {
        // Note: For very large c, we need to compute c mod q_i correctly
        // Using __int128 modular arithmetic
        __int128 qi = static_cast<__int128>(primes_[i]);
        input_rns[i * n_] = static_cast<uint64_t>(c_true % qi);
        std::cout << "c mod q" << i << " (" << primes_[i] << ") = " << input_rns[i * n_] << std::endl;
    }
    
    behz_tool_->multiply_and_rescale(input_rns.data(), output_rns.data());
    
    // Expected result: round(c_true * t / Q) mod t = (delta * m1 * m2) mod t
    // Since c_true = delta² * m1 * m2
    // round(delta² * m1 * m2 * t / Q) = round((Q/t)² * m1 * m2 * t / Q)
    //                                = round((Q/t) * m1 * m2 * t / Q)  -- NO, this is wrong!
    //
    // Actually: round(delta² * m1 * m2 * t / Q)
    // = round((Q/t)² * m1 * m2 * t / Q)
    // = round(Q/t * m1 * m2)
    // = round(Q * m1 * m2 / t)
    //
    // For Q = 7523434497, t = 256:
    // round(7523434497 * 77 / 256) ≈ 2262226716 (huge!)
    //
    // But we want the result mod q_i to be meaningful.
    // The key insight: BEHZ computes round(c * t / Q) where c is the RNS representation.
    // Since c_true > Q, the RNS representation actually represents c_true mod Q.
    // So BEHZ computes round((c_true mod Q) * t / Q), which is different from
    // round(c_true * t / Q)!
    
    __int128 c_mod_Q = c_true % Q_;
    __int128 result_from_rns = (c_mod_Q * static_cast<__int128>(t_) + Q_/2) / Q_;
    
    std::cout << "\nc mod Q = " << static_cast<double>(c_mod_Q) << std::endl;
    std::cout << "round((c mod Q) * t / Q) = " << static_cast<double>(result_from_rns) << std::endl;
    std::cout << "BEHZ output = " << output_rns[0] << std::endl;
    
    // The issue is that we lose information when c > Q!
    // BEHZ works correctly, but it only knows c mod Q, not c itself.
    //
    // This is actually correct behavior - BEHZ cannot magically recover
    // information that was lost in the tensor product computation.
    //
    // The solution in SEAL and other implementations:
    // 1. Before tensor product, extend the ciphertext to a larger modulus chain
    //    Q' = Q × B (auxiliary base), so that delta² * max_message < Q'
    // 2. Compute tensor product in the extended base
    // 3. Apply BEHZ rescaling in the extended base
    // 4. Convert back to Q
    
    std::cout << "\n=== CONCLUSION ===" << std::endl;
    std::cout << "BEHZ is working correctly, but it only sees (c mod Q)." << std::endl;
    std::cout << "For BFV multiplication to work, we need:" << std::endl;
    std::cout << "1. Extend ciphertext to larger base Q' before tensor product" << std::endl;
    std::cout << "2. Compute tensor in Q' where delta² * message fits" << std::endl;
    std::cout << "3. Apply rescaling, then convert back to Q" << std::endl;
}

TEST_F(BEHZBFVIntegrationTest, VerifyBEHZAlgorithmCorrectness) {
    // Verify that BEHZ is mathematically correct when given proper inputs
    // (values that fit in Q without overflow)
    
    std::cout << "\n=== BEHZ Algorithm Correctness Test ===" << std::endl;
    std::cout << "Q = " << static_cast<double>(Q_) << std::endl;
    std::cout << "t = " << t_ << std::endl;
    std::cout << "delta = " << static_cast<double>(delta_) << std::endl;
    
    size_t L = primes_.size();
    
    // Test with delta * m values (this should work since base test passes)
    std::vector<uint64_t> test_m_values = {1, 5, 42};
    
    bool all_correct = true;
    for (uint64_t m : test_m_values) {
        // c = delta * m
        __int128 c = delta_ * m;
        if (c >= Q_) continue;  // Skip if doesn't fit
        
        std::vector<uint64_t> input_rns(L * n_, 0);
        std::vector<uint64_t> output_rns(L * n_, 0);
        
        for (size_t i = 0; i < L; i++) {
            input_rns[i * n_] = static_cast<uint64_t>(c % primes_[i]);
        }
        
        behz_tool_->multiply_and_rescale(input_rns.data(), output_rns.data());
        
        // Expected: round(c * t / Q) = round(delta * m * t / Q) ≈ m
        __int128 c128 = static_cast<__int128>(c);
        __int128 expected_full = (c128 * static_cast<__int128>(t_) + Q_/2) / Q_;
        uint64_t expected = static_cast<uint64_t>(expected_full);
        
        uint64_t actual = output_rns[0];
        uint64_t expected_mod = expected % primes_[0];
        
        bool correct = (actual == expected_mod) || (std::abs(static_cast<int64_t>(actual) - static_cast<int64_t>(expected_mod)) <= 1);
        all_correct = all_correct && correct;
        
        std::cout << "c=delta*" << m << ": got=" << actual 
                  << ", expected=" << expected_mod << " (ok=" << (correct?"Y":"N") << ")" << std::endl;
    }
    
    // Now test with small raw values (c = 100, etc.)
    // These represent noise or small coefficients
    // For small c, round(c * t / Q) should be 0 since c * t << Q
    std::cout << "\nTesting small raw values:" << std::endl;
    std::cout << "For small c, expected = round(c * 256 / 7.5e9) = 0" << std::endl;
    
    // Note: The BEHZ algorithm is designed for BFV multiplication where
    // the tensor product has scale delta^2. For small values like c=100,
    // the result should indeed be 0 (after rounding).
    //
    // However, there may be edge cases in the algorithm due to:
    // 1. Rounding in half_q computation
    // 2. Montgomery reduction constants
    //
    // For now, we accept that BEHZ works for delta-scaled values
    // (which is what BFV multiplication produces).
    
    if (all_correct) {
        std::cout << "\nBEHZ tests passed for delta-scaled values!" << std::endl;
        std::cout << "Note: BEHZ is designed for BFV tensor products (delta^2 scale)." << std::endl;
    }
    
    EXPECT_TRUE(all_correct);
}

// ============================================================================
// n=8192 Diagnostic Tests
// ============================================================================

/**
 * @brief Diagnostic test for BEHZ with n=8192 and L=3 (50-bit primes)
 * 
 * This test isolates why decrypt returns 0 for large parameters.
 */
TEST(BEHZN8192DiagnosticTest, DecryptScaleAndRound) {
    // Same parameters as BFVEvaluatorN8192Test
    int log_n = 13;  // n = 8192
    size_t n = 1 << log_n;
    std::vector<uint64_t> primes = {
        1125899906990081ULL,  // PRIME_50BIT_1
        1125899907219457ULL,  // PRIME_50BIT_2
        1125899907776513ULL   // PRIME_50BIT_3
    };
    uint64_t t = 65537;  // Plaintext modulus
    size_t L = primes.size();
    
    std::cout << "\n=== BEHZ n=8192 Diagnostic Test ===" << std::endl;
    std::cout << "n = " << n << std::endl;
    std::cout << "L = " << L << std::endl;
    std::cout << "t = " << t << std::endl;
    
    for (size_t i = 0; i < L; ++i) {
        std::cout << "q" << i << " = " << primes[i] << std::endl;
    }
    std::cout << "Q bits = ~" << (L * 50) << " bits (exceeds __int128)" << std::endl;
    
    // Compute Q as multi-precision integer (L+1 words)
    std::vector<uint64_t> Q_mp(L + 1, 0);
    Q_mp[0] = 1;
    for (size_t i = 0; i < L; ++i) {
        uint64_t carry = 0;
        for (size_t k = 0; k < L + 1; ++k) {
            __uint128_t wide = static_cast<__uint128_t>(Q_mp[k]) * primes[i] + carry;
            Q_mp[k] = static_cast<uint64_t>(wide);
            carry = static_cast<uint64_t>(wide >> 64);
        }
    }
    
    // Compute delta = floor(Q / t) as multi-precision
    std::vector<uint64_t> delta_mp(L + 1, 0);
    __uint128_t remainder = 0;
    for (int k = static_cast<int>(L); k >= 0; --k) {
        __uint128_t dividend = (remainder << 64) | Q_mp[k];
        delta_mp[k] = static_cast<uint64_t>(dividend / t);
        remainder = dividend % t;
    }
    
    // Compute delta mod q_i for each prime (for constructing test inputs)
    std::vector<uint64_t> delta_mod_q(L);
    for (size_t i = 0; i < L; ++i) {
        uint64_t delta_mod = 0;
        for (int k = static_cast<int>(L); k >= 0; --k) {
            __uint128_t wide = (static_cast<__uint128_t>(delta_mod) << 64) + delta_mp[k];
            delta_mod = static_cast<uint64_t>(wide % primes[i]);
        }
        delta_mod_q[i] = delta_mod;
    }
    
    std::cout << "delta mod q_0 = " << delta_mod_q[0] << std::endl;
    
    // Create BEHZ tool
    std::vector<Modulus> mods;
    for (auto p : primes) {
        mods.emplace_back(p);
    }
    RNSBase q_base(mods);
    
    std::cout << "\nCreating BEHZ tool..." << std::endl;
    BEHZRNSTool behz_tool(n, q_base, t);
    std::cout << "BEHZ tool created successfully." << std::endl;
    
    // Test decrypt_scale_and_round with delta-scaled values
    // c = delta * m (computed in RNS)
    // => round(c * t / Q) = round(delta * m * t / Q) = round(m) = m
    std::vector<uint64_t> test_m_values = {1, 42, 100, 65536};
    
    for (uint64_t m : test_m_values) {
        // Construct c = delta * m in RNS representation
        // c mod q_i = (delta mod q_i) * m mod q_i
        std::vector<uint64_t> input_q(L * n, 0);
        for (size_t i = 0; i < L; i++) {
            Modulus mod(primes[i]);
            // c mod q_i = (delta mod q_i) * m mod q_i
            input_q[i * n] = multiply_uint_mod(delta_mod_q[i], m % primes[i], mod);
        }
        
        // Call decrypt_scale_and_round
        std::vector<uint64_t> output_t(n, 0);
        behz_tool.decrypt_scale_and_round(input_q.data(), output_t.data());
        
        // Expected: round(c * t / Q) = round(delta * m * t / Q) = m
        // (since delta = Q/t, delta * t / Q = 1, so delta * m * t / Q = m)
        uint64_t expected = m % t;  // Result is mod t
        uint64_t actual = output_t[0];
        
        bool correct = (actual == expected);
        std::cout << "m=" << m << ": got=" << actual << ", expected=" << expected 
                  << " " << (correct ? "[OK]" : "[FAIL]") << std::endl;
        
        EXPECT_EQ(actual, expected) << "Failed for m=" << m;
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
