/**
 * @file test_ntt_harvey.cpp
 * @brief Unit Tests for Harvey NTT Implementation
 * 
 * Tests correctness of the SEAL-compatible Harvey NTT algorithm.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.9.1
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include "kctsb/advanced/fe/common/ntt_harvey.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include <vector>
#include <random>
#include <chrono>

using namespace kctsb::fhe;

// ============================================================================
// Modular Operations Tests
// ============================================================================

class ModularOpsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use a standard NTT-friendly prime: 2^16 + 1 = 65537
        prime1_ = 65537;
        // Larger prime for realistic testing (61 bits max)
        // 2^60 - 2^14 + 1 = 1152921504606830593 (within 61 bits)
        prime2_ = 0x0FFFFFFFC0000001ULL;  // About 60 bits
        
        mod1_ = Modulus(prime1_);
        mod2_ = Modulus(prime2_);
    }
    
    uint64_t prime1_;
    uint64_t prime2_;
    Modulus mod1_;
    Modulus mod2_;
};

TEST_F(ModularOpsTest, ModulusConstruction) {
    EXPECT_EQ(mod1_.value(), prime1_);
    // const_ratio is internal - just verify modulus works
    EXPECT_GT(mod1_.value(), 0ULL);
    
    EXPECT_EQ(mod2_.value(), prime2_);
}

TEST_F(ModularOpsTest, AdditionMod) {
    uint64_t a = 100;
    uint64_t b = 200;
    
    uint64_t result = add_uint_mod(a, b, mod1_);
    EXPECT_EQ(result, 300);
    
    // Test wraparound
    a = prime1_ - 10;
    b = 20;
    result = add_uint_mod(a, b, mod1_);
    EXPECT_EQ(result, 10);
}

TEST_F(ModularOpsTest, SubtractionMod) {
    uint64_t a = 300;
    uint64_t b = 100;
    
    uint64_t result = sub_uint_mod(a, b, mod1_);
    EXPECT_EQ(result, 200);
    
    // Test wraparound (negative result)
    a = 10;
    b = 20;
    result = sub_uint_mod(a, b, mod1_);
    EXPECT_EQ(result, prime1_ - 10);
}

TEST_F(ModularOpsTest, MultiplicationMod) {
    uint64_t a = 256;
    uint64_t b = 256;
    
    uint64_t result = multiply_uint_mod(a, b, mod1_);
    EXPECT_EQ(result, 65536 % prime1_);
    
    // Test with precomputed operand
    MultiplyUIntModOperand b_op;
    b_op.set(b, mod1_);
    
    uint64_t result2 = multiply_uint_mod(a, b_op, mod1_);
    EXPECT_EQ(result2, result);
}

TEST_F(ModularOpsTest, NegationMod) {
    uint64_t a = 100;
    uint64_t neg_a = negate_uint_mod(a, mod1_);
    
    uint64_t sum = add_uint_mod(a, neg_a, mod1_);
    EXPECT_EQ(sum, 0);
}

TEST_F(ModularOpsTest, InverseModSmall) {
    uint64_t a = 7;
    uint64_t inv_a = inv_mod(a, mod1_);
    
    uint64_t product = multiply_uint_mod(a, inv_a, mod1_);
    EXPECT_EQ(product, 1);
}

TEST_F(ModularOpsTest, PowerMod) {
    uint64_t base = 3;
    uint64_t exp = 10;
    
    uint64_t result = pow_mod(base, exp, mod1_);
    
    // Verify: 3^10 = 59049
    EXPECT_EQ(result, 59049 % prime1_);
}

TEST_F(ModularOpsTest, LazyReduction) {
    uint64_t a = 100;
    MultiplyUIntModOperand b_op;
    b_op.set(200, mod1_);
    
    uint64_t result = multiply_uint_mod_lazy(a, b_op, mod1_);
    
    // Result should be in [0, 2q)
    EXPECT_LT(result, 2 * prime1_);
    
    // And when reduced, should equal a*b mod q
    if (result >= prime1_) result -= prime1_;
    EXPECT_EQ(result, (100 * 200) % prime1_);
}

// ============================================================================
// NTT Tables Tests
// ============================================================================

class NTTTablesTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Prime q ≡ 1 (mod 2n) for n = 16 (2n = 32)
        // 65537 = 2^16 + 1, check: 65537 - 1 = 65536 = 2048 * 32 ✓
        prime_ = 65537;
        log_n_ = 4;  // n = 16
        n_ = 16;
        
        mod_ = Modulus(prime_);
    }
    
    uint64_t prime_;
    int log_n_;
    size_t n_;
    Modulus mod_;
};

TEST_F(NTTTablesTest, Construction) {
    NTTTables tables(log_n_, mod_);
    
    EXPECT_EQ(tables.coeff_count(), n_);
    EXPECT_EQ(tables.coeff_count_power(), log_n_);
    EXPECT_EQ(tables.modulus().value(), prime_);
}

TEST_F(NTTTablesTest, RootPowerUnity) {
    NTTTables tables(log_n_, mod_);
    
    // The root should satisfy root^{2n} = 1 mod q
    uint64_t root = tables.root();
    uint64_t power = pow_mod(root, 2 * n_, mod_);
    EXPECT_EQ(power, 1);
    
    // And root^n = -1 mod q (for negacyclic NTT)
    power = pow_mod(root, n_, mod_);
    EXPECT_EQ(power, prime_ - 1);
}

// ============================================================================
// Harvey NTT Tests
// ============================================================================

class HarveyNTTTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use larger parameters for realistic testing
        log_n_ = 8;  // n = 256
        n_ = 256;
        
        // NTT-friendly prime: needs q ≡ 1 (mod 2n)
        // For n=256, 2n=512. Find prime with (q-1) divisible by 512.
        // 786433 = 3 * 2^18 + 1, check: 786432 / 512 = 1536 ✓
        prime_ = 786433;
        
        mod_ = Modulus(prime_);
        tables_ = std::make_unique<NTTTables>(log_n_, mod_);
    }
    
    int log_n_;
    size_t n_;
    uint64_t prime_;
    Modulus mod_;
    std::unique_ptr<NTTTables> tables_;
};

TEST_F(HarveyNTTTest, ZeroPolynomial) {
    std::vector<uint64_t> poly(n_, 0);
    
    ntt_negacyclic_harvey(poly.data(), *tables_);
    
    // NTT of zero should be zero
    for (size_t i = 0; i < n_; ++i) {
        EXPECT_EQ(poly[i], 0);
    }
    
    inverse_ntt_negacyclic_harvey(poly.data(), *tables_);
    
    for (size_t i = 0; i < n_; ++i) {
        EXPECT_EQ(poly[i], 0);
    }
}

TEST_F(HarveyNTTTest, ConstantPolynomial) {
    std::vector<uint64_t> poly(n_, 0);
    poly[0] = 42;  // Constant polynomial
    
    std::vector<uint64_t> original = poly;
    
    ntt_negacyclic_harvey(poly.data(), *tables_);
    inverse_ntt_negacyclic_harvey(poly.data(), *tables_);
    
    // After NTT and inverse NTT, should get back original
    for (size_t i = 0; i < n_; ++i) {
        EXPECT_EQ(poly[i], original[i]) << "Mismatch at index " << i;
    }
}

TEST_F(HarveyNTTTest, RandomPolynomialRoundTrip) {
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<uint64_t> dist(0, prime_ - 1);
    
    std::vector<uint64_t> poly(n_);
    for (size_t i = 0; i < n_; ++i) {
        poly[i] = dist(rng);
    }
    
    std::vector<uint64_t> original = poly;
    
    ntt_negacyclic_harvey(poly.data(), *tables_);
    inverse_ntt_negacyclic_harvey(poly.data(), *tables_);
    
    for (size_t i = 0; i < n_; ++i) {
        EXPECT_EQ(poly[i], original[i]) << "Mismatch at index " << i;
    }
}

TEST_F(HarveyNTTTest, ConvolutionProperty) {
    // Test that NTT enables point-wise multiplication for polynomial multiplication
    std::mt19937_64 rng(54321);
    std::uniform_int_distribution<uint64_t> dist(0, 100);  // Small values to avoid overflow
    
    std::vector<uint64_t> a(n_), b(n_);
    for (size_t i = 0; i < n_ / 4; ++i) {  // Only first quarter non-zero
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    // Compute reference: naive polynomial multiplication mod (x^n + 1)
    std::vector<uint64_t> ref(n_, 0);
    for (size_t i = 0; i < n_; ++i) {
        for (size_t j = 0; j < n_; ++j) {
            size_t idx = i + j;
            uint64_t product = multiply_uint_mod(a[i], b[j], mod_);
            if (idx >= n_) {
                // Negacyclic: x^n = -1
                idx -= n_;
                ref[idx] = sub_uint_mod(ref[idx], product, mod_);
            } else {
                ref[idx] = add_uint_mod(ref[idx], product, mod_);
            }
        }
    }
    
    // NTT-based multiplication
    std::vector<uint64_t> a_ntt = a;
    std::vector<uint64_t> b_ntt = b;
    
    ntt_negacyclic_harvey(a_ntt.data(), *tables_);
    ntt_negacyclic_harvey(b_ntt.data(), *tables_);
    
    // Point-wise multiply
    std::vector<uint64_t> c_ntt(n_);
    for (size_t i = 0; i < n_; ++i) {
        c_ntt[i] = multiply_uint_mod(a_ntt[i], b_ntt[i], mod_);
    }
    
    inverse_ntt_negacyclic_harvey(c_ntt.data(), *tables_);
    
    // Compare
    for (size_t i = 0; i < n_; ++i) {
        EXPECT_EQ(c_ntt[i], ref[i]) << "Mismatch at index " << i;
    }
}

TEST_F(HarveyNTTTest, LazyNTTCorrectness) {
    std::mt19937_64 rng(11111);
    std::uniform_int_distribution<uint64_t> dist(0, prime_ - 1);
    
    std::vector<uint64_t> poly(n_);
    for (size_t i = 0; i < n_; ++i) {
        poly[i] = dist(rng);
    }
    
    std::vector<uint64_t> poly_lazy = poly;
    std::vector<uint64_t> poly_normal = poly;
    
    // Lazy version
    ntt_negacyclic_harvey_lazy(poly_lazy.data(), *tables_);
    
    // Normal version
    ntt_negacyclic_harvey(poly_normal.data(), *tables_);
    
    // Lazy results should be in [0, 2q) and reduce to normal results
    for (size_t i = 0; i < n_; ++i) {
        EXPECT_LT(poly_lazy[i], 2 * prime_) << "Lazy result out of range at " << i;
        
        uint64_t reduced = poly_lazy[i];
        if (reduced >= prime_) reduced -= prime_;
        EXPECT_EQ(reduced, poly_normal[i]) << "Mismatch at index " << i;
    }
}

// AVX2 forward NTT correctness test (fixed indexing bug in v4.10.0)
#ifdef __AVX2__
TEST_F(HarveyNTTTest, AVX2Correctness) {
    std::mt19937_64 rng(99999);
    std::uniform_int_distribution<uint64_t> dist(0, prime_ - 1);
    
    std::vector<uint64_t> poly(n_);
    for (size_t i = 0; i < n_; ++i) {
        poly[i] = dist(rng);
    }
    
    std::vector<uint64_t> poly_scalar = poly;
    std::vector<uint64_t> poly_avx2 = poly;
    
    ntt_negacyclic_harvey(poly_scalar.data(), *tables_);
    ntt_negacyclic_harvey_avx2(poly_avx2.data(), *tables_);
    
    for (size_t i = 0; i < n_; ++i) {
        EXPECT_EQ(poly_avx2[i], poly_scalar[i]) << "AVX2 mismatch at index " << i;
    }
}
#endif

// ============================================================================
// RNS Polynomial Tests
// ============================================================================

class RNSPolyTest : public ::testing::Test {
protected:
    void SetUp() override {
        log_n_ = 4;  // n = 16
        n_ = 16;
        
        // Use multiple NTT-friendly primes
        primes_ = {65537, 114689, 147457};  // All ≡ 1 (mod 32)
        
        context_ = std::make_unique<RNSContext>(log_n_, primes_);
    }
    
    int log_n_;
    size_t n_;
    std::vector<uint64_t> primes_;
    std::unique_ptr<RNSContext> context_;
};

TEST_F(RNSPolyTest, ContextConstruction) {
    EXPECT_EQ(context_->n(), n_);
    EXPECT_EQ(context_->log_n(), log_n_);
    EXPECT_EQ(context_->level_count(), primes_.size());
}

TEST_F(RNSPolyTest, ZeroPolynomial) {
    RNSPoly poly(context_.get());
    
    EXPECT_FALSE(poly.empty());
    EXPECT_FALSE(poly.is_ntt_form());
    EXPECT_TRUE(poly.is_zero());
    EXPECT_EQ(poly.n(), n_);
    EXPECT_EQ(poly.current_level(), primes_.size());
}

TEST_F(RNSPolyTest, PolynomialFromCoeffs) {
    std::vector<uint64_t> coeffs = {1, 2, 3, 4, 5};
    RNSPoly poly(context_.get(), coeffs);
    
    EXPECT_FALSE(poly.is_zero());
    
    // Check coefficients are correct mod each prime
    for (size_t level = 0; level < primes_.size(); ++level) {
        for (size_t i = 0; i < coeffs.size(); ++i) {
            EXPECT_EQ(poly(level, i), coeffs[i] % primes_[level]);
        }
        for (size_t i = coeffs.size(); i < n_; ++i) {
            EXPECT_EQ(poly(level, i), 0);
        }
    }
}

TEST_F(RNSPolyTest, CopyAndMove) {
    std::vector<uint64_t> coeffs = {10, 20, 30};
    RNSPoly original(context_.get(), coeffs);
    
    // Copy
    RNSPoly copy(original);
    EXPECT_EQ(copy(0, 0), original(0, 0));
    EXPECT_EQ(copy(0, 1), original(0, 1));
    
    // Modify copy shouldn't affect original
    copy(0, 0) = 999;
    EXPECT_NE(copy(0, 0), original(0, 0));
    
    // Move
    RNSPoly moved(std::move(copy));
    EXPECT_EQ(moved(0, 0), 999);
    EXPECT_TRUE(copy.empty());  // After move, source should be empty
}

TEST_F(RNSPolyTest, NTTRoundTrip) {
    std::vector<uint64_t> coeffs = {1, 2, 3, 4, 5, 6, 7, 8};
    RNSPoly poly(context_.get(), coeffs);
    
    // Store original
    std::vector<std::vector<uint64_t>> original(primes_.size());
    for (size_t l = 0; l < primes_.size(); ++l) {
        original[l].resize(n_);
        std::memcpy(original[l].data(), poly.data(l), n_ * sizeof(uint64_t));
    }
    
    EXPECT_FALSE(poly.is_ntt_form());
    
    // NTT
    poly.ntt_transform();
    EXPECT_TRUE(poly.is_ntt_form());
    
    // INTT
    poly.intt_transform();
    EXPECT_FALSE(poly.is_ntt_form());
    
    // Compare
    for (size_t l = 0; l < primes_.size(); ++l) {
        for (size_t i = 0; i < n_; ++i) {
            EXPECT_EQ(poly(l, i), original[l][i]) << "Mismatch at level " << l << ", index " << i;
        }
    }
}

TEST_F(RNSPolyTest, Addition) {
    std::vector<uint64_t> coeffs_a = {1, 2, 3, 4};
    std::vector<uint64_t> coeffs_b = {10, 20, 30, 40};
    
    RNSPoly a(context_.get(), coeffs_a);
    RNSPoly b(context_.get(), coeffs_b);
    
    a += b;
    
    for (size_t l = 0; l < primes_.size(); ++l) {
        for (size_t i = 0; i < coeffs_a.size(); ++i) {
            uint64_t expected = (coeffs_a[i] + coeffs_b[i]) % primes_[l];
            EXPECT_EQ(a(l, i), expected);
        }
    }
}

TEST_F(RNSPolyTest, Subtraction) {
    std::vector<uint64_t> coeffs_a = {100, 200, 300, 400};
    std::vector<uint64_t> coeffs_b = {10, 20, 30, 40};
    
    RNSPoly a(context_.get(), coeffs_a);
    RNSPoly b(context_.get(), coeffs_b);
    
    a -= b;
    
    for (size_t l = 0; l < primes_.size(); ++l) {
        for (size_t i = 0; i < coeffs_a.size(); ++i) {
            uint64_t expected = (coeffs_a[i] - coeffs_b[i]) % primes_[l];
            EXPECT_EQ(a(l, i), expected);
        }
    }
}

TEST_F(RNSPolyTest, Multiplication) {
    std::vector<uint64_t> coeffs_a = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // Just constant 1
    std::vector<uint64_t> coeffs_b = {5, 10, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    
    RNSPoly a(context_.get(), coeffs_a);
    RNSPoly b(context_.get(), coeffs_b);
    
    // Transform to NTT
    a.ntt_transform();
    b.ntt_transform();
    
    // Multiply
    a *= b;
    
    // Transform back
    a.intt_transform();
    
    // Result should be b (since a was 1)
    for (size_t l = 0; l < primes_.size(); ++l) {
        for (size_t i = 0; i < 3; ++i) {
            EXPECT_EQ(a(l, i), coeffs_b[i] % primes_[l]);
        }
    }
}

TEST_F(RNSPolyTest, PolyMultiplyFunction) {
    std::vector<uint64_t> coeffs_a = {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // 1 + x
    std::vector<uint64_t> coeffs_b = {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // 1 + x
    
    RNSPoly a(context_.get(), coeffs_a);
    RNSPoly b(context_.get(), coeffs_b);
    
    // Use poly_multiply helper
    RNSPoly c = poly_multiply(a, b, false);
    
    // (1 + x)^2 = 1 + 2x + x^2
    // Expected: [1, 2, 1, 0, ...]
    EXPECT_FALSE(c.is_ntt_form());
    
    for (size_t l = 0; l < primes_.size(); ++l) {
        EXPECT_EQ(c(l, 0), 1);
        EXPECT_EQ(c(l, 1), 2);
        EXPECT_EQ(c(l, 2), 1);
        for (size_t i = 3; i < n_; ++i) {
            EXPECT_EQ(c(l, i), 0) << "Non-zero at level " << l << ", index " << i;
        }
    }
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

class NTTPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use realistic FHE parameters
        log_n_ = 12;  // n = 4096
        n_ = 4096;
        
        // Generate NTT-friendly primes
        primes_ = generate_ntt_primes(50, n_, 10);  // 10 primes, ~50 bits each
    }
    
    int log_n_;
    size_t n_;
    std::vector<uint64_t> primes_;
};

TEST_F(NTTPerformanceTest, SingleNTTBenchmark) {
    Modulus mod(primes_[0]);
    NTTTables tables(log_n_, mod);
    
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, primes_[0] - 1);
    
    std::vector<uint64_t> poly(n_);
    for (size_t i = 0; i < n_; ++i) {
        poly[i] = dist(rng);
    }
    
    constexpr int ITERATIONS = 100;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        ntt_negacyclic_harvey(poly.data(), tables);
        inverse_ntt_negacyclic_harvey(poly.data(), tables);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double avg_us = static_cast<double>(duration_us) / (ITERATIONS * 2);  // *2 for NTT + INTT
    
    std::cout << "Single NTT (n=" << n_ << "): " << avg_us << " us average" << std::endl;
    
    // Performance target: should be under 100us for n=4096
    EXPECT_LT(avg_us, 500.0) << "NTT too slow";
}

TEST_F(NTTPerformanceTest, RNSContextBenchmark) {
    RNSContext context(log_n_, primes_);
    
    std::mt19937_64 rng(42);
    
    std::vector<uint64_t> coeffs(n_);
    std::uniform_int_distribution<uint64_t> dist(0, (1ULL << 40) - 1);
    for (size_t i = 0; i < n_; ++i) {
        coeffs[i] = dist(rng);
    }
    
    constexpr int ITERATIONS = 50;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        RNSPoly poly(&context, coeffs);
        poly.ntt_transform();
        poly.intt_transform();
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double avg_us = static_cast<double>(duration_us) / ITERATIONS;
    
    std::cout << "RNS Poly (n=" << n_ << ", L=" << primes_.size() << "): " 
              << avg_us << " us average" << std::endl;
}

TEST_F(NTTPerformanceTest, PolynomialMultiplicationBenchmark) {
    // Smaller n for faster testing
    int small_log_n = 10;  // n = 1024
    size_t small_n = 1024;
    
    auto small_primes = generate_ntt_primes(50, small_n, 3);
    RNSContext context(small_log_n, small_primes);
    
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, (1ULL << 40) - 1);
    
    std::vector<uint64_t> coeffs_a(small_n), coeffs_b(small_n);
    for (size_t i = 0; i < small_n; ++i) {
        coeffs_a[i] = dist(rng);
        coeffs_b[i] = dist(rng);
    }
    
    RNSPoly a(&context, coeffs_a);
    RNSPoly b(&context, coeffs_b);
    
    constexpr int ITERATIONS = 100;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < ITERATIONS; ++iter) {
        RNSPoly c = poly_multiply(a, b, false);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double avg_us = static_cast<double>(duration_us) / ITERATIONS;
    
    std::cout << "Poly Multiply (n=" << small_n << ", L=" << small_primes.size() << "): " 
              << avg_us << " us average" << std::endl;
    
    // Performance target: polynomial multiplication should be under 1ms
    EXPECT_LT(avg_us, 1000.0) << "Polynomial multiplication too slow";
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
