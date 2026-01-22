/**
 * @file test_ntt_poly_ops.cpp
 * @brief Unit tests for NTT-Accelerated Polynomial Operations
 * 
 * Tests the high-level polynomial operation interface that bridges
 * between coefficient domain and NTT domain operations.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/fe/common/ntt_poly_ops.hpp"
#include <algorithm>
#include <numeric>
#include <random>
#include <chrono>

namespace kctsb {
namespace fhe {
namespace ntt {
namespace test {

// ============================================================================
// Test Fixture
// ============================================================================

class NTTPolyOpsTest : public ::testing::Test {
protected:
    // Standard NTT-friendly primes for testing
    static constexpr uint64_t Q_SMALL = 65537;       // 2^16 + 1, Fermat prime
    static constexpr uint64_t Q_MEDIUM = 786433;     // 3 * 2^18 + 1
    static constexpr uint64_t Q_LARGE = 12289;       // 3 * 2^12 + 1
    
    // Standard polynomial degrees
    static constexpr size_t N_16 = 16;
    static constexpr size_t N_64 = 64;
    static constexpr size_t N_256 = 256;
    
    std::mt19937_64 rng;
    
    void SetUp() override {
        rng.seed(42);
    }
    
    std::vector<uint64_t> random_poly(size_t n, uint64_t q) {
        std::vector<uint64_t> poly(n);
        std::uniform_int_distribution<uint64_t> dist(0, q - 1);
        for (size_t i = 0; i < n; ++i) {
            poly[i] = dist(rng);
        }
        return poly;
    }
    
    std::vector<uint64_t> zero_poly(size_t n) {
        return std::vector<uint64_t>(n, 0);
    }
    
    std::vector<uint64_t> one_poly(size_t n) {
        std::vector<uint64_t> poly(n, 0);
        poly[0] = 1;
        return poly;
    }
    
    // Schoolbook multiplication in ring R_q = Z_q[x]/(x^n + 1)
    std::vector<uint64_t> schoolbook_negacyclic(
        const std::vector<uint64_t>& a,
        const std::vector<uint64_t>& b,
        uint64_t q)
    {
        size_t n = a.size();
        std::vector<uint64_t> result(n, 0);
        
        for (size_t i = 0; i < n; ++i) {
            for (size_t j = 0; j < n; ++j) {
                size_t idx = i + j;
                __uint128_t prod = static_cast<__uint128_t>(a[i]) * b[j];
                prod %= q;
                
                if (idx >= n) {
                    // x^n = -1 in x^n + 1
                    result[idx - n] = (result[idx - n] + q - static_cast<uint64_t>(prod)) % q;
                } else {
                    result[idx] = (result[idx] + static_cast<uint64_t>(prod)) % q;
                }
            }
        }
        
        return result;
    }
};

// ============================================================================
// Basic Multiply Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_Identity) {
    // Multiplying by 1 should give the same polynomial
    auto a = random_poly(N_16, Q_SMALL);
    auto one = one_poly(N_16);
    
    auto result = multiply_poly_ntt(a, one, N_16, Q_SMALL);
    
    EXPECT_EQ(result, a);
}

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_Zero) {
    // Multiplying by 0 should give zero
    auto a = random_poly(N_16, Q_SMALL);
    auto zero = zero_poly(N_16);
    
    auto result = multiply_poly_ntt(a, zero, N_16, Q_SMALL);
    
    EXPECT_EQ(result, zero);
}

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_Commutativity) {
    // a * b = b * a
    auto a = random_poly(N_64, Q_MEDIUM);
    auto b = random_poly(N_64, Q_MEDIUM);
    
    auto ab = multiply_poly_ntt(a, b, N_64, Q_MEDIUM);
    auto ba = multiply_poly_ntt(b, a, N_64, Q_MEDIUM);
    
    EXPECT_EQ(ab, ba);
}

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_VsSchoolbook) {
    // NTT result should match schoolbook multiplication
    auto a = random_poly(N_16, Q_SMALL);
    auto b = random_poly(N_16, Q_SMALL);
    
    auto ntt_result = multiply_poly_ntt(a, b, N_16, Q_SMALL);
    auto schoolbook_result = schoolbook_negacyclic(a, b, Q_SMALL);
    
    EXPECT_EQ(ntt_result, schoolbook_result);
}

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_VsSchoolbook_LargerDegree) {
    // Test with n=64
    auto a = random_poly(N_64, Q_MEDIUM);
    auto b = random_poly(N_64, Q_MEDIUM);
    
    auto ntt_result = multiply_poly_ntt(a, b, N_64, Q_MEDIUM);
    auto schoolbook_result = schoolbook_negacyclic(a, b, Q_MEDIUM);
    
    EXPECT_EQ(ntt_result, schoolbook_result);
}

// ============================================================================
// Inplace Multiply Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, MultiplyPolyNTTInplace_CorrectResult) {
    auto a = random_poly(N_16, Q_SMALL);
    auto a_copy = a;
    auto b = random_poly(N_16, Q_SMALL);
    
    auto expected = multiply_poly_ntt(a, b, N_16, Q_SMALL);
    multiply_poly_ntt_inplace(a_copy, b, Q_SMALL);
    
    EXPECT_EQ(a_copy, expected);
}

// ============================================================================
// Arithmetic Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, AddPolyMod_BasicAddition) {
    std::vector<uint64_t> a = {1, 2, 3, 4};
    std::vector<uint64_t> b = {5, 6, 7, 8};
    std::vector<uint64_t> result;
    uint64_t q = 17;
    
    add_poly_mod(result, a, b, q);
    
    std::vector<uint64_t> expected = {6, 8, 10, 12};
    EXPECT_EQ(result, expected);
}

TEST_F(NTTPolyOpsTest, AddPolyMod_Wraparound) {
    std::vector<uint64_t> a = {15, 16, 10, 12};
    std::vector<uint64_t> b = {5, 3, 8, 9};
    std::vector<uint64_t> result;
    uint64_t q = 17;
    
    add_poly_mod(result, a, b, q);
    
    // 15+5=20 mod 17=3, 16+3=19 mod 17=2, 10+8=18 mod 17=1, 12+9=21 mod 17=4
    std::vector<uint64_t> expected = {3, 2, 1, 4};
    EXPECT_EQ(result, expected);
}

TEST_F(NTTPolyOpsTest, SubPolyMod_BasicSubtraction) {
    std::vector<uint64_t> a = {10, 15, 8, 12};
    std::vector<uint64_t> b = {3, 5, 2, 4};
    std::vector<uint64_t> result;
    uint64_t q = 17;
    
    sub_poly_mod(result, a, b, q);
    
    std::vector<uint64_t> expected = {7, 10, 6, 8};
    EXPECT_EQ(result, expected);
}

TEST_F(NTTPolyOpsTest, SubPolyMod_Wraparound) {
    std::vector<uint64_t> a = {3, 5, 2, 1};
    std::vector<uint64_t> b = {10, 8, 7, 6};
    std::vector<uint64_t> result;
    uint64_t q = 17;
    
    sub_poly_mod(result, a, b, q);
    
    // 3-10 mod 17 = -7 mod 17 = 10, etc.
    std::vector<uint64_t> expected = {10, 14, 12, 12};
    EXPECT_EQ(result, expected);
}

TEST_F(NTTPolyOpsTest, NegatePolyMod) {
    std::vector<uint64_t> poly = {0, 5, 10, 16};
    uint64_t q = 17;
    
    negate_poly_mod(poly, q);
    
    // 0->0, 5->12, 10->7, 16->1
    std::vector<uint64_t> expected = {0, 12, 7, 1};
    EXPECT_EQ(poly, expected);
}

TEST_F(NTTPolyOpsTest, ScalarMulPolyMod) {
    std::vector<uint64_t> poly = {1, 2, 3, 4};
    uint64_t scalar = 5;
    uint64_t q = 17;
    
    scalar_mul_poly_mod(poly, scalar, q);
    
    // 1*5=5, 2*5=10, 3*5=15, 4*5=20 mod 17=3
    std::vector<uint64_t> expected = {5, 10, 15, 3};
    EXPECT_EQ(poly, expected);
}

// ============================================================================
// NTT Form Conversion Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, ToFromNTTForm_Roundtrip) {
    auto poly = random_poly(N_16, Q_SMALL);
    auto original = poly;
    
    // Convert to NTT form
    to_ntt_form(poly, N_16, Q_SMALL);
    
    // Should be different from original (unless very special case)
    // This is probabilistic but extremely unlikely to fail
    
    // Convert back
    from_ntt_form(poly, N_16, Q_SMALL);
    
    EXPECT_EQ(poly, original);
}

TEST_F(NTTPolyOpsTest, NTTForm_MultiplicationEquivalence) {
    auto a = random_poly(N_64, Q_MEDIUM);
    auto b = random_poly(N_64, Q_MEDIUM);
    
    // Method 1: High-level API
    auto result1 = multiply_poly_ntt(a, b, N_64, Q_MEDIUM);
    
    // Method 2: Manual NTT form conversion
    auto a_ntt = a;
    auto b_ntt = b;
    to_ntt_form(a_ntt, N_64, Q_MEDIUM);
    to_ntt_form(b_ntt, N_64, Q_MEDIUM);
    
    // Pointwise multiplication in NTT domain
    std::vector<uint64_t> c_ntt(N_64);
    for (size_t i = 0; i < N_64; ++i) {
        c_ntt[i] = mul_mod_slow(a_ntt[i], b_ntt[i], Q_MEDIUM);
    }
    
    from_ntt_form(c_ntt, N_64, Q_MEDIUM);
    
    EXPECT_EQ(result1, c_ntt);
}

// ============================================================================
// RNS Batch Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_RNS_TwoModuli) {
    std::vector<uint64_t> moduli = {Q_SMALL, Q_MEDIUM};
    size_t n = N_16;
    
    std::vector<std::vector<uint64_t>> a(2), b(2);
    for (size_t level = 0; level < 2; ++level) {
        a[level] = random_poly(n, moduli[level]);
        b[level] = random_poly(n, moduli[level]);
    }
    
    auto result = multiply_poly_ntt_rns(a, b, n, moduli);
    
    // Verify each level
    for (size_t level = 0; level < 2; ++level) {
        auto expected = multiply_poly_ntt(a[level], b[level], n, moduli[level]);
        EXPECT_EQ(result[level], expected);
    }
}

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_RNS_ThreeModuli) {
    std::vector<uint64_t> moduli = {Q_SMALL, Q_MEDIUM, Q_LARGE};
    size_t n = N_16;
    
    std::vector<std::vector<uint64_t>> a(3), b(3);
    for (size_t level = 0; level < 3; ++level) {
        a[level] = random_poly(n, moduli[level]);
        b[level] = random_poly(n, moduli[level]);
    }
    
    auto result = multiply_poly_ntt_rns(a, b, n, moduli);
    
    EXPECT_EQ(result.size(), 3u);
    
    for (size_t level = 0; level < 3; ++level) {
        auto expected = schoolbook_negacyclic(a[level], b[level], moduli[level]);
        EXPECT_EQ(result[level], expected);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_SizeMismatch) {
    auto a = random_poly(16, Q_SMALL);
    auto b = random_poly(32, Q_SMALL);
    
    EXPECT_THROW(multiply_poly_ntt(a, b, 16, Q_SMALL), std::invalid_argument);
}

TEST_F(NTTPolyOpsTest, MultiplyPolyNTT_WrongDegree) {
    auto a = random_poly(32, Q_SMALL);
    auto b = random_poly(32, Q_SMALL);
    
    // Pass wrong n
    EXPECT_THROW(multiply_poly_ntt(a, b, 16, Q_SMALL), std::invalid_argument);
}

TEST_F(NTTPolyOpsTest, AddPolyMod_SizeMismatch) {
    std::vector<uint64_t> a = {1, 2, 3};
    std::vector<uint64_t> b = {1, 2, 3, 4};
    std::vector<uint64_t> result;
    
    EXPECT_THROW(add_poly_mod(result, a, b, Q_SMALL), std::invalid_argument);
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, Performance_NTTVsSchoolbook_N256) {
    auto a = random_poly(N_256, Q_MEDIUM);
    auto b = random_poly(N_256, Q_MEDIUM);
    
    const int iterations = 100;
    
    // NTT timing
    auto start_ntt = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto result = multiply_poly_ntt(a, b, N_256, Q_MEDIUM);
        (void)result;
    }
    auto end_ntt = std::chrono::high_resolution_clock::now();
    auto ntt_time = std::chrono::duration_cast<std::chrono::microseconds>(end_ntt - start_ntt).count();
    
    // Schoolbook timing (fewer iterations due to O(n^2))
    auto start_sb = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations / 10; ++i) {
        auto result = schoolbook_negacyclic(a, b, Q_MEDIUM);
        (void)result;
    }
    auto end_sb = std::chrono::high_resolution_clock::now();
    auto sb_time = std::chrono::duration_cast<std::chrono::microseconds>(end_sb - start_sb).count();
    
    // Scale schoolbook time to same iterations
    sb_time *= 10;
    
    std::cout << "N=256 Multiply Performance (" << iterations << " iterations):" << std::endl;
    std::cout << "  NTT:       " << ntt_time << " us" << std::endl;
    std::cout << "  Schoolbook: " << sb_time << " us" << std::endl;
    std::cout << "  Speedup:   " << static_cast<double>(sb_time) / ntt_time << "x" << std::endl;
    
    // NTT should be faster (at least 2x for n=256)
    EXPECT_LT(ntt_time, sb_time);
}

// ============================================================================
// Distribution Tests
// ============================================================================

TEST_F(NTTPolyOpsTest, Associativity) {
    // (a * b) * c = a * (b * c)
    auto a = random_poly(N_16, Q_SMALL);
    auto b = random_poly(N_16, Q_SMALL);
    auto c = random_poly(N_16, Q_SMALL);
    
    auto ab = multiply_poly_ntt(a, b, N_16, Q_SMALL);
    auto ab_c = multiply_poly_ntt(ab, c, N_16, Q_SMALL);
    
    auto bc = multiply_poly_ntt(b, c, N_16, Q_SMALL);
    auto a_bc = multiply_poly_ntt(a, bc, N_16, Q_SMALL);
    
    EXPECT_EQ(ab_c, a_bc);
}

TEST_F(NTTPolyOpsTest, Distributivity) {
    // a * (b + c) = a*b + a*c
    auto a = random_poly(N_16, Q_SMALL);
    auto b = random_poly(N_16, Q_SMALL);
    auto c = random_poly(N_16, Q_SMALL);
    
    // Left side: a * (b + c)
    std::vector<uint64_t> b_plus_c;
    add_poly_mod(b_plus_c, b, c, Q_SMALL);
    auto left = multiply_poly_ntt(a, b_plus_c, N_16, Q_SMALL);
    
    // Right side: a*b + a*c
    auto ab = multiply_poly_ntt(a, b, N_16, Q_SMALL);
    auto ac = multiply_poly_ntt(a, c, N_16, Q_SMALL);
    std::vector<uint64_t> right;
    add_poly_mod(right, ab, ac, Q_SMALL);
    
    EXPECT_EQ(left, right);
}

}  // namespace test
}  // namespace ntt
}  // namespace fhe
}  // namespace kctsb
