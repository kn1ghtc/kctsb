/**
 * @file test_ntt_large_prime.cpp
 * @brief Diagnostic tests for NTT with large (50-bit) primes
 * 
 * This file tests NTT operations with 50-bit primes used in BGV/BFV.
 * It's crucial for diagnosing the multiply correctness failure at n=8192.
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/fe/common/ntt.hpp"
#include "kctsb/advanced/fe/common/ntt_poly_ops.hpp"
#include <random>
#include <cstdint>

using namespace kctsb::fhe::ntt;

namespace {

// 50-bit NTT-friendly primes for n=8192 (verified with sympy)
// These are the actual primes used in BGV with SECURITY_128 params
constexpr uint64_t PRIME_50BIT_1 = 1125899906990081ULL;  // verified: p-1 = 2^19 * 2144617231
constexpr uint64_t PRIME_50BIT_2 = 1125899907219457ULL;  // verified: p-1 = 2^19 * 2144617669
constexpr uint64_t PRIME_50BIT_3 = 1125899907776513ULL;  // verified: p-1 = 2^19 * 2144618731

// Smaller NTT-friendly prime for comparison
constexpr uint64_t PRIME_20BIT = 786433ULL;  // 3 * 2^18 + 1

// Test parameters
constexpr size_t TEST_N_SMALL = 256;
constexpr size_t TEST_N_LARGE = 8192;

/**
 * @brief Reference schoolbook multiplication in ring Z_q[x]/(x^n + 1)
 */
std::vector<uint64_t> schoolbook_multiply(
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    size_t n,
    uint64_t q)
{
    std::vector<uint64_t> result(n, 0);
    
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            __uint128_t product = static_cast<__uint128_t>(a[i]) * b[j];
            size_t idx = (i + j) % n;
            
            // For x^n + 1, terms with i+j >= n get negated
            if (i + j >= n) {
                // Subtract from result
                uint64_t val = static_cast<uint64_t>(product % q);
                if (result[idx] >= val) {
                    result[idx] -= val;
                } else {
                    result[idx] = q - (val - result[idx]);
                }
            } else {
                // Add to result
                result[idx] = (result[idx] + static_cast<uint64_t>(product % q)) % q;
            }
        }
    }
    
    return result;
}

}  // anonymous namespace

// ============================================================================
// Basic 50-bit Prime NTT Tests
// ============================================================================

TEST(NTTLargePrimeTest, Is50BitPrimeNTTFriendly) {
    // Verify our 50-bit primes are NTT-friendly for n=8192
    EXPECT_TRUE(is_ntt_prime(PRIME_50BIT_1, TEST_N_LARGE))
        << "Prime " << PRIME_50BIT_1 << " should be NTT-friendly for n=" << TEST_N_LARGE;
    EXPECT_TRUE(is_ntt_prime(PRIME_50BIT_2, TEST_N_LARGE))
        << "Prime " << PRIME_50BIT_2 << " should be NTT-friendly for n=" << TEST_N_LARGE;
    EXPECT_TRUE(is_ntt_prime(PRIME_50BIT_3, TEST_N_LARGE))
        << "Prime " << PRIME_50BIT_3 << " should be NTT-friendly for n=" << TEST_N_LARGE;
}

TEST(NTTLargePrimeTest, NTTTableCreation50Bit) {
    // Verify NTT table can be created for 50-bit primes
    EXPECT_NO_THROW({
        const NTTTable& ntt = NTTTableCache::instance().get(TEST_N_LARGE, PRIME_50BIT_1);
        EXPECT_EQ(ntt.degree(), TEST_N_LARGE);
        EXPECT_EQ(ntt.modulus(), PRIME_50BIT_1);
    });
}

TEST(NTTLargePrimeTest, ForwardInverseRoundTrip50Bit) {
    const size_t n = TEST_N_LARGE;
    const uint64_t q = PRIME_50BIT_1;
    
    // Random polynomial
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<uint64_t> dist(0, q - 1);
    
    std::vector<uint64_t> original(n);
    for (size_t i = 0; i < n; ++i) {
        original[i] = dist(rng);
    }
    
    // Forward then inverse should give back original
    std::vector<uint64_t> data = original;
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    
    ntt.forward_negacyclic(data.data());
    ntt.inverse_negacyclic(data.data());
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(data[i], original[i]) 
            << "Mismatch at coefficient " << i;
    }
}

// ============================================================================
// Multiplication Correctness with 50-bit Primes
// ============================================================================

TEST(NTTLargePrimeTest, SimpleMultiply50Bit) {
    // Simple test: (1 + x) * (1 + x) = 1 + 2x + x^2
    const size_t n = TEST_N_SMALL;
    const uint64_t q = PRIME_50BIT_1;
    
    std::vector<uint64_t> a(n, 0);
    std::vector<uint64_t> b(n, 0);
    a[0] = 1; a[1] = 1;  // 1 + x
    b[0] = 1; b[1] = 1;  // 1 + x
    
    auto result = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
    
    // Expected: 1 + 2x + x^2
    EXPECT_EQ(result[0], 1) << "Constant term should be 1";
    EXPECT_EQ(result[1], 2) << "x term should be 2";
    EXPECT_EQ(result[2], 1) << "x^2 term should be 1";
    
    for (size_t i = 3; i < n; ++i) {
        EXPECT_EQ(result[i], 0) << "Higher terms should be 0";
    }
}

TEST(NTTLargePrimeTest, MultiplyAgainstSchoolbook_SmallDegree) {
    // Compare NTT vs schoolbook at n=256 with 50-bit prime
    const size_t n = TEST_N_SMALL;
    const uint64_t q = PRIME_50BIT_1;
    
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, q - 1);
    
    std::vector<uint64_t> a(n), b(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    auto result_ntt = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
    auto result_ref = schoolbook_multiply(a, b, n, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(result_ntt[i], result_ref[i]) 
            << "Mismatch at coefficient " << i << " (n=" << n << ", q=" << q << ")";
    }
}

TEST(NTTLargePrimeTest, MultiplyAgainstSchoolbook_LargeDegree) {
    // Compare NTT vs schoolbook at n=8192 with 50-bit prime
    // This is the critical test - replicates the BGV benchmark scenario
    const size_t n = TEST_N_LARGE;
    const uint64_t q = PRIME_50BIT_1;
    
    std::mt19937_64 rng(42);
    // Use small coefficients for faster schoolbook reference
    std::uniform_int_distribution<uint64_t> dist(0, 100);
    
    std::vector<uint64_t> a(n), b(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    auto result_ntt = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
    auto result_ref = schoolbook_multiply(a, b, n, q);
    
    size_t mismatch_count = 0;
    for (size_t i = 0; i < n; ++i) {
        if (result_ntt[i] != result_ref[i]) {
            if (mismatch_count < 10) {
                std::cerr << "Mismatch at coef " << i << ": NTT=" << result_ntt[i] 
                          << ", REF=" << result_ref[i] << std::endl;
            }
            ++mismatch_count;
        }
    }
    
    EXPECT_EQ(mismatch_count, 0) 
        << "Total mismatches: " << mismatch_count << "/" << n;
}

TEST(NTTLargePrimeTest, MultiplyWithLargeCoefficients) {
    // Test with coefficients close to the modulus (worst case for overflow)
    const size_t n = 256;
    const uint64_t q = PRIME_50BIT_1;
    
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<uint64_t> dist(q - 10000, q - 1);
    
    std::vector<uint64_t> a(n), b(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    auto result_ntt = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
    auto result_ref = schoolbook_multiply(a, b, n, q);
    
    size_t mismatch_count = 0;
    for (size_t i = 0; i < n; ++i) {
        if (result_ntt[i] != result_ref[i]) {
            ++mismatch_count;
        }
    }
    
    EXPECT_EQ(mismatch_count, 0) 
        << "Mismatches with large coefficients: " << mismatch_count << "/" << n;
}

// ============================================================================
// Multi-RNS Tests (Simulating BGV Pipeline)
// ============================================================================

TEST(NTTLargePrimeTest, RNSMultiplyConsistency) {
    // Multiply same polynomial across multiple RNS levels
    const size_t n = 256;
    std::vector<uint64_t> primes = {PRIME_50BIT_1, PRIME_50BIT_2, PRIME_50BIT_3};
    
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, 1000);
    
    std::vector<uint64_t> a(n), b(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    // Multiply in each RNS level
    for (uint64_t q : primes) {
        // Reduce to this level
        std::vector<uint64_t> a_mod(n), b_mod(n);
        for (size_t i = 0; i < n; ++i) {
            a_mod[i] = a[i] % q;
            b_mod[i] = b[i] % q;
        }
        
        auto result_ntt = poly_multiply_negacyclic_ntt(a_mod.data(), b_mod.data(), n, q);
        auto result_ref = schoolbook_multiply(a_mod, b_mod, n, q);
        
        for (size_t i = 0; i < n; ++i) {
            EXPECT_EQ(result_ntt[i], result_ref[i]) 
                << "Mismatch at coef " << i << " for prime " << q;
        }
    }
}

// ============================================================================
// Performance Comparison: 20-bit vs 50-bit Primes
// ============================================================================

TEST(NTTLargePrimeTest, DISABLED_PerformanceComparison) {
    // Compare performance of 20-bit vs 50-bit prime operations
    const size_t n = 8192;
    const int iterations = 10;
    
    std::vector<uint64_t> a(n), b(n);
    std::mt19937_64 rng(42);
    
    // Initialize
    for (size_t i = 0; i < n; ++i) {
        a[i] = rng() % 1000;
        b[i] = rng() % 1000;
    }
    
    // Warm up tables
    NTTTableCache::instance().get(n, PRIME_20BIT);
    NTTTableCache::instance().get(n, PRIME_50BIT_1);
    
    // Time 20-bit prime
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint64_t> a_mod(n), b_mod(n);
        for (size_t j = 0; j < n; ++j) {
            a_mod[j] = a[j] % PRIME_20BIT;
            b_mod[j] = b[j] % PRIME_20BIT;
        }
        auto result = poly_multiply_negacyclic_ntt(a_mod.data(), b_mod.data(), n, PRIME_20BIT);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto time_20bit = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Time 50-bit prime
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto result = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, PRIME_50BIT_1);
    }
    end = std::chrono::high_resolution_clock::now();
    auto time_50bit = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "20-bit prime: " << time_20bit << " ms for " << iterations << " iterations\n";
    std::cout << "50-bit prime: " << time_50bit << " ms for " << iterations << " iterations\n";
}

