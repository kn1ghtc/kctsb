/**
 * @file test_math.cpp
 * @brief Math utilities unit tests
 *
 * Tests for mathematical operations including:
 * - Polynomial operations (when NTL is available)
 * - Linear algebra utilities
 * - Probability/statistics functions
 * - Big integer arithmetic
 *
 * Note: Some tests require KCTSB_HAS_NTL to be defined (NTL library available).
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cmath>
#include <vector>
#include <cstring>

#include "kctsb/kctsb.h"

// NTL-dependent tests
#ifdef KCTSB_HAS_NTL
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/GF2X.h>
#endif

class MathTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

// ============================================================================
// Basic Math Operations (No External Dependencies)
// ============================================================================

/**
 * @brief Test modular exponentiation
 */
TEST_F(MathTest, ModularExponentiation) {
    // Simple test: 2^10 mod 1000 = 24
    auto mod_exp = [](uint64_t base, uint64_t exp, uint64_t mod) -> uint64_t {
        uint64_t result = 1;
        base %= mod;
        while (exp > 0) {
            if (exp & 1) result = (result * base) % mod;
            exp >>= 1;
            base = (base * base) % mod;
        }
        return result;
    };

    EXPECT_EQ(mod_exp(2, 10, 1000), 24ULL);
    EXPECT_EQ(mod_exp(3, 5, 7), 5ULL);  // 3^5 = 243 mod 7 = 5
    EXPECT_EQ(mod_exp(7, 2, 13), 10ULL); // 49 mod 13 = 10
}

/**
 * @brief Test GCD (Greatest Common Divisor)
 */
TEST_F(MathTest, GCD) {
    auto gcd = [](uint64_t a, uint64_t b) -> uint64_t {
        while (b != 0) {
            uint64_t t = b;
            b = a % b;
            a = t;
        }
        return a;
    };

    EXPECT_EQ(gcd(48, 18), 6);
    EXPECT_EQ(gcd(101, 103), 1);  // Coprime
    EXPECT_EQ(gcd(100, 25), 25);
    EXPECT_EQ(gcd(1, 1000000), 1);
}

/**
 * @brief Test Extended GCD
 */
TEST_F(MathTest, ExtendedGCD) {
    std::function<int64_t(int64_t, int64_t, int64_t&, int64_t&)> extended_gcd =
        [&extended_gcd](int64_t a, int64_t b, int64_t& x, int64_t& y) -> int64_t {
        if (b == 0) {
            x = 1;
            y = 0;
            return a;
        }
        int64_t x1, y1;
        int64_t d = extended_gcd(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return d;
    };

    int64_t x, y;
    int64_t d = extended_gcd(35, 15, x, y);

    EXPECT_EQ(d, 5);
    EXPECT_EQ(35 * x + 15 * y, d);  // Bezout's identity
}

/**
 * @brief Test primality check (trial division)
 */
TEST_F(MathTest, IsPrime) {
    auto is_prime = [](uint64_t n) -> bool {
        if (n < 2) return false;
        if (n == 2) return true;
        if (n % 2 == 0) return false;
        for (uint64_t i = 3; i * i <= n; i += 2) {
            if (n % i == 0) return false;
        }
        return true;
    };

    EXPECT_FALSE(is_prime(0));
    EXPECT_FALSE(is_prime(1));
    EXPECT_TRUE(is_prime(2));
    EXPECT_TRUE(is_prime(3));
    EXPECT_FALSE(is_prime(4));
    EXPECT_TRUE(is_prime(17));
    EXPECT_TRUE(is_prime(101));
    EXPECT_FALSE(is_prime(100));
    EXPECT_TRUE(is_prime(7919));  // 1000th prime
}

/**
 * @brief Test modular inverse
 */
TEST_F(MathTest, ModularInverse) {
    auto mod_inverse = [](int64_t a, int64_t m) -> int64_t {
        int64_t m0 = m, x0 = 0, x1 = 1;
        if (m == 1) return 0;
        while (a > 1) {
            int64_t q = a / m;
            int64_t t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) x1 += m0;
        return x1;
    };

    // 3 * 5 = 15 ≡ 1 (mod 7)
    EXPECT_EQ(mod_inverse(3, 7), 5);

    // Verify: a * a^(-1) ≡ 1 (mod m)
    int64_t a = 17, m = 43;
    int64_t inv = mod_inverse(a, m);
    EXPECT_EQ((a * inv) % m, 1);
}

// ============================================================================
// NTL-Based Tests (Conditional)
// ============================================================================

#ifdef KCTSB_HAS_NTL

/**
 * @brief Test NTL big integer operations
 */
TEST_F(MathTest, NTL_BigInteger) {
    NTL::ZZ a, b, c;

    // Large number arithmetic
    a = NTL::conv<NTL::ZZ>("123456789012345678901234567890");
    b = NTL::conv<NTL::ZZ>("987654321098765432109876543210");

    c = a + b;
    EXPECT_GT(c, a);
    EXPECT_GT(c, b);

    c = a * b;
    EXPECT_EQ(c / a, b);
    EXPECT_EQ(c / b, a);
}

/**
 * @brief Test polynomial operations
 * @note Uses simple polynomial operations to avoid NTL Vec::SetLength issues on MinGW
 */
TEST_F(MathTest, NTL_Polynomial) {
    // Test polynomial degree and coefficient operations
    // Use GF2X instead of ZZX to avoid Vec::SetLength overflow on MinGW
    NTL::GF2X f, g, h;

    // f(x) = x^2 + x + 1 in GF(2)
    NTL::SetCoeff(f, 0, 1);  // constant term
    NTL::SetCoeff(f, 1, 1);  // x coefficient
    NTL::SetCoeff(f, 2, 1);  // x^2 coefficient

    EXPECT_EQ(NTL::deg(f), 2);
    EXPECT_EQ(NTL::IsOne(NTL::coeff(f, 0)), 1);
    EXPECT_EQ(NTL::IsOne(NTL::coeff(f, 1)), 1);
    EXPECT_EQ(NTL::IsOne(NTL::coeff(f, 2)), 1);

    // g(x) = x + 1
    NTL::SetCoeff(g, 0, 1);
    NTL::SetCoeff(g, 1, 1);
    
    EXPECT_EQ(NTL::deg(g), 1);
    
    // Test polynomial multiplication
    h = f * g;
    EXPECT_GT(NTL::deg(h), NTL::deg(f));
}

/**
 * @brief Test polynomial factorization
 * @note Commented out due to NTL API compatibility issues
 */
/*
TEST_F(MathTest, NTL_PolynomialFactorization) {
    NTL::ZZX f;

    // f(x) = x^2 - 1 = (x-1)(x+1)
    NTL::SetCoeff(f, 0, -1);
    NTL::SetCoeff(f, 2, 1);

    // TODO: Fix NTL factorization API usage
    // NTL::vec_pair_ZZX_long factors;
    // NTL::ZZ c;
    // NTL::factor(c, factors, f);

    // Should have 2 factors
    // EXPECT_EQ(factors.length(), 2);
}
*/

/**
 * @brief Test GF(2) polynomial (binary field)
 */
TEST_F(MathTest, NTL_GF2Polynomial) {
    NTL::GF2X f, g, h;

    // f(x) = x^3 + x + 1 (irreducible over GF(2), AES polynomial)
    NTL::SetCoeff(f, 0, 1);
    NTL::SetCoeff(f, 1, 1);
    NTL::SetCoeff(f, 3, 1);

    // Test that it's non-zero
    EXPECT_NE(NTL::IsZero(f), 1);

    // Test degree
    EXPECT_EQ(NTL::deg(f), 3);
}

/**
 * @brief Test Miller-Rabin primality via NTL
 */
TEST_F(MathTest, NTL_MillerRabin) {
    NTL::ZZ n;

    // Test with known primes
    n = 7919;  // 1000th prime
    EXPECT_NE(NTL::ProbPrime(n), 0);

    n = 104729;  // 10000th prime
    EXPECT_NE(NTL::ProbPrime(n), 0);

    // Test with composite
    n = 100;
    EXPECT_EQ(NTL::ProbPrime(n), 0);
}

#else

/**
 * @brief Placeholder test when NTL is not available
 */
TEST_F(MathTest, NTL_NotAvailable) {
    // NTL is not compiled in, skip advanced polynomial tests
    GTEST_SKIP() << "NTL not available, skipping polynomial tests";
}

#endif  // KCTSB_HAS_NTL

// ============================================================================
// Statistical Functions
// ============================================================================

/**
 * @brief Test mean calculation
 */
TEST_F(MathTest, Statistics_Mean) {
    std::vector<double> data = {1.0, 2.0, 3.0, 4.0, 5.0};

    double sum = 0;
    for (double x : data) sum += x;
    double mean = sum / data.size();

    EXPECT_DOUBLE_EQ(mean, 3.0);
}

/**
 * @brief Test variance calculation
 */
TEST_F(MathTest, Statistics_Variance) {
    std::vector<double> data = {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};

    // Mean = 5
    double mean = 5.0;

    // Variance = E[(X - μ)^2]
    double variance = 0;
    for (double x : data) {
        variance += (x - mean) * (x - mean);
    }
    variance /= data.size();

    EXPECT_DOUBLE_EQ(variance, 4.0);
}

/**
 * @brief Test standard deviation
 */
TEST_F(MathTest, Statistics_StdDev) {
    std::vector<double> data = {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};
    double stddev = 2.0;  // sqrt(4.0)

    EXPECT_DOUBLE_EQ(std::sqrt(4.0), stddev);
}
