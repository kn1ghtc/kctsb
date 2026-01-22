/**
 * @file test_ntt.cpp
 * @brief Unit Tests for Number Theoretic Transform (NTT)
 * 
 * Tests:
 * - Modular arithmetic (Barrett reduction)
 * - Primitive root finding
 * - Forward/Inverse NTT correctness
 * - Polynomial multiplication
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#include <gtest/gtest.h>
#include <vector>
#include <random>
#include <algorithm>

#include "kctsb/advanced/fe/common/ntt.hpp"

using namespace kctsb::fhe::ntt;

// ============================================================================
// Test Parameters
// ============================================================================

// NTT-friendly primes: q = 1 (mod 2n)
// For n=256: q = 1 (mod 512)
// 65537 = 1 + 2^16 = 1 (mod 512) ✓
// 786433 = 1 + 3 * 2^18 = 1 (mod 512) ✓

constexpr uint64_t TEST_PRIME_SMALL = 257;      // For n=2,4,8,16,32,64,128 (2^8+1)
constexpr uint64_t TEST_PRIME_257 = 65537;      // For n up to 32768 (2^16+1, Fermat F4)
constexpr uint64_t TEST_PRIME_LARGE = 786433;   // 3 * 2^18 + 1

// ============================================================================
// Modular Arithmetic Tests
// ============================================================================

TEST(NTTModArithTest, AddMod) {
    EXPECT_EQ(add_mod(3, 4, 7), 0);   // 3 + 4 = 7 ≡ 0
    EXPECT_EQ(add_mod(3, 4, 10), 7);  // 3 + 4 = 7
    EXPECT_EQ(add_mod(5, 6, 7), 4);   // 5 + 6 = 11 ≡ 4
}

TEST(NTTModArithTest, SubMod) {
    EXPECT_EQ(sub_mod(5, 3, 7), 2);   // 5 - 3 = 2
    EXPECT_EQ(sub_mod(3, 5, 7), 5);   // 3 - 5 = -2 ≡ 5
    EXPECT_EQ(sub_mod(0, 1, 7), 6);   // 0 - 1 = -1 ≡ 6
}

TEST(NTTModArithTest, MulModSlow) {
    EXPECT_EQ(mul_mod_slow(3, 4, 7), 5);   // 12 ≡ 5
    EXPECT_EQ(mul_mod_slow(6, 6, 7), 1);   // 36 ≡ 1
    
    // Large numbers
    uint64_t a = 12345678901234ULL;
    uint64_t b = 98765432109876ULL;
    uint64_t q = 1000000007ULL;
    uint64_t result = mul_mod_slow(a % q, b % q, q);
    EXPECT_LT(result, q);
}

TEST(NTTModArithTest, MulModBarrett) {
    BarrettConstants bc(7);
    EXPECT_EQ(mul_mod_barrett(3, 4, bc), 5);
    EXPECT_EQ(mul_mod_barrett(6, 6, bc), 1);
    
    // Verify Barrett matches slow version
    BarrettConstants bc_large(TEST_PRIME_257);
    for (uint64_t i = 0; i < 100; ++i) {
        uint64_t a = (i * 1234) % TEST_PRIME_257;
        uint64_t b = (i * 5678) % TEST_PRIME_257;
        EXPECT_EQ(mul_mod_barrett(a, b, bc_large), mul_mod_slow(a, b, TEST_PRIME_257));
    }
}

TEST(NTTModArithTest, PowMod) {
    EXPECT_EQ(pow_mod(2, 10, 1000), 24);      // 1024 % 1000 = 24
    EXPECT_EQ(pow_mod(3, 4, 7), 4);            // 81 % 7 = 4
    // Fermat's little theorem: a^(p-1) ≡ 1 (mod p) for prime p
    EXPECT_EQ(pow_mod(2, 65536, TEST_PRIME_257), 1);  // 2^(65537-1) mod 65537 = 1
    EXPECT_EQ(pow_mod(3, 6, 7), 1);  // 3^6 mod 7 = 729 mod 7 = 1
}

TEST(NTTModArithTest, InvMod) {
    // 3 * 5 = 15 ≡ 1 (mod 7), so 3^(-1) = 5
    EXPECT_EQ(inv_mod(3, 7), 5);
    
    // Verify a * a^(-1) = 1
    for (uint64_t a = 1; a < 20; ++a) {
        uint64_t inv = inv_mod(a, TEST_PRIME_257);
        EXPECT_EQ(mul_mod_slow(a, inv, TEST_PRIME_257), 1);
    }
}

// ============================================================================
// Primitive Root Tests
// ============================================================================

TEST(NTTPrimeTest, IsNTTPrime) {
    // Valid NTT primes for n=256
    EXPECT_TRUE(is_ntt_prime(TEST_PRIME_257, 256));   // 65537 = 1 (mod 512)
    EXPECT_TRUE(is_ntt_prime(TEST_PRIME_LARGE, 256)); // 786433 = 1 (mod 512)
    
    // Not prime
    EXPECT_FALSE(is_ntt_prime(100, 8));
    
    // Prime but not NTT-friendly
    EXPECT_FALSE(is_ntt_prime(17, 256));  // 17 ≠ 1 (mod 512)
}

TEST(NTTPrimeTest, FindPrimitiveRoot) {
    // For small n, find root and verify
    uint64_t q = TEST_PRIME_257;
    size_t n = 256;
    
    uint64_t root = find_primitive_root(q, n);
    
    // Verify root^(2n) = 1
    EXPECT_EQ(pow_mod(root, 2 * n, q), 1);
    
    // Verify root^n ≠ 1 (primitive)
    EXPECT_NE(pow_mod(root, n, q), 1);
}

// ============================================================================
// NTT Table Tests
// ============================================================================

TEST(NTTTableTest, Construction) {
    // Should not throw for valid parameters
    EXPECT_NO_THROW(NTTTable(8, 257));
    EXPECT_NO_THROW(NTTTable(256, TEST_PRIME_257));
    
    // Should throw for invalid n (not power of 2)
    EXPECT_THROW(NTTTable(7, 257), std::invalid_argument);
    
    // Should throw for non-NTT-friendly prime
    EXPECT_THROW(NTTTable(256, 17), std::invalid_argument);
}

TEST(NTTTableTest, ForwardInverseIdentity_Small) {
    // NTT(iNTT(x)) = x for small n
    size_t n = 8;
    uint64_t q = 257;  // 257 = 1 (mod 16) ✓
    
    NTTTable ntt(n, q);
    
    std::vector<uint64_t> original = {1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<uint64_t> data = original;
    
    ntt.forward(data.data());
    ntt.inverse(data.data());
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(data[i], original[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTTableTest, ForwardInverseIdentity_Medium) {
    // NTT(iNTT(x)) = x for medium n
    size_t n = 256;
    uint64_t q = TEST_PRIME_257;
    
    NTTTable ntt(n, q);
    
    std::vector<uint64_t> original(n);
    for (size_t i = 0; i < n; ++i) {
        original[i] = i % q;
    }
    std::vector<uint64_t> data = original;
    
    ntt.forward(data.data());
    ntt.inverse(data.data());
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(data[i], original[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTTableTest, InverseForwardIdentity) {
    // iNTT(NTT(x)) = x
    size_t n = 64;
    uint64_t q = TEST_PRIME_257;
    
    NTTTable ntt(n, q);
    
    std::vector<uint64_t> original(n);
    std::mt19937_64 rng(42);
    for (size_t i = 0; i < n; ++i) {
        original[i] = rng() % q;
    }
    std::vector<uint64_t> data = original;
    
    ntt.inverse(data.data());
    ntt.forward(data.data());
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(data[i], original[i]) << "Mismatch at index " << i;
    }
}

// ============================================================================
// Polynomial Multiplication Tests
// ============================================================================

/**
 * @brief Schoolbook cyclic convolution (reference implementation)
 * @note Uses x^n - 1 reduction (cyclic), not x^n + 1 (negacyclic)
 */
std::vector<uint64_t> poly_multiply_cyclic_schoolbook(
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q)
{
    size_t n = a.size();
    std::vector<uint64_t> c(n, 0);
    
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            // x^n ≡ 1 (mod x^n - 1) - cyclic convolution
            size_t idx = (i + j) % n;
            uint64_t product = mul_mod_slow(a[i], b[j], q);
            c[idx] = add_mod(c[idx], product, q);
        }
    }
    
    return c;
}

TEST(NTTPolyMultTest, CyclicSmallPolynomials) {
    // NTT computes cyclic convolution (x^n - 1)
    size_t n = 4;
    uint64_t q = 257;  // 257 = 1 + 256 = 1 + 2^8, so 2^8 | (q-1)
    
    std::vector<uint64_t> a = {1, 1, 0, 0};  // 1 + x
    std::vector<uint64_t> b = {1, 1, 0, 0};  // 1 + x
    
    // Expected: (1+x)^2 = 1 + 2x + x^2 (no wrap-around for small polys)
    auto c_ref = poly_multiply_cyclic_schoolbook(a, b, q);
    
    // Get NTT table and verify roots
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    uint64_t omega = ntt.root(1);
    EXPECT_EQ(pow_mod(omega, n, q), 1ULL) << "omega^n should equal 1";
    
    // Forward NTT of a
    std::vector<uint64_t> a_ntt = a;
    ntt.forward(a_ntt.data());
    
    // Verify NTT matches manual DFT
    for (size_t k = 0; k < n; ++k) {
        uint64_t dft_k = 0;
        for (size_t j = 0; j < n; ++j) {
            uint64_t omega_jk = pow_mod(omega, j * k, q);
            dft_k = add_mod(dft_k, mul_mod_slow(a[j], omega_jk, q), q);
        }
        EXPECT_EQ(a_ntt[k], dft_k) << "NTT should match DFT at index " << k;
    }
    
    // Test full polynomial multiplication
    auto c_ntt = poly_multiply_ntt(a.data(), b.data(), n, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(c_ntt[i], c_ref[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTPolyMultTest, CyclicRandomPolynomials) {
    size_t n = 64;
    uint64_t q = TEST_PRIME_257;
    
    std::mt19937_64 rng(123);
    std::vector<uint64_t> a(n), b(n);
    
    for (size_t i = 0; i < n; ++i) {
        a[i] = rng() % q;
        b[i] = rng() % q;
    }
    
    auto c_ntt = poly_multiply_ntt(a.data(), b.data(), n, q);
    auto c_ref = poly_multiply_cyclic_schoolbook(a, b, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(c_ntt[i], c_ref[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTPolyMultTest, CyclicInplaceMultiply) {
    size_t n = 32;
    uint64_t q = TEST_PRIME_257;
    
    std::vector<uint64_t> a = {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<uint64_t> b = {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    
    auto c_ref = poly_multiply_cyclic_schoolbook(a, b, q);
    
    std::vector<uint64_t> a_copy = a;
    poly_multiply_ntt_inplace(a_copy.data(), b.data(), n, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(a_copy[i], c_ref[i]) << "Mismatch at index " << i;
    }
}

// ============================================================================
// Negacyclic NTT Tests (x^n + 1 ring)
// ============================================================================

/**
 * @brief Schoolbook negacyclic convolution (reference implementation)
 * @note Uses x^n + 1 reduction (negacyclic): x^n ≡ -1
 */
std::vector<uint64_t> poly_multiply_negacyclic_schoolbook(
    const std::vector<uint64_t>& a,
    const std::vector<uint64_t>& b,
    uint64_t q)
{
    size_t n = a.size();
    std::vector<uint64_t> c(n, 0);
    
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            size_t idx = (i + j) % n;
            uint64_t product = mul_mod_slow(a[i], b[j], q);
            
            if (i + j >= n) {
                // x^n ≡ -1 (mod x^n + 1) - negacyclic: subtract
                c[idx] = sub_mod(c[idx], product, q);
            } else {
                c[idx] = add_mod(c[idx], product, q);
            }
        }
    }
    
    return c;
}

TEST(NTTNegacyclicTest, SmallPolynomials) {
    // Test: (1 + x) * (1 + x) mod (x^4 + 1) = 1 + 2x + x^2
    // Note: x^4 ≡ -1, so no wrap-around for degree < 4
    size_t n = 4;
    uint64_t q = 257;
    
    std::vector<uint64_t> a = {1, 1, 0, 0};  // 1 + x
    std::vector<uint64_t> b = {1, 1, 0, 0};  // 1 + x
    
    auto c_ref = poly_multiply_negacyclic_schoolbook(a, b, q);
    auto c_ntt = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(c_ntt[i], c_ref[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTNegacyclicTest, WrapAroundTest) {
    // Test wrap-around: x^(n-1) * x = x^n ≡ -1 (mod x^n + 1)
    size_t n = 4;
    uint64_t q = 257;
    
    // a = x^3, b = x → a*b = x^4 ≡ -1 (mod x^4 + 1)
    std::vector<uint64_t> a = {0, 0, 0, 1};  // x^3
    std::vector<uint64_t> b = {0, 1, 0, 0};  // x
    
    auto c_ref = poly_multiply_negacyclic_schoolbook(a, b, q);
    // Expected: -1 = q - 1 = 256 at position 0
    EXPECT_EQ(c_ref[0], 256ULL);
    EXPECT_EQ(c_ref[1], 0ULL);
    EXPECT_EQ(c_ref[2], 0ULL);
    EXPECT_EQ(c_ref[3], 0ULL);
    
    auto c_ntt = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(c_ntt[i], c_ref[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTNegacyclicTest, RandomPolynomials) {
    size_t n = 64;
    uint64_t q = TEST_PRIME_257;
    
    std::mt19937_64 rng(456);
    std::vector<uint64_t> a(n), b(n);
    
    for (size_t i = 0; i < n; ++i) {
        a[i] = rng() % q;
        b[i] = rng() % q;
    }
    
    auto c_ntt = poly_multiply_negacyclic_ntt(a.data(), b.data(), n, q);
    auto c_ref = poly_multiply_negacyclic_schoolbook(a, b, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(c_ntt[i], c_ref[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTNegacyclicTest, InplaceMultiply) {
    size_t n = 32;
    uint64_t q = TEST_PRIME_257;
    
    std::vector<uint64_t> a = {1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<uint64_t> b = {5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    
    auto c_ref = poly_multiply_negacyclic_schoolbook(a, b, q);
    
    std::vector<uint64_t> a_copy = a;
    poly_multiply_negacyclic_ntt_inplace(a_copy.data(), b.data(), n, q);
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(a_copy[i], c_ref[i]) << "Mismatch at index " << i;
    }
}

TEST(NTTNegacyclicTest, ForwardInverseIdentity) {
    size_t n = 16;
    uint64_t q = TEST_PRIME_257;
    
    const NTTTable& ntt = NTTTableCache::instance().get(n, q);
    
    std::vector<uint64_t> original = {1, 2, 3, 4, 5, 6, 7, 8, 
                                       9, 10, 11, 12, 13, 14, 15, 16};
    std::vector<uint64_t> data = original;
    
    ntt.forward_negacyclic(data.data());
    ntt.inverse_negacyclic(data.data());
    
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(data[i], original[i]) << "Mismatch at index " << i;
    }
}

// ============================================================================
// Performance Sanity Check
// ============================================================================

TEST(NTTPerformanceTest, LargerDegree) {
    // Just verify it works for larger n (not a real benchmark)
    size_t n = 1024;
    uint64_t q = TEST_PRIME_LARGE;
    
    std::vector<uint64_t> a(n, 1);
    std::vector<uint64_t> b(n, 1);
    
    // Should complete without error
    EXPECT_NO_THROW({
        auto c = poly_multiply_ntt(a.data(), b.data(), n, q);
        EXPECT_EQ(c.size(), n);
    });
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
