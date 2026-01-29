/**
 * @file test_rns.cpp
 * @brief Unit Tests for Residue Number System (RNS)
 * 
 * Tests:
 * - RNS base construction
 * - RNS polynomial operations
 * - NTT form conversion
 * - Base conversion
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.6.0
 */

#include <gtest/gtest.h>
#include <vector>
#include <random>

#include "kctsb/advanced/fe/common/rns.hpp"
#include "kctsb/advanced/fe/common/ntt.hpp"

using namespace kctsb::fhe::rns;
using namespace kctsb::fhe::ntt;

// ============================================================================
// Test Parameters
// ============================================================================

// NTT-friendly primes for n=16: q = 1 (mod 32)
// 65537 = 2^16 + 1 = 1 (mod 32) ✓
// 786433 = 3 * 2^18 + 1 = 1 (mod 32) ✓
// 12289 = 3 * 2^12 + 1 = 1 (mod 32) ✓

constexpr size_t TEST_POLY_DEGREE = 16;
const std::vector<uint64_t> TEST_MODULI = {65537, 786433, 12289};

// ============================================================================
// Utility Tests
// ============================================================================

TEST(RNSUtilityTest, AreCoprime) {
    EXPECT_TRUE(are_coprime({7, 11, 13}));
    EXPECT_TRUE(are_coprime({65537, 786433}));
    EXPECT_FALSE(are_coprime({6, 9}));  // gcd = 3
    EXPECT_FALSE(are_coprime({4, 6, 9}));
}

TEST(RNSUtilityTest, GenerateNTTPrimes) {
    // Generate 3 primes of approximately 16 bits for n=16
    auto primes = generate_ntt_primes(3, 16, 16);
    
    EXPECT_EQ(primes.size(), 3);
    
    for (auto q : primes) {
        // Check NTT-friendly
        EXPECT_TRUE(is_ntt_prime(q, 16)) << "Prime " << q << " is not NTT-friendly";
        
        // Check approximate bit size
        EXPECT_GE(q, 1ULL << 15);
        EXPECT_LT(q, 1ULL << 17);
    }
    
    // Check pairwise coprime
    EXPECT_TRUE(are_coprime(primes));
}

// ============================================================================
// RNSBase Tests
// ============================================================================

TEST(RNSBaseTest, Construction) {
    EXPECT_NO_THROW({
        RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
        EXPECT_EQ(base.size(), 3);
        EXPECT_EQ(base.poly_degree(), 16);
    });
}

TEST(RNSBaseTest, ModulusAccess) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    
    for (size_t i = 0; i < TEST_MODULI.size(); ++i) {
        EXPECT_EQ(base.modulus(i), TEST_MODULI[i]);
    }
}

TEST(RNSBaseTest, InvalidModuli) {
    // Non-coprime moduli should fail
    EXPECT_THROW({
        RNSBase base({6, 9}, TEST_POLY_DEGREE);
    }, std::invalid_argument);
    
    // Non-NTT-friendly modulus should fail
    EXPECT_THROW({
        RNSBase base({7}, TEST_POLY_DEGREE);  // 7 = 1 (mod 6) ≠ 1 (mod 32)
    }, std::invalid_argument);
}

TEST(RNSBaseTest, QHatInverse) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    
    // Verify Q_i^(-1) * Q_i = 1 (mod q_i)
    for (size_t i = 0; i < base.size(); ++i) {
        uint64_t q_i = base.modulus(i);
        uint64_t q_hat_inv = base.q_hat_inv(i);
        
        // Compute Q_i mod q_i
        uint64_t q_hat = 1;
        for (size_t j = 0; j < base.size(); ++j) {
            if (i != j) {
                q_hat = mul_mod_slow(q_hat, base.modulus(j) % q_i, q_i);
            }
        }
        
        // Verify inverse
        EXPECT_EQ(mul_mod_slow(q_hat, q_hat_inv, q_i), 1) 
            << "Q_hat_inv verification failed for level " << i;
    }
}

TEST(RNSBaseTest, NTTTableAccess) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    
    for (size_t i = 0; i < base.size(); ++i) {
        const NTTTable& ntt = base.ntt_table(i);
        EXPECT_EQ(ntt.degree(), TEST_POLY_DEGREE);
        EXPECT_EQ(ntt.modulus(), TEST_MODULI[i]);
    }
}

// ============================================================================
// RNSPoly Tests
// ============================================================================

TEST(RNSPolyTest, DefaultConstruction) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    RNSPoly poly(base);
    
    EXPECT_EQ(poly.num_levels(), 3);
    EXPECT_EQ(poly.degree(), TEST_POLY_DEGREE);
    EXPECT_FALSE(poly.is_ntt());
    
    // Should be zero-initialized
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        for (size_t i = 0; i < poly.degree(); ++i) {
            EXPECT_EQ(poly[level][i], 0);
        }
    }
}

TEST(RNSPolyTest, CoefficientConstruction) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    
    std::vector<std::vector<uint64_t>> coeffs(3);
    for (size_t level = 0; level < 3; ++level) {
        coeffs[level].resize(TEST_POLY_DEGREE);
        for (size_t i = 0; i < TEST_POLY_DEGREE; ++i) {
            coeffs[level][i] = (i + 1) % TEST_MODULI[level];
        }
    }
    
    RNSPoly poly(base, coeffs);
    
    for (size_t level = 0; level < 3; ++level) {
        for (size_t i = 0; i < TEST_POLY_DEGREE; ++i) {
            EXPECT_EQ(poly[level][i], coeffs[level][i]);
        }
    }
}

TEST(RNSPolyTest, SetZero) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    RNSPoly poly(base);
    
    // Set some non-zero values
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        poly[level][0] = 42;
    }
    
    poly.set_zero();
    
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        for (size_t i = 0; i < poly.degree(); ++i) {
            EXPECT_EQ(poly[level][i], 0);
        }
    }
}

TEST(RNSPolyTest, Negate) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    RNSPoly poly(base);
    
    // Set test values
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        poly[level][0] = 5;
        poly[level][1] = 0;  // Zero should stay zero
    }
    
    poly.negate();
    
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        EXPECT_EQ(poly[level][0], base.modulus(level) - 5);
        EXPECT_EQ(poly[level][1], 0);
    }
}

// ============================================================================
// NTT Form Conversion Tests
// ============================================================================

TEST(RNSPolyTest, NTTConversion) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    RNSPoly poly(base);
    
    // Set some test values
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        for (size_t i = 0; i < poly.degree(); ++i) {
            poly[level][i] = (i + 1) % base.modulus(level);
        }
    }
    
    // Save original
    std::vector<std::vector<uint64_t>> original(poly.num_levels());
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        original[level].assign(poly[level], poly[level] + poly.degree());
    }
    
    // Convert to NTT and back
    EXPECT_FALSE(poly.is_ntt());
    
    poly.to_ntt();
    EXPECT_TRUE(poly.is_ntt());
    
    poly.from_ntt();
    EXPECT_FALSE(poly.is_ntt());
    
    // Should match original
    for (size_t level = 0; level < poly.num_levels(); ++level) {
        for (size_t i = 0; i < poly.degree(); ++i) {
            EXPECT_EQ(poly[level][i], original[level][i])
                << "Mismatch at level " << level << ", index " << i;
        }
    }
}

TEST(RNSPolyTest, DoubleNTTConversion) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    RNSPoly poly(base);
    
    poly[0][0] = 1;
    
    // Double to_ntt should be idempotent
    poly.to_ntt();
    poly.to_ntt();  // Should be no-op
    EXPECT_TRUE(poly.is_ntt());
    
    // Double from_ntt should be idempotent
    poly.from_ntt();
    poly.from_ntt();  // Should be no-op
    EXPECT_FALSE(poly.is_ntt());
}

// ============================================================================
// Arithmetic Tests
// ============================================================================

TEST(RNSPolyArithmeticTest, Addition) {
    RNSBase base({65537}, TEST_POLY_DEGREE);  // Single modulus for simplicity
    
    RNSPoly a(base);
    RNSPoly b(base);
    
    a[0][0] = 100;
    a[0][1] = 65530;  // Near modulus
    
    b[0][0] = 200;
    b[0][1] = 10;
    
    a += b;
    
    EXPECT_EQ(a[0][0], 300);
    EXPECT_EQ(a[0][1], add_mod(65530, 10, 65537));  // 65540 mod 65537 = 3
}

TEST(RNSPolyArithmeticTest, Subtraction) {
    RNSBase base({65537}, TEST_POLY_DEGREE);
    
    RNSPoly a(base);
    RNSPoly b(base);
    
    a[0][0] = 300;
    a[0][1] = 5;  // Will underflow
    
    b[0][0] = 100;
    b[0][1] = 10;
    
    a -= b;
    
    EXPECT_EQ(a[0][0], 200);
    EXPECT_EQ(a[0][1], sub_mod(5, 10, 65537));  // -5 mod 65537 = 65532
}

TEST(RNSPolyArithmeticTest, Multiplication) {
    RNSBase base({65537}, TEST_POLY_DEGREE);
    
    RNSPoly a(base);
    RNSPoly b(base);
    
    // a(x) = 1 + 2x (rest zeros)
    a[0][0] = 1;
    a[0][1] = 2;
    
    // b(x) = 3 + 4x (rest zeros)
    b[0][0] = 3;
    b[0][1] = 4;
    
    // Convert to NTT form
    a.to_ntt();
    b.to_ntt();
    
    // Multiply
    a *= b;
    
    // Convert back
    a.from_ntt();
    
    // Expected: (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2 (in negacyclic ring)
    // But for x^n + 1 ring, x^n = -1, so x^16 = -1
    // For n=16: result is just the low degree terms since we only set x^0 and x^1
    
    EXPECT_EQ(a[0][0], 3);   // Constant term
    EXPECT_EQ(a[0][1], 10);  // x coefficient: 1*4 + 2*3 = 10
    EXPECT_EQ(a[0][2], 8);   // x^2 coefficient: 2*4 = 8
}

TEST(RNSPolyArithmeticTest, MultiLevelAddition) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    
    RNSPoly a(base);
    RNSPoly b(base);
    
    // Set values at all levels
    for (size_t level = 0; level < base.size(); ++level) {
        a[level][0] = 100;
        b[level][0] = 200;
    }
    
    RNSPoly c = a + b;
    
    for (size_t level = 0; level < base.size(); ++level) {
        EXPECT_EQ(c[level][0], 300);
    }
}

// ============================================================================
// Base Conversion Tests
// ============================================================================

TEST(RNSBaseConverterTest, SameBaseIdentity) {
    // Converting within the same base should preserve values
    RNSBase base({65537, 786433}, TEST_POLY_DEGREE);
    RNSBaseConverter converter(base, base);
    
    RNSPoly input(base);
    RNSPoly output(base);
    
    input[0][0] = 42;
    input[0][1] = 100;
    input[1][0] = 42 % 786433;
    input[1][1] = 100;
    
    converter.convert(input, output);
    
    // Values should be preserved (within CRT reconstruction)
    // Note: exact preservation depends on the value being representable
    EXPECT_EQ(output[0][0], input[0][0]);
    EXPECT_EQ(output[1][0], input[1][0]);
}

TEST(RNSBaseConverterTest, SmallValueConversion) {
    // For small values that fit in all moduli, conversion should preserve them
    RNSBase base1({65537}, TEST_POLY_DEGREE);
    RNSBase base2({786433}, TEST_POLY_DEGREE);
    
    RNSBaseConverter converter(base1, base2);
    
    RNSPoly input(base1);
    RNSPoly output(base2);
    
    input[0][0] = 12345;  // Small value that fits in both moduli
    
    converter.convert(input, output);
    
    // Output should be the same value
    EXPECT_EQ(output[0][0], 12345);
}

// ============================================================================
// Copy/Move Tests
// ============================================================================

TEST(RNSPolyCopyMoveTest, CopyConstruction) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    
    RNSPoly original(base);
    original[0][0] = 42;
    original.to_ntt();
    
    RNSPoly copy(original);
    
    EXPECT_EQ(copy[0][0], original[0][0]);
    EXPECT_EQ(copy.is_ntt(), original.is_ntt());
}

TEST(RNSPolyCopyMoveTest, MoveConstruction) {
    RNSBase base(TEST_MODULI, TEST_POLY_DEGREE);
    
    RNSPoly original(base);
    original[0][0] = 42;
    
    RNSPoly moved(std::move(original));
    
    EXPECT_EQ(moved[0][0], 42);
}

// ============================================================================
// Performance Sanity Check
// ============================================================================

TEST(RNSPerformanceTest, LargerDegree) {
    // Generate larger degree RNS base
    size_t n = 256;
    auto primes = generate_ntt_primes(4, 20, n);
    
    EXPECT_NO_THROW({
        RNSBase base(primes, n);
        RNSPoly poly(base);
        
        // Set some values
        for (size_t level = 0; level < base.size(); ++level) {
            for (size_t i = 0; i < n; ++i) {
                poly[level][i] = i % base.modulus(level);
            }
        }
        
        // NTT round-trip
        poly.to_ntt();
        poly.from_ntt();
    });
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
