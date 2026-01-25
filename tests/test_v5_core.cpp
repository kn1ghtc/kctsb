/**
 * @file test_v5_core.cpp
 * @brief V5.0 Core module tests - Self-contained ZZ, BigInt, Fe256 implementations
 * 
 * This file contains comprehensive tests for the v5.0 self-contained
 * cryptographic core modules. Tests verify that all operations work
 * correctly without any external dependencies (GMP, NTL, etc.).
 * 
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <kctsb/core/zz.h>
#include <kctsb/core/bigint.h>
#include <kctsb/core/fe256.h>
#include <kctsb/version.h>
#include <vector>
#include <string>
#include <chrono>
#include <random>

using namespace kctsb;

/**
 * @brief Test fixture for ZZ (arbitrary-precision integer) tests
 */
class ZZTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test vectors
    }
    
    void TearDown() override {
        // Cleanup
    }
};

// ============================================================================
// ZZ Basic Operations Tests
// ============================================================================

TEST_F(ZZTest, DefaultConstruction) {
    ZZ a;
    EXPECT_TRUE(IsZero(a));
    EXPECT_EQ(NumBits(a), 0);
}

TEST_F(ZZTest, IntegerConstruction) {
    ZZ a(0);
    EXPECT_TRUE(IsZero(a));
    
    ZZ b(1);
    EXPECT_FALSE(IsZero(b));
    EXPECT_EQ(NumBits(b), 1);
    
    ZZ c(255);
    EXPECT_EQ(NumBits(c), 8);
    
    ZZ d(-100);
    EXPECT_TRUE(IsNegative(d));
}

TEST_F(ZZTest, StringConstruction) {
    ZZ a;
    conv(a, "12345678901234567890");
    EXPECT_FALSE(IsZero(a));
    EXPECT_GT(NumBits(a), 60);  // Should be > 64 bits
}

TEST_F(ZZTest, Addition) {
    ZZ a(100);
    ZZ b(200);
    ZZ c;
    add(c, a, b);
    
    ZZ expected(300);
    EXPECT_EQ(c, expected);
}

TEST_F(ZZTest, Subtraction) {
    ZZ a(200);
    ZZ b(50);
    ZZ c;
    sub(c, a, b);
    
    ZZ expected(150);
    EXPECT_EQ(c, expected);
}

TEST_F(ZZTest, Multiplication) {
    ZZ a(123);
    ZZ b(456);
    ZZ c;
    mul(c, a, b);
    
    ZZ expected(56088);
    EXPECT_EQ(c, expected);
}

TEST_F(ZZTest, Division) {
    ZZ a(100);
    ZZ b(7);
    ZZ q, r;
    DivRem(q, r, a, b);
    
    ZZ expected_q(14);
    ZZ expected_r(2);
    EXPECT_EQ(q, expected_q);
    EXPECT_EQ(r, expected_r);
}

TEST_F(ZZTest, GCDTest) {
    ZZ a(48);
    ZZ b(18);
    ZZ g;
    GCD(g, a, b);
    
    ZZ expected(6);
    EXPECT_EQ(g, expected);
}

TEST_F(ZZTest, PowerModTest) {
    ZZ base(2);
    ZZ exp(10);
    ZZ mod(1000);
    ZZ result;
    PowerMod(result, base, exp, mod);
    
    ZZ expected(24);  // 2^10 mod 1000 = 1024 mod 1000 = 24
    EXPECT_EQ(result, expected);
}

TEST_F(ZZTest, InvModTest) {
    ZZ a(3);
    ZZ mod(11);
    ZZ inv;
    InvMod(inv, a, mod);
    
    // 3 * 4 = 12 ≡ 1 (mod 11)
    ZZ expected(4);
    EXPECT_EQ(inv, expected);
}

TEST_F(ZZTest, MulModTest) {
    ZZ a(7);
    ZZ b(8);
    ZZ mod(13);
    ZZ result;
    MulMod(result, a, b, mod);
    
    // 7 * 8 = 56 mod 13 = 4
    ZZ expected(4);
    EXPECT_EQ(result, expected);
}

TEST_F(ZZTest, IsOddTest) {
    ZZ odd(13);
    ZZ even(14);
    
    EXPECT_TRUE(IsOdd(odd));
    EXPECT_FALSE(IsOdd(even));
}

TEST_F(ZZTest, ByteConversion) {
    std::vector<uint8_t> bytes = {0x12, 0x34, 0x56, 0x78};
    ZZ a;
    ZZFromBytes(a, bytes.data(), bytes.size());
    
    std::vector<uint8_t> output(4);
    BytesFromZZ(output.data(), a, 4);
    
    EXPECT_EQ(bytes, output);
}

// ============================================================================
// BigInt Tests
// ============================================================================

class BigIntTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(BigIntTest, Construction256) {
    BigInt<256> a;
    EXPECT_TRUE(a.is_zero());
    
    BigInt<256> b(12345);
    EXPECT_FALSE(b.is_zero());
}

TEST_F(BigIntTest, Addition256) {
    BigInt<256> a(1000);
    BigInt<256> b(2345);
    BigInt<256> c = a + b;
    
    BigInt<256> expected(3345);
    EXPECT_EQ(c, expected);
}

TEST_F(BigIntTest, Subtraction256) {
    BigInt<256> a(5000);
    BigInt<256> b(3000);
    BigInt<256> c = a - b;
    
    BigInt<256> expected(2000);
    EXPECT_EQ(c, expected);
}

// TODO: BigInt multiplication needs implementation in v5.0
/*
TEST_F(BigIntTest, Multiplication256) {
    BigInt<256> a(123);
    BigInt<256> b(456);
    BigInt<256> c = a * b;
    
    BigInt<256> expected(56088);
    EXPECT_EQ(c, expected);
}
*/

TEST_F(BigIntTest, Comparison) {
    BigInt<256> a(100);
    BigInt<256> b(200);
    BigInt<256> c(100);
    
    EXPECT_TRUE(a < b);
    EXPECT_TRUE(b > a);
    EXPECT_TRUE(a == c);
    EXPECT_TRUE(a <= c);
    EXPECT_TRUE(a >= c);
}

TEST_F(BigIntTest, HexConversion) {
    BigInt<256> a;
    a.from_hex("DEADBEEF");
    
    std::string hex = a.to_hex();
    // Normalize both to uppercase for comparison
    std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);
    EXPECT_NE(hex.find("DEADBEEF"), std::string::npos);
}

// ============================================================================
// Fe256 (Field Element) Tests
// ============================================================================

class Fe256Test : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(Fe256Test, Construction) {
    Fe256 a;
    EXPECT_TRUE(a.is_zero());
    
    Fe256 b(12345);
    EXPECT_FALSE(b.is_zero());
}

TEST_F(Fe256Test, Addition) {
    Fe256 a(100);
    Fe256 b(200);
    Fe256 c;
    kctsb::fe256_ops::fe256_add(&c, &a, &b);
    
    EXPECT_EQ(c[0], 300ULL);
}

TEST_F(Fe256Test, Subtraction) {
    Fe256 a(300);
    Fe256 b(100);
    Fe256 c;
    kctsb::fe256_ops::fe256_sub(&c, &a, &b);
    
    EXPECT_EQ(c[0], 200ULL);
}

// ============================================================================
// Performance Tests
// ============================================================================

class V5PerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(V5PerformanceTest, ZZAdditionSpeed) {
    ZZ a, b, c;
    conv(a, "12345678901234567890123456789012345678901234567890");
    conv(b, "98765432109876543210987654321098765432109876543210");
    
    const int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        add(c, a, b);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete in reasonable time
    EXPECT_LT(duration.count(), 100000);  // < 100ms for 10000 iterations
}

// TODO: BigInt multiplication needs implementation in v5.0
/*
TEST_F(V5PerformanceTest, BigInt256MultiplicationSpeed) {
    BigInt<256> a, b, c;
    a.from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    b.from_hex("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE");
    
    const int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        c = a * b;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Should complete in reasonable time
    EXPECT_LT(duration.count(), 100000);  // < 100ms for 10000 iterations
}
*/

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
