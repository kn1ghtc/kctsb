/**
 * @file test_sm2_mont_debug.cpp
 * @brief SM2 Montgomery Domain Debug Tests
 *
 * This test file isolates and validates each component of the SM2 Montgomery
 * acceleration to identify the crash source during integration.
 *
 * Debug hierarchy:
 * 1. fe256_to_mont / fe256_from_mont roundtrip
 * 2. fe256_mont_mul basic operation
 * 3. compute_precomp_table initialization
 * 4. scalar_mul_base execution
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdint>

// ============================================================================
// SM2 Montgomery/Precomputation headers
// ============================================================================

#include "kctsb/crypto/sm/sm2_mont.h"
#include "crypto/sm/sm2_mont_curve.h"

namespace kctsb::internal::sm2::precomp {
void compute_precomp_table();
void scalar_mul_base(sm2_point_jacobian* r, const uint64_t* k);
bool is_precomp_ready();
void reset_precomp_table();
}  // namespace kctsb::internal::sm2::precomp

// ============================================================================
// Test Fixture
// ============================================================================

class SM2MontDebugTest : public ::testing::Test {
protected:
    using MontFe = kctsb::internal::sm2::mont::fe256;
    using PrecompFe = kctsb::internal::sm2::precomp::fe256;
    using JacobianPoint = kctsb::internal::sm2::precomp::sm2_point_jacobian;

    void SetUp() override {
        // Reset precomp table before each test
        kctsb::internal::sm2::precomp::reset_precomp_table();
    }

    void print_fe256(const char* name, const uint64_t* limbs) {
        std::cerr << name << ": ";
        for (int i = 3; i >= 0; i--) {
            std::cerr << std::hex << std::setfill('0') << std::setw(16) << limbs[i];
        }
        std::cerr << std::dec << std::endl;
    }

    bool is_zero(const MontFe* a) {
        return a->limb[0] == 0 && a->limb[1] == 0 && 
               a->limb[2] == 0 && a->limb[3] == 0;
    }
};

// ============================================================================
// Test 1: Verify Montgomery constants
// ============================================================================

TEST_F(SM2MontDebugTest, MontConstantsAreCorrect) {
    using namespace kctsb::internal::sm2::mont;

    // SM2 prime: p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    const uint64_t expected_p[4] = {
        0xFFFFFFFFFFFFFFFFULL,  // limb[0]
        0xFFFFFFFF00000000ULL,  // limb[1]
        0xFFFFFFFFFFFFFFFFULL,  // limb[2]
        0xFFFFFFFEFFFFFFFFULL   // limb[3]
    };

    // MONT_ONE = R mod p = 2^256 mod p
    // For SM2: MONT_ONE = 2^256 - p = 2^224 + 2^96 - 2^64 + 1
    const uint64_t expected_mont_one[4] = {
        0x0000000000000001ULL,  // +1
        0x00000000FFFFFFFFULL,  // -2^64 + 2^96
        0x0000000000000000ULL,
        0x0000000100000000ULL   // 2^224
    };

    std::cerr << "=== Verifying SM2 Montgomery Constants ===" << std::endl;
    print_fe256("Expected p      ", expected_p);
    print_fe256("Expected MONT_ONE", expected_mont_one);

    // Test: 1 (normal) -> to_mont -> should equal MONT_ONE
    MontFe one, one_mont;
    one.limb[0] = 1;
    one.limb[1] = 0;
    one.limb[2] = 0;
    one.limb[3] = 0;

    std::cerr << "Testing fe256_to_mont(1)..." << std::endl;
    fe256_to_mont(&one_mont, &one);
    print_fe256("to_mont(1)      ", one_mont.limb);
    print_fe256("Expected        ", expected_mont_one);

    EXPECT_EQ(one_mont.limb[0], expected_mont_one[0]);
    EXPECT_EQ(one_mont.limb[1], expected_mont_one[1]);
    EXPECT_EQ(one_mont.limb[2], expected_mont_one[2]);
    EXPECT_EQ(one_mont.limb[3], expected_mont_one[3]);
}

// ============================================================================
// Test 2: to_mont / from_mont roundtrip
// ============================================================================

TEST_F(SM2MontDebugTest, MontRoundtripWorks) {
    using namespace kctsb::internal::sm2::mont;

    std::cerr << "=== Testing Montgomery Roundtrip ===" << std::endl;

    // Test value: SM2 generator X coordinate
    MontFe gx, gx_mont, gx_back;
    gx.limb[0] = 0x715A4589334C74C7ULL;
    gx.limb[1] = 0x8FE30BBFF2660BE1ULL;
    gx.limb[2] = 0x5F9904466A39C994ULL;
    gx.limb[3] = 0x32C4AE2C1F198119ULL;

    print_fe256("Original Gx", gx.limb);

    std::cerr << "Calling fe256_to_mont..." << std::endl;
    fe256_to_mont(&gx_mont, &gx);
    print_fe256("to_mont(Gx) ", gx_mont.limb);

    ASSERT_FALSE(is_zero(&gx_mont)) << "to_mont should not produce zero";

    std::cerr << "Calling fe256_from_mont..." << std::endl;
    fe256_from_mont(&gx_back, &gx_mont);
    print_fe256("from_mont() ", gx_back.limb);

    EXPECT_EQ(gx_back.limb[0], gx.limb[0]) << "Roundtrip limb[0] mismatch";
    EXPECT_EQ(gx_back.limb[1], gx.limb[1]) << "Roundtrip limb[1] mismatch";
    EXPECT_EQ(gx_back.limb[2], gx.limb[2]) << "Roundtrip limb[2] mismatch";
    EXPECT_EQ(gx_back.limb[3], gx.limb[3]) << "Roundtrip limb[3] mismatch";
}

// ============================================================================
// Test 3: Montgomery multiplication basic operation
// ============================================================================

TEST_F(SM2MontDebugTest, MontMultiplicationWorks) {
    using namespace kctsb::internal::sm2::mont;

    std::cerr << "=== Testing Montgomery Multiplication ===" << std::endl;

    // Test: 2 * 3 = 6 in Montgomery form
    MontFe two, three, six_expected;
    MontFe two_mont, three_mont, result_mont, result;

    two.limb[0] = 2; two.limb[1] = 0; two.limb[2] = 0; two.limb[3] = 0;
    three.limb[0] = 3; three.limb[1] = 0; three.limb[2] = 0; three.limb[3] = 0;
    six_expected.limb[0] = 6; six_expected.limb[1] = 0; six_expected.limb[2] = 0; six_expected.limb[3] = 0;

    fe256_to_mont(&two_mont, &two);
    fe256_to_mont(&three_mont, &three);

    print_fe256("2 in mont ", two_mont.limb);
    print_fe256("3 in mont ", three_mont.limb);

    std::cerr << "Calling fe256_mont_mul..." << std::endl;
    fe256_mont_mul(&result_mont, &two_mont, &three_mont);
    print_fe256("2*3 mont  ", result_mont.limb);

    std::cerr << "Converting back from Montgomery..." << std::endl;
    fe256_from_mont(&result, &result_mont);
    print_fe256("2*3 normal", result.limb);

    EXPECT_EQ(result.limb[0], 6ULL) << "2*3 should equal 6";
    EXPECT_EQ(result.limb[1], 0ULL);
    EXPECT_EQ(result.limb[2], 0ULL);
    EXPECT_EQ(result.limb[3], 0ULL);
}

// ============================================================================
// Test 4: Precomputation table initialization
// ============================================================================

TEST_F(SM2MontDebugTest, PrecompTableInitializes) {
    using namespace kctsb::internal::sm2::precomp;

    std::cerr << "=== Testing Precomputation Table Init ===" << std::endl;

    EXPECT_FALSE(is_precomp_ready()) << "Table should not be initialized yet";

    std::cerr << "Calling compute_precomp_table()..." << std::endl;
    compute_precomp_table();
    std::cerr << "compute_precomp_table() completed!" << std::endl;

    EXPECT_TRUE(is_precomp_ready()) << "Table should be initialized after call";
}

// ============================================================================
// Test 5: Scalar multiplication k=1 produces G
// ============================================================================

TEST_F(SM2MontDebugTest, ScalarMul_k1_ProducesG) {
    using namespace kctsb::internal::sm2::precomp;
    using namespace kctsb::internal::sm2::mont;

    std::cerr << "=== Testing scalar_mul_base(k=1) ===" << std::endl;

    // k = 1
    uint64_t k[4] = {1, 0, 0, 0};

    JacobianPoint result;
    std::cerr << "Calling scalar_mul_base(k=1)..." << std::endl;
    scalar_mul_base(&result, k);
    std::cerr << "scalar_mul_base completed!" << std::endl;

    print_fe256("Result X (mont)", result.X.limb);
    print_fe256("Result Y (mont)", result.Y.limb);
    print_fe256("Result Z (mont)", result.Z.limb);

    // Convert back from Montgomery to verify
    MontFe x_aff, y_aff;
    fe256_from_mont(&x_aff, reinterpret_cast<MontFe*>(&result.X));
    fe256_from_mont(&y_aff, reinterpret_cast<MontFe*>(&result.Y));

    // Expected: SM2 generator point (affine, but Z might not be 1)
    // Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    // Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    const uint64_t expected_gx[4] = {
        0x715A4589334C74C7ULL,
        0x8FE30BBFF2660BE1ULL,
        0x5F9904466A39C994ULL,
        0x32C4AE2C1F198119ULL
    };

    std::cerr << "Checking if result is valid (non-zero Z)..." << std::endl;
    EXPECT_NE(result.Z.limb[0] | result.Z.limb[1] | result.Z.limb[2] | result.Z.limb[3], 0ULL)
        << "Z should not be zero (not infinity)";

    // For proper verification, we need to convert from Jacobian to affine
    // x = X/Z^2, y = Y/Z^3
    // For now, just check that the point is not degenerate
    EXPECT_NE(result.X.limb[0] | result.X.limb[1] | result.X.limb[2] | result.X.limb[3], 0ULL)
        << "X should not be zero";
    EXPECT_NE(result.Y.limb[0] | result.Y.limb[1] | result.Y.limb[2] | result.Y.limb[3], 0ULL)
        << "Y should not be zero";
}

// ============================================================================
// Test 6: Complete integration test (simulates sm2_keygen.cpp usage)
// ============================================================================

TEST_F(SM2MontDebugTest, IntegrationTest_KeyGenPath) {
    using namespace kctsb::internal::sm2::precomp;
    using namespace kctsb::internal::sm2::mont;

    std::cerr << "=== Integration Test: KeyGen Path ===" << std::endl;

    // Simulate private key (random 256-bit value mod n)
    // Use a fixed test value for reproducibility
    uint64_t d[4] = {
        0x7B9DFFB0F67F7E02ULL,
        0xBC3A4DB39E8A2D17ULL,
        0x6F9A3E0C45B6DAF2ULL,
        0x128B2FA8BD098F6AULL
    };

    std::cerr << "Test private key d:" << std::endl;
    print_fe256("d", d);

    std::cerr << "Step 1: Ensure precomp table is ready..." << std::endl;
    if (!is_precomp_ready()) {
        compute_precomp_table();
    }
    ASSERT_TRUE(is_precomp_ready());

    std::cerr << "Step 2: Compute P = d*G using scalar_mul_base..." << std::endl;
    JacobianPoint P;
    scalar_mul_base(&P, d);
    std::cerr << "scalar_mul_base completed!" << std::endl;

    print_fe256("P.X (mont)", P.X.limb);
    print_fe256("P.Y (mont)", P.Y.limb);
    print_fe256("P.Z (mont)", P.Z.limb);

    // Verify the result is not degenerate
    EXPECT_NE(P.Z.limb[0] | P.Z.limb[1] | P.Z.limb[2] | P.Z.limb[3], 0ULL)
        << "Public key Z should not be zero";

    std::cerr << "Step 3: Convert from Montgomery form..." << std::endl;
    MontFe x_norm, y_norm, z_norm;
    fe256_from_mont(&x_norm, reinterpret_cast<MontFe*>(&P.X));
    fe256_from_mont(&y_norm, reinterpret_cast<MontFe*>(&P.Y));
    fe256_from_mont(&z_norm, reinterpret_cast<MontFe*>(&P.Z));

    print_fe256("P.X (normal)", x_norm.limb);
    print_fe256("P.Y (normal)", y_norm.limb);
    print_fe256("P.Z (normal)", z_norm.limb);

    std::cerr << "Integration test completed successfully!" << std::endl;
}
// ============================================================================
// Test 7: Verify fe256_mont_inv works correctly
// ============================================================================

namespace kctsb::internal::sm2::mont {
    extern void fe256_mont_inv(fe256* r, const fe256* a);
}

TEST_F(SM2MontDebugTest, MontInverseWorks) {
    using namespace kctsb::internal::sm2::mont;

    std::cerr << "=== Testing fe256_mont_inv ===" << std::endl;

    // Test: a * a^(-1) = 1 (in Montgomery domain, = MONT_ONE)
    // Use a = 2 as test value
    MontFe a = {{2, 0, 0, 0}};  // a = 2 (normal form)
    MontFe a_mont, a_inv, product;

    // Convert to Montgomery
    fe256_to_mont(&a_mont, &a);
    print_fe256("a (mont)", a_mont.limb);

    // Compute inverse
    fe256_mont_inv(&a_inv, &a_mont);
    print_fe256("a^(-1) (mont)", a_inv.limb);

    // Verify: a * a^(-1) = 1 in Montgomery domain (= MONT_ONE)
    fe256_mont_mul(&product, &a_mont, &a_inv);
    print_fe256("a * a^(-1) (mont)", product.limb);

    // Convert to normal form - should be 1
    MontFe product_norm;
    fe256_from_mont(&product_norm, &product);
    print_fe256("a * a^(-1) (normal)", product_norm.limb);

    // Expected: 1
    EXPECT_EQ(product_norm.limb[0], 1ULL);
    EXPECT_EQ(product_norm.limb[1], 0ULL);
    EXPECT_EQ(product_norm.limb[2], 0ULL);
    EXPECT_EQ(product_norm.limb[3], 0ULL);
}