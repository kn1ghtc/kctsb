/**
 * @file test_ecc.cpp
 * @brief ECC (Elliptic Curve Cryptography) unit tests
 * 
 * Comprehensive tests for ECC functionality including:
 * - ECCurve class with bignum backend
 * - Generator point validation for secp256k1, P-256, SM2
 * - Scalar multiplication (Montgomery ladder)
 * - Point addition and doubling
 * - Coordinate conversion (Jacobian 鈫?Affine)
 * 
 * Tests migrated from test_fe256_point.cpp (v4.6.0)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>

// Check if bignum modules are available
#if defined(KCTSB_HAS_BIGNUM_MODULES) || defined(KCTSB_USE_BIGNUM)

#include "kctsb/math/bignum/ZZ.h"
#include "kctsb/math/bignum/ZZ_p.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
using namespace kctsb;
using namespace kctsb::ecc::internal;  // ZZ-based internal implementation

// ============================================================================
// ECCurve Test Fixture
// ============================================================================

class ECCurveTest : public ::testing::Test {
protected:
    void SetUp() override {
        curve_secp256k1_ = std::make_unique<ECCurve>(ECCurve::from_name("secp256k1"));
        curve_p256_ = std::make_unique<ECCurve>(ECCurve::from_name("secp256r1"));
        curve_sm2_ = std::make_unique<ECCurve>(ECCurve::from_name("sm2"));
    }

    std::unique_ptr<ECCurve> curve_secp256k1_;
    std::unique_ptr<ECCurve> curve_p256_;
    std::unique_ptr<ECCurve> curve_sm2_;
};

// ============================================================================
// Curve Creation and Parameter Tests
// ============================================================================

TEST_F(ECCurveTest, CreateSecp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    EXPECT_EQ(curve_secp256k1_->get_name(), "secp256k1");
    EXPECT_EQ(curve_secp256k1_->get_bit_size(), 256);
}

TEST_F(ECCurveTest, CreateP256) {
    ASSERT_NE(curve_p256_, nullptr);
    EXPECT_EQ(curve_p256_->get_name(), "secp256r1");
    EXPECT_EQ(curve_p256_->get_bit_size(), 256);
}

TEST_F(ECCurveTest, CreateSM2) {
    ASSERT_NE(curve_sm2_, nullptr);
    EXPECT_EQ(curve_sm2_->get_name(), "sm2");
    EXPECT_EQ(curve_sm2_->get_bit_size(), 256);
}

TEST_F(ECCurveTest, CurveFromNameVariants) {
    // Test various P-256 aliases
    auto p256_1 = ECCurve::from_name("p-256");
    auto p256_2 = ECCurve::from_name("P256");
    auto p256_3 = ECCurve::from_name("prime256v1");
    
    EXPECT_EQ(p256_1.get_name(), "secp256r1");
    EXPECT_EQ(p256_2.get_name(), "secp256r1");
    EXPECT_EQ(p256_3.get_name(), "secp256r1");
}

TEST_F(ECCurveTest, InvalidCurveName) {
    EXPECT_THROW(ECCurve::from_name("unknown_curve"), std::invalid_argument);
}

// ============================================================================
// Generator Point Tests
// ============================================================================

TEST_F(ECCurveTest, GeneratorOnCurve_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    JacobianPoint G = curve_secp256k1_->get_generator();
    EXPECT_TRUE(curve_secp256k1_->is_on_curve(G)) << "secp256k1 generator should be on curve";
}

TEST_F(ECCurveTest, GeneratorOnCurve_P256) {
    ASSERT_NE(curve_p256_, nullptr);
    JacobianPoint G = curve_p256_->get_generator();
    EXPECT_TRUE(curve_p256_->is_on_curve(G)) << "P-256 generator should be on curve";
}

TEST_F(ECCurveTest, GeneratorOnCurve_SM2) {
    ASSERT_NE(curve_sm2_, nullptr);
    JacobianPoint G = curve_sm2_->get_generator();
    EXPECT_TRUE(curve_sm2_->is_on_curve(G)) << "SM2 generator should be on curve";
}

TEST_F(ECCurveTest, GeneratorCoordinates_Secp256k1) {
    // Expected secp256k1 Gx: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    // Expected secp256k1 Gy: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    
    ASSERT_NE(curve_secp256k1_, nullptr);
    JacobianPoint G = curve_secp256k1_->get_generator();
    AffinePoint G_aff = curve_secp256k1_->to_affine(G);
    
    ZZ expected_Gx = ZZ::from_decimal("55066263022277343669578718895168534326250603453777594175500187360389116729240");
    ZZ expected_Gy = ZZ::from_decimal("32670510020758816978083085130507043184471273380659243275938904335757337482424");
    
    EXPECT_EQ(rep(G_aff.x), expected_Gx) << "secp256k1 Gx mismatch";
    EXPECT_EQ(rep(G_aff.y), expected_Gy) << "secp256k1 Gy mismatch";
}

TEST_F(ECCurveTest, GeneratorCoordinates_P256) {
    // Expected P-256 Gx: 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    // Expected P-256 Gy: 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    
    ASSERT_NE(curve_p256_, nullptr);
    JacobianPoint G = curve_p256_->get_generator();
    AffinePoint G_aff = curve_p256_->to_affine(G);
    
    ZZ expected_Gx = ZZ::from_decimal("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    ZZ expected_Gy = ZZ::from_decimal("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    
    EXPECT_EQ(rep(G_aff.x), expected_Gx) << "P-256 Gx mismatch";
    EXPECT_EQ(rep(G_aff.y), expected_Gy) << "P-256 Gy mismatch";
}

TEST_F(ECCurveTest, GeneratorCoordinates_SM2) {
    ASSERT_NE(curve_sm2_, nullptr);
    JacobianPoint G = curve_sm2_->get_generator();
    AffinePoint G_aff = curve_sm2_->to_affine(G);
    
    ZZ expected_Gx = ZZ::from_decimal("22963146547237050559479531362550074578802567295341616970375194840604139615431");
    ZZ expected_Gy = ZZ::from_decimal("85132369209828568825618990617112496413088388631904505083283536607588877201568");
    
    EXPECT_EQ(rep(G_aff.x), expected_Gx) << "SM2 Gx mismatch";
    EXPECT_EQ(rep(G_aff.y), expected_Gy) << "SM2 Gy mismatch";
}

// ============================================================================
// Scalar Multiplication Tests (Montgomery Ladder)
// ============================================================================

TEST_F(ECCurveTest, ScalarMultOne_Secp256k1) {
    // Test: 1*G should equal G
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    ZZ k = ZZ(1);
    JacobianPoint G = curve_secp256k1_->get_generator();
    JacobianPoint result = curve_secp256k1_->scalar_mult(k, G);
    
    AffinePoint G_aff = curve_secp256k1_->to_affine(G);
    AffinePoint result_aff = curve_secp256k1_->to_affine(result);
    
    EXPECT_EQ(rep(result_aff.x), rep(G_aff.x)) << "1*G should equal G (x coordinate)";
    EXPECT_EQ(rep(result_aff.y), rep(G_aff.y)) << "1*G should equal G (y coordinate)";
}

TEST_F(ECCurveTest, ScalarMultTwo_Secp256k1) {
    // Test: 2*G by scalar multiplication
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    ZZ k = ZZ(2);
    JacobianPoint G = curve_secp256k1_->get_generator();
    JacobianPoint result = curve_secp256k1_->scalar_mult(k, G);
    
    EXPECT_TRUE(curve_secp256k1_->is_on_curve(result)) << "2*G should be on curve";
    EXPECT_FALSE(result.is_infinity()) << "2*G should not be infinity";
}

TEST_F(ECCurveTest, ScalarMultVarious_Secp256k1) {
    // Test with various k values
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    
    std::vector<std::string> test_ks = {
        "1", "2", "3", "4", "5", "10", "100", "1000",
        "12345678901234567890",
        "295990755083832485362655746424040587759"
    };

    for (const auto& ks : test_ks) {
        ZZ k = ZZ::from_decimal(ks.c_str());
        JacobianPoint result = curve_secp256k1_->scalar_mult(k, G);
        
        EXPECT_TRUE(curve_secp256k1_->is_on_curve(result)) 
            << "k*G should be on curve for k=" << ks;
    }
}

TEST_F(ECCurveTest, ScalarMultBase_P256) {
    // Test scalar_mult_base function
    ASSERT_NE(curve_p256_, nullptr);
    
    ZZ k = ZZ::from_decimal("295990755083832485362655746424040587759");
    JacobianPoint result = curve_p256_->scalar_mult_base(k);
    
    EXPECT_TRUE(curve_p256_->is_on_curve(result)) << "k*G should be on curve for P-256";
    
    // Compare with manual scalar_mult
    JacobianPoint G = curve_p256_->get_generator();
    JacobianPoint manual_result = curve_p256_->scalar_mult(k, G);
    
    AffinePoint aff1 = curve_p256_->to_affine(result);
    AffinePoint aff2 = curve_p256_->to_affine(manual_result);
    
    EXPECT_EQ(rep(aff1.x), rep(aff2.x)) << "scalar_mult_base should match scalar_mult";
    EXPECT_EQ(rep(aff1.y), rep(aff2.y)) << "scalar_mult_base should match scalar_mult";
}

TEST_F(ECCurveTest, ScalarMultOrder_Secp256k1) {
    // Test: n*G = O (infinity)
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    ZZ n = curve_secp256k1_->get_order();
    JacobianPoint G = curve_secp256k1_->get_generator();
    JacobianPoint result = curve_secp256k1_->scalar_mult(n, G);
    
    EXPECT_TRUE(result.is_infinity()) << "n*G should be infinity";
}

// ============================================================================
// Point Addition Tests
// ============================================================================

TEST_F(ECCurveTest, PointAddition_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    JacobianPoint two_G = curve_secp256k1_->add(G, G);
    JacobianPoint three_G = curve_secp256k1_->add(two_G, G);
    
    // Verify 3*G computed by addition matches scalar_mult(3, G)
    JacobianPoint three_G_scalar = curve_secp256k1_->scalar_mult(ZZ(3), G);
    
    AffinePoint aff1 = curve_secp256k1_->to_affine(three_G);
    AffinePoint aff2 = curve_secp256k1_->to_affine(three_G_scalar);
    
    EXPECT_EQ(rep(aff1.x), rep(aff2.x)) << "G+G+G should equal 3*G (x)";
    EXPECT_EQ(rep(aff1.y), rep(aff2.y)) << "G+G+G should equal 3*G (y)";
}

TEST_F(ECCurveTest, PointDoubling_P256) {
    ASSERT_NE(curve_p256_, nullptr);
    
    JacobianPoint G = curve_p256_->get_generator();
    JacobianPoint two_G = curve_p256_->double_point(G);
    
    // Verify 2*G by doubling matches scalar_mult(2, G)
    JacobianPoint two_G_scalar = curve_p256_->scalar_mult(ZZ(2), G);
    
    AffinePoint aff1 = curve_p256_->to_affine(two_G);
    AffinePoint aff2 = curve_p256_->to_affine(two_G_scalar);
    
    EXPECT_EQ(rep(aff1.x), rep(aff2.x)) << "2*G by double should match scalar_mult";
    EXPECT_EQ(rep(aff1.y), rep(aff2.y)) << "2*G by double should match scalar_mult";
}

TEST_F(ECCurveTest, PointNegation_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    JacobianPoint neg_G = curve_secp256k1_->negate(G);
    JacobianPoint sum = curve_secp256k1_->add(G, neg_G);
    
    EXPECT_TRUE(sum.is_infinity()) << "G + (-G) should be infinity";
}

TEST_F(ECCurveTest, PointSubtraction_SM2) {
    ASSERT_NE(curve_sm2_, nullptr);
    
    JacobianPoint G = curve_sm2_->get_generator();
    JacobianPoint two_G = curve_sm2_->scalar_mult(ZZ(2), G);
    JacobianPoint result = curve_sm2_->subtract(two_G, G);
    
    AffinePoint aff1 = curve_sm2_->to_affine(result);
    AffinePoint aff2 = curve_sm2_->to_affine(G);
    
    EXPECT_EQ(rep(aff1.x), rep(aff2.x)) << "2G - G should equal G (x)";
    EXPECT_EQ(rep(aff1.y), rep(aff2.y)) << "2G - G should equal G (y)";
}

// ============================================================================
// Double Scalar Multiplication (Shamir's Trick)
// ============================================================================

TEST_F(ECCurveTest, DoubleScalarMult_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    ZZ k1 = ZZ(123);
    ZZ k2 = ZZ(456);
    
    // Compute k1*G + k2*G using double_scalar_mult
    JacobianPoint result = curve_secp256k1_->double_scalar_mult(k1, G, k2, G);
    
    // Compare with (k1 + k2)*G
    JacobianPoint expected = curve_secp256k1_->scalar_mult(k1 + k2, G);
    
    AffinePoint aff1 = curve_secp256k1_->to_affine(result);
    AffinePoint aff2 = curve_secp256k1_->to_affine(expected);
    
    EXPECT_EQ(rep(aff1.x), rep(aff2.x)) << "k1*G + k2*G should equal (k1+k2)*G";
    EXPECT_EQ(rep(aff1.y), rep(aff2.y)) << "k1*G + k2*G should equal (k1+k2)*G";
}

// ============================================================================
// Point Serialization Tests
// ============================================================================

TEST_F(ECCurveTest, PointSerialization_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    AffinePoint G_aff = curve_secp256k1_->to_affine(G);
    
    // Serialize
    unsigned char buffer[65];
    int len = curve_secp256k1_->point_to_bytes(G_aff, buffer, sizeof(buffer));
    
    EXPECT_EQ(len, 65) << "Uncompressed point should be 65 bytes";
    EXPECT_EQ(buffer[0], 0x04) << "Uncompressed format should start with 0x04";
    
    // Deserialize
    AffinePoint G_restored = curve_secp256k1_->point_from_bytes(buffer, len);
    
    EXPECT_EQ(rep(G_restored.x), rep(G_aff.x)) << "Restored x should match";
    EXPECT_EQ(rep(G_restored.y), rep(G_aff.y)) << "Restored y should match";
}

TEST_F(ECCurveTest, InfinityPointSerialization) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    AffinePoint infinity;  // Default is infinity
    unsigned char buffer[65];
    int len = curve_secp256k1_->point_to_bytes(infinity, buffer, sizeof(buffer));
    
    EXPECT_EQ(len, 1) << "Infinity point should serialize to 1 byte";
    EXPECT_EQ(buffer[0], 0x00) << "Infinity point should be 0x00";
}

// ============================================================================
// Point Validation Tests
// ============================================================================

TEST_F(ECCurveTest, ValidatePoint_OnCurve) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    EXPECT_TRUE(curve_secp256k1_->validate_point(G)) 
        << "Generator should be valid (on curve and in subgroup)";
}

TEST_F(ECCurveTest, InvalidPointNotOnCurve) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    // Create a point with arbitrary coordinates (likely not on curve)
    ZZ_p::init(curve_secp256k1_->get_prime());
    ZZ_p bad_x = ZZ_p(12345);
    ZZ_p bad_y = ZZ_p(67890);
    AffinePoint bad_point(bad_x, bad_y);
    
    EXPECT_FALSE(curve_secp256k1_->is_on_curve(bad_point)) 
        << "Arbitrary point should not be on curve";
}

#else
// Bignum modules not available - skip tests
TEST(ECCTest, DISABLED_Bignum_NotAvailable) {
    GTEST_SKIP() << "Bignum modules not available, ECC tests skipped";
}
#endif // KCTSB_HAS_BIGNUM_MODULES

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

