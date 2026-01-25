/**
 * @file test_fe256_debug.cpp
 * @brief fe256 Layer Debug Tests
 *
 * This test file is specifically for debugging fe256 point operations.
 * It compares fe256 results against NTL baseline to identify calculation bugs.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

// Enable fe256 debug mode
#define KCTSB_DEBUG_FE256 1

#include <gtest/gtest.h>
#include <iostream>
#include <iomanip>
#include <vector>

#if defined(KCTSB_HAS_BIGNUM_MODULES) || defined(KCTSB_USE_BIGNUM)

#include "kctsb/math/bignum/ZZ.h"
#include "kctsb/math/bignum/ZZ_p.h"
#include "kctsb/crypto/ecc/ecc_curve.h"

using namespace kctsb;
using namespace kctsb::ecc;

// ============================================================================
// fe256 Debug Test Fixture
// ============================================================================

class Fe256DebugTest : public ::testing::Test {
protected:
    void SetUp() override {
        curve_secp256k1_ = std::make_unique<ECCurve>(ECCurve::from_name("secp256k1"));
    }

    std::unique_ptr<ECCurve> curve_secp256k1_;
    
    // Helper to print ZZ in hex
    void print_hex(const char* name, const ZZ& v) {
        std::cerr << name << ": ";
        std::vector<uint8_t> bytes(32, 0);
        BytesFromZZ(bytes.data(), v, 32);
        for (int i = 31; i >= 0; --i) {
            std::cerr << std::hex << std::setfill('0') << std::setw(2) 
                      << (int)bytes[i];
        }
        std::cerr << std::dec << std::endl;
    }
};

// ============================================================================
// Test: Verify k=1 produces G
// ============================================================================

TEST_F(Fe256DebugTest, ScalarMult_k1_ProducesG) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    ZZ k = ZZ(1);
    
    // This will use fe256 path if KCTSB_DEBUG_FE256 is defined
    JacobianPoint result = curve_secp256k1_->scalar_mult(k, G);
    
    AffinePoint G_aff = curve_secp256k1_->to_affine(G);
    AffinePoint result_aff = curve_secp256k1_->to_affine(result);
    
    std::cerr << "=== k=1 Test ===" << std::endl;
    print_hex("G.x     ", rep(G_aff.x));
    print_hex("result.x", rep(result_aff.x));
    print_hex("G.y     ", rep(G_aff.y));
    print_hex("result.y", rep(result_aff.y));
    
    EXPECT_EQ(rep(result_aff.x), rep(G_aff.x)) << "1*G.x should equal G.x";
    EXPECT_EQ(rep(result_aff.y), rep(G_aff.y)) << "1*G.y should equal G.y";
}

// ============================================================================
// Test: Verify k=2 produces correct 2*G
// ============================================================================

TEST_F(Fe256DebugTest, ScalarMult_k2_Produces2G) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    ZZ k = ZZ(2);
    
    JacobianPoint result = curve_secp256k1_->scalar_mult(k, G);
    
    // Expected 2*G coordinates (secp256k1)
    ZZ expected_2Gx = ZZ::from_decimal("89565891926547004231252920425935692360644145829622209833684329913297188986597");
    ZZ expected_2Gy = ZZ::from_decimal("12158399299693830322967808612713398636155367887041628176798871954788371653930");
    
    AffinePoint result_aff = curve_secp256k1_->to_affine(result);
    
    std::cerr << "=== k=2 Test ===" << std::endl;
    print_hex("expected 2G.x", expected_2Gx);
    print_hex("result.x     ", rep(result_aff.x));
    print_hex("expected 2G.y", expected_2Gy);
    print_hex("result.y     ", rep(result_aff.y));
    
    EXPECT_TRUE(curve_secp256k1_->is_on_curve(result)) << "2*G should be on curve";
    EXPECT_EQ(rep(result_aff.x), expected_2Gx) << "2*G.x mismatch";
    EXPECT_EQ(rep(result_aff.y), expected_2Gy) << "2*G.y mismatch";
}

// ============================================================================
// Test: Verify k=3 works
// ============================================================================

TEST_F(Fe256DebugTest, ScalarMult_k3_OnCurve) {
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    JacobianPoint G = curve_secp256k1_->get_generator();
    ZZ k = ZZ(3);
    
    JacobianPoint result = curve_secp256k1_->scalar_mult(k, G);
    
    EXPECT_TRUE(curve_secp256k1_->is_on_curve(result)) << "3*G should be on curve";
    EXPECT_FALSE(result.is_infinity()) << "3*G should not be infinity";
    
    AffinePoint result_aff = curve_secp256k1_->to_affine(result);
    std::cerr << "=== k=3 Test ===" << std::endl;
    print_hex("result.x", rep(result_aff.x));
    print_hex("result.y", rep(result_aff.y));
}

#else
TEST(Fe256DebugTest, DISABLED_Bignum_NotAvailable) {
    GTEST_SKIP() << "Bignum modules not available";
}
#endif


