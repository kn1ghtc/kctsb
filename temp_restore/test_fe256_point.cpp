/**
 * @file test_fe256_point.cpp
 * @brief Unit tests for fe256_point optimized point arithmetic
 *
 * Tests fe256-accelerated point operations against ZZ_p reference implementation.
 * Verifies correctness of:
 * - Generator point coordinates
 * - Montgomery form conversion
 * - Scalar multiplication
 * - Affine conversion
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "crypto/ecc/fe256.h"
#include "crypto/ecc/fe256_point.h"
#include "crypto/ecc/fe256_ecc_fast.h"
#include <iostream>
#include <iomanip>
#include <cstring>

using namespace kctsb;
using namespace kctsb::ecc;

// Helper to print fe256 in hex
static void print_fe256(const char* name, const fe256* a) {
    std::cout << name << " = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << a->limb[i];
    }
    std::cout << std::dec << std::endl;
}

class Fe256PointTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up test curves using from_name
        curve_secp256k1_ = std::make_unique<ECCurve>(ECCurve::from_name("secp256k1"));
        curve_p256_ = std::make_unique<ECCurve>(ECCurve::from_name("secp256r1"));
    }

    std::unique_ptr<ECCurve> curve_secp256k1_;
    std::unique_ptr<ECCurve> curve_p256_;
};

// Test 1: Verify generator point coordinates match expected values
TEST_F(Fe256PointTest, GeneratorCoordinatesSecp256k1) {
    // Expected secp256k1 Gx (hex): 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    // Expected Gy: 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    const fe256_point* g = fe256_get_generator(FE256_CURVE_SECP256K1);

    // Generator is now in Montgomery form, so we need to convert back
    fe256 gx_normal, gy_normal;
    fe256_copy(&gx_normal, &g->X);
    fe256_copy(&gy_normal, &g->Y);
    fe256_from_mont_secp256k1(&gx_normal, &gx_normal);
    fe256_from_mont_secp256k1(&gy_normal, &gy_normal);

    // Expected values (little-endian limbs)
    const uint64_t expected_gx[4] = {
        0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
        0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
    };
    const uint64_t expected_gy[4] = {
        0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
        0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
    };

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(gx_normal.limb[i], expected_gx[i]) << "Gx limb " << i << " mismatch";
        EXPECT_EQ(gy_normal.limb[i], expected_gy[i]) << "Gy limb " << i << " mismatch";
    }
}

TEST_F(Fe256PointTest, GeneratorCoordinatesP256) {
    // Expected P-256 Gx: 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    // Expected Gy: 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

    const fe256_point* g = fe256_get_generator(FE256_CURVE_P256);

    fe256 gx_normal, gy_normal;
    fe256_copy(&gx_normal, &g->X);
    fe256_copy(&gy_normal, &g->Y);
    fe256_from_mont_p256(&gx_normal, &gx_normal);
    fe256_from_mont_p256(&gy_normal, &gy_normal);

    const uint64_t expected_gx[4] = {
        0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL,
        0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL
    };
    const uint64_t expected_gy[4] = {
        0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL,
        0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL
    };

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(gx_normal.limb[i], expected_gx[i]) << "Gx limb " << i << " mismatch";
        EXPECT_EQ(gy_normal.limb[i], expected_gy[i]) << "Gy limb " << i << " mismatch";
    }
}

// Test 2: Verify Montgomery conversion is reversible
TEST_F(Fe256PointTest, MontgomeryRoundtripSecp256k1) {
    fe256 original;
    original.limb[0] = 0x1234567890ABCDEFULL;
    original.limb[1] = 0xFEDCBA0987654321ULL;
    original.limb[2] = 0xAAAABBBBCCCCDDDDULL;
    original.limb[3] = 0x1111222233334444ULL;

    fe256 mont, recovered;
    fe256_to_mont_secp256k1(&mont, &original);
    fe256_from_mont_secp256k1(&recovered, &mont);

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(recovered.limb[i], original.limb[i]) << "Limb " << i << " mismatch";
    }
}

TEST_F(Fe256PointTest, MontgomeryRoundtripP256) {
    fe256 original;
    original.limb[0] = 0x1234567890ABCDEFULL;
    original.limb[1] = 0xFEDCBA0987654321ULL;
    original.limb[2] = 0xAAAABBBBCCCCDDDDULL;
    original.limb[3] = 0x1111222233334444ULL;

    fe256 mont, recovered;
    fe256_to_mont_p256(&mont, &original);
    fe256_from_mont_p256(&recovered, &mont);

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(recovered.limb[i], original.limb[i]) << "Limb " << i << " mismatch";
    }
}

// Test 3: Verify scalar mult base (k*G) produces valid point
TEST_F(Fe256PointTest, ScalarMultBaseSecp256k1) {
    // Test: 1*G should equal G
    uint64_t k_one[4] = {1, 0, 0, 0};

    fe256_point result;
    fe256_point_scalar_mult_base(&result, k_one, FE256_CURVE_SECP256K1);

    // Convert to affine
    fe256 x_aff, y_aff;
    int rc = fe256_point_to_affine(&x_aff, &y_aff, &result, FE256_CURVE_SECP256K1);
    ASSERT_EQ(rc, 0) << "Affine conversion failed";

    // Convert from Montgomery
    fe256_from_mont_secp256k1(&x_aff, &x_aff);
    fe256_from_mont_secp256k1(&y_aff, &y_aff);

    // Expected Gx
    const uint64_t expected_gx[4] = {
        0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
        0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
    };

    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(x_aff.limb[i], expected_gx[i]) << "1*G.x limb " << i << " mismatch";
    }
}

// Test 4: Verify 2*G calculation
TEST_F(Fe256PointTest, ScalarMultTwoG_Secp256k1) {
    // First compute using ZZ_p reference
    ASSERT_NE(curve_secp256k1_, nullptr);
    
    ZZ p = curve_secp256k1_->get_prime();
    ZZ_p::init(p);
    
    // Test basic field operations: A^2 where A is G.x
    JacobianPoint G_jac = curve_secp256k1_->get_generator();
    AffinePoint G_aff = curve_secp256k1_->to_affine(G_jac);
    
    // Compute A = Gx^2 using ZZ_p
    ZZ_p A_zz = G_aff.x * G_aff.x;
    std::cout << "ZZ_p G.x^2 = " << std::hex << rep(A_zz) << std::dec << std::endl;
    
    // Compute A = Gx^2 using fe256
    const fe256_point* fe_g = fe256_get_generator(FE256_CURVE_SECP256K1);
    fe256 A_fe;
    fe256_sqr_mont_secp256k1(&A_fe, &fe_g->X);
    
    std::cout << "fe256 G.x^2 = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << A_fe.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    // Convert to ZZ for comparison
    ZZ A_fe_zz = fe256_to_zz(&A_fe);
    
    EXPECT_EQ(A_fe_zz, rep(A_zz)) << "G.x^2 mismatch!";
    
    // Test multiplication: B = Gx * Gy
    ZZ_p B_zz = G_aff.x * G_aff.y;
    std::cout << "ZZ_p G.x*G.y = " << std::hex << rep(B_zz) << std::dec << std::endl;
    
    fe256 B_fe;
    fe256_mul_mont_secp256k1(&B_fe, &fe_g->X, &fe_g->Y);
    
    std::cout << "fe256 G.x*G.y = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << B_fe.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    ZZ B_fe_zz = fe256_to_zz(&B_fe);
    EXPECT_EQ(B_fe_zz, rep(B_zz)) << "G.x*G.y mismatch!";
}

// Test 5: Compare fe256 result with ZZ_p reference for various k values
TEST_F(Fe256PointTest, CompareWithZZ_pReference_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);

    JacobianPoint G = curve_secp256k1_->get_generator();

    // Test with various k values (decimal strings for NTL conv<ZZ>)
    std::vector<std::string> test_ks = {
        "1", "2", "3", "4", "5", "10", "100", "1000",
        "12345678901234567890",
        "295990755083832485362655746424040587759"  // 0xDEADBEEFCAFEBABE1234567890ABCDEF
    };

    for (const auto& ks : test_ks) {
        ZZ k = conv<ZZ>(ks.c_str());

        // Compute using ZZ_p scalar_mult (k * G)
        JacobianPoint ref_mult = curve_secp256k1_->scalar_mult(k, G);
        AffinePoint ref_mult_aff = curve_secp256k1_->to_affine(ref_mult);

        // Use fe256_fast_scalar_mult_base
        JacobianPoint fe_result_jac = fe256_fast_scalar_mult_base("secp256k1", k,
                                                                   curve_secp256k1_->get_prime());
        AffinePoint fe_aff = curve_secp256k1_->to_affine(fe_result_jac);

        EXPECT_EQ(rep(fe_aff.x), rep(ref_mult_aff.x)) << "X coordinate mismatch for k=" << ks;
        EXPECT_EQ(rep(fe_aff.y), rep(ref_mult_aff.y)) << "Y coordinate mismatch for k=" << ks;
    }
}

// Test 6: Test JacobianPoint to fe256_point roundtrip
TEST_F(Fe256PointTest, JacobianRoundtrip_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);

    // Get generator from ECCurve
    JacobianPoint G_jac = curve_secp256k1_->get_generator();

    // Convert to fe256_point
    fe256_point fe_g;
    jacobian_to_fe256_point(&fe_g, G_jac, FE256_CURVE_SECP256K1);

    // Convert back to JacobianPoint
    JacobianPoint G_back;
    fe256_point_to_jacobian(G_back, &fe_g, curve_secp256k1_->get_prime(), FE256_CURVE_SECP256K1);

    // Verify it's still on curve
    EXPECT_TRUE(curve_secp256k1_->is_on_curve(G_back)) 
        << "Roundtrip point is not on curve!";

    // Verify coordinates match
    AffinePoint aff_orig = curve_secp256k1_->to_affine(G_jac);
    AffinePoint aff_back = curve_secp256k1_->to_affine(G_back);

    EXPECT_EQ(rep(aff_orig.x), rep(aff_back.x)) << "X coordinate changed in roundtrip";
    EXPECT_EQ(rep(aff_orig.y), rep(aff_back.y)) << "Y coordinate changed in roundtrip";
}

// Test 7: Full integration test - fe256 fast path
TEST_F(Fe256PointTest, FastPathIntegration_Secp256k1) {
    ASSERT_NE(curve_secp256k1_, nullptr);

    // Use decimal string for NTL ZZ conversion (hex strings don't work with conv<ZZ>)
    // 0xDEADBEEFCAFEBABE1234567890ABCDEF = 295990755083832485362655746424040587759
    ZZ k = conv<ZZ>("295990755083832485362655746424040587759");

    // Get generator
    JacobianPoint G = curve_secp256k1_->get_generator();

    // Compute k*G using fe256 fast path
    JacobianPoint result = fe256_fast_scalar_mult_base("secp256k1", k,
                                                       curve_secp256k1_->get_prime());

    // Verify result is on curve
    EXPECT_TRUE(curve_secp256k1_->is_on_curve(result))
        << "fe256 fast path result is not on curve!";

    // Compare with standard scalar_mult reference
    JacobianPoint ref = curve_secp256k1_->scalar_mult(k, G);
    AffinePoint aff_result = curve_secp256k1_->to_affine(result);
    AffinePoint aff_ref = curve_secp256k1_->to_affine(ref);

    EXPECT_EQ(rep(aff_result.x), rep(aff_ref.x)) << "X mismatch vs reference";
    EXPECT_EQ(rep(aff_result.y), rep(aff_ref.y)) << "Y mismatch vs reference";
}

// Test 8: P-256 basic field arithmetic test - verify Solinas reduction works
TEST_F(Fe256PointTest, P256_FieldArithmetic_GxSquared) {
    // Expected Gx^2 mod p for P-256
    // Gx^2 = 0x98f6b84d29bef2b281819a5e0e3690d833b699495d694dd1002ae56c426b3f8c
    const uint64_t expected_gx_sq[4] = {
        0x002AE56C426B3F8CULL, 0x33B699495D694DD1ULL,
        0x81819A5E0E3690D8ULL, 0x98F6B84D29BEF2B2ULL
    };

    // Get P-256 generator (in Montgomery form, but P-256 uses identity)
    const fe256_point* g = fe256_get_generator(FE256_CURVE_P256);
    
    // Compute Gx^2
    fe256 gx_sq;
    fe256_sqr_mont_p256(&gx_sq, &g->X);
    
    // Print actual value
    std::cout << "P-256 Gx^2 (fe256) = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << gx_sq.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    // Verify
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(gx_sq.limb[i], expected_gx_sq[i]) << "Gx^2 limb " << i << " mismatch";
    }
}

// Test 8b: P-256 simple multiplication test
TEST_F(Fe256PointTest, P256_FieldArithmetic_SimpleMul) {
    // Test: 2 * 3 = 6 (no reduction needed)
    fe256 a, b, result;
    fe256_zero(&a);
    fe256_zero(&b);
    a.limb[0] = 2;
    b.limb[0] = 3;
    
    fe256_mul_mont_p256(&result, &a, &b);
    
    std::cout << "P-256 2*3 = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << result.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    EXPECT_EQ(result.limb[0], 6ULL) << "2*3 should be 6";
    EXPECT_EQ(result.limb[1], 0ULL);
    EXPECT_EQ(result.limb[2], 0ULL);
    EXPECT_EQ(result.limb[3], 0ULL);
}

// Test 8b2: P-256 simple squaring test
TEST_F(Fe256PointTest, P256_FieldArithmetic_SimpleSquare) {
    // Test: 3^2 = 9
    fe256 a, result;
    fe256_zero(&a);
    a.limb[0] = 3;
    
    fe256_sqr_mont_p256(&result, &a);
    
    std::cout << "P-256 3^2 = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << result.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    EXPECT_EQ(result.limb[0], 9ULL) << "3^2 should be 9";
    EXPECT_EQ(result.limb[1], 0ULL);
    EXPECT_EQ(result.limb[2], 0ULL);
    EXPECT_EQ(result.limb[3], 0ULL);
    
    // Test: square with aliasing (r == a)
    fe256 b;
    fe256_zero(&b);
    b.limb[0] = 5;
    fe256_sqr_mont_p256(&b, &b);  // b = 5^2 = 25
    
    std::cout << "P-256 5^2 (aliased) = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << b.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    EXPECT_EQ(b.limb[0], 25ULL) << "5^2 should be 25";
    EXPECT_EQ(b.limb[1], 0ULL);
    EXPECT_EQ(b.limb[2], 0ULL);
    EXPECT_EQ(b.limb[3], 0ULL);
}

// Test 8b3: P-256 repeated squaring test (simulating inversion loop)
TEST_F(Fe256PointTest, P256_FieldArithmetic_RepeatedSquare) {
    // Start with 2
    fe256 result;
    fe256_zero(&result);
    result.limb[0] = 2;
    
    // Square 10 times with aliasing
    for (int i = 0; i < 10; i++) {
        fe256_sqr_mont_p256(&result, &result);
    }
    
    // Expected: 2^(2^10) mod p = 2^1024 mod p
    // This is a huge number, let's just verify it's non-zero and consistent
    std::cout << "P-256 2^1024 mod p = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << result.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    // Compute expected with Python:
    // pow(2, 1024, p) = 0x00000069000000320000004000000011ffffffbcffffffc6ffffffd900000015
    const uint64_t expected[4] = {
        0xFFFFFFD900000015ULL, 0xFFFFFFBCFFFFFFC6ULL,
        0x0000004000000011ULL, 0x0000006900000032ULL
    };
    
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(result.limb[i], expected[i]) << "2^1024 limb " << i << " mismatch";
    }
}

// Test 8c: P-256 inversion test
TEST_F(Fe256PointTest, P256_FieldArithmetic_Inversion) {
    // Test: 2^(-1) mod p
    // Expected: 0x7fffffff80000000800000000000000000000000800000000000000000000000
    const uint64_t expected_inv[4] = {
        0x0000000000000000ULL, 0x0000000080000000ULL,
        0x8000000000000000ULL, 0x7FFFFFFF80000000ULL
    };

    fe256 a;
    fe256_zero(&a);
    a.limb[0] = 2;  // a = 2
    
    fe256 a_inv;
    fe256_inv_p256(&a_inv, &a);
    
    // Print actual value
    std::cout << "P-256 2^(-1) = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << a_inv.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    // Verify
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(a_inv.limb[i], expected_inv[i]) << "2^(-1) limb " << i << " mismatch";
    }
    
    // Also verify: a * a_inv = 1 mod p
    fe256 product;
    fe256_mul_mont_p256(&product, &a, &a_inv);
    
    std::cout << "P-256 2 * 2^(-1) = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << product.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    EXPECT_EQ(product.limb[0], 1ULL) << "2 * 2^(-1) limb 0 should be 1";
    EXPECT_EQ(product.limb[1], 0ULL) << "2 * 2^(-1) limb 1 should be 0";
    EXPECT_EQ(product.limb[2], 0ULL) << "2 * 2^(-1) limb 2 should be 0";
    EXPECT_EQ(product.limb[3], 0ULL) << "2 * 2^(-1) limb 3 should be 0";
}

// Test 8d: P-256 debug sqr - test wide mul and reduce separately
TEST_F(Fe256PointTest, P256_FieldArithmetic_InversionDebug) {
    // Test value that causes sqr bug
    fe256 a;
    a.limb[0] = 0xFFFF83B27FFF5897ULL;
    a.limb[1] = 0x0000C8F0FFFFD82BULL;
    a.limb[2] = 0x000061970000BEC6ULL;
    a.limb[3] = 0xFFFF8B3A00009F6FULL;
    
    std::cout << "Input a: ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << a.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    // Step 1: Test fe256_mul_wide
    fe512 wide;
    fe256_mul_wide(&wide, &a, &a);
    
    std::cout << "Wide result (a^2 512-bit): ";
    for (int i = 7; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << wide.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    // Expected wide result from Python:
    const uint64_t expected_wide[8] = {
        0xE29314936D7A2911ULL, 0x1FDE39AA70726F5EULL,
        0x88936116498C5338ULL, 0x0B04FAEA33122D74ULL,
        0xB0117BE8672782ABULL, 0xCB853A8C5B819E52ULL,
        0x6E8D8B7A0A44C218ULL, 0xFFFF167435454801ULL
    };
    
    for (int i = 0; i < 8; i++) {
        EXPECT_EQ(wide.limb[i], expected_wide[i]) << "wide limb " << i << " mismatch";
    }
    
    // Step 2: Test fe256_reduce_p256
    fe256 result;
    fe256_reduce_p256(&result, &wide);
    
    std::cout << "Reduced result: ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << result.limb[i];
    }
    std::cout << std::dec << std::endl;
    
    // Expected: 0xd2509a842a34bf46a93145a264e31c2322c7a963f3a75e4d400f82c60b165786
    const uint64_t expected[4] = {
        0x400F82C60B165786ULL, 0x22C7A963F3A75E4DULL,
        0xA93145A264E31C23ULL, 0xD2509A842A34BF46ULL
    };
    
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(result.limb[i], expected[i]) << "reduced limb " << i << " mismatch";
    }
}

// Test 9: P-256 2*G basic test - verify point doubling works correctly
TEST_F(Fe256PointTest, PointDouble_P256_TwoG) {
    ASSERT_NE(curve_p256_, nullptr);

    // Expected 2G for P-256 (computed from standard affine doubling formula)
    // 2G.x = 0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978
    // 2G.y = 0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1
    const uint64_t expected_2gx[4] = {
        0xA60B48FC47669978ULL, 0xC08969E277F21B35ULL,
        0x8A52380304B51AC3ULL, 0x7CF27B188D034F7EULL
    };
    const uint64_t expected_2gy[4] = {
        0x9E04B79D227873D1ULL, 0xBA7DADE63CE98229ULL,
        0x293D9AC69F7430DBULL, 0x07775510DB8ED040ULL
    };

    // Get P-256 generator and compute 2*G directly
    const fe256_point* g = fe256_get_generator(FE256_CURVE_P256);
    fe256_point two_g;
    fe256_point_double(&two_g, g, FE256_CURVE_P256);

    // Convert to affine
    fe256 x_aff, y_aff;
    int ret = fe256_point_to_affine(&x_aff, &y_aff, &two_g, FE256_CURVE_P256);
    ASSERT_EQ(ret, 0) << "Failed to convert 2G to affine";

    // Print actual values for debugging
    std::cout << "P-256 2*G affine x = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << x_aff.limb[i];
    }
    std::cout << std::dec << std::endl;

    std::cout << "P-256 2*G affine y = ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << y_aff.limb[i];
    }
    std::cout << std::dec << std::endl;

    // Verify
    for (int i = 0; i < 4; i++) {
        EXPECT_EQ(x_aff.limb[i], expected_2gx[i]) << "2G.x limb " << i << " mismatch";
        EXPECT_EQ(y_aff.limb[i], expected_2gy[i]) << "2G.y limb " << i << " mismatch";
    }
}

// Test 9: P-256 integration test
TEST_F(Fe256PointTest, FastPathIntegration_P256) {
    ASSERT_NE(curve_p256_, nullptr);

    // Use decimal string for NTL ZZ conversion
    // 0xDEADBEEFCAFEBABE1234567890ABCDEF = 295990755083832485362655746424040587759
    ZZ k = conv<ZZ>("295990755083832485362655746424040587759");

    // Compute k*G using fe256 fast path
    JacobianPoint result = fe256_fast_scalar_mult_base("secp256r1", k,
                                                       curve_p256_->get_prime());

    // Verify result is on curve
    EXPECT_TRUE(curve_p256_->is_on_curve(result))
        << "fe256 fast path result is not on curve for P-256!";

    // Compare with standard scalar_mult reference
    JacobianPoint G = curve_p256_->get_generator();
    JacobianPoint ref = curve_p256_->scalar_mult(k, G);
    AffinePoint aff_result = curve_p256_->to_affine(result);
    AffinePoint aff_ref = curve_p256_->to_affine(ref);

    EXPECT_EQ(rep(aff_result.x), rep(aff_ref.x)) << "X mismatch vs reference";
    EXPECT_EQ(rep(aff_result.y), rep(aff_ref.y)) << "Y mismatch vs reference";
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
