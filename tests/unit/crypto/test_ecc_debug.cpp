/**
 * @brief Direct test of kctsb ECC functions to debug Montgomery issue
 */
#include <iostream>
#include <iomanip>
#include <gtest/gtest.h>

#include "kctsb/math/ZZ.h"
#include "kctsb/math/ZZ_p.h"
#include "kctsb/crypto/ecc/ecc_curve.h"

using namespace kctsb;
using namespace kctsb::ecc::internal;

TEST(DebugMontTest, ScalarMultOne) {
    auto curve = ECCurve::from_name("secp256k1");
    
    // Get generator
    JacobianPoint G = curve.get_generator();
    AffinePoint G_aff = curve.to_affine(G);
    
    std::cout << "Generator G:\n";
    std::cout << "  Gx = " << rep(G_aff.x) << "\n";
    std::cout << "  Gy = " << rep(G_aff.y) << "\n";
    
    // Compute 1*G
    ZZ k = ZZ(1);
    JacobianPoint result = curve.scalar_mult(k, G);
    AffinePoint result_aff = curve.to_affine(result);
    
    std::cout << "\n1*G result:\n";
    std::cout << "  x = " << rep(result_aff.x) << "\n";
    std::cout << "  y = " << rep(result_aff.y) << "\n";
    
    std::cout << "\nExpected (same as G):\n";
    std::cout << "  Gx = " << rep(G_aff.x) << "\n";
    std::cout << "  Gy = " << rep(G_aff.y) << "\n";
    
    EXPECT_EQ(rep(result_aff.x), rep(G_aff.x)) << "1*G.x should equal G.x";
    EXPECT_EQ(rep(result_aff.y), rep(G_aff.y)) << "1*G.y should equal G.y";
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
