#include <iostream>
#include <cstring>
#include <iomanip>
#include "fe256_native.h"

using namespace kctsb::ecc::native;

void print_fe256(const char* label, const Fe256* a) {
    std::cout << label << ": ";
    for (int i = 3; i >= 0; i--) {
        std::cout << std::hex << std::setfill('0') << std::setw(16) << a->d[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    const CurveParams* curve = get_curve_params(CurveId::SECP256K1);
    
    std::cout << "=== Test scalar_mult basics ===" << std::endl;
    
    // Test 1: d = 1 (should give G)
    Fe256 d1(1);
    Fe256Point Q1;
    scalar_mult_base(&Q1, &d1, curve);
    Fe256 x1, y1;
    point_to_affine(&x1, &y1, &Q1, curve);
    std::cout << "1*G:" << std::endl;
    print_fe256("  x", &x1);
    print_fe256("  y", &y1);
    print_fe256(" Gx", &curve->Gx);
    print_fe256(" Gy", &curve->Gy);
    bool match1 = (fe256_cmp(&x1, &curve->Gx) == 0 && fe256_cmp(&y1, &curve->Gy) == 0);
    std::cout << "Match: " << (match1 ? "YES" : "NO") << std::endl;
    
    // Test 2: d = 2 (should give 2G)
    Fe256 d2(2);
    Fe256Point Q2;
    scalar_mult_base(&Q2, &d2, curve);
    Fe256 x2, y2;
    point_to_affine(&x2, &y2, &Q2, curve);
    std::cout << std::endl << "2*G:" << std::endl;
    print_fe256("  x", &x2);
    print_fe256("  y", &y2);
    
    // Test 3: d = 3 (should give 3G)
    Fe256 d3(3);
    Fe256Point Q3;
    scalar_mult_base(&Q3, &d3, curve);
    Fe256 x3, y3;
    point_to_affine(&x3, &y3, &Q3, curve);
    std::cout << std::endl << "3*G:" << std::endl;
    print_fe256("  x", &x3);
    print_fe256("  y", &y3);
    
    std::cout << std::endl << "=== Test double_scalar_mult ===" << std::endl;
    
    // Prepare G point in Montgomery form for double_scalar_mult
    Fe256Point G_mont;
    fe256_to_mont(&G_mont.X, &curve->Gx, &curve->R2, &curve->p, curve->n0_p);
    fe256_to_mont(&G_mont.Y, &curve->Gy, &curve->R2, &curve->p, curve->n0_p);
    G_mont.Z = Fe256(1);
    fe256_to_mont(&G_mont.Z, &G_mont.Z, &curve->R2, &curve->p, curve->n0_p);
    G_mont.is_infinity = 0;
    
    // Test: k1=1, k2=0, P=G => should give 1*G + 0*G = G
    Fe256 k1_1(1), k2_0(0);
    Fe256Point R1;
    double_scalar_mult(&R1, &k1_1, &k2_0, &G_mont, curve);
    Fe256 rx1, ry1;
    point_to_affine(&rx1, &ry1, &R1, curve);
    std::cout << "double_scalar_mult(1, 0, G) = 1*G + 0*G:" << std::endl;
    std::cout << "  is_infinity: " << R1.is_infinity << std::endl;
    print_fe256("  x", &rx1);
    print_fe256("  y", &ry1);
    bool match_dsm1 = (fe256_cmp(&rx1, &curve->Gx) == 0 && fe256_cmp(&ry1, &curve->Gy) == 0);
    std::cout << "Match G: " << (match_dsm1 ? "YES" : "NO") << std::endl;
    
    // Test: k1=0, k2=1, P=G => should give 0*G + 1*G = G
    Fe256 k1_0(0), k2_1(1);
    Fe256Point R2_dsm;
    double_scalar_mult(&R2_dsm, &k1_0, &k2_1, &G_mont, curve);
    Fe256 rx2, ry2;
    point_to_affine(&rx2, &ry2, &R2_dsm, curve);
    std::cout << std::endl << "double_scalar_mult(0, 1, G) = 0*G + 1*G:" << std::endl;
    std::cout << "  is_infinity: " << R2_dsm.is_infinity << std::endl;
    print_fe256("  x", &rx2);
    print_fe256("  y", &ry2);
    bool match_dsm2 = (fe256_cmp(&rx2, &curve->Gx) == 0 && fe256_cmp(&ry2, &curve->Gy) == 0);
    std::cout << "Match G: " << (match_dsm2 ? "YES" : "NO") << std::endl;
    
    // Test: k1=1, k2=1, P=G => should give 1*G + 1*G = 2G
    Fe256 k1_1b(1), k2_1b(1);
    Fe256Point R3_dsm;
    double_scalar_mult(&R3_dsm, &k1_1b, &k2_1b, &G_mont, curve);
    Fe256 rx3, ry3;
    point_to_affine(&rx3, &ry3, &R3_dsm, curve);
    std::cout << std::endl << "double_scalar_mult(1, 1, G) = 1*G + 1*G:" << std::endl;
    std::cout << "  is_infinity: " << R3_dsm.is_infinity << std::endl;
    print_fe256("  x", &rx3);
    print_fe256("  y", &ry3);
    bool match_dsm3 = (fe256_cmp(&rx3, &x2) == 0 && fe256_cmp(&ry3, &y2) == 0);
    std::cout << "Match 2G: " << (match_dsm3 ? "YES" : "NO") << std::endl;
    
    // NEW TEST: P = 2G (not equal to G)
    // Create P = 2G
    Fe256 d_two(2);
    Fe256Point P_2G;
    scalar_mult_base(&P_2G, &d_two, curve);  // This is 2G in Montgomery form
    
    // Test: k1=1, k2=1, P=2G => should give 1*G + 1*2G = 1*G + 2G = 3G
    Fe256 k1_test(1), k2_test(1);
    Fe256Point R_test;
    double_scalar_mult(&R_test, &k1_test, &k2_test, &P_2G, curve);
    Fe256 rx_test, ry_test;
    point_to_affine(&rx_test, &ry_test, &R_test, curve);
    std::cout << std::endl << "double_scalar_mult(1, 1, 2G) = 1*G + 1*2G = 3G:" << std::endl;
    std::cout << "  is_infinity: " << R_test.is_infinity << std::endl;
    print_fe256("  x", &rx_test);
    print_fe256("  y", &ry_test);
    print_fe256(" 3Gx", &x3);
    print_fe256(" 3Gy", &y3);
    bool match_dsm_2g = (fe256_cmp(&rx_test, &x3) == 0 && fe256_cmp(&ry_test, &y3) == 0);
    std::cout << "Match 3G: " << (match_dsm_2g ? "YES" : "NO") << std::endl;
    
    // Summary
    std::cout << std::endl << "=== SUMMARY ===" << std::endl;
    std::cout << "scalar_mult(1) = G: " << (match1 ? "PASS" : "FAIL") << std::endl;
    std::cout << "double_scalar_mult(1,0,G) = G: " << (match_dsm1 ? "PASS" : "FAIL") << std::endl;
    std::cout << "double_scalar_mult(0,1,G) = G: " << (match_dsm2 ? "PASS" : "FAIL") << std::endl;
    std::cout << "double_scalar_mult(1,1,G) = 2G: " << (match_dsm3 ? "PASS" : "FAIL") << std::endl;
    std::cout << "double_scalar_mult(1,1,2G) = 3G: " << (match_dsm_2g ? "PASS" : "FAIL") << std::endl;
    
    return (match1 && match_dsm1 && match_dsm2 && match_dsm3 && match_dsm_2g) ? 0 : 1;
}
