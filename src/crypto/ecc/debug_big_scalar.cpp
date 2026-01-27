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
    
    // Use the exact u1, u2 values from ECDSA verify test
    // u1 = 089d6bb10c2fca12ea8c21835e63c917b2ce407f52e3b99c29dcc62c9b94d740
    // u2 = 2a8131bf5c118fde0a2235a6fe511b2460ce7b0530a3b9fd8fc86b56f7361e11
    
    Fe256 u1, u2;
    u1.d[0] = 0x29dcc62c9b94d740ULL;
    u1.d[1] = 0xb2ce407f52e3b99cULL;
    u1.d[2] = 0xea8c21835e63c917ULL;
    u1.d[3] = 0x089d6bb10c2fca12ULL;
    
    u2.d[0] = 0x8fc86b56f7361e11ULL;
    u2.d[1] = 0x60ce7b0530a3b9fdULL;
    u2.d[2] = 0x0a2235a6fe511b24ULL;
    u2.d[3] = 0x2a8131bf5c118fdeULL;
    
    print_fe256("u1", &u1);
    print_fe256("u2", &u2);
    
    // Create Q = d*G (from keygen)
    // d = 123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0
    Fe256 d;
    d.d[0] = 0x123456789abcdef0ULL;
    d.d[1] = 0x123456789abcdef0ULL;
    d.d[2] = 0x123456789abcdef0ULL;
    d.d[3] = 0x123456789abcdef0ULL;
    
    Fe256Point Q;
    scalar_mult_base(&Q, &d, curve);
    Fe256 Qx, Qy;
    point_to_affine(&Qx, &Qy, &Q, curve);
    print_fe256("Qx", &Qx);
    print_fe256("Qy", &Qy);
    
    // Method 1: manual u1*G + u2*Q
    Fe256Point u1G, u2Q, R_manual;
    scalar_mult_base(&u1G, &u1, curve);
    scalar_mult(&u2Q, &u2, &Q, curve);
    point_add(&R_manual, &u1G, &u2Q, curve);
    Fe256 Rmx, Rmy;
    point_to_affine(&Rmx, &Rmy, &R_manual, curve);
    std::cout << "\nManual method (u1*G then u2*Q then add):" << std::endl;
    print_fe256("  u1*G + u2*Q x", &Rmx);
    
    // Method 2: double_scalar_mult
    Fe256Point R_dsm;
    double_scalar_mult(&R_dsm, &u1, &u2, &Q, curve);
    Fe256 Rdx, Rdy;
    point_to_affine(&Rdx, &Rdy, &R_dsm, curve);
    std::cout << "\ndouble_scalar_mult method:" << std::endl;
    print_fe256("  result x", &Rdx);
    
    bool match = (fe256_cmp(&Rmx, &Rdx) == 0);
    std::cout << "\nMatch: " << (match ? "YES" : "NO") << std::endl;
    
    // Expected r
    Fe256 expected_r;
    expected_r.d[0] = 0x8416d236084167b4ULL;
    expected_r.d[1] = 0xfd44f91e4cddee39ULL;
    expected_r.d[2] = 0xd98a7072b8154c21ULL;
    expected_r.d[3] = 0x38793b8e1ffc08ceULL;
    print_fe256("\nExpected r", &expected_r);
    
    bool manual_correct = (fe256_cmp(&Rmx, &expected_r) == 0);
    bool dsm_correct = (fe256_cmp(&Rdx, &expected_r) == 0);
    
    std::cout << "Manual method correct: " << (manual_correct ? "YES" : "NO") << std::endl;
    std::cout << "DSM method correct: " << (dsm_correct ? "YES" : "NO") << std::endl;
    
    return (match && manual_correct) ? 0 : 1;
}
