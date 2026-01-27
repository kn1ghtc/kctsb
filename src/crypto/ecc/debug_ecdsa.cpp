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

// Manually test modular inverse in n domain
bool test_mod_n_inverse() {
    std::cout << "=== Test Mod N Inverse ===" << std::endl;
    
    const CurveParams* curve = get_curve_params(CurveId::SECP256K1);
    
    // Test: a * a^-1 mod n should equal 1
    Fe256 a(12345);
    
    // a in Montgomery form
    Fe256 a_mont;
    fe256_to_mont(&a_mont, &a, &curve->R2_n, &curve->n, curve->n0_n);
    
    // a^-1 in Montgomery form
    Fe256 a_inv_mont;
    fe256_inv(&a_inv_mont, &a_mont, &curve->n, curve->n0_n);
    
    // a * a^-1 in Montgomery form
    Fe256 prod_mont;
    fe256_mul_mont(&prod_mont, &a_mont, &a_inv_mont, &curve->n, curve->n0_n);
    
    // Convert back from Montgomery
    Fe256 prod;
    fe256_from_mont(&prod, &prod_mont, &curve->n, curve->n0_n);
    
    print_fe256("a", &a);
    print_fe256("a * a^-1 mod n", &prod);
    
    Fe256 one(1);
    bool ok = (fe256_cmp(&prod, &one) == 0);
    std::cout << "Is 1: " << (ok ? "YES" : "NO") << std::endl;
    
    return ok;
}

bool test_ecdsa_manual() {
    std::cout << "\n=== Manual ECDSA Test ===" << std::endl;
    
    const CurveParams* curve = get_curve_params(CurveId::SECP256K1);
    
    // Fixed private key
    uint8_t random_d[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    };
    
    // Generate keypair
    EcdsaKeyPair kp;
    ecdsa_keygen(&kp, random_d, CurveId::SECP256K1);
    
    print_fe256("Private key d", &kp.private_key);
    
    // Get public key in affine
    Fe256 Qx, Qy;
    point_to_affine(&Qx, &Qy, &kp.public_key, curve);
    print_fe256("Public key Qx", &Qx);
    print_fe256("Public key Qy", &Qy);
    
    // Verify Q = d*G
    Fe256Point Q_check;
    scalar_mult_base(&Q_check, &kp.private_key, curve);
    Fe256 Qx_check, Qy_check;
    point_to_affine(&Qx_check, &Qy_check, &Q_check, curve);
    bool q_ok = (fe256_cmp(&Qx, &Qx_check) == 0 && fe256_cmp(&Qy, &Qy_check) == 0);
    std::cout << "Q = d*G: " << (q_ok ? "YES" : "NO") << std::endl;
    
    // Fixed hash
    uint8_t hash[32] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe
    };
    
    // Fixed k
    uint8_t random_k[32] = {
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd
    };
    
    // Sign
    EcdsaSignature sig;
    int sign_result = ecdsa_sign(&sig, hash, 32, &kp.private_key, random_k, CurveId::SECP256K1);
    std::cout << "\nSign result: " << (sign_result == 0 ? "OK" : "FAIL") << std::endl;
    print_fe256("Signature r", &sig.r);
    print_fe256("Signature s", &sig.s);
    
    // Manual verification steps
    std::cout << "\n=== Manual Verification Steps ===" << std::endl;
    
    // Step 1: e = hash mod n
    Fe256 e;
    scalar_reduce(&e, hash, 32, &curve->n);
    print_fe256("e (hash mod n)", &e);
    
    // Step 2: s^-1 mod n
    Fe256 s_mont, s_inv_mont, s_inv;
    fe256_to_mont(&s_mont, &sig.s, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_inv(&s_inv_mont, &s_mont, &curve->n, curve->n0_n);
    fe256_from_mont(&s_inv, &s_inv_mont, &curve->n, curve->n0_n);
    print_fe256("s^-1 mod n", &s_inv);
    
    // Verify: s * s^-1 mod n = 1
    Fe256 check_mont;
    fe256_mul_mont(&check_mont, &s_mont, &s_inv_mont, &curve->n, curve->n0_n);
    Fe256 check;
    fe256_from_mont(&check, &check_mont, &curve->n, curve->n0_n);
    print_fe256("s * s^-1 mod n", &check);
    
    // Step 3: u1 = e * s^-1 mod n
    Fe256 e_mont, u1_mont, u1;
    fe256_to_mont(&e_mont, &e, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_mul_mont(&u1_mont, &e_mont, &s_inv_mont, &curve->n, curve->n0_n);
    fe256_from_mont(&u1, &u1_mont, &curve->n, curve->n0_n);
    print_fe256("u1 = e * s^-1", &u1);
    
    // Step 4: u2 = r * s^-1 mod n
    Fe256 r_mont, u2_mont, u2;
    fe256_to_mont(&r_mont, &sig.r, &curve->R2_n, &curve->n, curve->n0_n);
    fe256_mul_mont(&u2_mont, &r_mont, &s_inv_mont, &curve->n, curve->n0_n);
    fe256_from_mont(&u2, &u2_mont, &curve->n, curve->n0_n);
    print_fe256("u2 = r * s^-1", &u2);
    
    // Step 5: R = u1*G + u2*Q
    Fe256Point R;
    double_scalar_mult(&R, &u1, &u2, &kp.public_key, curve);
    Fe256 Rx, Ry;
    point_to_affine(&Rx, &Ry, &R, curve);
    std::cout << "\nR = u1*G + u2*Q:" << std::endl;
    std::cout << "  is_infinity: " << R.is_infinity << std::endl;
    print_fe256("  Rx", &Rx);
    print_fe256("  Ry", &Ry);
    
    // Step 6: v = Rx mod n
    Fe256 v = Rx;
    while (fe256_cmp(&v, &curve->n) >= 0) {
        uint64_t borrow = 0;
        v.d[0] = sbb64(v.d[0], curve->n.d[0], 0, &borrow);
        v.d[1] = sbb64(v.d[1], curve->n.d[1], borrow, &borrow);
        v.d[2] = sbb64(v.d[2], curve->n.d[2], borrow, &borrow);
        v.d[3] = sbb64(v.d[3], curve->n.d[3], borrow, &borrow);
    }
    print_fe256("v = Rx mod n", &v);
    print_fe256("r (expected)", &sig.r);
    
    bool verify_ok = (fe256_cmp(&v, &sig.r) == 0);
    std::cout << "\nv == r: " << (verify_ok ? "YES (PASS)" : "NO (FAIL)") << std::endl;
    
    // Also check individual components
    std::cout << "\n=== Debug individual parts ===" << std::endl;
    
    // Compute u1*G
    Fe256Point u1G;
    scalar_mult_base(&u1G, &u1, curve);
    Fe256 u1Gx, u1Gy;
    point_to_affine(&u1Gx, &u1Gy, &u1G, curve);
    print_fe256("u1*G x", &u1Gx);
    
    // Compute u2*Q
    Fe256Point u2Q;
    scalar_mult(&u2Q, &u2, &kp.public_key, curve);
    Fe256 u2Qx, u2Qy;
    point_to_affine(&u2Qx, &u2Qy, &u2Q, curve);
    print_fe256("u2*Q x", &u2Qx);
    
    // Add them
    Fe256Point R_manual;
    point_add(&R_manual, &u1G, &u2Q, curve);
    Fe256 Rmx, Rmy;
    point_to_affine(&Rmx, &Rmy, &R_manual, curve);
    print_fe256("u1*G + u2*Q x (manual add)", &Rmx);
    
    return verify_ok;
}

int main() {
    bool ok1 = test_mod_n_inverse();
    bool ok2 = test_ecdsa_manual();
    
    std::cout << "\n=== SUMMARY ===" << std::endl;
    std::cout << "Mod N inverse: " << (ok1 ? "PASS" : "FAIL") << std::endl;
    std::cout << "ECDSA verify: " << (ok2 ? "PASS" : "FAIL") << std::endl;
    
    return (ok1 && ok2) ? 0 : 1;
}
