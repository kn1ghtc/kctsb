/**
 * @file test_fe256_native.cpp
 * @brief Test program for pure native fe256 ECC implementation
 * 
 * Tests correctness and benchmarks performance against current implementation.
 */

#include "fe256_native.h"
#include <iostream>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <random>

using namespace kctsb::ecc::native;

// Test vectors for secp256k1
const uint8_t SECP256K1_TEST_PRIVKEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

// Expected public key for d=1 is G itself
const uint8_t SECP256K1_GX[32] = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};

const uint8_t SECP256K1_GY[32] = {
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
};

void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

void print_fe256(const char* label, const Fe256* a) {
    uint8_t bytes[32];
    a->to_bytes_be(bytes);
    print_hex(label, bytes, 32);
}

bool test_keygen_secp256k1() {
    std::cout << "\n=== Test KeyGen secp256k1 ===" << std::endl;
    
    const CurveParams* curve = get_curve_params(CurveId::SECP256K1);
    
    // d = 1, expect Q = G
    Fe256 d = Fe256(1);
    Fe256Point Q;
    scalar_mult_base(&Q, &d, curve);
    
    Fe256 x, y;
    point_to_affine(&x, &y, &Q, curve);
    
    uint8_t x_bytes[32], y_bytes[32];
    x.to_bytes_be(x_bytes);
    y.to_bytes_be(y_bytes);
    
    print_hex("Expected Gx", SECP256K1_GX, 32);
    print_hex("Got      x ", x_bytes, 32);
    print_hex("Expected Gy", SECP256K1_GY, 32);
    print_hex("Got      y ", y_bytes, 32);
    
    bool ok = (memcmp(x_bytes, SECP256K1_GX, 32) == 0) && 
              (memcmp(y_bytes, SECP256K1_GY, 32) == 0);
    
    std::cout << "Result: " << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

bool test_keygen_2G_secp256k1() {
    std::cout << "\n=== Test KeyGen 2*G secp256k1 ===" << std::endl;
    
    const CurveParams* curve = get_curve_params(CurveId::SECP256K1);
    
    // d = 2, expect Q = 2G
    Fe256 d = Fe256(2);
    Fe256Point Q;
    scalar_mult_base(&Q, &d, curve);
    
    Fe256 x, y;
    point_to_affine(&x, &y, &Q, curve);
    
    // Expected 2G for secp256k1 (verified via Python: y^2 = x^3 + 7 mod p)
    const uint8_t expected_2Gx[32] = {
        0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
        0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
        0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
        0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5
    };
    // Correct 2Gy: 1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a
    const uint8_t expected_2Gy[32] = {
        0x1a, 0xe1, 0x68, 0xfe, 0xa6, 0x3d, 0xc3, 0x39,
        0xa3, 0xc5, 0x84, 0x19, 0x46, 0x6c, 0xea, 0xee,
        0xf7, 0xf6, 0x32, 0x65, 0x32, 0x66, 0xd0, 0xe1,
        0x23, 0x64, 0x31, 0xa9, 0x50, 0xcf, 0xe5, 0x2a
    };
    
    uint8_t x_bytes[32], y_bytes[32];
    x.to_bytes_be(x_bytes);
    y.to_bytes_be(y_bytes);
    
    print_hex("Expected 2Gx", expected_2Gx, 32);
    print_hex("Got       x ", x_bytes, 32);
    print_hex("Expected 2Gy", expected_2Gy, 32);
    print_hex("Got       y ", y_bytes, 32);
    
    bool ok = (memcmp(x_bytes, expected_2Gx, 32) == 0) && 
              (memcmp(y_bytes, expected_2Gy, 32) == 0);
    
    std::cout << "Result: " << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

bool test_ecdsa_sign_verify() {
    std::cout << "\n=== Test ECDSA Sign/Verify ===" << std::endl;
    
    // Generate keypair
    uint8_t random_d[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    };
    
    EcdsaKeyPair kp;
    ecdsa_keygen(&kp, random_d, CurveId::SECP256K1);
    
    // Sign
    uint8_t hash[32] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe
    };
    
    uint8_t random_k[32] = {
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd
    };
    
    EcdsaSignature sig;
    int sign_result = ecdsa_sign(&sig, hash, 32, &kp.private_key, random_k, CurveId::SECP256K1);
    
    if (sign_result != 0) {
        std::cout << "Sign failed!" << std::endl;
        return false;
    }
    
    print_fe256("Signature r", &sig.r);
    print_fe256("Signature s", &sig.s);
    
    // Verify
    int verify_result = ecdsa_verify(&sig, hash, 32, &kp.public_key, CurveId::SECP256K1);
    
    bool ok = (verify_result == 0);
    std::cout << "Verify result: " << (ok ? "PASS" : "FAIL") << std::endl;
    
    // Test with wrong hash
    hash[0] ^= 0xFF;
    verify_result = ecdsa_verify(&sig, hash, 32, &kp.public_key, CurveId::SECP256K1);
    bool wrong_hash_rejected = (verify_result != 0);
    std::cout << "Wrong hash rejected: " << (wrong_hash_rejected ? "PASS" : "FAIL") << std::endl;
    
    return ok && wrong_hash_rejected;
}

void benchmark_keygen(CurveId curve_id, const char* name, int iterations) {
    std::cout << "\n=== Benchmark " << name << " KeyGen ===" << std::endl;
    
    const CurveParams* curve = get_curve_params(curve_id);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        uint8_t random[32];
        for (int j = 0; j < 32; j++) random[j] = dist(gen);
        
        EcdsaKeyPair kp;
        ecdsa_keygen(&kp, random, curve_id);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double per_op = elapsed_ms / iterations;
    
    std::cout << "Iterations: " << iterations << std::endl;
    std::cout << "Total time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Per operation: " << per_op << " ms" << std::endl;
    std::cout << "Throughput: " << (1000.0 / per_op) << " op/s" << std::endl;
}

void benchmark_sign(CurveId curve_id, const char* name, int iterations) {
    std::cout << "\n=== Benchmark " << name << " ECDSA Sign ===" << std::endl;
    
    const CurveParams* curve = get_curve_params(curve_id);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    
    // Generate keypair once
    uint8_t random_d[32];
    for (int j = 0; j < 32; j++) random_d[j] = dist(gen);
    EcdsaKeyPair kp;
    ecdsa_keygen(&kp, random_d, curve_id);
    
    uint8_t hash[32];
    for (int j = 0; j < 32; j++) hash[j] = dist(gen);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        uint8_t random_k[32];
        for (int j = 0; j < 32; j++) random_k[j] = dist(gen);
        
        EcdsaSignature sig;
        ecdsa_sign(&sig, hash, 32, &kp.private_key, random_k, curve_id);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double per_op = elapsed_ms / iterations;
    
    std::cout << "Iterations: " << iterations << std::endl;
    std::cout << "Total time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Per operation: " << per_op << " ms" << std::endl;
    std::cout << "Throughput: " << (1000.0 / per_op) << " op/s" << std::endl;
}

void benchmark_verify(CurveId curve_id, const char* name, int iterations) {
    std::cout << "\n=== Benchmark " << name << " ECDSA Verify ===" << std::endl;
    
    const CurveParams* curve = get_curve_params(curve_id);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    
    // Generate keypair and signature once
    uint8_t random_d[32];
    for (int j = 0; j < 32; j++) random_d[j] = dist(gen);
    EcdsaKeyPair kp;
    ecdsa_keygen(&kp, random_d, curve_id);
    
    uint8_t hash[32];
    for (int j = 0; j < 32; j++) hash[j] = dist(gen);
    
    uint8_t random_k[32];
    for (int j = 0; j < 32; j++) random_k[j] = dist(gen);
    
    EcdsaSignature sig;
    ecdsa_sign(&sig, hash, 32, &kp.private_key, random_k, curve_id);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        ecdsa_verify(&sig, hash, 32, &kp.public_key, curve_id);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double per_op = elapsed_ms / iterations;
    
    std::cout << "Iterations: " << iterations << std::endl;
    std::cout << "Total time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Per operation: " << per_op << " ms" << std::endl;
    std::cout << "Throughput: " << (1000.0 / per_op) << " op/s" << std::endl;
}

int main() {
    std::cout << "===== Fe256 Native ECC Test & Benchmark =====" << std::endl;
    
    bool all_pass = true;
    
    // Correctness tests
    all_pass &= test_keygen_secp256k1();
    all_pass &= test_keygen_2G_secp256k1();
    all_pass &= test_ecdsa_sign_verify();
    
    if (!all_pass) {
        std::cout << "\n*** CORRECTNESS TESTS FAILED ***" << std::endl;
        return 1;
    }
    
    std::cout << "\n*** All correctness tests passed ***" << std::endl;
    
    // Performance benchmarks
    const int iterations = 100;
    
    benchmark_keygen(CurveId::SECP256K1, "secp256k1", iterations);
    benchmark_sign(CurveId::SECP256K1, "secp256k1", iterations);
    benchmark_verify(CurveId::SECP256K1, "secp256k1", iterations);
    
    benchmark_keygen(CurveId::P256, "P-256", iterations);
    benchmark_sign(CurveId::P256, "P-256", iterations);
    benchmark_verify(CurveId::P256, "P-256", iterations);
    
    std::cout << "\n===== Benchmark Complete =====" << std::endl;
    
    // OpenSSL reference times for comparison:
    std::cout << "\n=== OpenSSL 3.6.0 Reference (approximate) ===" << std::endl;
    std::cout << "secp256k1 KeyGen:  ~0.36 ms" << std::endl;
    std::cout << "secp256k1 Sign:    ~0.43 ms" << std::endl;
    std::cout << "secp256k1 Verify:  ~0.34 ms" << std::endl;
    std::cout << "P-256 KeyGen:      ~0.03 ms" << std::endl;
    std::cout << "P-256 Sign:        ~0.02 ms" << std::endl;
    std::cout << "P-256 Verify:      ~0.07 ms" << std::endl;
    
    return 0;
}
