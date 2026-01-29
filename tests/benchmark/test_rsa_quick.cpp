/**
 * @file test_rsa_quick.cpp
 * @brief Quick RSA Montgomery implementation test
 */

#include <iostream>
#include <chrono>
#include <vector>
#include <cstdint>
#include <cassert>
#include <cstring>
#include "kctsb/kctsb_api.h"
#include "kctsb/crypto/sha256.h"

// Forward declare the internal test function (defined in rsa.cpp within extern "C")
extern "C" int kctsb_test_montgomery_internal();
extern "C" int kctsb_test_rsa_core_internal();
extern "C" int kctsb_test_pss_internal();

using namespace std::chrono;

// Test Montgomery basics with simple modexp
void test_mont_basic() {
    std::cout << "=== Montgomery Basic Test ===" << std::endl;
    
    // Simple test: compute 2^65537 mod small_prime
    // Using a known test case first
    
    // Test: 3^5 mod 7 = 243 mod 7 = 5
    // Test with RSA: m^e mod n, then result^d mod n should equal m
    
    std::cout << "Testing with actual RSA operations..." << std::endl;
}

// Test basic RSA operations
void test_rsa_basic() {
    std::cout << "=== RSA PSS Sign/Verify Test ===" << std::endl;
    
    // Generate keypair
    kctsb_rsa_public_key_t pub{};
    kctsb_rsa_private_key_t priv{};
    
    auto start = high_resolution_clock::now();
    int rc = kctsb_rsa_generate_keypair(3072, &pub, &priv);
    auto end = high_resolution_clock::now();
    
    if (rc != KCTSB_SUCCESS) {
        std::cout << "FAIL: keygen failed with rc=" << rc << std::endl;
        return;
    }
    std::cout << "Keygen: " << duration_cast<milliseconds>(end - start).count() << "ms" << std::endl;
    std::cout << "  n_len=" << pub.n_len << " e_len=" << pub.e_len << std::endl;
    
    // Print first few bytes of n and e for debugging
    std::cout << "  n[0..7]: ";
    for (int i = 0; i < 8; i++) std::cout << std::hex << (int)pub.n[i] << " ";
    std::cout << std::dec << std::endl;
    std::cout << "  e[0..7]: ";
    for (size_t i = 0; i < pub.e_len && i < 8; i++) std::cout << std::hex << (int)pub.e[i] << " ";
    std::cout << std::dec << std::endl;
    
    // Hash a message
    const uint8_t msg[] = "Hello RSA Test!";
    size_t msg_len = sizeof(msg) - 1;
    uint8_t hash[32];
    kctsb_sha256(msg, msg_len, hash);
    
    // Test PSS sign
    std::vector<uint8_t> sig(KCTSB_RSA_3072_BYTES);
    size_t sig_len = sig.size();
    
    start = high_resolution_clock::now();
    rc = kctsb_rsa_pss_sign_sha256(&priv, hash, 32, nullptr, 0, sig.data(), &sig_len);
    end = high_resolution_clock::now();
    
    if (rc != KCTSB_SUCCESS) {
        std::cout << "FAIL: sign failed with rc=" << rc << std::endl;
        return;
    }
    std::cout << "Sign: " << duration_cast<milliseconds>(end - start).count() << "ms, sig_len=" << sig_len << std::endl;
    
    // Print first few bytes of signature
    std::cout << "  sig[0..7]: ";
    for (int i = 0; i < 8; i++) std::cout << std::hex << (int)sig[i] << " ";
    std::cout << std::dec << std::endl;
    
    // Test PSS verify
    start = high_resolution_clock::now();
    rc = kctsb_rsa_pss_verify_sha256(&pub, hash, 32, sig.data(), sig_len);
    end = high_resolution_clock::now();
    
    std::cout << "Verify: " << duration_cast<milliseconds>(end - start).count() << "ms, rc=" << rc << std::endl;
    
    if (rc != KCTSB_SUCCESS) {
        std::cout << "FAIL: verify failed with rc=" << rc << std::endl;
        return;
    }
    
    std::cout << "PASS: RSA PSS sign/verify" << std::endl;
}

// Test OAEP encrypt/decrypt
void test_oaep() {
    std::cout << "\n=== RSA OAEP Test ===" << std::endl;
    
    const uint8_t msg[] = "OAEP Test Message";
    size_t msg_len = sizeof(msg) - 1;
    
    kctsb_rsa_public_key_t pub{};
    kctsb_rsa_private_key_t priv{};
    int rc = kctsb_rsa_generate_keypair(3072, &pub, &priv);
    if (rc != KCTSB_SUCCESS) {
        std::cout << "FAIL: keygen failed" << std::endl;
        return;
    }
    
    std::vector<uint8_t> ct(KCTSB_RSA_3072_BYTES);
    size_t ct_len = ct.size();
    
    auto start = high_resolution_clock::now();
    rc = kctsb_rsa_oaep_encrypt_sha256(&pub, msg, msg_len, nullptr, 0, ct.data(), &ct_len);
    auto end = high_resolution_clock::now();
    
    if (rc != KCTSB_SUCCESS) {
        std::cout << "FAIL: encrypt failed with rc=" << rc << std::endl;
        return;
    }
    std::cout << "Encrypt: " << duration_cast<milliseconds>(end - start).count() << "ms" << std::endl;
    
    std::vector<uint8_t> pt(KCTSB_RSA_3072_BYTES);
    size_t pt_len = pt.size();
    
    start = high_resolution_clock::now();
    rc = kctsb_rsa_oaep_decrypt_sha256(&priv, ct.data(), ct_len, nullptr, 0, pt.data(), &pt_len);
    end = high_resolution_clock::now();
    
    std::cout << "Decrypt: rc=" << rc << ", pt_len=" << pt_len << std::endl;
    
    if (rc != KCTSB_SUCCESS) {
        std::cout << "FAIL: decrypt failed with rc=" << rc << std::endl;
        return;
    }
    
    if (pt_len != msg_len || memcmp(pt.data(), msg, msg_len) != 0) {
        std::cout << "FAIL: decrypted message mismatch" << std::endl;
        return;
    }
    
    std::cout << "PASS: RSA OAEP encrypt/decrypt" << std::endl;
}

int main() {
    std::cout << "kctsb RSA Quick Test\n" << std::endl;
    
    // First run Montgomery internal tests
    std::cout << "Running Montgomery internal tests..." << std::endl;
    int mont_rc = kctsb_test_montgomery_internal();
    if (mont_rc != 0) {
        std::cout << "Montgomery internal test FAILED with rc=" << mont_rc << std::endl;
        return 1;
    }
    std::cout << std::endl;
    
    // Run RSA core tests
    std::cout << "Running RSA core tests..." << std::endl;
    int rsa_rc = kctsb_test_rsa_core_internal();
    if (rsa_rc != 0) {
        std::cout << "RSA core test FAILED with rc=" << rsa_rc << std::endl;
        return 1;
    }
    std::cout << std::endl;
    
    test_mont_basic();
    test_rsa_basic();
    test_oaep();
    
    return 0;
}
