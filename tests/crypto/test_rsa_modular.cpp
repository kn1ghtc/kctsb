/**
 * @file test_rsa_modular.cpp
 * @brief Test RSA modular refactor (v5.0.0)
 * 
 * Validates that all RSA submodules work correctly after split.
 */

#include "kctsb/crypto/rsa/rsa.h"
#include <iostream>
#include <vector>
#include <cstring>

using namespace kctsb::rsa;

int main() {
    std::cout << "RSA Modular Refactor Test (v5.0.0)\n";
    std::cout << "====================================\n\n";
    
    // Test 1: Key generation
    std::cout << "[1] Generating RSA-2048 key pair...\n";
    auto kp = generate_keypair<2048>();
    
    if (!kp.is_valid()) {
        std::cerr << "ERROR: Key pair invalid!\n";
        return 1;
    }
    std::cout << "    ✓ Key generation successful\n";
    std::cout << "    Public key modulus bits: " << kp.public_key.n.num_bits() << "\n\n";
    
    // Test 2: PKCS#1 v1.5 encryption
    std::cout << "[2] Testing RSAES-PKCS1-v1_5...\n";
    const char* msg = "Hello RSA modular refactor!";
    auto ct_pkcs1 = encrypt_pkcs1<2048>(
        reinterpret_cast<const uint8_t*>(msg),
        std::strlen(msg),
        kp.public_key
    );
    std::cout << "    ✓ Encryption successful (" << ct_pkcs1.size() << " bytes)\n";
    
    auto pt_pkcs1 = decrypt_pkcs1<2048>(
        ct_pkcs1.data(),
        ct_pkcs1.size(),
        kp.private_key
    );
    
    if (pt_pkcs1.size() != std::strlen(msg) ||
        std::memcmp(pt_pkcs1.data(), msg, std::strlen(msg)) != 0) {
        std::cerr << "ERROR: Decryption mismatch!\n";
        return 1;
    }
    std::cout << "    ✓ Decryption successful\n\n";
    
    // Test 3: OAEP encryption
    std::cout << "[3] Testing RSAES-OAEP...\n";
    auto ct_oaep = encrypt_oaep<2048>(
        reinterpret_cast<const uint8_t*>(msg),
        std::strlen(msg),
        kp.public_key
    );
    std::cout << "    ✓ OAEP encryption successful\n";
    
    auto pt_oaep = decrypt_oaep<2048>(
        ct_oaep.data(),
        ct_oaep.size(),
        kp.private_key
    );
    
    if (pt_oaep.size() != std::strlen(msg) ||
        std::memcmp(pt_oaep.data(), msg, std::strlen(msg)) != 0) {
        std::cerr << "ERROR: OAEP decryption mismatch!\n";
        return 1;
    }
    std::cout << "    ✓ OAEP decryption successful\n\n";
    
    // Test 4: PKCS#1 v1.5 signatures
    std::cout << "[4] Testing RSASSA-PKCS1-v1_5...\n";
    uint8_t hash[32] = {0}; // Mock hash
    for (int i = 0; i < 32; i++) hash[i] = static_cast<uint8_t>(i);
    
    auto sig_pkcs1 = sign_pkcs1<2048>(hash, 32, kp.private_key);
    std::cout << "    ✓ Signature generation successful\n";
    
    bool valid_pkcs1 = verify_pkcs1<2048>(
        hash, 32,
        sig_pkcs1.data(), sig_pkcs1.size(),
        kp.public_key
    );
    
    if (!valid_pkcs1) {
        std::cerr << "ERROR: Signature verification failed!\n";
        return 1;
    }
    std::cout << "    ✓ Signature verification successful\n\n";
    
    // Test 5: PSS signatures
    std::cout << "[5] Testing RSASSA-PSS...\n";
    auto sig_pss = sign_pss<2048>(hash, 32, kp.private_key);
    std::cout << "    ✓ PSS signature generation successful\n";
    
    bool valid_pss = verify_pss<2048>(
        hash, 32,
        sig_pss.data(), sig_pss.size(),
        kp.public_key
    );
    
    if (!valid_pss) {
        std::cerr << "ERROR: PSS verification failed!\n";
        return 1;
    }
    std::cout << "    ✓ PSS verification successful\n\n";
    
    // Test 6: RSA class wrapper
    std::cout << "[6] Testing RSA class wrapper...\n";
    auto kp2 = RSA2048::generate_keypair();
    auto ct = RSA2048::encrypt_pkcs1(
        reinterpret_cast<const uint8_t*>(msg),
        std::strlen(msg),
        kp2.public_key
    );
    auto pt = RSA2048::decrypt_pkcs1(ct.data(), ct.size(), kp2.private_key);
    
    if (pt.size() != std::strlen(msg) ||
        std::memcmp(pt.data(), msg, std::strlen(msg)) != 0) {
        std::cerr << "ERROR: RSA class wrapper failed!\n";
        return 1;
    }
    std::cout << "    ✓ RSA class wrapper works correctly\n\n";
    
    std::cout << "====================================\n";
    std::cout << "All tests PASSED ✓\n";
    std::cout << "RSA modular refactor successful!\n";
    
    return 0;
}
