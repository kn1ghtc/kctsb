/**
 * @file main.cpp
 * @brief kctsb library demo application
 */

#include "kctsb/kctsb.h"
#include <iostream>
#include <iomanip>

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec;
}

int main() {
    std::cout << "============================================" << std::endl;
    std::cout << "   kctsb - Cryptographic Library Demo" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << std::endl;
    
    // Library info
    std::cout << "Library version: " << kctsb_version() << std::endl;
    std::cout << "Platform: " << kctsb_platform() << std::endl;
    std::cout << std::endl;
    
    // Initialize
    if (kctsb_init() != KCTSB_SUCCESS) {
        std::cerr << "Failed to initialize library" << std::endl;
        return 1;
    }
    
    // Demo: Random number generation
    std::cout << "=== Random Number Generation ===" << std::endl;
    uint8_t random_bytes[16];
    kctsb_random_bytes(random_bytes, 16);
    std::cout << "Random bytes: ";
    print_hex(random_bytes, 16);
    std::cout << std::endl;
    std::cout << "Random u32: " << kctsb_random_u32() << std::endl;
    std::cout << std::endl;
    
    // Demo: AES encryption
    std::cout << "=== AES-128 Encryption ===" << std::endl;
    
    uint8_t aes_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    uint8_t plaintext[16] = "Hello, kctsb!!";
    
    std::cout << "Key: ";
    print_hex(aes_key, 16);
    std::cout << std::endl;
    
    std::cout << "Plaintext: ";
    print_hex(plaintext, 16);
    std::cout << " (\"" << (char*)plaintext << "\")" << std::endl;
    
    kctsb_aes_ctx_t aes_ctx;
    kctsb_aes_init(&aes_ctx, aes_key, 16);
    
    uint8_t ciphertext[16];
    kctsb_aes_encrypt_block(&aes_ctx, plaintext, ciphertext);
    
    std::cout << "Ciphertext: ";
    print_hex(ciphertext, 16);
    std::cout << std::endl;
    
    uint8_t decrypted[16];
    kctsb_aes_decrypt_block(&aes_ctx, ciphertext, decrypted);
    
    std::cout << "Decrypted: ";
    print_hex(decrypted, 16);
    std::cout << " (\"" << (char*)decrypted << "\")" << std::endl;
    
    kctsb_aes_clear(&aes_ctx);
    std::cout << std::endl;
    
    // Cleanup
    kctsb_cleanup();
    
    std::cout << "============================================" << std::endl;
    std::cout << "   Demo completed successfully!" << std::endl;
    std::cout << "============================================" << std::endl;
    
    return 0;
}
