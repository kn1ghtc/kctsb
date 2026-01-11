/**
 * @file aes_example.cpp
 * @brief AES encryption example
 */

#include "kctsb/kctsb.h"
#include <iostream>
#include <iomanip>
#include <cstring>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== kctsb AES Example ===" << std::endl;
    std::cout << "Library version: " << kctsb_version() << std::endl;
    std::cout << "Platform: " << kctsb_platform() << std::endl;
    std::cout << std::endl;
    
    // Initialize library
    if (kctsb_init() != KCTSB_SUCCESS) {
        std::cerr << "Failed to initialize kctsb" << std::endl;
        return 1;
    }
    
    // AES-128 key (16 bytes)
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    // Plaintext (16 bytes)
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    print_hex("Key", key, 16);
    print_hex("Plaintext", plaintext, 16);
    
    // Initialize AES context
    kctsb_aes_ctx_t ctx;
    if (kctsb_aes_init(&ctx, key, 16) != KCTSB_SUCCESS) {
        std::cerr << "Failed to initialize AES context" << std::endl;
        return 1;
    }
    
    // Encrypt
    uint8_t ciphertext[16];
    if (kctsb_aes_encrypt_block(&ctx, plaintext, ciphertext) != KCTSB_SUCCESS) {
        std::cerr << "Encryption failed" << std::endl;
        return 1;
    }
    
    print_hex("Ciphertext", ciphertext, 16);
    
    // Decrypt
    uint8_t decrypted[16];
    if (kctsb_aes_decrypt_block(&ctx, ciphertext, decrypted) != KCTSB_SUCCESS) {
        std::cerr << "Decryption failed" << std::endl;
        return 1;
    }
    
    print_hex("Decrypted", decrypted, 16);
    
    // Verify
    if (memcmp(plaintext, decrypted, 16) == 0) {
        std::cout << "\nSuccess: Decrypted text matches original plaintext!" << std::endl;
    } else {
        std::cout << "\nError: Decrypted text does not match!" << std::endl;
    }
    
    // Clean up
    kctsb_aes_clear(&ctx);
    kctsb_cleanup();
    
    return 0;
}
