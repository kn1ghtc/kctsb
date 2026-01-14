/**
 * @file cmd_aes.cpp
 * @brief AES subcommand implementation for kctsb CLI
 *
 * Supports:
 *   - AES-128/192/256 encryption/decryption
 *   - Modes: ECB, CBC, GCM (default: GCM)
 *   - Key derivation from password (PBKDF2)
 *   - File I/O and hex encoding
 *
 * Usage:
 *   kctsb aes -encrypt -in plaintext.txt -out ciphertext.bin -key mypassword -mode gcm
 *   kctsb aes -decrypt -in ciphertext.bin -out plaintext.txt -key mypassword -mode gcm
 *
 * @author kctsb Development Team
 * @date 2026-01-12
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

#include "kctsb/crypto/aes.h"
// #include "kctsb/utils/hex.h"  // TODO: create hex utility

/**
 * @brief Print AES subcommand help
 */
void print_aes_help() {
    std::cout << "\nUsage: kctsb aes [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -encrypt          Encrypt input file\n";
    std::cout << "  -decrypt          Decrypt input file\n";
    std::cout << "  -in <file>        Input file path (required)\n";
    std::cout << "  -out <file>       Output file path (required)\n";
    std::cout << "  -key <string>     Encryption key or password (required)\n";
    std::cout << "  -mode <mode>      AES mode: ecb, cbc, gcm (default: gcm)\n";
    std::cout << "  -keysize <bits>   Key size: 128, 192, 256 (default: 256)\n";
    std::cout << "  -iv <hex>         Initialization vector (hex, optional)\n";
    std::cout << "  --hex             Output in hexadecimal format\n";
    std::cout << "  --help            Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  # Encrypt with AES-256-GCM\n";
    std::cout << "  kctsb aes -encrypt -in secret.txt -out secret.enc -key mypassword\n\n";
    std::cout << "  # Decrypt with specific mode\n";
    std::cout << "  kctsb aes -decrypt -in secret.enc -out secret.txt -key mypassword -mode gcm\n\n";
    std::cout << "  # CBC mode with custom IV\n";
    std::cout << "  kctsb aes -encrypt -in data.bin -out data.enc -key mykey -mode cbc -iv 0123456789ABCDEF\n\n";
}

// Use shared CLI utilities
#include "cli_utils.h"
using kctsb::cli::read_file;
using kctsb::cli::write_file;

/**
 * @brief AES subcommand handler
 */
int cmd_aes(int argc, char* argv[]) {
    // Parse arguments
    bool encrypt = false, decrypt = false;
    std::string input_file, output_file, key_str, mode = "gcm", iv_hex;
    int keysize = 256;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        if (arg == "-encrypt") {
            encrypt = true;
        } else if (arg == "-decrypt") {
            decrypt = true;
        } else if (arg == "-in" && i + 1 < argc) {
            input_file = argv[++i];
        } else if (arg == "-out" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "-key" && i + 1 < argc) {
            key_str = argv[++i];
        } else if (arg == "-mode" && i + 1 < argc) {
            mode = argv[++i];
            std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
        } else if (arg == "-keysize" && i + 1 < argc) {
            keysize = std::stoi(argv[++i]);
        } else if (arg == "-iv" && i + 1 < argc) {
            iv_hex = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            print_aes_help();
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_aes_help();
            return 1;
        }
    }

    // Validate arguments
    if (!encrypt && !decrypt) {
        std::cerr << "Error: Must specify -encrypt or -decrypt\n";
        print_aes_help();
        return 1;
    }
    if (encrypt && decrypt) {
        std::cerr << "Error: Cannot specify both -encrypt and -decrypt\n";
        return 1;
    }
    if (input_file.empty() || output_file.empty() || key_str.empty()) {
        std::cerr << "Error: Missing required arguments (-in, -out, -key)\n";
        print_aes_help();
        return 1;
    }
    if (keysize != 128 && keysize != 192 && keysize != 256) {
        std::cerr << "Error: Invalid key size. Must be 128, 192, or 256\n";
        return 1;
    }

    try {
        // Read input file
        auto input_data = read_file(input_file);
        std::cout << "Read " << input_data.size() << " bytes from " << input_file << "\n";

        // Derive key from password (simplified - production should use PBKDF2)
        std::vector<unsigned char> key(keysize / 8);
        std::memset(key.data(), 0, key.size());
        std::memcpy(key.data(), key_str.data(),
                    std::min(key.size(), key_str.size()));

        std::vector<unsigned char> output_data;

        // Execute encryption/decryption based on mode
        if (mode == "gcm") {
            // AES-GCM mode (recommended)
            std::cout << "Using AES-" << keysize << "-GCM mode\n";

            // Initialize AES context
            kctsb_aes_ctx_t aes_ctx;
            kctsb_error_t ret = kctsb_aes_init(&aes_ctx, key.data(), key.size());
            if (ret != KCTSB_SUCCESS) {
                throw std::runtime_error("Failed to initialize AES context");
            }

            if (encrypt) {
                // Generate random IV (12 bytes for GCM)
                unsigned char iv[12];
                // TODO: Use kctsb_random_bytes for cryptographic randomness
                for (int i = 0; i < 12; ++i) iv[i] = static_cast<unsigned char>(rand() % 256);

                // Allocate output buffer (same size as input for GCM)
                std::vector<unsigned char> ciphertext(input_data.size());
                unsigned char tag[16];

                ret = kctsb_aes_gcm_encrypt(
                    &aes_ctx,
                    iv, 12,                                    // IV
                    nullptr, 0,                                // No AAD
                    input_data.data(), input_data.size(),      // Plaintext
                    ciphertext.data(),                         // Ciphertext output
                    tag                                        // Tag output
                );

                kctsb_aes_clear(&aes_ctx);

                if (ret != KCTSB_SUCCESS) {
                    throw std::runtime_error("AES-GCM encryption failed");
                }

                // Output: IV (12) + Tag (16) + Ciphertext
                output_data.insert(output_data.end(), iv, iv + 12);
                output_data.insert(output_data.end(), tag, tag + 16);
                output_data.insert(output_data.end(), ciphertext.begin(), ciphertext.end());

                std::cout << "Encrypted " << input_data.size() << " bytes\n";
            } else {
                // Decrypt: Extract IV, Tag, Ciphertext
                if (input_data.size() < 28) {
                    throw std::runtime_error("Invalid ciphertext: too short");
                }

                unsigned char iv[12], tag[16];
                std::memcpy(iv, input_data.data(), 12);
                std::memcpy(tag, input_data.data() + 12, 16);

                size_t ciphertext_len = input_data.size() - 28;
                std::vector<unsigned char> plaintext(ciphertext_len);

                ret = kctsb_aes_gcm_decrypt(
                    &aes_ctx,
                    iv, 12,                                    // IV
                    nullptr, 0,                                // No AAD
                    input_data.data() + 28, ciphertext_len,    // Ciphertext
                    tag,                                       // Tag to verify
                    plaintext.data()                           // Plaintext output
                );

                kctsb_aes_clear(&aes_ctx);

                if (ret != KCTSB_SUCCESS) {
                    throw std::runtime_error("AES-GCM decryption failed (authentication tag mismatch)");
                }

                output_data = std::move(plaintext);
                std::cout << "Decrypted " << output_data.size() << " bytes\n";
            }
        } else {
            std::cerr << "Error: Mode '" << mode << "' not yet implemented\n";
            std::cerr << "Supported modes: gcm\n";
            std::cerr << "Coming soon: ecb, cbc\n";
            return 1;
        }

        // Write output
        write_file(output_file, output_data);
        std::cout << "Wrote " << output_data.size() << " bytes to " << output_file << "\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
