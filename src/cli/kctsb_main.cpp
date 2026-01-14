/**
 * @file kctsb_main.cpp
 * @brief kctsb Command-Line Interface - Main Entry Point
 * 
 * kctsb (Knight's Cryptographic Trusted Security Base) CLI Tool
 * Reference: OpenSSL command-line interface design
 * 
 * Usage:
 *   kctsb <command> [options]
 * 
 * Commands:
 *   aes          AES encryption/decryption (ECB, CBC, GCM)
 *   hash         Hash functions (SHA3-256, BLAKE2b, SHA-256)
 *   rsa          RSA encryption, signing, key generation
 *   ecc          Elliptic Curve cryptography (ECDH, ECDSA)
 *   chacha20     ChaCha20-Poly1305 AEAD encryption
 *   benchmark    Performance benchmarks vs OpenSSL
 *   version      Display version information
 *   help         Show help message
 * 
 * @author kctsb Development Team
 * @date 2026-01-12 (Beijing Time, UTC+8)
 * @version 3.0.0
 * @copyright Apache License 2.0
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>

// kctsb core headers - kctsb.h includes all crypto headers
#include "kctsb/kctsb.h"

// Subcommand handlers (forward declarations)
int cmd_aes(int argc, char* argv[]);
int cmd_hash(int argc, char* argv[]);
int cmd_rsa(int argc, char* argv[]);
int cmd_ecc(int argc, char* argv[]);
int cmd_chacha20(int argc, char* argv[]);
int cmd_benchmark(int argc, char* argv[]);
void cmd_version();
void cmd_help();

// Version information
constexpr const char* KCTSB_VERSION_CLI = KCTSB_VERSION_STRING;
constexpr const char* KCTSB_BUILD_DATE = "2026-01-14";

/**
 * @brief Print general usage information
 */
void print_usage() {
    std::cout << "\nUsage: kctsb <command> [options]\n\n";
    std::cout << "Available Commands:\n";
    std::cout << "  aes          AES encryption/decryption (ECB, CBC, GCM modes)\n";
    std::cout << "  hash         Compute hash digests (SHA3-256, BLAKE2b, SHA-256)\n";
    std::cout << "  rsa          RSA operations (encrypt, decrypt, sign, verify)\n";
    std::cout << "  ecc          Elliptic Curve operations (ECDH, ECDSA)\n";
    std::cout << "  chacha20     ChaCha20-Poly1305 AEAD encryption/decryption\n";
    std::cout << "  benchmark    Run performance benchmarks (kctsb vs OpenSSL)\n";
    std::cout << "  version      Display version and build information\n";
    std::cout << "  help         Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  kctsb aes -encrypt -in file.txt -out file.enc -key mykey -mode gcm\n";
    std::cout << "  kctsb hash -algorithm sha3-256 -in file.txt\n";
    std::cout << "  kctsb rsa -genkey -keysize 2048 -out keypair.pem\n";
    std::cout << "  kctsb benchmark\n\n";
    std::cout << "For command-specific help, use: kctsb <command> --help\n\n";
}

/**
 * @brief Display version information
 */
void cmd_version() {
    std::cout << "\n";
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  kctsb - Knight's Cryptographic Trusted Security Base         ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    std::cout << "Version:      " << KCTSB_VERSION_CLI << "\n";
    std::cout << "Build Date:   " << KCTSB_BUILD_DATE << " (Beijing Time, UTC+8)\n";
    std::cout << "License:      Apache License 2.0\n";
    std::cout << "Author:       kctsb Development Team\n";
    std::cout << "\n";
    std::cout << "Supported Algorithms:\n";
    std::cout << "  - AES-128/192/256 (ECB, CBC, GCM)\n";
    std::cout << "  - ChaCha20-Poly1305 AEAD\n";
    std::cout << "  - SHA-256, SHA3-256, BLAKE2b\n";
    std::cout << "  - RSA-2048/4096 (OAEP, PSS)\n";
    std::cout << "  - ECC (ECDH, ECDSA, secp256k1, P-256)\n";
    std::cout << "\n";
    std::cout << "Dependencies:\n";
    std::cout << "  - NTL 11.6.0 (Number Theory Library)\n";
    std::cout << "  - GMP 6.3.0 (GNU Multiple Precision Arithmetic)\n";
#ifdef KCTSB_ENABLE_SEAL
    std::cout << "  - Microsoft SEAL 4.1.2 (Homomorphic Encryption)\n";
#endif
#ifdef KCTSB_ENABLE_OPENSSL
    std::cout << "  - OpenSSL 3.6.0 (for benchmarking)\n";
#endif
    std::cout << "\n";
}

/**
 * @brief Display help message (alias for print_usage)
 */
void cmd_help() {
    print_usage();
}

/**
 * @brief Main entry point
 */
int main(int argc, char* argv[]) {
    // No arguments - print help
    if (argc < 2) {
        print_usage();
        return 0;
    }

    // Parse command
    std::string command(argv[1]);
    
    // Convert to lowercase for case-insensitive matching
    std::transform(command.begin(), command.end(), command.begin(), ::tolower);

    // Route to appropriate subcommand handler
    if (command == "aes") {
        return cmd_aes(argc - 1, argv + 1);
    } 
    else if (command == "hash") {
        return cmd_hash(argc - 1, argv + 1);
    } 
    else if (command == "rsa") {
        return cmd_rsa(argc - 1, argv + 1);
    } 
    else if (command == "ecc") {
        return cmd_ecc(argc - 1, argv + 1);
    } 
    else if (command == "chacha20" || command == "chacha") {
        return cmd_chacha20(argc - 1, argv + 1);
    } 
    else if (command == "benchmark" || command == "bench") {
        return cmd_benchmark(argc - 1, argv + 1);
    } 
    else if (command == "version" || command == "-v" || command == "--version") {
        cmd_version();
        return 0;
    } 
    else if (command == "help" || command == "-h" || command == "--help") {
        cmd_help();
        return 0;
    } 
    else {
        std::cerr << "\nError: Unknown command '" << command << "'\n";
        print_usage();
        return 1;
    }

    return 0;
}
