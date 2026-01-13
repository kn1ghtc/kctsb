/**
 * @file cmd_hash.cpp
 * @brief Hash subcommand implementation for kctsb CLI
 *
 * Supports:
 *   - SHA-256 (OpenSSL compatibility)
 *   - SHA3-256 (NIST FIPS 202)
 *   - BLAKE2b (high performance)
 *
 * Usage:
 *   kctsb hash -algorithm sha3-256 -in file.txt
 *   kctsb hash -algorithm blake2b -in data.bin -hex
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
#include <iomanip>
#include <sstream>

#include "kctsb/crypto/sha.h"
#include "kctsb/crypto/blake.h"
#include "kctsb/crypto/hash/keccak.h"

/**
 * @brief Print hash subcommand help
 */
void print_hash_help() {
    std::cout << "\nUsage: kctsb hash [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -algorithm <algo>  Hash algorithm: sha256, sha3-256, blake2b (required)\n";
    std::cout << "  -in <file>         Input file path (required)\n";
    std::cout << "  -hex               Output in hexadecimal (default)\n";
    std::cout << "  -binary            Output raw binary\n";
    std::cout << "  --help             Show this help message\n\n";
    std::cout << "Supported Algorithms:\n";
    std::cout << "  sha256      SHA-256 (32 bytes, OpenSSL compatible)\n";
    std::cout << "  sha3-256    SHA3-256 (32 bytes, NIST FIPS 202)\n";
    std::cout << "  blake2b     BLAKE2b-256 (32 bytes, high performance)\n\n";
    std::cout << "Examples:\n";
    std::cout << "  kctsb hash -algorithm sha3-256 -in document.pdf\n";
    std::cout << "  kctsb hash -algorithm blake2b -in large_file.bin\n";
    std::cout << "  kctsb hash -algorithm sha256 -in data.txt -hex\n\n";
}

// Use shared CLI utilities
#include "cli_utils.h"
using kctsb::cli::read_file;
using kctsb::cli::bytes_to_hex;

/**
 * @brief Hash subcommand handler
 */
int cmd_hash(int argc, char* argv[]) {
    // Parse arguments
    std::string algorithm, input_file;
    bool hex_output = true;  // Default to hex

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        if ((arg == "-algorithm" || arg == "-algo") && i + 1 < argc) {
            algorithm = argv[++i];
            std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(), ::tolower);
        } else if (arg == "-in" && i + 1 < argc) {
            input_file = argv[++i];
        } else if (arg == "-hex") {
            hex_output = true;
        } else if (arg == "-binary") {
            hex_output = false;
        } else if (arg == "--help" || arg == "-h") {
            print_hash_help();
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_hash_help();
            return 1;
        }
    }

    // Validate arguments
    if (algorithm.empty() || input_file.empty()) {
        std::cerr << "Error: Missing required arguments (-algorithm, -in)\n";
        print_hash_help();
        return 1;
    }

    try {
        // Read input file
        auto input_data = read_file(input_file);
        std::cout << "Input file: " << input_file << " (" << input_data.size() << " bytes)\n";

        unsigned char hash[32];  // All supported algorithms output 32 bytes
        std::memset(hash, 0, sizeof(hash));

        // Compute hash based on algorithm
        if (algorithm == "sha256") {
            // TODO: Implement SHA-256 (currently requires OpenSSL)
            std::cerr << "Error: SHA-256 not yet implemented (requires OpenSSL integration)\n";
            return 1;
        }
        else if (algorithm == "sha3-256" || algorithm == "sha3") {
            std::cout << "Algorithm: SHA3-256\n";

            // Call kctsb SHA3-256 implementation (FIPS 202)
            FIPS202_SHA3_256(input_data.data(),
                             static_cast<unsigned int>(input_data.size()),
                             hash);
        }
        else if (algorithm == "blake2b") {
            std::cout << "Algorithm: BLAKE2b-256\n";

            // Call kctsb BLAKE2b implementation
            kctsb_blake2b(input_data.data(), input_data.size(), hash, 32);
        }
        else {
            std::cerr << "Error: Unknown algorithm '" << algorithm << "'\n";
            std::cerr << "Supported: sha256, sha3-256, blake2b\n";
            return 1;
        }

        // Output hash
        if (hex_output) {
            std::string hex_hash = bytes_to_hex(hash, 32);
            std::cout << "Hash (hex): " << hex_hash << "\n";
        } else {
            std::cout.write(reinterpret_cast<const char*>(hash), 32);
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
