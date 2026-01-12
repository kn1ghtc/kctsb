/**
 * @file cmd_benchmark.cpp
 * @brief Benchmark subcommand implementation for kctsb CLI
 * 
 * Runs performance benchmarks comparing kctsb with OpenSSL
 * 
 * Usage:
 *   kctsb benchmark
 *   kctsb benchmark --verbose
 * 
 * @author kctsb Development Team
 * @date 2026-01-12
 */

#include <iostream>
#include <string>

// Forward declaration of benchmark main (from benchmarks/benchmark_main.cpp)
extern "C" int benchmark_main_entry();

/**
 * @brief Print benchmark subcommand help
 */
void print_benchmark_help() {
    std::cout << "\nUsage: kctsb benchmark [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --verbose      Show detailed output\n";
    std::cout << "  --help         Show this help message\n\n";
    std::cout << "Description:\n";
    std::cout << "  Runs performance benchmarks comparing kctsb implementations\n";
    std::cout << "  against OpenSSL for validation:\n";
    std::cout << "    - AES-256-GCM encryption/decryption\n";
    std::cout << "    - ChaCha20-Poly1305 AEAD\n";
    std::cout << "    - SHA3-256, BLAKE2b hash functions\n\n";
    std::cout << "  Test data sizes: 1KB, 1MB, 10MB\n";
    std::cout << "  Iterations: 100 (warmup: 10)\n\n";
}

/**
 * @brief Benchmark subcommand handler
 */
int cmd_benchmark(int argc, char* argv[]) {
    bool verbose = false;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        
        if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            print_benchmark_help();
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_benchmark_help();
            return 1;
        }
    }

    // Run benchmark suite
    std::cout << "\nRunning kctsb vs OpenSSL Performance Benchmarks...\n";
    std::cout << "This may take several minutes...\n\n";

    // Call the benchmark main entry point from benchmarks/benchmark_main.cpp
    return benchmark_main_entry();
}
