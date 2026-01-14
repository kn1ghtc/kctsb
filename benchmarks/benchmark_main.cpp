/**
 * @file benchmark_main.cpp
 * @brief kctsb vs OpenSSL Performance Benchmark Suite
 *
 * This benchmark suite compares kctsb cryptographic implementations
 * against OpenSSL reference implementations for performance validation.
 *
 * Usage:
 *   kctsb_benchmark [algorithm]
 *
 * Algorithms:
 *   all     - Run all benchmarks (default)
 *   aes     - AES-256-GCM and AES-128-GCM
 *   chacha  - ChaCha20-Poly1305
 *   hash    - SHA3-256, BLAKE2b hash functions
 *   ecc     - Elliptic curve (ECDSA, ECDH)
 *   rsa     - RSA-2048/4096 operations
 *   sm      - Chinese national crypto (SM2/SM3/SM4)
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <set>
#include "kctsb/kctsb.h"
#include "kctsb/utils/console.h"

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// Forward declarations for benchmark functions
void benchmark_aes_gcm();
void benchmark_aes_128_gcm();
void benchmark_chacha20_poly1305();
void benchmark_hash_functions();
void benchmark_ecc();
void benchmark_rsa();
void benchmark_sm();

/**
 * @brief High-resolution timer for benchmarking
 */
class BenchmarkTimer {
public:
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = std::chrono::time_point<Clock>;
    using Duration = std::chrono::duration<double, std::milli>;

    void start() {
        start_time_ = Clock::now();
    }

    double stop() {
        auto end_time = Clock::now();
        Duration elapsed = end_time - start_time_;
        return elapsed.count();
    }

private:
    TimePoint start_time_;
};

/**
 * @brief Benchmark result structure
 */
struct BenchmarkResult {
    std::string name;
    std::string implementation;
    double throughput_mbps;      // MB/s
    double avg_time_ms;          // Average time in milliseconds
    double min_time_ms;
    double max_time_ms;
    size_t data_size_bytes;
    size_t iterations;
};

/**
 * @brief Print benchmark result in formatted table
 */
void print_result(const BenchmarkResult& result) {
    std::cout << std::left << std::setw(25) << result.name
              << std::setw(15) << result.implementation
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(12) << result.throughput_mbps << " MB/s"
              << std::setw(12) << result.avg_time_ms << " ms"
              << std::endl;
}

/**
 * @brief Print comparison between two implementations
 */
void print_comparison(const BenchmarkResult& kctsb, const BenchmarkResult& openssl) {
    double ratio = kctsb.throughput_mbps / openssl.throughput_mbps;
    std::string verdict;

    if (ratio >= 1.0) {
        verdict = "kctsb faster by " + std::to_string(int((ratio - 1.0) * 100)) + "%";
    } else {
        verdict = "OpenSSL faster by " + std::to_string(int((1.0 - ratio) * 100)) + "%";
    }

    std::cout << "  Comparison: " << std::fixed << std::setprecision(2)
              << ratio << "x (" << verdict << ")" << std::endl;
}

/**
 * @brief Generate random test data
 */
std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    RAND_bytes(data.data(), static_cast<int>(size));
    return data;
}

/**
 * @brief Print section header
 */
void print_section_header(const std::string& title) {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << std::left << std::setw(25) << "Algorithm"
              << std::setw(15) << "Implementation"
              << std::right << std::setw(15) << "Throughput"
              << std::setw(12) << "Avg Time"
              << std::endl;
    std::cout << std::string(70, '-') << std::endl;
}

/**
 * @brief Print usage help
 */
void print_usage(const char* program_name) {
    std::cout << "\nUsage: " << program_name << " [algorithm]\n\n";
    std::cout << "Algorithms:\n";
    std::cout << "  all     - Run all benchmarks (default)\n";
    std::cout << "  aes     - AES-256-GCM and AES-128-GCM\n";
    std::cout << "  chacha  - ChaCha20-Poly1305\n";
    std::cout << "  hash    - SHA3-256, BLAKE2b hash functions\n";
    std::cout << "  ecc     - Elliptic curve (ECDSA, ECDH)\n";
    std::cout << "  rsa     - RSA-2048/4096 operations\n";
    std::cout << "  sm      - Chinese national crypto (SM2/SM3/SM4)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << "        # Run all benchmarks\n";
    std::cout << "  " << program_name << " sm     # Run only SM2/SM3/SM4 benchmarks\n";
    std::cout << "  " << program_name << " aes    # Run only AES benchmarks\n";
}

/**
 * @brief Print benchmark summary
 */
void print_summary() {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  BENCHMARK SUMMARY" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "\nNote: All benchmarks use identical input data and parameters.\n";
    std::cout << "Results may vary based on CPU, memory, and compiler optimizations.\n";
    std::cout << "\nkctsb implementations are designed for:\n";
    std::cout << "  - Correctness and security first\n";
    std::cout << "  - Cross-platform compatibility\n";
    std::cout << "  - Educational clarity in code structure\n";
    std::cout << "\nFor production use, ensure algorithms meet your security requirements.\n";
    std::cout << std::string(70, '=') << std::endl;
}

/**
 * @brief Benchmark main logic (callable from CLI)
 */
extern "C" int benchmark_main_entry() {
    // This function runs all benchmarks (legacy compatibility)
    return 0;  // Now handled by main()
}

/**
 * @brief Main benchmark entry point with command-line argument support
 */
int main(int argc, char* argv[]) {
    kctsb::utils::enable_utf8_console();

    // Parse command-line arguments
    std::string algorithm = "all";
    if (argc > 1) {
        algorithm = argv[1];
        // Convert to lowercase
        std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(), ::tolower);
    }

    // Valid algorithms
    std::set<std::string> valid_algorithms = {"all", "aes", "chacha", "hash", "ecc", "rsa", "sm", "help", "-h", "--help"};

    if (valid_algorithms.find(algorithm) == valid_algorithms.end()) {
        std::cerr << "Error: Unknown algorithm '" << algorithm << "'\n";
        print_usage(argv[0]);
        return 1;
    }

    if (algorithm == "help" || algorithm == "-h" || algorithm == "--help") {
        print_usage(argv[0]);
        return 0;
    }

    std::cout << "\n";
    std::cout << "+======================================================================+\n";
    std::cout << "|         kctsb vs OpenSSL Performance Benchmark Suite               |\n";
    std::cout << "|                    Version " << KCTSB_VERSION_STRING << "                                 |\n";
    std::cout << "+======================================================================+\n";

    // Initialize kctsb/OpenSSL
    if (kctsb_init() != 0) {
        std::cerr << "kctsb initialization failed" << std::endl;
        return 1;
    }
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::cout << "\nOpenSSL Version: " << OpenSSL_version(OPENSSL_VERSION) << std::endl;
    std::cout << "Test Data Sizes: 1KB, 1MB, 10MB" << std::endl;
    std::cout << "Iterations per test: 100 (warmup: 10)" << std::endl;

    if (algorithm != "all") {
        std::cout << "Selected algorithm: " << algorithm << std::endl;
    }

    // Run selected benchmarks
    if (algorithm == "all" || algorithm == "aes") {
        benchmark_aes_gcm();
        benchmark_aes_128_gcm();
    }

    if (algorithm == "all" || algorithm == "chacha") {
        benchmark_chacha20_poly1305();
    }

    if (algorithm == "all" || algorithm == "hash") {
        benchmark_hash_functions();
    }

    if (algorithm == "all" || algorithm == "ecc") {
        benchmark_ecc();
    }

    if (algorithm == "all" || algorithm == "rsa") {
        benchmark_rsa();
    }

    if (algorithm == "all" || algorithm == "sm") {
        benchmark_sm();
    }

    // Print summary
    print_summary();

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();
    kctsb_cleanup();

    return 0;
}
