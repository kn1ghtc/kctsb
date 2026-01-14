/**
 * @file benchmark_main.cpp
 * @brief kctsb vs OpenSSL Performance Benchmark Suite
 *
 * This benchmark suite compares kctsb cryptographic implementations
 * against OpenSSL reference implementations for performance validation.
 *
 * Benchmark Categories:
 * - AES-256-GCM: Authenticated encryption throughput
 * - ChaCha20-Poly1305: Stream cipher AEAD throughput
 * - SHA3-256/BLAKE2b: Hash function throughput
 *
 * Output Format:
 * - Throughput in MB/s for encryption/decryption operations
 * - Comparison ratio (kctsb / OpenSSL)
 * - Statistical summary with min/max/avg timings
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

    // Run benchmarks
    benchmark_aes_gcm();
    benchmark_aes_128_gcm();
    benchmark_chacha20_poly1305();
    benchmark_hash_functions();
    benchmark_ecc();
    benchmark_rsa();
    benchmark_sm();

    // Print summary
    print_summary();

    // Cleanup
    EVP_cleanup();
    ERR_free_strings();
    kctsb_cleanup();

    return 0;
}

/**
 * @brief Main benchmark entry point (standalone mode)
 */
int main(int argc, char* argv[]) {
    kctsb::utils::enable_utf8_console();

    (void)argc;  /* Unused parameter */
    (void)argv;  /* Unused parameter */

    return benchmark_main_entry();
}
