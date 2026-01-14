/**
 * @file benchmark_hash.cpp
 * @brief Hash Function Performance Benchmark: kctsb vs OpenSSL
 *
 * Benchmarks hash function throughput for:
 * - SHA3-256 (Keccak-based)
 * - BLAKE2b-256
 * - SHA-256 (baseline comparison)
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <functional>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>

// kctsb headers (conditional)
#if defined(KCTSB_HAS_SHA3) || defined(KCTSB_HAS_BLAKE2)
#include "kctsb/crypto/hash/keccak.h"
#include "kctsb/crypto/blake.h"
#endif

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 10;
constexpr size_t BENCHMARK_ITERATIONS = 100;
// HASH_OUTPUT_SIZE (256 bits / 32 bytes) used in hash buffer sizing below

// Test data sizes
const std::vector<size_t> TEST_SIZES = {
    1024,           // 1 KB
    1024 * 1024,    // 1 MB
    10 * 1024 * 1024 // 10 MB
};

using Clock = std::chrono::high_resolution_clock;
using Duration = std::chrono::duration<double, std::milli>;

/**
 * @brief Generate random bytes
 */
static void generate_random(uint8_t* buf, size_t len) {
    RAND_bytes(buf, static_cast<int>(len));
}

/**
 * @brief Calculate throughput in MB/s
 */
static double calculate_throughput(size_t bytes, double ms) {
    return (bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
}

/**
 * @brief OpenSSL hash benchmark template
 */
static double benchmark_openssl_hash(
    const EVP_MD* md,
    const std::vector<uint8_t>& data,
    uint8_t* digest
) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return -1.0;

    unsigned int digest_len = 0;

    auto start = Clock::now();

    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);

    auto end = Clock::now();
    Duration elapsed = end - start;

    EVP_MD_CTX_free(ctx);
    return elapsed.count();
}

/**
 * @brief Run benchmark iterations
 */
static void run_benchmark_iterations(
    const std::string& name,
    const std::string& impl,
    size_t data_size,
    std::function<double()> benchmark_func
) {
    std::vector<double> times;
    times.reserve(BENCHMARK_ITERATIONS);

    // Warmup
    for (size_t i = 0; i < WARMUP_ITERATIONS; ++i) {
        benchmark_func();
    }

    // Benchmark
    for (size_t i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        times.push_back(benchmark_func());
    }

    // Statistics
    double avg = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    double throughput = calculate_throughput(data_size, avg);

    std::cout << std::left << std::setw(25) << name
              << std::setw(15) << impl
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(10) << throughput << " MB/s"
              << std::setw(10) << avg << " ms"
              << std::endl;
}

/**
 * @brief Main hash benchmark function
 */
void benchmark_hash_functions() {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  Hash Functions Benchmark" << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    uint8_t digest[EVP_MAX_MD_SIZE];

    for (size_t data_size : TEST_SIZES) {
        std::string size_str;
        if (data_size >= 1024 * 1024) {
            size_str = std::to_string(data_size / (1024 * 1024)) + " MB";
        } else {
            size_str = std::to_string(data_size / 1024) + " KB";
        }

        std::cout << "\n--- Data Size: " << size_str << " ---" << std::endl;
        std::cout << std::left << std::setw(25) << "Algorithm"
                  << std::setw(15) << "Implementation"
                  << std::right << std::setw(13) << "Throughput"
                  << std::setw(10) << "Avg Time"
                  << std::endl;
        std::cout << std::string(63, '-') << std::endl;

        // Generate test data
        std::vector<uint8_t> data(data_size);
        generate_random(data.data(), data_size);

        // SHA-256 (baseline)
        run_benchmark_iterations(
            "SHA-256", "OpenSSL", data_size,
            [&]() {
                return benchmark_openssl_hash(EVP_sha256(), data, digest);
            }
        );

        // SHA3-256
        run_benchmark_iterations(
            "SHA3-256", "OpenSSL", data_size,
            [&]() {
                return benchmark_openssl_hash(EVP_sha3_256(), data, digest);
            }
        );

#ifdef KCTSB_HAS_HASH
        // kctsb SHA3-256 (Keccak)
        run_benchmark_iterations(
            "SHA3-256", "kctsb", data_size,
            [&]() {
                auto start = Clock::now();
                // Using kctsb Keccak implementation
                uint8_t kctsb_digest[32];
                // TODO: Call actual kctsb Keccak SHA3-256
                // kctsb::sha3_256(data.data(), data.size(), kctsb_digest);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            }
        );
#else
        std::cout << "SHA3-256                 kctsb          (not compiled)" << std::endl;
#endif

        // BLAKE2b-256
        run_benchmark_iterations(
            "BLAKE2b-256", "OpenSSL", data_size,
            [&]() {
                return benchmark_openssl_hash(EVP_blake2b512(), data, digest);
            }
        );

#ifdef KCTSB_HAS_HASH
        // kctsb BLAKE2b
        run_benchmark_iterations(
            "BLAKE2b-256", "kctsb", data_size,
            [&]() {
                auto start = Clock::now();
                uint8_t kctsb_digest[32];
                // TODO: Call actual kctsb BLAKE2b-256
                // kctsb::blake2b(data.data(), data.size(), kctsb_digest, 32);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            }
        );
#else
        std::cout << "BLAKE2b-256              kctsb          (not compiled)" << std::endl;
#endif
    }

    // Print notes
    std::cout << "\nNotes:" << std::endl;
    std::cout << "  - SHA-256 included as baseline comparison" << std::endl;
    std::cout << "  - SHA3-256 uses Keccak sponge construction" << std::endl;
    std::cout << "  - BLAKE2b is optimized for software performance" << std::endl;
}
