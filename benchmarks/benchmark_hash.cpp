/**
 * @file benchmark_hash.cpp
 * @brief Hash Function Performance Benchmark: kctsb v3.4.1 vs OpenSSL
 *
 * Complete coverage benchmarks for all hash algorithms:
 * - SHA-256: FIPS 180-4
 * - SHA-512: FIPS 180-4
 * - SHA3-256: FIPS 202 (Keccak)
 * - SHA3-512: FIPS 202 (Keccak)
 * - SHAKE128/256: FIPS 202 XOF
 * - BLAKE2b-256/512: RFC 7693
 * - BLAKE2s-256: RFC 7693
 * - SM3: GB/T 32905-2016 (Chinese national standard)
 *
 * Note: SHA-384 removed in v3.4.1 (only 256/512 supported)
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

// Disable conversion warnings for benchmark code (intentional size_t -> double conversions)
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

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

// kctsb v3.4.0 headers - use unified public API
#include "kctsb/kctsb_api.h"

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 10;
constexpr size_t BENCHMARK_ITERATIONS = 100;

// Test data sizes
const std::vector<size_t> TEST_SIZES = {
    1024,              // 1 KB
    64 * 1024,         // 64 KB
    1024 * 1024,       // 1 MB
    10 * 1024 * 1024   // 10 MB
};

using Clock = std::chrono::high_resolution_clock;
using Duration = std::chrono::duration<double, std::milli>;

/**
 * @brief Generate random bytes using OpenSSL
 */
static void generate_random(uint8_t* buf, size_t len) {
    RAND_bytes(buf, static_cast<int>(len));
}

/**
 * @brief Calculate throughput in MB/s
 * @param bytes Data size in bytes (will be converted to double)
 * @param ms Time in milliseconds
 * @return Throughput in MB/s
 */
static double calculate_throughput(size_t bytes, double ms) {
    return (static_cast<double>(bytes) / (1024.0 * 1024.0)) / (ms / 1000.0);
}

/**
 * @brief Format size string
 */
static std::string format_size(size_t bytes) {
    if (bytes >= 1024 * 1024) {
        return std::to_string(bytes / (1024 * 1024)) + " MB";
    } else {
        return std::to_string(bytes / 1024) + " KB";
    }
}

/**
 * @brief OpenSSL hash benchmark template
 */
static double benchmark_openssl_hash(
    const EVP_MD* md,
    const uint8_t* data,
    size_t data_len,
    uint8_t* digest
) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return -1.0;

    unsigned int digest_len = 0;

    auto start = Clock::now();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    auto end = Clock::now();

    EVP_MD_CTX_free(ctx);
    return std::chrono::duration<double, std::milli>(end - start).count();
}

/**
 * @brief Run benchmark iterations and return average throughput
 * 
 * @param name Algorithm name
 * @param impl Implementation name (OpenSSL/kctsb)
 * @param data_size Data size in bytes
 * @param benchmark_func Benchmark function returning time in ms
 * @return Average throughput in MB/s
 */
static double run_benchmark_iterations(
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
    double avg = std::accumulate(times.begin(), times.end(), 0.0) /
                 static_cast<double>(times.size());
    double throughput = calculate_throughput(data_size, avg);

    // Print result (consistent format with other benchmarks)
    std::cout << std::left << std::setw(25) << name
              << std::setw(15) << impl
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(10) << throughput << " MB/s"
              << std::setw(10) << avg << " ms"
              << std::endl;
    
    return throughput;
}

/**
 * @brief Print ratio comparison between kctsb and OpenSSL
 * 
 * @param kctsb_throughput kctsb throughput in MB/s
 * @param openssl_throughput OpenSSL throughput in MB/s
 */
static void print_ratio(double kctsb_throughput, double openssl_throughput) {
    double ratio = kctsb_throughput / openssl_throughput;
    const char* status = ratio >= 1.0 ? "FASTER" : "SLOWER";
    const char* symbol = ratio >= 1.0 ? "+" : "";
    double diff_percent = (ratio - 1.0) * 100.0;
    
    std::cout << std::left << std::setw(25) << "  ==> Ratio"
              << std::setw(15) << ""
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(10) << ratio << "x"
              << "    (" << symbol << diff_percent << "% " << status << ")"
              << std::endl;
}

// ============================================================================
// Individual Algorithm Benchmarks (returning throughput for ratio calculation)
// ============================================================================

static double benchmark_sha256_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark_iterations("SHA-256", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha256(), data, size, digest);
    });
}

static double benchmark_sha256_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark_iterations("SHA-256", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha256(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_sha512_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark_iterations("SHA-512", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha512(), data, size, digest);
    });
}

static double benchmark_sha512_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark_iterations("SHA-512", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha512(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_sha3_256_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark_iterations("SHA3-256", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha3_256(), data, size, digest);
    });
}

static double benchmark_sha3_256_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark_iterations("SHA3-256", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha3_256(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_sha3_512_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark_iterations("SHA3-512", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha3_512(), data, size, digest);
    });
}

static double benchmark_sha3_512_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark_iterations("SHA3-512", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha3_512(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_blake2b_512_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark_iterations("BLAKE2b-512", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_blake2b512(), data, size, digest);
    });
}

static double benchmark_blake2b_512_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark_iterations("BLAKE2b-512", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_blake2b(data, size, digest, 64);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_sm3_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark_iterations("SM3", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sm3(), data, size, digest);
    });
}

static double benchmark_sm3_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark_iterations("SM3", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sm3(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

// ============================================================================
// Main Benchmark Function
// ============================================================================

void benchmark_hash_functions() {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  kctsb v3.4.0 Hash Functions Benchmark vs OpenSSL" << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    // Initialize kctsb
    kctsb_init();

    for (size_t data_size : TEST_SIZES) {
        std::string size_str = format_size(data_size);

        std::cout << "\n--- Data Size: " << size_str << " ---" << std::endl;
        std::cout << std::left << std::setw(25) << "Algorithm"
                  << std::setw(15) << "Implementation"
                  << std::right << std::setw(13) << "Throughput"
                  << std::setw(10) << "Avg Time"
                  << std::endl;
        std::cout << std::string(63, '-') << std::endl;

        // Generate random test data
        std::vector<uint8_t> data(data_size);
        generate_random(data.data(), data_size);

        double ssl_tp, kc_tp;

        // SHA-256
        ssl_tp = benchmark_sha256_openssl(data.data(), data_size);
        kc_tp = benchmark_sha256_kctsb(data.data(), data_size);
        print_ratio(kc_tp, ssl_tp);

        // SHA-512
        ssl_tp = benchmark_sha512_openssl(data.data(), data_size);
        kc_tp = benchmark_sha512_kctsb(data.data(), data_size);
        print_ratio(kc_tp, ssl_tp);

        // SHA3-256
        ssl_tp = benchmark_sha3_256_openssl(data.data(), data_size);
        kc_tp = benchmark_sha3_256_kctsb(data.data(), data_size);
        print_ratio(kc_tp, ssl_tp);

        // SHA3-512
        ssl_tp = benchmark_sha3_512_openssl(data.data(), data_size);
        kc_tp = benchmark_sha3_512_kctsb(data.data(), data_size);
        print_ratio(kc_tp, ssl_tp);

        // BLAKE2b-512
        ssl_tp = benchmark_blake2b_512_openssl(data.data(), data_size);
        kc_tp = benchmark_blake2b_512_kctsb(data.data(), data_size);
        print_ratio(kc_tp, ssl_tp);

        // SM3
        ssl_tp = benchmark_sm3_openssl(data.data(), data_size);
        kc_tp = benchmark_sm3_kctsb(data.data(), data_size);
        print_ratio(kc_tp, ssl_tp);
    }

    // Summary
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  Benchmark Summary" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Algorithms tested: SHA-256, SHA-512, SHA3-256, SHA3-512," << std::endl;
    std::cout << "                   BLAKE2b-512, SM3" << std::endl;
    std::cout << "Iterations per test: " << BENCHMARK_ITERATIONS << std::endl;
    std::cout << "Warmup iterations: " << WARMUP_ITERATIONS << std::endl;
    std::cout << "\nNotes:" << std::endl;
    std::cout << "  - SHA-256/512: FIPS 180-4 compliant" << std::endl;
    std::cout << "  - SHA3: FIPS 202 Keccak sponge construction" << std::endl;
    std::cout << "  - BLAKE2: RFC 7693, optimized for software" << std::endl;
    std::cout << "  - SM3: GB/T 32905-2016 Chinese national standard" << std::endl;
    std::cout << "  - Ratio > 1.0x means kctsb is faster than OpenSSL" << std::endl;
}

// Restore diagnostic settings
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
