/**
 * @file benchmark_hash.cpp
 * @brief Hash Function Performance Benchmark: kctsb v3.4.0 vs OpenSSL
 *
 * Complete coverage benchmarks for all hash algorithms:
 * - SHA-256: FIPS 180-4
 * - SHA-384: FIPS 180-4 truncated SHA-512
 * - SHA-512: FIPS 180-4
 * - SHA3-256: FIPS 202 (Keccak)
 * - SHA3-512: FIPS 202 (Keccak)
 * - SHAKE128/256: FIPS 202 XOF
 * - BLAKE2b-256/512: RFC 7693
 * - BLAKE2s-256: RFC 7693
 * - SM3: GB/T 32905-2016 (Chinese national standard)
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
 */
static double calculate_throughput(size_t bytes, double ms) {
    return (bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
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
 * @brief Benchmark result structure
 */
struct BenchmarkResult {
    std::string algorithm;
    std::string impl;
    double avg_time_ms;
    double throughput_mbs;
    double min_time_ms;
    double max_time_ms;
};

/**
 * @brief Run benchmark iterations and collect statistics
 */
static BenchmarkResult run_benchmark(
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
    std::sort(times.begin(), times.end());
    double avg = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    double throughput = calculate_throughput(data_size, avg);

    return {
        name,
        impl,
        avg,
        throughput,
        times.front(),
        times.back()
    };
}

/**
 * @brief Print benchmark result
 */
static void print_result(const BenchmarkResult& r) {
    std::cout << std::left << std::setw(18) << r.algorithm
              << std::setw(10) << r.impl
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(12) << r.throughput_mbs << " MB/s"
              << std::setw(10) << r.avg_time_ms << " ms"
              << std::endl;
}

/**
 * @brief Print comparison between kctsb and OpenSSL
 */
static void print_comparison(const BenchmarkResult& kctsb, const BenchmarkResult& openssl) {
    double ratio = kctsb.throughput_mbs / openssl.throughput_mbs;
    const char* status = ratio >= 1.0 ? "✓" : "✗";
    std::cout << "    → kctsb/OpenSSL ratio: " << std::fixed << std::setprecision(2)
              << ratio << "x " << status << std::endl;
}

// ============================================================================
// Individual Algorithm Benchmarks
// ============================================================================

static BenchmarkResult benchmark_sha256_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("SHA-256", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha256(), data, size, digest);
    });
}

static BenchmarkResult benchmark_sha256_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("SHA-256", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha256(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static BenchmarkResult benchmark_sha384_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[48];
    return run_benchmark("SHA-384", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha384(), data, size, digest);
    });
}

static BenchmarkResult benchmark_sha384_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[48];
    return run_benchmark("SHA-384", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha384(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static BenchmarkResult benchmark_sha512_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark("SHA-512", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha512(), data, size, digest);
    });
}

static BenchmarkResult benchmark_sha512_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark("SHA-512", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha512(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static BenchmarkResult benchmark_sha3_256_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("SHA3-256", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha3_256(), data, size, digest);
    });
}

static BenchmarkResult benchmark_sha3_256_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("SHA3-256", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha3_256(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static BenchmarkResult benchmark_sha3_512_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark("SHA3-512", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sha3_512(), data, size, digest);
    });
}

static BenchmarkResult benchmark_sha3_512_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark("SHA3-512", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_sha3_512(data, size, digest);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static BenchmarkResult benchmark_blake2b_512_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark("BLAKE2b-512", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_blake2b512(), data, size, digest);
    });
}

static BenchmarkResult benchmark_blake2b_512_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[64];
    return run_benchmark("BLAKE2b-512", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_blake2b(data, size, digest, 64);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static BenchmarkResult benchmark_blake2s_256_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("BLAKE2s-256", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_blake2s256(), data, size, digest);
    });
}

static BenchmarkResult benchmark_blake2s_256_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("BLAKE2s-256", "kctsb", size, [&]() {
        auto start = Clock::now();
        kctsb_blake2s(data, size, digest, 32);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static BenchmarkResult benchmark_sm3_openssl(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("SM3", "OpenSSL", size, [&]() {
        return benchmark_openssl_hash(EVP_sm3(), data, size, digest);
    });
}

static BenchmarkResult benchmark_sm3_kctsb(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    return run_benchmark("SM3", "kctsb", size, [&]() {
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
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  kctsb v3.4.0 Hash Functions Benchmark vs OpenSSL" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

    // Initialize kctsb
    kctsb_init();

    for (size_t data_size : TEST_SIZES) {
        std::cout << "\n━━━ Data Size: " << format_size(data_size) << " ━━━" << std::endl;
        std::cout << std::left << std::setw(18) << "Algorithm"
                  << std::setw(10) << "Impl"
                  << std::right << std::setw(15) << "Throughput"
                  << std::setw(10) << "Avg Time"
                  << std::endl;
        std::cout << std::string(55, '-') << std::endl;

        // Generate random test data
        std::vector<uint8_t> data(data_size);
        generate_random(data.data(), data_size);

        // SHA-256
        auto sha256_ssl = benchmark_sha256_openssl(data.data(), data_size);
        auto sha256_kc = benchmark_sha256_kctsb(data.data(), data_size);
        print_result(sha256_ssl);
        print_result(sha256_kc);
        print_comparison(sha256_kc, sha256_ssl);

        std::cout << std::endl;

        // SHA-384
        auto sha384_ssl = benchmark_sha384_openssl(data.data(), data_size);
        auto sha384_kc = benchmark_sha384_kctsb(data.data(), data_size);
        print_result(sha384_ssl);
        print_result(sha384_kc);
        print_comparison(sha384_kc, sha384_ssl);

        std::cout << std::endl;

        // SHA-512
        auto sha512_ssl = benchmark_sha512_openssl(data.data(), data_size);
        auto sha512_kc = benchmark_sha512_kctsb(data.data(), data_size);
        print_result(sha512_ssl);
        print_result(sha512_kc);
        print_comparison(sha512_kc, sha512_ssl);

        std::cout << std::endl;

        // SHA3-256
        auto sha3_256_ssl = benchmark_sha3_256_openssl(data.data(), data_size);
        auto sha3_256_kc = benchmark_sha3_256_kctsb(data.data(), data_size);
        print_result(sha3_256_ssl);
        print_result(sha3_256_kc);
        print_comparison(sha3_256_kc, sha3_256_ssl);

        std::cout << std::endl;

        // SHA3-512
        auto sha3_512_ssl = benchmark_sha3_512_openssl(data.data(), data_size);
        auto sha3_512_kc = benchmark_sha3_512_kctsb(data.data(), data_size);
        print_result(sha3_512_ssl);
        print_result(sha3_512_kc);
        print_comparison(sha3_512_kc, sha3_512_ssl);

        std::cout << std::endl;

        // BLAKE2b-512
        auto blake2b_ssl = benchmark_blake2b_512_openssl(data.data(), data_size);
        auto blake2b_kc = benchmark_blake2b_512_kctsb(data.data(), data_size);
        print_result(blake2b_ssl);
        print_result(blake2b_kc);
        print_comparison(blake2b_kc, blake2b_ssl);

        std::cout << std::endl;

        // BLAKE2s-256
        auto blake2s_ssl = benchmark_blake2s_256_openssl(data.data(), data_size);
        auto blake2s_kc = benchmark_blake2s_256_kctsb(data.data(), data_size);
        print_result(blake2s_ssl);
        print_result(blake2s_kc);
        print_comparison(blake2s_kc, blake2s_ssl);

        std::cout << std::endl;

        // SM3
        auto sm3_ssl = benchmark_sm3_openssl(data.data(), data_size);
        auto sm3_kc = benchmark_sm3_kctsb(data.data(), data_size);
        print_result(sm3_ssl);
        print_result(sm3_kc);
        print_comparison(sm3_kc, sm3_ssl);
    }

    // Summary
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  Benchmark Summary" << std::endl;
    std::cout << std::string(75, '=') << std::endl;
    std::cout << "Algorithms tested: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512," << std::endl;
    std::cout << "                   BLAKE2b-512, BLAKE2s-256, SM3" << std::endl;
    std::cout << "Iterations per test: " << BENCHMARK_ITERATIONS << std::endl;
    std::cout << "Warmup iterations: " << WARMUP_ITERATIONS << std::endl;
    std::cout << "\nNotes:" << std::endl;
    std::cout << "  - SHA-256/384/512: FIPS 180-4 compliant" << std::endl;
    std::cout << "  - SHA3: FIPS 202 Keccak sponge construction" << std::endl;
    std::cout << "  - BLAKE2: RFC 7693, optimized for software" << std::endl;
    std::cout << "  - SM3: GB/T 32905-2016 Chinese national standard" << std::endl;
    std::cout << "  - kctsb/OpenSSL ratio > 1.0 means kctsb is faster" << std::endl;
}
