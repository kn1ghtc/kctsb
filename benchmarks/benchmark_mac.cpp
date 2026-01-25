/**
 * @file benchmark_mac.cpp
 * @brief MAC Performance Benchmark: kctsb vs OpenSSL
 *
 * Algorithms:
 * - HMAC-SHA256
 * - HMAC-SHA512
 * - CMAC-AES128
 * - GMAC-AES128 (GCM AAD-only)
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

// Disable conversion warnings for benchmark code (intentional size_t -> int/double conversions)
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
#include <array>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <functional>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
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
    }
    return std::to_string(bytes / 1024) + " KB";
}

/**
 * @brief Run benchmark iterations and return average throughput
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

    double avg = std::accumulate(times.begin(), times.end(), 0.0) /
                 static_cast<double>(times.size());
    double throughput = calculate_throughput(data_size, avg);

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
// OpenSSL Benchmarks
// ============================================================================

static double benchmark_openssl_hmac_sha256(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    size_t key_len
) {
    uint8_t mac[32];
    unsigned int mac_len = 0;
    return run_benchmark_iterations("HMAC-SHA256", "OpenSSL", data_size, [&]() {
        auto start = Clock::now();
        HMAC(EVP_sha256(), key, static_cast<int>(key_len), data,
             data_size, mac, &mac_len);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_openssl_hmac_sha512(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    size_t key_len
) {
    uint8_t mac[64];
    unsigned int mac_len = 0;
    return run_benchmark_iterations("HMAC-SHA512", "OpenSSL", data_size, [&]() {
        auto start = Clock::now();
        HMAC(EVP_sha512(), key, static_cast<int>(key_len), data,
             data_size, mac, &mac_len);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_openssl_cmac_aes128(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key
) {
    uint8_t mac[16];
    size_t mac_len = 16;
    return run_benchmark_iterations("CMAC-AES128", "OpenSSL", data_size, [&]() {
        // Use OpenSSL 3.0 EVP_MAC API instead of deprecated CMAC_* functions
        EVP_MAC* mac_impl = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
        if (!mac_impl) return 0.0;
        
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac_impl);
        if (!ctx) {
            EVP_MAC_free(mac_impl);
            return 0.0;
        }
        
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("cipher", const_cast<char*>("AES-128-CBC"), 0),
            OSSL_PARAM_construct_end()
        };
        
        auto start = Clock::now();
        EVP_MAC_init(ctx, key, 16, params);
        EVP_MAC_update(ctx, data, data_size);
        EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac));
        auto end = Clock::now();
        
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac_impl);
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_openssl_gmac_aes128(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    const uint8_t* iv,
    size_t iv_len
) {
    uint8_t tag[16];
    return run_benchmark_iterations("GMAC-AES128", "OpenSSL", data_size, [&]() {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return 0.0;
        int out_len = 0;
        auto start = Clock::now();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv_len), nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
        EVP_EncryptUpdate(ctx, nullptr, &out_len, data, static_cast<int>(data_size));
        EVP_EncryptFinal_ex(ctx, nullptr, &out_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
        auto end = Clock::now();
        EVP_CIPHER_CTX_free(ctx);
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

// ============================================================================
// kctsb Benchmarks
// ============================================================================

static double benchmark_kctsb_hmac_sha256(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    size_t key_len
) {
    uint8_t mac[32];
    return run_benchmark_iterations("HMAC-SHA256", "kctsb", data_size, [&]() {
        auto start = Clock::now();
        kctsb_hmac_sha256(key, key_len, data, data_size, mac);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_kctsb_hmac_sha512(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    size_t key_len
) {
    uint8_t mac[64];
    return run_benchmark_iterations("HMAC-SHA512", "kctsb", data_size, [&]() {
        auto start = Clock::now();
        kctsb_hmac_sha512(key, key_len, data, data_size, mac);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_kctsb_cmac_aes128(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key
) {
    uint8_t mac[16];
    return run_benchmark_iterations("CMAC-AES128", "kctsb", data_size, [&]() {
        auto start = Clock::now();
        kctsb_cmac_aes(key, data, data_size, mac);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

static double benchmark_kctsb_gmac_aes128(
    const uint8_t* data,
    size_t data_size,
    const uint8_t* key,
    const uint8_t* iv,
    size_t iv_len
) {
    uint8_t tag[16];
    return run_benchmark_iterations("GMAC-AES128", "kctsb", data_size, [&]() {
        auto start = Clock::now();
        kctsb_gmac(key, iv, iv_len, data, data_size, tag);
        auto end = Clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    });
}

// ============================================================================
// Main Benchmark Function
// ============================================================================

void benchmark_mac() {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  kctsb MAC Benchmark vs OpenSSL" << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    std::array<uint8_t, 32> hmac256_key;
    std::array<uint8_t, 64> hmac512_key;
    std::array<uint8_t, 16> aes_key;
    std::array<uint8_t, 12> gmac_iv;
    generate_random(hmac256_key.data(), hmac256_key.size());
    generate_random(hmac512_key.data(), hmac512_key.size());
    generate_random(aes_key.data(), aes_key.size());
    generate_random(gmac_iv.data(), gmac_iv.size());

    for (size_t data_size : TEST_SIZES) {
        std::string size_str = format_size(data_size);

        std::cout << "\n--- Data Size: " << size_str << " ---" << std::endl;
        std::cout << std::left << std::setw(25) << "Algorithm"
                  << std::setw(15) << "Implementation"
                  << std::right << std::setw(13) << "Throughput"
                  << std::setw(10) << "Avg Time"
                  << std::endl;
        std::cout << std::string(63, '-') << std::endl;

        std::vector<uint8_t> data(data_size);
        generate_random(data.data(), data_size);

        double ssl_tp = 0.0;
        double kc_tp = 0.0;

        ssl_tp = benchmark_openssl_hmac_sha256(
            data.data(), data_size, hmac256_key.data(), hmac256_key.size());
        kc_tp = benchmark_kctsb_hmac_sha256(
            data.data(), data_size, hmac256_key.data(), hmac256_key.size());
        print_ratio(kc_tp, ssl_tp);

        ssl_tp = benchmark_openssl_hmac_sha512(
            data.data(), data_size, hmac512_key.data(), hmac512_key.size());
        kc_tp = benchmark_kctsb_hmac_sha512(
            data.data(), data_size, hmac512_key.data(), hmac512_key.size());
        print_ratio(kc_tp, ssl_tp);

        ssl_tp = benchmark_openssl_cmac_aes128(
            data.data(), data_size, aes_key.data());
        kc_tp = benchmark_kctsb_cmac_aes128(
            data.data(), data_size, aes_key.data());
        print_ratio(kc_tp, ssl_tp);

        ssl_tp = benchmark_openssl_gmac_aes128(
            data.data(), data_size, aes_key.data(), gmac_iv.data(), gmac_iv.size());
        kc_tp = benchmark_kctsb_gmac_aes128(
            data.data(), data_size, aes_key.data(), gmac_iv.data(), gmac_iv.size());
        print_ratio(kc_tp, ssl_tp);
    }

    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  Benchmark Summary" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Algorithms tested: HMAC-SHA256, HMAC-SHA512," << std::endl;
    std::cout << "                   CMAC-AES128, GMAC-AES128" << std::endl;
    std::cout << "Iterations per test: " << BENCHMARK_ITERATIONS << std::endl;
    std::cout << "Warmup iterations: " << WARMUP_ITERATIONS << std::endl;
    std::cout << "\nNotes:" << std::endl;
    std::cout << "  - Ratio > 1.0x means kctsb is faster than OpenSSL" << std::endl;
}

// Restore diagnostic settings
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
