/**
 * @file benchmark_gmssl.cpp
 * @brief kctsb vs GmSSL Chinese Cryptography Performance Comparison
 *
 * Compares:
 *   - SM2: Signature/Verification (GM/T 0003-2012)
 *   - SM3: Hash throughput
 *   - SM4-GCM: AEAD encryption throughput
 *
 * Follows AGENTS.md specification:
 *   - Uses only public API (kctsb_api.h)
 *   - Library-level comparison, no internal dependencies
 *   - 10 warmup, 100 benchmark iterations
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifdef BENCHMARK_HAS_GMSSL

#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>

#include "benchmark_common.hpp"

// kctsb public API ONLY - no internal headers
#include "kctsb/kctsb_api.h"

// GmSSL headers
extern "C" {
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
}

namespace {

// Test data sizes
const std::vector<size_t> TEST_SIZES = {
    benchmark::SIZE_1KB,
    benchmark::SIZE_1MB,
    benchmark::SIZE_10MB
};

// Default user ID (SM2 standard)
constexpr const char* DEFAULT_USER_ID = "1234567812345678";
constexpr size_t DEFAULT_USER_ID_LEN = 16;

// ============================================================================
// SM3 Hash Comparison
// ============================================================================

void benchmark_sm3() {
    std::cout << "\n--- SM3 Hash ---\n";
    benchmark::print_table_header();

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t hash_kctsb[32];
        uint8_t hash_gmssl[32];

        // kctsb performance
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sm3(data.data(), data_size, hash_kctsb);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sm3(data.data(), data_size, hash_kctsb);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // GmSSL performance
        double gmssl_total = 0;
        SM3_CTX ctx;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            sm3_init(&ctx);
            sm3_update(&ctx, data.data(), data_size);
            sm3_finish(&ctx, hash_gmssl);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            sm3_init(&ctx);
            sm3_update(&ctx, data.data(), data_size);
            sm3_finish(&ctx, hash_gmssl);
            gmssl_total += timer.stop();
        }

        double gmssl_avg = gmssl_total / benchmark::BENCHMARK_ITERATIONS;
        double gmssl_throughput = benchmark::calculate_throughput(data_size, gmssl_avg);

        // Print results
        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "SM3 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result gmssl_result{
            "SM3 " + size_name, "GmSSL",
            gmssl_avg, gmssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(gmssl_result);

        double ratio = kctsb_avg / gmssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// SM4-GCM Comparison
// ============================================================================

void benchmark_sm4_gcm() {
    std::cout << "\n--- SM4-GCM ---\n";
    benchmark::print_table_header();

    constexpr size_t KEY_SIZE = 16;
    constexpr size_t IV_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;

    auto key = benchmark::generate_random_data(KEY_SIZE);
    auto iv = benchmark::generate_random_data(IV_SIZE);

    for (size_t data_size : TEST_SIZES) {
        auto plaintext = benchmark::generate_random_data(data_size);
        std::vector<uint8_t> ciphertext(data_size + TAG_SIZE);
        std::vector<uint8_t> tag(TAG_SIZE);

        // kctsb performance (using oneshot API)
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sm4_gcm_encrypt_oneshot(
                key.data(), iv.data(),
                nullptr, 0,
                plaintext.data(), data_size,
                ciphertext.data(), tag.data()
            );
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sm4_gcm_encrypt_oneshot(
                key.data(), iv.data(),
                nullptr, 0,
                plaintext.data(), data_size,
                ciphertext.data(), tag.data()
            );
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // GmSSL performance
        double gmssl_total = 0;
        SM4_KEY sm4_key;
        sm4_set_encrypt_key(&sm4_key, key.data());

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            sm4_gcm_encrypt(&sm4_key, iv.data(), IV_SIZE,
                           nullptr, 0,
                           plaintext.data(), data_size,
                           ciphertext.data(), TAG_SIZE, tag.data());
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            sm4_gcm_encrypt(&sm4_key, iv.data(), IV_SIZE,
                           nullptr, 0,
                           plaintext.data(), data_size,
                           ciphertext.data(), TAG_SIZE, tag.data());
            gmssl_total += timer.stop();
        }

        double gmssl_avg = gmssl_total / benchmark::BENCHMARK_ITERATIONS;
        double gmssl_throughput = benchmark::calculate_throughput(data_size, gmssl_avg);

        // Print results
        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "SM4-GCM " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result gmssl_result{
            "SM4-GCM " + size_name, "GmSSL",
            gmssl_avg, gmssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(gmssl_result);

        double ratio = kctsb_avg / gmssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// SM2 Signature Comparison
// ============================================================================

void benchmark_sm2() {
    std::cout << "\n--- SM2 Signature (GM/T 0003-2012) ---\n";
    benchmark::print_table_header();

    // Prepare test message
    auto message = benchmark::generate_random_data(32);

    // ============ KeyGen Comparison ============
    {
        std::cout << "=== SM2 KeyGen ===\n";

        benchmark::Timer timer;
        double kctsb_total = 0;

        // kctsb key generation
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sm2_keypair_t keypair;
            kctsb_sm2_generate_keypair(&keypair);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            kctsb_sm2_keypair_t keypair;
            timer.start();
            kctsb_sm2_generate_keypair(&keypair);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        // GmSSL key generation
        double gmssl_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            SM2_KEY gmssl_key;
            sm2_key_generate(&gmssl_key);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            SM2_KEY gmssl_key;
            timer.start();
            sm2_key_generate(&gmssl_key);
            gmssl_total += timer.stop();
        }

        double gmssl_avg = gmssl_total / benchmark::BENCHMARK_ITERATIONS;

        benchmark::print_result({"SM2 KeyGen", "kctsb", kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"SM2 KeyGen", "GmSSL", gmssl_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});

        double ratio = kctsb_avg / gmssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // ============ Sign Comparison ============
    {
        std::cout << "=== SM2 Sign ===\n";

        // Prepare kctsb keypair
        kctsb_sm2_keypair_t kctsb_keypair;
        kctsb_sm2_generate_keypair(&kctsb_keypair);

        kctsb_sm2_signature_t kctsb_sig;

        benchmark::Timer timer;
        double kctsb_total = 0;

        // kctsb sign warmup
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sm2_sign(
                kctsb_keypair.private_key,
                kctsb_keypair.public_key,
                reinterpret_cast<const uint8_t*>(DEFAULT_USER_ID),
                DEFAULT_USER_ID_LEN,
                message.data(), message.size(),
                &kctsb_sig
            );
        }

        // kctsb sign benchmark
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sm2_sign(
                kctsb_keypair.private_key,
                kctsb_keypair.public_key,
                reinterpret_cast<const uint8_t*>(DEFAULT_USER_ID),
                DEFAULT_USER_ID_LEN,
                message.data(), message.size(),
                &kctsb_sig
            );
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        // GmSSL sign
        SM2_KEY gmssl_key;
        sm2_key_generate(&gmssl_key);

        uint8_t gmssl_sig[128];
        size_t gmssl_sig_len = sizeof(gmssl_sig);

        double gmssl_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            gmssl_sig_len = sizeof(gmssl_sig);
            sm2_sign(&gmssl_key, message.data(), gmssl_sig, &gmssl_sig_len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            gmssl_sig_len = sizeof(gmssl_sig);
            timer.start();
            sm2_sign(&gmssl_key, message.data(), gmssl_sig, &gmssl_sig_len);
            gmssl_total += timer.stop();
        }

        double gmssl_avg = gmssl_total / benchmark::BENCHMARK_ITERATIONS;

        benchmark::print_result({"SM2 Sign", "kctsb", kctsb_avg, 0, 32, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"SM2 Sign", "GmSSL", gmssl_avg, 0, 32, benchmark::BENCHMARK_ITERATIONS});

        double ratio = kctsb_avg / gmssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }

    // ============ Verify Comparison ============
    {
        std::cout << "=== SM2 Verify ===\n";

        // Prepare kctsb keypair and signature
        kctsb_sm2_keypair_t kctsb_keypair;
        kctsb_sm2_generate_keypair(&kctsb_keypair);

        kctsb_sm2_signature_t kctsb_sig;
        kctsb_sm2_sign(
            kctsb_keypair.private_key,
            kctsb_keypair.public_key,
            reinterpret_cast<const uint8_t*>(DEFAULT_USER_ID),
            DEFAULT_USER_ID_LEN,
            message.data(), message.size(),
            &kctsb_sig
        );

        benchmark::Timer timer;
        double kctsb_total = 0;

        // kctsb verify warmup
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sm2_verify(
                kctsb_keypair.public_key,
                reinterpret_cast<const uint8_t*>(DEFAULT_USER_ID),
                DEFAULT_USER_ID_LEN,
                message.data(), message.size(),
                &kctsb_sig
            );
        }

        // kctsb verify benchmark
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sm2_verify(
                kctsb_keypair.public_key,
                reinterpret_cast<const uint8_t*>(DEFAULT_USER_ID),
                DEFAULT_USER_ID_LEN,
                message.data(), message.size(),
                &kctsb_sig
            );
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        // GmSSL verify
        SM2_KEY gmssl_key;
        sm2_key_generate(&gmssl_key);

        uint8_t gmssl_sig[128];
        size_t gmssl_sig_len = sizeof(gmssl_sig);
        sm2_sign(&gmssl_key, message.data(), gmssl_sig, &gmssl_sig_len);

        double gmssl_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            sm2_verify(&gmssl_key, message.data(), gmssl_sig, gmssl_sig_len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            sm2_verify(&gmssl_key, message.data(), gmssl_sig, gmssl_sig_len);
            gmssl_total += timer.stop();
        }

        double gmssl_avg = gmssl_total / benchmark::BENCHMARK_ITERATIONS;

        benchmark::print_result({"SM2 Verify", "kctsb", kctsb_avg, 0, 32, benchmark::BENCHMARK_ITERATIONS});
        benchmark::print_result({"SM2 Verify", "GmSSL", gmssl_avg, 0, 32, benchmark::BENCHMARK_ITERATIONS});

        double ratio = kctsb_avg / gmssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

} // anonymous namespace

// ============================================================================
// Export function
// ============================================================================

void run_gmssl_benchmarks() {
    std::cout << "\n=== GmSSL Chinese Cryptography Comparison ===\n";
    std::cout << "Testing: SM2, SM3, SM4-GCM (GM/T standards)\n";
    std::cout << "Iterations: " << benchmark::BENCHMARK_ITERATIONS
              << " (warmup: " << benchmark::WARMUP_ITERATIONS << ")\n";

    benchmark_sm3();
    benchmark_sm4_gcm();
    benchmark_sm2();

    std::cout << "\nGmSSL benchmarks complete.\n";
}

#endif // BENCHMARK_HAS_GMSSL
