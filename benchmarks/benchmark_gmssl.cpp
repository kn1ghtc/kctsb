/**
 * @file benchmark_gmssl.cpp
 * @brief kctsb vs GmSSL 国密算法性能对比
 *
 * 对比算法:
 *   - SM2: 签名/验签/密钥交换
 *   - SM3: 哈希吞吐量
 *   - SM4-GCM: AEAD 加解密吞吐量
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifdef BENCHMARK_HAS_GMSSL

#include <iostream>
#include <vector>
#include <cstring>

#include "benchmark_common.hpp"

// kctsb 公共 API
#include "kctsb/kctsb_api.h"

// GmSSL 头文件
extern "C" {
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
}

namespace {

// 测试数据大小
const std::vector<size_t> TEST_SIZES = {
    benchmark::SIZE_1KB,
    benchmark::SIZE_1MB,
    benchmark::SIZE_10MB
};

// ============================================================================
// SM3 哈希对比
// ============================================================================

void benchmark_sm3() {
    std::cout << "\n--- SM3 Hash ---\n";
    benchmark::print_table_header();

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t hash_kctsb[32];
        uint8_t hash_gmssl[32];

        // kctsb 性能
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

        // GmSSL 性能
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

        // 打印结果
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
// SM4-GCM 对比
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

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            size_t ct_len = ciphertext.size();
            kctsb_sm4_gcm_encrypt(
                key.data(), iv.data(), IV_SIZE,
                nullptr, 0,
                plaintext.data(), data_size,
                ciphertext.data(), &ct_len,
                tag.data()
            );
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            size_t ct_len = ciphertext.size();
            timer.start();
            kctsb_sm4_gcm_encrypt(
                key.data(), iv.data(), IV_SIZE,
                nullptr, 0,
                plaintext.data(), data_size,
                ciphertext.data(), &ct_len,
                tag.data()
            );
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // GmSSL 性能
        double gmssl_total = 0;
        SM4_KEY sm4_key;
        sm4_set_encrypt_key(&sm4_key, key.data());

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            size_t ct_len = 0;
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

        // 打印结果
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
// SM2 签名/验签对比
// ============================================================================

void benchmark_sm2() {
    std::cout << "\n--- SM2 Signature ---\n";
    benchmark::print_table_header();

    // 准备测试数据
    auto message = benchmark::generate_random_data(32);

    // ============ 签名对比 ============
    {
        // kctsb SM2
        kctsb_sm2_keypair_t kctsb_kp = nullptr;
        kctsb_sm2_generate_keypair(&kctsb_kp);

        uint8_t kctsb_sig[128];
        size_t kctsb_sig_len = sizeof(kctsb_sig);

        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sig_len = sizeof(kctsb_sig);
            kctsb_sm2_sign(kctsb_kp, message.data(), message.size(),
                          kctsb_sig, &kctsb_sig_len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            kctsb_sig_len = sizeof(kctsb_sig);
            timer.start();
            kctsb_sm2_sign(kctsb_kp, message.data(), message.size(),
                          kctsb_sig, &kctsb_sig_len);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        // GmSSL SM2
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

        kctsb_sm2_free_keypair(kctsb_kp);
    }

    // ============ 验签对比 ============
    {
        // 准备签名
        kctsb_sm2_keypair_t kctsb_kp = nullptr;
        kctsb_sm2_generate_keypair(&kctsb_kp);

        uint8_t kctsb_sig[128];
        size_t kctsb_sig_len = sizeof(kctsb_sig);
        kctsb_sm2_sign(kctsb_kp, message.data(), message.size(), kctsb_sig, &kctsb_sig_len);

        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sm2_verify(kctsb_kp, message.data(), message.size(),
                            kctsb_sig, kctsb_sig_len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sm2_verify(kctsb_kp, message.data(), message.size(),
                            kctsb_sig, kctsb_sig_len);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;

        // GmSSL SM2
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

        kctsb_sm2_free_keypair(kctsb_kp);
    }
}

} // anonymous namespace

// ============================================================================
// 导出函数
// ============================================================================

void run_gmssl_benchmarks() {
    std::cout << "\nRunning GmSSL comparison benchmarks...\n";
    std::cout << "Testing: SM2, SM3, SM4-GCM Chinese cryptography standards\n";

    benchmark_sm3();
    benchmark_sm4_gcm();
    benchmark_sm2();

    std::cout << "\nGmSSL benchmarks complete.\n";
}

#endif // BENCHMARK_HAS_GMSSL
