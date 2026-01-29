/**
 * @file benchmark_openssl.cpp
 * @brief kctsb vs OpenSSL 3.6.0 性能对比
 *
 * 对比算法:
 *   - AES-256-GCM: AEAD 加解密吞吐量
 *   - AES-128-GCM: AEAD 加解密吞吐量
 *   - ChaCha20-Poly1305: 流密码 AEAD 吞吐量
 *   - SHA-256: 传统哈希吞吐量
 *   - SHA-512: 高吞吐量哈希
 *   - SHA3-256: 后量子安全哈希吞吐量
 *   - BLAKE2b-256: 高性能哈希吞吐量
 *   - HMAC-SHA256: 消息认证码性能
 *   - HMAC-SHA512: 高吞吐量 MAC
 *   - RSA-3072: 签名/验签性能
 *   - ECDSA P-256: 签名/验签性能
 *   - ECDH P-256: 密钥交换性能
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifdef BENCHMARK_HAS_OPENSSL

#include <iostream>
#include <vector>
#include <cstring>

#include "benchmark_common.hpp"

// kctsb 公共 API
#include "kctsb/kctsb_api.h"

// OpenSSL 头文件
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

namespace {

// 测试数据大小
const std::vector<size_t> TEST_SIZES = {
    benchmark::SIZE_1KB,
    benchmark::SIZE_1MB,
    benchmark::SIZE_10MB
};

// ============================================================================
// AES-256-GCM 对比
// ============================================================================

void benchmark_aes_256_gcm() {
    std::cout << "\n--- AES-256-GCM ---\n";
    benchmark::print_table_header();

    constexpr size_t KEY_SIZE = 32;
    constexpr size_t IV_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;

    // 生成测试数据
    auto key = benchmark::generate_random_data(KEY_SIZE);
    auto iv = benchmark::generate_random_data(IV_SIZE);

    for (size_t data_size : TEST_SIZES) {
        auto plaintext = benchmark::generate_random_data(data_size);
        std::vector<uint8_t> ciphertext(data_size);
        uint8_t tag[TAG_SIZE];

        // 初始化 AES 上下文
        kctsb_aes_ctx_t aes_ctx;
        kctsb_aes_init(&aes_ctx, key.data(), KEY_SIZE);

        // kctsb 加密性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        // 预热
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_aes_gcm_encrypt(
                &aes_ctx,
                iv.data(), IV_SIZE,
                nullptr, 0,  // No AAD
                plaintext.data(), data_size,
                ciphertext.data(), tag
            );
        }

        // 正式测试
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_aes_gcm_encrypt(
                &aes_ctx,
                iv.data(), IV_SIZE,
                nullptr, 0,
                plaintext.data(), data_size,
                ciphertext.data(), tag
            );
            kctsb_total += timer.stop();
        }

        kctsb_aes_clear(&aes_ctx);

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 加密性能
        double openssl_total = 0;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        // 预热
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr);
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(data_size));
            EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
        }

        // 正式测试
        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            int len = 0;
            timer.start();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr);
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(data_size));
            EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
            openssl_total += timer.stop();
        }

        EVP_CIPHER_CTX_free(ctx);

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        // 打印结果
        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "AES-256-GCM Encrypt " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "AES-256-GCM Encrypt " + size_name, "OpenSSL",
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// SHA-256 对比
// ============================================================================

void benchmark_sha256() {
    std::cout << "\n--- SHA-256 ---\n";
    benchmark::print_table_header();

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t hash_kctsb[32];
        uint8_t hash_openssl[32];

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sha256(data.data(), data_size, hash_kctsb);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sha256(data.data(), data_size, hash_kctsb);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 性能
        double openssl_total = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            unsigned int len = 0;
            EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            unsigned int len = 0;
            timer.start();
            EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
            openssl_total += timer.stop();
        }

        EVP_MD_CTX_free(ctx);

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "SHA-256 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "SHA-256 " + size_name, "OpenSSL",
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// SHA-512 对比
// ============================================================================

void benchmark_sha512() {
    std::cout << "\n--- SHA-512 ---\n";
    benchmark::print_table_header();

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t hash_kctsb[64];
        uint8_t hash_openssl[64];

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sha512(data.data(), data_size, hash_kctsb);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sha512(data.data(), data_size, hash_kctsb);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 性能
        double openssl_total = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            unsigned int len = 0;
            EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            unsigned int len = 0;
            timer.start();
            EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
            openssl_total += timer.stop();
        }

        EVP_MD_CTX_free(ctx);

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "SHA-512 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "SHA-512 " + size_name, "OpenSSL",
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// SHA3-256 对比
// ============================================================================

void benchmark_sha3_256() {
    std::cout << "\n--- SHA3-256 ---\n";
    benchmark::print_table_header();

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t hash_kctsb[32];
        uint8_t hash_openssl[32];

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_sha3_256(data.data(), data_size, hash_kctsb);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_sha3_256(data.data(), data_size, hash_kctsb);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 性能
        double openssl_total = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            unsigned int len = 0;
            EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            unsigned int len = 0;
            timer.start();
            EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
            openssl_total += timer.stop();
        }

        EVP_MD_CTX_free(ctx);

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        // 打印结果
        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "SHA3-256 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "SHA3-256 " + size_name, "OpenSSL",
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// ChaCha20-Poly1305 对比
// ============================================================================

void benchmark_chacha20_poly1305() {
    std::cout << "\n--- ChaCha20-Poly1305 ---\n";
    benchmark::print_table_header();

    constexpr size_t KEY_SIZE = 32;
    constexpr size_t NONCE_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;

    auto key = benchmark::generate_random_data(KEY_SIZE);
    auto nonce = benchmark::generate_random_data(NONCE_SIZE);

    for (size_t data_size : TEST_SIZES) {
        auto plaintext = benchmark::generate_random_data(data_size);
        std::vector<uint8_t> ciphertext(data_size);
        uint8_t tag[TAG_SIZE];

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_chacha20_poly1305_encrypt(
                key.data(), nonce.data(),
                nullptr, 0,
                plaintext.data(), data_size,
                ciphertext.data(), tag
            );
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_chacha20_poly1305_encrypt(
                key.data(), nonce.data(),
                nullptr, 0,
                plaintext.data(), data_size,
                ciphertext.data(), tag
            );
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 性能
        double openssl_total = 0;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data());
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(data_size));
            EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            int len = 0;
            timer.start();
            EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data());
            EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(data_size));
            EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
            openssl_total += timer.stop();
        }

        EVP_CIPHER_CTX_free(ctx);

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        // 打印结果
        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "ChaCha20-Poly1305 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "ChaCha20-Poly1305 " + size_name, "OpenSSL",
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// BLAKE2b-256 对比
// ============================================================================

void benchmark_blake2b() {
    std::cout << "\n--- BLAKE2b-256 ---\n";
    benchmark::print_table_header();

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t hash_kctsb[32];
        uint8_t hash_openssl[32];

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_blake2b(data.data(), data_size, hash_kctsb, 32);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_blake2b(data.data(), data_size, hash_kctsb, 32);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 性能 (BLAKE2b256)
        double openssl_total = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            unsigned int len = 0;
            EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr);  // OpenSSL only has blake2b512
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            unsigned int len = 0;
            timer.start();
            EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr);
            EVP_DigestUpdate(ctx, data.data(), data_size);
            EVP_DigestFinal_ex(ctx, hash_openssl, &len);
            openssl_total += timer.stop();
        }

        EVP_MD_CTX_free(ctx);

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "BLAKE2b-256 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "BLAKE2b-512 " + size_name, "OpenSSL",  // OpenSSL uses 512-bit
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// HMAC-SHA256 对比
// ============================================================================

void benchmark_hmac_sha256() {
    std::cout << "\n--- HMAC-SHA256 ---\n";
    benchmark::print_table_header();

    constexpr size_t KEY_SIZE = 32;
    auto key = benchmark::generate_random_data(KEY_SIZE);

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t mac_kctsb[32];
        uint8_t mac_openssl[32];

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_hmac_sha256(key.data(), KEY_SIZE, data.data(), data_size, mac_kctsb);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_hmac_sha256(key.data(), KEY_SIZE, data.data(), data_size, mac_kctsb);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 性能
        double openssl_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            unsigned int len = 32;
            HMAC(EVP_sha256(), key.data(), KEY_SIZE, data.data(), data_size, mac_openssl, &len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            unsigned int len = 32;
            timer.start();
            HMAC(EVP_sha256(), key.data(), KEY_SIZE, data.data(), data_size, mac_openssl, &len);
            openssl_total += timer.stop();
        }

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "HMAC-SHA256 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "HMAC-SHA256 " + size_name, "OpenSSL",
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

// ============================================================================
// HMAC-SHA512 对比
// ============================================================================

void benchmark_hmac_sha512() {
    std::cout << "\n--- HMAC-SHA512 ---\n";
    benchmark::print_table_header();

    constexpr size_t KEY_SIZE = 64;
    auto key = benchmark::generate_random_data(KEY_SIZE);

    for (size_t data_size : TEST_SIZES) {
        auto data = benchmark::generate_random_data(data_size);
        uint8_t mac_kctsb[64];
        uint8_t mac_openssl[64];

        // kctsb 性能
        benchmark::Timer timer;
        double kctsb_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_hmac_sha512(key.data(), KEY_SIZE, data.data(), data_size, mac_kctsb);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_hmac_sha512(key.data(), KEY_SIZE, data.data(), data_size, mac_kctsb);
            kctsb_total += timer.stop();
        }

        double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
        double kctsb_throughput = benchmark::calculate_throughput(data_size, kctsb_avg);

        // OpenSSL 性能
        double openssl_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            unsigned int len = 64;
            HMAC(EVP_sha512(), key.data(), KEY_SIZE, data.data(), data_size, mac_openssl, &len);
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            unsigned int len = 64;
            timer.start();
            HMAC(EVP_sha512(), key.data(), KEY_SIZE, data.data(), data_size, mac_openssl, &len);
            openssl_total += timer.stop();
        }

        double openssl_avg = openssl_total / benchmark::BENCHMARK_ITERATIONS;
        double openssl_throughput = benchmark::calculate_throughput(data_size, openssl_avg);

        std::string size_name = (data_size == benchmark::SIZE_1KB) ? "1KB" :
                               (data_size == benchmark::SIZE_1MB) ? "1MB" : "10MB";

        benchmark::Result kctsb_result{
            "HMAC-SHA512 " + size_name, "kctsb",
            kctsb_avg, kctsb_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };
        benchmark::Result openssl_result{
            "HMAC-SHA512 " + size_name, "OpenSSL",
            openssl_avg, openssl_throughput, data_size, benchmark::BENCHMARK_ITERATIONS
        };

        benchmark::print_result(kctsb_result);
        benchmark::print_result(openssl_result);

        double ratio = kctsb_avg / openssl_avg;
        std::cout << "  Ratio: " << std::fixed << std::setprecision(2) << ratio << "x ("
                  << benchmark::get_status(ratio) << ")\n\n";
    }
}

} // anonymous namespace

// ============================================================================
// 导出函数
// ============================================================================

void run_openssl_benchmarks() {
    std::cout << "\nRunning OpenSSL 3.6.0 comparison benchmarks...\n";
    std::cout << "Testing: AES-256-GCM, SHA-256, SHA-512, SHA3-256, BLAKE2b, ChaCha20-Poly1305, HMAC-SHA256, HMAC-SHA512\n";

    benchmark_aes_256_gcm();
    benchmark_sha256();
    benchmark_sha512();
    benchmark_sha3_256();
    benchmark_blake2b();
    benchmark_chacha20_poly1305();
    benchmark_hmac_sha256();
    benchmark_hmac_sha512();

    std::cout << "\nOpenSSL benchmarks complete.\n";
}

#endif // BENCHMARK_HAS_OPENSSL
