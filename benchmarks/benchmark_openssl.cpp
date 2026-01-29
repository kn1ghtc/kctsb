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
 *   - RSA-PSS (SHA-256): RSA 签名/验签 (3072/4096 bits)
 *   - RSA-OAEP (SHA-256, MGF1-SHA256): RSA 加密/解密 (3072/4096 bits)
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

// ============================================================================
// RSA-PSS Signature (SHA-256, 3072/4096 bits) 对比
// ============================================================================

/**
 * @brief RSA-PSS 签名/验签性能测试
 * @details 对比 kctsb 和 OpenSSL 的 RSA-PSS (SHA-256) 性能
 *          测试密钥长度: 3072-bit 和 4096-bit
 */
void benchmark_rsa_pss() {
    std::cout << "\n--- RSA-PSS (SHA-256) Signature ---\n";
    std::cout << "Generating RSA keypairs (3072/4096-bit)...\n";

    constexpr int RSA_ITERATIONS = 100;  // RSA 操作较慢，使用较少迭代
    const std::vector<int> KEY_SIZES = {3072, 4096};

    for (int bits : KEY_SIZES) {
        std::cout << "\n-- RSA-" << bits << " --\n";
        benchmark::print_table_header();

        // 生成 kctsb RSA 密钥对
        kctsb_rsa_public_key_t kctsb_pub;
        kctsb_rsa_private_key_t kctsb_priv;
        if (kctsb_rsa_generate_keypair(bits, &kctsb_pub, &kctsb_priv) != KCTSB_SUCCESS) {
            std::cerr << "Failed to generate kctsb RSA-" << bits << " keypair\n";
            continue;
        }

        // 生成 OpenSSL RSA 密钥对
        EVP_PKEY_CTX* gen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY* openssl_key = nullptr;
        EVP_PKEY_keygen_init(gen_ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(gen_ctx, bits);
        EVP_PKEY_keygen(gen_ctx, &openssl_key);
        EVP_PKEY_CTX_free(gen_ctx);

        if (!openssl_key) {
            std::cerr << "Failed to generate OpenSSL RSA-" << bits << " keypair\n";
            continue;
        }

        // 测试消息和哈希
        auto message = benchmark::generate_random_data(256);
        uint8_t hash[32];
        kctsb_sha256(message.data(), message.size(), hash);

        size_t modulus_len = bits / 8;
        std::vector<uint8_t> signature(modulus_len);
        size_t sig_len = modulus_len;

        // ---- 签名性能 ----
        benchmark::Timer timer;
        double kctsb_sign_total = 0;
        double openssl_sign_total = 0;

        // kctsb 签名预热
        for (size_t i = 0; i < 5; ++i) {
            sig_len = modulus_len;
            kctsb_rsa_pss_sign_sha256(&kctsb_priv, hash, 32, nullptr, 0,
                                       signature.data(), &sig_len);
        }

        // kctsb 签名测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            sig_len = modulus_len;
            timer.start();
            kctsb_rsa_pss_sign_sha256(&kctsb_priv, hash, 32, nullptr, 0,
                                       signature.data(), &sig_len);
            kctsb_sign_total += timer.stop();
        }

        double kctsb_sign_avg = kctsb_sign_total / RSA_ITERATIONS;

        // OpenSSL PSS 签名预热
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        std::vector<uint8_t> openssl_sig(modulus_len);

        for (size_t i = 0; i < 5; ++i) {
            sig_len = modulus_len;
            EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, openssl_key);
            EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(md_ctx), RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_get_pkey_ctx(md_ctx), 32);
            EVP_DigestSign(md_ctx, openssl_sig.data(), &sig_len, message.data(), message.size());
        }

        // OpenSSL 签名测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            sig_len = modulus_len;
            timer.start();
            EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, openssl_key);
            EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(md_ctx), RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_get_pkey_ctx(md_ctx), 32);
            EVP_DigestSign(md_ctx, openssl_sig.data(), &sig_len, message.data(), message.size());
            openssl_sign_total += timer.stop();
        }

        double openssl_sign_avg = openssl_sign_total / RSA_ITERATIONS;

        // 打印签名结果
        benchmark::Result kctsb_sign_result{
            "RSA-" + std::to_string(bits) + " PSS Sign", "kctsb",
            kctsb_sign_avg, 0, 0, RSA_ITERATIONS
        };
        benchmark::Result openssl_sign_result{
            "RSA-" + std::to_string(bits) + " PSS Sign", "OpenSSL",
            openssl_sign_avg, 0, 0, RSA_ITERATIONS
        };

        benchmark::print_result(kctsb_sign_result);
        benchmark::print_result(openssl_sign_result);

        double sign_ratio = kctsb_sign_avg / openssl_sign_avg;
        std::cout << "  Sign Ratio: " << std::fixed << std::setprecision(2) << sign_ratio << "x ("
                  << benchmark::get_status(sign_ratio) << ")\n\n";

        // ---- 验签性能 ----
        double kctsb_verify_total = 0;
        double openssl_verify_total = 0;

        // 生成有效签名用于验证
        sig_len = modulus_len;
        kctsb_rsa_pss_sign_sha256(&kctsb_priv, hash, 32, nullptr, 0,
                                   signature.data(), &sig_len);

        // kctsb 验签预热
        for (size_t i = 0; i < 5; ++i) {
            kctsb_rsa_pss_verify_sha256(&kctsb_pub, hash, 32,
                                         signature.data(), sig_len);
        }

        // kctsb 验签测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            timer.start();
            kctsb_rsa_pss_verify_sha256(&kctsb_pub, hash, 32,
                                         signature.data(), sig_len);
            kctsb_verify_total += timer.stop();
        }

        double kctsb_verify_avg = kctsb_verify_total / RSA_ITERATIONS;

        // OpenSSL 验签 (使用 OpenSSL 生成的签名)
        sig_len = modulus_len;
        EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, openssl_key);
        EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(md_ctx), RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_get_pkey_ctx(md_ctx), 32);
        EVP_DigestSign(md_ctx, openssl_sig.data(), &sig_len, message.data(), message.size());

        // OpenSSL 验签预热
        for (size_t i = 0; i < 5; ++i) {
            EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, openssl_key);
            EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(md_ctx), RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_get_pkey_ctx(md_ctx), 32);
            EVP_DigestVerify(md_ctx, openssl_sig.data(), sig_len, message.data(), message.size());
        }

        // OpenSSL 验签测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            timer.start();
            EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, openssl_key);
            EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(md_ctx), RSA_PKCS1_PSS_PADDING);
            EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_get_pkey_ctx(md_ctx), 32);
            EVP_DigestVerify(md_ctx, openssl_sig.data(), sig_len, message.data(), message.size());
            openssl_verify_total += timer.stop();
        }

        double openssl_verify_avg = openssl_verify_total / RSA_ITERATIONS;

        // 打印验签结果
        benchmark::Result kctsb_verify_result{
            "RSA-" + std::to_string(bits) + " PSS Verify", "kctsb",
            kctsb_verify_avg, 0, 0, RSA_ITERATIONS
        };
        benchmark::Result openssl_verify_result{
            "RSA-" + std::to_string(bits) + " PSS Verify", "OpenSSL",
            openssl_verify_avg, 0, 0, RSA_ITERATIONS
        };

        benchmark::print_result(kctsb_verify_result);
        benchmark::print_result(openssl_verify_result);

        double verify_ratio = kctsb_verify_avg / openssl_verify_avg;
        std::cout << "  Verify Ratio: " << std::fixed << std::setprecision(2) << verify_ratio << "x ("
                  << benchmark::get_status(verify_ratio) << ")\n\n";

        // 清理
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(openssl_key);
    }
}

// ============================================================================
// RSA-OAEP Encryption (SHA-256, MGF1-SHA256, 3072/4096 bits) 对比
// ============================================================================

/**
 * @brief RSA-OAEP 加解密性能测试
 * @details 对比 kctsb 和 OpenSSL 的 RSAES-OAEP (SHA-256, MGF1-SHA256) 性能
 *          测试密钥长度: 3072-bit 和 4096-bit
 */
void benchmark_rsa_oaep() {
    std::cout << "\n--- RSA-OAEP (SHA-256, MGF1-SHA256) Encryption ---\n";
    std::cout << "Using pre-generated keypairs...\n";

    constexpr int RSA_ITERATIONS = 100;
    const std::vector<int> KEY_SIZES = {3072, 4096};

    for (int bits : KEY_SIZES) {
        std::cout << "\n-- RSA-" << bits << " OAEP --\n";
        benchmark::print_table_header();

        size_t modulus_len = bits / 8;
        // OAEP 最大明文长度 = modulus_len - 2*hash_len - 2
        // 对于 SHA-256: max_len = modulus_len - 66
        size_t max_plaintext_len = modulus_len - 66;
        size_t test_len = std::min(max_plaintext_len, (size_t)190);  // 使用 190 字节测试

        // 生成 kctsb RSA 密钥对
        kctsb_rsa_public_key_t kctsb_pub;
        kctsb_rsa_private_key_t kctsb_priv;
        if (kctsb_rsa_generate_keypair(bits, &kctsb_pub, &kctsb_priv) != KCTSB_SUCCESS) {
            std::cerr << "Failed to generate kctsb RSA-" << bits << " keypair\n";
            continue;
        }

        // 生成 OpenSSL RSA 密钥对
        EVP_PKEY_CTX* gen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY* openssl_key = nullptr;
        EVP_PKEY_keygen_init(gen_ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(gen_ctx, bits);
        EVP_PKEY_keygen(gen_ctx, &openssl_key);
        EVP_PKEY_CTX_free(gen_ctx);

        if (!openssl_key) {
            std::cerr << "Failed to generate OpenSSL RSA-" << bits << " keypair\n";
            continue;
        }

        // 测试明文
        auto plaintext = benchmark::generate_random_data(test_len);
        std::vector<uint8_t> ciphertext(modulus_len);
        std::vector<uint8_t> decrypted(test_len);
        size_t ct_len = modulus_len;
        size_t dec_len = test_len;

        // ---- 加密性能 ----
        benchmark::Timer timer;
        double kctsb_enc_total = 0;
        double openssl_enc_total = 0;

        // kctsb 加密预热
        for (size_t i = 0; i < 5; ++i) {
            ct_len = modulus_len;
            kctsb_rsa_oaep_encrypt_sha256(&kctsb_pub, plaintext.data(), test_len,
                                           nullptr, 0, ciphertext.data(), &ct_len);
        }

        // kctsb 加密测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            ct_len = modulus_len;
            timer.start();
            kctsb_rsa_oaep_encrypt_sha256(&kctsb_pub, plaintext.data(), test_len,
                                           nullptr, 0, ciphertext.data(), &ct_len);
            kctsb_enc_total += timer.stop();
        }

        double kctsb_enc_avg = kctsb_enc_total / RSA_ITERATIONS;

        // OpenSSL OAEP 加密预热
        EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(openssl_key, nullptr);
        EVP_PKEY_encrypt_init(enc_ctx);
        EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256());
        EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, EVP_sha256());

        std::vector<uint8_t> openssl_ct(modulus_len);

        for (size_t i = 0; i < 5; ++i) {
            ct_len = modulus_len;
            EVP_PKEY_encrypt(enc_ctx, openssl_ct.data(), &ct_len, plaintext.data(), test_len);
        }

        // OpenSSL 加密测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            ct_len = modulus_len;
            timer.start();
            EVP_PKEY_encrypt(enc_ctx, openssl_ct.data(), &ct_len, plaintext.data(), test_len);
            openssl_enc_total += timer.stop();
        }

        double openssl_enc_avg = openssl_enc_total / RSA_ITERATIONS;

        EVP_PKEY_CTX_free(enc_ctx);

        // 打印加密结果
        benchmark::Result kctsb_enc_result{
            "RSA-" + std::to_string(bits) + " OAEP Encrypt", "kctsb",
            kctsb_enc_avg, 0, test_len, RSA_ITERATIONS
        };
        benchmark::Result openssl_enc_result{
            "RSA-" + std::to_string(bits) + " OAEP Encrypt", "OpenSSL",
            openssl_enc_avg, 0, test_len, RSA_ITERATIONS
        };

        benchmark::print_result(kctsb_enc_result);
        benchmark::print_result(openssl_enc_result);

        double enc_ratio = kctsb_enc_avg / openssl_enc_avg;
        std::cout << "  Encrypt Ratio: " << std::fixed << std::setprecision(2) << enc_ratio << "x ("
                  << benchmark::get_status(enc_ratio) << ")\n\n";

        // ---- 解密性能 ----
        double kctsb_dec_total = 0;
        double openssl_dec_total = 0;

        // kctsb 解密预热 (使用 kctsb 加密的密文)
        ct_len = modulus_len;
        kctsb_rsa_oaep_encrypt_sha256(&kctsb_pub, plaintext.data(), test_len,
                                       nullptr, 0, ciphertext.data(), &ct_len);

        for (size_t i = 0; i < 5; ++i) {
            dec_len = test_len;
            kctsb_rsa_oaep_decrypt_sha256(&kctsb_priv, ciphertext.data(), ct_len,
                                           nullptr, 0, decrypted.data(), &dec_len);
        }

        // kctsb 解密测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            dec_len = test_len;
            timer.start();
            kctsb_rsa_oaep_decrypt_sha256(&kctsb_priv, ciphertext.data(), ct_len,
                                           nullptr, 0, decrypted.data(), &dec_len);
            kctsb_dec_total += timer.stop();
        }

        double kctsb_dec_avg = kctsb_dec_total / RSA_ITERATIONS;

        // OpenSSL 解密预热
        EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(openssl_key, nullptr);
        EVP_PKEY_decrypt_init(dec_ctx);
        EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(dec_ctx, EVP_sha256());
        EVP_PKEY_CTX_set_rsa_mgf1_md(dec_ctx, EVP_sha256());

        // OpenSSL 解密 (使用 OpenSSL 加密的密文)
        enc_ctx = EVP_PKEY_CTX_new(openssl_key, nullptr);
        EVP_PKEY_encrypt_init(enc_ctx);
        EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING);
        EVP_PKEY_CTX_set_rsa_oaep_md(enc_ctx, EVP_sha256());
        EVP_PKEY_CTX_set_rsa_mgf1_md(enc_ctx, EVP_sha256());
        ct_len = modulus_len;
        EVP_PKEY_encrypt(enc_ctx, openssl_ct.data(), &ct_len, plaintext.data(), test_len);
        EVP_PKEY_CTX_free(enc_ctx);

        for (size_t i = 0; i < 5; ++i) {
            dec_len = test_len;
            EVP_PKEY_decrypt(dec_ctx, decrypted.data(), &dec_len, openssl_ct.data(), ct_len);
        }

        // OpenSSL 解密测试
        for (size_t i = 0; i < RSA_ITERATIONS; ++i) {
            dec_len = test_len;
            timer.start();
            EVP_PKEY_decrypt(dec_ctx, decrypted.data(), &dec_len, openssl_ct.data(), ct_len);
            openssl_dec_total += timer.stop();
        }

        double openssl_dec_avg = openssl_dec_total / RSA_ITERATIONS;

        EVP_PKEY_CTX_free(dec_ctx);

        // 打印解密结果
        benchmark::Result kctsb_dec_result{
            "RSA-" + std::to_string(bits) + " OAEP Decrypt", "kctsb",
            kctsb_dec_avg, 0, test_len, RSA_ITERATIONS
        };
        benchmark::Result openssl_dec_result{
            "RSA-" + std::to_string(bits) + " OAEP Decrypt", "OpenSSL",
            openssl_dec_avg, 0, test_len, RSA_ITERATIONS
        };

        benchmark::print_result(kctsb_dec_result);
        benchmark::print_result(openssl_dec_result);

        double dec_ratio = kctsb_dec_avg / openssl_dec_avg;
        std::cout << "  Decrypt Ratio: " << std::fixed << std::setprecision(2) << dec_ratio << "x ("
                  << benchmark::get_status(dec_ratio) << ")\n\n";

        // 清理
        EVP_PKEY_free(openssl_key);
    }
}

} // anonymous namespace

// ============================================================================
// 导出函数
// ============================================================================

void run_openssl_benchmarks() {
    std::cout << "\nRunning OpenSSL 3.6.0 comparison benchmarks...\n";
    std::cout << "Testing: AES-256-GCM, SHA-256, SHA-512, SHA3-256, BLAKE2b, ChaCha20-Poly1305, "
              << "HMAC-SHA256, HMAC-SHA512, RSA-PSS, RSA-OAEP\n";

    benchmark_aes_256_gcm();
    benchmark_sha256();
    benchmark_sha512();
    benchmark_sha3_256();
    benchmark_blake2b();
    benchmark_chacha20_poly1305();
    benchmark_hmac_sha256();
    benchmark_hmac_sha512();
    benchmark_rsa_pss();
    benchmark_rsa_oaep();

    std::cout << "\nOpenSSL benchmarks complete.\n";
}

#endif // BENCHMARK_HAS_OPENSSL
