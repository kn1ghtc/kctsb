/**
 * @file benchmark_aes_gcm.cpp
 * @brief AES-256-GCM Performance Benchmark: kctsb vs OpenSSL
 *
 * Benchmarks authenticated encryption/decryption throughput for:
 * - Various data sizes (1KB, 1MB, 10MB)
 * - Encryption and decryption operations separately
 * - Authentication tag verification
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
#include <stdexcept>
#include <limits>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// kctsb headers (conditional)
#ifdef KCTSB_HAS_AES_GCM
#include "kctsb/crypto/aes.h"
#endif

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 10;
constexpr size_t BENCHMARK_ITERATIONS = 100;
constexpr size_t AES_256_KEY_SIZE = 32;  // AES-256
constexpr size_t AES_128_KEY_SIZE = 16;  // AES-128
constexpr size_t AES_KEY_SIZE = AES_256_KEY_SIZE;  // Default to AES-256
constexpr size_t GCM_IV_SIZE = 12;
constexpr size_t GCM_TAG_SIZE = 16;

// Test data sizes
const std::vector<size_t> TEST_SIZES = {
    1024,           // 1 KB
    1024 * 1024,    // 1 MB
    10 * 1024 * 1024 // 10 MB
};

/**
 * @brief High-resolution timer
 */
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
static double calculate_throughput(double bytes, double ms) {
    return (bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
}

/**
 * @brief OpenSSL AES-128-GCM encryption benchmark
 */
static double benchmark_openssl_aes128_gcm_encrypt(
    const std::vector<uint8_t>& plaintext,
    const uint8_t* key,
    const uint8_t* iv,
    std::vector<uint8_t>& ciphertext,
    uint8_t* tag
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1.0;

    ciphertext.resize(plaintext.size() + GCM_TAG_SIZE);
    int len = 0;
    std::size_t ciphertext_len = 0;

    auto start = Clock::now();

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                      static_cast<int>(plaintext.size()));
    if (len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1.0;
    }
    ciphertext_len = static_cast<std::size_t>(len);
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    if (len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1.0;
    }
    ciphertext_len += static_cast<std::size_t>(len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag);

    auto end = Clock::now();
    Duration elapsed = end - start;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return elapsed.count();
}

/**
 * @brief OpenSSL AES-128-GCM decryption benchmark
 */
static double benchmark_openssl_aes128_gcm_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* tag,
    std::vector<uint8_t>& plaintext
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1.0;

    plaintext.resize(ciphertext.size());
    int len = 0;
    std::size_t plaintext_len = 0;

    auto start = Clock::now();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                      static_cast<int>(ciphertext.size()));
    if (len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1.0;
    }
    plaintext_len = static_cast<std::size_t>(len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                        const_cast<uint8_t*>(tag));
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

    auto end = Clock::now();
    Duration elapsed = end - start;

    if (ret > 0) {
        if (len < 0) {
            EVP_CIPHER_CTX_free(ctx);
            return -1.0;
        }
        plaintext_len += static_cast<std::size_t>(len);
        plaintext.resize(plaintext_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    return elapsed.count();
}

/**
 * @brief OpenSSL AES-256-GCM encryption benchmark
 */
static double benchmark_openssl_aes_gcm_encrypt(
    const std::vector<uint8_t>& plaintext,
    const uint8_t* key,
    const uint8_t* iv,
    std::vector<uint8_t>& ciphertext,
    uint8_t* tag
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1.0;

    ciphertext.resize(plaintext.size() + GCM_TAG_SIZE);
    int len = 0;
    std::size_t ciphertext_len = 0;

    auto start = Clock::now();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                      static_cast<int>(plaintext.size()));
    if (len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1.0;
    }
    ciphertext_len = static_cast<std::size_t>(len);
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    if (len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1.0;
    }
    ciphertext_len += static_cast<std::size_t>(len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag);

    auto end = Clock::now();
    Duration elapsed = end - start;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return elapsed.count();
}

/**
 * @brief OpenSSL AES-256-GCM decryption benchmark
 */
static double benchmark_openssl_aes_gcm_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* tag,
    std::vector<uint8_t>& plaintext
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1.0;

    plaintext.resize(ciphertext.size());
    int len = 0;
    std::size_t plaintext_len = 0;

    auto start = Clock::now();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                      static_cast<int>(ciphertext.size()));
    if (len < 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1.0;
    }
    plaintext_len = static_cast<std::size_t>(len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                        const_cast<uint8_t*>(tag));
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

    auto end = Clock::now();
    Duration elapsed = end - start;

    if (ret > 0) {
        if (len < 0) {
            EVP_CIPHER_CTX_free(ctx);
            return -1.0;
        }
        plaintext_len += static_cast<std::size_t>(len);
        plaintext.resize(plaintext_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    return elapsed.count();
}

/**
 * @brief Run benchmark iterations and collect statistics
 * @return Throughput in MB/s for ratio calculation
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

    // Calculate statistics
    double avg = std::accumulate(times.begin(), times.end(), 0.0) /
                 static_cast<double>(times.size());
    double throughput = calculate_throughput(static_cast<double>(data_size), avg);

    // Print result
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

/**
 * @brief Main AES-GCM benchmark function
 */
void benchmark_aes_gcm() {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  AES-256-GCM Benchmark" << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    // Generate key and IV
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    generate_random(key, AES_KEY_SIZE);
    generate_random(iv, GCM_IV_SIZE);

    for (size_t data_size : TEST_SIZES) {
        std::string size_str;
        if (data_size >= 1024 * 1024) {
            size_str = std::to_string(data_size / (1024 * 1024)) + " MB";
        } else {
            size_str = std::to_string(data_size / 1024) + " KB";
        }

        std::cout << "\n--- Data Size: " << size_str << " ---" << std::endl;
        std::cout << std::left << std::setw(25) << "Operation"
                  << std::setw(15) << "Implementation"
                  << std::right << std::setw(13) << "Throughput"
                  << std::setw(10) << "Avg Time"
                  << std::endl;
        std::cout << std::string(63, '-') << std::endl;

        // Generate test data
        std::vector<uint8_t> plaintext(data_size);
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;
        generate_random(plaintext.data(), data_size);

        // Precompute kctsb reference ciphertext/tag for decrypt benchmarks
        std::vector<uint8_t> kctsb_ciphertext(data_size);
        uint8_t kctsb_tag[GCM_TAG_SIZE] = {0};
        kctsb_aes_ctx_t kctsb_ctx;
        if (kctsb_aes_init(&kctsb_ctx, key, AES_KEY_SIZE) != KCTSB_SUCCESS) {
            throw std::runtime_error("kctsb AES init failed");
        }
        if (kctsb_aes_gcm_encrypt(&kctsb_ctx, iv, GCM_IV_SIZE,
                                  nullptr, 0,
                                  plaintext.data(), data_size,
                                  kctsb_ciphertext.data(), kctsb_tag) != KCTSB_SUCCESS) {
            throw std::runtime_error("kctsb AES-GCM encrypt precompute failed");
        }

        double ssl_enc_tp, ssl_dec_tp, kc_enc_tp, kc_dec_tp;

        // OpenSSL Encryption
        ssl_enc_tp = run_benchmark_iterations(
            "AES-256-GCM Encrypt", "OpenSSL", data_size,
            [&]() {
                return benchmark_openssl_aes_gcm_encrypt(
                    plaintext, key, iv, ciphertext, tag);
            }
        );

#ifdef KCTSB_HAS_AES_GCM
        // kctsb Encryption
        kc_enc_tp = run_benchmark_iterations(
            "AES-256-GCM Encrypt", "kctsb", data_size,
            [&]() {
                if (ciphertext.size() != data_size) {
                    ciphertext.resize(data_size);
                }
                auto start = Clock::now();
                auto status = kctsb_aes_gcm_encrypt(&kctsb_ctx, iv, GCM_IV_SIZE,
                                                    nullptr, 0,
                                                    plaintext.data(), data_size,
                                                    ciphertext.data(), tag);
                auto end = Clock::now();
                if (status != KCTSB_SUCCESS) {
                    return std::numeric_limits<double>::infinity();
                }
                Duration elapsed = end - start;
                return elapsed.count();
            }
        );
        print_ratio(kc_enc_tp, ssl_enc_tp);
#else
        std::cout << "AES-256-GCM Encrypt      kctsb          (not compiled)" << std::endl;
#endif

        // OpenSSL Decryption
        ssl_dec_tp = run_benchmark_iterations(
            "AES-256-GCM Decrypt", "OpenSSL", data_size,
            [&]() {
                return benchmark_openssl_aes_gcm_decrypt(
                    ciphertext, key, iv, tag, decrypted);
            }
        );

#ifdef KCTSB_HAS_AES_GCM
        // kctsb Decryption - using actual implementation
        std::vector<uint8_t> kctsb_decrypted(data_size);
        kc_dec_tp = run_benchmark_iterations(
            "AES-256-GCM Decrypt", "kctsb", data_size,
            [&]() {
                if (decrypted.size() != data_size) {
                    decrypted.resize(data_size);
                }
                auto start = Clock::now();
                auto status = kctsb_aes_gcm_decrypt(&kctsb_ctx, iv, GCM_IV_SIZE,
                                                    nullptr, 0,
                                                    kctsb_ciphertext.data(), data_size,
                                                    kctsb_tag,
                                                    decrypted.data());
                auto end = Clock::now();
                if (status != KCTSB_SUCCESS) {
                    return std::numeric_limits<double>::infinity();
                }
                Duration elapsed = end - start;
                return elapsed.count();
            }
        );
        print_ratio(kc_dec_tp, ssl_dec_tp);
#else
        std::cout << "AES-256-GCM Decrypt      kctsb          (not compiled)" << std::endl;
#endif
    }
}

/**
 * @brief AES-128-GCM Benchmark function
 */
void benchmark_aes_128_gcm() {
    std::cout << "\n" << std::string(70, '=') << std::endl;
    std::cout << "  AES-128-GCM Benchmark" << std::endl;
    std::cout << std::string(70, '=') << std::endl;

    // Generate key and IV
    uint8_t key128[AES_128_KEY_SIZE];
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    generate_random(key128, AES_128_KEY_SIZE);
    generate_random(iv, GCM_IV_SIZE);

    for (size_t data_size : TEST_SIZES) {
        std::string size_str;
        if (data_size >= 1024 * 1024) {
            size_str = std::to_string(data_size / (1024 * 1024)) + " MB";
        } else {
            size_str = std::to_string(data_size / 1024) + " KB";
        }

        std::cout << "\n--- Data Size: " << size_str << " ---" << std::endl;
        std::cout << std::left << std::setw(25) << "Operation"
                  << std::setw(15) << "Implementation"
                  << std::right << std::setw(13) << "Throughput"
                  << std::setw(10) << "Avg Time"
                  << std::setw(13) << "Ratio"
                  << std::endl;
        std::cout << std::string(76, '-') << std::endl;

        // Generate test data
        std::vector<uint8_t> plaintext(data_size);
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;
        generate_random(plaintext.data(), data_size);

        // Throughput variables for ratio calculation
        double ssl_enc_tp = 0.0, ssl_dec_tp = 0.0;
        double kc_enc_tp = 0.0, kc_dec_tp = 0.0;

        // OpenSSL AES-128 Encryption
        ssl_enc_tp = run_benchmark_iterations(
            "AES-128-GCM Encrypt", "OpenSSL", data_size,
            [&]() {
                return benchmark_openssl_aes128_gcm_encrypt(
                    plaintext, key128, iv, ciphertext, tag);
            }
        );

        // OpenSSL AES-128 Decryption
        ssl_dec_tp = run_benchmark_iterations(
            "AES-128-GCM Decrypt", "OpenSSL", data_size,
            [&]() {
                return benchmark_openssl_aes128_gcm_decrypt(
                    ciphertext, key128, iv, tag, decrypted);
            }
        );

#if defined(KCTSB_HAS_AES_GCM) && defined(KCTSB_HAS_AES_128)
        // kctsb AES-128 Encryption
        kctsb_aes_ctx_t kctsb_ctx128;
        if (kctsb_aes_init(&kctsb_ctx128, key128, AES_128_KEY_SIZE) == KCTSB_SUCCESS) {
            std::vector<uint8_t> kctsb_ct(data_size);
            uint8_t kctsb_tag[GCM_TAG_SIZE];

            kc_enc_tp = run_benchmark_iterations(
                "AES-128-GCM Encrypt", "kctsb", data_size,
                [&]() {
                    auto start = Clock::now();
                    auto status = kctsb_aes_gcm_encrypt(&kctsb_ctx128, iv, GCM_IV_SIZE,
                                                        nullptr, 0,
                                                        plaintext.data(), data_size,
                                                        kctsb_ct.data(), kctsb_tag);
                    auto end = Clock::now();
                    if (status != KCTSB_SUCCESS) {
                        return std::numeric_limits<double>::infinity();
                    }
                    Duration elapsed = end - start;
                    return elapsed.count();
                }
            );
            print_ratio(kc_enc_tp, ssl_enc_tp);

            // kctsb AES-128 Decryption
            std::vector<uint8_t> kctsb_pt(data_size);
            kc_dec_tp = run_benchmark_iterations(
                "AES-128-GCM Decrypt", "kctsb", data_size,
                [&]() {
                    auto start = Clock::now();
                    auto status = kctsb_aes_gcm_decrypt(&kctsb_ctx128, iv, GCM_IV_SIZE,
                                                        nullptr, 0,
                                                        kctsb_ct.data(), data_size,
                                                        kctsb_tag,
                                                        kctsb_pt.data());
                    auto end = Clock::now();
                    if (status != KCTSB_SUCCESS) {
                        return std::numeric_limits<double>::infinity();
                    }
                    Duration elapsed = end - start;
                    return elapsed.count();
                }
            );
            print_ratio(kc_dec_tp, ssl_dec_tp);
        } else {
            std::cout << "AES-128-GCM Encrypt      kctsb          (init failed)" << std::endl;
            std::cout << "AES-128-GCM Decrypt      kctsb          (init failed)" << std::endl;
        }
#else
        std::cout << "AES-128-GCM Encrypt      kctsb          (not compiled)" << std::endl;
        std::cout << "AES-128-GCM Decrypt      kctsb          (not compiled)" << std::endl;
#endif
    }
}
