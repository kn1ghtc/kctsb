/**
 * @file benchmark_sm.cpp
 * @brief SM Algorithm Performance Benchmark: kctsb vs OpenSSL
 *
 * Benchmarks Chinese National Standard cryptographic algorithms:
 * - SM2: Key generation, Sign/Verify
 * - SM3: Hash computation throughput
 * - SM4: Block cipher encryption/decryption
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
#include <openssl/err.h>

// kctsb SM headers (conditional)
#ifdef KCTSB_HAS_SM2
#include "kctsb/crypto/sm2.h"
#endif

#ifdef KCTSB_HAS_SM3
#include "kctsb/crypto/sm3.h"
#endif

#ifdef KCTSB_HAS_SM4
#include "kctsb/crypto/sm4.h"
#endif

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 5;
constexpr size_t BENCHMARK_ITERATIONS = 100;
constexpr size_t HASH_SIZE = 32;

// Test data sizes for hash/cipher
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
static double calculate_throughput(size_t bytes, double ms) {
    return (bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
}

/**
 * @brief Run benchmark and collect statistics
 */
static void run_benchmark(
    const std::string& name,
    const std::string& impl,
    std::function<double()> benchmark_func,
    bool show_throughput = false,
    size_t data_size = 0
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
    double avg = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    double min_val = *std::min_element(times.begin(), times.end());

    // Print result
    std::cout << std::left << std::setw(25) << name
              << std::setw(10) << impl
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(12) << avg << " ms"
              << std::setw(12) << min_val << " ms";

    if (show_throughput && data_size > 0) {
        double throughput = calculate_throughput(data_size, avg);
        std::cout << std::setw(12) << std::setprecision(2) << throughput << " MB/s";
    }
    std::cout << std::endl;
}

/**
 * @brief Print section header
 */
static void print_header(const std::string& title) {
    std::cout << "\n  " << title << std::endl;
    std::cout << std::string(75, '-') << std::endl;
    std::cout << std::left << std::setw(25) << "Operation"
              << std::setw(10) << "Impl"
              << std::right << std::setw(15) << "Avg"
              << std::setw(12) << "Min"
              << std::setw(15) << "Throughput"
              << std::endl;
    std::cout << std::string(75, '-') << std::endl;
}

// ============================================================================
// SM2 Benchmarks
// ============================================================================

/**
 * @brief SM2 benchmark suite
 */
void benchmark_sm2() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  SM2 Benchmark (Chinese National Standard)" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

#ifdef KCTSB_HAS_SM2
    print_header("SM2 Operations");

    // Test message
    uint8_t message[64];
    generate_random(message, sizeof(message));
    const uint8_t user_id[] = "1234567812345678";
    size_t user_id_len = 16;

    // ========================================================================
    // Key Generation
    // ========================================================================
    run_benchmark(
        "SM2 Key Generation",
        "kctsb",
        [&]() {
            kctsb_sm2_keypair_t keypair;
            auto start = Clock::now();
            auto status = kctsb_sm2_generate_keypair(&keypair);
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // Generate persistent keypair for sign/verify benchmarks
    kctsb_sm2_keypair_t keypair;
    kctsb_sm2_generate_keypair(&keypair);

    // ========================================================================
    // Sign
    // ========================================================================
    run_benchmark(
        "SM2 Sign",
        "kctsb",
        [&]() {
            kctsb_sm2_signature_t sig;
            auto start = Clock::now();
            auto status = kctsb_sm2_sign(
                keypair.private_key, keypair.public_key,
                user_id, user_id_len,
                message, sizeof(message),
                &sig
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // Generate a signature for verify benchmark
    kctsb_sm2_signature_t signature;
    kctsb_sm2_sign(
        keypair.private_key, keypair.public_key,
        user_id, user_id_len,
        message, sizeof(message),
        &signature
    );

    // ========================================================================
    // Verify
    // ========================================================================
    run_benchmark(
        "SM2 Verify",
        "kctsb",
        [&]() {
            auto start = Clock::now();
            auto status = kctsb_sm2_verify(
                keypair.public_key,
                user_id, user_id_len,
                message, sizeof(message),
                &signature
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    std::cout << "\n  Note: OpenSSL 3.0+ supports SM2 via EVP interface.\n";
#else
    std::cout << "\n  SM2 benchmarks skipped (KCTSB_HAS_SM2 not defined)\n";
#endif
}

// ============================================================================
// SM3 Benchmarks
// ============================================================================

/**
 * @brief SM3 benchmark suite
 */
void benchmark_sm3() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  SM3 Hash Benchmark (Chinese National Standard)" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

#ifdef KCTSB_HAS_SM3
    for (size_t data_size : TEST_SIZES) {
        std::string size_str;
        if (data_size >= 1024 * 1024) {
            size_str = std::to_string(data_size / (1024 * 1024)) + " MB";
        } else {
            size_str = std::to_string(data_size / 1024) + " KB";
        }

        print_header("SM3 - Data Size: " + size_str);

        // Generate test data
        std::vector<uint8_t> data(data_size);
        generate_random(data.data(), data_size);
        uint8_t digest[32];

        // OpenSSL SM3 (if available)
        const EVP_MD* sm3_md = EVP_sm3();
        if (sm3_md) {
            run_benchmark(
                "SM3 Hash",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                    EVP_DigestInit_ex(ctx, sm3_md, nullptr);
                    EVP_DigestUpdate(ctx, data.data(), data_size);
                    unsigned int digest_len = 32;
                    EVP_DigestFinal_ex(ctx, digest, &digest_len);
                    EVP_MD_CTX_free(ctx);
                    auto end = Clock::now();
                    Duration elapsed = end - start;
                    return elapsed.count();
                },
                true, data_size
            );
        } else {
            std::cout << std::left << std::setw(25) << "SM3 Hash"
                      << std::setw(10) << "OpenSSL"
                      << "  (not supported in this OpenSSL build)" << std::endl;
        }

        // kctsb SM3
        run_benchmark(
            "SM3 Hash",
            "kctsb",
            [&]() {
                auto start = Clock::now();
                kctsb_sm3(data.data(), data_size, digest);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            },
            true, data_size
        );
    }
#else
    std::cout << "\n  SM3 benchmarks skipped (KCTSB_HAS_SM3 not defined)\n";
#endif
}

// ============================================================================
// SM4 Benchmarks
// ============================================================================

/**
 * @brief SM4 benchmark suite
 */
void benchmark_sm4() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  SM4 Cipher Benchmark (Chinese National Standard)" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

#ifdef KCTSB_HAS_SM4
    // Generate key and IV
    uint8_t key[16];
    uint8_t iv[16];
    generate_random(key, 16);
    generate_random(iv, 16);

    for (size_t data_size : TEST_SIZES) {
        std::string size_str;
        if (data_size >= 1024 * 1024) {
            size_str = std::to_string(data_size / (1024 * 1024)) + " MB";
        } else {
            size_str = std::to_string(data_size / 1024) + " KB";
        }

        print_header("SM4-CBC - Data Size: " + size_str);

        // Generate test data (aligned to 16 bytes for CBC)
        size_t aligned_size = (data_size / 16) * 16;
        std::vector<uint8_t> plaintext(aligned_size);
        std::vector<uint8_t> ciphertext(aligned_size);
        std::vector<uint8_t> decrypted(aligned_size);
        generate_random(plaintext.data(), aligned_size);

        // OpenSSL SM4 (if available)
        const EVP_CIPHER* sm4_cbc = EVP_sm4_cbc();
        if (sm4_cbc) {
            run_benchmark(
                "SM4-CBC Encrypt",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    int len = 0;
                    EVP_EncryptInit_ex(ctx, sm4_cbc, nullptr, key, iv);
                    EVP_CIPHER_CTX_set_padding(ctx, 0);
                    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                     plaintext.data(), static_cast<int>(aligned_size));
                    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
                    EVP_CIPHER_CTX_free(ctx);
                    auto end = Clock::now();
                    Duration elapsed = end - start;
                    return elapsed.count();
                },
                true, aligned_size
            );

            run_benchmark(
                "SM4-CBC Decrypt",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    int len = 0;
                    EVP_DecryptInit_ex(ctx, sm4_cbc, nullptr, key, iv);
                    EVP_CIPHER_CTX_set_padding(ctx, 0);
                    EVP_DecryptUpdate(ctx, decrypted.data(), &len,
                                     ciphertext.data(), static_cast<int>(aligned_size));
                    EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
                    EVP_CIPHER_CTX_free(ctx);
                    auto end = Clock::now();
                    Duration elapsed = end - start;
                    return elapsed.count();
                },
                true, aligned_size
            );
        } else {
            std::cout << std::left << std::setw(25) << "SM4-CBC Encrypt"
                      << std::setw(10) << "OpenSSL"
                      << "  (not supported in this OpenSSL build)" << std::endl;
            std::cout << std::left << std::setw(25) << "SM4-CBC Decrypt"
                      << std::setw(10) << "OpenSSL"
                      << "  (not supported in this OpenSSL build)" << std::endl;
        }

        // kctsb SM4 Encrypt
        kctsb_sm4_ctx_t enc_ctx;
        kctsb_sm4_set_encrypt_key(&enc_ctx, key);

        run_benchmark(
            "SM4-CBC Encrypt",
            "kctsb",
            [&]() {
                auto start = Clock::now();
                kctsb_sm4_cbc_encrypt(&enc_ctx, iv, plaintext.data(),
                                     aligned_size, ciphertext.data());
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            },
            true, aligned_size
        );

        // kctsb SM4 Decrypt
        kctsb_sm4_ctx_t dec_ctx;
        kctsb_sm4_set_decrypt_key(&dec_ctx, key);

        run_benchmark(
            "SM4-CBC Decrypt",
            "kctsb",
            [&]() {
                auto start = Clock::now();
                kctsb_sm4_cbc_decrypt(&dec_ctx, iv, ciphertext.data(),
                                     aligned_size, decrypted.data());
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            },
            true, aligned_size
        );
    }
#else
    std::cout << "\n  SM4 benchmarks skipped (KCTSB_HAS_SM4 not defined)\n";
#endif
}

// ============================================================================
// Main SM Benchmark Entry Point
// ============================================================================

/**
 * @brief Main SM algorithm benchmark function
 */
void benchmark_sm() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  Chinese National Standard Cryptography (SM2/SM3/SM4)" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

    benchmark_sm2();
    benchmark_sm3();
    benchmark_sm4();

    std::cout << "\n  Note: SM algorithms follow GB/T 32905/32907/32918 specifications.\n";
}
