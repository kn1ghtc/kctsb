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
// SM2 Benchmarks with OpenSSL Comparison
// ============================================================================

/**
 * @brief SM2 benchmark suite with OpenSSL comparison
 */
void benchmark_sm2() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  SM2 Benchmark (Chinese National Standard GB/T 32918)" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

#ifdef KCTSB_HAS_SM2
    print_header("SM2 Key Generation");

    // Test message
    uint8_t message[64];
    generate_random(message, sizeof(message));
    const uint8_t user_id[] = "1234567812345678";
    size_t user_id_len = 16;

    // ========================================================================
    // OpenSSL SM2 Key Generation
    // ========================================================================
    EVP_PKEY* openssl_keypair = nullptr;
    {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, nullptr);
        if (pctx) {
            run_benchmark(
                "SM2 Key Generation",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_PKEY_keygen_init(pctx);
                    EVP_PKEY* pkey = nullptr;
                    EVP_PKEY_keygen(pctx, &pkey);
                    auto end = Clock::now();
                    if (openssl_keypair == nullptr) {
                        openssl_keypair = pkey;  // Keep first key
                    } else {
                        EVP_PKEY_free(pkey);
                    }
                    Duration elapsed = end - start;
                    return elapsed.count();
                }
            );
            EVP_PKEY_CTX_free(pctx);
        } else {
            std::cout << std::left << std::setw(25) << "SM2 Key Generation"
                      << std::setw(10) << "OpenSSL"
                      << "  (not supported)" << std::endl;
        }
    }

    // kctsb Key Generation
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

    // Generate persistent keypair for sign/verify/encrypt/decrypt benchmarks
    kctsb_sm2_keypair_t keypair;
    kctsb_sm2_generate_keypair(&keypair);

    // ========================================================================
    // SM2 Sign/Verify
    // ========================================================================
    print_header("SM2 Sign/Verify");

    // OpenSSL SM2 Sign
    if (openssl_keypair) {
        EVP_PKEY_CTX* sign_ctx = EVP_PKEY_CTX_new(openssl_keypair, nullptr);
        if (sign_ctx) {
            EVP_PKEY_CTX_set1_id(sign_ctx, user_id, user_id_len);
            
            run_benchmark(
                "SM2 Sign",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
                    EVP_MD_CTX_set_pkey_ctx(md_ctx, sign_ctx);
                    EVP_DigestSignInit(md_ctx, nullptr, EVP_sm3(), nullptr, openssl_keypair);
                    
                    size_t sig_len = 0;
                    EVP_DigestSign(md_ctx, nullptr, &sig_len, message, sizeof(message));
                    std::vector<uint8_t> sig(sig_len);
                    EVP_DigestSign(md_ctx, sig.data(), &sig_len, message, sizeof(message));
                    
                    EVP_MD_CTX_free(md_ctx);
                    auto end = Clock::now();
                    Duration elapsed = end - start;
                    return elapsed.count();
                }
            );
            EVP_PKEY_CTX_free(sign_ctx);
        }
    } else {
        std::cout << std::left << std::setw(25) << "SM2 Sign"
                  << std::setw(10) << "OpenSSL"
                  << "  (not supported)" << std::endl;
    }

    // kctsb SM2 Sign
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

    // kctsb SM2 Verify
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

    // ========================================================================
    // SM2 Encrypt/Decrypt (GB/T 32918.4)
    // ========================================================================
    print_header("SM2 Encrypt/Decrypt (GB/T 32918.4)");

    // Test plaintext for encryption
    uint8_t plaintext[32];
    generate_random(plaintext, sizeof(plaintext));
    
    // kctsb SM2 Encrypt
    std::vector<uint8_t> ciphertext(256);
    size_t ciphertext_len = 0;
    
    run_benchmark(
        "SM2 Encrypt",
        "kctsb",
        [&]() {
            auto start = Clock::now();
            ciphertext_len = ciphertext.size();
            auto status = kctsb_sm2_encrypt(
                keypair.public_key,
                plaintext, sizeof(plaintext),
                ciphertext.data(), &ciphertext_len
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // kctsb SM2 Decrypt
    std::vector<uint8_t> decrypted(256);
    size_t decrypted_len = 0;
    
    run_benchmark(
        "SM2 Decrypt",
        "kctsb",
        [&]() {
            auto start = Clock::now();
            decrypted_len = decrypted.size();
            auto status = kctsb_sm2_decrypt(
                keypair.private_key,
                ciphertext.data(), ciphertext_len,
                decrypted.data(), &decrypted_len
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // Cleanup OpenSSL key
    if (openssl_keypair) {
        EVP_PKEY_free(openssl_keypair);
    }

    std::cout << "\n  Note: SM2 follows GB/T 32918.1-5 specifications.\n";
    std::cout << "  Encryption uses C1||C3||C2 format (GB/T 32918.4).\n";
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
// SM4 Benchmarks - GCM Mode Only (AEAD)
// ============================================================================

/**
 * @brief SM4 benchmark suite - GCM mode only
 */
void benchmark_sm4() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  SM4-GCM Cipher Benchmark (Chinese National Standard)" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

#ifdef KCTSB_HAS_SM4
    // Generate key and IV (12 bytes for GCM)
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t tag[16];
    generate_random(key, 16);
    generate_random(iv, 12);

    for (size_t data_size : TEST_SIZES) {
        std::string size_str;
        if (data_size >= 1024 * 1024) {
            size_str = std::to_string(data_size / (1024 * 1024)) + " MB";
        } else {
            size_str = std::to_string(data_size / 1024) + " KB";
        }

        print_header("SM4-GCM - Data Size: " + size_str);

        // Generate test data
        std::vector<uint8_t> plaintext(data_size);
        std::vector<uint8_t> ciphertext(data_size);
        std::vector<uint8_t> decrypted(data_size);
        generate_random(plaintext.data(), data_size);

        // AAD for authenticated encryption
        uint8_t aad[16] = "benchmark_aad";

        // OpenSSL SM4-CTR (GCM not available in OpenSSL, use CTR for comparison)
        // Note: OpenSSL does not have SM4-GCM, so we compare with CTR mode
        const EVP_CIPHER* sm4_ctr = EVP_sm4_ctr();
        if (sm4_ctr) {
            // Use full 16-byte IV for CTR mode
            uint8_t iv_ctr[16];
            std::memcpy(iv_ctr, iv, 12);
            std::memset(iv_ctr + 12, 0, 4);
            
            run_benchmark(
                "SM4-CTR (ref)",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    int len = 0;
                    EVP_EncryptInit_ex(ctx, sm4_ctr, nullptr, key, iv_ctr);
                    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                     plaintext.data(), static_cast<int>(data_size));
                    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
                    EVP_CIPHER_CTX_free(ctx);
                    auto end = Clock::now();
                    Duration elapsed = end - start;
                    return elapsed.count();
                },
                true, data_size
            );
        } else {
            std::cout << std::left << std::setw(25) << "SM4-CTR (ref)"
                      << std::setw(10) << "OpenSSL"
                      << "  (not supported in this OpenSSL build)" << std::endl;
        }

        // kctsb SM4-GCM Encrypt
        run_benchmark(
            "SM4-GCM Encrypt",
            "kctsb",
            [&]() {
                auto start = Clock::now();
                kctsb_sm4_gcm_encrypt_oneshot(key, iv, aad, sizeof(aad),
                                              plaintext.data(), data_size,
                                              ciphertext.data(), tag);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            },
            true, data_size
        );

        // kctsb SM4-GCM Decrypt
        run_benchmark(
            "SM4-GCM Decrypt",
            "kctsb",
            [&]() {
                auto start = Clock::now();
                auto ret = kctsb_sm4_gcm_decrypt_oneshot(key, iv, aad, sizeof(aad),
                                                          ciphertext.data(), data_size,
                                                          tag, decrypted.data());
                auto end = Clock::now();
                Duration elapsed = end - start;
                return (ret == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
            },
            true, data_size
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
    std::cout << "  SM4: Only GCM mode supported (AEAD). CBC removed for security.\n";
}
