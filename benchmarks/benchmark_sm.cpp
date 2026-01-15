/**
 * @file benchmark_sm.cpp
 * @brief SM Algorithm Performance Benchmark: kctsb vs OpenSSL
 *
 * Benchmarks Chinese National Standard cryptographic algorithms:
 * - SM2: Key generation, Encrypt/Decrypt, Sign/Verify (full comparison)
 * - SM3: Hash computation throughput
 * - SM4: Block cipher GCM mode encryption/decryption
 *
 * OpenSSL SM2 EVP interface usage (3.x):
 * - Key generation: EVP_PKEY_keygen with EVP_PKEY_SM2
 * - Sign/Verify: EVP_DigestSign/Verify with EVP_sm3()
 * - Encrypt/Decrypt: EVP_PKEY_encrypt/decrypt
 *
 * Note on SM4:
 * - OpenSSL 3.x does NOT support SM4-GCM mode
 * - We compare with SM4-CBC for reference (both encrypt and decrypt)
 * - kctsb SM4 uses GCM mode only for security (AEAD)
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
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

// kctsb SM headers (conditional) - correct paths
#ifdef KCTSB_HAS_SM2
#include "kctsb/crypto/sm/sm2.h"
#endif

#ifdef KCTSB_HAS_SM3
#include "kctsb/crypto/sm/sm3.h"
#endif

#ifdef KCTSB_HAS_SM4
#include "kctsb/crypto/sm/sm4.h"
#endif

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 5;
constexpr size_t BENCHMARK_ITERATIONS = 100;

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
// SM2 Benchmarks with OpenSSL Full Comparison
// ============================================================================

/**
 * @brief SM2 benchmark suite with OpenSSL comparison
 * Tests: Key Generation, Encrypt, Decrypt, Sign, Verify
 */
void benchmark_sm2() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  SM2 Complete Benchmark (GB/T 32918)" << std::endl;
    std::cout << "  Operations: KeyGen, Encrypt, Decrypt, Sign, Verify" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

#ifdef KCTSB_HAS_SM2
    // Test message and user ID
    uint8_t message[64];
    generate_random(message, sizeof(message));
    const uint8_t user_id[] = "1234567812345678";
    size_t user_id_len = 16;

    // Plaintext for encryption test
    uint8_t plaintext[32];
    generate_random(plaintext, sizeof(plaintext));

    print_header("SM2 Key Generation + Sign/Verify + Encrypt/Decrypt");

    // ========================================================================
    // OpenSSL SM2 Operations
    // ========================================================================
    EVP_PKEY* openssl_keypair = nullptr;
    std::vector<uint8_t> openssl_signature;
    std::vector<uint8_t> openssl_ciphertext;

    // OpenSSL SM2 Key Generation
    {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, nullptr);
        if (pctx && EVP_PKEY_keygen_init(pctx) > 0) {
            run_benchmark(
                "SM2 KeyGen",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_PKEY* pkey = nullptr;
                    EVP_PKEY_keygen(pctx, &pkey);
                    auto end = Clock::now();
                    if (openssl_keypair == nullptr) {
                        openssl_keypair = pkey;
                    } else {
                        EVP_PKEY_free(pkey);
                    }
                    Duration elapsed = end - start;
                    return elapsed.count();
                }
            );
        } else {
            std::cout << std::left << std::setw(25) << "SM2 KeyGen"
                      << std::setw(10) << "OpenSSL"
                      << "  (not supported)" << std::endl;
        }
        if (pctx) EVP_PKEY_CTX_free(pctx);
    }

    // OpenSSL SM2 Sign
    if (openssl_keypair) {
        run_benchmark(
            "SM2 Sign",
            "OpenSSL",
            [&]() {
                auto start = Clock::now();
                EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
                EVP_PKEY_CTX* sign_pctx = nullptr;

                EVP_DigestSignInit(md_ctx, &sign_pctx, EVP_sm3(), nullptr, openssl_keypair);
                EVP_PKEY_CTX_set1_id(sign_pctx, user_id, user_id_len);

                size_t sig_len = 0;
                EVP_DigestSign(md_ctx, nullptr, &sig_len, message, sizeof(message));
                openssl_signature.resize(sig_len);
                EVP_DigestSign(md_ctx, openssl_signature.data(), &sig_len, message, sizeof(message));
                openssl_signature.resize(sig_len);

                EVP_MD_CTX_free(md_ctx);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            }
        );
    }

    // OpenSSL SM2 Verify
    if (openssl_keypair && !openssl_signature.empty()) {
        run_benchmark(
            "SM2 Verify",
            "OpenSSL",
            [&]() {
                auto start = Clock::now();
                EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
                EVP_PKEY_CTX* verify_pctx = nullptr;

                EVP_DigestVerifyInit(md_ctx, &verify_pctx, EVP_sm3(), nullptr, openssl_keypair);
                EVP_PKEY_CTX_set1_id(verify_pctx, user_id, user_id_len);

                int ret = EVP_DigestVerify(md_ctx, openssl_signature.data(), openssl_signature.size(),
                                           message, sizeof(message));

                EVP_MD_CTX_free(md_ctx);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return (ret == 1) ? elapsed.count() : -1.0;
            }
        );
    }

    // OpenSSL SM2 Encrypt
    if (openssl_keypair) {
        run_benchmark(
            "SM2 Encrypt",
            "OpenSSL",
            [&]() {
                auto start = Clock::now();
                EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(openssl_keypair, nullptr);
                EVP_PKEY_encrypt_init(enc_ctx);

                size_t ct_len = 0;
                EVP_PKEY_encrypt(enc_ctx, nullptr, &ct_len, plaintext, sizeof(plaintext));
                openssl_ciphertext.resize(ct_len);
                EVP_PKEY_encrypt(enc_ctx, openssl_ciphertext.data(), &ct_len, plaintext, sizeof(plaintext));
                openssl_ciphertext.resize(ct_len);

                EVP_PKEY_CTX_free(enc_ctx);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            }
        );
    }

    // OpenSSL SM2 Decrypt
    if (openssl_keypair && !openssl_ciphertext.empty()) {
        run_benchmark(
            "SM2 Decrypt",
            "OpenSSL",
            [&]() {
                auto start = Clock::now();
                EVP_PKEY_CTX* dec_ctx = EVP_PKEY_CTX_new(openssl_keypair, nullptr);
                EVP_PKEY_decrypt_init(dec_ctx);

                size_t pt_len = 0;
                EVP_PKEY_decrypt(dec_ctx, nullptr, &pt_len, openssl_ciphertext.data(), openssl_ciphertext.size());
                std::vector<uint8_t> decrypted(pt_len);
                EVP_PKEY_decrypt(dec_ctx, decrypted.data(), &pt_len, openssl_ciphertext.data(), openssl_ciphertext.size());

                EVP_PKEY_CTX_free(dec_ctx);
                auto end = Clock::now();
                Duration elapsed = end - start;
                return elapsed.count();
            }
        );
    }

    // ========================================================================
    // kctsb SM2 Operations
    // ========================================================================
    kctsb_sm2_keypair_t keypair;
    kctsb_sm2_generate_keypair(&keypair);
    kctsb_sm2_signature_t kctsb_signature;
    std::vector<uint8_t> kctsb_ciphertext(256);
    size_t kctsb_ct_len = 0;

    // kctsb SM2 Key Generation
    run_benchmark(
        "SM2 KeyGen",
        "kctsb",
        [&]() {
            kctsb_sm2_keypair_t kp;
            auto start = Clock::now();
            auto status = kctsb_sm2_generate_keypair(&kp);
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // kctsb SM2 Sign
    run_benchmark(
        "SM2 Sign",
        "kctsb",
        [&]() {
            auto start = Clock::now();
            auto status = kctsb_sm2_sign(
                keypair.private_key, keypair.public_key,
                user_id, user_id_len,
                message, sizeof(message),
                &kctsb_signature
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // Generate signature for verify
    kctsb_sm2_sign(keypair.private_key, keypair.public_key,
                   user_id, user_id_len, message, sizeof(message), &kctsb_signature);

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
                &kctsb_signature
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // kctsb SM2 Encrypt
    run_benchmark(
        "SM2 Encrypt",
        "kctsb",
        [&]() {
            auto start = Clock::now();
            kctsb_ct_len = kctsb_ciphertext.size();
            auto status = kctsb_sm2_encrypt(
                keypair.public_key,
                plaintext, sizeof(plaintext),
                kctsb_ciphertext.data(), &kctsb_ct_len
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // Generate ciphertext for decrypt
    kctsb_ct_len = kctsb_ciphertext.size();
    kctsb_sm2_encrypt(keypair.public_key, plaintext, sizeof(plaintext),
                      kctsb_ciphertext.data(), &kctsb_ct_len);

    // kctsb SM2 Decrypt
    std::vector<uint8_t> kctsb_decrypted(256);
    size_t kctsb_dec_len = 0;
    run_benchmark(
        "SM2 Decrypt",
        "kctsb",
        [&]() {
            auto start = Clock::now();
            kctsb_dec_len = kctsb_decrypted.size();
            auto status = kctsb_sm2_decrypt(
                keypair.private_key,
                kctsb_ciphertext.data(), kctsb_ct_len,
                kctsb_decrypted.data(), &kctsb_dec_len
            );
            auto end = Clock::now();
            Duration elapsed = end - start;
            return (status == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
        }
    );

    // Cleanup
    if (openssl_keypair) {
        EVP_PKEY_free(openssl_keypair);
    }

    std::cout << "\n  Note: SM2 follows GB/T 32918.1-5 specifications.\n";
    std::cout << "  OpenSSL and kctsb may use different internal formats.\n";
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
    std::cout << "  SM3 Hash Benchmark (GB/T 32905)" << std::endl;
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

        // OpenSSL SM3
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
// SM4 Benchmarks - GCM Mode with CBC Reference
// ============================================================================

/**
 * @brief SM4 benchmark suite
 * - kctsb: GCM mode (AEAD, secure)
 * - OpenSSL: CBC mode for reference (GCM not available)
 */
void benchmark_sm4() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  SM4 Cipher Benchmark (GB/T 32907)" << std::endl;
    std::cout << "  kctsb: GCM mode (AEAD) | OpenSSL: CBC mode (reference)" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

#ifdef KCTSB_HAS_SM4
    // Generate key and IVs
    uint8_t key[16];
    uint8_t iv_gcm[12];   // 12 bytes for GCM
    uint8_t iv_cbc[16];   // 16 bytes for CBC
    uint8_t tag[16];
    generate_random(key, 16);
    generate_random(iv_gcm, 12);
    generate_random(iv_cbc, 16);

    for (size_t data_size : TEST_SIZES) {
        std::string size_str;
        if (data_size >= 1024 * 1024) {
            size_str = std::to_string(data_size / (1024 * 1024)) + " MB";
        } else {
            size_str = std::to_string(data_size / 1024) + " KB";
        }

        print_header("SM4 - Data Size: " + size_str);

        // Generate test data (padded for CBC)
        size_t padded_size = ((data_size + 15) / 16) * 16;
        std::vector<uint8_t> plaintext(padded_size);
        std::vector<uint8_t> ciphertext_cbc(padded_size);
        std::vector<uint8_t> ciphertext_gcm(data_size);
        std::vector<uint8_t> decrypted(padded_size);
        generate_random(plaintext.data(), data_size);

        // AAD for GCM
        uint8_t aad[16] = "benchmark_aad__";

        // ====================================================================
        // OpenSSL SM4-CBC (both encrypt and decrypt)
        // ====================================================================
        const EVP_CIPHER* sm4_cbc = EVP_sm4_cbc();
        if (sm4_cbc) {
            // OpenSSL SM4-CBC Encrypt
            run_benchmark(
                "SM4-CBC Encrypt (ref)",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    int len = 0, final_len = 0;
                    EVP_EncryptInit_ex(ctx, sm4_cbc, nullptr, key, iv_cbc);
                    EVP_CIPHER_CTX_set_padding(ctx, 0);  // No padding for fair comparison
                    EVP_EncryptUpdate(ctx, ciphertext_cbc.data(), &len,
                                     plaintext.data(), static_cast<int>(padded_size));
                    EVP_EncryptFinal_ex(ctx, ciphertext_cbc.data() + len, &final_len);
                    EVP_CIPHER_CTX_free(ctx);
                    auto end = Clock::now();
                    Duration elapsed = end - start;
                    return elapsed.count();
                },
                true, data_size
            );

            // OpenSSL SM4-CBC Decrypt
            run_benchmark(
                "SM4-CBC Decrypt (ref)",
                "OpenSSL",
                [&]() {
                    auto start = Clock::now();
                    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                    int len = 0, final_len = 0;
                    EVP_DecryptInit_ex(ctx, sm4_cbc, nullptr, key, iv_cbc);
                    EVP_CIPHER_CTX_set_padding(ctx, 0);
                    EVP_DecryptUpdate(ctx, decrypted.data(), &len,
                                     ciphertext_cbc.data(), static_cast<int>(padded_size));
                    EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len);
                    EVP_CIPHER_CTX_free(ctx);
                    auto end = Clock::now();
                    Duration elapsed = end - start;
                    return elapsed.count();
                },
                true, data_size
            );
        } else {
            std::cout << std::left << std::setw(25) << "SM4-CBC (ref)"
                      << std::setw(10) << "OpenSSL"
                      << "  (not supported)" << std::endl;
        }

        // ====================================================================
        // kctsb SM4-GCM (both encrypt and decrypt)
        // ====================================================================

        // kctsb SM4-GCM Encrypt
        run_benchmark(
            "SM4-GCM Encrypt",
            "kctsb",
            [&]() {
                auto start = Clock::now();
                kctsb_sm4_gcm_encrypt_oneshot(key, iv_gcm, aad, sizeof(aad),
                                              plaintext.data(), data_size,
                                              ciphertext_gcm.data(), tag);
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
                auto ret = kctsb_sm4_gcm_decrypt_oneshot(key, iv_gcm, aad, sizeof(aad),
                                                          ciphertext_gcm.data(), data_size,
                                                          tag, decrypted.data());
                auto end = Clock::now();
                Duration elapsed = end - start;
                return (ret == KCTSB_SUCCESS) ? elapsed.count() : -1.0;
            },
            true, data_size
        );
    }

    std::cout << "\n  Note: OpenSSL 3.x does NOT support SM4-GCM mode.\n";
    std::cout << "  SM4-CBC is used as reference for throughput comparison.\n";
    std::cout << "  kctsb SM4-GCM provides authenticated encryption (AEAD).\n";
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
    std::cout << "  SM4: GCM mode only in kctsb (AEAD, secure). CBC removed.\n";
}
