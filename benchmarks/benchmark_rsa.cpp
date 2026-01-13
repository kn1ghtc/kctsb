/**
 * @file benchmark_rsa.cpp
 * @brief RSA Performance Benchmark: kctsb vs OpenSSL
 * 
 * Benchmarks RSA operations:
 * - Key generation (2048, 3072, 4096 bits)
 * - RSA-OAEP encryption/decryption
 * - RSA-PSS sign/verify
 * - PKCS#1 v1.5 operations
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
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 3;
constexpr size_t KEYGEN_ITERATIONS = 5;  // Key generation is slow
constexpr size_t CRYPTO_ITERATIONS = 50;
constexpr size_t HASH_SIZE = 32;  // SHA-256 hash size

/**
 * @brief High-resolution timer
 */
using Clock = std::chrono::high_resolution_clock;
using Duration = std::chrono::duration<double, std::milli>;

/**
 * @brief Generate random bytes
 */
static void generate_random(uint8_t* buf, size_t len) {
    RAND_bytes(buf, static_cast<int>(len));
}

/**
 * @brief RSA key size configurations
 */
static const int TEST_KEY_SIZES[] = {2048, 3072, 4096};

/**
 * @brief OpenSSL RSA key generation benchmark
 */
static double benchmark_openssl_rsa_keygen(int bits) {
    auto start = Clock::now();
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* pkey = nullptr;
    
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    EVP_PKEY_keygen(ctx, &pkey);
    
    auto end = Clock::now();
    Duration elapsed = end - start;
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return elapsed.count();
}

/**
 * @brief OpenSSL RSA-OAEP encryption benchmark
 */
static double benchmark_openssl_rsa_oaep_encrypt(
    EVP_PKEY* pkey,
    const uint8_t* plaintext,
    size_t plaintext_len,
    std::vector<uint8_t>& ciphertext
) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    size_t outlen = 0;
    
    auto start = Clock::now();
    
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    
    EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext, plaintext_len);
    ciphertext.resize(outlen);
    EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext, plaintext_len);
    
    auto end = Clock::now();
    Duration elapsed = end - start;
    
    ciphertext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    
    return elapsed.count();
}

/**
 * @brief OpenSSL RSA-OAEP decryption benchmark
 */
static double benchmark_openssl_rsa_oaep_decrypt(
    EVP_PKEY* pkey,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    std::vector<uint8_t>& plaintext
) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    size_t outlen = 0;
    
    auto start = Clock::now();
    
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    
    EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext, ciphertext_len);
    plaintext.resize(outlen);
    EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext, ciphertext_len);
    
    auto end = Clock::now();
    Duration elapsed = end - start;
    
    plaintext.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    
    return elapsed.count();
}

/**
 * @brief OpenSSL RSA-PSS sign benchmark
 */
static double benchmark_openssl_rsa_pss_sign(
    EVP_PKEY* pkey,
    const uint8_t* hash,
    std::vector<uint8_t>& signature
) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    size_t sig_len = 0;
    
    auto start = Clock::now();
    
    EVP_DigestSignInit(md_ctx, &pkey_ctx, EVP_sha256(), nullptr, pkey);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
    
    EVP_DigestSignUpdate(md_ctx, hash, HASH_SIZE);
    EVP_DigestSignFinal(md_ctx, nullptr, &sig_len);
    signature.resize(sig_len);
    EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len);
    
    auto end = Clock::now();
    Duration elapsed = end - start;
    
    signature.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);
    
    return elapsed.count();
}

/**
 * @brief OpenSSL RSA-PSS verify benchmark
 */
static double benchmark_openssl_rsa_pss_verify(
    EVP_PKEY* pkey,
    const uint8_t* hash,
    const uint8_t* signature,
    size_t sig_len
) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    
    auto start = Clock::now();
    
    EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), nullptr, pkey);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
    
    EVP_DigestVerifyUpdate(md_ctx, hash, HASH_SIZE);
    int ret = EVP_DigestVerifyFinal(md_ctx, signature, sig_len);
    (void)ret;  // Suppress unused warning
    
    auto end = Clock::now();
    Duration elapsed = end - start;
    
    EVP_MD_CTX_free(md_ctx);
    
    return elapsed.count();
}

/**
 * @brief Run benchmark iterations and print results
 */
static void run_benchmark(
    const std::string& name,
    const std::string& impl,
    size_t iterations,
    std::function<double()> benchmark_func
) {
    std::vector<double> times;
    times.reserve(iterations);
    
    // Warmup
    for (size_t i = 0; i < WARMUP_ITERATIONS; ++i) {
        benchmark_func();
    }
    
    // Benchmark
    for (size_t i = 0; i < iterations; ++i) {
        times.push_back(benchmark_func());
    }
    
    // Calculate statistics
    double avg = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    double min_time = *std::min_element(times.begin(), times.end());
    double ops_per_sec = 1000.0 / avg;
    
    std::cout << std::left << std::setw(25) << name
              << std::setw(12) << impl
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(12) << avg << " ms"
              << std::setw(10) << min_time << " ms"
              << std::setw(10) << ops_per_sec << " op/s"
              << std::endl;
}

/**
 * @brief Print section header
 */
static void print_header(const std::string& title) {
    std::cout << "\n  " << title << std::endl;
    std::cout << std::string(75, '-') << std::endl;
    std::cout << std::left << std::setw(25) << "Operation"
              << std::setw(12) << "Impl"
              << std::right << std::setw(14) << "Avg"
              << std::setw(10) << "Min"
              << std::setw(12) << "Throughput"
              << std::endl;
    std::cout << std::string(75, '-') << std::endl;
}

/**
 * @brief Main RSA benchmark function
 */
void benchmark_rsa() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  RSA Cryptography Benchmark" << std::endl;
    std::cout << std::string(75, '=') << std::endl;
    
    // Generate test data
    uint8_t hash[HASH_SIZE];
    generate_random(hash, HASH_SIZE);
    
    // Small plaintext for encryption (max for RSA-OAEP with SHA-256)
    uint8_t plaintext[128];
    generate_random(plaintext, sizeof(plaintext));
    
    for (int key_bits : TEST_KEY_SIZES) {
        std::string key_name = "RSA-" + std::to_string(key_bits);
        print_header(key_name);
        
        // ================================================================
        // Key Generation Benchmark
        // ================================================================
        run_benchmark(
            "Key Generation",
            "OpenSSL",
            KEYGEN_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_keygen(key_bits); }
        );
        
        // Generate persistent key pair for other tests
        EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen_init(keygen_ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(keygen_ctx, key_bits);
        EVP_PKEY_keygen(keygen_ctx, &pkey);
        EVP_PKEY_CTX_free(keygen_ctx);
        
        // Calculate max plaintext size for OAEP
        size_t max_pt_size = (key_bits / 8) - 2 * HASH_SIZE - 2;
        size_t pt_size = std::min(sizeof(plaintext), max_pt_size);
        
        // ================================================================
        // RSA-OAEP Encryption Benchmark
        // ================================================================
        std::vector<uint8_t> ciphertext;
        run_benchmark(
            "OAEP Encryption",
            "OpenSSL",
            CRYPTO_ITERATIONS,
            [&]() { 
                return benchmark_openssl_rsa_oaep_encrypt(
                    pkey, plaintext, pt_size, ciphertext); 
            }
        );
        
        // ================================================================
        // RSA-OAEP Decryption Benchmark
        // ================================================================
        // Encrypt once to get valid ciphertext
        benchmark_openssl_rsa_oaep_encrypt(pkey, plaintext, pt_size, ciphertext);
        
        std::vector<uint8_t> decrypted;
        run_benchmark(
            "OAEP Decryption",
            "OpenSSL",
            CRYPTO_ITERATIONS,
            [&]() { 
                return benchmark_openssl_rsa_oaep_decrypt(
                    pkey, ciphertext.data(), ciphertext.size(), decrypted); 
            }
        );
        
        // ================================================================
        // RSA-PSS Sign Benchmark
        // ================================================================
        std::vector<uint8_t> signature;
        run_benchmark(
            "PSS Sign",
            "OpenSSL",
            CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_pss_sign(pkey, hash, signature); }
        );
        
        // ================================================================
        // RSA-PSS Verify Benchmark
        // ================================================================
        // Sign once to get valid signature
        benchmark_openssl_rsa_pss_sign(pkey, hash, signature);
        
        run_benchmark(
            "PSS Verify",
            "OpenSSL",
            CRYPTO_ITERATIONS,
            [&]() { 
                return benchmark_openssl_rsa_pss_verify(
                    pkey, hash, signature.data(), signature.size()); 
            }
        );
        
        // Cleanup
        EVP_PKEY_free(pkey);
        
        std::cout << std::endl;
    }
    
    // Summary
    std::cout << "\n  Note: kctsb RSA implementation uses NTL backend with CRT optimization.\n";
    std::cout << "  OpenSSL results shown as baseline reference.\n";
}

// Declare external benchmark entry
extern void benchmark_rsa();
