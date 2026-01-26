/**
 * @file benchmark_rsa.cpp
 * @brief RSA Performance Benchmark: kctsb vs OpenSSL 3.6.0
 *
 * Benchmarks RSA operations:
 * - Key generation (2048, 3072, 4096 bits)
 * - RSA-OAEP encryption/decryption
 * - RSA-PSS sign/verify
 * 
 * v5.1.0: Fixed template class usage for kctsb::rsa::RSA<BITS>
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

// Common benchmark utilities
#include "benchmark_common.hpp"

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>

// kctsb RSA headers (conditional)
#ifdef KCTSB_HAS_RSA
#include "kctsb/crypto/rsa/rsa.h"
#endif

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 3;
constexpr size_t KEYGEN_ITERATIONS = 5;
constexpr size_t CRYPTO_ITERATIONS = 50;
constexpr size_t HASH_SIZE = 32;

using Clock = std::chrono::high_resolution_clock;
using Duration = std::chrono::duration<double, std::milli>;

static void generate_random(uint8_t* buf, size_t len) {
    RAND_bytes(buf, static_cast<int>(len));
}

/**
 * @brief Run benchmark iterations and return average time
 */
static double run_benchmark(
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

    double avg = std::accumulate(times.begin(), times.end(), 0.0) /
                 static_cast<double>(times.size());
    double min_time = *std::min_element(times.begin(), times.end());
    double ops_per_sec = 1000.0 / avg;

    std::cout << std::left << std::setw(25) << name
              << std::setw(12) << impl
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(10) << avg << " ms"
              << std::setw(10) << min_time << " ms"
              << std::setw(10) << ops_per_sec << " op/s"
              << std::endl;
    
    return avg;
}

/**
 * @brief Print section header
 */
static void print_header(const std::string& title) {
    std::cout << "\n  " << title << std::endl;
    std::cout << std::string(70, '-') << std::endl;
    std::cout << std::left << std::setw(25) << "Operation"
              << std::setw(12) << "Impl"
              << std::right << std::setw(12) << "Avg"
              << std::setw(10) << "Min"
              << std::setw(12) << "Throughput"
              << std::endl;
    std::cout << std::string(70, '-') << std::endl;
}

/**
 * @brief Print ratio comparison
 */
static void print_ratio(double kctsb_time, double openssl_time) {
    if (openssl_time <= 0 || kctsb_time <= 0) return;
    double ratio = openssl_time / kctsb_time;
    const char* status = ratio >= 1.0 ? "FASTER" : "SLOWER";
    std::cout << std::left << std::setw(25) << "  ==> Ratio"
              << std::setw(12) << ""
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(8) << (ratio * 100.0) << "%"
              << " of OpenSSL (" << ratio << "x " << status << ")"
              << std::endl;
}

// OpenSSL benchmark functions
static double benchmark_openssl_rsa_keygen(int bits) {
    auto start = Clock::now();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    EVP_PKEY_keygen(ctx, &pkey);
    auto end = Clock::now();
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return Duration(end - start).count();
}

static double benchmark_openssl_rsa_oaep_encrypt(
    EVP_PKEY* pkey, const uint8_t* pt, size_t pt_len, std::vector<uint8_t>& ct
) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    size_t outlen = 0;
    auto start = Clock::now();
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    EVP_PKEY_encrypt(ctx, nullptr, &outlen, pt, pt_len);
    ct.resize(outlen);
    EVP_PKEY_encrypt(ctx, ct.data(), &outlen, pt, pt_len);
    auto end = Clock::now();
    ct.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return Duration(end - start).count();
}

static double benchmark_openssl_rsa_oaep_decrypt(
    EVP_PKEY* pkey, const uint8_t* ct, size_t ct_len, std::vector<uint8_t>& pt
) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    size_t outlen = 0;
    auto start = Clock::now();
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    EVP_PKEY_decrypt(ctx, nullptr, &outlen, ct, ct_len);
    pt.resize(outlen);
    EVP_PKEY_decrypt(ctx, pt.data(), &outlen, ct, ct_len);
    auto end = Clock::now();
    pt.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return Duration(end - start).count();
}

static double benchmark_openssl_rsa_pss_sign(
    EVP_PKEY* pkey, const uint8_t* hash, std::vector<uint8_t>& sig
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
    sig.resize(sig_len);
    EVP_DigestSignFinal(md_ctx, sig.data(), &sig_len);
    auto end = Clock::now();
    sig.resize(sig_len);
    EVP_MD_CTX_free(md_ctx);
    return Duration(end - start).count();
}

static double benchmark_openssl_rsa_pss_verify(
    EVP_PKEY* pkey, const uint8_t* hash, const uint8_t* sig, size_t sig_len
) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    auto start = Clock::now();
    EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), nullptr, pkey);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST);
    EVP_DigestVerifyUpdate(md_ctx, hash, HASH_SIZE);
    EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
    auto end = Clock::now();
    EVP_MD_CTX_free(md_ctx);
    return Duration(end - start).count();
}

#ifdef KCTSB_HAS_RSA
/**
 * @brief Template benchmark for kctsb RSA operations
 */
template<size_t BITS>
static void benchmark_kctsb_rsa_impl(
    double openssl_keygen_time,
    const uint8_t* plaintext,
    size_t pt_size,
    const uint8_t* hash
) {
    using RSAType = kctsb::rsa::RSA<BITS>;
    using KeyPair = typename RSAType::KeyPair;
    
    // Key Generation
    double kctsb_keygen = run_benchmark("Key Generation", "kctsb", KEYGEN_ITERATIONS,
        []() {
            auto start = Clock::now();
            auto kp = RSAType::generate_keypair();
            auto end = Clock::now();
            (void)kp;
            return Duration(end - start).count();
        }
    );
    print_ratio(kctsb_keygen, openssl_keygen_time);
    
    KeyPair kctsb_keypair = RSAType::generate_keypair();
    
    // OAEP Encryption
    std::vector<uint8_t> kctsb_ct;
    bool oaep_works = true;
    try {
        kctsb_ct = RSAType::encrypt_oaep(plaintext, pt_size, kctsb_keypair.public_key);
    } catch (...) { oaep_works = false; }
    
    if (oaep_works) {
        run_benchmark("OAEP Encryption", "kctsb", CRYPTO_ITERATIONS,
            [&]() {
                auto start = Clock::now();
                auto ct = RSAType::encrypt_oaep(plaintext, pt_size, kctsb_keypair.public_key);
                auto end = Clock::now();
                (void)ct;
                return Duration(end - start).count();
            }
        );
        
        // OAEP Decryption
        run_benchmark("OAEP Decryption", "kctsb", CRYPTO_ITERATIONS,
            [&]() {
                auto start = Clock::now();
                auto pt = RSAType::decrypt_oaep(kctsb_ct.data(), kctsb_ct.size(), kctsb_keypair.private_key);
                auto end = Clock::now();
                (void)pt;
                return Duration(end - start).count();
            }
        );
    }
    
    // PSS Sign
    std::vector<uint8_t> kctsb_sig;
    bool pss_works = true;
    try {
        kctsb_sig = RSAType::sign_pss(hash, HASH_SIZE, kctsb_keypair.private_key);
    } catch (...) { pss_works = false; }
    
    if (pss_works) {
        run_benchmark("PSS Sign", "kctsb", CRYPTO_ITERATIONS,
            [&]() {
                auto start = Clock::now();
                auto sig = RSAType::sign_pss(hash, HASH_SIZE, kctsb_keypair.private_key);
                auto end = Clock::now();
                (void)sig;
                return Duration(end - start).count();
            }
        );
        
        // PSS Verify
        run_benchmark("PSS Verify", "kctsb", CRYPTO_ITERATIONS,
            [&]() {
                auto start = Clock::now();
                bool valid = RSAType::verify_pss(hash, HASH_SIZE, kctsb_sig.data(), kctsb_sig.size(), kctsb_keypair.public_key);
                auto end = Clock::now();
                (void)valid;
                return Duration(end - start).count();
            }
        );
    }
}
#endif

/**
 * @brief Main RSA benchmark function
 */
void benchmark_rsa() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           RSA Performance Benchmark: kctsb vs OpenSSL 3.6.0       ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════════╝\n";

    uint8_t hash[HASH_SIZE];
    uint8_t plaintext[128];
    generate_random(hash, sizeof(hash));
    generate_random(plaintext, sizeof(plaintext));

    // RSA-2048
    {
        constexpr int BITS = 2048;
        print_header("RSA-2048");
        
        double ssl_keygen = run_benchmark("Key Generation", "OpenSSL", KEYGEN_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_keygen(BITS); });
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, BITS);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
        
        size_t pt_size = std::min(sizeof(plaintext), static_cast<size_t>((BITS / 8) - 2 * HASH_SIZE - 2));
        
        std::vector<uint8_t> ct, sig;
        run_benchmark("OAEP Encryption", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_oaep_encrypt(pkey, plaintext, pt_size, ct); });
        
        benchmark_openssl_rsa_oaep_encrypt(pkey, plaintext, pt_size, ct);
        std::vector<uint8_t> dec;
        run_benchmark("OAEP Decryption", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_oaep_decrypt(pkey, ct.data(), ct.size(), dec); });
        
        run_benchmark("PSS Sign", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_pss_sign(pkey, hash, sig); });
        
        benchmark_openssl_rsa_pss_sign(pkey, hash, sig);
        run_benchmark("PSS Verify", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_pss_verify(pkey, hash, sig.data(), sig.size()); });
        
#ifdef KCTSB_HAS_RSA
        benchmark_kctsb_rsa_impl<2048>(ssl_keygen, plaintext, pt_size, hash);
#endif
        EVP_PKEY_free(pkey);
    }

    // RSA-3072
    {
        constexpr int BITS = 3072;
        print_header("RSA-3072");
        
        double ssl_keygen = run_benchmark("Key Generation", "OpenSSL", KEYGEN_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_keygen(BITS); });
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, BITS);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
        
        size_t pt_size = std::min(sizeof(plaintext), static_cast<size_t>((BITS / 8) - 2 * HASH_SIZE - 2));
        
        std::vector<uint8_t> ct, sig;
        run_benchmark("OAEP Encryption", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_oaep_encrypt(pkey, plaintext, pt_size, ct); });
        
        benchmark_openssl_rsa_oaep_encrypt(pkey, plaintext, pt_size, ct);
        std::vector<uint8_t> dec;
        run_benchmark("OAEP Decryption", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_oaep_decrypt(pkey, ct.data(), ct.size(), dec); });
        
        run_benchmark("PSS Sign", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_pss_sign(pkey, hash, sig); });
        
        benchmark_openssl_rsa_pss_sign(pkey, hash, sig);
        run_benchmark("PSS Verify", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_pss_verify(pkey, hash, sig.data(), sig.size()); });
        
#ifdef KCTSB_HAS_RSA
        benchmark_kctsb_rsa_impl<3072>(ssl_keygen, plaintext, pt_size, hash);
#endif
        EVP_PKEY_free(pkey);
    }

    // RSA-4096
    {
        constexpr int BITS = 4096;
        print_header("RSA-4096");
        
        double ssl_keygen = run_benchmark("Key Generation", "OpenSSL", KEYGEN_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_keygen(BITS); });
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, BITS);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
        
        size_t pt_size = std::min(sizeof(plaintext), static_cast<size_t>((BITS / 8) - 2 * HASH_SIZE - 2));
        
        std::vector<uint8_t> ct, sig;
        run_benchmark("OAEP Encryption", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_oaep_encrypt(pkey, plaintext, pt_size, ct); });
        
        benchmark_openssl_rsa_oaep_encrypt(pkey, plaintext, pt_size, ct);
        std::vector<uint8_t> dec;
        run_benchmark("OAEP Decryption", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_oaep_decrypt(pkey, ct.data(), ct.size(), dec); });
        
        run_benchmark("PSS Sign", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_pss_sign(pkey, hash, sig); });
        
        benchmark_openssl_rsa_pss_sign(pkey, hash, sig);
        run_benchmark("PSS Verify", "OpenSSL", CRYPTO_ITERATIONS,
            [&]() { return benchmark_openssl_rsa_pss_verify(pkey, hash, sig.data(), sig.size()); });
        
#ifdef KCTSB_HAS_RSA
        benchmark_kctsb_rsa_impl<4096>(ssl_keygen, plaintext, pt_size, hash);
#endif
        EVP_PKEY_free(pkey);
    }

    std::cout << "\n  Performance Comparison Summary:\n";
    std::cout << "  - OpenSSL 3.6.0 uses highly optimized assembly implementations\n";
    std::cout << "  - kctsb uses template-based BigInt with CRT optimization\n";
}

extern void benchmark_rsa();
