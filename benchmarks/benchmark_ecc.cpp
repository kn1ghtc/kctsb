/**
 * @file benchmark_ecc.cpp
 * @brief ECC Performance Benchmark: kctsb vs OpenSSL 3.6.0
 *
 * Benchmarks elliptic curve operations (256-bit curves only):
 * - Key generation (secp256k1, secp256r1/P-256)
 * - ECDSA sign/verify operations
 * - ECDH key agreement
 * 
 * v5.2.0: Uses NATIVE ECC API (fe256_native) - zero NTL dependency
 * v5.1.0: Uses internal ECC API (ZZ-based) for benchmarking
 * v4.6.0: Removed P-384/P-521, focus on 256-bit curves
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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// kctsb NATIVE ECC API (fe256_native - zero NTL dependency)
#include "../src/crypto/ecc/fe256_native.h"
namespace kctsb_native = kctsb::ecc::native;

// Legacy NTL-based ECC API (kept for reference, but not used in benchmark)
#ifdef KCTSB_HAS_ECC
#include "kctsb/crypto/ecc/ecdsa.h"
#include "kctsb/crypto/ecc/ecdh.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
namespace kctsb_ecc = kctsb::ecc::internal;
#endif

// Benchmark configuration
constexpr size_t WARMUP_ITERATIONS = 5;
constexpr size_t BENCHMARK_ITERATIONS = 50;
constexpr size_t HASH_SIZE = 32;  // SHA-256 hash size

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
 * @brief Curve configurations for testing
 */
struct CurveConfig {
    int nid;                              // OpenSSL NID
    const char* name;                     // Display name
    size_t key_bits;                      // Key size in bits
    kctsb_native::CurveId native_id;      // Native ECC implementation
};

static const CurveConfig TEST_CURVES[] = {
    {NID_secp256k1, "secp256k1", 256, kctsb_native::CurveId::SECP256K1},
    {NID_X9_62_prime256v1, "secp256r1 (P-256)", 256, kctsb_native::CurveId::P256},
};

// ============================================================================
// OpenSSL Benchmark Functions
// ============================================================================

/**
 * @brief OpenSSL EC key generation benchmark
 */
static double benchmark_openssl_ec_keygen(int nid) {
    auto start = Clock::now();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* pkey = nullptr;

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    EVP_PKEY_keygen(ctx, &pkey);

    auto end = Clock::now();
    Duration elapsed = end - start;

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return elapsed.count();
}

/**
 * @brief OpenSSL ECDSA sign benchmark
 */
static double benchmark_openssl_ecdsa_sign(EVP_PKEY* pkey, const uint8_t* hash) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;

    auto start = Clock::now();

    EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(md_ctx, hash, HASH_SIZE);
    EVP_DigestSignFinal(md_ctx, nullptr, &sig_len);

    std::vector<uint8_t> signature(sig_len);
    EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len);

    auto end = Clock::now();
    Duration elapsed = end - start;

    EVP_MD_CTX_free(md_ctx);
    return elapsed.count();
}

/**
 * @brief OpenSSL ECDSA verify benchmark
 */
static double benchmark_openssl_ecdsa_verify(
    EVP_PKEY* pkey,
    const uint8_t* hash,
    const uint8_t* sig,
    size_t sig_len
) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    auto start = Clock::now();

    EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestVerifyUpdate(md_ctx, hash, HASH_SIZE);
    int ret = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
    (void)ret;

    auto end = Clock::now();
    Duration elapsed = end - start;

    EVP_MD_CTX_free(md_ctx);
    return elapsed.count();
}

/**
 * @brief OpenSSL ECDH key derivation benchmark
 */
static double benchmark_openssl_ecdh(EVP_PKEY* priv_key, EVP_PKEY* peer_pub) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    size_t secret_len = 0;

    auto start = Clock::now();

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pub);
    EVP_PKEY_derive(ctx, nullptr, &secret_len);

    std::vector<uint8_t> secret(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);

    auto end = Clock::now();
    Duration elapsed = end - start;

    EVP_PKEY_CTX_free(ctx);
    return elapsed.count();
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Run benchmark iterations and return average time
 */
static double run_benchmark(
    const std::string& name,
    const std::string& impl,
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

    // Statistics
    double avg = std::accumulate(times.begin(), times.end(), 0.0) /
                 static_cast<double>(times.size());
    double min_time = *std::min_element(times.begin(), times.end());
    double ops_per_sec = 1000.0 / avg;

    std::cout << std::left << std::setw(30) << name
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
    std::cout << std::string(75, '-') << std::endl;
    std::cout << std::left << std::setw(30) << "Operation"
              << std::setw(12) << "Impl"
              << std::right << std::setw(12) << "Avg"
              << std::setw(10) << "Min"
              << std::setw(12) << "Throughput"
              << std::endl;
    std::cout << std::string(75, '-') << std::endl;
}

/**
 * @brief Print performance ratio (kctsb vs OpenSSL)
 */
static void print_ratio(double kctsb_time, double openssl_time) {
    if (openssl_time > 0 && kctsb_time > 0) {
        double ratio = openssl_time / kctsb_time;
        std::cout << std::right << std::setw(40) 
                  << "  -> Ratio (kctsb/OpenSSL): " << std::fixed 
                  << std::setprecision(2) << ratio << "x";
        if (ratio >= 1.0) {
            std::cout << " (faster)";
        } else {
            std::cout << " (slower)";
        }
        std::cout << std::endl;
    }
}

// ============================================================================
// Main ECC Benchmark
// ============================================================================

/**
 * @brief Main ECC benchmark function
 */
void benchmark_ecc() {
    std::cout << "\n" << std::string(80, '=') << std::endl;
    std::cout << "  Elliptic Curve Cryptography (ECC) Benchmark vs OpenSSL 3.6.0" << std::endl;
    std::cout << "  Implementation: kctsb NATIVE (fe256_native - zero NTL dependency)" << std::endl;
    std::cout << std::string(80, '=') << std::endl;

    // Generate test hash
    uint8_t hash[HASH_SIZE];
    generate_random(hash, HASH_SIZE);

    for (const auto& curve : TEST_CURVES) {
        print_header(curve.name);

        // Variables for ratio comparison
        double openssl_keygen_time = 0, kctsb_keygen_time = 0;
        double openssl_sign_time = 0, kctsb_sign_time = 0;
        double openssl_verify_time = 0, kctsb_verify_time = 0;
        double openssl_ecdh_time = 0, kctsb_ecdh_time = 0;

        // ================================================================
        // Key Generation Benchmark
        // ================================================================
        openssl_keygen_time = run_benchmark(
            "Key Generation",
            "OpenSSL",
            [&]() { return benchmark_openssl_ec_keygen(curve.nid); }
        );

        // Native implementation
        {
            uint8_t random32[32];
            
            kctsb_keygen_time = run_benchmark(
                "Key Generation",
                "kctsb",
                [&]() {
                    auto start = Clock::now();
                    generate_random(random32, 32);
                    kctsb_native::EcdsaKeyPair kp;
                    kctsb_native::ecdsa_keygen(&kp, random32, curve.native_id);
                    auto end = Clock::now();
                    return Duration(end - start).count();
                }
            );
            print_ratio(kctsb_keygen_time, openssl_keygen_time);
        }

        // Generate persistent key pair for sign/verify tests
        EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen_init(keygen_ctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keygen_ctx, curve.nid);
        EVP_PKEY_keygen(keygen_ctx, &pkey);
        EVP_PKEY_CTX_free(keygen_ctx);

        // ================================================================
        // ECDSA Sign Benchmark
        // ================================================================
        openssl_sign_time = run_benchmark(
            "ECDSA Sign",
            "OpenSSL",
            [&]() { return benchmark_openssl_ecdsa_sign(pkey, hash); }
        );

        // Native implementation
        {
            uint8_t random32[32], k32[32];
            generate_random(random32, 32);
            kctsb_native::EcdsaKeyPair kp;
            kctsb_native::ecdsa_keygen(&kp, random32, curve.native_id);
            
            kctsb_sign_time = run_benchmark(
                "ECDSA Sign",
                "kctsb",
                [&]() {
                    auto start = Clock::now();
                    generate_random(k32, 32);
                    kctsb_native::EcdsaSignature sig;
                    kctsb_native::ecdsa_sign(&sig, hash, HASH_SIZE, 
                                             &kp.private_key, k32, curve.native_id);
                    auto end = Clock::now();
                    return Duration(end - start).count();
                }
            );
            print_ratio(kctsb_sign_time, openssl_sign_time);
        }

        // Generate a signature for verify benchmark
        EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
        size_t sig_len = 0;
        EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(), nullptr, pkey);
        EVP_DigestSignUpdate(sign_ctx, hash, HASH_SIZE);
        EVP_DigestSignFinal(sign_ctx, nullptr, &sig_len);
        std::vector<uint8_t> signature(sig_len);
        EVP_DigestSignFinal(sign_ctx, signature.data(), &sig_len);
        EVP_MD_CTX_free(sign_ctx);

        // ================================================================
        // ECDSA Verify Benchmark
        // ================================================================
        openssl_verify_time = run_benchmark(
            "ECDSA Verify",
            "OpenSSL",
            [&]() {
                return benchmark_openssl_ecdsa_verify(pkey, hash,
                    signature.data(), sig_len);
            }
        );

        // Native implementation
        {
            uint8_t random32[32], k32[32];
            generate_random(random32, 32);
            kctsb_native::EcdsaKeyPair kp;
            kctsb_native::ecdsa_keygen(&kp, random32, curve.native_id);
            
            // Pre-sign for verify benchmark
            generate_random(k32, 32);
            kctsb_native::EcdsaSignature sig;
            kctsb_native::ecdsa_sign(&sig, hash, HASH_SIZE, 
                                     &kp.private_key, k32, curve.native_id);
            
            kctsb_verify_time = run_benchmark(
                "ECDSA Verify",
                "kctsb",
                [&]() {
                    auto start = Clock::now();
                    int valid = kctsb_native::ecdsa_verify(&sig, hash, HASH_SIZE,
                                                           &kp.public_key, curve.native_id);
                    auto end = Clock::now();
                    (void)valid;
                    return Duration(end - start).count();
                }
            );
            print_ratio(kctsb_verify_time, openssl_verify_time);
        }

        // ================================================================
        // ECDH Key Agreement Benchmark
        // ================================================================
        EVP_PKEY_CTX* peer_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY* peer_pkey = nullptr;
        EVP_PKEY_keygen_init(peer_ctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(peer_ctx, curve.nid);
        EVP_PKEY_keygen(peer_ctx, &peer_pkey);
        EVP_PKEY_CTX_free(peer_ctx);

        openssl_ecdh_time = run_benchmark(
            "ECDH Key Agreement",
            "OpenSSL",
            [&]() { return benchmark_openssl_ecdh(pkey, peer_pkey); }
        );

        // Native implementation
        {
            uint8_t random1[32], random2[32];
            generate_random(random1, 32);
            generate_random(random2, 32);
            
            kctsb_native::EcdsaKeyPair our_kp, peer_kp;
            kctsb_native::ecdsa_keygen(&our_kp, random1, curve.native_id);
            kctsb_native::ecdsa_keygen(&peer_kp, random2, curve.native_id);
            
            kctsb_ecdh_time = run_benchmark(
                "ECDH Key Agreement",
                "kctsb",
                [&]() {
                    auto start = Clock::now();
                    uint8_t shared_secret[32];
                    kctsb_native::ecdh_compute(shared_secret, &our_kp.private_key,
                                               &peer_kp.public_key, curve.native_id);
                    auto end = Clock::now();
                    return Duration(end - start).count();
                }
            );
            print_ratio(kctsb_ecdh_time, openssl_ecdh_time);
        }

        // Cleanup
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peer_pkey);

        std::cout << std::endl;
    }

    // Summary note
    std::cout << "\n  Note: kctsb ECC uses NATIVE fe256 implementation (zero NTL dependency).\n";
    std::cout << "  All operations use constant-time Montgomery ladder.\n";
    std::cout << "  OpenSSL uses optimized ASM with platform-specific acceleration.\n";
    std::cout << "  Ratio > 1.0 = kctsb faster, Ratio < 1.0 = OpenSSL faster.\n";
}

// External declaration for benchmark main
extern void benchmark_ecc();

