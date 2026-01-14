/**
 * @file benchmark_ecc.cpp
 * @brief ECC Performance Benchmark: kctsb vs OpenSSL
 *
 * Benchmarks elliptic curve operations:
 * - Key generation (secp256k1, secp256r1, secp384r1)
 * - ECDSA sign/verify operations
 * - ECDH key agreement
 * - Point multiplication
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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// kctsb ECC headers (conditional)
#ifdef KCTSB_HAS_ECC
#include "kctsb/crypto/ecc/ecdsa.h"
#include "kctsb/crypto/ecc/ecdh.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
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
 * @brief Generate random bytes
 */
static void generate_random(uint8_t* buf, size_t len) {
    RAND_bytes(buf, static_cast<int>(len));
}

/**
 * @brief Curve configurations for testing
 */
struct CurveConfig {
    int nid;
    const char* name;
    size_t key_bits;
#ifdef KCTSB_HAS_ECC
    kctsb::ecc::CurveType kctsb_type;
#endif
};

static const CurveConfig TEST_CURVES[] = {
#ifdef KCTSB_HAS_ECC
    {NID_secp256k1, "secp256k1", 256, kctsb::ecc::CurveType::SECP256K1},
    {NID_X9_62_prime256v1, "secp256r1 (P-256)", 256, kctsb::ecc::CurveType::SECP256R1},
    {NID_secp384r1, "secp384r1 (P-384)", 384, kctsb::ecc::CurveType::SECP384R1},
#else
    {NID_secp256k1, "secp256k1", 256},
    {NID_X9_62_prime256v1, "secp256r1 (P-256)", 256},
    {NID_secp384r1, "secp384r1 (P-384)", 384},
#endif
};

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
    (void)ret;  // Suppress unused warning

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

/**
 * @brief Run benchmark iterations and print results
 */
static void run_benchmark(
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

    // Calculate statistics
    double avg = std::accumulate(times.begin(), times.end(), 0.0) / times.size();
    double min_time = *std::min_element(times.begin(), times.end());
    (void)*std::max_element(times.begin(), times.end()); // max_time for future use
    double ops_per_sec = 1000.0 / avg;

    std::cout << std::left << std::setw(30) << name
              << std::setw(12) << impl
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(10) << avg << " ms"
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
    std::cout << std::left << std::setw(30) << "Operation"
              << std::setw(12) << "Impl"
              << std::right << std::setw(12) << "Avg"
              << std::setw(10) << "Min"
              << std::setw(12) << "Throughput"
              << std::endl;
    std::cout << std::string(75, '-') << std::endl;
}

/**
 * @brief Main ECC benchmark function
 */
void benchmark_ecc() {
    std::cout << "\n" << std::string(75, '=') << std::endl;
    std::cout << "  Elliptic Curve Cryptography (ECC) Benchmark" << std::endl;
    std::cout << std::string(75, '=') << std::endl;

    // Generate test hash
    uint8_t hash[HASH_SIZE];
    generate_random(hash, HASH_SIZE);

    for (const auto& curve : TEST_CURVES) {
        print_header(curve.name);

        // ================================================================
        // Key Generation Benchmark
        // ================================================================
        run_benchmark(
            "Key Generation",
            "OpenSSL",
            [&]() { return benchmark_openssl_ec_keygen(curve.nid); }
        );

#ifdef KCTSB_HAS_ECC
        // kctsb ECDSA Key Generation
        run_benchmark(
            "Key Generation",
            "kctsb",
            [&curve]() {
                kctsb::ecc::ECDSA ecdsa(curve.kctsb_type);
                auto keypair = ecdsa.generate_keypair();
                return keypair.is_valid(ecdsa.get_curve()) ? 1.0 : 0.0;
            }
        );
#endif

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
        run_benchmark(
            "ECDSA Sign",
            "OpenSSL",
            [&]() { return benchmark_openssl_ecdsa_sign(pkey, hash); }
        );

#ifdef KCTSB_HAS_ECC
        // kctsb ECDSA Sign
        {
            kctsb::ecc::ECDSA ecdsa(curve.kctsb_type);
            auto kctsb_keypair = ecdsa.generate_keypair();
            run_benchmark(
                "ECDSA Sign",
                "kctsb",
                [&ecdsa, &kctsb_keypair, &hash]() {
                    auto sig = ecdsa.sign(hash, HASH_SIZE, kctsb_keypair.private_key);
                    return sig.is_valid(ecdsa.get_curve().get_order()) ? 1.0 : 0.0;
                }
            );
        }
#endif

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
        run_benchmark(
            "ECDSA Verify",
            "OpenSSL",
            [&]() {
                return benchmark_openssl_ecdsa_verify(pkey, hash,
                    signature.data(), sig_len);
            }
        );

#ifdef KCTSB_HAS_ECC
        // kctsb ECDSA Verify
        {
            kctsb::ecc::ECDSA ecdsa(curve.kctsb_type);
            auto kctsb_keypair = ecdsa.generate_keypair();
            auto kctsb_sig = ecdsa.sign(hash, HASH_SIZE, kctsb_keypair.private_key);
            run_benchmark(
                "ECDSA Verify",
                "kctsb",
                [&ecdsa, &kctsb_keypair, &kctsb_sig, &hash]() {
                    bool valid = ecdsa.verify(hash, HASH_SIZE,
                                             kctsb_sig, kctsb_keypair.public_key);
                    return valid ? 1.0 : 0.0;
                }
            );
        }
#endif

        // ================================================================
        // ECDH Key Agreement Benchmark
        // ================================================================
        // Generate peer key pair
        EVP_PKEY_CTX* peer_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY* peer_pkey = nullptr;
        EVP_PKEY_keygen_init(peer_ctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(peer_ctx, curve.nid);
        EVP_PKEY_keygen(peer_ctx, &peer_pkey);
        EVP_PKEY_CTX_free(peer_ctx);

        run_benchmark(
            "ECDH Key Agreement",
            "OpenSSL",
            [&]() { return benchmark_openssl_ecdh(pkey, peer_pkey); }
        );

#ifdef KCTSB_HAS_ECC
        // kctsb ECDH Key Agreement
        {
            kctsb::ecc::ECDH ecdh(curve.kctsb_type);
            auto our_keypair = ecdh.generate_keypair();
            auto peer_keypair = ecdh.generate_keypair();
            run_benchmark(
                "ECDH Key Agreement",
                "kctsb",
                [&ecdh, &our_keypair, &peer_keypair]() {
                    auto secret = ecdh.compute_shared_secret(
                        our_keypair.private_key, peer_keypair.public_key);
                    return secret.empty() ? 0.0 : 1.0;
                }
            );
        }
#endif

        // Cleanup
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peer_pkey);

        std::cout << std::endl;
    }

    // Summary
    std::cout << "\n  Note: kctsb ECC implementation uses NTL backend.\n";
    std::cout << "  OpenSSL results shown as baseline reference.\n";
}

// Declare external benchmark entry
extern void benchmark_ecc();
