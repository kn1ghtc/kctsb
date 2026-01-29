/**
 * @file benchmark_seal.cpp
 * @brief kctsb BFV vs Microsoft SEAL 4.1.2 Homomorphic Encryption Comparison
 *
 * Compares BFV scheme operations:
 *   - KeyGen: Key pair generation
 *   - Encrypt: Public key encryption
 *   - Add: Homomorphic addition
 *   - Multiply: Homomorphic multiplication
 *
 * Parameter Sets (128-bit security, 60-bit primes):
 *   - n=8192,  L=3: Basic FHE (3-level depth)
 *   - n=16384, L=5: Medium FHE (5-level depth)
 *   - n=32768, L=8: Deep FHE (8-level depth)
 *
 * Uses only kctsb_api.h public API for kctsb.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */


#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include <cmath>

#include "benchmark_common.hpp"

// kctsb public API ONLY
#include "kctsb/kctsb_api.h"

// SEAL headers
#include <seal/seal.h>

namespace {

// ============================================================================
// SEAL Context Factory - 128-bit Security, 60-bit Primes
// ============================================================================

/**
 * @brief Create SEAL BFV context with 128-bit security
 * Uses 60-bit NTT-friendly primes
 */
seal::SEALContext create_seal_bfv_context(size_t n, size_t num_primes)
{
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(n);
    
    // Generate 60-bit NTT-friendly primes
    std::vector<int> bit_sizes(num_primes, 60);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(n, bit_sizes));
    
    // Plain modulus for batching
    parms.set_plain_modulus(seal::PlainModulus::Batching(n, 20));
    
    return seal::SEALContext(parms);
}

// ============================================================================
// BFV Benchmark: kctsb vs SEAL
// ============================================================================

void benchmark_bfv_comparison() {
    std::cout << "\n--- BFV Scheme Comparison (128-bit Security) ---\n";
    std::cout << "Parameters: 60-bit NTT-friendly primes\n\n";
    
    benchmark::print_table_header();
    
    struct TestParams {
        uint32_t log_n;           // log2(n)
        size_t n;                 // Polynomial degree
        uint32_t num_primes;      // Number of RNS primes (L+1)
        std::string name;
    };
    
    // 128-bit security parameter sets
    std::vector<TestParams> params_list = {
        {13, 8192,  3, "n=8192 L=3"},
        {14, 16384, 5, "n=16384 L=5"},
        {15, 32768, 8, "n=32768 L=8"},
    };
    
    for (const auto& params : params_list) {
        std::cout << "\n=== " << params.name << " ===\n";
        
        // Create SEAL context
        auto seal_context = create_seal_bfv_context(params.n, params.num_primes);
        
        // Create kctsb context
        auto kctsb_ctx = kctsb_bfv_create_context(params.log_n, params.num_primes);
        bool kctsb_available = (kctsb_ctx != nullptr);
        
        // ============ KeyGen ============
        {
            benchmark::Timer timer;
            double seal_total = 0;
            double kctsb_total = 0;
            
            // SEAL warmup & benchmark
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::KeyGenerator keygen(seal_context);
                (void)keygen.secret_key();
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                timer.start();
                seal::KeyGenerator keygen(seal_context);
                seal::PublicKey pk;
                keygen.create_public_key(pk);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({
                "BFV KeyGen " + params.name, "SEAL",
                seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
            });
            
            // kctsb benchmark
            if (kctsb_available) {
                for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                    kctsb_bfv_secret_key_t sk = nullptr;
                    kctsb_bfv_public_key_t pk = nullptr;
                    kctsb_bfv_keygen(kctsb_ctx, &sk, &pk);
                    kctsb_bfv_destroy_secret_key(sk);
                    kctsb_bfv_destroy_public_key(pk);
                }
                
                for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                    kctsb_bfv_secret_key_t sk = nullptr;
                    kctsb_bfv_public_key_t pk = nullptr;
                    timer.start();
                    kctsb_bfv_keygen(kctsb_ctx, &sk, &pk);
                    kctsb_total += timer.stop();
                    kctsb_bfv_destroy_secret_key(sk);
                    kctsb_bfv_destroy_public_key(pk);
                }
                
                double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
                benchmark::print_result({
                    "BFV KeyGen " + params.name, "kctsb",
                    kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
                });
                
                double ratio = kctsb_avg / seal_avg;
                std::cout << "  Ratio: " << std::fixed << std::setprecision(2)
                          << ratio << "x (" << benchmark::get_status(ratio) << ")\n\n";
            } else {
                benchmark::print_result({
                    "BFV KeyGen " + params.name, "kctsb",
                    0, 0, 0, 0
                });
                std::cout << "  kctsb: Context creation failed\n\n";
            }
        }
        
        // ============ Encrypt ============
        {
            // SEAL setup
            seal::KeyGenerator seal_keygen(seal_context);
            seal::SecretKey seal_sk = seal_keygen.secret_key();
            seal::PublicKey seal_pk;
            seal_keygen.create_public_key(seal_pk);
            seal::Encryptor seal_encryptor(seal_context, seal_pk);
            seal::BatchEncoder seal_encoder(seal_context);
            
            std::vector<uint64_t> plain_data(seal_encoder.slot_count(), 42);
            seal::Plaintext seal_plain;
            seal_encoder.encode(plain_data, seal_plain);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext ct;
                seal_encryptor.encrypt(seal_plain, ct);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext ct;
                timer.start();
                seal_encryptor.encrypt(seal_plain, ct);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({
                "BFV Encrypt " + params.name, "SEAL",
                seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
            });
            
            // kctsb benchmark
            if (kctsb_available) {
                kctsb_bfv_secret_key_t kctsb_sk = nullptr;
                kctsb_bfv_public_key_t kctsb_pk = nullptr;
                kctsb_bfv_keygen(kctsb_ctx, &kctsb_sk, &kctsb_pk);
                
                auto kctsb_pt = kctsb_bfv_create_plaintext(kctsb_ctx, 42);
                
                double kctsb_total = 0;
                
                for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                    kctsb_bfv_ciphertext_t ct = nullptr;
                    kctsb_bfv_encrypt(kctsb_ctx, kctsb_pk, kctsb_pt, &ct);
                    kctsb_bfv_destroy_ciphertext(ct);
                }
                
                for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                    kctsb_bfv_ciphertext_t ct = nullptr;
                    timer.start();
                    kctsb_bfv_encrypt(kctsb_ctx, kctsb_pk, kctsb_pt, &ct);
                    kctsb_total += timer.stop();
                    kctsb_bfv_destroy_ciphertext(ct);
                }
                
                double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
                benchmark::print_result({
                    "BFV Encrypt " + params.name, "kctsb",
                    kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
                });
                
                double ratio = kctsb_avg / seal_avg;
                std::cout << "  Ratio: " << std::fixed << std::setprecision(2)
                          << ratio << "x (" << benchmark::get_status(ratio) << ")\n\n";
                
                kctsb_bfv_destroy_plaintext(kctsb_pt);
                kctsb_bfv_destroy_secret_key(kctsb_sk);
                kctsb_bfv_destroy_public_key(kctsb_pk);
            } else {
                benchmark::print_result({
                    "BFV Encrypt " + params.name, "kctsb",
                    0, 0, 0, 0
                });
                std::cout << "  kctsb: Not available\n\n";
            }
        }
        
        // ============ Add ============
        {
            // SEAL setup
            seal::KeyGenerator seal_keygen(seal_context);
            seal::PublicKey seal_pk;
            seal_keygen.create_public_key(seal_pk);
            seal::Encryptor seal_encryptor(seal_context, seal_pk);
            seal::Evaluator seal_evaluator(seal_context);
            seal::BatchEncoder seal_encoder(seal_context);
            
            std::vector<uint64_t> plain_data(seal_encoder.slot_count(), 42);
            seal::Plaintext seal_plain;
            seal_encoder.encode(plain_data, seal_plain);
            
            seal::Ciphertext seal_ct1, seal_ct2;
            seal_encryptor.encrypt(seal_plain, seal_ct1);
            seal_encryptor.encrypt(seal_plain, seal_ct2);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext result;
                seal_evaluator.add(seal_ct1, seal_ct2, result);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext result;
                timer.start();
                seal_evaluator.add(seal_ct1, seal_ct2, result);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({
                "BFV Add " + params.name, "SEAL",
                seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
            });
            
            // kctsb benchmark
            if (kctsb_available) {
                kctsb_bfv_secret_key_t kctsb_sk = nullptr;
                kctsb_bfv_public_key_t kctsb_pk = nullptr;
                kctsb_bfv_keygen(kctsb_ctx, &kctsb_sk, &kctsb_pk);
                
                auto kctsb_pt = kctsb_bfv_create_plaintext(kctsb_ctx, 42);
                kctsb_bfv_ciphertext_t kctsb_ct1 = nullptr;
                kctsb_bfv_ciphertext_t kctsb_ct2 = nullptr;
                kctsb_bfv_encrypt(kctsb_ctx, kctsb_pk, kctsb_pt, &kctsb_ct1);
                kctsb_bfv_encrypt(kctsb_ctx, kctsb_pk, kctsb_pt, &kctsb_ct2);
                
                double kctsb_total = 0;
                
                for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                    kctsb_bfv_ciphertext_t result = nullptr;
                    kctsb_bfv_add(kctsb_ctx, kctsb_ct1, kctsb_ct2, &result);
                    kctsb_bfv_destroy_ciphertext(result);
                }
                
                for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                    kctsb_bfv_ciphertext_t result = nullptr;
                    timer.start();
                    kctsb_bfv_add(kctsb_ctx, kctsb_ct1, kctsb_ct2, &result);
                    kctsb_total += timer.stop();
                    kctsb_bfv_destroy_ciphertext(result);
                }
                
                double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
                benchmark::print_result({
                    "BFV Add " + params.name, "kctsb",
                    kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
                });
                
                double ratio = kctsb_avg / seal_avg;
                std::cout << "  Ratio: " << std::fixed << std::setprecision(2)
                          << ratio << "x (" << benchmark::get_status(ratio) << ")\n\n";
                
                kctsb_bfv_destroy_ciphertext(kctsb_ct1);
                kctsb_bfv_destroy_ciphertext(kctsb_ct2);
                kctsb_bfv_destroy_plaintext(kctsb_pt);
                kctsb_bfv_destroy_secret_key(kctsb_sk);
                kctsb_bfv_destroy_public_key(kctsb_pk);
            } else {
                benchmark::print_result({
                    "BFV Add " + params.name, "kctsb",
                    0, 0, 0, 0
                });
                std::cout << "  kctsb: Not available\n\n";
            }
        }
        
        // ============ Multiply ============
        {
            // SEAL setup
            seal::KeyGenerator seal_keygen(seal_context);
            seal::PublicKey seal_pk;
            seal_keygen.create_public_key(seal_pk);
            seal::Encryptor seal_encryptor(seal_context, seal_pk);
            seal::Evaluator seal_evaluator(seal_context);
            seal::BatchEncoder seal_encoder(seal_context);
            
            std::vector<uint64_t> plain_data(seal_encoder.slot_count(), 3);
            seal::Plaintext seal_plain;
            seal_encoder.encode(plain_data, seal_plain);
            
            seal::Ciphertext seal_ct1, seal_ct2;
            seal_encryptor.encrypt(seal_plain, seal_ct1);
            seal_encryptor.encrypt(seal_plain, seal_ct2);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext result;
                seal_evaluator.multiply(seal_ct1, seal_ct2, result);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext result;
                timer.start();
                seal_evaluator.multiply(seal_ct1, seal_ct2, result);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({
                "BFV Multiply " + params.name, "SEAL",
                seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
            });
            
            // kctsb benchmark
            if (kctsb_available) {
                kctsb_bfv_secret_key_t kctsb_sk = nullptr;
                kctsb_bfv_public_key_t kctsb_pk = nullptr;
                kctsb_bfv_keygen(kctsb_ctx, &kctsb_sk, &kctsb_pk);
                
                auto kctsb_pt = kctsb_bfv_create_plaintext(kctsb_ctx, 3);
                kctsb_bfv_ciphertext_t kctsb_ct1 = nullptr;
                kctsb_bfv_ciphertext_t kctsb_ct2 = nullptr;
                kctsb_bfv_encrypt(kctsb_ctx, kctsb_pk, kctsb_pt, &kctsb_ct1);
                kctsb_bfv_encrypt(kctsb_ctx, kctsb_pk, kctsb_pt, &kctsb_ct2);
                
                double kctsb_total = 0;
                
                for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                    kctsb_bfv_ciphertext_t result = nullptr;
                    kctsb_bfv_multiply(kctsb_ctx, kctsb_ct1, kctsb_ct2, &result);
                    kctsb_bfv_destroy_ciphertext(result);
                }
                
                for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                    kctsb_bfv_ciphertext_t result = nullptr;
                    timer.start();
                    kctsb_bfv_multiply(kctsb_ctx, kctsb_ct1, kctsb_ct2, &result);
                    kctsb_total += timer.stop();
                    kctsb_bfv_destroy_ciphertext(result);
                }
                
                double kctsb_avg = kctsb_total / benchmark::BENCHMARK_ITERATIONS;
                benchmark::print_result({
                    "BFV Multiply " + params.name, "kctsb",
                    kctsb_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS
                });
                
                double ratio = kctsb_avg / seal_avg;
                std::cout << "  Ratio: " << std::fixed << std::setprecision(2)
                          << ratio << "x (" << benchmark::get_status(ratio) << ")\n\n";
                
                kctsb_bfv_destroy_ciphertext(kctsb_ct1);
                kctsb_bfv_destroy_ciphertext(kctsb_ct2);
                kctsb_bfv_destroy_plaintext(kctsb_pt);
                kctsb_bfv_destroy_secret_key(kctsb_sk);
                kctsb_bfv_destroy_public_key(kctsb_pk);
            } else {
                benchmark::print_result({
                    "BFV Multiply " + params.name, "kctsb",
                    0, 0, 0, 0
                });
                std::cout << "  kctsb: Not available\n\n";
            }
        }
        
        // Cleanup kctsb context
        if (kctsb_ctx) {
            kctsb_bfv_destroy_context(kctsb_ctx);
        }
    }
}

}  // anonymous namespace

// ============================================================================
// Export function
// ============================================================================

void run_seal_benchmarks() {
    std::cout << "\n=== SEAL 4.1.2 vs kctsb BFV Comparison ===\n";
    std::cout << "Security: 128-bit (Lattice Estimator)\n";
    std::cout << "Primes: 60-bit NTT-friendly\n";
    std::cout << "Iterations: " << benchmark::BENCHMARK_ITERATIONS
              << " (warmup: " << benchmark::WARMUP_ITERATIONS << ")\n";
    
    benchmark_bfv_comparison();
    
    std::cout << "\nSEAL benchmarks complete.\n";
}