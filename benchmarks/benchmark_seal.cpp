/**
 * @file benchmark_seal.cpp
 * @brief kctsb vs Microsoft SEAL 4.1.2 Homomorphic Encryption Comparison
 *
 * Compares:
 *   - BFV: KeyGen, Encrypt, Decrypt, Add, Multiply, Relinearize
 *   - CKKS: KeyGen, Encrypt, Decrypt, Add, Multiply, Rescale
 *
 * Status: kctsb FHE public API not yet exported to kctsb_api.h
 * This benchmark shows SEAL reference performance only.
 *
 * Dependencies:
 *   - SEAL 4.1.2: thirdparty/win-x64/lib/libseal-4.1.a
 *   - SEAL headers: thirdparty/win-x64/include/SEAL-4.1/
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifdef BENCHMARK_HAS_SEAL

#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include <cmath>

#include "benchmark_common.hpp"

// SEAL headers
#include <seal/seal.h>

namespace {

// ============================================================================
// Helper: Create SEAL BFV Context
// ============================================================================

seal::SEALContext create_seal_bfv_context(
    size_t poly_modulus_degree,
    int coeff_modulus_count)
{
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, 20));
    return seal::SEALContext(parms);
}

// ============================================================================
// Helper: Create SEAL CKKS Context
// ============================================================================

seal::SEALContext create_seal_ckks_context(
    size_t poly_modulus_degree,
    int /* coeff_modulus_count */)
{
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // CKKS: Use SEAL's pre-defined coefficient modulus for simplicity
    // This ensures valid parameters for the security level
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
    return seal::SEALContext(parms);
}

// ============================================================================
// BFV Benchmark (SEAL Reference Only)
// ============================================================================

void benchmark_bfv_seal_only() {
    std::cout << "\n--- BFV Scheme (SEAL Reference Only) ---\n";
    std::cout << "Note: kctsb FHE public API not yet available\n\n";
    
    benchmark::print_table_header();
    
    struct TestParams {
        size_t poly_modulus_degree;
        int coeff_modulus_count;
        std::string name;
    };
    
    std::vector<TestParams> params_list = {
        {4096, 2, "n=4096 L=2"},
        {8192, 3, "n=8192 L=3"},
    };
    
    for (const auto& params : params_list) {
        auto context = create_seal_bfv_context(params.poly_modulus_degree, params.coeff_modulus_count);
        
        // ============ KeyGen ============
        {
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::KeyGenerator keygen(context);
                auto sk = keygen.secret_key();
                seal::PublicKey pk;
                keygen.create_public_key(pk);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                timer.start();
                seal::KeyGenerator keygen(context);
                auto sk = keygen.secret_key();
                seal::PublicKey pk;
                keygen.create_public_key(pk);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"BFV KeyGen " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"BFV KeyGen " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
        
        // ============ Encrypt ============
        {
            seal::KeyGenerator keygen(context);
            seal::SecretKey sk = keygen.secret_key();
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            seal::Encryptor encryptor(context, pk);
            seal::BatchEncoder encoder(context);
            
            std::vector<uint64_t> plain_data(encoder.slot_count(), 42);
            seal::Plaintext plain;
            encoder.encode(plain_data, plain);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext ct;
                encryptor.encrypt(plain, ct);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext ct;
                timer.start();
                encryptor.encrypt(plain, ct);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"BFV Encrypt " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"BFV Encrypt " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
        
        // ============ Add ============
        {
            seal::KeyGenerator keygen(context);
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            seal::Encryptor encryptor(context, pk);
            seal::Evaluator evaluator(context);
            seal::BatchEncoder encoder(context);
            
            std::vector<uint64_t> plain_data(encoder.slot_count(), 42);
            seal::Plaintext plain;
            encoder.encode(plain_data, plain);
            
            seal::Ciphertext ct1, ct2;
            encryptor.encrypt(plain, ct1);
            encryptor.encrypt(plain, ct2);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext result;
                evaluator.add(ct1, ct2, result);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext result;
                timer.start();
                evaluator.add(ct1, ct2, result);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"BFV Add " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"BFV Add " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
        
        // ============ Multiply ============
        {
            seal::KeyGenerator keygen(context);
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            seal::Encryptor encryptor(context, pk);
            seal::Evaluator evaluator(context);
            seal::BatchEncoder encoder(context);
            
            std::vector<uint64_t> plain_data(encoder.slot_count(), 3);
            seal::Plaintext plain;
            encoder.encode(plain_data, plain);
            
            seal::Ciphertext ct1, ct2;
            encryptor.encrypt(plain, ct1);
            encryptor.encrypt(plain, ct2);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext result;
                evaluator.multiply(ct1, ct2, result);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext result;
                timer.start();
                evaluator.multiply(ct1, ct2, result);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"BFV Multiply " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"BFV Multiply " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
    }
}

// ============================================================================
// CKKS Benchmark (SEAL Reference Only)
// ============================================================================

void benchmark_ckks_seal_only() {
    std::cout << "\n--- CKKS Scheme (SEAL Reference Only) ---\n";
    std::cout << "Note: kctsb FHE public API not yet available\n\n";
    
    benchmark::print_table_header();
    
    struct TestParams {
        size_t poly_modulus_degree;
        int coeff_modulus_count;
        std::string name;
    };
    
    std::vector<TestParams> params_list = {
        {4096, 2, "n=4096 L=2"},
        {8192, 3, "n=8192 L=3"},
    };
    
    for (const auto& params : params_list) {
        auto context = create_seal_ckks_context(params.poly_modulus_degree, params.coeff_modulus_count);
        // Use smaller scale to allow multiply without overflow
        // For n=4096 with BFVDefault, total bit count is ~109, so scale^2 must fit
        double scale = std::pow(2.0, 20);
        
        // ============ KeyGen ============
        {
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::KeyGenerator keygen(context);
                auto sk = keygen.secret_key();
                seal::PublicKey pk;
                keygen.create_public_key(pk);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                timer.start();
                seal::KeyGenerator keygen(context);
                auto sk = keygen.secret_key();
                seal::PublicKey pk;
                keygen.create_public_key(pk);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"CKKS KeyGen " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"CKKS KeyGen " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
        
        // ============ Encrypt ============
        {
            seal::KeyGenerator keygen(context);
            seal::SecretKey sk = keygen.secret_key();
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            seal::Encryptor encryptor(context, pk);
            seal::CKKSEncoder encoder(context);
            
            size_t slot_count = encoder.slot_count();
            std::vector<double> input(slot_count, 1.5);
            
            seal::Plaintext plain;
            encoder.encode(input, scale, plain);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext ct;
                encryptor.encrypt(plain, ct);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext ct;
                timer.start();
                encryptor.encrypt(plain, ct);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"CKKS Encrypt " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"CKKS Encrypt " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
        
        // ============ Add ============
        {
            seal::KeyGenerator keygen(context);
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            seal::Encryptor encryptor(context, pk);
            seal::Evaluator evaluator(context);
            seal::CKKSEncoder encoder(context);
            
            std::vector<double> input(encoder.slot_count(), 1.5);
            seal::Plaintext plain;
            encoder.encode(input, scale, plain);
            
            seal::Ciphertext ct1, ct2;
            encryptor.encrypt(plain, ct1);
            encryptor.encrypt(plain, ct2);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext result;
                evaluator.add(ct1, ct2, result);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext result;
                timer.start();
                evaluator.add(ct1, ct2, result);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"CKKS Add " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"CKKS Add " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
        
        // ============ Multiply ============
        {
            seal::KeyGenerator keygen(context);
            seal::PublicKey pk;
            keygen.create_public_key(pk);
            seal::Encryptor encryptor(context, pk);
            seal::Evaluator evaluator(context);
            seal::CKKSEncoder encoder(context);
            
            std::vector<double> input(encoder.slot_count(), 1.5);
            seal::Plaintext plain;
            encoder.encode(input, scale, plain);
            
            seal::Ciphertext ct1, ct2;
            encryptor.encrypt(plain, ct1);
            encryptor.encrypt(plain, ct2);
            
            benchmark::Timer timer;
            double seal_total = 0;
            
            for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
                seal::Ciphertext result;
                evaluator.multiply(ct1, ct2, result);
            }
            
            for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
                seal::Ciphertext result;
                timer.start();
                evaluator.multiply(ct1, ct2, result);
                seal_total += timer.stop();
            }
            
            double seal_avg = seal_total / benchmark::BENCHMARK_ITERATIONS;
            benchmark::print_result({"CKKS Multiply " + params.name, "SEAL", seal_avg, 0, 0, benchmark::BENCHMARK_ITERATIONS});
            benchmark::print_result({"CKKS Multiply " + params.name, "kctsb", 0, 0, 0, 0});
            std::cout << "  kctsb: NOT YET IMPLEMENTED\n\n";
        }
    }
}

} // anonymous namespace

// ============================================================================
// Export function
// ============================================================================

void run_seal_benchmarks() {
    std::cout << "\n=== SEAL 4.1.2 Homomorphic Encryption Comparison ===\n";
    std::cout << "Status: kctsb FHE public API not yet exported to kctsb_api.h\n";
    std::cout << "This benchmark shows SEAL reference performance only.\n";
    std::cout << "\n";
    std::cout << "To enable full comparison:\n";
    std::cout << "  1. Add FHE C API to kctsb_api.h\n";
    std::cout << "  2. Update this benchmark with kctsb FHE calls\n";
    std::cout << "\n";
    std::cout << "Iterations: " << benchmark::BENCHMARK_ITERATIONS
              << " (warmup: " << benchmark::WARMUP_ITERATIONS << ")\n";
    
    benchmark_bfv_seal_only();
    benchmark_ckks_seal_only();
    
    std::cout << "\nSEAL benchmarks complete.\n";
}

#endif // BENCHMARK_HAS_SEAL
