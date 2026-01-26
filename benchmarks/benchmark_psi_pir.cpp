/**
 * @file benchmark_psi_pir.cpp
 * @brief PSI/PIR Performance Benchmark - kctsb vs SEAL Comparison
 * 
 * @details Comprehensive performance comparison:
 * - Piano-PSI (O(√n) communication) - Large-scale balanced datasets
 * - OT-PSI (IKNP Extension) - Malicious security, small-medium datasets
 * - Native-PIR vs SEAL-PIR (BGV/CKKS)
 * 
 * SEAL integration: Links prebuilt static library only (no source dependency)
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include <random>
#include <cmath>
#include <sstream>

// kctsb Native PSI/PIR
#include "kctsb/advanced/psi/psi.h"
#include "kctsb/advanced/psi/ot_psi.h"
// Native PIR disabled - API not yet implemented in v5.0
// #include "kctsb/advanced/psi/native_pir.h"
#define KCTSB_DISABLE_NATIVE_PIR 1

// Optional: SEAL for comparison (prebuilt library only)
#ifdef KCTSB_HAS_SEAL
#include <seal/seal.h>
#endif

using namespace std::chrono;

// ============================================================================
// Benchmark Parameters
// ============================================================================

constexpr size_t BENCHMARK_ITERATIONS = 10;
constexpr size_t WARMUP_ITERATIONS = 3;

// ============================================================================
// Benchmark Result Structure
// ============================================================================

struct BenchmarkResult {
    std::string operation;
    double kctsb_ms;
    double seal_ms;
    
    double speedup_vs_seal() const {
        return (kctsb_ms > 0 && seal_ms > 0) ? seal_ms / kctsb_ms : 0;
    }
};

std::vector<BenchmarkResult> g_results;

// ============================================================================
// Benchmark Utilities
// ============================================================================

template<typename Func>
double benchmark_op(Func&& func, size_t warmup = WARMUP_ITERATIONS, 
                    size_t iterations = BENCHMARK_ITERATIONS) {
    // Warmup
    for (size_t i = 0; i < warmup; ++i) {
        func();
    }
    
    // Benchmark
    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        func();
    }
    auto end = high_resolution_clock::now();
    
    return duration_cast<microseconds>(end - start).count() / 1000.0 / 
           static_cast<double>(iterations);
}

void print_header(const std::string& title) {
    std::cout << "\n";
    std::cout << "===================================================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "===================================================================\n";
}

void print_result(const std::string& name, double time_ms) {
    std::cout << std::left << std::setw(35) << name 
              << std::right << std::setw(12) << std::fixed << std::setprecision(3) 
              << time_ms << " ms"
              << "\n";
}

void print_comparison(const std::string& name, double kctsb_ms, double seal_ms) {
    double speedup = (kctsb_ms > 0 && seal_ms > 0) ? seal_ms / kctsb_ms : 0;
    std::cout << std::left << std::setw(35) << name 
              << std::right << std::setw(10) << std::fixed << std::setprecision(3) 
              << kctsb_ms << " ms"
              << std::setw(10) << seal_ms << " ms"
              << std::setw(10) << std::setprecision(2) << speedup << "x"
              << "\n";
}

// ============================================================================
// Test Data Generation
// ============================================================================

void generate_datasets(size_t client_size, size_t server_size,
                       std::vector<int64_t>& client, std::vector<int64_t>& server) {
    std::mt19937_64 rng(12345);
    std::uniform_int_distribution<int64_t> dist(1, 1000000);
    
    client.resize(client_size);
    server.resize(server_size);
    
    for (auto& v : client) v = dist(rng);
    for (auto& v : server) v = dist(rng);
    
    // Add 20% overlap
    size_t overlap = client_size / 5;
    for (size_t i = 0; i < overlap && i < server_size; ++i) {
        server[i] = client[i];
    }
}

// ============================================================================
// Piano-PSI Benchmarks
// ============================================================================

void benchmark_piano_psi() {
    print_header("Piano-PSI Benchmarks (O(sqrt n) Communication)");
    std::cout << "Use case: Large-scale balanced datasets, semi-honest security\n\n";
    
    std::vector<std::pair<size_t, size_t>> dataset_sizes = {
        {100, 100},
        {1000, 1000},
    };
    
    for (const auto& sizes : dataset_sizes) {
        size_t client_size = sizes.first;
        size_t server_size = sizes.second;
        
        std::vector<int64_t> client, server;
        generate_datasets(client_size, server_size, client, server);
        
        kctsb_psi_config_t config;
        kctsb_psi_config_init(&config);
        kctsb_psi_ctx_t* ctx = kctsb_piano_psi_create(&config);
        
        if (!ctx) {
            std::cout << "  [Piano-PSI " << client_size << "x" << server_size << "] FAILED to create context\n";
            continue;
        }
        
        double time_ms = benchmark_op([&]() {
            kctsb_psi_result_t result;
            kctsb_piano_psi_compute(ctx, client.data(), client.size(),
                                   server.data(), server.size(), &result);
        }, 2, 5);
        
        std::ostringstream name;
        name << "Piano-PSI " << client_size << "x" << server_size;
        print_result(name.str(), time_ms);
        g_results.push_back({name.str(), time_ms, 0});
        
        kctsb_piano_psi_destroy(ctx);
    }
}

// ============================================================================
// OT-PSI Benchmarks
// ============================================================================

void benchmark_ot_psi() {
    print_header("OT-PSI Benchmarks (IKNP Extension)");
    std::cout << "Use case: Small-medium datasets, malicious security support\n\n";
    
    std::vector<std::pair<size_t, size_t>> dataset_sizes = {
        {100, 100},
        {1000, 1000},
    };
    
    for (const auto& sizes : dataset_sizes) {
        size_t client_size = sizes.first;
        size_t server_size = sizes.second;
        
        std::vector<int64_t> client, server;
        generate_datasets(client_size, server_size, client, server);
        
        kctsb_ot_psi_config_t config;
        kctsb_ot_psi_config_init(&config, KCTSB_OT_EXTENSION);
        kctsb_ot_psi_ctx_t* ctx = kctsb_ot_psi_create(&config);
        
        if (!ctx) {
            std::cout << "  [OT-PSI " << client_size << "x" << server_size << "] FAILED to create context\n";
            continue;
        }
        
        double time_ms = benchmark_op([&]() {
            kctsb_ot_psi_result_t result;
            kctsb_ot_psi_compute(ctx, client.data(), client.size(),
                                server.data(), server.size(), &result);
            kctsb_ot_psi_result_free(&result);
        }, 2, 5);
        
        std::ostringstream name;
        name << "OT-PSI " << client_size << "x" << server_size;
        print_result(name.str(), time_ms);
        g_results.push_back({name.str(), time_ms, 0});
        
        kctsb_ot_psi_destroy(ctx);
    }
}

// ============================================================================
// Native PIR Benchmarks
// ============================================================================

#ifndef KCTSB_DISABLE_NATIVE_PIR
void benchmark_native_pir() {
    print_header("Native PIR Benchmarks (kctsb BGV/CKKS)");
    
    std::vector<size_t> db_sizes = {100, 1000};
    
    for (size_t db_size : db_sizes) {
        // BGV Integer Database
        {
            std::vector<int64_t> database(db_size);
            for (size_t i = 0; i < db_size; ++i) database[i] = static_cast<int64_t>(i * 10);
            
            kctsb_native_pir_config_t config;
            kctsb_native_pir_config_init(&config, KCTSB_PIR_BGV, db_size);
            kctsb_native_pir_ctx_t* ctx = kctsb_native_pir_create_int(&config, database.data(), db_size);
            
            if (!ctx) {
                std::cout << "  [Native PIR BGV DB=" << db_size << "] FAILED to create context\n";
                continue;
            }
            
            double time_ms = benchmark_op([&]() {
                kctsb_native_pir_result_t result;
                kctsb_native_pir_query(ctx, db_size / 2, &result);
                kctsb_native_pir_result_free(&result);
            }, 2, 5);
            
            std::ostringstream name;
            name << "Native PIR BGV DB=" << db_size;
            print_result(name.str(), time_ms);
            g_results.push_back({name.str(), time_ms, 0});
            
            kctsb_native_pir_destroy(ctx);
        }
        
        // CKKS Double Database
        {
            std::vector<double> database(db_size);
            for (size_t i = 0; i < db_size; ++i) database[i] = i * 1.5;
            
            kctsb_native_pir_config_t config;
            kctsb_native_pir_config_init(&config, KCTSB_PIR_CKKS, db_size);
            kctsb_native_pir_ctx_t* ctx = kctsb_native_pir_create_double(&config, database.data(), db_size);
            
            if (!ctx) {
                std::cout << "  [Native PIR CKKS DB=" << db_size << "] FAILED to create context\n";
                continue;
            }
            
            double time_ms = benchmark_op([&]() {
                kctsb_native_pir_result_t result;
                kctsb_native_pir_query(ctx, db_size / 2, &result);
                kctsb_native_pir_result_free(&result);
            }, 2, 5);
            
            std::ostringstream name;
            name << "Native PIR CKKS DB=" << db_size;
            print_result(name.str(), time_ms);
            g_results.push_back({name.str(), time_ms, 0});
            
            kctsb_native_pir_destroy(ctx);
        }
    }
}
#endif // KCTSB_DISABLE_NATIVE_PIR

// ============================================================================
// SEAL PIR Benchmarks (Reference)
// ============================================================================

#ifdef KCTSB_HAS_SEAL
void benchmark_seal_pir() {
    print_header("Microsoft SEAL PIR Benchmarks (Reference)");
    
    using namespace seal;
    
    // CKKS PIR Implementation for comparison
    std::vector<size_t> db_sizes = {100, 1000};
    
    for (size_t db_size : db_sizes) {
        try {
            // Create SEAL context
            EncryptionParameters parms(scheme_type::ckks);
            size_t poly_modulus_degree = 8192;
            parms.set_poly_modulus_degree(poly_modulus_degree);
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 40, 40, 50}));
            
            SEALContext context(parms);
            
            // Generate keys
            KeyGenerator keygen(context);
            auto secret_key = keygen.secret_key();
            PublicKey public_key;
            keygen.create_public_key(public_key);
            RelinKeys relin_keys;
            keygen.create_relin_keys(relin_keys);
            
            CKKSEncoder encoder(context);
            Encryptor encryptor(context, public_key);
            Evaluator evaluator(context);
            Decryptor decryptor(context, secret_key);
            
            double scale = std::pow(2.0, 40);
            size_t slot_count = encoder.slot_count();
            
            // Create database
            std::vector<double> database(db_size);
            for (size_t i = 0; i < db_size; ++i) database[i] = i * 1.5;
            
            // Encode and encrypt database
            std::vector<double> db_batch(slot_count, 0.0);
            for (size_t i = 0; i < std::min(db_size, slot_count); ++i) {
                db_batch[i] = database[i];
            }
            Plaintext db_plain;
            encoder.encode(db_batch, scale, db_plain);
            Ciphertext db_encrypted;
            encryptor.encrypt(db_plain, db_encrypted);
            
            size_t target_index = db_size / 2;
            
            // Benchmark PIR query
            double time_ms = benchmark_op([&]() {
                // Generate selection vector
                std::vector<double> selection(slot_count, 0.0);
                if (target_index < slot_count) selection[target_index] = 1.0;
                
                Plaintext selection_plain;
                encoder.encode(selection, scale, selection_plain);
                Ciphertext selection_encrypted;
                encryptor.encrypt(selection_plain, selection_encrypted);
                
                // Server processing
                Ciphertext result_encrypted;
                evaluator.multiply(db_encrypted, selection_encrypted, result_encrypted);
                evaluator.relinearize_inplace(result_encrypted, relin_keys);
                
                // Decrypt
                Plaintext decrypted_plain;
                decryptor.decrypt(result_encrypted, decrypted_plain);
                std::vector<double> decoded_result;
                encoder.decode(decrypted_plain, decoded_result);
            }, 2, 5);
            
            std::ostringstream name;
            name << "SEAL PIR CKKS DB=" << db_size;
            print_result(name.str(), time_ms);
            
            // Update corresponding kctsb results
            std::string target_op = "Native PIR CKKS DB=" + std::to_string(db_size);
            for (auto& r : g_results) {
                if (r.operation == target_op) {
                    r.seal_ms = time_ms;
                }
            }
            
        } catch (const std::exception& e) {
            std::cout << "  [SEAL PIR DB=" << db_size << "] Exception: " << e.what() << "\n";
        }
    }
}
#endif

// ============================================================================
// Comparison Summary
// ============================================================================

void print_comparison_table() {
    print_header("Performance Comparison Summary");
    
    std::cout << std::left << std::setw(35) << "Operation"
              << std::right << std::setw(12) << "kctsb (ms)"
              << std::setw(12) << "SEAL (ms)"
              << std::setw(10) << "Speedup"
              << "\n";
    std::cout << std::string(70, '-') << "\n";
    
    for (const auto& r : g_results) {
        std::cout << std::left << std::setw(35) << r.operation
                  << std::right << std::setw(12) << std::fixed << std::setprecision(3) 
                  << r.kctsb_ms;
        
        if (r.seal_ms > 0) {
            std::cout << std::setw(12) << r.seal_ms
                      << std::setw(10) << std::setprecision(2) << r.speedup_vs_seal() << "x";
        } else {
            std::cout << std::setw(12) << "N/A" << std::setw(10) << "-";
        }
        
        std::cout << "\n";
    }
    
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Speedup > 1.0 means kctsb is faster than reference\n";
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    std::cout << "================================================================\n";
    std::cout << "  kctsb PSI/PIR Performance Benchmark\n";
    std::cout << "  Version: v4.14.0\n";
    std::cout << "================================================================\n";
    
    // Run kctsb PSI benchmarks
    benchmark_piano_psi();
    benchmark_ot_psi();
    
    // Run kctsb PIR benchmarks (disabled in v5.0 - API not implemented)
#ifndef KCTSB_DISABLE_NATIVE_PIR
    benchmark_native_pir();
#else
    std::cout << "\n[Note: Native PIR benchmarks disabled in v5.0]\n";
#endif
    
#ifdef KCTSB_HAS_SEAL
    // Run SEAL PIR benchmarks for comparison
    benchmark_seal_pir();
    
    // Print comparison table
    print_comparison_table();
#else
    std::cout << "\n[Note: SEAL not available for comparison]\n";
    std::cout << "[Build with -DKCTSB_HAS_SEAL=1 for comparison benchmarks]\n";
#endif
    
    std::cout << "\nBenchmark completed.\n";
    return 0;
}
