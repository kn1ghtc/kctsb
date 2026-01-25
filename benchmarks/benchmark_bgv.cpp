/**
 * @file benchmark_bgv.cpp
 * @brief BGV Homomorphic Encryption Industry Benchmark (Pure RNS API)
 * 
 * Standard benchmark using n=8192 for industry comparison with SEAL and HElib.
 * Uses the Pure RNS API which requires no NTL dependency.
 * 
 * Key Design Decisions:
 * - n=8192 is the industry standard for 128-bit security comparisons
 * - Pure RNS implementation for maximum portability
 * - Ratio output format: SEAL_time / kctsb_time (higher is better for kctsb)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.12.0
 */

#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
#include <random>

// kctsb BGV Pure RNS API
#include "kctsb/advanced/fe/bgv/bgv.hpp"

// Optional: SEAL for comparison
#ifdef KCTSB_HAS_SEAL
#include <seal/seal.h>
#endif

using namespace std::chrono;
using namespace kctsb::fhe::bgv;

// ============================================================================
// Industry Standard Parameters (n=8192, 128-bit security)
// ============================================================================

constexpr size_t INDUSTRY_POLY_DEGREE = 8192;
constexpr size_t BENCHMARK_ITERATIONS = 10;
constexpr size_t WARMUP_ITERATIONS = 3;
constexpr uint64_t PLAINTEXT_MODULUS = 65537;  // Standard plaintext modulus

// ============================================================================
// Benchmark Result Structure
// ============================================================================

struct BenchmarkResult {
    std::string operation;
    double kctsb_ms;
    double seal_ms;
    double helib_ms;
    
    // Ratio: SEAL / kctsb (higher = kctsb faster)
    double speedup_vs_seal() const {
        return (kctsb_ms > 0 && seal_ms > 0) ? seal_ms / kctsb_ms : 0;
    }
    
    double speedup_vs_helib() const {
        return (kctsb_ms > 0 && helib_ms > 0) ? helib_ms / kctsb_ms : 0;
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
    for (size_t i = 0; i < warmup; i++) {
        func();
    }
    
    // Benchmark
    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; i++) {
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

void print_result(const std::string& name, double time_ms, 
                  double seal_time_ms = 0, double helib_time_ms = 0) {
    double ops_per_sec = 1000.0 / time_ms;
    
    std::cout << std::left << std::setw(35) << name 
              << std::right << std::setw(10) << std::fixed << std::setprecision(3) 
              << time_ms << " ms"
              << std::setw(10) << std::fixed << std::setprecision(1) 
              << ops_per_sec << " ops/s";
    
    // Show speedup if reference available (SEAL_time / kctsb_time)
    if (seal_time_ms > 0) {
        double speedup = seal_time_ms / time_ms;
        std::cout << "  [vs SEAL: " << std::setprecision(2) << speedup << "x faster]";
    }
    if (helib_time_ms > 0) {
        double speedup = helib_time_ms / time_ms;
        std::cout << "  [vs HElib: " << std::setprecision(2) << speedup << "x faster]";
    }
    
    std::cout << "\n";
}

void print_comparison_table() {
    print_header("Performance Comparison Summary (Speedup: reference / kctsb)");
    
    std::cout << std::left << std::setw(25) << "Operation"
              << std::right << std::setw(12) << "kctsb (ms)"
              << std::setw(12) << "SEAL (ms)"
              << std::setw(10) << "Speedup"
              << "\n";
    std::cout << std::string(60, '-') << "\n";
    
    for (const auto& r : g_results) {
        std::cout << std::left << std::setw(25) << r.operation
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
    
    std::cout << std::string(60, '-') << "\n";
    std::cout << "Speedup > 1.0 means kctsb is faster than reference\n";
}

// ============================================================================
// kctsb BGV Benchmarks (Pure RNS API)
// ============================================================================

void benchmark_kctsb_bgv() {
    print_header("kctsb Native BGV Benchmarks (Pure RNS, n=8192)");
    
    // Create RNS context using n=8192 for industry standard comparison
    auto ctx = StandardParams::SECURITY_128_N8192();
    
    std::cout << "Parameters:\n";
    std::cout << "  Ring degree (n):      " << ctx->n() << "\n";
    std::cout << "  Number of primes (L): " << ctx->level_count() << "\n";
    std::cout << "  Plaintext modulus (t):" << PLAINTEXT_MODULUS << "\n";
    std::cout << "  Security level:       128-bit classical\n";
    std::cout << "  Benchmark iterations: " << BENCHMARK_ITERATIONS << "\n";
    std::cout << "\n";
    
    // Create evaluator
    BGVEvaluator evaluator(ctx.get(), PLAINTEXT_MODULUS);
    std::mt19937_64 rng(42);  // Fixed seed for reproducibility
    
    // =========================================================================
    // Key Generation Benchmarks
    // =========================================================================
    std::cout << "--- Key Generation ---\n";
    
    double sk_time = benchmark_op([&]() {
        auto sk = evaluator.generate_secret_key(rng);
    });
    print_result("Secret key generation", sk_time);
    
    auto sk = evaluator.generate_secret_key(rng);
    
    double pk_time = benchmark_op([&]() {
        auto pk = evaluator.generate_public_key(sk, rng);
    });
    print_result("Public key generation", pk_time);
    
    auto pk = evaluator.generate_public_key(sk, rng);
    
    double rk_time = benchmark_op([&]() {
        auto rk = evaluator.generate_relin_key(sk, rng);
    }, 1, 3);  // Fewer iterations - slower operation
    print_result("Relin key generation", rk_time);
    
    auto rk = evaluator.generate_relin_key(sk, rng);
    
    double keygen_total = sk_time + pk_time;
    g_results.push_back({"KeyGen (SK+PK)", keygen_total, 0, 0});
    g_results.push_back({"Relin key gen", rk_time, 0, 0});
    
    // =========================================================================
    // Encryption/Decryption Benchmarks
    // =========================================================================
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    // Create test plaintext (single integer for simplicity)
    // BGVPlaintext is std::vector<uint64_t>, not a struct
    BGVPlaintext pt1(ctx->n(), 0);
    pt1[0] = 7;  // Constant polynomial = 7
    
    double enc_time = benchmark_op([&]() {
        auto ct = evaluator.encrypt(pt1, pk, rng);
    });
    print_result("Encrypt", enc_time);
    g_results.push_back({"Encrypt", enc_time, 0, 0});
    
    auto ct1 = evaluator.encrypt(pt1, pk, rng);
    
    double dec_time = benchmark_op([&]() {
        auto pt = evaluator.decrypt(ct1, sk);
    });
    print_result("Decrypt", dec_time);
    g_results.push_back({"Decrypt", dec_time, 0, 0});
    
    // =========================================================================
    // Homomorphic Operations
    // =========================================================================
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    // Prepare second ciphertext
    BGVPlaintext pt2(ctx->n(), 0);
    pt2[0] = 6;  // Constant polynomial = 6
    auto ct2 = evaluator.encrypt(pt2, pk, rng);
    
    double add_time = benchmark_op([&]() {
        auto ct_sum = evaluator.add(ct1, ct2);
    });
    print_result("Ciphertext add", add_time);
    g_results.push_back({"Add", add_time, 0, 0});
    
    double sub_time = benchmark_op([&]() {
        auto ct_sub = evaluator.sub(ct1, ct2);
    });
    print_result("Ciphertext sub", sub_time);
    
    double mul_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply(ct1, ct2);
    }, 1, 5);
    print_result("Ciphertext multiply (no relin)", mul_time);
    g_results.push_back({"Multiply", mul_time, 0, 0});
    
    // Multiply and relinearize
    auto ct_prod = evaluator.multiply(ct1, ct2);
    double relin_time = benchmark_op([&]() {
        auto ct_prod_copy = ct_prod;
        evaluator.relinearize_inplace(ct_prod_copy, rk);
    }, 1, 5);
    print_result("Relinearize", relin_time);
    
    double mul_relin_time = mul_time + relin_time;
    print_result("Multiply + Relinearize (total)", mul_relin_time);
    g_results.push_back({"Mul + Relin", mul_relin_time, 0, 0});
    
    // =========================================================================
    // Correctness Verification
    // =========================================================================
    std::cout << "\n--- Correctness Verification ---\n";
    
    // Test addition: 7 + 6 = 13
    auto ct_sum = evaluator.add(ct1, ct2);
    auto pt_sum = evaluator.decrypt(ct_sum, sk);
    bool add_correct = (pt_sum[0] == 13);
    std::cout << "Addition (7 + 6 = 13): " << (add_correct ? "PASS" : "FAIL");
    if (!add_correct) {
        std::cout << " (got " << pt_sum[0] << ")";
    }
    std::cout << "\n";
    
    // Test multiplication WITHOUT relinearization first
    auto ct_mul_norelin = evaluator.multiply(ct1, ct2);
    auto pt_mul_norelin = evaluator.decrypt(ct_mul_norelin, sk);
    bool mul_norelin_correct = (pt_mul_norelin[0] == 42);
    std::cout << "Multiply (no relin): " << (mul_norelin_correct ? "PASS" : "FAIL");
    if (!mul_norelin_correct) {
        std::cout << " (got " << pt_mul_norelin[0] << ")";
    }
    std::cout << "\n";
    
    // Debug: verify key switching key correctness
    // ksk0 + ksk1*s should equal s^2 (mod t)
    {
        kctsb::fhe::RNSPoly test = rk.ksk0[0] + (rk.ksk1[0] * sk.s);
        kctsb::fhe::RNSPoly s2 = sk.s * sk.s;
        
        // Convert to coefficient domain
        test.intt_transform();
        kctsb::fhe::RNSPoly s2_coeff = s2;
        s2_coeff.intt_transform();
        
        // Check difference mod t
        uint64_t q0 = ctx->modulus(0).value();
        const uint64_t* test_data = test.data(0);
        const uint64_t* s2_data = s2_coeff.data(0);
        
        bool ksk_correct = true;
        for (size_t i = 0; i < 10 && ksk_correct; ++i) {
            int64_t d1 = static_cast<int64_t>(test_data[i]);
            int64_t d2 = static_cast<int64_t>(s2_data[i]);
            if (d1 > static_cast<int64_t>(q0/2)) d1 -= q0;
            if (d2 > static_cast<int64_t>(q0/2)) d2 -= q0;
            int64_t diff = d1 - d2;
            if (diff < 0) diff = -diff;
            // diff should be a multiple of t (noise * t)
            // For small noise, diff should be small * t < some bound
            if (diff > 1000 * static_cast<int64_t>(PLAINTEXT_MODULUS)) {
                ksk_correct = false;
            }
        }
        std::cout << "KSK correctness: " << (ksk_correct ? "PASS" : "FAIL") << "\n";
    }
    
    // Test multiplication: 7 * 6 = 42 (with relinearization)
    auto ct_mul = evaluator.multiply(ct1, ct2);
    evaluator.relinearize_inplace(ct_mul, rk);
    auto pt_mul = evaluator.decrypt(ct_mul, sk);
    bool mul_correct = (pt_mul[0] == 42);
    std::cout << "Multiplication (7 * 6 = 42): " << (mul_correct ? "PASS" : "FAIL");
    if (!mul_correct) {
        std::cout << " (got " << pt_mul[0] << ")";
    }
    std::cout << "\n";
    
    // Summary
    std::cout << "\n--- Summary ---\n";
    std::cout << "API Version: Pure RNS (v4.12.0)\n";
    std::cout << "NTL Dependency: None\n";
}

// ============================================================================
// SEAL Comparison (if available)
// ============================================================================

#ifdef KCTSB_HAS_SEAL
void benchmark_seal_bgv() {
    print_header("Microsoft SEAL BGV Benchmarks (Reference)");
    
    using namespace seal;
    
    // Create context with industry standard n=8192
    EncryptionParameters parms(scheme_type::bgv);
    parms.set_poly_modulus_degree(INDUSTRY_POLY_DEGREE);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(INDUSTRY_POLY_DEGREE));
    parms.set_plain_modulus(PlainModulus::Batching(INDUSTRY_POLY_DEGREE, 20));
    
    SEALContext context(parms);
    
    std::cout << "Parameters:\n";
    std::cout << "  poly_modulus_degree: " << INDUSTRY_POLY_DEGREE << "\n";
    std::cout << "  plain_modulus:       " << parms.plain_modulus().value() << "\n";
    std::cout << "\n";
    
    KeyGenerator keygen(context);
    
    // Key generation
    std::cout << "--- Key Generation ---\n";
    
    double sk_time = benchmark_op([&]() {
        SecretKey sk = keygen.secret_key();
    });
    print_result("Secret key", sk_time);
    
    SecretKey sk = keygen.secret_key();
    
    double pk_time = benchmark_op([&]() {
        PublicKey pk;
        keygen.create_public_key(pk);
    });
    print_result("Public key", pk_time);
    
    double keygen_total = sk_time + pk_time;
    
    PublicKey pk;
    keygen.create_public_key(pk);
    
    double rk_time = benchmark_op([&]() {
        RelinKeys rk;
        keygen.create_relin_keys(rk);
    }, 1, 3);
    print_result("Relin keys", rk_time);
    
    RelinKeys rk;
    keygen.create_relin_keys(rk);
    
    // Update SEAL times in results
    for (auto& r : g_results) {
        if (r.operation == "KeyGen (SK+PK)") r.seal_ms = keygen_total;
        if (r.operation == "Relin key gen") r.seal_ms = rk_time;
    }
    
    // Encryption benchmarks
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    BatchEncoder encoder(context);
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    
    std::vector<uint64_t> pod_vector(encoder.slot_count(), 7);
    Plaintext plain;
    encoder.encode(pod_vector, plain);
    
    double enc_time = benchmark_op([&]() {
        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
    });
    print_result("Encrypt", enc_time);
    
    Ciphertext ct1;
    encryptor.encrypt(plain, ct1);
    
    double dec_time = benchmark_op([&]() {
        Plaintext decrypted;
        decryptor.decrypt(ct1, decrypted);
    });
    print_result("Decrypt", dec_time);
    
    for (auto& r : g_results) {
        if (r.operation == "Encrypt") r.seal_ms = enc_time;
        if (r.operation == "Decrypt") r.seal_ms = dec_time;
    }
    
    // Homomorphic operations
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    Evaluator evaluator(context);
    
    std::vector<uint64_t> pod_vector2(encoder.slot_count(), 6);
    Plaintext plain2;
    encoder.encode(pod_vector2, plain2);
    Ciphertext ct2;
    encryptor.encrypt(plain2, ct2);
    
    double add_time = benchmark_op([&]() {
        Ciphertext result;
        evaluator.add(ct1, ct2, result);
    });
    print_result("Ciphertext add", add_time);
    
    double mul_time = benchmark_op([&]() {
        Ciphertext result;
        evaluator.multiply(ct1, ct2, result);
    }, 1, 5);
    print_result("Ciphertext multiply", mul_time);
    
    Ciphertext ct_mul;
    evaluator.multiply(ct1, ct2, ct_mul);
    
    double relin_time = benchmark_op([&]() {
        Ciphertext result = ct_mul;
        evaluator.relinearize_inplace(result, rk);
    }, 1, 5);
    print_result("Relinearize", relin_time);
    
    for (auto& r : g_results) {
        if (r.operation == "Add") r.seal_ms = add_time;
        if (r.operation == "Multiply") r.seal_ms = mul_time;
        if (r.operation == "Mul + Relin") r.seal_ms = mul_time + relin_time;
    }
}
#endif

// ============================================================================
// Main Entry Point
// ============================================================================

int main() {
    std::cout << "================================================================\n";
    std::cout << "  kctsb FHE Performance Benchmark (BGV Scheme)\n";
    std::cout << "  Version: v4.12.0 (Pure RNS)\n";
    std::cout << "================================================================\n";
    
    // Run kctsb benchmarks
    benchmark_kctsb_bgv();
    
#ifdef KCTSB_HAS_SEAL
    // Run SEAL benchmarks for comparison
    benchmark_seal_bgv();
    
    // Print comparison table
    print_comparison_table();
#else
    std::cout << "\n[Note: SEAL not available for comparison]\n";
    std::cout << "[Build with -DKCTSB_ENABLE_SEAL=ON for comparison benchmarks]\n";
#endif
    
    std::cout << "\nBenchmark completed.\n";
    return 0;
}
