/**
 * @file test_bgv_benchmark.cpp
 * @brief BGV Performance Benchmark Tests (n=32768)
 * 
 * Internal performance testing using large polynomial degree n=32768.
 * For industry comparison with SEAL/HElib, use benchmarks/benchmark_bgv.cpp with n=8192.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <gtest/gtest.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <vector>
#include <numeric>

#include "kctsb/advanced/fe/bgv/bgv.hpp"

namespace {

using namespace std::chrono;
using namespace kctsb::fhe::bgv;

// ============================================================================
// Benchmark Utilities
// ============================================================================

struct BenchResult {
    std::string operation;
    double time_ms;
    double ops_per_sec;
    size_t iterations;
};

template<typename Func>
double run_benchmark(Func&& func, size_t warmup = 3, size_t iterations = 10) {
    // Warmup phase
    for (size_t i = 0; i < warmup; i++) {
        func();
    }
    
    // Measurement phase
    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; i++) {
        func();
    }
    auto end = high_resolution_clock::now();
    
    return duration_cast<microseconds>(end - start).count() / 1000.0 / 
           static_cast<double>(iterations);
}

void print_result(const std::string& op, double time_ms, 
                  const std::string& target = "") {
    double ops_per_sec = 1000.0 / time_ms;
    std::cout << std::left << std::setw(40) << op
              << std::right << std::setw(12) << std::fixed << std::setprecision(3)
              << time_ms << " ms"
              << std::setw(14) << std::fixed << std::setprecision(1)
              << ops_per_sec << " ops/s";
    if (!target.empty()) {
        std::cout << "  [" << target << "]";
    }
    std::cout << "\n";
}

// ============================================================================
// BGV Benchmark Test Fixtures
// ============================================================================

class BGVBenchmarkTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::cout << "\n";
        std::cout << "===================================================================\n";
        std::cout << "  kctsb BGV Internal Benchmark (n=32768 for production testing)\n";
        std::cout << "===================================================================\n";
        std::cout << "\n";
        std::cout << "Note: For industry comparison with SEAL/HElib, run:\n";
        std::cout << "      benchmarks/benchmark_bgv.exe (uses n=8192)\n";
        std::cout << "\n";
    }
};

// ============================================================================
// Test: TOY_PARAMS Benchmark (n=256, for quick validation)
// ============================================================================

TEST_F(BGVBenchmarkTest, ToyParams_QuickBenchmark) {
    std::cout << "--- TOY_PARAMS (n=256) Quick Benchmark ---\n";
    
    auto params = StandardParams::TOY_PARAMS();
    BGVContext context(params);
    
    std::cout << "  Ring degree (n): " << context.ring_degree() << "\n";
    std::cout << "  Plaintext modulus (t): " << context.plaintext_modulus() << "\n";
    std::cout << "\n";
    
    // Key generation
    auto sk = context.generate_secret_key();
    auto pk = context.generate_public_key(sk);
    auto rk = context.generate_relin_key(sk);
    
    BGVEncoder encoder(context);
    BGVEvaluator evaluator(context);
    
    // Prepare test data
    std::vector<int64_t> data1(context.slot_count());
    std::vector<int64_t> data2(context.slot_count());
    std::iota(data1.begin(), data1.end(), 1);
    std::iota(data2.begin(), data2.end(), 100);
    
    auto pt1 = encoder.encode_batch(data1);
    auto pt2 = encoder.encode_batch(data2);
    auto ct1 = context.encrypt(pk, pt1);
    auto ct2 = context.encrypt(pk, pt2);
    
    // Benchmark operations
    double encrypt_time = run_benchmark([&]() {
        auto ct = context.encrypt(pk, pt1);
    });
    print_result("Encrypt", encrypt_time);
    
    double decrypt_time = run_benchmark([&]() {
        auto pt = context.decrypt(sk, ct1);
    });
    print_result("Decrypt", decrypt_time);
    
    double add_time = run_benchmark([&]() {
        auto ct_sum = evaluator.add(ct1, ct2);
    });
    print_result("Ciphertext addition", add_time);
    
    double mul_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct1, ct2);
    }, 1, 5);
    print_result("Ciphertext multiplication", mul_time);
    
    double mul_relin_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply_relin(ct1, ct2, rk);
    }, 1, 5);
    print_result("Multiply + relinearize", mul_relin_time);
    
    std::cout << "\n";
    
    // Verify correctness
    auto ct_sum = evaluator.add(ct1, ct2);
    auto pt_result = context.decrypt(sk, ct_sum);
    auto values = encoder.decode_batch(pt_result);
    
    bool correct = true;
    for (size_t i = 0; i < std::min(size_t(5), data1.size()); i++) {
        int64_t expected = (data1[i] + data2[i]) % context.plaintext_modulus();
        if (values[i] != expected) {
            correct = false;
            break;
        }
    }
    
    EXPECT_TRUE(correct) << "Addition correctness check failed";
}

// ============================================================================
// Test: SECURITY_128_DEPTH_3 Benchmark (n=4096)
// ============================================================================

TEST_F(BGVBenchmarkTest, Security128Depth3_Benchmark) {
    std::cout << "--- SECURITY_128_DEPTH_3 (n=4096) Benchmark ---\n";
    
    auto params = StandardParams::SECURITY_128_DEPTH_3();
    BGVContext context(params);
    
    std::cout << "  Ring degree (n): " << context.ring_degree() << "\n";
    std::cout << "  Plaintext modulus (t): " << context.plaintext_modulus() << "\n";
    std::cout << "\n";
    
    // Key generation timing
    double sk_time = run_benchmark([&]() {
        auto sk = context.generate_secret_key();
    });
    print_result("Secret key generation", sk_time);
    
    auto sk = context.generate_secret_key();
    
    double pk_time = run_benchmark([&]() {
        auto pk = context.generate_public_key(sk);
    });
    print_result("Public key generation", pk_time);
    
    auto pk = context.generate_public_key(sk);
    
    double rk_time = run_benchmark([&]() {
        auto rk = context.generate_relin_key(sk);
    }, 1, 3);
    print_result("Relinearization key generation", rk_time);
    
    auto rk = context.generate_relin_key(sk);
    
    // Encoder and evaluator
    BGVEncoder encoder(context);
    BGVEvaluator evaluator(context);
    
    // Prepare test data
    std::vector<int64_t> data(context.slot_count());
    std::iota(data.begin(), data.end(), 1);
    
    auto pt = encoder.encode_batch(data);
    auto ct = context.encrypt(pk, pt);
    
    // Operation benchmarks
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    double add_time = run_benchmark([&]() {
        auto ct_sum = evaluator.add(ct, ct);
    });
    print_result("Addition", add_time, "< 0.3 ms target");
    
    double mul_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct, ct);
    }, 1, 5);
    print_result("Multiplication", mul_time, "< 100 ms target");
    
    double mul_relin_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply_relin(ct, ct, rk);
    }, 1, 5);
    print_result("Multiply + Relinearize", mul_relin_time);
    
    // Noise budget
    std::cout << "\n--- Noise Budget ---\n";
    double fresh_budget = context.noise_budget(sk, ct);
    std::cout << "Fresh ciphertext: " << std::fixed << std::setprecision(1) 
              << fresh_budget << " bits\n";
    
    auto ct_prod = evaluator.multiply_relin(ct, ct, rk);
    double after_mul = context.noise_budget(sk, ct_prod);
    std::cout << "After multiplication: " << after_mul << " bits\n";
    
    std::cout << "\n";
    
    // Performance assertions
    EXPECT_LT(add_time, 1.0) << "Addition should be < 1 ms";
}

// ============================================================================
// Test: Large Polynomial Degree (n=8192, industry standard)
// ============================================================================

TEST_F(BGVBenchmarkTest, IndustryStandard_N8192) {
    std::cout << "--- Industry Standard (n=8192) for SEAL Comparison ---\n";
    std::cout << "Note: This matches SEAL default parameters\n\n";
    
    auto params = StandardParams::SECURITY_128_DEPTH_5();
    // Adjust to n=8192 explicitly
    BGVContext context(params);
    
    std::cout << "  Ring degree (n): " << context.ring_degree() << "\n";
    std::cout << "  Security level: 128-bit\n";
    std::cout << "\n";
    
    // Key generation
    auto sk = context.generate_secret_key();
    auto pk = context.generate_public_key(sk);
    auto rk = context.generate_relin_key(sk);
    
    BGVEncoder encoder(context);
    BGVEvaluator evaluator(context);
    
    std::vector<int64_t> data(context.slot_count());
    std::iota(data.begin(), data.end(), 1);
    
    auto pt = encoder.encode_batch(data);
    auto ct = context.encrypt(pk, pt);
    
    // Benchmark all operations
    std::cout << "--- Key Generation ---\n";
    
    double keygen_time = run_benchmark([&]() {
        auto temp_sk = context.generate_secret_key();
        auto temp_pk = context.generate_public_key(temp_sk);
    }, 1, 3);
    print_result("KeyGen (SK + PK)", keygen_time, "SEAL: ~50 ms");
    
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    double enc_time = run_benchmark([&]() {
        auto temp_ct = context.encrypt(pk, pt);
    });
    print_result("Encrypt", enc_time, "SEAL: ~5 ms");
    
    double dec_time = run_benchmark([&]() {
        auto temp_pt = context.decrypt(sk, ct);
    });
    print_result("Decrypt", dec_time);
    
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    double add_time = run_benchmark([&]() {
        auto ct_sum = evaluator.add(ct, ct);
    });
    print_result("Add", add_time, "SEAL: ~0.1 ms");
    
    double mul_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct, ct);
    }, 1, 3);
    print_result("Multiply", mul_time, "SEAL: ~10 ms");
    
    double relin_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct, ct);
        evaluator.relinearize_inplace(ct_prod, rk);
    }, 1, 3);
    print_result("Multiply + Relin", relin_time, "SEAL: ~18 ms");
    
    std::cout << "\n";
}

}  // namespace
