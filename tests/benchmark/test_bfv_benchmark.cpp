/**
 * @file test_bfv_benchmark.cpp
 * @brief BFV Homomorphic Encryption Performance Benchmark
 * 
 * Benchmarks BFV operations and compares with BGV.
 * Reference values from SEAL 4.1 for comparison.
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

#include "kctsb/advanced/fe/bfv/bfv.hpp"
#include "kctsb/advanced/fe/bgv/bgv.hpp"

namespace {

using namespace kctsb::fhe::bfv;
namespace bgv = kctsb::fhe::bgv;

// ============================================================================
// Utility Functions
// ============================================================================

template<typename Func>
double measure_ms(Func&& f, int iterations = 1) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        f();
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    return elapsed.count() / iterations;
}

void print_separator() {
    std::cout << std::string(70, '=') << "\n";
}

void print_benchmark_header(const std::string& title) {
    print_separator();
    std::cout << title << "\n";
    print_separator();
}

// ============================================================================
// BFV Benchmark Tests
// ============================================================================

class BFVBenchmarkTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::cout << std::fixed << std::setprecision(3);
    }
};

// Test: TOY_PARAMS Benchmark (n=256, for quick validation)
TEST_F(BFVBenchmarkTest, ToyParamsBenchmark) {
    print_benchmark_header("BFV TOY_PARAMS (n=256) Quick Benchmark");
    
    auto params = StandardParams::TOY_PARAMS();
    std::cout << "Parameters: n=" << params.n 
              << ", t=" << params.t 
              << ", L=" << params.L << "\n\n";
    
    BFVContext ctx(params);
    BFVEncoder encoder(ctx);
    BFVEvaluator evaluator(ctx);
    
    // Key Generation
    double keygen_time = measure_ms([&]() {
        auto sk = ctx.generate_secret_key();
        auto pk = ctx.generate_public_key(sk);
        auto rk = ctx.generate_relin_key(sk);
    }, 3);
    std::cout << "KeyGen (SK+PK+RK): " << keygen_time << " ms\n";
    
    // Generate keys for other tests
    auto sk = ctx.generate_secret_key();
    auto pk = ctx.generate_public_key(sk);
    auto rk = ctx.generate_relin_key(sk);
    
    // Encryption
    auto pt = encoder.encode(42);
    double encrypt_time = measure_ms([&]() {
        auto ct = ctx.encrypt(pk, pt);
    }, 10);
    std::cout << "Encrypt: " << encrypt_time << " ms\n";
    
    // Decryption
    auto ct = ctx.encrypt(pk, pt);
    double decrypt_time = measure_ms([&]() {
        auto decrypted = ctx.decrypt(sk, ct);
    }, 10);
    std::cout << "Decrypt: " << decrypt_time << " ms\n";
    
    // Addition
    auto ct1 = ctx.encrypt(pk, encoder.encode(10));
    auto ct2 = ctx.encrypt(pk, encoder.encode(20));
    double add_time = measure_ms([&]() {
        auto result = evaluator.add(ct1, ct2);
    }, 100);
    std::cout << "Add: " << add_time << " ms\n";
    
    // Multiplication
    double mult_time = measure_ms([&]() {
        auto result = evaluator.multiply(ct1, ct2);
    }, 5);
    std::cout << "Multiply: " << mult_time << " ms\n";
    
    // Multiply + Relinearize
    double mult_relin_time = measure_ms([&]() {
        auto result = evaluator.multiply_relin(ct1, ct2, rk);
    }, 3);
    std::cout << "Multiply+Relin: " << mult_relin_time << " ms\n";
    
    std::cout << "\n";
}

// Test: SECURITY_128 Benchmark (n=8192, production-level)
TEST_F(BFVBenchmarkTest, Security128Benchmark) {
    print_benchmark_header("BFV SECURITY_128 (n=8192) Production Benchmark");
    
    auto params = StandardParams::SECURITY_128();
    std::cout << "Parameters: n=" << params.n 
              << ", t=" << params.t 
              << ", L=" << params.L 
              << ", log2(q)=" << kctsb::NumBits(params.q) << "\n\n";
    
    BFVContext ctx(params);
    BFVEncoder encoder(ctx);
    BFVEvaluator evaluator(ctx);
    
    // Key Generation
    std::cout << "Benchmarking KeyGen... ";
    std::cout.flush();
    double keygen_time = measure_ms([&]() {
        auto sk = ctx.generate_secret_key();
        auto pk = ctx.generate_public_key(sk);
    });
    std::cout << keygen_time << " ms\n";
    
    // Generate keys for other tests
    auto sk = ctx.generate_secret_key();
    auto pk = ctx.generate_public_key(sk);
    
    std::cout << "Benchmarking Relin Key Gen... ";
    std::cout.flush();
    double relinkey_time = measure_ms([&]() {
        auto rk = ctx.generate_relin_key(sk);
    });
    std::cout << relinkey_time << " ms\n";
    
    auto rk = ctx.generate_relin_key(sk);
    
    // Encryption
    auto pt = encoder.encode(42);
    std::cout << "Benchmarking Encrypt... ";
    std::cout.flush();
    double encrypt_time = measure_ms([&]() {
        auto ct = ctx.encrypt(pk, pt);
    }, 3);
    std::cout << encrypt_time << " ms\n";
    
    // Decryption
    auto ct = ctx.encrypt(pk, pt);
    std::cout << "Benchmarking Decrypt... ";
    std::cout.flush();
    double decrypt_time = measure_ms([&]() {
        auto decrypted = ctx.decrypt(sk, ct);
    }, 3);
    std::cout << decrypt_time << " ms\n";
    
    // Addition
    auto ct1 = ctx.encrypt(pk, encoder.encode(10));
    auto ct2 = ctx.encrypt(pk, encoder.encode(20));
    std::cout << "Benchmarking Add... ";
    std::cout.flush();
    double add_time = measure_ms([&]() {
        auto result = evaluator.add(ct1, ct2);
    }, 10);
    std::cout << add_time << " ms\n";
    
    // Multiplication
    std::cout << "Benchmarking Multiply... ";
    std::cout.flush();
    double mult_time = measure_ms([&]() {
        auto result = evaluator.multiply(ct1, ct2);
    });
    std::cout << mult_time << " ms\n";
    
    // Multiply + Relinearize
    std::cout << "Benchmarking Multiply+Relin... ";
    std::cout.flush();
    double mult_relin_time = measure_ms([&]() {
        auto result = evaluator.multiply_relin(ct1, ct2, rk);
    });
    std::cout << mult_relin_time << " ms\n";
    
    // Print summary table
    std::cout << "\n";
    print_separator();
    std::cout << "BFV SECURITY_128 Summary (vs SEAL 4.1 reference)\n";
    print_separator();
    std::cout << std::left << std::setw(20) << "Operation" 
              << std::right << std::setw(12) << "kctsb (ms)"
              << std::setw(12) << "SEAL (ms)"
              << std::setw(12) << "Ratio" << "\n";
    std::cout << std::string(56, '-') << "\n";
    
    // SEAL reference values (approximate, BFV n=8192, t=65537)
    double seal_keygen = 50.0;
    double seal_encrypt = 5.0;
    double seal_decrypt = 2.0;
    double seal_add = 0.1;
    double seal_mult = 10.0;
    double seal_mult_relin = 18.0;
    
    auto print_row = [](const std::string& name, double kctsb, double seal) {
        std::cout << std::left << std::setw(20) << name
                  << std::right << std::setw(12) << kctsb
                  << std::setw(12) << seal
                  << std::setw(12) << std::fixed << std::setprecision(0) 
                  << (kctsb / seal) << "x\n";
    };
    
    print_row("KeyGen", keygen_time, seal_keygen);
    print_row("Encrypt", encrypt_time, seal_encrypt);
    print_row("Decrypt", decrypt_time, seal_decrypt);
    print_row("Add", add_time, seal_add);
    print_row("Multiply", mult_time, seal_mult);
    print_row("Multiply+Relin", mult_relin_time, seal_mult_relin);
    
    print_separator();
}

// Test: BFV vs BGV Comparison
TEST_F(BFVBenchmarkTest, BFVvsBGVComparison) {
    print_benchmark_header("BFV vs BGV Performance Comparison (TOY_PARAMS)");
    
    auto bfv_params = StandardParams::TOY_PARAMS();
    auto bgv_params = bgv::StandardParams::TOY_PARAMS();
    
    std::cout << "Parameters: n=" << bfv_params.n 
              << ", t=" << bfv_params.t 
              << ", L=" << bfv_params.L << "\n\n";
    
    // BFV Setup
    BFVContext bfv_ctx(bfv_params);
    BFVEncoder bfv_encoder(bfv_ctx);
    BFVEvaluator bfv_eval(bfv_ctx);
    auto bfv_sk = bfv_ctx.generate_secret_key();
    auto bfv_pk = bfv_ctx.generate_public_key(bfv_sk);
    auto bfv_rk = bfv_ctx.generate_relin_key(bfv_sk);
    
    // BGV Setup
    bgv::BGVContext bgv_ctx(bgv_params);
    bgv::BGVEncoder bgv_encoder(bgv_ctx);
    bgv::BGVEvaluator bgv_eval(bgv_ctx);
    auto bgv_sk = bgv_ctx.generate_secret_key();
    auto bgv_pk = bgv_ctx.generate_public_key(bgv_sk);
    auto bgv_rk = bgv_ctx.generate_relin_key(bgv_sk);
    
    // Prepare plaintexts
    auto bfv_pt = bfv_encoder.encode(42);
    auto bgv_pt = bgv_encoder.encode(42);
    
    // Encryption comparison
    double bfv_encrypt = measure_ms([&]() {
        auto ct = bfv_ctx.encrypt(bfv_pk, bfv_pt);
    }, 10);
    double bgv_encrypt = measure_ms([&]() {
        auto ct = bgv_ctx.encrypt(bgv_pk, bgv_pt);
    }, 10);
    
    // Decryption comparison
    auto bfv_ct = bfv_ctx.encrypt(bfv_pk, bfv_pt);
    auto bgv_ct = bgv_ctx.encrypt(bgv_pk, bgv_pt);
    
    double bfv_decrypt = measure_ms([&]() {
        auto pt = bfv_ctx.decrypt(bfv_sk, bfv_ct);
    }, 10);
    double bgv_decrypt = measure_ms([&]() {
        auto pt = bgv_ctx.decrypt(bgv_sk, bgv_ct);
    }, 10);
    
    // Addition comparison
    auto bfv_ct1 = bfv_ctx.encrypt(bfv_pk, bfv_encoder.encode(10));
    auto bfv_ct2 = bfv_ctx.encrypt(bfv_pk, bfv_encoder.encode(20));
    auto bgv_ct1 = bgv_ctx.encrypt(bgv_pk, bgv_encoder.encode(10));
    auto bgv_ct2 = bgv_ctx.encrypt(bgv_pk, bgv_encoder.encode(20));
    
    double bfv_add = measure_ms([&]() {
        auto result = bfv_eval.add(bfv_ct1, bfv_ct2);
    }, 100);
    double bgv_add = measure_ms([&]() {
        auto result = bgv_eval.add(bgv_ct1, bgv_ct2);
    }, 100);
    
    // Multiplication comparison
    double bfv_mult = measure_ms([&]() {
        auto result = bfv_eval.multiply(bfv_ct1, bfv_ct2);
    }, 5);
    double bgv_mult = measure_ms([&]() {
        auto result = bgv_eval.multiply(bgv_ct1, bgv_ct2);
    }, 5);
    
    // Print comparison table
    std::cout << std::left << std::setw(15) << "Operation" 
              << std::right << std::setw(12) << "BFV (ms)"
              << std::setw(12) << "BGV (ms)"
              << std::setw(12) << "Diff %" << "\n";
    std::cout << std::string(51, '-') << "\n";
    
    auto print_compare = [](const std::string& name, double bfv, double bgv) {
        double diff = ((bfv - bgv) / bgv) * 100;
        std::cout << std::left << std::setw(15) << name
                  << std::right << std::setw(12) << bfv
                  << std::setw(12) << bgv
                  << std::setw(11) << std::showpos << std::fixed 
                  << std::setprecision(1) << diff << "%\n";
    };
    
    print_compare("Encrypt", bfv_encrypt, bgv_encrypt);
    print_compare("Decrypt", bfv_decrypt, bgv_decrypt);
    print_compare("Add", bfv_add, bgv_add);
    print_compare("Multiply", bfv_mult, bgv_mult);
    
    std::cout << "\nNote: BFV reuses BGV infrastructure, performance should be similar.\n";
    print_separator();
}

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
