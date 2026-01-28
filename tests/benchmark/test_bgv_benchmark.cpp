/**
 * @file test_bgv_benchmark.cpp
 * @brief BGV Performance Benchmark Tests (Pure RNS)
 *
 * Internal performance testing using pure RNS BGV evaluator.
 * For industry comparison with SEAL/HElib, use benchmarks/benchmark_bgv.cpp.
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

#include "kctsb/advanced/fe/bgv/bgv.hpp"

namespace {

using namespace std::chrono;
using namespace kctsb::fhe::bgv;

constexpr uint64_t kToyPlaintextModulus = 257;
constexpr uint64_t kSecurityPlaintextModulus = 65537;

std::unique_ptr<kctsb::fhe::RNSContext> create_toy_context() {
    std::vector<uint64_t> primes = {65537, 114689};
    return std::make_unique<kctsb::fhe::RNSContext>(8, primes);
}

BGVPlaintext make_plaintext(uint64_t value) {
    return BGVPlaintext{value};
}

template<typename Func>
double run_benchmark(Func&& func, size_t warmup = 3, size_t iterations = 10) {
    for (size_t i = 0; i < warmup; ++i) {
        func();
    }
    auto start = high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        func();
    }
    auto end = high_resolution_clock::now();
    return duration_cast<microseconds>(end - start).count() / 1000.0 /
           static_cast<double>(iterations);
}

void print_result(const std::string& op, double time_ms, const std::string& target = "") {
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

class BGVBenchmarkTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::cout << "\n";
        std::cout << "===================================================================\n";
        std::cout << "  kctsb BGV Internal Benchmark (Pure RNS)\n";
        std::cout << "===================================================================\n";
        std::cout << "\n";
        std::cout << "Note: For industry comparison with SEAL/HElib, run:\n";
        std::cout << "      benchmarks/benchmark_bgv.exe (uses n=8192)\n";
        std::cout << "\n";
    }
};

TEST_F(BGVBenchmarkTest, ToyParams_QuickBenchmark) {
    std::cout << "--- TOY_PARAMS (n=256) Quick Benchmark ---\n";

    auto context = create_toy_context();
    std::mt19937_64 rng(0xDEADBEEF);
    BGVEvaluator evaluator(context.get(), kToyPlaintextModulus);

    std::cout << "  Ring degree (n): " << context->n() << "\n";
    std::cout << "  Plaintext modulus (t): " << kToyPlaintextModulus << "\n\n";

    auto sk = evaluator.generate_secret_key(rng);
    auto pk = evaluator.generate_public_key(sk, rng);
    auto rk = evaluator.generate_relin_key(sk, rng);

    auto pt1 = make_plaintext(10);
    auto pt2 = make_plaintext(20);
    auto ct1 = evaluator.encrypt(pt1, pk, rng);
    auto ct2 = evaluator.encrypt(pt2, pk, rng);

    double encrypt_time = run_benchmark([&]() {
        auto ct = evaluator.encrypt(pt1, pk, rng);
        (void)ct;
    });
    print_result("Encrypt", encrypt_time);

    double decrypt_time = run_benchmark([&]() {
        auto pt = evaluator.decrypt(ct1, sk);
        (void)pt;
    });
    print_result("Decrypt", decrypt_time);

    double add_time = run_benchmark([&]() {
        auto ct_sum = evaluator.add(ct1, ct2);
        (void)ct_sum;
    });
    print_result("Ciphertext addition", add_time);

    double mul_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct1, ct2);
        (void)ct_prod;
    }, 1, 5);
    print_result("Ciphertext multiplication", mul_time);

    double mul_relin_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct1, ct2);
        evaluator.relinearize_inplace(ct_prod, rk);
    }, 1, 5);
    print_result("Multiply + relinearize", mul_relin_time);

    auto ct_sum = evaluator.add(ct1, ct2);
    auto pt_result = evaluator.decrypt(ct_sum, sk);
    EXPECT_EQ(pt_result[0], 30u);
}

TEST_F(BGVBenchmarkTest, Security128Depth3_Benchmark) {
    std::cout << "--- SECURITY_128 (n=4096) Benchmark ---\n";

    auto context = StandardParams::SECURITY_128_N4096();
    std::mt19937_64 rng(0x12345678);
    BGVEvaluator evaluator(context.get(), kSecurityPlaintextModulus);

    std::cout << "  Ring degree (n): " << context->n() << "\n";
    std::cout << "  Plaintext modulus (t): " << kSecurityPlaintextModulus << "\n\n";

    double sk_time = run_benchmark([&]() {
        auto sk = evaluator.generate_secret_key(rng);
        (void)sk;
    });
    print_result("Secret key generation", sk_time);

    auto sk = evaluator.generate_secret_key(rng);

    double pk_time = run_benchmark([&]() {
        auto pk = evaluator.generate_public_key(sk, rng);
        (void)pk;
    });
    print_result("Public key generation", pk_time);

    auto pk = evaluator.generate_public_key(sk, rng);

    double rk_time = run_benchmark([&]() {
        auto rk = evaluator.generate_relin_key(sk, rng);
        (void)rk;
    }, 1, 3);
    print_result("Relinearization key generation", rk_time);

    auto rk = evaluator.generate_relin_key(sk, rng);
    auto pt = make_plaintext(42);
    auto ct = evaluator.encrypt(pt, pk, rng);

    std::cout << "\n--- Homomorphic Operations ---\n";

    double add_time = run_benchmark([&]() {
        auto ct_sum = evaluator.add(ct, ct);
        (void)ct_sum;
    });
    print_result("Addition", add_time, "< 0.3 ms target");

    double mul_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct, ct);
        (void)ct_prod;
    }, 1, 5);
    print_result("Multiplication", mul_time, "< 100 ms target");

    double mul_relin_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct, ct);
        evaluator.relinearize_inplace(ct_prod, rk);
    }, 1, 5);
    print_result("Multiply + Relinearize", mul_relin_time);

    EXPECT_LT(add_time, 1.0) << "Addition should be < 1 ms";
}

TEST_F(BGVBenchmarkTest, IndustryStandard_N8192) {
    std::cout << "--- Industry Standard (n=8192) for SEAL Comparison ---\n";
    std::cout << "Note: This matches SEAL default parameters\n\n";

    auto context = StandardParams::SECURITY_128_N8192();
    std::mt19937_64 rng(0x87654321);
    BGVEvaluator evaluator(context.get(), kSecurityPlaintextModulus);

    std::cout << "  Ring degree (n): " << context->n() << "\n";
    std::cout << "  Security level: 128-bit\n\n";

    auto sk = evaluator.generate_secret_key(rng);
    auto pk = evaluator.generate_public_key(sk, rng);
    auto rk = evaluator.generate_relin_key(sk, rng);

    auto pt = make_plaintext(42);
    auto ct = evaluator.encrypt(pt, pk, rng);

    std::cout << "--- Key Generation ---\n";
    double keygen_time = run_benchmark([&]() {
        auto temp_sk = evaluator.generate_secret_key(rng);
        auto temp_pk = evaluator.generate_public_key(temp_sk, rng);
        (void)temp_pk;
    }, 1, 3);
    print_result("KeyGen (SK + PK)", keygen_time, "SEAL: ~50 ms");

    std::cout << "\n--- Encryption/Decryption ---\n";
    double enc_time = run_benchmark([&]() {
        auto temp_ct = evaluator.encrypt(pt, pk, rng);
        (void)temp_ct;
    });
    print_result("Encrypt", enc_time, "SEAL: ~5 ms");

    double dec_time = run_benchmark([&]() {
        auto temp_pt = evaluator.decrypt(ct, sk);
        (void)temp_pt;
    });
    print_result("Decrypt", dec_time);

    std::cout << "\n--- Homomorphic Operations ---\n";
    double add_time = run_benchmark([&]() {
        auto ct_sum = evaluator.add(ct, ct);
        (void)ct_sum;
    });
    print_result("Add", add_time, "SEAL: ~0.1 ms");

    double mul_time = run_benchmark([&]() {
        auto ct_prod = evaluator.multiply(ct, ct);
        (void)ct_prod;
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
