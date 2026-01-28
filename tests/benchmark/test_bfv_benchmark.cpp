/**
 * @file test_bfv_benchmark.cpp
 * @brief BFV Homomorphic Encryption Performance Benchmark (Pure RNS)
 *
 * Benchmarks BFV operations and compares with BGV using pure RNS API.
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

#include "kctsb/advanced/fe/bfv/bfv.hpp"
#include "kctsb/advanced/fe/bgv/bgv.hpp"

namespace {

using namespace kctsb::fhe::bfv;
namespace bgv = kctsb::fhe::bgv;

constexpr uint64_t kToyPlaintextModulus = 257;
constexpr uint64_t kSecurityPlaintextModulus = 65537;

std::unique_ptr<kctsb::fhe::RNSContext> create_bfv_toy_context() {
    return StandardParams::TOY_N256();
}

std::unique_ptr<kctsb::fhe::RNSContext> create_bgv_toy_context() {
    std::vector<uint64_t> primes = {65537, 114689};
    return std::make_unique<kctsb::fhe::RNSContext>(8, primes);
}

BFVPlaintext make_bfv_plaintext(uint64_t value) {
    return BFVPlaintext{value};
}

bgv::BGVPlaintext make_bgv_plaintext(uint64_t value) {
    return bgv::BGVPlaintext{value};
}

template<typename Func>
double measure_ms(Func&& f, int iterations = 1) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
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

class BFVBenchmarkTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::cout << std::fixed << std::setprecision(3);
    }
};

TEST_F(BFVBenchmarkTest, ToyParamsBenchmark) {
    print_benchmark_header("BFV TOY_PARAMS (n=256) Quick Benchmark");

    auto context = create_bfv_toy_context();
    std::mt19937_64 rng(0xBEEFBEEF);
    BFVEvaluator evaluator(context.get(), kToyPlaintextModulus);

    std::cout << "Parameters: n=" << context->n()
              << ", t=" << kToyPlaintextModulus
              << ", L=" << context->level_count() << "\n\n";

    double keygen_time = measure_ms([&]() {
        auto sk = evaluator.generate_secret_key(rng);
        auto pk = evaluator.generate_public_key(sk, rng);
        auto rk = evaluator.generate_relin_key(sk, rng);
        (void)pk;
        (void)rk;
    }, 3);
    std::cout << "KeyGen (SK+PK+RK): " << keygen_time << " ms\n";

    auto sk = evaluator.generate_secret_key(rng);
    auto pk = evaluator.generate_public_key(sk, rng);
    auto rk = evaluator.generate_relin_key(sk, rng);

    auto pt = make_bfv_plaintext(42);
    double encrypt_time = measure_ms([&]() {
        auto ct = evaluator.encrypt(pt, pk, rng);
        (void)ct;
    }, 10);
    std::cout << "Encrypt: " << encrypt_time << " ms\n";

    auto ct = evaluator.encrypt(pt, pk, rng);
    double decrypt_time = measure_ms([&]() {
        auto decrypted = evaluator.decrypt(ct, sk);
        (void)decrypted;
    }, 10);
    std::cout << "Decrypt: " << decrypt_time << " ms\n";

    auto ct1 = evaluator.encrypt(make_bfv_plaintext(10), pk, rng);
    auto ct2 = evaluator.encrypt(make_bfv_plaintext(20), pk, rng);
    double add_time = measure_ms([&]() {
        auto result = evaluator.add(ct1, ct2);
        (void)result;
    }, 100);
    std::cout << "Add: " << add_time << " ms\n";

    double mult_time = measure_ms([&]() {
        auto result = evaluator.multiply(ct1, ct2);
        (void)result;
    }, 5);
    std::cout << "Multiply: " << mult_time << " ms\n";

    double mult_relin_time = measure_ms([&]() {
        auto result = evaluator.multiply(ct1, ct2);
        evaluator.relinearize_inplace(result, rk);
    }, 3);
    std::cout << "Multiply+Relin: " << mult_relin_time << " ms\n\n";
}

TEST_F(BFVBenchmarkTest, Security128Benchmark) {
    print_benchmark_header("BFV SECURITY_128 (n=8192) Production Benchmark");

    auto context = StandardParams::SECURITY_128_N8192();
    std::mt19937_64 rng(0x12345678);
    BFVEvaluator evaluator(context.get(), kSecurityPlaintextModulus);

    std::cout << "Parameters: n=" << context->n()
              << ", t=" << kSecurityPlaintextModulus
              << ", L=" << context->level_count() << "\n\n";

    std::cout << "Benchmarking KeyGen... ";
    std::cout.flush();
    double keygen_time = measure_ms([&]() {
        auto sk = evaluator.generate_secret_key(rng);
        auto pk = evaluator.generate_public_key(sk, rng);
        (void)pk;
    });
    std::cout << keygen_time << " ms\n";

    auto sk = evaluator.generate_secret_key(rng);
    auto pk = evaluator.generate_public_key(sk, rng);

    std::cout << "Benchmarking Relin Key Gen... ";
    std::cout.flush();
    double relinkey_time = measure_ms([&]() {
        auto rk = evaluator.generate_relin_key(sk, rng);
        (void)rk;
    });
    std::cout << relinkey_time << " ms\n";

    auto rk = evaluator.generate_relin_key(sk, rng);

    auto pt = make_bfv_plaintext(42);
    std::cout << "Benchmarking Encrypt... ";
    std::cout.flush();
    double encrypt_time = measure_ms([&]() {
        auto ct = evaluator.encrypt(pt, pk, rng);
        (void)ct;
    }, 3);
    std::cout << encrypt_time << " ms\n";

    auto ct = evaluator.encrypt(pt, pk, rng);
    std::cout << "Benchmarking Decrypt... ";
    std::cout.flush();
    double decrypt_time = measure_ms([&]() {
        auto decrypted = evaluator.decrypt(ct, sk);
        (void)decrypted;
    }, 3);
    std::cout << decrypt_time << " ms\n";

    auto ct1 = evaluator.encrypt(make_bfv_plaintext(10), pk, rng);
    auto ct2 = evaluator.encrypt(make_bfv_plaintext(20), pk, rng);
    std::cout << "Benchmarking Add... ";
    std::cout.flush();
    double add_time = measure_ms([&]() {
        auto result = evaluator.add(ct1, ct2);
        (void)result;
    }, 10);
    std::cout << add_time << " ms\n";

    std::cout << "Benchmarking Multiply... ";
    std::cout.flush();
    double mult_time = measure_ms([&]() {
        auto result = evaluator.multiply(ct1, ct2);
        (void)result;
    });
    std::cout << mult_time << " ms\n";

    std::cout << "Benchmarking Multiply+Relin... ";
    std::cout.flush();
    double mult_relin_time = measure_ms([&]() {
        auto result = evaluator.multiply(ct1, ct2);
        evaluator.relinearize_inplace(result, rk);
    });
    std::cout << mult_relin_time << " ms\n\n";

    print_separator();
    std::cout << "BFV SECURITY_128 Summary (vs SEAL 4.1 reference)\n";
    print_separator();
    std::cout << std::left << std::setw(20) << "Operation"
              << std::right << std::setw(12) << "kctsb (ms)"
              << std::setw(12) << "SEAL (ms)"
              << std::setw(12) << "Ratio" << "\n";
    std::cout << std::string(56, '-') << "\n";

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

TEST_F(BFVBenchmarkTest, BFVvsBGVComparison) {
    print_benchmark_header("BFV vs BGV Performance Comparison (Toy)");

    auto bfv_context = create_bfv_toy_context();
    auto bgv_context = create_bgv_toy_context();
    std::mt19937_64 rng(0xD00DFEED);

    BFVEvaluator bfv_eval(bfv_context.get(), kToyPlaintextModulus);
    bgv::BGVEvaluator bgv_eval(bgv_context.get(), kToyPlaintextModulus);

    auto bfv_sk = bfv_eval.generate_secret_key(rng);
    auto bfv_pk = bfv_eval.generate_public_key(bfv_sk, rng);
    auto bfv_rk = bfv_eval.generate_relin_key(bfv_sk, rng);

    auto bgv_sk = bgv_eval.generate_secret_key(rng);
    auto bgv_pk = bgv_eval.generate_public_key(bgv_sk, rng);
    auto bgv_rk = bgv_eval.generate_relin_key(bgv_sk, rng);

    auto bfv_pt = make_bfv_plaintext(42);
    auto bgv_pt = make_bgv_plaintext(42);

    double bfv_encrypt = measure_ms([&]() {
        auto ct = bfv_eval.encrypt(bfv_pt, bfv_pk, rng);
        (void)ct;
    }, 10);
    double bgv_encrypt = measure_ms([&]() {
        auto ct = bgv_eval.encrypt(bgv_pt, bgv_pk, rng);
        (void)ct;
    }, 10);

    auto bfv_ct = bfv_eval.encrypt(bfv_pt, bfv_pk, rng);
    auto bgv_ct = bgv_eval.encrypt(bgv_pt, bgv_pk, rng);

    double bfv_decrypt = measure_ms([&]() {
        auto pt = bfv_eval.decrypt(bfv_ct, bfv_sk);
        (void)pt;
    }, 10);
    double bgv_decrypt = measure_ms([&]() {
        auto pt = bgv_eval.decrypt(bgv_ct, bgv_sk);
        (void)pt;
    }, 10);

    auto bfv_ct1 = bfv_eval.encrypt(make_bfv_plaintext(10), bfv_pk, rng);
    auto bfv_ct2 = bfv_eval.encrypt(make_bfv_plaintext(20), bfv_pk, rng);
    auto bgv_ct1 = bgv_eval.encrypt(make_bgv_plaintext(10), bgv_pk, rng);
    auto bgv_ct2 = bgv_eval.encrypt(make_bgv_plaintext(20), bgv_pk, rng);

    double bfv_add = measure_ms([&]() {
        auto result = bfv_eval.add(bfv_ct1, bfv_ct2);
        (void)result;
    }, 100);
    double bgv_add = measure_ms([&]() {
        auto result = bgv_eval.add(bgv_ct1, bgv_ct2);
        (void)result;
    }, 100);

    double bfv_mult = measure_ms([&]() {
        auto result = bfv_eval.multiply(bfv_ct1, bfv_ct2);
        bfv_eval.relinearize_inplace(result, bfv_rk);
    }, 5);
    double bgv_mult = measure_ms([&]() {
        auto result = bgv_eval.multiply(bgv_ct1, bgv_ct2);
        bgv_eval.relinearize_inplace(result, bgv_rk);
    }, 5);

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

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
