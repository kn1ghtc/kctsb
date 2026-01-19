/**
 * @file benchmark_bgv.cpp
 * @brief BGV Homomorphic Encryption Benchmarks
 * 
 * Benchmarks for native kctsb BGV implementation.
 * Compares with SEAL/HElib when available.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include <numeric>

// kctsb BGV (always available)
#include "kctsb/advanced/fe/bgv/bgv.hpp"

// Optional: SEAL for comparison
#ifdef KCTSB_HAS_SEAL
#include <seal/seal.h>
#endif

// Optional: HElib for comparison
#ifdef KCTSB_HAS_HELIB
#include <helib/helib.h>
#endif

using namespace std::chrono;
using namespace kctsb::fhe::bgv;

// ============================================================================
// Benchmark Utilities
// ============================================================================

struct BenchmarkResult {
    std::string name;
    double time_ms;
    double ops_per_sec;
    size_t iterations;
};

template<typename Func>
double benchmark_op(Func&& func, size_t warmup = 3, size_t iterations = 10) {
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
    
    return duration_cast<microseconds>(end - start).count() / 1000.0 / iterations;
}

void print_header(const std::string& title) {
    std::cout << "\n";
    std::cout << "===================================================================\n";
    std::cout << "  " << title << "\n";
    std::cout << "===================================================================\n";
}

void print_result(const std::string& name, double time_ms, size_t iterations = 10) {
    double ops_per_sec = 1000.0 / time_ms;
    std::cout << std::left << std::setw(40) << name 
              << std::right << std::setw(10) << std::fixed << std::setprecision(3) 
              << time_ms << " ms"
              << std::setw(12) << std::fixed << std::setprecision(1) 
              << ops_per_sec << " ops/s\n";
}

// ============================================================================
// kctsb BGV Benchmarks
// ============================================================================

void benchmark_kctsb_bgv() {
    print_header("kctsb Native BGV Benchmarks");
    
    // Create context with toy parameters for testing
    std::cout << "Creating BGV context with test parameters...\n";
    auto params = StandardParams::TOY_PARAMS();
    BGVContext context(params);
    
    std::cout << "  Ring degree (n): " << context.ring_degree() << "\n";
    std::cout << "  Plaintext modulus (t): " << context.plaintext_modulus() << "\n";
    std::cout << "  Slot count: " << context.slot_count() << "\n";
    std::cout << "\n";
    
    // Key generation benchmarks
    std::cout << "--- Key Generation ---\n";
    
    double sk_time = benchmark_op([&]() {
        auto sk = context.generate_secret_key();
    });
    print_result("Secret key generation", sk_time);
    
    auto sk = context.generate_secret_key();
    
    double pk_time = benchmark_op([&]() {
        auto pk = context.generate_public_key(sk);
    });
    print_result("Public key generation", pk_time);
    
    auto pk = context.generate_public_key(sk);
    
    double rk_time = benchmark_op([&]() {
        auto rk = context.generate_relin_key(sk);
    }, 1, 3);  // Fewer iterations - slower
    print_result("Relinearization key generation", rk_time);
    
    auto rk = context.generate_relin_key(sk);
    
    // Encoding benchmarks
    std::cout << "\n--- Encoding ---\n";
    
    BGVEncoder encoder(context);
    std::vector<int64_t> test_data(context.slot_count());
    std::iota(test_data.begin(), test_data.end(), 1);  // 1, 2, 3, ...
    
    double encode_time = benchmark_op([&]() {
        auto pt = encoder.encode_batch(test_data);
    });
    print_result("Batch encode", encode_time);
    
    auto pt1 = encoder.encode_batch(test_data);
    
    double decode_time = benchmark_op([&]() {
        auto values = encoder.decode_batch(pt1);
    });
    print_result("Batch decode", decode_time);
    
    // Encryption benchmarks
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    double enc_time = benchmark_op([&]() {
        auto ct = context.encrypt(pk, pt1);
    });
    print_result("Encrypt", enc_time);
    
    auto ct1 = context.encrypt(pk, pt1);
    
    double dec_time = benchmark_op([&]() {
        auto pt = context.decrypt(sk, ct1);
    });
    print_result("Decrypt", dec_time);
    
    // Homomorphic operations
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    BGVEvaluator evaluator(context);
    
    // Prepare second ciphertext
    std::vector<int64_t> test_data2(context.slot_count());
    std::iota(test_data2.begin(), test_data2.end(), 100);
    auto pt2 = encoder.encode_batch(test_data2);
    auto ct2 = context.encrypt(pk, pt2);
    
    double add_time = benchmark_op([&]() {
        auto ct_sum = evaluator.add(ct1, ct2);
    });
    print_result("Ciphertext addition", add_time);
    
    double add_plain_time = benchmark_op([&]() {
        auto ct_sum = evaluator.add_plain(ct1, pt2);
    });
    print_result("Plaintext addition", add_plain_time);
    
    double mul_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply(ct1, ct2);
    }, 1, 5);  // Slower operation
    print_result("Ciphertext multiplication (no relin)", mul_time);
    
    double mul_relin_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply_relin(ct1, ct2, rk);
    }, 1, 5);
    print_result("Multiply + relinearize", mul_relin_time);
    
    double mul_plain_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply_plain(ct1, pt2);
    });
    print_result("Plaintext multiplication", mul_plain_time);
    
    double square_time = benchmark_op([&]() {
        auto ct_sq = evaluator.square(ct1);
    }, 1, 5);
    print_result("Square", square_time);
    
    // Verify correctness
    std::cout << "\n--- Correctness Verification ---\n";
    
    auto ct_sum = evaluator.add(ct1, ct2);
    auto pt_sum = context.decrypt(sk, ct_sum);
    auto values_sum = encoder.decode_batch(pt_sum);
    
    bool add_correct = true;
    for (size_t i = 0; i < std::min(size_t(5), test_data.size()); i++) {
        int64_t expected = (test_data[i] + test_data2[i]) % context.plaintext_modulus();
        if (values_sum[i] != expected) {
            add_correct = false;
            break;
        }
    }
    std::cout << "Addition correctness: " << (add_correct ? "PASS" : "FAIL") << "\n";
    
    // Noise budget
    std::cout << "\n--- Noise Budget ---\n";
    double fresh_budget = context.noise_budget(sk, ct1);
    std::cout << "Fresh ciphertext: " << std::fixed << std::setprecision(1) 
              << fresh_budget << " bits\n";
    
    double after_add = context.noise_budget(sk, ct_sum);
    std::cout << "After addition: " << after_add << " bits\n";
    
    auto ct_prod = evaluator.multiply_relin(ct1, ct2, rk);
    double after_mul = context.noise_budget(sk, ct_prod);
    std::cout << "After multiplication: " << after_mul << " bits\n";
}

// ============================================================================
// SEAL Comparison (if available)
// ============================================================================

#ifdef KCTSB_HAS_SEAL
void benchmark_seal_bgv() {
    print_header("Microsoft SEAL BFV/BGV Benchmarks (Comparison)");
    
    using namespace seal;
    
    // Create context with equivalent parameters
    EncryptionParameters parms(scheme_type::bgv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    
    SEALContext context(parms);
    
    std::cout << "SEAL parameters:\n";
    std::cout << "  poly_modulus_degree: " << poly_modulus_degree << "\n";
    std::cout << "  plain_modulus: " << parms.plain_modulus().value() << "\n";
    std::cout << "\n";
    
    KeyGenerator keygen(context);
    
    // Key generation
    std::cout << "--- Key Generation ---\n";
    
    double sk_time = benchmark_op([&]() {
        SecretKey sk = keygen.secret_key();
    });
    print_result("Secret key generation", sk_time);
    
    SecretKey sk = keygen.secret_key();
    
    double pk_time = benchmark_op([&]() {
        PublicKey pk;
        keygen.create_public_key(pk);
    });
    print_result("Public key generation", pk_time);
    
    PublicKey pk;
    keygen.create_public_key(pk);
    
    double rk_time = benchmark_op([&]() {
        RelinKeys rk;
        keygen.create_relin_keys(rk);
    }, 1, 3);
    print_result("Relinearization key generation", rk_time);
    
    RelinKeys rk;
    keygen.create_relin_keys(rk);
    
    // Encryption
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    BatchEncoder encoder(context);
    Evaluator evaluator(context);
    
    size_t slot_count = encoder.slot_count();
    std::vector<int64_t> test_data(slot_count);
    std::iota(test_data.begin(), test_data.end(), 1);
    
    // Encoding
    std::cout << "\n--- Encoding ---\n";
    
    double encode_time = benchmark_op([&]() {
        Plaintext pt;
        encoder.encode(test_data, pt);
    });
    print_result("Batch encode", encode_time);
    
    Plaintext pt1, pt2;
    encoder.encode(test_data, pt1);
    
    std::vector<int64_t> test_data2(slot_count);
    std::iota(test_data2.begin(), test_data2.end(), 100);
    encoder.encode(test_data2, pt2);
    
    // Encryption
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    double enc_time = benchmark_op([&]() {
        Ciphertext ct;
        encryptor.encrypt(pt1, ct);
    });
    print_result("Encrypt", enc_time);
    
    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);
    
    double dec_time = benchmark_op([&]() {
        Plaintext pt;
        decryptor.decrypt(ct1, pt);
    });
    print_result("Decrypt", dec_time);
    
    // Homomorphic operations
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    double add_time = benchmark_op([&]() {
        Ciphertext ct_sum;
        evaluator.add(ct1, ct2, ct_sum);
    });
    print_result("Ciphertext addition", add_time);
    
    double mul_time = benchmark_op([&]() {
        Ciphertext ct_prod;
        evaluator.multiply(ct1, ct2, ct_prod);
    }, 1, 5);
    print_result("Ciphertext multiplication (no relin)", mul_time);
    
    double mul_relin_time = benchmark_op([&]() {
        Ciphertext ct_prod;
        evaluator.multiply(ct1, ct2, ct_prod);
        evaluator.relinearize_inplace(ct_prod, rk);
    }, 1, 5);
    print_result("Multiply + relinearize", mul_relin_time);
    
    // Noise budget
    std::cout << "\n--- Noise Budget ---\n";
    int fresh_budget = decryptor.invariant_noise_budget(ct1);
    std::cout << "Fresh ciphertext: " << fresh_budget << " bits\n";
    
    Ciphertext ct_sum;
    evaluator.add(ct1, ct2, ct_sum);
    int after_add = decryptor.invariant_noise_budget(ct_sum);
    std::cout << "After addition: " << after_add << " bits\n";
    
    Ciphertext ct_prod;
    evaluator.multiply(ct1, ct2, ct_prod);
    evaluator.relinearize_inplace(ct_prod, rk);
    int after_mul = decryptor.invariant_noise_budget(ct_prod);
    std::cout << "After multiplication: " << after_mul << " bits\n";
}
#endif

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "==========================================================\n";
    std::cout << "  kctsb BGV Homomorphic Encryption Benchmark Suite\n";
    std::cout << "==========================================================\n";
    std::cout << "\n";
    std::cout << "Benchmarking native kctsb BGV implementation.\n";
    std::cout << "Comparison with SEAL/HElib when available.\n";
    
    // Always benchmark native kctsb BGV
    benchmark_kctsb_bgv();
    
    // Optional: SEAL comparison
#ifdef KCTSB_HAS_SEAL
    benchmark_seal_bgv();
#else
    std::cout << "\n[INFO] SEAL not available - skipping SEAL benchmarks\n";
    std::cout << "       To enable: set KCTSB_ENABLE_SEAL=ON and provide SEAL library\n";
#endif

    // Optional: HElib comparison
#ifdef KCTSB_HAS_HELIB
    // benchmark_helib_bgv();  // TODO: Implement HElib benchmark
    std::cout << "\n[INFO] HElib benchmarks: TODO\n";
#else
    std::cout << "\n[INFO] HElib not available - skipping HElib benchmarks\n";
    std::cout << "       To enable: set KCTSB_ENABLE_HELIB=ON and provide HElib library\n";
#endif
    
    std::cout << "\n==========================================================\n";
    std::cout << "  Benchmark Complete\n";
    std::cout << "==========================================================\n";
    
    return 0;
}
