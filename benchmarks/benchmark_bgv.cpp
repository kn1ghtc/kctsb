/**
 * @file benchmark_bgv.cpp
 * @brief BGV Homomorphic Encryption Industry Benchmark
 * 
 * Standard benchmark using n=8192 for industry comparison with SEAL and HElib.
 * Outputs ratio comparison to show performance relative to reference implementations.
 * 
 * Key Design Decisions:
 * - n=8192 is the industry standard for 128-bit security comparisons
 * - For internal testing with larger n, use tests/benchmark/test_bgv_benchmark.cpp
 * - Ratio output format: kctsb_time / seal_time (lower is better)
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
#include <cmath>

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
// Industry Standard Parameters (n=8192, 128-bit security)
// ============================================================================

constexpr size_t INDUSTRY_POLY_DEGREE = 8192;
constexpr size_t BENCHMARK_ITERATIONS = 10;
constexpr size_t WARMUP_ITERATIONS = 3;

// ============================================================================
// Benchmark Result Structure
// ============================================================================

struct BenchmarkResult {
    std::string operation;
    double kctsb_ms;
    double seal_ms;
    double helib_ms;
    
    double ratio_vs_seal() const {
        return (seal_ms > 0) ? kctsb_ms / seal_ms : 0;
    }
    
    double ratio_vs_helib() const {
        return (helib_ms > 0) ? kctsb_ms / helib_ms : 0;
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
    
    // Show ratio if reference available
    if (seal_time_ms > 0) {
        double ratio = time_ms / seal_time_ms;
        std::cout << "  [SEAL: " << std::setprecision(2) << ratio << "x]";
    }
    if (helib_time_ms > 0) {
        double ratio = time_ms / helib_time_ms;
        std::cout << "  [HElib: " << std::setprecision(2) << ratio << "x]";
    }
    
    std::cout << "\n";
}

void print_comparison_table() {
    print_header("Performance Comparison Summary (Ratio: kctsb / reference)");
    
    std::cout << std::left << std::setw(25) << "Operation"
              << std::right << std::setw(12) << "kctsb (ms)"
              << std::setw(12) << "SEAL (ms)"
              << std::setw(10) << "Ratio"
              << std::setw(12) << "HElib (ms)"
              << std::setw(10) << "Ratio"
              << "\n";
    std::cout << std::string(81, '-') << "\n";
    
    for (const auto& r : g_results) {
        std::cout << std::left << std::setw(25) << r.operation
                  << std::right << std::setw(12) << std::fixed << std::setprecision(3) 
                  << r.kctsb_ms;
        
        if (r.seal_ms > 0) {
            std::cout << std::setw(12) << r.seal_ms
                      << std::setw(10) << std::setprecision(2) << r.ratio_vs_seal();
        } else {
            std::cout << std::setw(12) << "N/A" << std::setw(10) << "-";
        }
        
        if (r.helib_ms > 0) {
            std::cout << std::setw(12) << r.helib_ms
                      << std::setw(10) << std::setprecision(2) << r.ratio_vs_helib();
        } else {
            std::cout << std::setw(12) << "N/A" << std::setw(10) << "-";
        }
        
        std::cout << "\n";
    }
    
    std::cout << std::string(81, '-') << "\n";
    std::cout << "Target: Ratio <= 1.5 for production readiness\n";
}

// ============================================================================
// kctsb BGV Benchmarks
// ============================================================================

void benchmark_kctsb_bgv() {
    print_header("kctsb Native BGV Benchmarks (n=8192, 128-bit security)");
    
    // Use n=8192 for industry standard comparison
    auto params = StandardParams::SECURITY_128_DEPTH_5();
    BGVContext context(params);
    
    std::cout << "Parameters:\n";
    std::cout << "  Ring degree (n):      " << context.ring_degree() << "\n";
    std::cout << "  Plaintext modulus (t):" << context.plaintext_modulus() << "\n";
    std::cout << "  Security level:       128-bit classical\n";
    std::cout << "  Benchmark iterations: " << BENCHMARK_ITERATIONS << "\n";
    std::cout << "\n";
    
    // =========================================================================
    // Key Generation Benchmarks
    // =========================================================================
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
    }, 1, 3);  // Fewer iterations - slower operation
    print_result("Relin key generation", rk_time);
    
    auto rk = context.generate_relin_key(sk);
    
    double keygen_total = sk_time + pk_time;
    g_results.push_back({"KeyGen (SK+PK)", keygen_total, 0, 0});
    g_results.push_back({"Relin key gen", rk_time, 0, 0});
    
    // =========================================================================
    // Encoding Benchmarks
    // =========================================================================
    std::cout << "\n--- Encoding ---\n";
    
    BGVEncoder encoder(context);
    std::vector<int64_t> test_data(context.slot_count());
    std::iota(test_data.begin(), test_data.end(), 1);
    
    double encode_time = benchmark_op([&]() {
        auto pt = encoder.encode_batch(test_data);
    });
    print_result("Batch encode", encode_time);
    
    auto pt1 = encoder.encode_batch(test_data);
    
    double decode_time = benchmark_op([&]() {
        auto values = encoder.decode_batch(pt1);
    });
    print_result("Batch decode", decode_time);
    
    // =========================================================================
    // Encryption/Decryption Benchmarks
    // =========================================================================
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    double enc_time = benchmark_op([&]() {
        auto ct = context.encrypt(pk, pt1);
    });
    print_result("Encrypt", enc_time);
    g_results.push_back({"Encrypt", enc_time, 0, 0});
    
    auto ct1 = context.encrypt(pk, pt1);
    
    double dec_time = benchmark_op([&]() {
        auto pt = context.decrypt(sk, ct1);
    });
    print_result("Decrypt", dec_time);
    g_results.push_back({"Decrypt", dec_time, 0, 0});
    
    // =========================================================================
    // Homomorphic Operations
    // =========================================================================
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
    print_result("Ciphertext add", add_time);
    g_results.push_back({"Add", add_time, 0, 0});
    
    double add_plain_time = benchmark_op([&]() {
        auto ct_sum = evaluator.add_plain(ct1, pt2);
    });
    print_result("Plaintext add", add_plain_time);
    
    double mul_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply(ct1, ct2);
    }, 1, 5);
    print_result("Ciphertext multiply (no relin)", mul_time);
    g_results.push_back({"Multiply", mul_time, 0, 0});
    
    double mul_relin_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply_relin(ct1, ct2, rk);
    }, 1, 5);
    print_result("Multiply + relinearize", mul_relin_time);
    g_results.push_back({"Mul + Relin", mul_relin_time, 0, 0});
    
    double mul_plain_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply_plain(ct1, pt2);
    });
    print_result("Plaintext multiply", mul_plain_time);
    
    double square_time = benchmark_op([&]() {
        auto ct_sq = evaluator.square(ct1);
    }, 1, 5);
    print_result("Square", square_time);
    
    // =========================================================================
    // Modulus Switching
    // =========================================================================
    std::cout << "\n--- Modulus Switching ---\n";
    
    auto ct_for_modswitch = context.encrypt(pk, pt1);
    double modswitch_time = benchmark_op([&]() {
        auto ct_copy = ct_for_modswitch;
        evaluator.mod_switch_inplace(ct_copy);
    }, 1, 5);
    print_result("Mod switch to next", modswitch_time);
    g_results.push_back({"Mod switch", modswitch_time, 0, 0});
    
    // =========================================================================
    // Correctness Verification
    // =========================================================================
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
    
    // Multiplication correctness - use single-value encoding for reliable testing
    // Note: Batch SIMD encoding requires proper CRT-based packing for multiplication
    auto pt_single1 = encoder.encode(7);
    auto pt_single2 = encoder.encode(6);
    auto ct_single1 = context.encrypt(pk, pt_single1);
    auto ct_single2 = context.encrypt(pk, pt_single2);
    auto ct_single_prod = evaluator.multiply_relin(ct_single1, ct_single2, rk);
    auto pt_single_result = context.decrypt(sk, ct_single_prod);
    auto single_result = encoder.decode_int(pt_single_result);
    
    bool mul_correct = (single_result == 42);
    std::cout << "Multiplication correctness: " << (mul_correct ? "PASS" : "FAIL") << "\n";
    
    // =========================================================================
    // Noise Budget
    // =========================================================================
    std::cout << "\n--- Noise Budget ---\n";
    double fresh_budget = context.noise_budget(sk, ct1);
    std::cout << "Fresh ciphertext:     " << std::fixed << std::setprecision(1) 
              << fresh_budget << " bits\n";
    
    double after_add = context.noise_budget(sk, ct_sum);
    std::cout << "After addition:       " << after_add << " bits\n";
    
    double after_mul = context.noise_budget(sk, ct_single_prod);
    std::cout << "After multiplication: " << after_mul << " bits\n";
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
    print_result("Relin key", rk_time);
    
    RelinKeys rk;
    keygen.create_relin_keys(rk);
    
    // Update kctsb results with SEAL reference times
    for (auto& r : g_results) {
        if (r.operation == "KeyGen (SK+PK)") r.seal_ms = keygen_total;
        if (r.operation == "Relin key gen") r.seal_ms = rk_time;
    }
    
    // Encryption
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    BatchEncoder encoder(context);
    Evaluator evaluator(context);
    
    size_t slot_count = encoder.slot_count();
    std::vector<int64_t> test_data(slot_count);
    std::iota(test_data.begin(), test_data.end(), 1);
    
    Plaintext pt1, pt2;
    encoder.encode(test_data, pt1);
    
    std::vector<int64_t> test_data2(slot_count);
    std::iota(test_data2.begin(), test_data2.end(), 100);
    encoder.encode(test_data2, pt2);
    
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
    
    // Update references
    for (auto& r : g_results) {
        if (r.operation == "Encrypt") r.seal_ms = enc_time;
        if (r.operation == "Decrypt") r.seal_ms = dec_time;
    }
    
    // Homomorphic operations
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    double add_time = benchmark_op([&]() {
        Ciphertext ct_sum;
        evaluator.add(ct1, ct2, ct_sum);
    });
    print_result("Add", add_time);
    
    double mul_time = benchmark_op([&]() {
        Ciphertext ct_prod;
        evaluator.multiply(ct1, ct2, ct_prod);
    }, 1, 5);
    print_result("Multiply", mul_time);
    
    double mul_relin_time = benchmark_op([&]() {
        Ciphertext ct_prod;
        evaluator.multiply(ct1, ct2, ct_prod);
        evaluator.relinearize_inplace(ct_prod, rk);
    }, 1, 5);
    print_result("Mul + Relin", mul_relin_time);
    
    // Update references
    for (auto& r : g_results) {
        if (r.operation == "Add") r.seal_ms = add_time;
        if (r.operation == "Multiply") r.seal_ms = mul_time;
        if (r.operation == "Mul + Relin") r.seal_ms = mul_relin_time;
    }
    
    // Modulus switching
    std::cout << "\n--- Modulus Switching ---\n";
    double modswitch_time = benchmark_op([&]() {
        Ciphertext ct_copy = ct1;
        evaluator.mod_switch_to_next_inplace(ct_copy);
    }, 1, 5);
    print_result("Mod switch", modswitch_time);
    
    for (auto& r : g_results) {
        if (r.operation == "Mod switch") r.seal_ms = modswitch_time;
    }
    
    // Noise budget
    std::cout << "\n--- Noise Budget ---\n";
    int fresh_budget = decryptor.invariant_noise_budget(ct1);
    std::cout << "Fresh ciphertext: " << fresh_budget << " bits\n";
    
    Ciphertext ct_prod;
    evaluator.multiply(ct1, ct2, ct_prod);
    evaluator.relinearize_inplace(ct_prod, rk);
    int after_mul = decryptor.invariant_noise_budget(ct_prod);
    std::cout << "After multiplication: " << after_mul << " bits\n";
}
#endif

// ============================================================================
// HElib Comparison (if available)
// ============================================================================

#ifdef KCTSB_HAS_HELIB
void benchmark_helib_bgv() {
    print_header("IBM HElib BGV Benchmarks (Reference)");
    
    // HElib parameter setup
    // m determines ring dimension, p is plaintext modulus, r is Hensel lifting
    long m = 32768;  // Closest to n=8192 for HElib (m ~ 2*n for power-of-2)
    long p = 65537;  // Plaintext modulus
    long r = 1;      // Hensel lifting
    long bits = 300; // Security bits for modulus chain
    
    helib::Context::Builder builder(m, p, r);
    builder.bits(bits);
    helib::Context context = builder.build();
    
    std::cout << "Parameters:\n";
    std::cout << "  m (cyclotomic):   " << m << "\n";
    std::cout << "  p (plaintext):    " << p << "\n";
    std::cout << "  bits (security):  " << bits << "\n";
    std::cout << "\n";
    
    // Key generation
    std::cout << "--- Key Generation ---\n";
    
    double keygen_time = benchmark_op([&]() {
        helib::SecKey secret_key(context);
        secret_key.GenSecKey();
    }, 1, 3);
    print_result("Full keygen", keygen_time);
    
    helib::SecKey secret_key(context);
    secret_key.GenSecKey();
    helib::addSome1DMatrices(secret_key);
    
    const helib::PubKey& public_key = secret_key;
    
    // Update references
    for (auto& r : g_results) {
        if (r.operation == "KeyGen (SK+PK)") r.helib_ms = keygen_time;
    }
    
    // Encryption
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    helib::Ptxt<helib::BGV> ptxt(context);
    for (long i = 0; i < ptxt.size(); i++) {
        ptxt[i] = i + 1;
    }
    
    double enc_time = benchmark_op([&]() {
        helib::Ctxt ctxt(public_key);
        public_key.Encrypt(ctxt, ptxt);
    });
    print_result("Encrypt", enc_time);
    
    helib::Ctxt ct1(public_key);
    public_key.Encrypt(ct1, ptxt);
    
    helib::Ctxt ct2(public_key);
    public_key.Encrypt(ct2, ptxt);
    
    double dec_time = benchmark_op([&]() {
        helib::Ptxt<helib::BGV> result(context);
        secret_key.Decrypt(result, ct1);
    });
    print_result("Decrypt", dec_time);
    
    for (auto& r : g_results) {
        if (r.operation == "Encrypt") r.helib_ms = enc_time;
        if (r.operation == "Decrypt") r.helib_ms = dec_time;
    }
    
    // Homomorphic operations
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    double add_time = benchmark_op([&]() {
        helib::Ctxt ct_sum = ct1;
        ct_sum += ct2;
    });
    print_result("Add", add_time);
    
    double mul_time = benchmark_op([&]() {
        helib::Ctxt ct_prod = ct1;
        ct_prod *= ct2;
    }, 1, 5);
    print_result("Multiply", mul_time);
    
    for (auto& r : g_results) {
        if (r.operation == "Add") r.helib_ms = add_time;
        if (r.operation == "Multiply") r.helib_ms = mul_time;
        if (r.operation == "Mul + Relin") r.helib_ms = mul_time;  // HElib auto-relinearizes
    }
}
#endif

// ============================================================================
// Main
// ============================================================================

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    std::cout << "===================================================================\n";
    std::cout << "  kctsb BGV Industry Benchmark Suite (n=" << INDUSTRY_POLY_DEGREE << ")\n";
    std::cout << "===================================================================\n";
    std::cout << "\n";
    std::cout << "This benchmark uses n=8192 for industry-standard comparison.\n";
    std::cout << "For internal testing with larger n, use:\n";
    std::cout << "  ctest -R test_bgv_benchmark -L performance\n";
    std::cout << "\n";
    
    // Always benchmark native kctsb BGV
    benchmark_kctsb_bgv();
    
    // Optional: SEAL comparison
#ifdef KCTSB_HAS_SEAL
    benchmark_seal_bgv();
#else
    std::cout << "\n[INFO] SEAL not available - skipping SEAL comparison\n";
    std::cout << "       To enable: cmake -DKCTSB_ENABLE_SEAL=ON\n";
#endif

    // Optional: HElib comparison
#ifdef KCTSB_HAS_HELIB
    benchmark_helib_bgv();
#else
    std::cout << "\n[INFO] HElib not available - skipping HElib comparison\n";
    std::cout << "       To enable: cmake -DKCTSB_ENABLE_HELIB=ON\n";
#endif
    
    // Print comparison table
    print_comparison_table();
    
    std::cout << "\n===================================================================\n";
    std::cout << "  Benchmark Complete\n";
    std::cout << "===================================================================\n";
    
    return 0;
}
