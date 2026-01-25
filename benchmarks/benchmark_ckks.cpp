/**
 * @file benchmark_ckks.cpp
 * @brief CKKS Homomorphic Encryption Industry Benchmark
 * 
 * Standard benchmark using n=8192 for industry comparison with SEAL and HElib.
 * CKKS (Cheon-Kim-Kim-Song) is designed for approximate arithmetic on real/complex numbers.
 * 
 * Key differences from BGV/BFV:
 * - Encodes real/complex values (approximate arithmetic)
 * - Rescaling operation to control ciphertext modulus growth
 * - Slot count = n/2 for complex numbers, n for real-only encoding
 * - Fixed-point encoding with scale parameter
 * 
 * Use cases: Machine learning inference, statistical analysis, signal processing
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include <complex>
#include <cmath>

// kctsb CKKS (Phase 3 implementation)
#ifdef KCTSB_HAS_CKKS
#include "kctsb/advanced/fe/ckks/ckks.hpp"
#endif

// SEAL for reference comparison
#ifdef KCTSB_HAS_SEAL
#include <seal/seal.h>
#endif

// HElib for reference (CKKS approximation)
#ifdef KCTSB_HAS_HELIB
#include <helib/helib.h>
#endif

using namespace std::chrono;

// ============================================================================
// Industry Standard Parameters
// ============================================================================

constexpr size_t INDUSTRY_POLY_DEGREE = 8192;
constexpr size_t BENCHMARK_ITERATIONS = 10;
constexpr size_t WARMUP_ITERATIONS = 3;

// CKKS-specific parameters
constexpr double CKKS_SCALE = std::pow(2.0, 40);  // 40-bit precision

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
    for (size_t i = 0; i < warmup; i++) {
        func();
    }
    
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
    print_header("CKKS Performance Comparison Summary");
    
    std::cout << std::left << std::setw(25) << "Operation"
              << std::right << std::setw(12) << "kctsb (ms)"
              << std::setw(12) << "SEAL (ms)"
              << std::setw(10) << "Ratio"
              << "\n";
    std::cout << std::string(59, '-') << "\n";
    
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
        
        std::cout << "\n";
    }
    
    std::cout << std::string(59, '-') << "\n";
    std::cout << "Target: Ratio <= 1.5 for production readiness\n";
}

// ============================================================================
// kctsb CKKS Benchmarks (Phase 3)
// ============================================================================

#ifdef KCTSB_HAS_CKKS
void benchmark_kctsb_ckks() {
    print_header("kctsb Native CKKS Benchmarks (n=8192)");
    
    using namespace kctsb::fhe::ckks;
    
    // Use SECURITY_128 parameters (n=8192)
    std::cout << "Loading parameters..." << std::endl;
    auto params = StandardParams::SECURITY_128();
    
    std::cout << "Creating context..." << std::endl;
    CKKSContext context(params);
    
    std::cout << "Parameters:\n";
    std::cout << "  Ring degree (n):    " << context.ring_degree() << "\n";
    std::cout << "  Slot count:         " << context.slot_count() << "\n";
    std::cout << "  Scale:              2^40\n";
    std::cout << "\n";
    
    // Key generation
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
    
    double keygen_total = sk_time + pk_time;
    g_results.push_back({"KeyGen (SK+PK)", keygen_total, 0, 0});
    
    // Encoding
    CKKSEncoder encoder(context);
    
    std::vector<std::complex<double>> test_data(context.slot_count());
    for (size_t i = 0; i < test_data.size(); i++) {
        test_data[i] = std::complex<double>(static_cast<double>(i) * 0.01, 0);
    }
    
    auto pt1 = encoder.encode(test_data, CKKS_SCALE);
    
    // Encryption/Decryption
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
    
    // Homomorphic operations
    std::cout << "\n--- Homomorphic Operations ---\n";
    
    CKKSEvaluator evaluator(context);
    
    std::vector<std::complex<double>> test_data2(context.slot_count());
    for (size_t i = 0; i < test_data2.size(); i++) {
        test_data2[i] = std::complex<double>(0.5, 0);
    }
    auto pt2 = encoder.encode(test_data2, CKKS_SCALE);
    auto ct2 = context.encrypt(pk, pt2);
    
    double add_time = benchmark_op([&]() {
        auto ct_sum = evaluator.add(ct1, ct2);
    });
    print_result("Ciphertext add", add_time);
    g_results.push_back({"Add", add_time, 0, 0});
    
    double mul_time = benchmark_op([&]() {
        auto ct_prod = evaluator.multiply(ct1, ct2);
    }, 1, 5);
    print_result("Ciphertext multiply", mul_time);
    g_results.push_back({"Multiply", mul_time, 0, 0});
    
    // Rescaling (CKKS-specific)
    std::cout << "\n--- Rescaling (CKKS-specific) ---\n";
    auto ct_prod = evaluator.multiply(ct1, ct2);
    double rescale_time = benchmark_op([&]() {
        auto ct_rescaled = evaluator.rescale(ct_prod);
    }, 1, 5);
    print_result("Rescale to next", rescale_time);
    g_results.push_back({"Rescale", rescale_time, 0, 0});
}
#endif

// ============================================================================
// SEAL CKKS Reference Benchmark
// ============================================================================

#ifdef KCTSB_HAS_SEAL
void benchmark_seal_ckks() {
    print_header("Microsoft SEAL CKKS Benchmarks (Reference)");
    
    using namespace seal;
    
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(INDUSTRY_POLY_DEGREE);
    parms.set_coeff_modulus(CoeffModulus::Create(INDUSTRY_POLY_DEGREE, {50, 40, 40, 40, 40, 50}));
    
    SEALContext context(parms);
    
    std::cout << "Parameters:\n";
    std::cout << "  poly_modulus_degree: " << INDUSTRY_POLY_DEGREE << "\n";
    std::cout << "  slot_count:          " << INDUSTRY_POLY_DEGREE / 2 << "\n";
    std::cout << "  scale:               2^40\n";
    std::cout << "\n";
    
    KeyGenerator keygen(context);
    
    // Key generation
    std::cout << "--- Key Generation ---\n";
    
    SecretKey sk = keygen.secret_key();
    
    double pk_time = benchmark_op([&]() {
        PublicKey pk;
        keygen.create_public_key(pk);
    });
    print_result("Public key", pk_time);
    
    PublicKey pk;
    keygen.create_public_key(pk);
    
    double rk_time = benchmark_op([&]() {
        RelinKeys rk;
        keygen.create_relin_keys(rk);
    }, 1, 3);
    print_result("Relin key", rk_time);
    
    RelinKeys rk;
    keygen.create_relin_keys(rk);
    
    // Update references
    for (auto& r : g_results) {
        if (r.operation == "KeyGen (SK+PK)") r.seal_ms = pk_time;
    }
    
    // Encryption
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);
    
    size_t slot_count = encoder.slot_count();
    
    std::vector<std::complex<double>> test_data(slot_count);
    for (size_t i = 0; i < test_data.size(); i++) {
        test_data[i] = std::complex<double>(static_cast<double>(i) * 0.01, 0);
    }
    
    Plaintext pt1;
    encoder.encode(test_data, CKKS_SCALE, pt1);
    
    std::cout << "\n--- Encryption/Decryption ---\n";
    
    double enc_time = benchmark_op([&]() {
        Ciphertext ct;
        encryptor.encrypt(pt1, ct);
    });
    print_result("Encrypt", enc_time);
    
    Ciphertext ct1;
    encryptor.encrypt(pt1, ct1);
    
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
    
    std::vector<std::complex<double>> test_data2(slot_count);
    for (size_t i = 0; i < test_data2.size(); i++) {
        test_data2[i] = std::complex<double>(0.5, 0);
    }
    Plaintext pt2;
    encoder.encode(test_data2, CKKS_SCALE, pt2);
    Ciphertext ct2;
    encryptor.encrypt(pt2, ct2);
    
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
    }
    
    // Rescaling
    std::cout << "\n--- Rescaling ---\n";
    Ciphertext ct_prod;
    evaluator.multiply(ct1, ct2, ct_prod);
    evaluator.relinearize_inplace(ct_prod, rk);
    
    double rescale_time = benchmark_op([&]() {
        Ciphertext ct_rescaled = ct_prod;
        evaluator.rescale_to_next_inplace(ct_rescaled);
    }, 1, 5);
    print_result("Rescale", rescale_time);
    
    for (auto& r : g_results) {
        if (r.operation == "Rescale") r.seal_ms = rescale_time;
    }
    
    // Precision analysis
    std::cout << "\n--- Precision Analysis ---\n";
    
    auto ct_sum = ct1;
    evaluator.add_inplace(ct_sum, ct2);
    
    Plaintext pt_result;
    decryptor.decrypt(ct_sum, pt_result);
    
    std::vector<std::complex<double>> result;
    encoder.decode(pt_result, result);
    
    // Calculate RMS error for first 10 slots
    double rms_error = 0;
    for (size_t i = 0; i < std::min(size_t(10), slot_count); i++) {
        std::complex<double> expected = test_data[i] + test_data2[i];
        std::complex<double> diff = result[i] - expected;
        rms_error += std::norm(diff);
    }
    rms_error = std::sqrt(rms_error / 10.0);
    std::cout << "RMS error (addition): " << std::scientific << rms_error << "\n";
}
#endif

// ============================================================================
// Main
// ============================================================================

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    std::cout << "===================================================================\n";
    std::cout << "  kctsb CKKS Industry Benchmark Suite (n=" << INDUSTRY_POLY_DEGREE << ")\n";
    std::cout << "===================================================================\n";
    std::cout << "\n";
    std::cout << "CKKS (Cheon-Kim-Kim-Song) Scheme:\n";
    std::cout << "  - Approximate arithmetic on real/complex numbers\n";
    std::cout << "  - Fixed-point encoding with configurable scale\n";
    std::cout << "  - Rescaling to manage ciphertext size after multiplication\n";
    std::cout << "  - Ideal for ML inference, statistics, signal processing\n";
    std::cout << "\n";
    
#ifdef KCTSB_HAS_CKKS
    benchmark_kctsb_ckks();
#else
    std::cout << "\n[INFO] kctsb CKKS module not yet implemented (Phase 3)\n";
    std::cout << "       Current phase focuses on BGV optimization\n";
    std::cout << "       CKKS implementation planned for Phase 3\n";
#endif

#ifdef KCTSB_HAS_SEAL
    benchmark_seal_ckks();
#else
    std::cout << "\n[INFO] SEAL not available - skipping SEAL comparison\n";
    std::cout << "       To enable: cmake -DKCTSB_ENABLE_SEAL=ON\n";
#endif
    
    if (!g_results.empty()) {
        print_comparison_table();
    }
    
    std::cout << "\n===================================================================\n";
    std::cout << "  CKKS Benchmark Complete\n";
    std::cout << "===================================================================\n";
    
    return 0;
}
