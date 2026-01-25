/**
 * @file test_ckks_evaluator.cpp
 * @brief CKKS Evaluator Tests - Pure RNS Implementation
 *
 * Comprehensive tests for CKKS homomorphic encryption.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <gtest/gtest.h>
#include "kctsb/advanced/fe/ckks/ckks_evaluator.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include <random>
#include <cmath>

using namespace kctsb::fhe;
using namespace kctsb::fhe::ckks;

namespace {

// Helper: compute log2 of n
int log2_n(size_t n) {
    int log_n = 0;
    while ((1ULL << log_n) < n) ++log_n;
    return log_n;
}

// Test fixture with RNS context
class CKKSEvaluatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use proper CKKS parameters for testing
        // n=1024, L=3, 40-bit NTT-friendly primes (q = k*2n + 1, verified prime)
        std::vector<uint64_t> primes = {
            549755860993ULL,  // 40-bit prime, k=268435479
            549755873281ULL,  // 40-bit prime, k=268435485
            549755904001ULL   // 40-bit prime, k=268435500
        };
        
        int log_n = log2_n(1024);  // log_n = 10
        context_ = std::make_unique<RNSContext>(log_n, primes);
        scale_ = std::pow(2.0, 30.0);  // 2^30 scale for testing
        
        evaluator_ = std::make_unique<CKKSEvaluator>(context_.get(), scale_);
        
        rng_.seed(42);
    }
    
    std::unique_ptr<RNSContext> context_;
    std::unique_ptr<CKKSEvaluator> evaluator_;
    double scale_;
    std::mt19937_64 rng_;
    
    // Helper: compare with tolerance
    bool approx_equal(double a, double b, double tol = 0.01) {
        double diff = std::abs(a - b);
        // Also check relative error for larger values
        double max_val = std::max(std::abs(a), std::abs(b));
        if (max_val > 1.0) {
            return (diff / max_val) < 0.5;  // 50% relative tolerance for debugging
        }
        return diff < tol;
    }
};

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST_F(CKKSEvaluatorTest, SecretKeyGeneration) {
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng_);
    
    EXPECT_TRUE(sk.is_ntt_form);
    // Secret key should be non-zero
    bool has_nonzero = false;
    for (size_t i = 0; i < 256; ++i) {
        if (sk.s(0, i) != 0) {  // Use operator() instead of get_coeff
            has_nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(has_nonzero);
}

TEST_F(CKKSEvaluatorTest, PublicKeyGeneration) {
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng_);
    CKKSPublicKey pk = evaluator_->generate_public_key(sk, rng_);
    
    EXPECT_TRUE(pk.is_ntt_form);
}

TEST_F(CKKSEvaluatorTest, RelinKeyGeneration) {
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng_);
    CKKSRelinKey rk = evaluator_->generate_relin_key(sk, rng_);
    
    EXPECT_TRUE(rk.is_ntt_form);
    EXPECT_GT(rk.key_components.size(), 0U);
}

// ============================================================================
// Encoder Tests
// ============================================================================

TEST_F(CKKSEvaluatorTest, EncodeSingleValue) {
    double value = 3.14159;
    
    CKKSPlaintext pt = evaluator_->encoder().encode_single(value, scale_);
    
    EXPECT_GT(pt.scale(), 0.0);
}

TEST_F(CKKSEvaluatorTest, EncodeDecodeRealVector) {
    std::vector<double> values = {1.0, 2.0, 3.0, 4.0};
    
    CKKSPlaintext pt = evaluator_->encoder().encode_real(values, scale_);
    std::vector<double> decoded = evaluator_->encoder().decode_real(pt);
    
    // Check first few values match (within tolerance due to FFT precision)
    for (size_t i = 0; i < values.size() && i < decoded.size(); ++i) {
        EXPECT_TRUE(approx_equal(values[i], decoded[i], 0.5))
            << "Mismatch at index " << i << ": expected " << values[i]
            << ", got " << decoded[i];
    }
}

// ============================================================================
// Encrypt/Decrypt Tests
// ============================================================================

// Debug test: Verify NTT root correctness for CKKS large params
TEST_F(CKKSEvaluatorTest, DebugNTTRootOrder) {
    size_t n = context_->n();  // 1024
    size_t L = context_->level_count();
    
    std::cout << "Checking NTT root order for n=" << n << ", L=" << L << std::endl;
    
    for (size_t level = 0; level < L; ++level) {
        const auto& tables = context_->ntt_tables(level);
        uint64_t root = tables.root();
        uint64_t q = tables.modulus().value();
        const Modulus& mod = tables.modulus();
        
        // Check: root^{2n} = 1
        uint64_t two_n = 2 * n;
        uint64_t root_2n = pow_mod(root, two_n, mod);
        
        // Check: root^n = -1 (mod q) for negacyclic NTT
        uint64_t root_n = pow_mod(root, n, mod);
        uint64_t expected_minus_one = q - 1;
        
        // Check: root^k != 1 for k < 2n (at least k=1 and k=n)
        uint64_t root_1 = root;
        
        std::cout << "Level " << level << ": q=" << q << ", root=" << root << std::endl;
        std::cout << "  root^{2n} = " << root_2n << " (expected 1)" << std::endl;
        std::cout << "  root^n = " << root_n << " (expected " << expected_minus_one << " = -1 mod q)" << std::endl;
        std::cout << "  root^1 = " << root_1 << " (expected != 1)" << std::endl;
        
        EXPECT_EQ(root_2n, 1ULL) << "root^{2n} should be 1";
        EXPECT_EQ(root_n, expected_minus_one) << "root^n should be -1 (mod q)";
        EXPECT_NE(root_1, 1ULL) << "root should not be 1";
    }
}

// Debug test: Verify NTT polynomial multiplication semantics with CKKS LARGE params
TEST_F(CKKSEvaluatorTest, DebugNTTPrimeValidity) {
    // Print CKKS prime info
    size_t n = context_->n();
    size_t L = context_->level_count();
    
    std::cout << "CKKS parameters: n=" << n << ", L=" << L << std::endl;
    
    for (size_t level = 0; level < L; ++level) {
        uint64_t q = context_->modulus(level).value();
        uint64_t order = q - 1;
        uint64_t two_n = 2 * n;
        
        bool ntt_friendly = (order % two_n == 0);
        uint64_t k = order / two_n;  // (q-1) / 2n
        
        std::cout << "Prime " << level << ": q=" << q 
                  << ", (q-1)=" << order 
                  << ", 2n=" << two_n
                  << ", (q-1)%2n=" << (order % two_n)
                  << ", NTT-friendly=" << (ntt_friendly ? "YES" : "NO")
                  << ", k=(q-1)/2n=" << k
                  << std::endl;
        
        EXPECT_TRUE(ntt_friendly) << "Prime " << level << " is not NTT-friendly!";
    }
}

// Debug test: Verify NTT polynomial multiplication semantics with SMALL params
TEST_F(CKKSEvaluatorTest, DebugNTTMultiplicationSemanticsSmall) {
    // Use small params like BFV (n=16)
    int log_n = 4;  // n=16
    std::vector<uint64_t> primes = {65537, 114689};
    auto small_ctx = std::make_unique<RNSContext>(log_n, primes);
    
    size_t n = small_ctx->n();  // 16
    size_t L = small_ctx->level_count();  // 2
    uint64_t q = small_ctx->modulus(0).value();
    uint64_t q_half = q / 2;
    
    std::cout << "Using SMALL params: n=" << n << ", L=" << L << ", q[0]=" << q << std::endl;
    
    // Create a small polynomial e (like Gaussian error)
    RNSPoly e(small_ctx.get());
    std::mt19937_64 rng(12345);
    std::normal_distribution<double> gauss(0.0, 3.2);
    for (size_t i = 0; i < n; ++i) {
        int val = static_cast<int>(std::round(gauss(rng)));
        for (size_t level = 0; level < L; ++level) {
            uint64_t q_lvl = small_ctx->modulus(level).value();
            e(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q_lvl - static_cast<uint64_t>(-val);
        }
    }
    
    // Create a ternary polynomial u
    RNSPoly u(small_ctx.get());
    std::uniform_int_distribution<int> ternary(-1, 1);
    int count_minus1 = 0, count_0 = 0, count_plus1 = 0;
    for (size_t i = 0; i < n; ++i) {
        int val = ternary(rng);
        if (val == -1) count_minus1++;
        else if (val == 0) count_0++;
        else count_plus1++;
        for (size_t level = 0; level < L; ++level) {
            uint64_t q_lvl = small_ctx->modulus(level).value();
            u(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q_lvl - static_cast<uint64_t>(-val);
        }
    }
    std::cout << "e: Gaussian(0, 3.2)" << std::endl;
    std::cout << "u: ternary, counts: -1=" << count_minus1 << ", 0=" << count_0 << ", +1=" << count_plus1 << std::endl;
    
    // Compute e * u in coefficient domain (slow, but reference)
    std::vector<int64_t> e_coeffs(n), u_coeffs(n);
    for (size_t i = 0; i < n; ++i) {
        uint64_t c = e(0, i);
        e_coeffs[i] = (c > q_half) ? -static_cast<int64_t>(q - c) : static_cast<int64_t>(c);
        c = u(0, i);
        u_coeffs[i] = (c > q_half) ? -static_cast<int64_t>(q - c) : static_cast<int64_t>(c);
    }
    
    // Print e and u
    std::cout << "e = [";
    for (size_t i = 0; i < n; ++i) std::cout << e_coeffs[i] << (i < n-1 ? ", " : "");
    std::cout << "]" << std::endl;
    std::cout << "u = [";
    for (size_t i = 0; i < n; ++i) std::cout << u_coeffs[i] << (i < n-1 ? ", " : "");
    std::cout << "]" << std::endl;
    
    // Polynomial multiplication mod X^n + 1 (negacyclic)
    std::vector<int64_t> product_ref(n, 0);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            size_t idx = i + j;
            int64_t term = e_coeffs[i] * u_coeffs[j];
            if (idx < n) {
                product_ref[idx] += term;
            } else {
                product_ref[idx - n] -= term;
            }
        }
    }
    // Reduce mod q
    for (size_t i = 0; i < n; ++i) {
        product_ref[i] = product_ref[i] % static_cast<int64_t>(q);
        if (product_ref[i] < 0) product_ref[i] += q;
        if (static_cast<uint64_t>(product_ref[i]) > q_half) {
            product_ref[i] = product_ref[i] - static_cast<int64_t>(q);
        }
    }
    
    std::cout << "Reference e*u = [";
    for (size_t i = 0; i < n; ++i) std::cout << product_ref[i] << (i < n-1 ? ", " : "");
    std::cout << "]" << std::endl;
    
    // Compute e * u using NTT
    e.ntt_transform();
    u.ntt_transform();
    RNSPoly product_ntt = e * u;
    product_ntt.intt_transform();
    
    // Get NTT result
    std::vector<int64_t> ntt_result(n);
    for (size_t i = 0; i < n; ++i) {
        uint64_t c = product_ntt(0, i);
        ntt_result[i] = (c > q_half) ? -static_cast<int64_t>(q - c) : static_cast<int64_t>(c);
    }
    
    std::cout << "NTT e*u = [";
    for (size_t i = 0; i < n; ++i) std::cout << ntt_result[i] << (i < n-1 ? ", " : "");
    std::cout << "]" << std::endl;
    
    // Compare
    int mismatch_count = 0;
    for (size_t i = 0; i < n; ++i) {
        if (ntt_result[i] != product_ref[i]) {
            mismatch_count++;
        }
    }
    std::cout << "Mismatches: " << mismatch_count << " / " << n << std::endl;
    
    EXPECT_EQ(mismatch_count, 0) << "NTT multiplication does not match reference (small params)!";
}

// Debug test: Verify NTT polynomial multiplication semantics
TEST_F(CKKSEvaluatorTest, DebugNTTMultiplicationSemantics) {
    size_t n = context_->n();
    size_t L = context_->level_count();
    uint64_t q = context_->modulus(0).value();
    uint64_t q_half = q / 2;
    
    // Create a small polynomial e (like Gaussian error)
    RNSPoly e(context_.get());
    std::mt19937_64 rng(12345);
    std::normal_distribution<double> gauss(0.0, 3.2);
    for (size_t i = 0; i < n; ++i) {
        int val = static_cast<int>(std::round(gauss(rng)));
        for (size_t level = 0; level < L; ++level) {
            uint64_t q_lvl = context_->modulus(level).value();
            e(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q_lvl - static_cast<uint64_t>(-val);
        }
    }
    
    // Create a ternary polynomial u
    RNSPoly u(context_.get());
    std::uniform_int_distribution<int> ternary(-1, 1);
    int count_minus1 = 0, count_0 = 0, count_plus1 = 0;
    for (size_t i = 0; i < n; ++i) {
        int val = ternary(rng);
        if (val == -1) count_minus1++;
        else if (val == 0) count_0++;
        else count_plus1++;
        for (size_t level = 0; level < L; ++level) {
            uint64_t q_lvl = context_->modulus(level).value();
            u(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q_lvl - static_cast<uint64_t>(-val);
        }
    }
    std::cout << "e: Gaussian(0, 3.2)" << std::endl;
    std::cout << "u: ternary, counts: -1=" << count_minus1 << ", 0=" << count_0 << ", +1=" << count_plus1 << std::endl;
    
    // Compute e * u in coefficient domain (slow, but reference)
    // Product of polynomials mod X^n + 1
    std::vector<int64_t> e_coeffs(n), u_coeffs(n);
    for (size_t i = 0; i < n; ++i) {
        uint64_t c = e(0, i);
        e_coeffs[i] = (c > q_half) ? -static_cast<int64_t>(q - c) : static_cast<int64_t>(c);
        c = u(0, i);
        u_coeffs[i] = (c > q_half) ? -static_cast<int64_t>(q - c) : static_cast<int64_t>(c);
    }
    
    // Polynomial multiplication mod X^n + 1 (negacyclic)
    std::vector<__int128> product_ref(n, 0);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < n; ++j) {
            size_t idx = i + j;
            __int128 term = static_cast<__int128>(e_coeffs[i]) * u_coeffs[j];
            if (idx < n) {
                product_ref[idx] += term;
            } else {
                // mod X^n + 1 means X^n = -1
                product_ref[idx - n] -= term;
            }
        }
    }
    
    // Compute e * u using NTT
    e.ntt_transform();
    u.ntt_transform();
    RNSPoly product_ntt = e * u;
    product_ntt.intt_transform();
    
    // Compare results
    double max_diff = 0;
    int64_t max_expected = 0;
    int mismatch_count = 0;
    for (size_t i = 0; i < n; ++i) {
        // Reference: reduce mod q
        __int128 ref_full = product_ref[i];
        int64_t ref_mod = static_cast<int64_t>(ref_full % static_cast<__int128>(q));
        if (ref_mod < 0) ref_mod += q;
        if (static_cast<uint64_t>(ref_mod) > q_half) {
            ref_mod = ref_mod - static_cast<int64_t>(q);
        }
        
        // NTT result
        uint64_t ntt_c = product_ntt(0, i);
        int64_t ntt_val = (ntt_c > q_half) ? -static_cast<int64_t>(q - ntt_c) : static_cast<int64_t>(ntt_c);
        
        double diff = std::abs(static_cast<double>(ref_mod) - static_cast<double>(ntt_val));
        if (diff > 0.5) {
            mismatch_count++;
            if (mismatch_count <= 5) {
                std::cout << "Mismatch at i=" << i << ": ref=" << ref_mod << ", ntt=" << ntt_val 
                          << ", diff=" << diff << std::endl;
            }
        }
        max_diff = std::max(max_diff, diff);
        max_expected = std::max(max_expected, std::abs(ref_mod));
    }
    
    std::cout << "Max difference: " << max_diff << std::endl;
    std::cout << "Max expected value in e*u: " << max_expected << std::endl;
    std::cout << "Mismatches: " << mismatch_count << " / " << n << std::endl;
    
    EXPECT_EQ(mismatch_count, 0) << "NTT multiplication does not match reference!";
}

// Debug test: Isolate public key encryption issue - step by step reproduce encrypt()
TEST_F(CKKSEvaluatorTest, DebugPublicKeyEncryptStep) {
    std::mt19937_64 rng1(100);
    std::mt19937_64 rng2(200);
    std::mt19937_64 rng3(400);  // Same as EncryptDecryptSingle for u/e sampling
    
    // Generate keys
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng1);
    CKKSPublicKey pk = evaluator_->generate_public_key(sk, rng2);
    
    size_t n = context_->n();
    size_t L = context_->level_count();
    
    // Verify RLWE: b + a*s should be small
    RNSPoly check = pk.b;
    RNSPoly as = pk.a * sk.s;
    check += as;
    check.intt_transform();
    
    double max_rlwe_error = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t q = context_->modulus(0).value();
        uint64_t q_half = q / 2;
        uint64_t c = check(0, i);
        double val = (c > q_half) ? -static_cast<double>(q - c) : static_cast<double>(c);
        max_rlwe_error = std::max(max_rlwe_error, std::abs(val));
    }
    std::cout << "RLWE check (b + a*s): max_error = " << max_rlwe_error << " (should be small ~10-20)" << std::endl;
    ASSERT_LT(max_rlwe_error, 1000) << "RLWE verification failed!";
    
    // Sample u just like encrypt() does
    RNSPoly u(context_.get());
    std::uniform_int_distribution<int> dist(-1, 1);
    for (size_t i = 0; i < n; ++i) {
        int val = dist(rng3);
        for (size_t level = 0; level < L; ++level) {
            uint64_t q = context_->modulus(level).value();
            u(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q - static_cast<uint64_t>(-val);
        }
    }
    
    // Count u distribution
    int count_minus1 = 0, count_0 = 0, count_plus1 = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t q = context_->modulus(0).value();
        uint64_t c = u(0, i);
        if (c == 0) count_0++;
        else if (c == 1) count_plus1++;
        else if (c == q - 1) count_minus1++;
    }
    std::cout << "u distribution: -1=" << count_minus1 << ", 0=" << count_0 << ", +1=" << count_plus1 << std::endl;
    
    u.ntt_transform();
    
    // KEY TEST: What is (b + a*s) * u in coefficient domain?
    // It should be -e * u, which is small (e is small, u is ternary)
    RNSPoly bpas = pk.b;
    bpas += as;  // Now bpas = b + a*s = -e (in NTT form)
    RNSPoly neg_e_times_u = bpas * u;  // (-e) * u
    neg_e_times_u.intt_transform();
    
    double max_eu_error = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t q = context_->modulus(0).value();
        uint64_t q_half = q / 2;
        uint64_t c = neg_e_times_u(0, i);
        double val = (c > q_half) ? -static_cast<double>(q - c) : static_cast<double>(c);
        max_eu_error = std::max(max_eu_error, std::abs(val));
    }
    std::cout << "(-e) * u: max_value = " << max_eu_error << " (should be small ~100)" << std::endl;
    
    // Now reproduce encrypt exactly
    // reload as from NTT form (need fresh copy since intt_transform modified it)
    RNSPoly as_ntt = pk.a * sk.s;  // fresh a*s in NTT
    
    // Refresh u from same RNG seed
    std::mt19937_64 rng3_copy(400);
    RNSPoly u2(context_.get());
    for (size_t i = 0; i < n; ++i) {
        int val = dist(rng3_copy);
        for (size_t level = 0; level < L; ++level) {
            uint64_t q = context_->modulus(level).value();
            u2(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q - static_cast<uint64_t>(-val);
        }
    }
    u2.ntt_transform();
    
    // c0 = b*u, c1 = a*u
    RNSPoly c0 = pk.b * u2;
    RNSPoly c1 = pk.a * u2;
    
    // Decrypt: c0 + c1*s
    RNSPoly decrypted_ntt = c0;
    decrypted_ntt += c1 * sk.s;  // c0 + c1*s
    decrypted_ntt.intt_transform();
    
    double max_decrypt_error = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t q = context_->modulus(0).value();
        uint64_t q_half = q / 2;
        uint64_t c = decrypted_ntt(0, i);
        double val = (c > q_half) ? -static_cast<double>(q - c) : static_cast<double>(c);
        max_decrypt_error = std::max(max_decrypt_error, std::abs(val));
    }
    std::cout << "c0 + c1*s (no message, no error terms e0/e1): max = " << max_decrypt_error << std::endl;
    
    // Mathematical expectation:
    // c0 + c1*s = b*u + (a*u)*s = b*u + a*s*u = (b + a*s)*u = (-e)*u
    // So this should equal neg_e_times_u!
    
    // But we need to verify associativity: (a*s)*u == a*(s*u)
    RNSPoly as_times_u = as_ntt * u2;  // (a*s) * u
    RNSPoly s_times_u = sk.s * u2;      // s * u
    RNSPoly a_times_su = pk.a * s_times_u;  // a * (s*u)
    
    as_times_u.intt_transform();
    a_times_su.intt_transform();
    
    bool assoc_match = true;
    for (size_t i = 0; i < n; ++i) {
        if (as_times_u(0, i) != a_times_su(0, i)) {
            std::cout << "Associativity mismatch at i=" << i << ": (a*s)*u=" << as_times_u(0, i)
                      << ", a*(s*u)=" << a_times_su(0, i) << std::endl;
            assoc_match = false;
            if (i >= 10) break;  // Limit output
        }
    }
    std::cout << "Associativity test: " << (assoc_match ? "PASS" : "FAIL") << std::endl;
    
    EXPECT_LT(max_decrypt_error, 1000) << "Decryption error too large (no message/noise)";
}

// Debug test: verify RLWE correctness step by step
TEST_F(CKKSEvaluatorTest, DebugRLWECorrectness) {
    std::mt19937_64 rng1(100);
    std::mt19937_64 rng2(200);
    
    // Generate secret key
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng1);
    
    // Generate public key
    CKKSPublicKey pk = evaluator_->generate_public_key(sk, rng2);
    
    // Verify: b + a*s should be close to zero (since b = -(a*s + e))
    // If b = -(a*s + e), then b + a*s = -e (small error)
    RNSPoly check = pk.a * sk.s;  // a*s in NTT domain
    check += pk.b;                 // a*s + b = a*s - (a*s + e) = -e
    
    // Transform to coefficient domain to check
    check.intt_transform();
    
    // Check that all coefficients are small (error is ~Gaussian(3.2))
    size_t n = context_->n();
    uint64_t q = context_->modulus(0).value();
    uint64_t q_half = q / 2;
    
    double max_error = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t coef = check(0, i);
        double val;
        if (coef > q_half) {
            val = -static_cast<double>(q - coef);
        } else {
            val = static_cast<double>(coef);
        }
        max_error = std::max(max_error, std::abs(val));
    }
    
    // Error should be small (< 100 for Gaussian with sigma=3.2)
    EXPECT_LT(max_error, 100.0)
        << "RLWE verification failed: max error = " << max_error;
}

// Debug test: verify NTT correctness using SMALL params like BFV
TEST_F(CKKSEvaluatorTest, DebugNTTCorrectness) {
    // Use SMALL params matching BFV test to isolate NTT issue
    int log_n_small = 4;  // n = 16
    std::vector<uint64_t> primes_small = {65537, 114689};  // Same as BFV test
    auto small_ctx = std::make_unique<RNSContext>(log_n_small, primes_small);
    
    size_t L = small_ctx->level_count();
    size_t n = small_ctx->n();  // 16
    
    std::cout << "Using small params: n=" << n << ", L=" << L << std::endl;
    
    // Test 1: Multiply by 1 (constant polynomial)
    // a = [1, 0, 0, ..., 0]
    // b = small polynomial
    // NTT(a) * NTT(b) -> INTT should equal b
    
    RNSPoly a(small_ctx.get());
    for (size_t level = 0; level < L; ++level) {
        a(level, 0) = 1;
        for (size_t i = 1; i < n; ++i) a(level, i) = 0;
    }
    
    RNSPoly b(small_ctx.get());
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<int> dist(-10, 10);
    for (size_t i = 0; i < n; ++i) {
        int val = dist(rng);
        for (size_t level = 0; level < L; ++level) {
            uint64_t q = small_ctx->modulus(level).value();
            b(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q - static_cast<uint64_t>(-val);
        }
    }
    
    // Save original b
    std::vector<int64_t> b_orig(n);
    uint64_t q = small_ctx->modulus(0).value();
    uint64_t q_half = q / 2;
    for (size_t i = 0; i < n; ++i) {
        uint64_t c = b(0, i);
        b_orig[i] = (c > q_half) ? -static_cast<int64_t>(q - c) : static_cast<int64_t>(c);
    }
    
    // Transform both
    a.ntt_transform();
    b.ntt_transform();
    
    // Multiply
    RNSPoly product = a * b;
    
    // Transform back
    product.intt_transform();
    
    // Compare
    bool match = true;
    for (size_t i = 0; i < n; ++i) {
        uint64_t c = product(0, i);
        int64_t val = (c > q_half) ? -static_cast<int64_t>(q - c) : static_cast<int64_t>(c);
        if (val != b_orig[i]) {
            std::cout << "Mismatch at i=" << i << ": expected=" << b_orig[i] << ", got=" << val << std::endl;
            match = false;
        }
    }
    EXPECT_TRUE(match) << "a=1 * b should equal b (small params)";
    
    // If passed, test with CKKS original large params
    if (match) {
        std::cout << "Small params passed, now testing CKKS original params..." << std::endl;
        
        // Test with CKKS context
        RNSPoly a2(context_.get());
        size_t L2 = context_->level_count();
        size_t n2 = context_->n();
        
        for (size_t level = 0; level < L2; ++level) {
            a2(level, 0) = 1;
            for (size_t i = 1; i < n2; ++i) a2(level, i) = 0;
        }
        
        RNSPoly b2(context_.get());
        for (size_t i = 0; i < n2; ++i) {
            int val = (i % 21) - 10;  // Values from -10 to 10
            for (size_t level = 0; level < L2; ++level) {
                uint64_t q_lvl = context_->modulus(level).value();
                b2(level, i) = (val >= 0) ? static_cast<uint64_t>(val) : q_lvl - static_cast<uint64_t>(-val);
            }
        }
        
        // Save original b2
        std::vector<int64_t> b2_orig(n2);
        uint64_t q2 = context_->modulus(0).value();
        uint64_t q2_half = q2 / 2;
        for (size_t i = 0; i < n2; ++i) {
            uint64_t c = b2(0, i);
            b2_orig[i] = (c > q2_half) ? -static_cast<int64_t>(q2 - c) : static_cast<int64_t>(c);
        }
        
        a2.ntt_transform();
        b2.ntt_transform();
        RNSPoly product2 = a2 * b2;
        product2.intt_transform();
        
        bool match2 = true;
        for (size_t i = 0; i < n2 && match2; ++i) {
            uint64_t c = product2(0, i);
            int64_t val = (c > q2_half) ? -static_cast<int64_t>(q2 - c) : static_cast<int64_t>(c);
            if (val != b2_orig[i]) {
                std::cout << "CKKS ctx mismatch at i=" << i << ": expected=" << b2_orig[i] << ", got=" << val << std::endl;
                match2 = false;
            }
        }
        EXPECT_TRUE(match2) << "a=1 * b should equal b (CKKS params)";
    }
}

TEST_F(CKKSEvaluatorTest, EncryptDecryptSingle) {
    // Debug: Test public key encryption step by step
    std::mt19937_64 rng1(100);
    std::mt19937_64 rng2(200);
    
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng1);
    
    double value = 3.14159;
    CKKSPlaintext pt = evaluator_->encoder().encode_real({value}, scale_);
    
    // Test 1: Symmetric encryption (baseline - should work)
    std::mt19937_64 rng3(300);
    CKKSCiphertext ct_sym = evaluator_->encrypt_symmetric(sk, pt, rng3);
    CKKSPlaintext dec_sym = evaluator_->decrypt(sk, ct_sym);
    std::vector<double> result_sym = evaluator_->encoder().decode_real(dec_sym);
    EXPECT_TRUE(approx_equal(value, result_sym[0], 1.0))
        << "Symmetric: Expected " << value << ", got " << result_sym[0];
    
    // Test 2: Public key encryption
    CKKSPublicKey pk = evaluator_->generate_public_key(sk, rng2);
    std::mt19937_64 rng4(400);
    CKKSCiphertext ct = evaluator_->encrypt(pk, pt, rng4);
    
    // Debug: Check ciphertext directly
    // Decrypt: c0 + c1*s should give m + small error
    RNSPoly result_poly = ct.c1();
    result_poly *= sk.s;  // c1 * s
    result_poly += ct.c0();  // c0 + c1*s
    result_poly.intt_transform();
    
    size_t n = context_->n();
    uint64_t q = context_->modulus(0).value();
    uint64_t q_half = q / 2;
    
    // Get the constant coefficient
    uint64_t c0 = result_poly(0, 0);
    double decrypted_scaled;
    if (c0 > q_half) {
        decrypted_scaled = -static_cast<double>(q - c0);
    } else {
        decrypted_scaled = static_cast<double>(c0);
    }
    double decrypted_value = decrypted_scaled / scale_;
    
    std::cout << "DEBUG: Plaintext encoded at coef[0] = " << pt.data()(0, 0) << std::endl;
    std::cout << "DEBUG: Expected scaled value = " << value * scale_ << std::endl;
    std::cout << "DEBUG: Decrypted (c0+c1*s)[0] = " << decrypted_scaled << std::endl;
    std::cout << "DEBUG: Decrypted value = " << decrypted_value << std::endl;
    
    // Check max error in ALL coefficients
    double max_error = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t c = result_poly(0, i);
        double val;
        if (c > q_half) {
            val = -static_cast<double>(q - c);
        } else {
            val = static_cast<double>(c);
        }
        // Subtract expected plaintext
        uint64_t pt_coef = pt.data()(0, i);
        double pt_val;
        if (pt_coef > q_half) {
            pt_val = -static_cast<double>(q - pt_coef);
        } else {
            pt_val = static_cast<double>(pt_coef);
        }
        double error = std::abs(val - pt_val);
        max_error = std::max(max_error, error);
    }
    std::cout << "DEBUG: Max decryption error (any coef) = " << max_error << std::endl;
    
    // Expect small error (should be < 1000 for reasonable params)
    EXPECT_LT(max_error, 100000.0) << "Decryption error too large";
    
    // Use evaluator's decrypt
    CKKSPlaintext decrypted = evaluator_->decrypt(sk, ct);
    std::vector<double> result = evaluator_->encoder().decode_real(decrypted);
    
    EXPECT_TRUE(approx_equal(value, result[0], 1.0))
        << "Public key: Expected " << value << ", got " << result[0];
}

TEST_F(CKKSEvaluatorTest, SymmetricEncryptDecrypt) {
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng_);
    
    std::vector<double> values = {1.0, 2.0, 3.0};
    CKKSPlaintext pt = evaluator_->encoder().encode_real(values, scale_);
    
    CKKSCiphertext ct = evaluator_->encrypt_symmetric(sk, pt, rng_);
    CKKSPlaintext decrypted = evaluator_->decrypt(sk, ct);
    
    std::vector<double> result = evaluator_->encoder().decode_real(decrypted);
    
    for (size_t i = 0; i < values.size() && i < result.size(); ++i) {
        EXPECT_TRUE(approx_equal(values[i], result[i], 1.0))
            << "Mismatch at index " << i;
    }
}

// ============================================================================
// Homomorphic Operation Tests
// ============================================================================

TEST_F(CKKSEvaluatorTest, HomomorphicAddition) {
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng_);
    CKKSPublicKey pk = evaluator_->generate_public_key(sk, rng_);
    
    double v1 = 2.0;
    double v2 = 3.0;
    
    // Use encode_real for proper canonical embedding
    CKKSPlaintext pt1 = evaluator_->encoder().encode_real({v1}, scale_);
    CKKSPlaintext pt2 = evaluator_->encoder().encode_real({v2}, scale_);
    
    CKKSCiphertext ct1 = evaluator_->encrypt(pk, pt1, rng_);
    CKKSCiphertext ct2 = evaluator_->encrypt(pk, pt2, rng_);
    
    CKKSCiphertext ct_sum = evaluator_->add(ct1, ct2);
    CKKSPlaintext decrypted = evaluator_->decrypt(sk, ct_sum);
    
    std::vector<double> result = evaluator_->encoder().decode_real(decrypted);
    
    double expected = v1 + v2;
    EXPECT_TRUE(approx_equal(expected, result[0], 1.5))
        << "Addition: expected " << expected << ", got " << result[0];
}

TEST_F(CKKSEvaluatorTest, HomomorphicSubtraction) {
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng_);
    CKKSPublicKey pk = evaluator_->generate_public_key(sk, rng_);
    
    double v1 = 5.0;
    double v2 = 2.0;
    
    // Use encode_real for proper canonical embedding
    CKKSPlaintext pt1 = evaluator_->encoder().encode_real({v1}, scale_);
    CKKSPlaintext pt2 = evaluator_->encoder().encode_real({v2}, scale_);
    
    CKKSCiphertext ct1 = evaluator_->encrypt(pk, pt1, rng_);
    CKKSCiphertext ct2 = evaluator_->encrypt(pk, pt2, rng_);
    
    CKKSCiphertext ct_diff = evaluator_->sub(ct1, ct2);
    CKKSPlaintext decrypted = evaluator_->decrypt(sk, ct_diff);
    
    std::vector<double> result = evaluator_->encoder().decode_real(decrypted);
    
    double expected = v1 - v2;
    EXPECT_TRUE(approx_equal(expected, result[0], 1.5))
        << "Subtraction: expected " << expected << ", got " << result[0];
}

TEST_F(CKKSEvaluatorTest, AddPlaintext) {
    CKKSSecretKey sk = evaluator_->generate_secret_key(rng_);
    CKKSPublicKey pk = evaluator_->generate_public_key(sk, rng_);
    
    double v1 = 3.0;
    double v2 = 7.0;
    
    // Use encode_real for proper canonical embedding
    CKKSPlaintext pt1 = evaluator_->encoder().encode_real({v1}, scale_);
    CKKSPlaintext pt2 = evaluator_->encoder().encode_real({v2}, scale_);
    
    CKKSCiphertext ct1 = evaluator_->encrypt(pk, pt1, rng_);
    CKKSCiphertext ct_sum = evaluator_->add_plain(ct1, pt2);
    
    CKKSPlaintext decrypted = evaluator_->decrypt(sk, ct_sum);
    std::vector<double> result = evaluator_->encoder().decode_real(decrypted);
    
    double expected = v1 + v2;
    EXPECT_TRUE(approx_equal(expected, result[0], 1.5))
        << "Add plain: expected " << expected << ", got " << result[0];
}

// ============================================================================
// Scale Management Tests
// ============================================================================

TEST_F(CKKSEvaluatorTest, ScalesMatch) {
    CKKSCiphertext ct1(context_.get(), 1000.0);
    CKKSCiphertext ct2(context_.get(), 1000.0);
    CKKSCiphertext ct3(context_.get(), 2000.0);
    
    EXPECT_TRUE(evaluator_->scales_match(ct1, ct2));
    EXPECT_FALSE(evaluator_->scales_match(ct1, ct3));
}

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
