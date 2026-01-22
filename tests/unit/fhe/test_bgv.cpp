/**
 * @file test_bgv.cpp
 * @brief Unit Tests for BGV Homomorphic Encryption
 * 
 * Tests for native kctsb BGV implementation.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <gtest/gtest.h>
#include <vector>
#include <numeric>
#include <random>

#include "kctsb/advanced/fe/bgv/bgv.hpp"

using namespace kctsb::fhe::bgv;

// ============================================================================
// Test Fixtures
// ============================================================================

class BGVTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use toy parameters for fast testing
        params_ = StandardParams::TOY_PARAMS();
        context_ = std::make_unique<BGVContext>(params_);
        encoder_ = std::make_unique<BGVEncoder>(*context_);
        evaluator_ = std::make_unique<BGVEvaluator>(*context_);
        
        // Generate keys
        sk_ = context_->generate_secret_key();
        pk_ = context_->generate_public_key(sk_);
        rk_ = context_->generate_relin_key(sk_);
    }
    
    void TearDown() override {
        // Cleanup handled by unique_ptrs
    }
    
    BGVParams params_;
    std::unique_ptr<BGVContext> context_;
    std::unique_ptr<BGVEncoder> encoder_;
    std::unique_ptr<BGVEvaluator> evaluator_;
    BGVSecretKey sk_;
    BGVPublicKey pk_;
    BGVRelinKey rk_;
};

// ============================================================================
// Parameter Tests
// ============================================================================

TEST(BGVParamsTest, ToyParamsAreValid) {
    auto params = StandardParams::TOY_PARAMS();
    EXPECT_TRUE(params.validate());
    EXPECT_GT(params.n, 0u);
    EXPECT_GT(params.t, 0u);
    EXPECT_GT(params.L, 0u);
}

TEST(BGVParamsTest, StandardParamsAreValid) {
    auto params128_3 = StandardParams::SECURITY_128_DEPTH_3();
    EXPECT_TRUE(params128_3.validate());
    
    auto params128_5 = StandardParams::SECURITY_128_DEPTH_5();
    EXPECT_TRUE(params128_5.validate());
}

TEST(BGVParamsTest, CreateStandardParams) {
    auto params = BGVParams::create_standard(SecurityLevel::CLASSICAL_128, 3, 65537);
    EXPECT_TRUE(params.validate());
    EXPECT_EQ(params.t, 65537u);
    EXPECT_EQ(params.L, 4u);  // depth + 1
}

// ============================================================================
// Context Tests
// ============================================================================

TEST(BGVContextTest, ContextCreation) {
    auto params = StandardParams::TOY_PARAMS();
    EXPECT_NO_THROW({
        BGVContext context(params);
    });
}

// Step-by-step debug test
TEST(BGVContextTest, StepByStepCreation) {
    auto params = StandardParams::TOY_PARAMS();
    
    // Step 1: Create context
    BGVContext context(params);
    
    // Step 2: Create encoder
    EXPECT_NO_THROW({
        BGVEncoder encoder(context);
    });
    
    // Step 3: Create evaluator
    EXPECT_NO_THROW({
        BGVEvaluator evaluator(context);
    });
    
    // Step 4: Generate secret key
    BGVSecretKey sk;
    EXPECT_NO_THROW({
        sk = context.generate_secret_key();
    });
    
    // Step 5: Generate public key
    EXPECT_NO_THROW({
        auto pk = context.generate_public_key(sk);
    });
    
    // Step 6: Generate relin key
    EXPECT_NO_THROW({
        auto rk = context.generate_relin_key(sk);
    });
}

TEST(BGVContextTest, InvalidParamsThrows) {
    BGVParams invalid_params;
    invalid_params.m = 0;  // Invalid
    
    EXPECT_THROW({
        BGVContext context(invalid_params);
    }, std::invalid_argument);
}

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST_F(BGVTest, SecretKeyGeneration) {
    auto sk = context_->generate_secret_key();
    // Secret key should have small coefficients
    EXPECT_FALSE(sk.data().is_zero());
}

TEST_F(BGVTest, PublicKeyGeneration) {
    auto sk = context_->generate_secret_key();
    auto pk = context_->generate_public_key(sk);
    
    // Public key has two components
    EXPECT_FALSE(pk.a().is_zero());
    EXPECT_FALSE(pk.b().is_zero());
}

TEST_F(BGVTest, RelinKeyGeneration) {
    auto sk = context_->generate_secret_key();
    auto rk = context_->generate_relin_key(sk);
    
    EXPECT_FALSE(rk.data().empty());
}

// ============================================================================
// Encoding Tests
// ============================================================================

TEST_F(BGVTest, IntegerEncode) {
    auto pt = encoder_->encode(42);
    EXPECT_EQ(encoder_->decode_int(pt), 42);
}

TEST_F(BGVTest, NegativeIntegerEncode) {
    auto pt = encoder_->encode(-42);
    // Should wrap around mod t
    int64_t decoded = encoder_->decode_int(pt);
    // Either -42 or t - 42
    EXPECT_TRUE(decoded == -42 || decoded == static_cast<int64_t>(params_.t) - 42);
}

TEST_F(BGVTest, BatchEncode) {
    std::vector<int64_t> values = {1, 2, 3, 4, 5};
    auto pt = encoder_->encode_batch(values);
    
    auto decoded = encoder_->decode_batch(pt);
    
    for (size_t i = 0; i < values.size(); i++) {
        EXPECT_EQ(decoded[i], values[i]) << "Mismatch at index " << i;
    }
}

TEST_F(BGVTest, PolyEncode) {
    std::vector<int64_t> coeffs = {1, 2, 3, 0, 0, 5};
    auto pt = encoder_->encode_poly(coeffs);
    
    auto decoded = encoder_->decode_poly(pt);
    
    for (size_t i = 0; i < coeffs.size(); i++) {
        EXPECT_EQ(decoded[i], coeffs[i]) << "Mismatch at index " << i;
    }
}

// ============================================================================
// Encryption/Decryption Tests
// ============================================================================

// Manual verification test - check each step of BGV encrypt/decrypt
TEST_F(BGVTest, ManualVerifyEncryptDecrypt) {
    using namespace kctsb;
    
    // Use fresh keys for this test
    std::cerr << "\n=== GENERATING NEW KEYS ===\n";
    auto sk = context_->generate_secret_key();
    
    // Print secret key coefficients BEFORE public key generation
    ZZ_p::init(params_.q);
    std::cerr << "sk.s[0] = " << rep(coeff(sk.data().poly(), 0)) << "\n";
    std::cerr << "sk.s[1] = " << rep(coeff(sk.data().poly(), 1)) << "\n";
    std::cerr << "sk.s[2] = " << rep(coeff(sk.data().poly(), 2)) << "\n";
    
    auto pk = context_->generate_public_key(sk);
    
    // Print secret key coefficients AFTER public key generation
    std::cerr << "After pk gen - sk.s[0] = " << rep(coeff(sk.data().poly(), 0)) << "\n";
    std::cerr << "After pk gen - sk.s[1] = " << rep(coeff(sk.data().poly(), 1)) << "\n";
    
    // Simple message: just put 42 in coefficient 0
    ZZ_p::init(to_ZZ(params_.t));
    BGVPlaintext pt;
    SetCoeff(pt.data().poly(), 0, conv<ZZ_p>(42));
    
    // Now encrypt - ensure we're in mod q context
    ZZ_p::init(params_.q);
    auto ct = context_->encrypt(pk, pt);
    
    // Get c0, c1
    const auto& c0 = ct[0];
    const auto& c1 = ct[1];
    
    // Get secret key s
    const auto& s = sk.data();
    
    std::cerr << "\n=== CHECKING s AFTER ENCRYPT ===\n";
    std::cerr << "s[0] after encrypt = " << rep(coeff(s.poly(), 0)) << "\n";
    std::cerr << "s[1] after encrypt = " << rep(coeff(s.poly(), 1)) << "\n";
    
    // Convert all to current context
    ZZ_pX s_q, c0_q, c1_q;
    for (long j = 0; j <= deg(s.poly()); j++) {
        SetCoeff(s_q, j, conv<ZZ_p>(rep(coeff(s.poly(), j))));
    }
    for (long j = 0; j <= deg(c0.poly()); j++) {
        SetCoeff(c0_q, j, conv<ZZ_p>(rep(coeff(c0.poly(), j))));
    }
    for (long j = 0; j <= deg(c1.poly()); j++) {
        SetCoeff(c1_q, j, conv<ZZ_p>(rep(coeff(c1.poly(), j))));
    }
    
    // Compute c1*s
    ZZ_pX c1s;
    PlainMul(c1s, c1_q, s_q);
    ZZ_pX cyclotomic;
    SetCoeff(cyclotomic, 0, conv<ZZ_p>(1));
    SetCoeff(cyclotomic, params_.n, conv<ZZ_p>(1));
    PlainRem(c1s, c1s, cyclotomic);
    
    // Compute result
    ZZ_pX result = c0_q + c1s;
    PlainRem(result, result, cyclotomic);
    
    ZZ r0 = rep(coeff(result, 0));
    ZZ t = to_ZZ(params_.t);
    ZZ r0_mod_t = r0 % t;
    
    std::cerr << "\n=== FINAL VERIFICATION ===\n";
    std::cerr << "c0[0] = " << rep(coeff(c0_q, 0)) << "\n";
    std::cerr << "c1[0] = " << rep(coeff(c1_q, 0)) << "\n";
    std::cerr << "s[0] = " << rep(coeff(s_q, 0)) << "\n";
    std::cerr << "c1s[0] = " << rep(coeff(c1s, 0)) << "\n";
    std::cerr << "result[0] = " << r0 << "\n";
    std::cerr << "result[0] mod t = " << r0_mod_t << "\n";
    std::cerr << "Expected: 42\n";
    
    // Also compute what c0 + c1*s SHOULD be:
    // c0 + c1*s = (b*u + te0 + m) + (a*u + te1)*s
    //           = b*u + a*u*s + m + t*(e0 + e1*s)
    //           = (-a*s + te)*u + a*s*u + m + t*(...)
    //           = t*e*u + m + t*(...)
    //           = m + t*(noise)
    // So (c0 + c1*s) mod t should equal m
    
    // Check if noise is too large
    // If r0 > q/2, it's negative
    ZZ q = params_.q;
    ZZ q_half = q / 2;
    if (r0 > q_half) {
        std::cerr << "Note: r0 is negative (> q/2)\n";
        ZZ r0_neg = r0 - q;  // Convert to signed
        std::cerr << "r0 (signed) = " << r0_neg << "\n";
        // For centered reduction
        ZZ r0_mod_t_signed = r0_neg % t;
        if (r0_mod_t_signed < 0) r0_mod_t_signed += t;
        std::cerr << "r0 mod t (centered) = " << r0_mod_t_signed << "\n";
    }
    
    // Now verify through normal decrypt
    auto pt_dec = context_->decrypt(sk, ct);
    int64_t decoded = encoder_->decode_int(pt_dec);
    
    std::cerr << "Decoded via normal decrypt: " << decoded << "\n";
    std::cerr << "=== END VERIFICATION ===\n\n";
    
    EXPECT_EQ(decoded, 42);
}

TEST_F(BGVTest, EncryptDecryptSingle) {
    // Debug: Print parameters
    std::cout << "Debug: t=" << params_.t << ", q=" << params_.q << ", n=" << params_.n << "\n";
    
    auto pt = encoder_->encode(42);
    std::cout << "Debug: Encoded value coeff(0)=" << rep(pt.data().coeff(0)) << "\n";
    
    auto ct = context_->encrypt(pk_, pt);
    std::cout << "Debug: Ciphertext size=" << ct.size() << "\n";
    
    auto pt_dec = context_->decrypt(sk_, ct);
    std::cout << "Debug: Decrypted coeff(0)=" << rep(pt_dec.data().coeff(0)) << "\n";
    
    int64_t decoded = encoder_->decode_int(pt_dec);
    std::cout << "Debug: Decoded value=" << decoded << "\n";
    
    EXPECT_EQ(decoded, 42);
}

TEST_F(BGVTest, EncryptDecryptBatch) {
    std::vector<int64_t> values(encoder_->slot_count());
    std::iota(values.begin(), values.end(), 1);
    
    auto pt = encoder_->encode_batch(values);
    auto ct = context_->encrypt(pk_, pt);
    auto pt_dec = context_->decrypt(sk_, ct);
    auto decoded = encoder_->decode_batch(pt_dec);
    
    for (size_t i = 0; i < values.size(); i++) {
        int64_t expected = values[i] % static_cast<int64_t>(params_.t);
        EXPECT_EQ(decoded[i], expected) << "Mismatch at slot " << i;
    }
}

TEST_F(BGVTest, EncryptZero) {
    auto ct = context_->encrypt_zero(pk_);
    auto pt = context_->decrypt(sk_, ct);
    
    // All coefficients should be zero
    EXPECT_TRUE(pt.data().is_zero() || encoder_->decode_int(pt) == 0);
}

TEST_F(BGVTest, SymmetricEncryption) {
    auto pt = encoder_->encode(123);
    auto ct = context_->encrypt_symmetric(sk_, pt);
    auto pt_dec = context_->decrypt(sk_, ct);
    
    EXPECT_EQ(encoder_->decode_int(pt_dec), 123);
}

// ============================================================================
// Homomorphic Addition Tests
// ============================================================================

TEST_F(BGVTest, AddCiphertexts) {
    auto pt1 = encoder_->encode(10);
    auto pt2 = encoder_->encode(20);
    
    auto ct1 = context_->encrypt(pk_, pt1);
    auto ct2 = context_->encrypt(pk_, pt2);
    
    auto ct_sum = evaluator_->add(ct1, ct2);
    auto pt_sum = context_->decrypt(sk_, ct_sum);
    
    EXPECT_EQ(encoder_->decode_int(pt_sum), 30);
}

TEST_F(BGVTest, AddPlaintext) {
    auto pt1 = encoder_->encode(10);
    auto pt2 = encoder_->encode(20);
    
    auto ct1 = context_->encrypt(pk_, pt1);
    auto ct_sum = evaluator_->add_plain(ct1, pt2);
    auto pt_sum = context_->decrypt(sk_, ct_sum);
    
    EXPECT_EQ(encoder_->decode_int(pt_sum), 30);
}

TEST_F(BGVTest, SubCiphertexts) {
    auto pt1 = encoder_->encode(50);
    auto pt2 = encoder_->encode(20);
    
    auto ct1 = context_->encrypt(pk_, pt1);
    auto ct2 = context_->encrypt(pk_, pt2);
    
    auto ct_diff = evaluator_->sub(ct1, ct2);
    auto pt_diff = context_->decrypt(sk_, ct_diff);
    
    EXPECT_EQ(encoder_->decode_int(pt_diff), 30);
}

TEST_F(BGVTest, Negate) {
    auto pt = encoder_->encode(42);
    auto ct = context_->encrypt(pk_, pt);
    
    auto ct_neg = evaluator_->negate(ct);
    auto pt_neg = context_->decrypt(sk_, ct_neg);
    
    int64_t result = encoder_->decode_int(pt_neg);
    // -42 mod t
    int64_t expected = static_cast<int64_t>(params_.t) - 42;
    EXPECT_TRUE(result == -42 || result == expected);
}

// ============================================================================
// Homomorphic Multiplication Tests
// ============================================================================

TEST_F(BGVTest, MultiplyPlaintext) {
    auto pt1 = encoder_->encode(7);
    auto pt2 = encoder_->encode(6);
    
    auto ct1 = context_->encrypt(pk_, pt1);
    auto ct_prod = evaluator_->multiply_plain(ct1, pt2);
    auto pt_prod = context_->decrypt(sk_, ct_prod);
    
    EXPECT_EQ(encoder_->decode_int(pt_prod), 42);
}

TEST_F(BGVTest, MultiplyCiphertexts) {
    auto pt1 = encoder_->encode(7);
    auto pt2 = encoder_->encode(6);
    
    auto ct1 = context_->encrypt(pk_, pt1);
    auto ct2 = context_->encrypt(pk_, pt2);
    
    auto ct_prod = evaluator_->multiply(ct1, ct2);
    
    // Without relinearization, ciphertext has 3 components
    EXPECT_EQ(ct_prod.size(), 3u);
    
    auto pt_prod = context_->decrypt(sk_, ct_prod);
    EXPECT_EQ(encoder_->decode_int(pt_prod), 42);
}

// Manual verification of multiplication correctness
TEST_F(BGVTest, ManualVerifyMultiply) {
    using namespace kctsb;
    
    std::cerr << "\n=== MANUAL MULTIPLY VERIFICATION ===\n";
    
    // Fresh keys
    auto sk = context_->generate_secret_key();
    auto pk = context_->generate_public_key(sk);
    
    ZZ_p::init(params_.q);
    
    // Get secret key polynomial
    ZZ_pX s;
    for (long j = 0; j <= sk.data().degree(); j++) {
        SetCoeff(s, j, conv<ZZ_p>(rep(sk.data().coeff(j))));
    }
    
    // Encrypt 7 and 6
    auto pt1 = encoder_->encode(7);
    auto pt2 = encoder_->encode(6);
    auto ct1 = context_->encrypt(pk, pt1);
    auto ct2 = context_->encrypt(pk, pt2);
    
    // First verify ct1 decrypts correctly
    ZZ_p::init(params_.q);
    ZZ_pX c0, c1, d0, d1;
    for (long j = 0; j <= ct1[0].degree(); j++) {
        SetCoeff(c0, j, conv<ZZ_p>(rep(ct1[0].coeff(j))));
    }
    for (long j = 0; j <= ct1[1].degree(); j++) {
        SetCoeff(c1, j, conv<ZZ_p>(rep(ct1[1].coeff(j))));
    }
    for (long j = 0; j <= ct2[0].degree(); j++) {
        SetCoeff(d0, j, conv<ZZ_p>(rep(ct2[0].coeff(j))));
    }
    for (long j = 0; j <= ct2[1].degree(); j++) {
        SetCoeff(d1, j, conv<ZZ_p>(rep(ct2[1].coeff(j))));
    }
    
    ZZ_pX cyclotomic;
    SetCoeff(cyclotomic, 0, conv<ZZ_p>(1));
    SetCoeff(cyclotomic, params_.n, conv<ZZ_p>(1));
    
    // Verify ct1 decrypts to 7
    ZZ_pX c1s;
    PlainMul(c1s, c1, s);
    PlainRem(c1s, c1s, cyclotomic);
    ZZ_pX m1_noise = c0 + c1s;
    PlainRem(m1_noise, m1_noise, cyclotomic);
    ZZ m1_coef0 = rep(coeff(m1_noise, 0));
    ZZ q = params_.q;
    if (m1_coef0 > q/2) m1_coef0 -= q;
    std::cerr << "ct1 decrypt: (c0+c1*s)[0] = " << m1_coef0 << " mod t = " << (m1_coef0 % to_ZZ(params_.t)) << " (expect 7)\n";
    
    // Verify ct2 decrypts to 6
    ZZ_pX d1s;
    PlainMul(d1s, d1, s);
    PlainRem(d1s, d1s, cyclotomic);
    ZZ_pX m2_noise = d0 + d1s;
    PlainRem(m2_noise, m2_noise, cyclotomic);
    ZZ m2_coef0 = rep(coeff(m2_noise, 0));
    if (m2_coef0 > q/2) m2_coef0 -= q;
    std::cerr << "ct2 decrypt: (d0+d1*s)[0] = " << m2_coef0 << " mod t = " << (m2_coef0 % to_ZZ(params_.t)) << " (expect 6)\n";
    
    // Now compute the product of (c0+c1*s) and (d0+d1*s)
    // This should equal m1*m2 + t*noise = 42 + t*noise
    ZZ_pX prod;
    PlainMul(prod, m1_noise, m2_noise);
    PlainRem(prod, prod, cyclotomic);
    ZZ prod_coef0 = rep(coeff(prod, 0));
    if (prod_coef0 > q/2) prod_coef0 -= q;
    std::cerr << "Direct multiply: ((c0+c1*s)*(d0+d1*s))[0] = " << prod_coef0 << " mod t = " << (prod_coef0 % to_ZZ(params_.t)) << " (expect 42)\n";
    
    // Now verify tensor product gives the same result
    // ct_prod = (c0*d0, c0*d1+c1*d0, c1*d1)
    // Decrypt: r0 + r1*s + r2*s^2 = c0*d0 + (c0*d1+c1*d0)*s + c1*d1*s^2
    //        = c0*d0 + c0*d1*s + c1*d0*s + c1*d1*s^2
    //        = c0*(d0+d1*s) + c1*s*(d0+d1*s)
    //        = (c0+c1*s)*(d0+d1*s)
    // So they should be identical!
    
    auto ct_prod = evaluator_->multiply(ct1, ct2);
    
    // Verify by manually computing r0 + r1*s + r2*s^2
    ZZ_pX r0, r1, r2;
    for (long j = 0; j <= ct_prod[0].degree(); j++) {
        SetCoeff(r0, j, conv<ZZ_p>(rep(ct_prod[0].coeff(j))));
    }
    for (long j = 0; j <= ct_prod[1].degree(); j++) {
        SetCoeff(r1, j, conv<ZZ_p>(rep(ct_prod[1].coeff(j))));
    }
    for (long j = 0; j <= ct_prod[2].degree(); j++) {
        SetCoeff(r2, j, conv<ZZ_p>(rep(ct_prod[2].coeff(j))));
    }
    
    // Compute s^2
    ZZ_pX s2;
    PlainMul(s2, s, s);
    PlainRem(s2, s2, cyclotomic);
    
    // Compute r1*s
    ZZ_pX r1s;
    PlainMul(r1s, r1, s);
    PlainRem(r1s, r1s, cyclotomic);
    
    // Compute r2*s^2
    ZZ_pX r2s2;
    PlainMul(r2s2, r2, s2);
    PlainRem(r2s2, r2s2, cyclotomic);
    
    // Sum
    ZZ_pX tensor_result = r0 + r1s + r2s2;
    PlainRem(tensor_result, tensor_result, cyclotomic);
    
    ZZ tensor_coef0 = rep(coeff(tensor_result, 0));
    if (tensor_coef0 > q/2) tensor_coef0 -= q;
    std::cerr << "Tensor decrypt: (r0+r1*s+r2*s^2)[0] = " << tensor_coef0 << " mod t = " << (tensor_coef0 % to_ZZ(params_.t)) << " (expect 42)\n";
    
    // Compare: prod_coef0 should equal tensor_coef0
    std::cerr << "Direct == Tensor? " << (prod_coef0 == tensor_coef0 ? "YES" : "NO") << "\n";
    
    // Also verify through normal decrypt
    auto pt_prod = context_->decrypt(sk, ct_prod);
    int64_t decoded = encoder_->decode_int(pt_prod);
    std::cerr << "Normal decrypt: " << decoded << " (expect 42)\n";
    
    std::cerr << "=== END MANUAL MULTIPLY VERIFICATION ===\n\n";
    
    EXPECT_EQ(decoded, 42);
}

TEST_F(BGVTest, MultiplyAndRelinearize) {
    auto pt1 = encoder_->encode(7);
    auto pt2 = encoder_->encode(6);
    
    auto ct1 = context_->encrypt(pk_, pt1);
    auto ct2 = context_->encrypt(pk_, pt2);
    
    auto ct_prod = evaluator_->multiply_relin(ct1, ct2, rk_);
    
    // After relinearization, should have 2 components
    EXPECT_EQ(ct_prod.size(), 2u);
    
    auto pt_prod = context_->decrypt(sk_, ct_prod);
    EXPECT_EQ(encoder_->decode_int(pt_prod), 42);
}

TEST_F(BGVTest, Square) {
    auto pt = encoder_->encode(7);
    auto ct = context_->encrypt(pk_, pt);
    
    auto ct_sq = evaluator_->square(ct);
    auto pt_sq = context_->decrypt(sk_, ct_sq);
    
    EXPECT_EQ(encoder_->decode_int(pt_sq), 49);
}

// ============================================================================
// Noise Budget Tests
// ============================================================================

TEST_F(BGVTest, FreshCiphertextHasNoiseBudget) {
    auto pt = encoder_->encode(42);
    auto ct = context_->encrypt(pk_, pt);
    
    double budget = context_->noise_budget(sk_, ct);
    EXPECT_GT(budget, 0);
}

TEST_F(BGVTest, NoiseBudgetDecreasesAfterMultiply) {
    auto pt = encoder_->encode(2);
    auto ct = context_->encrypt(pk_, pt);
    
    double initial_budget = context_->noise_budget(sk_, ct);
    
    auto ct_sq = evaluator_->square(ct);
    double after_budget = context_->noise_budget(sk_, ct_sq);
    
    EXPECT_LT(after_budget, initial_budget);
}

TEST_F(BGVTest, CiphertextValidity) {
    auto pt = encoder_->encode(42);
    auto ct = context_->encrypt(pk_, pt);
    
    EXPECT_TRUE(context_->is_valid(sk_, ct));
}

// ============================================================================
// Complex Operations Tests
// ============================================================================

TEST_F(BGVTest, InnerProduct) {
    std::vector<BGVCiphertext> ct1_vec;
    std::vector<BGVCiphertext> ct2_vec;
    
    int64_t expected_sum = 0;
    
    for (int i = 1; i <= 3; i++) {
        auto pt1 = encoder_->encode(i);
        auto pt2 = encoder_->encode(i + 1);
        ct1_vec.push_back(context_->encrypt(pk_, pt1));
        ct2_vec.push_back(context_->encrypt(pk_, pt2));
        expected_sum += i * (i + 1);
    }
    
    auto ct_result = evaluator_->inner_product(ct1_vec, ct2_vec, rk_);
    auto pt_result = context_->decrypt(sk_, ct_result);
    
    EXPECT_EQ(encoder_->decode_int(pt_result), expected_sum);
}

// Use standalone test (not fixture) to avoid modulus context pollution
TEST(BGVStandaloneTest, Power) {
    // Completely isolated test: NO fixture, NO SetUp
    // Test: Compute 3^3 = 27 using relinearization
    
    auto params = kctsb::fhe::bgv::StandardParams::TOY_PARAMS();
    auto ctx = std::make_shared<kctsb::fhe::bgv::BGVContext>(params);
    
    auto local_sk = ctx->generate_secret_key();
    auto local_pk = ctx->generate_public_key(local_sk);
    auto local_rk = ctx->generate_relin_key(local_sk);
    auto local_encoder = std::make_shared<kctsb::fhe::bgv::BGVEncoder>(*ctx);
    auto local_eval = std::make_shared<kctsb::fhe::bgv::BGVEvaluator>(*ctx);
    
    // Step 1: Encrypt 3
    auto pt_3 = local_encoder->encode(3);
    auto ct_3 = ctx->encrypt(local_pk, pt_3);
    
    auto dec_3 = ctx->decrypt(local_sk, ct_3);
    int val_3 = local_encoder->decode_int(dec_3);
    std::cerr << "Power test: encrypt(3) = " << val_3 << "\n";
    EXPECT_EQ(val_3, 3);
    
    // Step 2: Compute 3*3 = 9
    auto ct_9 = local_eval->multiply(ct_3, ct_3);
    
    auto dec_9_before = ctx->decrypt(local_sk, ct_9);
    int val_9_before = local_encoder->decode_int(dec_9_before);
    std::cerr << "Power test: 3*3 (size=" << ct_9.size() << ") = " << val_9_before << " (expected 9)\n";
    EXPECT_EQ(val_9_before, 9);
    
    // Step 3: Relinearize
    local_eval->relinearize_inplace(ct_9, local_rk);
    
    auto dec_9_after = ctx->decrypt(local_sk, ct_9);
    int val_9_after = local_encoder->decode_int(dec_9_after);
    std::cerr << "Power test: 3*3 after relin (size=" << ct_9.size() << ") = " << val_9_after << " (expected 9)\n";
    EXPECT_EQ(val_9_after, 9);
    
    // Step 4: Encrypt fresh 3
    auto pt_3b = local_encoder->encode(3);
    auto ct_3b = ctx->encrypt(local_pk, pt_3b);
    
    auto dec_3b = ctx->decrypt(local_sk, ct_3b);
    int val_3b = local_encoder->decode_int(dec_3b);
    std::cerr << "Power test: encrypt(3) again = " << val_3b << "\n";
    EXPECT_EQ(val_3b, 3);
    
    // Step 5: Compute 9*3 = 27
    auto ct_27 = local_eval->multiply(ct_9, ct_3b);
    
    auto dec_27_before = ctx->decrypt(local_sk, ct_27);
    int val_27_before = local_encoder->decode_int(dec_27_before);
    std::cerr << "Power test: 9*3 (size=" << ct_27.size() << ") = " << val_27_before << " (expected 27)\n";
    EXPECT_EQ(val_27_before, 27);
    
    // Step 6: Relinearize final result
    local_eval->relinearize_inplace(ct_27, local_rk);
    
    auto dec_27_after = ctx->decrypt(local_sk, ct_27);
    int val_27_after = local_encoder->decode_int(dec_27_after);
    std::cerr << "Power test: 9*3 after relin (size=" << ct_27.size() << ") = " << val_27_after << " (expected 27)\n";
    EXPECT_EQ(val_27_after, 27);
}

// ============================================================================
// Serialization Tests
// ============================================================================

TEST_F(BGVTest, CiphertextSerialize) {
    auto pt = encoder_->encode(42);
    auto ct = context_->encrypt(pk_, pt);
    
    auto data = ct.serialize();
    // For now, just check it doesn't crash
    EXPECT_TRUE(true);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
