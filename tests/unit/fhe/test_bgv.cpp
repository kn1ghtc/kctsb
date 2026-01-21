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

TEST_F(BGVTest, EncryptDecryptSingle) {
    auto pt = encoder_->encode(42);
    auto ct = context_->encrypt(pk_, pt);
    auto pt_dec = context_->decrypt(sk_, ct);
    
    EXPECT_EQ(encoder_->decode_int(pt_dec), 42);
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

TEST_F(BGVTest, Power) {
    auto pt = encoder_->encode(3);
    auto ct = context_->encrypt(pk_, pt);
    
    auto ct_cubed = evaluator_->power(ct, 3, rk_);
    auto pt_cubed = context_->decrypt(sk_, ct_cubed);
    
    EXPECT_EQ(encoder_->decode_int(pt_cubed), 27);
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
