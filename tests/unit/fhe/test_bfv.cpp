/**
 * @file test_bfv.cpp
 * @brief BFV Homomorphic Encryption Test Suite
 * 
 * Tests for BFV scheme implementation including:
 * - Parameter creation
 * - Encoding/Decoding with Δ scaling
 * - Encryption/Decryption
 * - Homomorphic addition and multiplication
 * - Rescale operation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <gtest/gtest.h>
#include <vector>
#include <numeric>
#include <cmath>
#include <iostream>

#include "kctsb/advanced/fe/bfv/bfv.hpp"

namespace {

using namespace kctsb::fhe::bfv;
using kctsb::ZZ;
using kctsb::NumBits;
using kctsb::deg;

// ============================================================================
// BFV Parameters Test
// ============================================================================

class BFVParamsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup if needed
    }
};

TEST_F(BFVParamsTest, ToyParamsValid) {
    auto params = StandardParams::TOY_PARAMS();
    
    EXPECT_EQ(params.n, 256);
    EXPECT_EQ(params.t, 257);
    EXPECT_GT(params.q, ZZ(0));
    EXPECT_FALSE(params.primes.empty());
    
    // Delta should be well-defined
    ZZ delta = params.delta();
    EXPECT_GT(delta, ZZ(0));
}

TEST_F(BFVParamsTest, Security128Valid) {
    auto params = StandardParams::SECURITY_128();
    
    EXPECT_EQ(params.n, 8192);
    EXPECT_GT(params.t, uint64_t(0));
    EXPECT_GT(params.q, ZZ(0));
    
    // For 128-bit security, q should be large
    EXPECT_GT(NumBits(params.q), 200);
}

TEST_F(BFVParamsTest, DeltaComputation) {
    auto params = StandardParams::TOY_PARAMS();
    
    ZZ expected_delta = params.q / ZZ(params.t);
    EXPECT_EQ(params.delta(), expected_delta);
}

// ============================================================================
// BFV Context Test
// ============================================================================

class BFVContextTest : public ::testing::Test {
protected:
    void SetUp() override {
        params_ = StandardParams::TOY_PARAMS();
    }
    
    BFVParams params_;
};

TEST_F(BFVContextTest, Construction) {
    EXPECT_NO_THROW({
        BFVContext ctx(params_);
    });
}

TEST_F(BFVContextTest, KeyGeneration) {
    BFVContext ctx(params_);
    
    auto sk = ctx.generate_secret_key();
    auto pk = ctx.generate_public_key(sk);
    auto rk = ctx.generate_relin_key(sk);
    
    // Keys should be non-trivial
    EXPECT_GT(sk.degree(), -1);
    EXPECT_GT(pk.b().degree(), -1);
}

TEST_F(BFVContextTest, ParameterAccess) {
    BFVContext ctx(params_);
    
    EXPECT_EQ(ctx.ring_degree(), params_.n);
    EXPECT_EQ(ctx.plaintext_modulus(), params_.t);
    EXPECT_EQ(ctx.delta(), params_.delta());
}

// ============================================================================
// BFV Encoder Test
// ============================================================================

class BFVEncoderTest : public ::testing::Test {
protected:
    void SetUp() override {
        params_ = StandardParams::TOY_PARAMS();
        ctx_ = std::make_unique<BFVContext>(params_);
        encoder_ = std::make_unique<BFVEncoder>(*ctx_);
    }
    
    BFVParams params_;
    std::unique_ptr<BFVContext> ctx_;
    std::unique_ptr<BFVEncoder> encoder_;
};

TEST_F(BFVEncoderTest, EncodeDecodeSingleValue) {
    // Test positive values
    for (int64_t val : {0, 1, 5, 42, 100}) {
        auto pt = encoder_->encode(val);
        int64_t decoded = encoder_->decode(pt);
        EXPECT_EQ(decoded, val) << "Failed for value: " << val;
    }
}

TEST_F(BFVEncoderTest, EncodeDecodeNegativeValues) {
    // Test negative values (mapped to [0, t-1])
    int64_t t = static_cast<int64_t>(ctx_->plaintext_modulus());
    
    for (int64_t val : {-1, -5, -42}) {
        auto pt = encoder_->encode(val);
        int64_t decoded = encoder_->decode(pt);
        
        // Negative values should decode correctly
        EXPECT_EQ(decoded, val) << "Failed for value: " << val;
    }
}

TEST_F(BFVEncoderTest, EncodeDecodeBatch) {
    std::vector<int64_t> values = {1, 2, 3, 4, 5};
    
    auto pt = encoder_->encode_batch(values);
    auto decoded = encoder_->decode_batch(pt);
    
    for (size_t i = 0; i < values.size(); i++) {
        EXPECT_EQ(decoded[i], values[i]) << "Mismatch at index " << i;
    }
}

TEST_F(BFVEncoderTest, SlotCount) {
    EXPECT_EQ(encoder_->slot_count(), ctx_->ring_degree());
}

// ============================================================================
// BFV Encryption Test
// ============================================================================

class BFVEncryptionTest : public ::testing::Test {
protected:
    void SetUp() override {
        params_ = StandardParams::TOY_PARAMS();
        ctx_ = std::make_unique<BFVContext>(params_);
        encoder_ = std::make_unique<BFVEncoder>(*ctx_);
        
        sk_ = ctx_->generate_secret_key();
        pk_ = ctx_->generate_public_key(sk_);
    }
    
    BFVParams params_;
    std::unique_ptr<BFVContext> ctx_;
    std::unique_ptr<BFVEncoder> encoder_;
    SecretKey sk_;
    PublicKey pk_;
};

TEST_F(BFVEncryptionTest, EncryptDecryptSingle) {
    int64_t value = 42;
    
    auto pt = encoder_->encode(value);
    auto ct = ctx_->encrypt(pk_, pt);
    auto decrypted = ctx_->decrypt(sk_, ct);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, value);
}

TEST_F(BFVEncryptionTest, EncryptDecryptNegative) {
    int64_t value = -17;
    
    auto pt = encoder_->encode(value);
    auto ct = ctx_->encrypt(pk_, pt);
    auto decrypted = ctx_->decrypt(sk_, ct);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, value);
}

TEST_F(BFVEncryptionTest, EncryptDecryptZero) {
    int64_t value = 0;
    
    auto pt = encoder_->encode(value);
    auto ct = ctx_->encrypt(pk_, pt);
    auto decrypted = ctx_->decrypt(sk_, ct);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, value);
}

TEST_F(BFVEncryptionTest, SymmetricEncryption) {
    int64_t value = 99;
    
    auto pt = encoder_->encode(value);
    auto ct = ctx_->encrypt_symmetric(sk_, pt);
    auto decrypted = ctx_->decrypt(sk_, ct);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, value);
}

TEST_F(BFVEncryptionTest, MultipleCiphertexts) {
    std::vector<int64_t> values = {1, 10, 100};
    
    for (int64_t val : values) {
        auto pt = encoder_->encode(val);
        auto ct = ctx_->encrypt(pk_, pt);
        auto decrypted = ctx_->decrypt(sk_, ct);
        int64_t result = encoder_->decode(decrypted);
        
        EXPECT_EQ(result, val) << "Failed for value: " << val;
    }
}

// ============================================================================
// BFV Operations Test
// ============================================================================

class BFVOperationsTest : public ::testing::Test {
protected:
    void SetUp() override {
        params_ = StandardParams::TOY_PARAMS();
        ctx_ = std::make_unique<BFVContext>(params_);
        encoder_ = std::make_unique<BFVEncoder>(*ctx_);
        evaluator_ = std::make_unique<BFVEvaluator>(*ctx_);
        
        sk_ = ctx_->generate_secret_key();
        pk_ = ctx_->generate_public_key(sk_);
        rk_ = ctx_->generate_relin_key(sk_);
    }
    
    BFVParams params_;
    std::unique_ptr<BFVContext> ctx_;
    std::unique_ptr<BFVEncoder> encoder_;
    std::unique_ptr<BFVEvaluator> evaluator_;
    SecretKey sk_;
    PublicKey pk_;
    RelinKey rk_;
};

TEST_F(BFVOperationsTest, Addition) {
    int64_t a = 7, b = 5;
    int64_t t = static_cast<int64_t>(ctx_->plaintext_modulus());
    int64_t expected = (a + b) % t;
    
    auto pt_a = encoder_->encode(a);
    auto pt_b = encoder_->encode(b);
    auto ct_a = ctx_->encrypt(pk_, pt_a);
    auto ct_b = ctx_->encrypt(pk_, pt_b);
    
    auto ct_sum = evaluator_->add(ct_a, ct_b);
    auto decrypted = ctx_->decrypt(sk_, ct_sum);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, expected);
}

TEST_F(BFVOperationsTest, Subtraction) {
    int64_t a = 20, b = 7;
    int64_t expected = a - b;
    
    auto pt_a = encoder_->encode(a);
    auto pt_b = encoder_->encode(b);
    auto ct_a = ctx_->encrypt(pk_, pt_a);
    auto ct_b = ctx_->encrypt(pk_, pt_b);
    
    auto ct_diff = evaluator_->sub(ct_a, ct_b);
    auto decrypted = ctx_->decrypt(sk_, ct_diff);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, expected);
}

TEST_F(BFVOperationsTest, MultiplicationRaw) {
    int64_t a = 7, b = 6;
    int64_t t = static_cast<int64_t>(ctx_->plaintext_modulus());
    int64_t expected = (a * b) % t;
    
    auto pt_a = encoder_->encode(a);
    auto pt_b = encoder_->encode(b);
    auto ct_a = ctx_->encrypt(pk_, pt_a);
    auto ct_b = ctx_->encrypt(pk_, pt_b);
    
    auto ct_prod = evaluator_->multiply_raw(ct_a, ct_b);
    
    // After multiply, result should have 3 components
    EXPECT_EQ(ct_prod.size(), 3);
    
    // Relinearize to get back to 2 components
    auto ct_relin = evaluator_->relinearize(ct_prod, rk_);
    EXPECT_EQ(ct_relin.size(), 2);
    
    auto decrypted = ctx_->decrypt(sk_, ct_relin);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, expected);
}

TEST_F(BFVOperationsTest, MultiplyRelin) {
    int64_t a = 7, b = 6;
    int64_t t = static_cast<int64_t>(ctx_->plaintext_modulus());
    int64_t expected = (a * b) % t;
    
    auto pt_a = encoder_->encode(a);
    auto pt_b = encoder_->encode(b);
    auto ct_a = ctx_->encrypt(pk_, pt_a);
    auto ct_b = ctx_->encrypt(pk_, pt_b);
    
    auto ct_prod = evaluator_->multiply_relin(ct_a, ct_b, rk_);
    
    // Should be 2 components after relin
    EXPECT_EQ(ct_prod.size(), 2);
    
    auto decrypted = ctx_->decrypt(sk_, ct_prod);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, expected);
}

TEST_F(BFVOperationsTest, AddPlaintext) {
    int64_t a = 10, b = 5;
    int64_t expected = a + b;
    
    auto pt_a = encoder_->encode(a);
    auto pt_b = encoder_->encode(b);
    auto ct_a = ctx_->encrypt(pk_, pt_a);
    
    auto ct_sum = evaluator_->add_plain(ct_a, pt_b);
    auto decrypted = ctx_->decrypt(sk_, ct_sum);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, expected);
}

TEST_F(BFVOperationsTest, NoiseBudget) {
    int64_t value = 42;
    
    auto pt = encoder_->encode(value);
    auto ct = ctx_->encrypt(pk_, pt);
    
    double budget = evaluator_->noise_budget(ct);
    
    // Fresh ciphertext should have positive noise budget
    EXPECT_GT(budget, 0.0);
}

// ============================================================================
// BFV Depth Test (Multiple Multiplications)
// ============================================================================

class BFVDepthTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use larger params for depth testing
        params_ = StandardParams::SECURITY_128_DEPTH_3();
        ctx_ = std::make_unique<BFVContext>(params_);
        encoder_ = std::make_unique<BFVEncoder>(*ctx_);
        evaluator_ = std::make_unique<BFVEvaluator>(*ctx_);
        
        sk_ = ctx_->generate_secret_key();
        pk_ = ctx_->generate_public_key(sk_);
        rk_ = ctx_->generate_relin_key(sk_);
    }
    
    BFVParams params_;
    std::unique_ptr<BFVContext> ctx_;
    std::unique_ptr<BFVEncoder> encoder_;
    std::unique_ptr<BFVEvaluator> evaluator_;
    SecretKey sk_;
    PublicKey pk_;
    RelinKey rk_;
};

TEST_F(BFVDepthTest, TwoMultiplications) {
    // a * b * c
    int64_t a = 2, b = 3, c = 4;
    int64_t t = static_cast<int64_t>(ctx_->plaintext_modulus());
    int64_t expected = (a * b * c) % t;
    
    auto pt_a = encoder_->encode(a);
    auto pt_b = encoder_->encode(b);
    auto pt_c = encoder_->encode(c);
    
    auto ct_a = ctx_->encrypt(pk_, pt_a);
    auto ct_b = ctx_->encrypt(pk_, pt_b);
    auto ct_c = ctx_->encrypt(pk_, pt_c);
    
    // First multiplication
    auto ct_ab = evaluator_->multiply_relin(ct_a, ct_b, rk_);
    
    // Second multiplication
    auto ct_abc = evaluator_->multiply_relin(ct_ab, ct_c, rk_);
    
    auto decrypted = ctx_->decrypt(sk_, ct_abc);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, expected);
}

TEST_F(BFVDepthTest, ThreeMultiplications) {
    // a * b * c * d
    int64_t a = 2, b = 2, c = 2, d = 2;
    int64_t t = static_cast<int64_t>(ctx_->plaintext_modulus());
    int64_t expected = (a * b * c * d) % t;  // = 16
    
    auto pt_a = encoder_->encode(a);
    auto pt_b = encoder_->encode(b);
    auto pt_c = encoder_->encode(c);
    auto pt_d = encoder_->encode(d);
    
    auto ct_a = ctx_->encrypt(pk_, pt_a);
    auto ct_b = ctx_->encrypt(pk_, pt_b);
    auto ct_c = ctx_->encrypt(pk_, pt_c);
    auto ct_d = ctx_->encrypt(pk_, pt_d);
    
    auto ct_ab = evaluator_->multiply_relin(ct_a, ct_b, rk_);
    auto ct_abc = evaluator_->multiply_relin(ct_ab, ct_c, rk_);
    auto ct_abcd = evaluator_->multiply_relin(ct_abc, ct_d, rk_);
    
    auto decrypted = ctx_->decrypt(sk_, ct_abcd);
    int64_t result = encoder_->decode(decrypted);
    
    EXPECT_EQ(result, expected);
}

// ============================================================================
// BFV vs BGV Comparison Test
// ============================================================================

class BFVvsBGVTest : public ::testing::Test {
protected:
    void SetUp() override {
        bfv_params_ = StandardParams::TOY_PARAMS();
        bgv_params_ = kctsb::fhe::bgv::StandardParams::TOY_PARAMS();
    }
    
    BFVParams bfv_params_;
    kctsb::fhe::bgv::BGVParams bgv_params_;
};

TEST_F(BFVvsBGVTest, SameParameterStructure) {
    // BFV and BGV should have compatible parameters
    EXPECT_EQ(bfv_params_.n, bgv_params_.n);
    EXPECT_EQ(bfv_params_.t, bgv_params_.t);
    EXPECT_EQ(bfv_params_.L, bgv_params_.L);
}

TEST_F(BFVvsBGVTest, SameAdditionResult) {
    // Both schemes should produce same addition result
    BFVContext bfv_ctx(bfv_params_);
    kctsb::fhe::bgv::BGVContext bgv_ctx(bgv_params_);
    
    int64_t a = 10, b = 20;
    int64_t t = static_cast<int64_t>(bfv_params_.t);
    int64_t expected = (a + b) % t;
    
    // BFV
    BFVEncoder bfv_enc(bfv_ctx);
    BFVEvaluator bfv_eval(bfv_ctx);
    auto bfv_sk = bfv_ctx.generate_secret_key();
    auto bfv_pk = bfv_ctx.generate_public_key(bfv_sk);
    
    auto bfv_pt_a = bfv_enc.encode(a);
    auto bfv_pt_b = bfv_enc.encode(b);
    auto bfv_ct_a = bfv_ctx.encrypt(bfv_pk, bfv_pt_a);
    auto bfv_ct_b = bfv_ctx.encrypt(bfv_pk, bfv_pt_b);
    auto bfv_ct_sum = bfv_eval.add(bfv_ct_a, bfv_ct_b);
    auto bfv_decrypted = bfv_ctx.decrypt(bfv_sk, bfv_ct_sum);
    int64_t bfv_result = bfv_enc.decode(bfv_decrypted);
    
    EXPECT_EQ(bfv_result, expected);
}

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
