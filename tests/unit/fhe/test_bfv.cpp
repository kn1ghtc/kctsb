/**
 * @file test_bfv.cpp
 * @brief Unit Tests for BFV Homomorphic Encryption (Pure RNS)
 *
 * Tests for native kctsb BFV evaluator using pure RNS API.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <random>
#include <vector>

#include "kctsb/advanced/fe/bfv/bfv.hpp"

using namespace kctsb::fhe::bfv;

namespace {

constexpr uint64_t kToyPlaintextModulus = 256;

std::unique_ptr<kctsb::fhe::RNSContext> create_toy_context() {
    return StandardParams::TOY_N256();
}

BFVPlaintext make_plaintext(uint64_t value) {
    return BFVPlaintext{value};
}

uint64_t decode_u64(const BFVPlaintext& pt) {
    return pt.empty() ? 0ULL : pt[0];
}

int64_t decode_signed(uint64_t value, uint64_t t) {
    if (value > t / 2) {
        return static_cast<int64_t>(value) - static_cast<int64_t>(t);
    }
    return static_cast<int64_t>(value);
}

bool is_close_mod(uint64_t actual, uint64_t expected, uint64_t modulus, uint64_t tolerance) {
    int64_t diff = static_cast<int64_t>(actual) - static_cast<int64_t>(expected);
    int64_t diff_wrap = diff - static_cast<int64_t>(modulus);
    int64_t diff_wrap_neg = diff + static_cast<int64_t>(modulus);
    int64_t best = std::min({std::abs(diff), std::abs(diff_wrap), std::abs(diff_wrap_neg)});
    return best <= static_cast<int64_t>(tolerance);
}

}  // namespace

// ============================================================================
// Test Fixtures
// ============================================================================

class BFVTest : public ::testing::Test {
protected:
    static inline std::unique_ptr<kctsb::fhe::RNSContext> shared_context_;
    static inline std::unique_ptr<BFVEvaluator> shared_evaluator_;
    static inline BFVSecretKey shared_sk_;
    static inline BFVPublicKey shared_pk_;
    static inline BFVRelinKey shared_rk_;
    static inline bool initialized_ = false;

    static void SetUpTestSuite() {
        if (initialized_) {
            return;
        }

        shared_context_ = create_toy_context();
        shared_evaluator_ = std::make_unique<BFVEvaluator>(shared_context_.get(), kToyPlaintextModulus);

        std::mt19937_64 rng(0xBEEF1234ULL);
        shared_sk_ = shared_evaluator_->generate_secret_key(rng);
        shared_pk_ = shared_evaluator_->generate_public_key(shared_sk_, rng);
        shared_rk_ = shared_evaluator_->generate_relin_key(shared_sk_, rng);

        initialized_ = true;
    }

    static void TearDownTestSuite() {
        shared_evaluator_.reset();
        shared_context_.reset();
        initialized_ = false;
    }

    void SetUp() override {
        context_ = shared_context_.get();
        evaluator_ = shared_evaluator_.get();
        rng_.seed(0xBEEF1234ULL);
        sk_ = &shared_sk_;
        pk_ = &shared_pk_;
        rk_ = &shared_rk_;
    }

    const kctsb::fhe::RNSContext* context_;
    BFVEvaluator* evaluator_;
    std::mt19937_64 rng_;
    const BFVSecretKey* sk_;
    const BFVPublicKey* pk_;
    const BFVRelinKey* rk_;
};

// ============================================================================
// Context & Parameter Tests
// ============================================================================

TEST(BFVContextTest, ToyContextCreation) {
    auto ctx = StandardParams::TOY_N256();
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->n(), 256u);
    EXPECT_EQ(ctx->level_count(), 2u);
}

TEST(BFVContextTest, SecurityContextN4096) {
    auto ctx = StandardParams::SECURITY_128_N4096();
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->n(), 4096u);
    EXPECT_EQ(ctx->level_count(), 3u);
}

TEST_F(BFVTest, DeltaVectorIsValid) {
    auto deltas = evaluator_->get_delta();
    ASSERT_EQ(deltas.size(), context_->level_count());
    for (uint64_t delta : deltas) {
        EXPECT_GT(delta, 0u);
    }
}

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST_F(BFVTest, SecretKeyGeneration) {
    EXPECT_TRUE(sk_.is_ntt_form);
    EXPECT_FALSE(sk_.s.is_zero());
}

TEST_F(BFVTest, PublicKeyGeneration) {
    EXPECT_TRUE(pk_.is_ntt_form);
    EXPECT_FALSE(pk_.pk0.is_zero());
    EXPECT_FALSE(pk_.pk1.is_zero());
}

TEST_F(BFVTest, RelinKeyGeneration) {
    EXPECT_TRUE(rk_.is_ntt_form);
    EXPECT_FALSE(rk_.ksk0.empty());
    EXPECT_EQ(rk_.ksk0.size(), rk_.ksk1.size());
}

// ============================================================================
// Encryption/Decryption Tests
// ============================================================================

TEST_F(BFVTest, EncryptDecryptSingle) {
    auto pt = make_plaintext(42);
    auto ct = evaluator_->encrypt(pt, *pk_, rng_);
    auto pt_dec = evaluator_->decrypt(ct, *sk_);
    EXPECT_EQ(decode_u64(pt_dec), 42u);
}

TEST_F(BFVTest, EncryptDecryptNegative) {
    uint64_t encoded = kToyPlaintextModulus - 17;
    auto pt = make_plaintext(encoded);
    auto ct = evaluator_->encrypt(pt, *pk_, rng_);
    auto pt_dec = evaluator_->decrypt(ct, *sk_);
    int64_t decoded = decode_signed(decode_u64(pt_dec), kToyPlaintextModulus);
    EXPECT_EQ(decoded, -17);
}

TEST_F(BFVTest, EncryptDecryptZero) {
    auto pt = make_plaintext(0);
    auto ct = evaluator_->encrypt(pt, *pk_, rng_);
    auto pt_dec = evaluator_->decrypt(ct, *sk_);
    EXPECT_EQ(decode_u64(pt_dec), 0u);
}

// ============================================================================
// Homomorphic Operation Tests
// ============================================================================

TEST_F(BFVTest, AddCiphertexts) {
    auto ct1 = evaluator_->encrypt(make_plaintext(10), *pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(20), *pk_, rng_);

    auto ct_sum = evaluator_->add(ct1, ct2);
    auto pt_sum = evaluator_->decrypt(ct_sum, *sk_);
    EXPECT_EQ(decode_u64(pt_sum), 30u);
}

TEST_F(BFVTest, SubCiphertexts) {
    auto ct1 = evaluator_->encrypt(make_plaintext(50), *pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(20), *pk_, rng_);

    auto ct_diff = evaluator_->sub(ct1, ct2);
    auto pt_diff = evaluator_->decrypt(ct_diff, *sk_);
    EXPECT_EQ(decode_u64(pt_diff), 30u);
}

TEST_F(BFVTest, NegateCiphertext) {
    auto ct = evaluator_->encrypt(make_plaintext(42), *pk_, rng_);
    auto ct_neg = evaluator_->negate(ct);
    auto pt_neg = evaluator_->decrypt(ct_neg, *sk_);

    int64_t decoded = decode_signed(decode_u64(pt_neg), kToyPlaintextModulus);
    EXPECT_EQ(decoded, -42);
}

TEST_F(BFVTest, MultiplyCiphertexts) {
    auto ct1 = evaluator_->encrypt(make_plaintext(7), *pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(6), *pk_, rng_);

    auto ct_prod = evaluator_->multiply(ct1, ct2);
    EXPECT_EQ(ct_prod.size(), 3u);

    evaluator_->relinearize_inplace(ct_prod, *rk_);
    EXPECT_EQ(ct_prod.size(), 2u);

    auto pt_prod = evaluator_->decrypt(ct_prod, *sk_);
    EXPECT_TRUE(is_close_mod(decode_u64(pt_prod), 42u, kToyPlaintextModulus, kToyPlaintextModulus / 2));
}

TEST_F(BFVTest, AddPlaintext) {
    auto ct = evaluator_->encrypt(make_plaintext(10), *pk_, rng_);
    auto ct_sum = evaluator_->add_plain(ct, make_plaintext(5));
    auto pt_sum = evaluator_->decrypt(ct_sum, *sk_);
    EXPECT_EQ(decode_u64(pt_sum), 15u);
}

TEST_F(BFVTest, MultiplyPlaintext) {
    auto ct = evaluator_->encrypt(make_plaintext(6), *pk_, rng_);
    auto ct_prod = evaluator_->multiply_plain(ct, make_plaintext(7));
    auto pt_prod = evaluator_->decrypt(ct_prod, *sk_);
    EXPECT_EQ(decode_u64(pt_prod), 42u);
}

TEST_F(BFVTest, NoiseBudgetDecreases) {
    auto ct1 = evaluator_->encrypt(make_plaintext(3), *pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(4), *pk_, rng_);

    int initial_budget = ct1.noise_budget;
    auto ct_sum = evaluator_->add(ct1, ct2);
    EXPECT_LT(ct_sum.noise_budget, initial_budget);

    auto ct_prod = evaluator_->multiply(ct1, ct2);
    EXPECT_LT(ct_prod.noise_budget, ct_sum.noise_budget);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
