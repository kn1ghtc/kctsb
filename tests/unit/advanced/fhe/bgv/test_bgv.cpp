/**
 * @file test_bgv.cpp
 * @brief Unit Tests for BGV Homomorphic Encryption (Pure RNS)
 *
 * Tests for native kctsb BGV evaluator using pure RNS API.
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

#include "kctsb/advanced/fe/bgv/bgv.hpp"
#include "kctsb/advanced/fe/bgv/bgv_ntt_helper.hpp"

using namespace kctsb::fhe::bgv;

namespace {

constexpr uint64_t kToyPlaintextModulus = 256;

const std::vector<uint64_t>& toy_primes() {
    static const std::vector<uint64_t> primes = {65537, 114689};
    return primes;
}

std::unique_ptr<kctsb::fhe::RNSContext> create_toy_context() {
    return std::make_unique<kctsb::fhe::RNSContext>(8, toy_primes());
}

BGVPlaintext make_plaintext(uint64_t value) {
    return BGVPlaintext{value};
}

uint64_t decode_u64(const BGVPlaintext& pt) {
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

std::vector<uint64_t> make_poly_coeffs(uint64_t c0, uint64_t c1, size_t n) {
    std::vector<uint64_t> coeffs(n, 0);
    if (n > 0) {
        coeffs[0] = c0;
    }
    if (n > 1) {
        coeffs[1] = c1;
    }
    return coeffs;
}

}  // namespace

// ============================================================================
// Test Fixtures
// ============================================================================

class BGVTest : public ::testing::Test {
protected:
    void SetUp() override {
        context_ = create_toy_context();
        evaluator_ = std::make_unique<BGVEvaluator>(context_.get(), kToyPlaintextModulus);
        rng_.seed(0xC0FFEEULL);

        sk_ = evaluator_->generate_secret_key(rng_);
        pk_ = evaluator_->generate_public_key(sk_, rng_);
        rk_ = evaluator_->generate_relin_key(sk_, rng_);
    }

    std::unique_ptr<kctsb::fhe::RNSContext> context_;
    std::unique_ptr<BGVEvaluator> evaluator_;
    std::mt19937_64 rng_;
    BGVSecretKey sk_;
    BGVPublicKey pk_;
    BGVRelinKey rk_;
};

// ============================================================================
// Context & Parameter Tests
// ============================================================================

TEST(BGVContextTest, StandardParamsN4096) {
    auto ctx = StandardParams::SECURITY_128_N4096();
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->n(), 4096u);
    EXPECT_EQ(ctx->level_count(), 3u);
}

TEST(BGVContextTest, StandardParamsN8192) {
    auto ctx = StandardParams::SECURITY_128_N8192();
    ASSERT_NE(ctx, nullptr);
    EXPECT_EQ(ctx->n(), 8192u);
    EXPECT_EQ(ctx->level_count(), 5u);
}

TEST(BGVContextTest, ToyContextSupportsNTT) {
    auto ctx = create_toy_context();
    ASSERT_NE(ctx, nullptr);
    EXPECT_TRUE(can_use_ntt(ctx->n(), toy_primes()));
}

// ============================================================================
// Key Generation Tests
// ============================================================================

TEST_F(BGVTest, SecretKeyGeneration) {
    EXPECT_TRUE(sk_.is_ntt_form);
    EXPECT_FALSE(sk_.s.is_zero());
}

TEST_F(BGVTest, PublicKeyGeneration) {
    EXPECT_TRUE(pk_.is_ntt_form);
    EXPECT_FALSE(pk_.pk0.is_zero());
    EXPECT_FALSE(pk_.pk1.is_zero());
}

TEST_F(BGVTest, RelinKeyGeneration) {
    EXPECT_TRUE(rk_.is_ntt_form);
    EXPECT_FALSE(rk_.ksk0.empty());
    EXPECT_EQ(rk_.ksk0.size(), rk_.ksk1.size());
}

// ============================================================================
// Encryption/Decryption Tests
// ============================================================================

TEST_F(BGVTest, EncryptDecryptSingle) {
    auto pt = make_plaintext(42);
    auto ct = evaluator_->encrypt(pt, pk_, rng_);
    auto pt_dec = evaluator_->decrypt(ct, sk_);
    EXPECT_EQ(decode_u64(pt_dec), 42u);
}

TEST_F(BGVTest, EncryptDecryptNegative) {
    uint64_t encoded = kToyPlaintextModulus - 42;
    auto pt = make_plaintext(encoded);
    auto ct = evaluator_->encrypt(pt, pk_, rng_);
    auto pt_dec = evaluator_->decrypt(ct, sk_);
    int64_t decoded = decode_signed(decode_u64(pt_dec), kToyPlaintextModulus);
    EXPECT_EQ(decoded, -42);
}

TEST_F(BGVTest, EncryptDecryptZero) {
    auto pt = make_plaintext(0);
    auto ct = evaluator_->encrypt(pt, pk_, rng_);
    auto pt_dec = evaluator_->decrypt(ct, sk_);
    EXPECT_EQ(decode_u64(pt_dec), 0u);
}

// ============================================================================
// Homomorphic Operation Tests
// ============================================================================

TEST_F(BGVTest, AddCiphertexts) {
    auto ct1 = evaluator_->encrypt(make_plaintext(10), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(20), pk_, rng_);

    auto ct_sum = evaluator_->add(ct1, ct2);
    auto pt_sum = evaluator_->decrypt(ct_sum, sk_);

    EXPECT_EQ(decode_u64(pt_sum), 30u);
}

TEST_F(BGVTest, SubCiphertexts) {
    auto ct1 = evaluator_->encrypt(make_plaintext(50), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(20), pk_, rng_);

    auto ct_diff = evaluator_->sub(ct1, ct2);
    auto pt_diff = evaluator_->decrypt(ct_diff, sk_);

    EXPECT_EQ(decode_u64(pt_diff), 30u);
}

TEST_F(BGVTest, NegateCiphertext) {
    auto ct = evaluator_->encrypt(make_plaintext(42), pk_, rng_);
    auto ct_neg = evaluator_->negate(ct);
    auto pt_neg = evaluator_->decrypt(ct_neg, sk_);

    int64_t decoded = decode_signed(decode_u64(pt_neg), kToyPlaintextModulus);
    EXPECT_EQ(decoded, -42);
}

TEST_F(BGVTest, MultiplyCiphertexts) {
    auto ct1 = evaluator_->encrypt(make_plaintext(7), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(6), pk_, rng_);

    auto ct_prod = evaluator_->multiply(ct1, ct2);
    EXPECT_EQ(ct_prod.size(), 3u);

    auto pt_prod = evaluator_->decrypt(ct_prod, sk_);
    EXPECT_TRUE(is_close_mod(decode_u64(pt_prod), 42u, kToyPlaintextModulus, kToyPlaintextModulus / 2));
}

TEST_F(BGVTest, MultiplyAndRelinearize) {
    auto ct1 = evaluator_->encrypt(make_plaintext(7), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(6), pk_, rng_);

    auto ct_prod = evaluator_->multiply(ct1, ct2);
    evaluator_->relinearize_inplace(ct_prod, rk_);
    EXPECT_EQ(ct_prod.size(), 2u);

    auto pt_prod = evaluator_->decrypt(ct_prod, sk_);
    EXPECT_TRUE(is_close_mod(decode_u64(pt_prod), 42u, kToyPlaintextModulus, kToyPlaintextModulus / 2));
}

TEST_F(BGVTest, NoiseBudgetDecreases) {
    auto ct1 = evaluator_->encrypt(make_plaintext(3), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(4), pk_, rng_);

    int initial_budget = ct1.noise_budget;
    auto ct_sum = evaluator_->add(ct1, ct2);
    EXPECT_LT(ct_sum.noise_budget, initial_budget);

    auto ct_prod = evaluator_->multiply(ct1, ct2);
    EXPECT_LT(ct_prod.noise_budget, ct_sum.noise_budget);
}

// ============================================================================
// NTT Helper Tests (Pure RNS)
// ============================================================================

TEST(BGVNTTTest, MultiplyNTTPure) {
    constexpr size_t n = 8;
    constexpr uint64_t q = 65537;

    auto a = make_poly_coeffs(1, 1, n);
    auto b = make_poly_coeffs(1, 1, n);

    auto result = multiply_ntt_pure(a, b, n, q);

    ASSERT_EQ(result.size(), n);
    EXPECT_EQ(result[0], 1u);
    EXPECT_EQ(result[1], 2u);
    EXPECT_EQ(result[2], 1u);
    for (size_t i = 3; i < n; ++i) {
        EXPECT_EQ(result[i], 0u);
    }
}

TEST(BGVNTTTest, MultiplyRNSNTTPure) {
    constexpr size_t n = 8;
    const std::vector<uint64_t> primes = toy_primes();

    auto coeffs_a = make_poly_coeffs(1, 1, n);
    auto coeffs_b = make_poly_coeffs(1, 1, n);

    std::vector<std::vector<uint64_t>> a_rns;
    std::vector<std::vector<uint64_t>> b_rns;

    a_rns.reserve(primes.size());
    b_rns.reserve(primes.size());

    for (uint64_t p : primes) {
        std::vector<uint64_t> a_mod(n, 0);
        std::vector<uint64_t> b_mod(n, 0);
        for (size_t i = 0; i < n; ++i) {
            a_mod[i] = coeffs_a[i] % p;
            b_mod[i] = coeffs_b[i] % p;
        }
        a_rns.push_back(std::move(a_mod));
        b_rns.push_back(std::move(b_mod));
    }

    auto result = multiply_rns_ntt_pure(a_rns, b_rns, n, primes);

    ASSERT_EQ(result.size(), primes.size());
    for (size_t idx = 0; idx < primes.size(); ++idx) {
        ASSERT_EQ(result[idx].size(), n);
        EXPECT_EQ(result[idx][0], 1u);
        EXPECT_EQ(result[idx][1], 2u);
        EXPECT_EQ(result[idx][2], 1u);
        for (size_t i = 3; i < n; ++i) {
            EXPECT_EQ(result[idx][i], 0u);
        }
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
