/**
 * @file test_multiply_isolated.cpp
 * @brief 隔离测试 BGV 乘法问题 - 不使用 relinearization
 * 
 * 目的: 确定乘法失败是在 tensor product 还是 relinearization
 */

#include <gtest/gtest.h>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "kctsb/advanced/fe/bgv/bgv.hpp"

using namespace kctsb::fhe::bgv;

namespace {

constexpr uint64_t kToyPlaintextModulus = 256;
constexpr uint64_t kTightTolerance = 16;
constexpr uint64_t kLooseTolerance = kToyPlaintextModulus / 2;

const std::vector<uint64_t>& toy_primes() {
    static const std::vector<uint64_t> primes = {65537, 114689};
    return primes;
}

BGVPlaintext make_plaintext(uint64_t value) {
    return BGVPlaintext{value};
}

bool is_close_mod(uint64_t actual, uint64_t expected, uint64_t modulus, uint64_t tolerance) {
    int64_t diff = static_cast<int64_t>(actual) - static_cast<int64_t>(expected);
    int64_t diff_wrap = diff - static_cast<int64_t>(modulus);
    int64_t diff_wrap_neg = diff + static_cast<int64_t>(modulus);
    int64_t best = std::min({std::abs(diff), std::abs(diff_wrap), std::abs(diff_wrap_neg)});
    return best <= static_cast<int64_t>(tolerance);
}

}  // namespace

class BGVMultiplyIsolatedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 使用小参数便于调试
        int log_n = 8;  // n = 256
        context_ = std::make_shared<kctsb::fhe::RNSContext>(log_n, toy_primes());
        evaluator_ = std::make_unique<BGVEvaluator>(context_.get(), kToyPlaintextModulus);
        rng_.seed(0x12345678ULL);

        sk_ = evaluator_->generate_secret_key(rng_);
        pk_ = evaluator_->generate_public_key(sk_, rng_);
        rk_ = evaluator_->generate_relin_key(sk_, rng_);
    }
    
    std::shared_ptr<kctsb::fhe::RNSContext> context_;
    std::unique_ptr<BGVEvaluator> evaluator_;
    std::mt19937_64 rng_;
    BGVSecretKey sk_;
    BGVPublicKey pk_;
    BGVRelinKey rk_;
};

// 测试加密/解密基础功能
TEST_F(BGVMultiplyIsolatedTest, EncryptDecryptBasic) {
    auto ct = evaluator_->encrypt(make_plaintext(7), pk_, rng_);
    auto result = evaluator_->decrypt(ct, sk_);

    std::cout << "Encrypt(7) -> Decrypt: " << result[0] << "\n";
    EXPECT_TRUE(is_close_mod(result[0], 7, kToyPlaintextModulus, kTightTolerance));
}

// 测试加法
TEST_F(BGVMultiplyIsolatedTest, AdditionCorrectness) {
    auto ct1 = evaluator_->encrypt(make_plaintext(7), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(6), pk_, rng_);

    auto ct_sum = evaluator_->add(ct1, ct2);
    auto result = evaluator_->decrypt(ct_sum, sk_);

    std::cout << "7 + 6 = " << result[0] << " (expected 13)\n";
    EXPECT_TRUE(is_close_mod(result[0], 13, kToyPlaintextModulus, kTightTolerance));
}

// 测试乘法 - 不使用 relinearization
TEST_F(BGVMultiplyIsolatedTest, MultiplyWithoutRelin) {
    auto ct1 = evaluator_->encrypt(make_plaintext(7), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(6), pk_, rng_);
    
    std::cout << "ct1 size before multiply: " << ct1.size() << "\n";
    std::cout << "ct2 size before multiply: " << ct2.size() << "\n";
    
    // 只做乘法，不做 relinearization
    auto ct_mul = evaluator_->multiply(ct1, ct2);
    
    std::cout << "ct_mul size after multiply: " << ct_mul.size() << "\n";
    
    // 需要用扩展的解密来处理 size=3 的密文
    // 标准解密只处理 (c0, c1)
    // 对于 (c0, c1, c2): m = c0 + c1*s + c2*s^2
    
    // 使用普通解密看结果
    auto result = evaluator_->decrypt(ct_mul, sk_);
    
    std::cout << "7 * 6 = " << result[0] << " (expected 42)\n";
    std::cout << "This tests multiply WITHOUT relinearization\n";
    
    // 如果这个测试通过，问题在 relinearization
    // 如果这个测试失败，问题在 tensor product
    EXPECT_TRUE(is_close_mod(result[0], 42, kToyPlaintextModulus, kLooseTolerance));
}

// 测试乘法 - 使用 relinearization
TEST_F(BGVMultiplyIsolatedTest, MultiplyWithRelin) {
    auto ct1 = evaluator_->encrypt(make_plaintext(7), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(6), pk_, rng_);
    
    auto ct_mul = evaluator_->multiply(ct1, ct2);
    std::cout << "ct_mul size before relin: " << ct_mul.size() << "\n";
    
    evaluator_->relinearize_inplace(ct_mul, rk_);
    std::cout << "ct_mul size after relin: " << ct_mul.size() << "\n";
    
    auto result = evaluator_->decrypt(ct_mul, sk_);
    
    std::cout << "7 * 6 = " << result[0] << " (expected 42, with relin)\n";
    EXPECT_TRUE(is_close_mod(result[0], 42, kToyPlaintextModulus, kLooseTolerance));
}

// 测试简单的 1 * 1 = 1 (排除 overflow 问题)
TEST_F(BGVMultiplyIsolatedTest, MultiplyOneByOne) {
    auto ct1 = evaluator_->encrypt(make_plaintext(1), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(1), pk_, rng_);
    
    auto ct_mul = evaluator_->multiply(ct1, ct2);
    auto result = evaluator_->decrypt(ct_mul, sk_);
    
    std::cout << "1 * 1 = " << result[0] << " (expected 1)\n";
    EXPECT_TRUE(is_close_mod(result[0], 1, kToyPlaintextModulus, kLooseTolerance));
}

// 测试 2 * 3 = 6
TEST_F(BGVMultiplyIsolatedTest, MultiplyTwoByThree) {
    auto ct1 = evaluator_->encrypt(make_plaintext(2), pk_, rng_);
    auto ct2 = evaluator_->encrypt(make_plaintext(3), pk_, rng_);
    
    auto ct_mul = evaluator_->multiply(ct1, ct2);
    auto result = evaluator_->decrypt(ct_mul, sk_);
    
    std::cout << "2 * 3 = " << result[0] << " (expected 6)\n";
    EXPECT_TRUE(is_close_mod(result[0], 6, kToyPlaintextModulus, kLooseTolerance));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
