/**
 * @file test_multiply_isolated.cpp
 * @brief 隔离测试 BGV 乘法问题 - 不使用 relinearization
 * 
 * 目的: 确定乘法失败是在 tensor product 还是 relinearization
 */

#include <gtest/gtest.h>
#include <iostream>
#include <cstdint>
#include <vector>

#include "kctsb/advanced/fe/bgv/bgv_evaluator.hpp"

using namespace kctsb::advanced::fe::bgv;

class BGVMultiplyIsolatedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 使用小参数便于调试
        size_t n = 4096;
        size_t L = 2;  // 2 个模数级别
        uint64_t t = 65537;  // 明文模数
        
        context_ = std::make_shared<BGVContext>(n, L, t);
    }
    
    std::shared_ptr<BGVContext> context_;
};

// 测试加密/解密基础功能
TEST_F(BGVMultiplyIsolatedTest, EncryptDecryptBasic) {
    BGVSecretKey sk(context_);
    BGVPublicKey pk(sk);
    BGVEvaluator evaluator(context_);
    
    // 加密 7
    std::vector<uint64_t> plain7 = {7};
    auto ct = evaluator.encrypt_secret(plain7, sk);
    
    // 解密
    auto result = evaluator.decrypt(ct, sk);
    
    std::cout << "Encrypt(7) -> Decrypt: " << result[0] << "\n";
    EXPECT_EQ(result[0], 7);
}

// 测试加法
TEST_F(BGVMultiplyIsolatedTest, AdditionCorrectness) {
    BGVSecretKey sk(context_);
    BGVPublicKey pk(sk);
    BGVEvaluator evaluator(context_);
    
    std::vector<uint64_t> plain7 = {7};
    std::vector<uint64_t> plain6 = {6};
    
    auto ct1 = evaluator.encrypt_secret(plain7, sk);
    auto ct2 = evaluator.encrypt_secret(plain6, sk);
    
    auto ct_sum = evaluator.add(ct1, ct2);
    auto result = evaluator.decrypt(ct_sum, sk);
    
    std::cout << "7 + 6 = " << result[0] << " (expected 13)\n";
    EXPECT_EQ(result[0], 13);
}

// 测试乘法 - 不使用 relinearization
TEST_F(BGVMultiplyIsolatedTest, MultiplyWithoutRelin) {
    BGVSecretKey sk(context_);
    BGVPublicKey pk(sk);
    BGVEvaluator evaluator(context_);
    
    std::vector<uint64_t> plain7 = {7};
    std::vector<uint64_t> plain6 = {6};
    
    auto ct1 = evaluator.encrypt_secret(plain7, sk);
    auto ct2 = evaluator.encrypt_secret(plain6, sk);
    
    std::cout << "ct1 size before multiply: " << ct1.size() << "\n";
    std::cout << "ct2 size before multiply: " << ct2.size() << "\n";
    
    // 只做乘法，不做 relinearization
    auto ct_mul = evaluator.multiply(ct1, ct2);
    
    std::cout << "ct_mul size after multiply: " << ct_mul.size() << "\n";
    
    // 需要用扩展的解密来处理 size=3 的密文
    // 标准解密只处理 (c0, c1)
    // 对于 (c0, c1, c2): m = c0 + c1*s + c2*s^2
    
    // 使用普通解密看结果
    auto result = evaluator.decrypt(ct_mul, sk);
    
    std::cout << "7 * 6 = " << result[0] << " (expected 42)\n";
    std::cout << "This tests multiply WITHOUT relinearization\n";
    
    // 如果这个测试通过，问题在 relinearization
    // 如果这个测试失败，问题在 tensor product
    EXPECT_EQ(result[0], 42);
}

// 测试乘法 - 使用 relinearization
TEST_F(BGVMultiplyIsolatedTest, MultiplyWithRelin) {
    BGVSecretKey sk(context_);
    BGVPublicKey pk(sk);
    BGVRelinKey rk(sk);
    BGVEvaluator evaluator(context_);
    
    std::vector<uint64_t> plain7 = {7};
    std::vector<uint64_t> plain6 = {6};
    
    auto ct1 = evaluator.encrypt_secret(plain7, sk);
    auto ct2 = evaluator.encrypt_secret(plain6, sk);
    
    auto ct_mul = evaluator.multiply(ct1, ct2);
    std::cout << "ct_mul size before relin: " << ct_mul.size() << "\n";
    
    evaluator.relinearize_inplace(ct_mul, rk);
    std::cout << "ct_mul size after relin: " << ct_mul.size() << "\n";
    
    auto result = evaluator.decrypt(ct_mul, sk);
    
    std::cout << "7 * 6 = " << result[0] << " (expected 42, with relin)\n";
    EXPECT_EQ(result[0], 42);
}

// 测试简单的 1 * 1 = 1 (排除 overflow 问题)
TEST_F(BGVMultiplyIsolatedTest, MultiplyOneByOne) {
    BGVSecretKey sk(context_);
    BGVPublicKey pk(sk);
    BGVEvaluator evaluator(context_);
    
    std::vector<uint64_t> plain1 = {1};
    
    auto ct1 = evaluator.encrypt_secret(plain1, sk);
    auto ct2 = evaluator.encrypt_secret(plain1, sk);
    
    auto ct_mul = evaluator.multiply(ct1, ct2);
    auto result = evaluator.decrypt(ct_mul, sk);
    
    std::cout << "1 * 1 = " << result[0] << " (expected 1)\n";
    EXPECT_EQ(result[0], 1);
}

// 测试 2 * 3 = 6
TEST_F(BGVMultiplyIsolatedTest, MultiplyTwoByThree) {
    BGVSecretKey sk(context_);
    BGVPublicKey pk(sk);
    BGVEvaluator evaluator(context_);
    
    std::vector<uint64_t> plain2 = {2};
    std::vector<uint64_t> plain3 = {3};
    
    auto ct1 = evaluator.encrypt_secret(plain2, sk);
    auto ct2 = evaluator.encrypt_secret(plain3, sk);
    
    auto ct_mul = evaluator.multiply(ct1, ct2);
    auto result = evaluator.decrypt(ct_mul, sk);
    
    std::cout << "2 * 3 = " << result[0] << " (expected 6)\n";
    EXPECT_EQ(result[0], 6);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
