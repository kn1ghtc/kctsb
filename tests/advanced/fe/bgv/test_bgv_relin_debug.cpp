/**
 * @file test_bgv_relin_debug.cpp
 * @brief 调试 BGV relinearization - 逐步检查每个操作
 */

#include <iostream>
#include <cstdint>
#include <vector>
#include <random>

#include "kctsb/advanced/fe/bgv/bgv_evaluator.hpp"
#include "kctsb/advanced/fe/common/rns_poly.hpp"

using namespace kctsb::fhe::bgv;
using namespace kctsb::fhe::common;

void print_first_n(const RNSPoly& p, size_t n, const std::string& name) {
    RNSPoly temp = p;
    if (temp.is_ntt_form()) {
        temp.intt_transform();
    }
    std::cout << name << ": [";
    const uint64_t* data = temp.data(0);
    for (size_t i = 0; i < std::min(n, size_t(16)); ++i) {
        std::cout << data[i];
        if (i < std::min(n, size_t(16)) - 1) std::cout << ", ";
    }
    std::cout << "]\n";
}

int main() {
    std::cout << "=== BGV Relinearization Debug ===\n\n";
    
    // 使用最小参数便于调试
    size_t n = 4096;
    size_t L = 2;
    uint64_t t = 257;  // 更小的明文模数便于调试
    
    auto context = std::make_shared<RNSContext>(n, L);
    BGVEvaluator evaluator(context.get(), t);
    
    std::mt19937_64 rng(42);  // 固定种子便于复现
    
    // 生成密钥
    auto sk = evaluator.generate_secret_key(rng);
    auto pk = evaluator.generate_public_key(sk, rng);
    auto rk = evaluator.generate_relin_key(sk, rng);
    
    std::cout << "Keys generated successfully\n";
    
    // 加密 7 和 6
    std::vector<uint64_t> plain7 = {7};
    std::vector<uint64_t> plain6 = {6};
    
    auto ct1 = evaluator.encrypt(plain7, pk, rng);
    auto ct2 = evaluator.encrypt(plain6, pk, rng);
    
    std::cout << "ct1 size: " << ct1.size() << "\n";
    std::cout << "ct2 size: " << ct2.size() << "\n";
    
    // 解密验证
    auto dec1 = evaluator.decrypt(ct1, sk);
    auto dec2 = evaluator.decrypt(ct2, sk);
    std::cout << "Decrypt ct1: " << dec1[0] << " (expected 7)\n";
    std::cout << "Decrypt ct2: " << dec2[0] << " (expected 6)\n";
    
    // 乘法
    auto ct_mul = evaluator.multiply(ct1, ct2);
    std::cout << "\nAfter multiply, ct_mul size: " << ct_mul.size() << "\n";
    
    // 不带 relinearization 的解密
    auto dec_mul_norelin = evaluator.decrypt(ct_mul, sk);
    std::cout << "Decrypt without relin: " << dec_mul_norelin[0] << " (expected 42)\n";
    
    // 手动检查 relinearization 过程
    std::cout << "\n=== Manual Relinearization Check ===\n";
    
    // 获取 c0, c1, c2
    print_first_n(ct_mul[0], 8, "c0");
    print_first_n(ct_mul[1], 8, "c1");
    print_first_n(ct_mul[2], 8, "c2");
    
    // 获取 ksk
    std::cout << "\nRelinearization key:\n";
    print_first_n(rk.ksk0[0], 8, "ksk0[0]");
    print_first_n(rk.ksk1[0], 8, "ksk1[0]");
    
    // 检查 ksk0 + ksk1*s 是否约等于 s^2
    {
        RNSPoly test = rk.ksk0[0] + (rk.ksk1[0] * sk.s);
        RNSPoly s2 = sk.s * sk.s;
        
        RNSPoly test_coeff = test;
        RNSPoly s2_coeff = s2;
        test_coeff.intt_transform();
        s2_coeff.intt_transform();
        
        std::cout << "\nksk0 + ksk1*s vs s^2 (first 8 coeffs):\n";
        const uint64_t* test_data = test_coeff.data(0);
        const uint64_t* s2_data = s2_coeff.data(0);
        uint64_t q0 = context->modulus(0).value();
        
        std::cout << "ksk0+ksk1*s: [";
        for (size_t i = 0; i < 8; ++i) {
            std::cout << test_data[i] << " ";
        }
        std::cout << "]\n";
        
        std::cout << "s^2:         [";
        for (size_t i = 0; i < 8; ++i) {
            std::cout << s2_data[i] << " ";
        }
        std::cout << "]\n";
        
        // 差值应该是 t 的倍数
        std::cout << "diff mod t:  [";
        for (size_t i = 0; i < 8; ++i) {
            int64_t d1 = static_cast<int64_t>(test_data[i]);
            int64_t d2 = static_cast<int64_t>(s2_data[i]);
            int64_t diff = d1 - d2;
            if (diff < 0) diff += q0;
            std::cout << (diff % t) << " ";
        }
        std::cout << "] (should be all 0)\n";
    }
    
    // 执行 relinearization
    evaluator.relinearize_inplace(ct_mul, rk);
    std::cout << "\nAfter relinearization, ct_mul size: " << ct_mul.size() << "\n";
    
    // 解密
    auto dec_mul = evaluator.decrypt(ct_mul, sk);
    std::cout << "Decrypt with relin: " << dec_mul[0] << " (expected 42)\n";
    
    if (dec_mul[0] == 42) {
        std::cout << "\n=== SUCCESS ===\n";
    } else {
        std::cout << "\n=== FAIL ===\n";
        std::cout << "Got " << dec_mul[0] << " instead of 42\n";
    }
    
    return 0;
}
