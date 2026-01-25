/**
 * @file psi_pir_demo.cpp
 * @brief PSI/PIR功能演示程序
 * 
 * 演示 kctsb v4.13.0 新增的 PSI/PIR 功能:
 * 1. Piano-PSI - O(√n) 通信复杂度
 * 2. OT-based PSI - 混淆传输PSI
 * 3. Native PIR - 原生FHE-based PIR (BGV/BFV/CKKS)
 * 
 * @author kn1ghtc
 * @version 4.13.0
 * @date 2026-01-25
 */

#include <iostream>
#include <vector>
#include <chrono>
#include <cstring>
#include <cmath>
#include "kctsb/advanced/psi/psi.h"
#include "kctsb/advanced/psi/ot_psi.h"
#include "kctsb/advanced/psi/native_pir.h"

void demo_piano_psi() {
    std::cout << "\n=== Piano-PSI 演示 ===\n";
    
    // 客户端集合
    std::vector<int64_t> client_set = {1, 2, 3, 4, 5, 10, 15, 20};
    std::cout << "客户端集合大小: " << client_set.size() << "\n";
    
    // 服务器集合
    std::vector<int64_t> server_set;
    for (int i = 0; i < 100; ++i) {
        server_set.push_back(i * 2);  // {0, 2, 4, 6, ...}
    }
    std::cout << "服务器集合大小: " << server_set.size() << "\n";
    
    // Piano-PSI 配置
    kctsb_psi_config_t config;
    std::memset(&config, 0, sizeof(config));
    config.hash_table_size = 0;  // Auto
    config.num_hash_functions = 3;
    config.bucket_size = 4;
    config.statistical_security = 128;
    config.max_cuckoo_iterations = 20;
    config.load_factor_threshold = 0.75;
    config.enable_batch_optimization = true;
    config.malicious_security = false;
    
    kctsb_psi_ctx_t* ctx = kctsb_piano_psi_create(&config);
    if (!ctx) {
        std::cout << "创建 Piano-PSI 上下文失败\n";
        return;
    }
    
    kctsb_psi_result_t result;
    std::memset(&result, 0, sizeof(result));
    int ret = kctsb_piano_psi_compute(
        ctx,
        client_set.data(), client_set.size(),
        server_set.data(), server_set.size(),
        &result
    );
    
    if (ret == 0 && result.is_correct) {
        std::cout << "✓ 交集大小: " << result.intersection_size << "\n";
        std::cout << "执行时间: " << result.execution_time_ms << " ms\n";
        std::cout << "通信开销: " << result.communication_bytes << " bytes\n";
        std::cout << "负载因子: " << result.hash_table_load_factor << "\n";
        
        if (result.intersection_elements) {
            std::cout << "交集元素: ";
            for (size_t i = 0; i < result.intersection_size; ++i) {
                std::cout << result.intersection_elements[i] << " ";
            }
            std::cout << "\n";
            delete[] result.intersection_elements;
        }
    } else {
        std::cout << "✗ Piano-PSI 计算失败: " << result.error_message << "\n";
    }
    
    kctsb_piano_psi_destroy(ctx);
}

void demo_ot_psi() {
    std::cout << "\n=== OT-based PSI 演示 ===\n";
    
    std::vector<int64_t> client_set = {10, 20, 30, 40, 50};
    std::vector<int64_t> server_set = {5, 10, 15, 20, 25, 30, 35};
    
    std::cout << "客户端集合: {10, 20, 30, 40, 50}\n";
    std::cout << "服务器集合: {5, 10, 15, 20, 25, 30, 35}\n";
    std::cout << "预期交集: {10, 20, 30}\n";
    
    kctsb::psi::OTPSI::Config config;
    config.variant = KCTSB_OT_EXTENSION;
    config.security_parameter = 128;
    
    kctsb::psi::OTPSI ot_psi(config);
    auto result = ot_psi.compute(client_set, server_set);
    
    std::cout << "✓ 交集大小: " << result.intersection_size << "\n";
    std::cout << "执行时间: " << result.execution_time_ms << " ms\n";
    std::cout << "  - OT Setup: " << result.ot_setup_time_ms << " ms\n";
    std::cout << "  - OT Execution: " << result.ot_execution_time_ms << " ms\n";
    std::cout << "  - PSI Compute: " << result.psi_compute_time_ms << " ms\n";
    std::cout << "通信开销: " << result.communication_bytes << " bytes\n";
    std::cout << "OT 数量: " << result.ot_count << "\n";
    
    if (!result.intersection_elements.empty()) {
        std::cout << "交集元素: ";
        for (auto elem : result.intersection_elements) {
            std::cout << elem << " ";
        }
        std::cout << "\n";
    }
}

void demo_native_pir_bgv() {
    std::cout << "\n=== Native PIR (BGV) 演示 ===\n";
    
    // 整数数据库
    std::vector<int64_t> database = {100, 200, 300, 400, 500, 600, 700, 800};
    std::cout << "数据库大小: " << database.size() << " 个整数\n";
    std::cout << "数据库内容: {100, 200, 300, 400, 500, 600, 700, 800}\n";
    
    // BGV-PIR 配置
    kctsb::pir::NativePIR::Config config;
    config.scheme = KCTSB_PIR_BGV;
    config.poly_modulus_degree = 4096;  // 小一点更快
    config.plaintext_modulus = 65537;
    config.enable_batching = true;
    
    std::cout << "方案: BGV\n";
    std::cout << "多项式模数度: " << config.poly_modulus_degree << "\n";
    std::cout << "明文模数: " << config.plaintext_modulus << "\n";
    
    try {
        kctsb::pir::NativePIR pir(config, database);
        
        // 查询索引 3 (期望得到 400)
        size_t target_index = 3;
        std::cout << "\n查询索引 " << target_index << " (期望值: 400)...\n";
        
        auto result = pir.query(target_index);
        
        if (result.is_correct && !result.retrieved_data.empty()) {
            std::cout << "✓ 检索成功!\n";
            std::cout << "检索值: " << result.retrieved_data[0] << "\n";
            std::cout << "查询时间: " << result.query_time_ms << " ms\n";
            std::cout << "服务器处理: " << result.server_time_ms << " ms\n";
            std::cout << "客户端解密: " << result.client_time_ms << " ms\n";
            std::cout << "通信开销: " << result.communication_bytes << " bytes\n";
            std::cout << "噪声预算: " << result.noise_budget_bits << " bits\n";
        } else {
            std::cout << "✗ 检索失败: " << result.error_message << "\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "异常: " << e.what() << "\n";
    }
}

void demo_native_pir_ckks() {
    std::cout << "\n=== Native PIR (CKKS) 演示 ===\n";
    
    // 浮点数数据库
    std::vector<double> database = {1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8};
    std::cout << "数据库大小: " << database.size() << " 个浮点数\n";
    std::cout << "数据库内容: {1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8}\n";
    
    // CKKS-PIR 配置
    kctsb::pir::NativePIR::Config config;
    config.scheme = KCTSB_PIR_CKKS;
    config.poly_modulus_degree = 4096;
    config.ckks_scale = std::pow(2.0, 30);  // 降低scale减少计算量
    config.enable_batching = true;
    
    std::cout << "方案: CKKS\n";
    std::cout << "多项式模数度: " << config.poly_modulus_degree << "\n";
    std::cout << "缩放因子: 2^30\n";
    
    try {
        kctsb::pir::NativePIR pir(config, database);
        
        // 查询索引 2 (期望得到 3.3)
        size_t target_index = 2;
        std::cout << "\n查询索引 " << target_index << " (期望值: 3.3)...\n";
        
        auto result = pir.query(target_index);
        
        if (result.is_correct && result.retrieved_double != 0.0) {
            std::cout << "✓ 检索成功!\n";
            std::cout << "检索值: " << result.retrieved_double << " (CKKS近似)\n";
            std::cout << "查询时间: " << result.query_time_ms << " ms\n";
            std::cout << "服务器处理: " << result.server_time_ms << " ms\n";
            std::cout << "客户端解密: " << result.client_time_ms << " ms\n";
            std::cout << "通信开销: " << result.communication_bytes << " bytes\n";
            std::cout << "噪声预算: " << result.noise_budget_bits << " bits\n";
        } else {
            std::cout << "✗ 检索失败: " << result.error_message << "\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "异常: " << e.what() << "\n";
    }
}

int main() {
    std::cout << "============================================================\n";
    std::cout << "kctsb v4.13.0 - PSI/PIR 功能演示\n";
    std::cout << "============================================================\n";
    
    try {
        demo_piano_psi();
        demo_ot_psi();
        demo_native_pir_bgv();
        demo_native_pir_ckks();
        
        std::cout << "\n============================================================\n";
        std::cout << "演示完成!\n";
        std::cout << "============================================================\n";
        
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
