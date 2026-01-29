/**
 * @file benchmark_main.cpp
 * @brief kctsb 三方库性能对比基准测试主程序
 *
 * 支持通过命令行参数选择对比目标:
 *   - openssl: 与 OpenSSL 3.6.0 对比 (AES-GCM, ChaCha20, SHA3, RSA, ECC)
 *   - seal:    与 SEAL 4.1.2 对比 (BFV, BGV, CKKS 同态加密)
 *   - gmssl:   与 GmSSL 对比 (SM2, SM3, SM4 国密算法)
 *   - cuda:    CPU vs GPU 对比 (NTT, FHE 操作)
 *   - all:     运行所有对比 (默认)
 *
 * 本程序仅通过库级别公共 API 进行对比，不依赖内部实现
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <iostream>
#include <string>

#include "benchmark_common.hpp"

// 仅使用 kctsb 公共 API
#include "kctsb/kctsb_api.h"

// ============================================================================
// 外部 benchmark 函数声明
// ============================================================================

#ifdef BENCHMARK_HAS_OPENSSL
/// OpenSSL 对比基准测试
void run_openssl_benchmarks();
#endif

#ifdef BENCHMARK_HAS_SEAL
/// SEAL 对比基准测试
void run_seal_benchmarks();
#endif

#ifdef BENCHMARK_HAS_GMSSL
/// GmSSL 对比基准测试
void run_gmssl_benchmarks();
#endif

#ifdef BENCHMARK_HAS_CUDA
/// CUDA 对比基准测试
void run_cuda_benchmarks();
#endif

// ============================================================================
// 版本信息
// ============================================================================

static void print_version_info() {
    std::cout << '\n';
    benchmark::print_separator('=');
    std::cout << "  kctsb Benchmark Suite v5.1.0\n";
    std::cout << "  Library-level Performance Comparison\n";
    benchmark::print_separator('=');

    std::cout << "\nAvailable Comparisons:\n";

#ifdef BENCHMARK_HAS_OPENSSL
    std::cout << "  [✓] OpenSSL 3.6.0 - AES-GCM, ChaCha20, SHA3, RSA, ECC\n";
#else
    std::cout << "  [✗] OpenSSL - Not available\n";
#endif

#ifdef BENCHMARK_HAS_SEAL
    std::cout << "  [✓] SEAL 4.1.2 - BFV, BGV, CKKS Homomorphic Encryption\n";
#else
    std::cout << "  [✗] SEAL - Not available\n";
#endif

#ifdef BENCHMARK_HAS_GMSSL
    std::cout << "  [✓] GmSSL - SM2, SM3, SM4 Chinese Cryptography\n";
#else
    std::cout << "  [✗] GmSSL - Not available\n";
#endif

#ifdef BENCHMARK_HAS_CUDA
    std::cout << "  [✓] CUDA GPU - NTT, FHE Operations\n";
#else
    std::cout << "  [✗] CUDA - Not available\n";
#endif

    std::cout << '\n';
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char* argv[]) {
    // 解析命令行参数
    auto opts = benchmark::parse_args(argc, argv);

    // 打印版本信息
    print_version_info();

    // 初始化 kctsb 库
    if (kctsb_init() != 0) {
        std::cerr << "Error: Failed to initialize kctsb library\n";
        return 1;
    }

    int benchmarks_run = 0;

    // 运行选定的基准测试
#ifdef BENCHMARK_HAS_OPENSSL
    if (opts.run_openssl || opts.run_all) {
        benchmark::print_header("OpenSSL 3.6.0 Comparison");
        run_openssl_benchmarks();
        ++benchmarks_run;
    }
#endif

#ifdef BENCHMARK_HAS_SEAL
    if (opts.run_seal || opts.run_all) {
        benchmark::print_header("SEAL 4.1.2 Comparison");
        run_seal_benchmarks();
        ++benchmarks_run;
    }
#endif

#ifdef BENCHMARK_HAS_GMSSL
    if (opts.run_gmssl || opts.run_all) {
        benchmark::print_header("GmSSL Comparison");
        run_gmssl_benchmarks();
        ++benchmarks_run;
    }
#endif

#ifdef BENCHMARK_HAS_CUDA
    if (opts.run_cuda || opts.run_all) {
        benchmark::print_header("CUDA GPU Comparison");
        run_cuda_benchmarks();
        ++benchmarks_run;
    }
#endif

    // 清理 kctsb 库
    kctsb_cleanup();

    if (benchmarks_run == 0) {
        std::cout << "No benchmarks were run.\n";
        std::cout << "Usage: " << argv[0] << " [openssl|seal|gmssl|cuda|all]\n";
        return 1;
    }

    std::cout << '\n';
    benchmark::print_separator('=');
    std::cout << "  Benchmark Complete - " << benchmarks_run << " comparison(s) run\n";
    benchmark::print_separator('=');
    std::cout << '\n';

    return 0;
}
