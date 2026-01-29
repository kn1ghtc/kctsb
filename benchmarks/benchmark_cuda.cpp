/**
 * @file benchmark_cuda.cpp
 * @brief kctsb CPU vs CUDA GPU 性能对比
 *
 * 对比操作:
 *   - NTT: 数论变换 (n=8192, 16384, 32768, 65536)
 *   - INTT: 逆数论变换
 *   - PolyMul: 多项式乘法
 *   - FHE 操作: 密文乘法、重线性化
 *
 * 测试参数:
 *   - 多项式维度: n = 8192 ~ 65536
 *   - 模数: 50-bit NTT 友好素数
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifdef BENCHMARK_HAS_CUDA

#include <iostream>
#include <vector>
#include <cstring>

#include "benchmark_common.hpp"

// kctsb 公共 API
#include "kctsb/kctsb_api.h"

// CUDA 运行时
#include <cuda_runtime.h>

namespace {

// 测试的多项式维度
const std::vector<size_t> TEST_DIMENSIONS = {
    8192,
    16384,
    32768,
    65536
};

// ============================================================================
// NTT 对比
// ============================================================================

void benchmark_ntt() {
    std::cout << "\n--- NTT (Number Theoretic Transform) ---\n";
    benchmark::print_table_header();

    for (size_t n : TEST_DIMENSIONS) {
        // 生成随机多项式系数
        std::vector<uint64_t> poly(n);
        for (size_t i = 0; i < n; ++i) {
            poly[i] = static_cast<uint64_t>(rand()) % ((1ULL << 50) - 1);
        }

        std::vector<uint64_t> result_cpu(n);
        std::vector<uint64_t> result_gpu(n);

        // ============ CPU NTT ============
        benchmark::Timer timer;
        double cpu_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_ntt_forward_cpu(poly.data(), n, result_cpu.data());
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_ntt_forward_cpu(poly.data(), n, result_cpu.data());
            cpu_total += timer.stop();
        }

        double cpu_avg = cpu_total / benchmark::BENCHMARK_ITERATIONS;

        // ============ GPU NTT ============
        double gpu_total = 0;

        // 预热 (包括 CUDA 初始化)
        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_ntt_forward_cuda(poly.data(), n, result_gpu.data());
        }
        cudaDeviceSynchronize();

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_ntt_forward_cuda(poly.data(), n, result_gpu.data());
            cudaDeviceSynchronize();
            gpu_total += timer.stop();
        }

        double gpu_avg = gpu_total / benchmark::BENCHMARK_ITERATIONS;

        // 打印结果
        std::string dim_name = "n=" + std::to_string(n);

        benchmark::print_result({
            "NTT " + dim_name, "CPU",
            cpu_avg, 0, n * sizeof(uint64_t), benchmark::BENCHMARK_ITERATIONS
        });
        benchmark::print_result({
            "NTT " + dim_name, "CUDA",
            gpu_avg, 0, n * sizeof(uint64_t), benchmark::BENCHMARK_ITERATIONS
        });

        double speedup = cpu_avg / gpu_avg;
        std::string status = (speedup >= 2.0) ? "EXCELLENT" :
                            (speedup >= 1.0) ? "GOOD" : "CPU FASTER";
        std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << speedup << "x ("
                  << status << ")\n\n";
    }
}

// ============================================================================
// INTT (逆 NTT) 对比
// ============================================================================

void benchmark_intt() {
    std::cout << "\n--- INTT (Inverse NTT) ---\n";
    benchmark::print_table_header();

    for (size_t n : TEST_DIMENSIONS) {
        // 生成 NTT 域多项式
        std::vector<uint64_t> poly_ntt(n);
        for (size_t i = 0; i < n; ++i) {
            poly_ntt[i] = static_cast<uint64_t>(rand()) % ((1ULL << 50) - 1);
        }

        std::vector<uint64_t> result_cpu(n);
        std::vector<uint64_t> result_gpu(n);

        // ============ CPU INTT ============
        benchmark::Timer timer;
        double cpu_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_ntt_inverse_cpu(poly_ntt.data(), n, result_cpu.data());
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_ntt_inverse_cpu(poly_ntt.data(), n, result_cpu.data());
            cpu_total += timer.stop();
        }

        double cpu_avg = cpu_total / benchmark::BENCHMARK_ITERATIONS;

        // ============ GPU INTT ============
        double gpu_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_ntt_inverse_cuda(poly_ntt.data(), n, result_gpu.data());
        }
        cudaDeviceSynchronize();

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_ntt_inverse_cuda(poly_ntt.data(), n, result_gpu.data());
            cudaDeviceSynchronize();
            gpu_total += timer.stop();
        }

        double gpu_avg = gpu_total / benchmark::BENCHMARK_ITERATIONS;

        // 打印结果
        std::string dim_name = "n=" + std::to_string(n);

        benchmark::print_result({
            "INTT " + dim_name, "CPU",
            cpu_avg, 0, n * sizeof(uint64_t), benchmark::BENCHMARK_ITERATIONS
        });
        benchmark::print_result({
            "INTT " + dim_name, "CUDA",
            gpu_avg, 0, n * sizeof(uint64_t), benchmark::BENCHMARK_ITERATIONS
        });

        double speedup = cpu_avg / gpu_avg;
        std::string status = (speedup >= 2.0) ? "EXCELLENT" :
                            (speedup >= 1.0) ? "GOOD" : "CPU FASTER";
        std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << speedup << "x ("
                  << status << ")\n\n";
    }
}

// ============================================================================
// 多项式乘法对比
// ============================================================================

void benchmark_polymul() {
    std::cout << "\n--- Polynomial Multiplication ---\n";
    benchmark::print_table_header();

    for (size_t n : TEST_DIMENSIONS) {
        // 生成两个随机多项式
        std::vector<uint64_t> poly_a(n);
        std::vector<uint64_t> poly_b(n);
        for (size_t i = 0; i < n; ++i) {
            poly_a[i] = static_cast<uint64_t>(rand()) % ((1ULL << 50) - 1);
            poly_b[i] = static_cast<uint64_t>(rand()) % ((1ULL << 50) - 1);
        }

        std::vector<uint64_t> result_cpu(n);
        std::vector<uint64_t> result_gpu(n);

        // ============ CPU PolyMul ============
        benchmark::Timer timer;
        double cpu_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_polymul_ntt_cpu(poly_a.data(), poly_b.data(), n, result_cpu.data());
        }

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_polymul_ntt_cpu(poly_a.data(), poly_b.data(), n, result_cpu.data());
            cpu_total += timer.stop();
        }

        double cpu_avg = cpu_total / benchmark::BENCHMARK_ITERATIONS;

        // ============ GPU PolyMul ============
        double gpu_total = 0;

        for (size_t i = 0; i < benchmark::WARMUP_ITERATIONS; ++i) {
            kctsb_polymul_ntt_cuda(poly_a.data(), poly_b.data(), n, result_gpu.data());
        }
        cudaDeviceSynchronize();

        for (size_t i = 0; i < benchmark::BENCHMARK_ITERATIONS; ++i) {
            timer.start();
            kctsb_polymul_ntt_cuda(poly_a.data(), poly_b.data(), n, result_gpu.data());
            cudaDeviceSynchronize();
            gpu_total += timer.stop();
        }

        double gpu_avg = gpu_total / benchmark::BENCHMARK_ITERATIONS;

        // 打印结果
        std::string dim_name = "n=" + std::to_string(n);

        benchmark::print_result({
            "PolyMul " + dim_name, "CPU",
            cpu_avg, 0, n * sizeof(uint64_t) * 2, benchmark::BENCHMARK_ITERATIONS
        });
        benchmark::print_result({
            "PolyMul " + dim_name, "CUDA",
            gpu_avg, 0, n * sizeof(uint64_t) * 2, benchmark::BENCHMARK_ITERATIONS
        });

        double speedup = cpu_avg / gpu_avg;
        std::string status = (speedup >= 2.0) ? "EXCELLENT" :
                            (speedup >= 1.0) ? "GOOD" : "CPU FASTER";
        std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << speedup << "x ("
                  << status << ")\n\n";
    }
}

// ============================================================================
// GPU 信息
// ============================================================================

void print_gpu_info() {
    int device_count = 0;
    cudaGetDeviceCount(&device_count);

    if (device_count == 0) {
        std::cout << "No CUDA-capable devices found.\n";
        return;
    }

    std::cout << "\nCUDA Device Information:\n";
    benchmark::print_separator('-', 50);

    for (int i = 0; i < device_count; ++i) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);

        std::cout << "Device " << i << ": " << prop.name << '\n';
        std::cout << "  Compute Capability: " << prop.major << "." << prop.minor << '\n';
        std::cout << "  Total Memory: " << prop.totalGlobalMem / (1024 * 1024) << " MB\n";
        std::cout << "  SM Count: " << prop.multiProcessorCount << '\n';
        std::cout << "  Max Threads/Block: " << prop.maxThreadsPerBlock << '\n';
        std::cout << "  Clock Rate: " << prop.clockRate / 1000 << " MHz\n";
    }

    std::cout << '\n';
}

} // anonymous namespace

// ============================================================================
// 导出函数
// ============================================================================

void run_cuda_benchmarks() {
    std::cout << "\nRunning CUDA GPU comparison benchmarks...\n";
    std::cout << "Testing: NTT, INTT, Polynomial Multiplication\n";

    print_gpu_info();

    benchmark_ntt();
    benchmark_intt();
    benchmark_polymul();

    std::cout << "\nCUDA benchmarks complete.\n";
    std::cout << "\nNote: For small n (<4096), CPU may be faster due to CUDA kernel launch overhead.\n";
    std::cout << "GPU acceleration becomes significant for n >= 16384.\n";
}

#endif // BENCHMARK_HAS_CUDA
