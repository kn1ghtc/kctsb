/**
 * @file benchmark_common.hpp
 * @brief 通用 benchmark 工具函数和类型定义
 *
 * 提供统一的计时器、结果格式化、数据生成等基础设施
 * 供所有 benchmark 程序共享使用
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_BENCHMARK_COMMON_HPP
#define KCTSB_BENCHMARK_COMMON_HPP

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace benchmark {

// ============================================================================
// 常量定义
// ============================================================================

/// 预热迭代次数
constexpr size_t WARMUP_ITERATIONS = 10;

/// 基准测试迭代次数
constexpr size_t BENCHMARK_ITERATIONS = 100;

/// 测试数据大小
constexpr size_t SIZE_1KB = 1024;
constexpr size_t SIZE_1MB = 1024 * 1024;
constexpr size_t SIZE_10MB = 10 * 1024 * 1024;

// ============================================================================
// 高精度计时器
// ============================================================================

/**
 * @brief 高精度计时器类
 */
class Timer {
public:
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = std::chrono::time_point<Clock>;
    using Duration = std::chrono::duration<double, std::milli>;

    /// 开始计时
    void start() {
        m_start = Clock::now();
    }

    /// 停止计时并返回经过时间（毫秒）
    double stop() {
        auto end = Clock::now();
        Duration elapsed = end - m_start;
        return elapsed.count();
    }

    /// 获取经过时间（毫秒）但不停止计时
    double elapsed() const {
        auto now = Clock::now();
        Duration elapsed = now - m_start;
        return elapsed.count();
    }

private:
    TimePoint m_start;
};

// ============================================================================
// 测试结果结构
// ============================================================================

/**
 * @brief 单项测试结果
 */
struct Result {
    std::string name;           ///< 算法名称
    std::string impl;           ///< 实现名称 (kctsb/openssl/seal/gmssl)
    double time_ms;             ///< 平均时间（毫秒）
    double throughput_mbps;     ///< 吞吐量（MB/s）
    size_t data_size;           ///< 数据大小（字节）
    size_t iterations;          ///< 迭代次数
};

/**
 * @brief 对比结果
 */
struct Comparison {
    std::string algorithm;
    Result kctsb_result;
    Result reference_result;
    double ratio;               ///< kctsb / reference (< 1.0 表示 kctsb 更快)
    std::string status;         ///< EXCELLENT / GOOD / OK / SLOW
};

// ============================================================================
// 输出格式化
// ============================================================================

/**
 * @brief 打印分隔线
 */
inline void print_separator(char c = '=', int width = 80) {
    std::cout << std::string(width, c) << '\n';
}

/**
 * @brief 打印标题
 */
inline void print_header(const std::string& title) {
    std::cout << '\n';
    print_separator('=');
    std::cout << "  " << title << '\n';
    print_separator('=');
}

/**
 * @brief 打印表格头
 */
inline void print_table_header() {
    std::cout << std::left
              << std::setw(30) << "Algorithm"
              << std::setw(12) << "Impl"
              << std::right
              << std::setw(12) << "Time (ms)"
              << std::setw(15) << "Throughput"
              << '\n';
    print_separator('-', 70);
}

/**
 * @brief 打印单项结果
 */
inline void print_result(const Result& r) {
    std::cout << std::left
              << std::setw(30) << r.name
              << std::setw(12) << r.impl
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(12) << r.time_ms;

    if (r.throughput_mbps > 0) {
        std::cout << std::setw(12) << r.throughput_mbps << " MB/s";
    } else {
        std::cout << std::setw(15) << "N/A";
    }
    std::cout << '\n';
}

/**
 * @brief 打印对比结果
 */
inline void print_comparison(const Comparison& cmp) {
    std::cout << std::left << std::setw(30) << cmp.algorithm
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(10) << cmp.ratio << "x"
              << std::setw(15) << cmp.status
              << '\n';
}

/**
 * @brief 根据比率确定状态
 */
inline std::string get_status(double ratio) {
    if (ratio <= 0.8) return "EXCELLENT";
    if (ratio <= 1.0) return "GOOD";
    if (ratio <= 1.2) return "OK";
    return "SLOW";
}

/**
 * @brief 计算吞吐量 (MB/s)
 */
inline double calculate_throughput(size_t bytes, double time_ms) {
    if (time_ms <= 0) return 0;
    double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    double seconds = time_ms / 1000.0;
    return mb / seconds;
}

// ============================================================================
// 数据生成
// ============================================================================

/**
 * @brief 生成随机数据
 */
inline std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }
    return data;
}

/**
 * @brief 生成固定模式数据（用于可重复测试）
 */
inline std::vector<uint8_t> generate_pattern_data(size_t size, uint8_t seed = 0x42) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
    return data;
}

// ============================================================================
// 命令行参数解析
// ============================================================================

/**
 * @brief 解析命令行参数
 */
struct BenchmarkOptions {
    bool run_openssl = false;
    bool run_seal = false;
    bool run_gmssl = false;
    bool run_cuda = false;
    bool run_all = true;
    bool verbose = false;
};

inline BenchmarkOptions parse_args(int argc, char* argv[]) {
    BenchmarkOptions opts;

    if (argc < 2) {
        opts.run_all = true;
        return opts;
    }

    opts.run_all = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "openssl") opts.run_openssl = true;
        else if (arg == "seal") opts.run_seal = true;
        else if (arg == "gmssl") opts.run_gmssl = true;
        else if (arg == "cuda") opts.run_cuda = true;
        else if (arg == "all") opts.run_all = true;
        else if (arg == "-v" || arg == "--verbose") opts.verbose = true;
        else if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options] [targets]\n\n"
                      << "Targets:\n"
                      << "  openssl  Run OpenSSL comparison benchmarks\n"
                      << "  seal     Run SEAL comparison benchmarks\n"
                      << "  gmssl    Run GmSSL comparison benchmarks\n"
                      << "  cuda     Run CUDA comparison benchmarks\n"
                      << "  all      Run all benchmarks (default)\n\n"
                      << "Options:\n"
                      << "  -v, --verbose  Enable verbose output\n"
                      << "  -h, --help     Show this help\n";
            std::exit(0);
        }
    }

    if (opts.run_all) {
        opts.run_openssl = true;
        opts.run_seal = true;
        opts.run_gmssl = true;
        opts.run_cuda = true;
    }

    return opts;
}

} // namespace benchmark

#endif // KCTSB_BENCHMARK_COMMON_HPP
