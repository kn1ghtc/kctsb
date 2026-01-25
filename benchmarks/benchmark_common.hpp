/**
 * @file benchmark_common.hpp
 * @brief Common utilities for kctsb benchmarks with ratio comparison
 * 
 * Provides unified benchmark output format with:
 * - Performance metrics (avg, min, throughput)
 * - OpenSSL vs kctsb ratio comparison
 * - Consistent formatting across all benchmark modules
 * 
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_BENCHMARK_COMMON_HPP
#define KCTSB_BENCHMARK_COMMON_HPP

#include <iostream>
#include <iomanip>
#include <string>
#include <functional>
#include <vector>
#include <algorithm>
#include <numeric>
#include <chrono>

namespace kctsb_bench {

/**
 * @brief High-resolution timer types
 */
using Clock = std::chrono::high_resolution_clock;
using Duration = std::chrono::duration<double, std::milli>;

/**
 * @brief Benchmark result containing timing and throughput data
 */
struct BenchmarkResult {
    double avg_ms;          ///< Average time in milliseconds
    double min_ms;          ///< Minimum time in milliseconds
    double throughput;      ///< Throughput in ops/s or MB/s
    bool valid;             ///< Whether benchmark completed successfully
    
    BenchmarkResult() : avg_ms(0), min_ms(0), throughput(0), valid(false) {}
    BenchmarkResult(double avg, double min_t, double tp) 
        : avg_ms(avg), min_ms(min_t), throughput(tp), valid(true) {}
};

/**
 * @brief Print ratio comparison between kctsb and OpenSSL
 * 
 * For time-based metrics (lower is better):
 *   ratio = openssl_time / kctsb_time
 *   ratio > 1.0 means kctsb is FASTER
 * 
 * For throughput-based metrics (higher is better):
 *   ratio = kctsb_throughput / openssl_throughput
 *   ratio > 1.0 means kctsb is FASTER
 * 
 * @param kctsb_value kctsb metric value
 * @param openssl_value OpenSSL metric value
 * @param is_time If true, lower is better; if false, higher is better
 */
inline void print_ratio(double kctsb_value, double openssl_value, bool is_time = true) {
    if (openssl_value <= 0 || kctsb_value <= 0) {
        std::cout << std::left << std::setw(25) << "  ==> Ratio"
                  << std::setw(12) << ""
                  << "  (comparison not available)" << std::endl;
        return;
    }
    
    double ratio;
    if (is_time) {
        // For time: lower is better, so ratio = openssl/kctsb
        ratio = openssl_value / kctsb_value;
    } else {
        // For throughput: higher is better, so ratio = kctsb/openssl
        ratio = kctsb_value / openssl_value;
    }
    
    const char* status = ratio >= 1.0 ? "FASTER" : "SLOWER";
    const char* symbol = ratio >= 1.0 ? "+" : "";
    double diff_percent = (ratio - 1.0) * 100.0;
    
    std::cout << std::left << std::setw(25) << "  ==> Ratio"
              << std::setw(12) << ""
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(10) << ratio << "x"
              << "    (" << symbol << std::setprecision(1) << diff_percent << "% " << status << ")"
              << std::endl;
}

/**
 * @brief Print ratio with percentage of OpenSSL performance
 * 
 * @param kctsb_time kctsb execution time in ms
 * @param openssl_time OpenSSL execution time in ms
 */
inline void print_time_ratio(double kctsb_time, double openssl_time) {
    if (openssl_time <= 0 || kctsb_time <= 0) {
        std::cout << std::left << std::setw(25) << "  ==> Ratio"
                  << std::setw(12) << ""
                  << "  (comparison not available)" << std::endl;
        return;
    }
    
    // Percentage of OpenSSL performance: (openssl_time / kctsb_time) * 100%
    double ratio = openssl_time / kctsb_time;
    double percent_of_openssl = ratio * 100.0;
    const char* status = ratio >= 1.0 ? "FASTER" : "SLOWER";
    
    std::cout << std::left << std::setw(25) << "  ==> Ratio"
              << std::setw(12) << ""
              << std::right << std::fixed << std::setprecision(2)
              << std::setw(8) << percent_of_openssl << "%"
              << " of OpenSSL (" << ratio << "x " << status << ")"
              << std::endl;
}

/**
 * @brief Run benchmark and return result with statistics
 * 
 * @param warmup_iters Number of warmup iterations
 * @param bench_iters Number of benchmark iterations
 * @param benchmark_func Function returning execution time in ms
 * @return BenchmarkResult with statistics
 */
inline BenchmarkResult run_benchmark_ex(
    size_t warmup_iters,
    size_t bench_iters,
    std::function<double()> benchmark_func
) {
    std::vector<double> times;
    times.reserve(bench_iters);
    
    // Warmup
    for (size_t i = 0; i < warmup_iters; ++i) {
        double t = benchmark_func();
        if (t < 0) return BenchmarkResult();  // Error during warmup
    }
    
    // Benchmark
    for (size_t i = 0; i < bench_iters; ++i) {
        double t = benchmark_func();
        if (t < 0) return BenchmarkResult();  // Error during benchmark
        times.push_back(t);
    }
    
    // Calculate statistics
    double avg = std::accumulate(times.begin(), times.end(), 0.0) /
                 static_cast<double>(times.size());
    double min_t = *std::min_element(times.begin(), times.end());
    double ops_per_sec = 1000.0 / avg;
    
    return BenchmarkResult(avg, min_t, ops_per_sec);
}

/**
 * @brief Print benchmark result line
 * 
 * @param name Operation name
 * @param impl Implementation name (OpenSSL/kctsb)
 * @param result Benchmark result
 * @param show_throughput If true, show throughput in op/s
 */
inline void print_result(
    const std::string& name,
    const std::string& impl,
    const BenchmarkResult& result,
    bool show_throughput = true
) {
    if (!result.valid) {
        std::cout << std::left << std::setw(25) << name
                  << std::setw(12) << impl
                  << "  (benchmark failed)" << std::endl;
        return;
    }
    
    std::cout << std::left << std::setw(25) << name
              << std::setw(12) << impl
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(10) << result.avg_ms << " ms"
              << std::setw(10) << result.min_ms << " ms";
    
    if (show_throughput) {
        std::cout << std::setw(10) << std::setprecision(1) << result.throughput << " op/s";
    }
    std::cout << std::endl;
}

/**
 * @brief Print benchmark result with throughput in MB/s
 * 
 * @param name Operation name
 * @param impl Implementation name
 * @param avg_ms Average time in ms
 * @param min_ms Minimum time in ms
 * @param data_size Data size in bytes
 */
inline void print_throughput_result(
    const std::string& name,
    const std::string& impl,
    double avg_ms,
    double min_ms,
    size_t data_size
) {
    double throughput = (static_cast<double>(data_size) / (1024.0 * 1024.0)) / (avg_ms / 1000.0);
    
    std::cout << std::left << std::setw(25) << name
              << std::setw(12) << impl
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(10) << avg_ms << " ms"
              << std::setw(10) << min_ms << " ms"
              << std::setw(10) << std::setprecision(2) << throughput << " MB/s"
              << std::endl;
}

} // namespace kctsb_bench

#endif // KCTSB_BENCHMARK_COMMON_HPP
