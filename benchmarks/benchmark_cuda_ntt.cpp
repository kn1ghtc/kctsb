/**
 * @file benchmark_cuda_ntt.cpp
 * @brief CUDA NTT Benchmark - Standalone test for GPU acceleration
 * 
 * @details Tests GPU vs CPU NTT performance
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-26
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <cstdint>
#include <cstring>
#include <iomanip>

// CUDA kernel declarations
extern "C" {
    bool kctsb_cuda_runtime_available();
    int kctsb_cuda_get_device_info(int device_id, char* name, size_t name_len,
                                   size_t* total_mem, int* compute_cap_major,
                                   int* compute_cap_minor);
    int kctsb_cuda_malloc(void** ptr, size_t size);
    int kctsb_cuda_free(void* ptr);
    int kctsb_cuda_memcpy_h2d(void* dst, const void* src, size_t size);
    int kctsb_cuda_memcpy_d2h(void* dst, const void* src, size_t size);
    int kctsb_cuda_ntt_forward(uint64_t* d_data, const uint64_t* d_root_powers,
                               const uint64_t* d_root_powers_shoup, uint64_t modulus, int log_n);
    int kctsb_cuda_ntt_inverse(uint64_t* d_data, const uint64_t* d_inv_root_powers,
                               const uint64_t* d_inv_root_powers_shoup, uint64_t modulus,
                               uint64_t inv_n, uint64_t inv_n_shoup, int log_n);
    int kctsb_cuda_poly_multiply(uint64_t* d_result, const uint64_t* d_a, const uint64_t* d_b,
                                 uint64_t modulus, uint64_t barrett_k, size_t n);
}

using Clock = std::chrono::high_resolution_clock;

// ============================================================================
// CPU Reference Implementation (for comparison)
// ============================================================================

/**
 * @brief CPU modular multiplication
 */
inline uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod) {
    __uint128_t product = static_cast<__uint128_t>(a) * b;
    return static_cast<uint64_t>(product % mod);
}

/**
 * @brief CPU modular exponentiation
 */
uint64_t powmod_cpu(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = mulmod_cpu(result, base, mod);
        }
        base = mulmod_cpu(base, base, mod);
        exp >>= 1;
    }
    return result;
}

/**
 * @brief Bit reverse an index
 */
size_t bit_reverse(size_t x, int bits) {
    size_t result = 0;
    for (int i = 0; i < bits; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

/**
 * @brief CPU NTT forward transform
 */
void ntt_forward_cpu(std::vector<uint64_t>& data, uint64_t modulus, 
                     const std::vector<uint64_t>& root_powers, int log_n) {
    size_t n = data.size();
    
    // Bit-reverse permutation
    for (size_t i = 0; i < n; ++i) {
        size_t j = bit_reverse(i, log_n);
        if (i < j) std::swap(data[i], data[j]);
    }
    
    // Cooley-Tukey butterfly
    for (int stage = 1; stage <= log_n; ++stage) {
        size_t m = 1ULL << stage;
        size_t half_m = m >> 1;
        
        for (size_t group = 0; group < n / m; ++group) {
            for (size_t j = 0; j < half_m; ++j) {
                size_t i0 = group * m + j;
                size_t i1 = i0 + half_m;
                
                size_t root_idx = (1ULL << (stage - 1)) + j;
                uint64_t w = (root_idx < root_powers.size()) ? root_powers[root_idx] : 1;
                
                uint64_t u = data[i0];
                uint64_t t = mulmod_cpu(data[i1], w, modulus);
                
                data[i0] = (u + t) % modulus;
                data[i1] = (u >= t) ? (u - t) : (modulus + u - t);
            }
        }
    }
}

/**
 * @brief Generate NTT-friendly prime
 */
uint64_t generate_ntt_prime(int bits, size_t n) {
    // Find a prime p = k * 2n + 1
    uint64_t two_n = 2 * n;
    uint64_t base = (1ULL << (bits - 1)) / two_n;
    
    for (uint64_t k = base; k < base + 10000; ++k) {
        uint64_t candidate = k * two_n + 1;
        
        // Simple primality check
        if (candidate % 2 == 0) continue;
        bool is_prime = true;
        for (uint64_t d = 3; d * d <= candidate && is_prime; d += 2) {
            if (candidate % d == 0) is_prime = false;
        }
        if (is_prime) return candidate;
    }
    return 0;
}

/**
 * @brief Compute root of unity powers
 */
std::vector<uint64_t> compute_root_powers(size_t n, uint64_t modulus) {
    std::vector<uint64_t> powers(n);
    
    // Find primitive 2n-th root of unity
    uint64_t g = 3;  // Common generator for NTT primes
    uint64_t order = modulus - 1;
    uint64_t root = powmod_cpu(g, order / (2 * n), modulus);
    
    powers[0] = 1;
    for (size_t i = 1; i < n; ++i) {
        powers[i] = mulmod_cpu(powers[i-1], root, modulus);
    }
    
    return powers;
}

// ============================================================================
// Benchmark
// ============================================================================

void print_separator() {
    std::cout << std::string(70, '=') << "\n";
}

void benchmark_ntt(int log_n, int iterations) {
    size_t n = 1ULL << log_n;
    uint64_t modulus = generate_ntt_prime(50, n);
    
    std::cout << "\nBenchmark: NTT (n = " << n << ", modulus = " << modulus << ")\n";
    print_separator();
    
    // Generate random data
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, modulus - 1);
    
    std::vector<uint64_t> data(n);
    for (size_t i = 0; i < n; ++i) {
        data[i] = dist(rng);
    }
    
    // Compute root powers
    auto root_powers = compute_root_powers(n, modulus);
    
    // CPU Benchmark
    std::vector<uint64_t> cpu_data = data;
    auto cpu_start = Clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        cpu_data = data;  // Reset
        ntt_forward_cpu(cpu_data, modulus, root_powers, log_n);
    }
    auto cpu_end = Clock::now();
    double cpu_time = std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count();
    double cpu_per_iter = cpu_time / iterations;
    
    std::cout << "CPU NTT:  " << std::fixed << std::setprecision(3) 
              << cpu_per_iter << " ms/iter (" << iterations << " iterations)\n";
    
    // GPU Benchmark (if available)
    if (kctsb_cuda_runtime_available()) {
        char device_name[256];
        size_t total_mem;
        int major, minor;
        kctsb_cuda_get_device_info(0, device_name, 256, &total_mem, &major, &minor);
        std::cout << "GPU: " << device_name << " (SM " << major << "." << minor 
                  << ", " << (total_mem / 1024 / 1024) << " MB)\n";
        
        // Allocate GPU memory
        uint64_t* d_data = nullptr;
        uint64_t* d_root_powers = nullptr;
        uint64_t* d_root_powers_shoup = nullptr;
        
        kctsb_cuda_malloc((void**)&d_data, n * sizeof(uint64_t));
        kctsb_cuda_malloc((void**)&d_root_powers, n * sizeof(uint64_t));
        kctsb_cuda_malloc((void**)&d_root_powers_shoup, n * sizeof(uint64_t));
        
        // Upload root powers
        kctsb_cuda_memcpy_h2d(d_root_powers, root_powers.data(), n * sizeof(uint64_t));
        // Note: Shoup precomputation would be done here in production
        kctsb_cuda_memcpy_h2d(d_root_powers_shoup, root_powers.data(), n * sizeof(uint64_t));
        
        // Warmup
        kctsb_cuda_memcpy_h2d(d_data, data.data(), n * sizeof(uint64_t));
        kctsb_cuda_ntt_forward(d_data, d_root_powers, d_root_powers_shoup, modulus, log_n);
        
        // Benchmark
        auto gpu_start = Clock::now();
        for (int iter = 0; iter < iterations; ++iter) {
            kctsb_cuda_memcpy_h2d(d_data, data.data(), n * sizeof(uint64_t));
            kctsb_cuda_ntt_forward(d_data, d_root_powers, d_root_powers_shoup, modulus, log_n);
        }
        auto gpu_end = Clock::now();
        double gpu_time = std::chrono::duration<double, std::milli>(gpu_end - gpu_start).count();
        double gpu_per_iter = gpu_time / iterations;
        
        std::cout << "GPU NTT:  " << std::fixed << std::setprecision(3) 
                  << gpu_per_iter << " ms/iter (" << iterations << " iterations)\n";
        std::cout << "Speedup:  " << std::fixed << std::setprecision(2) 
                  << (cpu_per_iter / gpu_per_iter) << "x\n";
        
        // Cleanup
        kctsb_cuda_free(d_data);
        kctsb_cuda_free(d_root_powers);
        kctsb_cuda_free(d_root_powers_shoup);
    } else {
        std::cout << "GPU: Not available\n";
    }
}

void benchmark_poly_multiply(int log_n, int iterations) {
    size_t n = 1ULL << log_n;
    uint64_t modulus = generate_ntt_prime(50, n);
    uint64_t barrett_k = UINT64_MAX / modulus + 1;
    
    std::cout << "\nBenchmark: Polynomial Multiply (n = " << n << ")\n";
    print_separator();
    
    // Generate random polynomials
    std::mt19937_64 rng(123);
    std::uniform_int_distribution<uint64_t> dist(0, modulus - 1);
    
    std::vector<uint64_t> a(n), b(n), result(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    // CPU Benchmark (pointwise in NTT domain)
    auto cpu_start = Clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        for (size_t i = 0; i < n; ++i) {
            result[i] = mulmod_cpu(a[i], b[i], modulus);
        }
    }
    auto cpu_end = Clock::now();
    double cpu_time = std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count();
    double cpu_per_iter = cpu_time / iterations;
    
    std::cout << "CPU:      " << std::fixed << std::setprecision(3) 
              << cpu_per_iter << " ms/iter\n";
    
    // GPU Benchmark
    if (kctsb_cuda_runtime_available()) {
        uint64_t *d_a, *d_b, *d_result;
        kctsb_cuda_malloc((void**)&d_a, n * sizeof(uint64_t));
        kctsb_cuda_malloc((void**)&d_b, n * sizeof(uint64_t));
        kctsb_cuda_malloc((void**)&d_result, n * sizeof(uint64_t));
        
        kctsb_cuda_memcpy_h2d(d_a, a.data(), n * sizeof(uint64_t));
        kctsb_cuda_memcpy_h2d(d_b, b.data(), n * sizeof(uint64_t));
        
        // Warmup
        kctsb_cuda_poly_multiply(d_result, d_a, d_b, modulus, barrett_k, n);
        
        // Benchmark
        auto gpu_start = Clock::now();
        for (int iter = 0; iter < iterations; ++iter) {
            kctsb_cuda_poly_multiply(d_result, d_a, d_b, modulus, barrett_k, n);
        }
        auto gpu_end = Clock::now();
        double gpu_time = std::chrono::duration<double, std::milli>(gpu_end - gpu_start).count();
        double gpu_per_iter = gpu_time / iterations;
        
        std::cout << "GPU:      " << std::fixed << std::setprecision(3) 
                  << gpu_per_iter << " ms/iter\n";
        std::cout << "Speedup:  " << std::fixed << std::setprecision(2) 
                  << (cpu_per_iter / gpu_per_iter) << "x\n";
        
        kctsb_cuda_free(d_a);
        kctsb_cuda_free(d_b);
        kctsb_cuda_free(d_result);
    }
}

int main() {
    std::cout << "\n";
    print_separator();
    std::cout << "  kctsb CUDA NTT/PIR Benchmark\n";
    print_separator();
    
    // Check CUDA availability
    if (kctsb_cuda_runtime_available()) {
        char device_name[256];
        size_t total_mem;
        int major, minor;
        kctsb_cuda_get_device_info(0, device_name, 256, &total_mem, &major, &minor);
        std::cout << "\nCUDA Device: " << device_name << "\n";
        std::cout << "Compute Capability: SM " << major << "." << minor << "\n";
        std::cout << "Total Memory: " << (total_mem / 1024 / 1024) << " MB\n";
    } else {
        std::cout << "\nWARNING: CUDA not available, running CPU-only benchmarks\n";
    }
    
    // Run benchmarks for different sizes
    const int iterations = 100;
    
    // Small (n=4096)
    benchmark_ntt(12, iterations);
    benchmark_poly_multiply(12, iterations);
    
    // Medium (n=8192)
    benchmark_ntt(13, iterations);
    benchmark_poly_multiply(13, iterations);
    
    // Large (n=16384)
    benchmark_ntt(14, iterations);
    benchmark_poly_multiply(14, iterations);
    
    print_separator();
    std::cout << "Benchmark complete.\n\n";
    
    return 0;
}
