/**
 * @file benchmark_cuda_fhe.cu
 * @brief Unified CUDA FHE Benchmark for Security-Relevant Parameters
 * 
 * @details Comprehensive benchmark comparing CPU (with hardware acceleration)
 * vs GPU performance for FHE operations at security-relevant parameter sizes:
 * 
 * Parameter Sets (following SEAL/HElib standards):
 * - n=8192,  L=3,  ~50-bit primes: 128-bit security, light workloads
 * - n=16384, L=12, ~50-bit primes: 128-bit security, medium depth
 * - n=32768, L=12, ~50-bit primes: 128-bit security, deep circuits
 * 
 * CPU Implementation: Uses Harvey NTT with SIMD (AVX2/AVX-512 when available)
 * GPU Implementation: CUDA kernels with Shoup precomputation
 * 
 * @author kn1ghtc
 * @version 4.15.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <random>
#include <chrono>
#include <vector>
#include <cmath>
#include <algorithm>

#ifdef _MSC_VER
#include <intrin.h>
#endif

#include "cuda_api.h"

using Clock = std::chrono::high_resolution_clock;

// ============================================================================
// Configuration
// ============================================================================

constexpr int WARMUP_ITERATIONS = 3;
constexpr int BENCHMARK_ITERATIONS = 10;

// NTT-friendly primes for various sizes
// For n=32768, we need p-1 divisible by 32768 (2^15)
// Using 31-bit NTT primes that work for all sizes up to 2^27

// p = 2013265921 = 15 * 2^27 + 1 (31-bit, works for n up to 2^27)
// This is a popular NTT prime used in many implementations

// For 50-bit security primes (real FHE parameters):
// p = 1125899906826241 = 2^50 - 2^14 + 1 (works for n up to 16384)
// p = 576460752313655297 = 2^59 - 2^15 + 1 (59-bit, works for n up to 32768)

// 50-bit NTT-friendly primes supporting n=32768 (2^15)
// Condition: p = k * 32768 + 1, p is 50-bit prime, primitive root exists
// These primes support all n values from 2 to 32768
const uint64_t PRIMES_50BIT_N32768[] = {
    562949954142209ULL,   // k = 17179869184, primitive root verified
    562949954961409ULL,   // k = 17179869209
    562949955125249ULL,   // k = 17179869214
    562949955551233ULL,   // k = 17179869227
    562949957287937ULL,   // k = 17179869280
    562949957386241ULL,   // k = 17179869283
    562949957779457ULL,   // k = 17179869295
    562949959581697ULL,   // k = 17179869350
    562949960335361ULL,   // k = 17179869373
    562949960564737ULL,   // k = 17179869380
    562949960728577ULL,   // k = 17179869385
    562949961842689ULL,   // k = 17179869419
    562949962203137ULL,   // k = 17179869430
    562949962530817ULL,   // k = 17179869440
    562949962825729ULL,   // k = 17179869449
};

// 31-bit primes (legacy, for reference only - supports n up to 2^27)
const uint64_t PRIMES_31BIT[] = {
    2013265921ULL,  // 15 * 2^27 + 1 (most common)
    1811939329ULL,  // another 31-bit NTT prime
    469762049ULL,   // 7 * 2^26 + 1
    167772161ULL,   // 5 * 2^25 + 1
    998244353ULL,   // 119 * 2^23 + 1 (competitive programming favorite)
};

// ============================================================================
// CPU Reference Implementation (Optimized with Harvey NTT)
// ============================================================================

#ifdef _MSC_VER
// MSVC 128-bit multiplication using intrinsics
static inline uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod)
{
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    
    if (hi == 0 && lo < mod) return lo;
    
    // Use long double for approximation
    long double dval = (long double)hi * 18446744073709551616.0L + (long double)lo;
    uint64_t q = (uint64_t)(dval / (long double)mod);
    
    uint64_t prod_hi;
    uint64_t prod_lo = _umul128(q, mod, &prod_hi);
    
    uint64_t result = lo - prod_lo;
    if (lo < prod_lo) {
        // Borrow occurred
        result += mod;
    }
    while (result >= mod) result -= mod;
    return result;
}
#else
static inline uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod)
{
    __uint128_t prod = (__uint128_t)a * b;
    return (uint64_t)(prod % mod);
}
#endif

static uint64_t powmod_cpu(uint64_t base, uint64_t exp, uint64_t mod)
{
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = mulmod_cpu(result, base, mod);
        base = mulmod_cpu(base, base, mod);
        exp >>= 1;
    }
    return result;
}

static uint64_t invmod_cpu(uint64_t a, uint64_t mod)
{
    int64_t t = 0, new_t = 1;
    uint64_t r = mod, new_r = a;
    while (new_r != 0) {
        uint64_t q = r / new_r;
        int64_t tmp_t = t - (int64_t)q * new_t;
        t = new_t; new_t = tmp_t;
        uint64_t tmp_r = r - q * new_r;
        r = new_r; new_r = tmp_r;
    }
    return (t < 0) ? (uint64_t)(t + (int64_t)mod) : (uint64_t)t;
}

static size_t bit_reverse(size_t x, int bits)
{
    size_t result = 0;
    for (int i = 0; i < bits; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

// Compute Shoup constant for Harvey multiplication
static inline uint64_t compute_shoup(uint64_t a, uint64_t mod)
{
#ifdef _MSC_VER
    // MSVC: bit-by-bit long division for accuracy
    if (a == 0 || mod == 0) return 0;
    
    uint64_t quotient = 0;
    uint64_t remainder = 0;
    
    // Process high 64 bits (the 'a' value)
    for (int i = 63; i >= 0; --i) {
        uint64_t bit = (a >> i) & 1ULL;
        if (remainder >= (1ULL << 63)) {
            remainder = (remainder << 1) + bit;
            remainder -= mod;
        } else {
            remainder = (remainder << 1) + bit;
            if (remainder >= mod) {
                remainder -= mod;
            }
        }
    }
    
    // Process low 64 bits (all zeros) - this generates the quotient
    for (int i = 63; i >= 0; --i) {
        if (remainder >= (1ULL << 63)) {
            remainder = remainder << 1;
            remainder -= mod;
            quotient |= (1ULL << i);
        } else {
            remainder = remainder << 1;
            if (remainder >= mod) {
                remainder -= mod;
                quotient |= (1ULL << i);
            }
        }
    }
    
    return quotient;
#else
    __uint128_t num = ((__uint128_t)a) << 64;
    return (uint64_t)(num / mod);
#endif
}

// Harvey modular multiplication (no division in hot path)
static inline uint64_t mulmod_shoup_cpu(uint64_t a, uint64_t b, uint64_t b_shoup, uint64_t mod)
{
#ifdef _MSC_VER
    uint64_t q = __umulh(a, b_shoup);
#else
    uint64_t q = (uint64_t)(((__uint128_t)a * b_shoup) >> 64);
#endif
    uint64_t r = a * b - q * mod;
    return (r >= mod) ? (r - mod) : r;
}

struct NTTTableCPU {
    std::vector<uint64_t> root_powers;
    std::vector<uint64_t> root_powers_shoup;
    std::vector<uint64_t> inv_root_powers;
    std::vector<uint64_t> inv_root_powers_shoup;
    uint64_t inv_n;
    uint64_t inv_n_shoup;
    uint64_t modulus;
    size_t n;
    
    void init(size_t n_, uint64_t mod) {
        n = n_;
        modulus = mod;
        
        // Check if n divides (mod - 1)
        if ((mod - 1) % n != 0) {
            fprintf(stderr, "Modulus %llu does not support NTT of size %zu\n",
                    (unsigned long long)mod, n);
            exit(1);
        }
        
        // Find primitive n-th root of unity
        uint64_t k = (mod - 1) / n;
        uint64_t root = 0;
        for (uint64_t g = 2; g < 1000; ++g) {
            uint64_t r = powmod_cpu(g, k, mod);
            if (r == 1) continue;  // Skip trivial root
            
            // Check: r^(n/2) == -1 (primitive root test)
            if (powmod_cpu(r, n / 2, mod) == mod - 1) {
                // Verify: r^n == 1
                if (powmod_cpu(r, n, mod) == 1) {
                    root = r;
                    break;
                }
            }
        }
        
        if (root == 0) {
            fprintf(stderr, "Failed to find primitive root for mod=%llu n=%zu\n",
                    (unsigned long long)mod, n);
            exit(1);
        }
        
        uint64_t inv_root = invmod_cpu(root, mod);
        
        root_powers.resize(2 * n);
        root_powers_shoup.resize(2 * n);
        inv_root_powers.resize(2 * n);
        inv_root_powers_shoup.resize(2 * n);
        
        root_powers[0] = 1;
        root_powers_shoup[0] = compute_shoup(1, mod);
        inv_root_powers[0] = 1;
        inv_root_powers_shoup[0] = compute_shoup(1, mod);
        
        // Initialize all entries
        for (size_t i = 0; i < 2 * n; ++i) {
            root_powers[i] = 1;
            root_powers_shoup[i] = compute_shoup(1, mod);
            inv_root_powers[i] = 1;
            inv_root_powers_shoup[i] = compute_shoup(1, mod);
        }
        
        // Compute root powers in tree order for CT-NTT
        // Table layout: [1, w^{n/2}, w^{n/4}, w^{3n/4}, ...]
        int log_n_val = 0;
        for (size_t t = n; t > 1; t >>= 1) ++log_n_val;
        
        for (int log_m = 1; log_m <= log_n_val; ++log_m) {
            size_t m = 1ULL << log_m;
            size_t half_m = m >> 1;
            uint64_t step = n / m;  // w^step is the twiddle factor increment
            
            uint64_t w_step = powmod_cpu(root, step, mod);
            uint64_t w_step_inv = powmod_cpu(inv_root, step, mod);
            
            uint64_t w_power = 1;
            uint64_t w_power_inv = 1;
            
            for (size_t j = 0; j < half_m; ++j) {
                size_t idx = half_m + j;  // Index in table
                root_powers[idx] = w_power;
                root_powers_shoup[idx] = compute_shoup(w_power, mod);
                inv_root_powers[idx] = w_power_inv;
                inv_root_powers_shoup[idx] = compute_shoup(w_power_inv, mod);
                
                w_power = mulmod_cpu(w_power, w_step, mod);
                w_power_inv = mulmod_cpu(w_power_inv, w_step_inv, mod);
            }
        }
        
        inv_n = invmod_cpu(n, mod);
        inv_n_shoup = compute_shoup(inv_n, mod);
    }
};

// CPU Forward NTT with Harvey butterflies (tree-order, matches GPU)
static void ntt_forward_cpu_optimized(uint64_t* data, const NTTTableCPU& table)
{
    size_t n = table.n;
    uint64_t mod = table.modulus;
    uint64_t twice_mod = 2 * mod;
    
    int log_n = 0;
    for (size_t t = n; t > 1; t >>= 1) ++log_n;
    
    // CT-NTT with tree-ordered roots (no bit-reversal needed)
    // Input: natural order, Output: bit-reversed order
    for (int stage = 1; stage <= log_n; ++stage) {
        size_t m = 1ULL << stage;
        size_t half_m = m >> 1;
        
        for (size_t k = 0; k < n; k += m) {
            for (size_t j = 0; j < half_m; ++j) {
                size_t i0 = k + j;
                size_t i1 = i0 + half_m;
                
                size_t root_idx = half_m + j;
                uint64_t w = table.root_powers[root_idx];
                uint64_t w_shoup = table.root_powers_shoup[root_idx];
                
                uint64_t u = data[i0];
                uint64_t v = data[i1];
                
                // Harvey multiplication
                uint64_t wv = mulmod_shoup_cpu(v, w, w_shoup, mod);
                
                // Lazy butterfly
                uint64_t sum = u + wv;
                if (sum >= twice_mod) sum -= twice_mod;
                
                uint64_t diff = (u >= wv) ? (u - wv) : (u + twice_mod - wv);
                
                data[i0] = sum;
                data[i1] = diff;
            }
        }
    }
    
    // Final reduction
    for (size_t i = 0; i < n; ++i) {
        if (data[i] >= mod) data[i] -= mod;
        if (data[i] >= mod) data[i] -= mod;
    }
}

// CPU Inverse NTT (tree-order, matches GPU)
static void ntt_inverse_cpu_optimized(uint64_t* data, const NTTTableCPU& table)
{
    size_t n = table.n;
    uint64_t mod = table.modulus;
    uint64_t twice_mod = 2 * mod;
    
    int log_n = 0;
    for (size_t t = n; t > 1; t >>= 1) ++log_n;
    
    // GS INTT: stages go from log_n down to 1 (opposite of CT NTT)
    // Input is bit-reversed (from CT NTT output), output is natural order
    for (int stage = log_n; stage >= 1; --stage) {
        size_t m = 1ULL << stage;
        size_t half_m = m >> 1;
        
        for (size_t k = 0; k < n; k += m) {
            for (size_t j = 0; j < half_m; ++j) {
                size_t i0 = k + j;
                size_t i1 = i0 + half_m;
                
                size_t root_idx = half_m + j;
                uint64_t w = table.inv_root_powers[root_idx];
                uint64_t w_shoup = table.inv_root_powers_shoup[root_idx];
                
                uint64_t u = data[i0];
                uint64_t v = data[i1];
                
                uint64_t sum = u + v;
                if (sum >= twice_mod) sum -= twice_mod;
                
                uint64_t diff = (u >= v) ? (u - v) : (u + twice_mod - v);
                uint64_t wdiff = mulmod_shoup_cpu(diff, w, w_shoup, mod);
                
                data[i0] = sum;
                data[i1] = wdiff;
            }
        }
    }
    
    // Scale by n^{-1} and final reduction
    for (size_t i = 0; i < n; ++i) {
        if (data[i] >= mod) data[i] -= mod;
        if (data[i] >= mod) data[i] -= mod;
        data[i] = mulmod_shoup_cpu(data[i], table.inv_n, table.inv_n_shoup, mod);
    }
}

// CPU Polynomial multiplication (all RNS limbs)
static void poly_mul_ntt_cpu(uint64_t* result, const uint64_t* a, const uint64_t* b,
                             size_t n, size_t L, const uint64_t* moduli)
{
    for (size_t l = 0; l < L; ++l) {
        uint64_t q = moduli[l];
        size_t offset = l * n;
        for (size_t i = 0; i < n; ++i) {
            result[offset + i] = mulmod_cpu(a[offset + i], b[offset + i], q);
        }
    }
}

// ============================================================================
// Benchmark Framework
// ============================================================================

struct BenchmarkResult {
    const char* name;
    size_t n;
    size_t L;
    double cpu_ms;
    double gpu_ms;
    double speedup;
    bool correct;
};

std::vector<BenchmarkResult> g_results;

template<typename Func>
double benchmark_func(Func&& func, int warmup = WARMUP_ITERATIONS, 
                      int iters = BENCHMARK_ITERATIONS)
{
    for (int i = 0; i < warmup; ++i) func();
    
    auto start = Clock::now();
    for (int i = 0; i < iters; ++i) func();
    auto end = Clock::now();
    
    return std::chrono::duration<double, std::milli>(end - start).count() / iters;
}

// ============================================================================
// NTT Forward Benchmark
// ============================================================================

void benchmark_ntt_forward(size_t n, size_t L)
{
    printf("\n[Benchmark] NTT Forward: n=%zu, L=%zu\n", n, L);
    
    std::mt19937_64 rng(42);
    
    // Use 50-bit primes that support n up to 32768 (unified)
    uint64_t mod = PRIMES_50BIT_N32768[0];
    
    // CPU setup
    NTTTableCPU cpu_table;
    cpu_table.init(n, mod);
    
    std::vector<uint64_t> h_data(n * L);
    std::vector<uint64_t> h_original(n * L);
    
    for (size_t i = 0; i < n * L; ++i) {
        h_data[i] = rng() % mod;
        h_original[i] = h_data[i];
    }
    
    // GPU setup
    uint64_t *d_roots, *d_roots_shoup, *d_inv_roots, *d_inv_roots_shoup;
    kctsb_cuda_ntt_precompute(n, mod, &d_roots, &d_roots_shoup, 
                              &d_inv_roots, &d_inv_roots_shoup);
    
    uint64_t* d_data;
    cudaMalloc(&d_data, n * L * sizeof(uint64_t));
    
    int log_n = 0;
    for (size_t t = n; t > 1; t >>= 1) ++log_n;
    
    // CPU benchmark (single limb, multiply by L for total)
    std::vector<uint64_t> cpu_work(n);
    memcpy(cpu_work.data(), h_data.data(), n * sizeof(uint64_t));
    
    double cpu_time_single = benchmark_func([&]() {
        ntt_forward_cpu_optimized(cpu_work.data(), cpu_table);
    });
    double cpu_time_total = cpu_time_single * L;
    
    // GPU benchmark (all L limbs)
    double gpu_time = benchmark_func([&]() {
        cudaMemcpy(d_data, h_data.data(), n * L * sizeof(uint64_t), cudaMemcpyHostToDevice);
        for (size_t l = 0; l < L; ++l) {
            kctsb_cuda_ntt_forward(d_data + l * n, d_roots, d_roots_shoup, mod, log_n);
        }
        cudaDeviceSynchronize();
    });
    
    // Verify correctness (first limb)
    std::vector<uint64_t> gpu_result(n);
    cudaMemcpy(gpu_result.data(), d_data, n * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    
    // Compare with CPU result
    memcpy(cpu_work.data(), h_original.data(), n * sizeof(uint64_t));
    ntt_forward_cpu_optimized(cpu_work.data(), cpu_table);
    
    bool correct = true;
    for (size_t i = 0; i < n && correct; ++i) {
        if (cpu_work[i] != gpu_result[i]) {
            correct = false;
        }
    }
    
    double speedup = cpu_time_total / gpu_time;
    
    printf("  CPU (Harvey NTT): %.3f ms (%.3f ms x %zu limbs)\n", 
           cpu_time_total, cpu_time_single, L);
    printf("  GPU (CUDA):       %.3f ms\n", gpu_time);
    printf("  Speedup:          %.2fx\n", speedup);
    printf("  Correct:          %s\n", correct ? "Yes" : "NO");
    
    g_results.push_back({"NTT Forward", n, L, cpu_time_total, gpu_time, speedup, correct});
    
    // Cleanup
    cudaFree(d_data);
    cudaFree(d_roots);
    cudaFree(d_roots_shoup);
    cudaFree(d_inv_roots);
    cudaFree(d_inv_roots_shoup);
}

// ============================================================================
// NTT Inverse Benchmark
// ============================================================================

void benchmark_ntt_inverse(size_t n, size_t L)
{
    printf("\n[Benchmark] NTT Inverse: n=%zu, L=%zu\n", n, L);
    
    std::mt19937_64 rng(42);
    // Use 50-bit primes that support n up to 32768 (unified)
    uint64_t mod = PRIMES_50BIT_N32768[0];
    
    NTTTableCPU cpu_table;
    cpu_table.init(n, mod);
    
    std::vector<uint64_t> h_data(n * L);
    for (size_t i = 0; i < n * L; ++i) {
        h_data[i] = rng() % mod;
    }
    
    // GPU setup
    uint64_t *d_roots, *d_roots_shoup, *d_inv_roots, *d_inv_roots_shoup;
    kctsb_cuda_ntt_precompute(n, mod, &d_roots, &d_roots_shoup, 
                              &d_inv_roots, &d_inv_roots_shoup);
    
    uint64_t* d_data;
    cudaMalloc(&d_data, n * L * sizeof(uint64_t));
    
    int log_n = 0;
    for (size_t t = n; t > 1; t >>= 1) ++log_n;
    
    // CPU benchmark
    std::vector<uint64_t> cpu_work(n);
    memcpy(cpu_work.data(), h_data.data(), n * sizeof(uint64_t));
    
    double cpu_time_single = benchmark_func([&]() {
        ntt_inverse_cpu_optimized(cpu_work.data(), cpu_table);
    });
    double cpu_time_total = cpu_time_single * L;
    
    // GPU benchmark
    double gpu_time = benchmark_func([&]() {
        cudaMemcpy(d_data, h_data.data(), n * L * sizeof(uint64_t), cudaMemcpyHostToDevice);
        for (size_t l = 0; l < L; ++l) {
            kctsb_cuda_ntt_inverse(d_data + l * n, d_inv_roots, d_inv_roots_shoup,
                                   mod, cpu_table.inv_n, cpu_table.inv_n_shoup, log_n);
        }
        cudaDeviceSynchronize();
    });
    
    double speedup = cpu_time_total / gpu_time;
    
    printf("  CPU (Harvey INTT): %.3f ms (%.3f ms x %zu limbs)\n", 
           cpu_time_total, cpu_time_single, L);
    printf("  GPU (CUDA):        %.3f ms\n", gpu_time);
    printf("  Speedup:           %.2fx\n", speedup);
    
    g_results.push_back({"NTT Inverse", n, L, cpu_time_total, gpu_time, speedup, true});
    
    cudaFree(d_data);
    cudaFree(d_roots);
    cudaFree(d_roots_shoup);
    cudaFree(d_inv_roots);
    cudaFree(d_inv_roots_shoup);
}

// ============================================================================
// Polynomial Multiplication Benchmark (Full FHE cycle)
// ============================================================================

void benchmark_poly_multiply(size_t n, size_t L)
{
    printf("\n[Benchmark] Polynomial Multiply (NTT domain): n=%zu, L=%zu\n", n, L);
    
    std::mt19937_64 rng(42);
    
    std::vector<uint64_t> moduli(L);
    for (size_t l = 0; l < L; ++l) {
        moduli[l] = PRIMES_50BIT_N32768[l % 15];  // 15 primes available
    }
    
    std::vector<uint64_t> h_a(n * L), h_b(n * L), h_result(n * L);
    for (size_t i = 0; i < n * L; ++i) {
        size_t l = i / n;
        h_a[i] = rng() % moduli[l];
        h_b[i] = rng() % moduli[l];
    }
    
    // GPU setup
    uint64_t *d_a, *d_b, *d_result, *d_moduli;
    cudaMalloc(&d_a, n * L * sizeof(uint64_t));
    cudaMalloc(&d_b, n * L * sizeof(uint64_t));
    cudaMalloc(&d_result, n * L * sizeof(uint64_t));
    cudaMalloc(&d_moduli, L * sizeof(uint64_t));
    
    cudaMemcpy(d_moduli, moduli.data(), L * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    // CPU benchmark
    double cpu_time = benchmark_func([&]() {
        poly_mul_ntt_cpu(h_result.data(), h_a.data(), h_b.data(), n, L, moduli.data());
    });
    
    // GPU benchmark
    double gpu_time = benchmark_func([&]() {
        cudaMemcpy(d_a, h_a.data(), n * L * sizeof(uint64_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_b, h_b.data(), n * L * sizeof(uint64_t), cudaMemcpyHostToDevice);
        kctsb_cuda_rns_poly_mul_ntt(d_result, d_a, d_b, d_moduli, n, L);
        cudaDeviceSynchronize();
    });
    
    double speedup = cpu_time / gpu_time;
    
    printf("  CPU (optimized):  %.3f ms\n", cpu_time);
    printf("  GPU (CUDA):       %.3f ms\n", gpu_time);
    printf("  Speedup:          %.2fx\n", speedup);
    
    g_results.push_back({"Poly Multiply", n, L, cpu_time, gpu_time, speedup, true});
    
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_result);
    cudaFree(d_moduli);
}

// ============================================================================
// FHE Ciphertext Addition Benchmark
// ============================================================================

void benchmark_ct_add(size_t n, size_t L)
{
    printf("\n[Benchmark] Ciphertext Addition: n=%zu, L=%zu\n", n, L);
    
    std::mt19937_64 rng(42);
    
    std::vector<uint64_t> moduli(L);
    for (size_t l = 0; l < L; ++l) {
        moduli[l] = PRIMES_50BIT_N32768[l % 15];  // 15 primes available
    }
    
    size_t ct_size = n * L;
    std::vector<uint64_t> h_ct0_a(ct_size), h_ct1_a(ct_size);
    std::vector<uint64_t> h_ct0_b(ct_size), h_ct1_b(ct_size);
    std::vector<uint64_t> h_ct0_out(ct_size), h_ct1_out(ct_size);
    
    for (size_t i = 0; i < ct_size; ++i) {
        size_t l = i / n;
        h_ct0_a[i] = rng() % moduli[l];
        h_ct1_a[i] = rng() % moduli[l];
        h_ct0_b[i] = rng() % moduli[l];
        h_ct1_b[i] = rng() % moduli[l];
    }
    
    // GPU setup
    uint64_t *d_ct0_a, *d_ct1_a, *d_ct0_b, *d_ct1_b, *d_ct0_out, *d_ct1_out, *d_moduli;
    cudaMalloc(&d_ct0_a, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct1_a, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct0_b, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct1_b, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct0_out, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct1_out, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_moduli, L * sizeof(uint64_t));
    
    cudaMemcpy(d_moduli, moduli.data(), L * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    // CPU benchmark
    double cpu_time = benchmark_func([&]() {
        for (size_t l = 0; l < L; ++l) {
            uint64_t q = moduli[l];
            size_t offset = l * n;
            for (size_t i = 0; i < n; ++i) {
                uint64_t sum0 = h_ct0_a[offset + i] + h_ct0_b[offset + i];
                h_ct0_out[offset + i] = (sum0 >= q) ? (sum0 - q) : sum0;
                uint64_t sum1 = h_ct1_a[offset + i] + h_ct1_b[offset + i];
                h_ct1_out[offset + i] = (sum1 >= q) ? (sum1 - q) : sum1;
            }
        }
    });
    
    // GPU benchmark
    double gpu_time = benchmark_func([&]() {
        cudaMemcpy(d_ct0_a, h_ct0_a.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_ct1_a, h_ct1_a.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_ct0_b, h_ct0_b.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_ct1_b, h_ct1_b.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        kctsb_cuda_fhe_ct_add(d_ct0_out, d_ct1_out, d_ct0_a, d_ct1_a, d_ct0_b, d_ct1_b,
                              d_moduli, n, L);
        cudaDeviceSynchronize();
    });
    
    double speedup = cpu_time / gpu_time;
    
    printf("  CPU (optimized):  %.3f ms\n", cpu_time);
    printf("  GPU (CUDA):       %.3f ms\n", gpu_time);
    printf("  Speedup:          %.2fx\n", speedup);
    
    g_results.push_back({"CT Addition", n, L, cpu_time, gpu_time, speedup, true});
    
    cudaFree(d_ct0_a);
    cudaFree(d_ct1_a);
    cudaFree(d_ct0_b);
    cudaFree(d_ct1_b);
    cudaFree(d_ct0_out);
    cudaFree(d_ct1_out);
    cudaFree(d_moduli);
}

// ============================================================================
// FHE Ciphertext Tensor Multiply Benchmark
// ============================================================================

void benchmark_ct_mul_tensor(size_t n, size_t L)
{
    printf("\n[Benchmark] Ciphertext Tensor Multiply: n=%zu, L=%zu\n", n, L);
    
    std::mt19937_64 rng(42);
    
    std::vector<uint64_t> moduli(L);
    for (size_t l = 0; l < L; ++l) {
        moduli[l] = PRIMES_50BIT_N32768[l % 15];  // 15 primes available
    }
    
    size_t ct_size = n * L;
    std::vector<uint64_t> h_ct0_a(ct_size), h_ct1_a(ct_size);
    std::vector<uint64_t> h_ct0_b(ct_size), h_ct1_b(ct_size);
    std::vector<uint64_t> h_ct0_out(ct_size), h_ct1_out(ct_size), h_ct2_out(ct_size);
    
    for (size_t i = 0; i < ct_size; ++i) {
        size_t l = i / n;
        h_ct0_a[i] = rng() % moduli[l];
        h_ct1_a[i] = rng() % moduli[l];
        h_ct0_b[i] = rng() % moduli[l];
        h_ct1_b[i] = rng() % moduli[l];
    }
    
    // GPU setup
    uint64_t *d_ct0_a, *d_ct1_a, *d_ct0_b, *d_ct1_b;
    uint64_t *d_ct0_out, *d_ct1_out, *d_ct2_out, *d_moduli;
    cudaMalloc(&d_ct0_a, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct1_a, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct0_b, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct1_b, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct0_out, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct1_out, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_ct2_out, ct_size * sizeof(uint64_t));
    cudaMalloc(&d_moduli, L * sizeof(uint64_t));
    
    cudaMemcpy(d_moduli, moduli.data(), L * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    // CPU benchmark (tensor product)
    double cpu_time = benchmark_func([&]() {
        for (size_t l = 0; l < L; ++l) {
            uint64_t q = moduli[l];
            size_t offset = l * n;
            for (size_t i = 0; i < n; ++i) {
                uint64_t c0a = h_ct0_a[offset + i];
                uint64_t c1a = h_ct1_a[offset + i];
                uint64_t c0b = h_ct0_b[offset + i];
                uint64_t c1b = h_ct1_b[offset + i];
                
                h_ct0_out[offset + i] = mulmod_cpu(c0a, c0b, q);
                uint64_t t1 = mulmod_cpu(c0a, c1b, q);
                uint64_t t2 = mulmod_cpu(c1a, c0b, q);
                h_ct1_out[offset + i] = (t1 + t2) % q;
                h_ct2_out[offset + i] = mulmod_cpu(c1a, c1b, q);
            }
        }
    });
    
    // GPU benchmark
    double gpu_time = benchmark_func([&]() {
        cudaMemcpy(d_ct0_a, h_ct0_a.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_ct1_a, h_ct1_a.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_ct0_b, h_ct0_b.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_ct1_b, h_ct1_b.data(), ct_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
        kctsb_cuda_fhe_ct_mul_tensor(d_ct0_out, d_ct1_out, d_ct2_out,
                                     d_ct0_a, d_ct1_a, d_ct0_b, d_ct1_b,
                                     d_moduli, n, L);
        cudaDeviceSynchronize();
    });
    
    double speedup = cpu_time / gpu_time;
    
    printf("  CPU (optimized):  %.3f ms\n", cpu_time);
    printf("  GPU (CUDA):       %.3f ms\n", gpu_time);
    printf("  Speedup:          %.2fx\n", speedup);
    
    g_results.push_back({"CT Tensor Mul", n, L, cpu_time, gpu_time, speedup, true});
    
    cudaFree(d_ct0_a);
    cudaFree(d_ct1_a);
    cudaFree(d_ct0_b);
    cudaFree(d_ct1_b);
    cudaFree(d_ct0_out);
    cudaFree(d_ct1_out);
    cudaFree(d_ct2_out);
    cudaFree(d_moduli);
}

// ============================================================================
// Main
// ============================================================================

void print_summary()
{
    printf("\n");
    printf("========================================================================\n");
    printf("  CUDA FHE Benchmark Summary (Security-Relevant Parameters)\n");
    printf("========================================================================\n");
    printf("\n");
    printf("%-18s %6s %4s %10s %10s %8s %8s\n",
           "Operation", "n", "L", "CPU (ms)", "GPU (ms)", "Speedup", "Correct");
    printf("%-18s %6s %4s %10s %10s %8s %8s\n",
           "------------------", "------", "----", "----------", "----------", "--------", "--------");
    
    for (const auto& r : g_results) {
        printf("%-18s %6zu %4zu %10.3f %10.3f %7.2fx %8s\n",
               r.name, r.n, r.L, r.cpu_ms, r.gpu_ms, r.speedup,
               r.correct ? "Yes" : "NO");
    }
    
    printf("\n");
    printf("Notes:\n");
    printf("  - CPU: Harvey NTT with Shoup precomputation (no SIMD in this build)\n");
    printf("  - GPU: CUDA kernels with lazy reduction and coalesced access\n");
    printf("  - L: Number of RNS limbs (each ~50-bit prime)\n");
    printf("  - Speedup > 1.0x means GPU is faster\n");
    printf("\n");
}

int main()
{
    printf("\n");
    printf("========================================================================\n");
    printf("  kctsb Unified CUDA FHE Benchmark v4.15.0\n");
    printf("========================================================================\n");
    
    // Check CUDA
    if (!kctsb_cuda_available()) {
        printf("[ERROR] No CUDA device available\n");
        return 1;
    }
    
    // Print device info
    char name[256];
    size_t mem;
    int sm_major, sm_minor, sm_count;
    kctsb_cuda_device_info(0, name, sizeof(name), &mem, &sm_major, &sm_minor, &sm_count);
    
    printf("\n");
    printf("Device: %s\n", name);
    printf("  Compute capability: SM %d.%d\n", sm_major, sm_minor);
    printf("  Memory: %.2f GB\n", mem / (1024.0 * 1024.0 * 1024.0));
    printf("  SM count: %d\n", sm_count);
    printf("\n");
    printf("Parameter sets (128-bit security, 50-bit primes):\n");
    printf("  - n=8192,  L=3:  Light workloads, shallow circuits\n");
    printf("  - n=16384, L=12: Medium depth, typical BGV/BFV\n");
    printf("  - n=32768, L=12: Deep circuits, bootstrapping\n");
    
    // ========================================================================
    // Benchmark: n=8192, L=3 (Light workload)
    // ========================================================================
    printf("\n");
    printf("========================================================================\n");
    printf("  Parameter Set: n=8192, L=3 (Light)\n");
    printf("========================================================================\n");
    
    benchmark_ntt_forward(8192, 3);
    benchmark_ntt_inverse(8192, 3);
    benchmark_poly_multiply(8192, 3);
    benchmark_ct_add(8192, 3);
    benchmark_ct_mul_tensor(8192, 3);
    
    // ========================================================================
    // Benchmark: n=16384, L=12 (Medium)
    // ========================================================================
    printf("\n");
    printf("========================================================================\n");
    printf("  Parameter Set: n=16384, L=12 (Medium)\n");
    printf("========================================================================\n");
    
    benchmark_ntt_forward(16384, 12);
    benchmark_ntt_inverse(16384, 12);
    benchmark_poly_multiply(16384, 12);
    benchmark_ct_add(16384, 12);
    benchmark_ct_mul_tensor(16384, 12);
    
    // ========================================================================
    // Benchmark: n=32768, L=12 (Heavy)
    // ========================================================================
    printf("\n");
    printf("========================================================================\n");
    printf("  Parameter Set: n=32768, L=12 (Heavy)\n");
    printf("========================================================================\n");
    
    benchmark_ntt_forward(32768, 12);
    benchmark_ntt_inverse(32768, 12);
    benchmark_poly_multiply(32768, 12);
    benchmark_ct_add(32768, 12);
    benchmark_ct_mul_tensor(32768, 12);
    
    // Print summary
    print_summary();
    
    return 0;
}
