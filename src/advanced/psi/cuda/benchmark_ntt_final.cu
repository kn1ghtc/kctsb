/**
 * @file benchmark_ntt_final.cu
 * @brief Final GPU NTT Benchmark with verified modular arithmetic
 * 
 * Uses a 50-bit NTT-friendly prime for reliable modular operations
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-26
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <chrono>
#include <vector>
#include <random>
#include <algorithm>

#ifdef _MSC_VER
#include <intrin.h>
#endif

using Clock = std::chrono::high_resolution_clock;

// ============================================================================
// NTT Prime Configuration
// ============================================================================

// 50-bit NTT-friendly prime: p = k * 2^n + 1 where n >= 20
// p = 1125899906842679 = 4473 * 2^48 + 1 (supports NTT up to n = 2^48)
// Actually, let's use: p = 1099511627521 = 2^40 - 2^31 + 1 (40-bit, simpler)
// Even simpler: p = 4610415792919313 = 17 * 2^48 + 1 (48-bit, NTT-friendly)

// Use a well-known small NTT prime for testing
constexpr uint64_t NTT_PRIME = 998244353ULL;  // 2^23 * 7 * 17 + 1, supports n up to 2^23
constexpr int MAX_LOG_N = 23;

// ============================================================================
// GPU Modular Arithmetic
// ============================================================================

__device__ __forceinline__ uint64_t mulmod_gpu(uint64_t a, uint64_t b, uint64_t mod) {
    // For 30-bit prime, product fits in 60 bits, can use simple modulo
    uint64_t lo, hi;
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));
    
    if (hi == 0) {
        return lo % mod;
    }
    
    // 128-bit mod using double approximation
    double dhi = static_cast<double>(hi);
    double dlo = static_cast<double>(lo);
    double dmod = static_cast<double>(mod);
    double dval = dhi * 18446744073709551616.0 + dlo;
    uint64_t q = static_cast<uint64_t>(dval / dmod);
    
    uint64_t r = lo - q * mod;
    while (r >= mod) r -= mod;
    
    return r;
}

__device__ __forceinline__ uint64_t addmod_gpu(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t sum = a + b;
    return (sum >= mod) ? (sum - mod) : sum;
}

__device__ __forceinline__ uint64_t submod_gpu(uint64_t a, uint64_t b, uint64_t mod) {
    return (a >= b) ? (a - b) : (mod + a - b);
}

// ============================================================================
// GPU NTT Kernels
// ============================================================================

__global__ void bit_reverse_kernel(uint64_t* data, int log_n) {
    size_t n = 1ULL << log_n;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx >= n) return;
    
    size_t rev = 0;
    size_t temp = idx;
    for (int i = 0; i < log_n; ++i) {
        rev = (rev << 1) | (temp & 1);
        temp >>= 1;
    }
    
    if (idx < rev) {
        uint64_t tmp = data[idx];
        data[idx] = data[rev];
        data[rev] = tmp;
    }
}

__global__ void ntt_butterfly_kernel(
    uint64_t* data,
    const uint64_t* twiddles,
    uint64_t mod,
    int log_n,
    int stage)
{
    size_t n = 1ULL << log_n;
    size_t m = 1ULL << stage;
    size_t half_m = m >> 1;
    
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    size_t total = n >> 1;
    
    if (tid >= total) return;
    
    size_t group = tid / half_m;
    size_t j = tid % half_m;
    size_t i0 = group * m + j;
    size_t i1 = i0 + half_m;
    
    size_t twiddle_idx = j << (log_n - stage);
    uint64_t w = twiddles[twiddle_idx];
    
    uint64_t u = data[i0];
    uint64_t v = data[i1];
    uint64_t t = mulmod_gpu(v, w, mod);
    
    data[i0] = addmod_gpu(u, t, mod);
    data[i1] = submod_gpu(u, t, mod);
}

__global__ void poly_mul_kernel(
    uint64_t* result,
    const uint64_t* a,
    const uint64_t* b,
    uint64_t mod,
    size_t n)
{
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    result[idx] = mulmod_gpu(a[idx], b[idx], mod);
}

// ============================================================================
// CPU Reference Implementation
// ============================================================================

#ifdef _MSC_VER
inline uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    
    if (hi == 0) return lo % mod;
    
    long double dval = static_cast<long double>(hi) * 18446744073709551616.0L + static_cast<long double>(lo);
    uint64_t q = static_cast<uint64_t>(dval / static_cast<long double>(mod));
    
    uint64_t prod_hi;
    uint64_t prod_lo = _umul128(q, mod, &prod_hi);
    
    uint64_t result = lo - prod_lo;
    if (lo < prod_lo) result += mod;  // Borrow correction
    while (result >= mod) result -= mod;
    
    return result;
}
#else
inline uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod) {
    unsigned __int128 product = static_cast<unsigned __int128>(a) * b;
    return static_cast<uint64_t>(product % mod);
}
#endif

inline uint64_t addmod_cpu(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t sum = a + b;
    return (sum >= mod) ? (sum - mod) : sum;
}

inline uint64_t submod_cpu(uint64_t a, uint64_t b, uint64_t mod) {
    return (a >= b) ? (a - b) : (mod + a - b);
}

uint64_t powmod_cpu(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = mulmod_cpu(result, base, mod);
        base = mulmod_cpu(base, base, mod);
        exp >>= 1;
    }
    return result;
}

size_t bit_reverse_cpu(size_t x, int bits) {
    size_t result = 0;
    for (int i = 0; i < bits; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

void ntt_forward_cpu(std::vector<uint64_t>& data, 
                     const std::vector<uint64_t>& twiddles,
                     uint64_t mod,
                     int log_n) {
    size_t n = data.size();
    
    // Bit-reverse permutation
    for (size_t i = 0; i < n; ++i) {
        size_t j = bit_reverse_cpu(i, log_n);
        if (i < j) std::swap(data[i], data[j]);
    }
    
    // Cooley-Tukey butterfly
    for (int stage = 1; stage <= log_n; ++stage) {
        size_t m = 1ULL << stage;
        size_t half_m = m >> 1;
        
        for (size_t k = 0; k < n; k += m) {
            for (size_t j = 0; j < half_m; ++j) {
                size_t twiddle_idx = j << (log_n - stage);
                uint64_t w = twiddles[twiddle_idx];
                
                size_t i0 = k + j;
                size_t i1 = i0 + half_m;
                
                uint64_t u = data[i0];
                uint64_t v = data[i1];
                uint64_t t = mulmod_cpu(v, w, mod);
                
                data[i0] = addmod_cpu(u, t, mod);
                data[i1] = submod_cpu(u, t, mod);
            }
        }
    }
}

// ============================================================================
// Benchmark
// ============================================================================

void print_separator() {
    printf("====================================================================\n");
}

struct BenchResult {
    double cpu_ms;
    double gpu_ms;
    double speedup;
    bool correct;
};

BenchResult benchmark_ntt(int log_n, int iterations) {
    BenchResult result = {0, 0, 0, false};
    size_t n = 1ULL << log_n;
    
    if (log_n > MAX_LOG_N) {
        printf("  n=%zu exceeds max supported size\n", n);
        return result;
    }
    
    // Compute primitive n-th root of unity
    // For p = 998244353, generator g = 3
    uint64_t g = 3;
    uint64_t root = powmod_cpu(g, (NTT_PRIME - 1) / n, NTT_PRIME);
    
    // Precompute twiddle factors
    std::vector<uint64_t> twiddles(n);
    twiddles[0] = 1;
    for (size_t i = 1; i < n; ++i) {
        twiddles[i] = mulmod_cpu(twiddles[i-1], root, NTT_PRIME);
    }
    
    // Generate random data
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, NTT_PRIME - 1);
    
    std::vector<uint64_t> original(n);
    for (size_t i = 0; i < n; ++i) {
        original[i] = dist(rng);
    }
    
    // CPU benchmark
    std::vector<uint64_t> cpu_data = original;
    std::vector<uint64_t> cpu_result;
    
    auto cpu_start = Clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        cpu_data = original;
        ntt_forward_cpu(cpu_data, twiddles, NTT_PRIME, log_n);
    }
    auto cpu_end = Clock::now();
    result.cpu_ms = std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count() / iterations;
    cpu_result = cpu_data;
    
    // GPU benchmark
    uint64_t *d_data, *d_twiddles;
    cudaMalloc(&d_data, n * sizeof(uint64_t));
    cudaMalloc(&d_twiddles, n * sizeof(uint64_t));
    
    cudaMemcpy(d_twiddles, twiddles.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    int block_size = 256;
    int grid_n = (n + block_size - 1) / block_size;
    int grid_half_n = ((n/2) + block_size - 1) / block_size;
    
    // Warmup
    cudaMemcpy(d_data, original.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    bit_reverse_kernel<<<grid_n, block_size>>>(d_data, log_n);
    for (int stage = 1; stage <= log_n; ++stage) {
        ntt_butterfly_kernel<<<grid_half_n, block_size>>>(d_data, d_twiddles, NTT_PRIME, log_n, stage);
    }
    cudaDeviceSynchronize();
    
    // Timed runs
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    
    cudaEventRecord(start);
    for (int iter = 0; iter < iterations; ++iter) {
        cudaMemcpy(d_data, original.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
        bit_reverse_kernel<<<grid_n, block_size>>>(d_data, log_n);
        for (int stage = 1; stage <= log_n; ++stage) {
            ntt_butterfly_kernel<<<grid_half_n, block_size>>>(d_data, d_twiddles, NTT_PRIME, log_n, stage);
        }
    }
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    
    float gpu_time;
    cudaEventElapsedTime(&gpu_time, start, stop);
    result.gpu_ms = gpu_time / iterations;
    
    // Verify
    std::vector<uint64_t> gpu_result(n);
    cudaMemcpy(gpu_result.data(), d_data, n * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    
    result.correct = true;
    for (size_t i = 0; i < n; ++i) {
        if (gpu_result[i] != cpu_result[i]) {
            result.correct = false;
            break;
        }
    }
    
    result.speedup = result.cpu_ms / result.gpu_ms;
    
    cudaFree(d_data);
    cudaFree(d_twiddles);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    
    return result;
}

BenchResult benchmark_poly_mul(int log_n, int iterations) {
    BenchResult result = {0, 0, 0, false};
    size_t n = 1ULL << log_n;
    
    std::mt19937_64 rng(123);
    std::uniform_int_distribution<uint64_t> dist(0, NTT_PRIME - 1);
    
    std::vector<uint64_t> a(n), b(n), c_cpu(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    // CPU
    auto cpu_start = Clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        for (size_t i = 0; i < n; ++i) {
            c_cpu[i] = mulmod_cpu(a[i], b[i], NTT_PRIME);
        }
    }
    auto cpu_end = Clock::now();
    result.cpu_ms = std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count() / iterations;
    
    // GPU
    uint64_t *d_a, *d_b, *d_c;
    cudaMalloc(&d_a, n * sizeof(uint64_t));
    cudaMalloc(&d_b, n * sizeof(uint64_t));
    cudaMalloc(&d_c, n * sizeof(uint64_t));
    
    cudaMemcpy(d_a, a.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_b, b.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    int block_size = 256;
    int grid_size = (n + block_size - 1) / block_size;
    
    // Warmup
    poly_mul_kernel<<<grid_size, block_size>>>(d_c, d_a, d_b, NTT_PRIME, n);
    cudaDeviceSynchronize();
    
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    
    cudaEventRecord(start);
    for (int iter = 0; iter < iterations; ++iter) {
        poly_mul_kernel<<<grid_size, block_size>>>(d_c, d_a, d_b, NTT_PRIME, n);
    }
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    
    float gpu_time;
    cudaEventElapsedTime(&gpu_time, start, stop);
    result.gpu_ms = gpu_time / iterations;
    
    // Verify
    std::vector<uint64_t> c_gpu(n);
    cudaMemcpy(c_gpu.data(), d_c, n * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    
    result.correct = true;
    for (size_t i = 0; i < n; ++i) {
        if (c_gpu[i] != c_cpu[i]) {
            result.correct = false;
            break;
        }
    }
    
    result.speedup = result.cpu_ms / result.gpu_ms;
    
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_c);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    
    return result;
}

int main() {
    printf("\n");
    print_separator();
    printf("  kctsb GPU NTT/PIR Final Benchmark\n");
    printf("  Prime: p = %llu (30-bit, NTT-friendly)\n", NTT_PRIME);
    print_separator();
    
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    printf("GPU: %s (SM %d.%d, %.2f GB, %d SMs)\n\n", 
           prop.name, prop.major, prop.minor,
           prop.totalGlobalMem / 1024.0 / 1024.0 / 1024.0,
           prop.multiProcessorCount);
    
    const int iterations = 50;
    
    printf("NTT Forward Transform (%d iterations)\n", iterations);
    print_separator();
    printf("%-12s %12s %12s %10s %8s\n", "Size", "CPU (ms)", "GPU (ms)", "Speedup", "Correct");
    print_separator();
    
    for (int log_n = 10; log_n <= 20; log_n += 2) {
        size_t n = 1ULL << log_n;
        auto r = benchmark_ntt(log_n, iterations);
        printf("n=%-10zu %12.4f %12.4f %9.2fx %8s\n",
               n, r.cpu_ms, r.gpu_ms, r.speedup,
               r.correct ? "Yes" : "NO");
    }
    
    printf("\n");
    printf("Polynomial Pointwise Multiplication (%d iterations)\n", iterations);
    print_separator();
    printf("%-12s %12s %12s %10s %8s\n", "Size", "CPU (ms)", "GPU (ms)", "Speedup", "Correct");
    print_separator();
    
    for (int log_n = 12; log_n <= 20; log_n += 2) {
        size_t n = 1ULL << log_n;
        auto r = benchmark_poly_mul(log_n, iterations);
        printf("n=%-10zu %12.4f %12.4f %9.2fx %8s\n",
               n, r.cpu_ms, r.gpu_ms, r.speedup,
               r.correct ? "Yes" : "NO");
    }
    
    printf("\n");
    print_separator();
    printf("  Benchmark Complete\n");
    print_separator();
    printf("\n");
    
    return 0;
}
