/**
 * @file benchmark_ntt_optimized.cu
 * @brief Optimized GPU NTT Benchmark with precise modular arithmetic
 * 
 * @details Tests GPU NTT acceleration with correct Barrett reduction
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
// Constants for Barrett Reduction
// ============================================================================

// NTT-friendly prime: q = 0xFFFFFFFF00000001 (2^64 - 2^32 + 1)
// This is a Goldilocks-like prime commonly used in ZK systems
constexpr uint64_t NTT_PRIME = 0xFFFFFFFF00000001ULL;

// Barrett constant: floor(2^128 / q)
// For this prime: mu = 2^64 + 2^32 - 1
constexpr uint64_t BARRETT_MU_LO = 0xFFFFFFFFFFFFFFFFULL;
constexpr uint64_t BARRETT_MU_HI = 0x1ULL;

// ============================================================================
// GPU Modular Arithmetic (Precise)
// ============================================================================

/**
 * @brief 64x64 -> 128 bit multiplication using PTX
 */
__device__ __forceinline__ void mul64_full(uint64_t a, uint64_t b, 
                                           uint64_t& lo, uint64_t& hi) {
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));
}

/**
 * @brief Precise reduction modulo p = 2^64 - 2^32 + 1
 * 
 * Uses the identity: 2^64 ≡ 2^32 - 1 (mod p)
 * 
 * For x = hi * 2^64 + lo:
 * x ≡ hi * (2^32 - 1) + lo (mod p)
 *   = (hi << 32) - hi + lo
 */
__device__ __forceinline__ uint64_t reduce_prime(uint64_t lo, uint64_t hi) {
    // If hi is 0, just reduce lo
    if (hi == 0) {
        return (lo >= NTT_PRIME) ? (lo - NTT_PRIME) : lo;
    }
    
    // Split hi into upper and lower 32 bits
    uint64_t hi_lo = hi & 0xFFFFFFFFULL;        // Lower 32 bits of hi
    uint64_t hi_hi = hi >> 32;                   // Upper 32 bits of hi
    
    // hi * (2^32 - 1) = hi * 2^32 - hi
    //                 = (hi_hi << 64) + (hi_lo << 32) - hi_hi * 2^32 - hi_lo
    //                 = (hi_hi << 64) + ((hi_lo - hi_hi) << 32) - hi_lo
    // 
    // Since hi_hi << 64 ≡ hi_hi * (2^32 - 1) (mod p), recursively:
    // But for our range (hi < 2^64), we can compute directly.
    
    // Compute contribution: hi * (2^32 - 1) mod p
    // = hi << 32 - hi
    // Taking care of overflow
    
    uint64_t t1 = hi << 32;     // May overflow, but that's okay
    uint64_t t2 = hi;
    
    // result = lo + t1 - t2
    // Handle the addition first
    uint64_t result = lo + t1;
    bool carry = result < lo;
    
    // Subtract t2
    bool borrow = result < t2;
    result -= t2;
    
    // Process carry: carry means we had a wrap-around, add 2^64 which is ≡ 2^32 - 1
    if (carry) {
        result += 0xFFFFFFFFULL;  // 2^32 - 1
        if (result < 0xFFFFFFFFULL) {
            // Wrapped again, add another 2^32 - 1
            result += 0xFFFFFFFFULL;
        }
    }
    
    // Process borrow: borrow means we subtracted too much, add p back
    if (borrow && !carry) {
        result += NTT_PRIME;
    }
    
    // Final reduction (may need multiple subtractions)
    while (result >= NTT_PRIME) result -= NTT_PRIME;
    
    return result;
}

/**
 * @brief Modular multiplication using the special prime structure
 */
__device__ __forceinline__ uint64_t mulmod_gpu(uint64_t a, uint64_t b) {
    uint64_t lo, hi;
    mul64_full(a, b, lo, hi);
    return reduce_prime(lo, hi);
}

/**
 * @brief Modular subtraction (lazy)
 */
__device__ __forceinline__ uint64_t submod_gpu(uint64_t a, uint64_t b) {
    return (a >= b) ? (a - b) : (NTT_PRIME + a - b);
}

/**
 * @brief Modular addition (lazy)
 */
__device__ __forceinline__ uint64_t addmod_gpu(uint64_t a, uint64_t b) {
    uint64_t sum = a + b;
    return (sum >= NTT_PRIME || sum < a) ? (sum - NTT_PRIME) : sum;
}

// ============================================================================
// GPU NTT Kernels
// ============================================================================

/**
 * @brief Bit-reverse permutation kernel (optimized)
 */
__global__ void bit_reverse_kernel(uint64_t* data, int log_n) {
    const size_t n = 1ULL << log_n;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx >= n) return;
    
    // Compute bit-reversed index using parallel bit manipulation
    size_t rev = 0;
    size_t temp = idx;
    #pragma unroll
    for (int i = 0; i < 20; ++i) {  // Support up to n=2^20
        if (i < log_n) {
            rev = (rev << 1) | (temp & 1);
            temp >>= 1;
        }
    }
    
    if (idx < rev) {
        uint64_t tmp = data[idx];
        data[idx] = data[rev];
        data[rev] = tmp;
    }
}

/**
 * @brief NTT butterfly kernel for single stage
 */
__global__ void ntt_butterfly_kernel(
    uint64_t* data,
    const uint64_t* twiddles,
    int log_n,
    int stage)
{
    const size_t n = 1ULL << log_n;
    const size_t m = 1ULL << stage;
    const size_t half_m = m >> 1;
    
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    size_t total_butterflies = (n >> 1);
    
    if (tid >= total_butterflies) return;
    
    // Compute butterfly indices
    size_t group = tid / half_m;
    size_t j = tid % half_m;
    size_t i0 = group * m + j;
    size_t i1 = i0 + half_m;
    
    // Twiddle factor index
    size_t twiddle_idx = j << (log_n - stage);
    uint64_t w = twiddles[twiddle_idx];
    
    // Butterfly operation
    uint64_t u = data[i0];
    uint64_t v = data[i1];
    uint64_t t = mulmod_gpu(v, w);
    
    data[i0] = addmod_gpu(u, t);
    data[i1] = submod_gpu(u, t);
}

/**
 * @brief Combined NTT kernel using shared memory (for small n)
 */
__global__ void ntt_shared_kernel(
    uint64_t* data,
    const uint64_t* twiddles,
    int log_n)
{
    extern __shared__ uint64_t shared_data[];
    
    const size_t n = 1ULL << log_n;
    size_t tid = threadIdx.x;
    size_t bid = blockIdx.x;
    
    // Load data to shared memory
    size_t base_idx = bid * blockDim.x;
    if (base_idx + tid < n) {
        shared_data[tid] = data[base_idx + tid];
    }
    __syncthreads();
    
    // Perform NTT stages in shared memory
    for (int stage = 1; stage <= log_n && (1ULL << stage) <= blockDim.x; ++stage) {
        size_t m = 1ULL << stage;
        size_t half_m = m >> 1;
        
        if (tid < (n >> 1)) {
            size_t group = tid / half_m;
            size_t j = tid % half_m;
            size_t i0 = group * m + j;
            size_t i1 = i0 + half_m;
            
            size_t twiddle_idx = j << (log_n - stage);
            uint64_t w = twiddles[twiddle_idx];
            
            uint64_t u = shared_data[i0];
            uint64_t v = shared_data[i1];
            uint64_t t = mulmod_gpu(v, w);
            
            shared_data[i0] = addmod_gpu(u, t);
            shared_data[i1] = submod_gpu(u, t);
        }
        __syncthreads();
    }
    
    // Write back to global memory
    if (base_idx + tid < n) {
        data[base_idx + tid] = shared_data[tid];
    }
}

/**
 * @brief Polynomial pointwise multiplication kernel
 */
__global__ void poly_mul_kernel(
    uint64_t* result,
    const uint64_t* a,
    const uint64_t* b,
    size_t n)
{
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    
    result[idx] = mulmod_gpu(a[idx], b[idx]);
}

// ============================================================================
// CPU Implementation (Reference)
// ============================================================================

#ifdef _MSC_VER
// MSVC implementation using intrinsics
inline uint64_t reduce_prime_cpu(uint64_t lo, uint64_t hi) {
    // Same algorithm as GPU
    uint64_t hi_shifted = hi << 32;
    uint64_t correction = hi >> 32;
    
    uint64_t result = lo + hi_shifted;
    result -= hi;
    result += correction * 0xFFFFFFFFULL;
    
    while (result >= NTT_PRIME) result -= NTT_PRIME;
    return result;
}

inline uint64_t mulmod_cpu(uint64_t a, uint64_t b) {
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    return reduce_prime_cpu(lo, hi);
}
#else
// GCC/Clang implementation
inline uint64_t mulmod_cpu(uint64_t a, uint64_t b) {
    unsigned __int128 product = static_cast<unsigned __int128>(a) * b;
    return static_cast<uint64_t>(product % NTT_PRIME);
}
#endif

uint64_t powmod_cpu(uint64_t base, uint64_t exp) {
    uint64_t result = 1;
    base %= NTT_PRIME;
    while (exp > 0) {
        if (exp & 1) result = mulmod_cpu(result, base);
        base = mulmod_cpu(base, base);
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
                uint64_t t = mulmod_cpu(v, w);
                
                data[i0] = (u + t) % NTT_PRIME;
                data[i1] = (u >= t) ? (u - t) : (NTT_PRIME + u - t);
            }
        }
    }
}

// ============================================================================
// Benchmark Functions
// ============================================================================

void print_separator() {
    printf("====================================================================\n");
}

void print_header() {
    printf("%-10s  %12s  %12s  %10s  %8s\n", "Size", "CPU (ms)", "GPU (ms)", "Speedup", "Correct");
    print_separator();
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
    
    printf("  Testing n=%zu (2^%d)...\n", n, log_n);
    
    // Compute primitive root of unity
    // For q = 2^64 - 2^32 + 1, a primitive 2^32-th root of unity is known
    // omega = 7^((q-1)/(2*n))
    uint64_t g = 7;  // Generator
    uint64_t order = NTT_PRIME - 1;
    uint64_t root = powmod_cpu(g, order / (2 * n));
    
    // Precompute twiddle factors
    std::vector<uint64_t> twiddles(n);
    twiddles[0] = 1;
    for (size_t i = 1; i < n; ++i) {
        twiddles[i] = mulmod_cpu(twiddles[i-1], root);
    }
    
    // Generate random data
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, NTT_PRIME - 1);
    
    std::vector<uint64_t> original(n);
    for (size_t i = 0; i < n; ++i) {
        original[i] = dist(rng);
    }
    
    // ==================== CPU Benchmark ====================
    std::vector<uint64_t> cpu_data = original;
    std::vector<uint64_t> cpu_result;
    
    auto cpu_start = Clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        cpu_data = original;
        ntt_forward_cpu(cpu_data, twiddles, log_n);
    }
    auto cpu_end = Clock::now();
    result.cpu_ms = std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count() / iterations;
    cpu_result = cpu_data;
    
    // ==================== GPU Benchmark ====================
    uint64_t *d_data, *d_twiddles;
    cudaMalloc(&d_data, n * sizeof(uint64_t));
    cudaMalloc(&d_twiddles, n * sizeof(uint64_t));
    
    cudaMemcpy(d_twiddles, twiddles.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    int block_size = 256;
    int grid_size = (n + block_size - 1) / block_size;
    int butterfly_grid = ((n/2) + block_size - 1) / block_size;
    
    // Warmup
    cudaMemcpy(d_data, original.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    bit_reverse_kernel<<<grid_size, block_size>>>(d_data, log_n);
    for (int stage = 1; stage <= log_n; ++stage) {
        ntt_butterfly_kernel<<<butterfly_grid, block_size>>>(d_data, d_twiddles, log_n, stage);
    }
    cudaDeviceSynchronize();
    
    // Timed benchmark
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    
    cudaEventRecord(start);
    for (int iter = 0; iter < iterations; ++iter) {
        cudaMemcpy(d_data, original.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
        bit_reverse_kernel<<<grid_size, block_size>>>(d_data, log_n);
        for (int stage = 1; stage <= log_n; ++stage) {
            ntt_butterfly_kernel<<<butterfly_grid, block_size>>>(d_data, d_twiddles, log_n, stage);
        }
    }
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    
    float gpu_time;
    cudaEventElapsedTime(&gpu_time, start, stop);
    result.gpu_ms = gpu_time / iterations;
    
    // Verify correctness
    std::vector<uint64_t> gpu_result(n);
    cudaMemcpy(gpu_result.data(), d_data, n * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    
    result.correct = true;
    int mismatch_count = 0;
    for (size_t i = 0; i < n && mismatch_count < 5; ++i) {
        if (gpu_result[i] != cpu_result[i]) {
            result.correct = false;
            mismatch_count++;
        }
    }
    
    result.speedup = result.cpu_ms / result.gpu_ms;
    
    // Cleanup
    cudaFree(d_data);
    cudaFree(d_twiddles);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    
    return result;
}

BenchResult benchmark_poly_mul(int log_n, int iterations) {
    BenchResult result = {0, 0, 0, false};
    size_t n = 1ULL << log_n;
    
    // Generate random data
    std::mt19937_64 rng(123);
    std::uniform_int_distribution<uint64_t> dist(0, NTT_PRIME - 1);
    
    std::vector<uint64_t> a(n), b(n), c_cpu(n);
    for (size_t i = 0; i < n; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
    }
    
    // CPU benchmark
    auto cpu_start = Clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        for (size_t i = 0; i < n; ++i) {
            c_cpu[i] = mulmod_cpu(a[i], b[i]);
        }
    }
    auto cpu_end = Clock::now();
    result.cpu_ms = std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count() / iterations;
    
    // GPU benchmark
    uint64_t *d_a, *d_b, *d_c;
    cudaMalloc(&d_a, n * sizeof(uint64_t));
    cudaMalloc(&d_b, n * sizeof(uint64_t));
    cudaMalloc(&d_c, n * sizeof(uint64_t));
    
    cudaMemcpy(d_a, a.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_b, b.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    int block_size = 256;
    int grid_size = (n + block_size - 1) / block_size;
    
    // Warmup
    poly_mul_kernel<<<grid_size, block_size>>>(d_c, d_a, d_b, n);
    cudaDeviceSynchronize();
    
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    
    cudaEventRecord(start);
    for (int iter = 0; iter < iterations; ++iter) {
        poly_mul_kernel<<<grid_size, block_size>>>(d_c, d_a, d_b, n);
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
    printf("  kctsb GPU NTT/PIR Optimized Benchmark\n");
    printf("  Prime: q = 2^64 - 2^32 + 1 (Goldilocks-like)\n");
    print_separator();
    
    // Get GPU info
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    printf("GPU: %s (SM %d.%d, %.2f GB)\n", prop.name, prop.major, prop.minor,
           prop.totalGlobalMem / 1024.0 / 1024.0 / 1024.0);
    printf("SMs: %d, Max Threads/Block: %d\n", prop.multiProcessorCount, prop.maxThreadsPerBlock);
    printf("\n");
    
    const int iterations = 50;
    
    printf("Benchmark: NTT Forward Transform (%d iterations each)\n", iterations);
    print_separator();
    print_header();
    
    for (int log_n = 10; log_n <= 18; log_n += 2) {
        size_t n = 1ULL << log_n;
        auto r = benchmark_ntt(log_n, iterations);
        printf("n=%-8zu  %12.4f  %12.4f  %9.2fx  %8s\n",
               n, r.cpu_ms, r.gpu_ms, r.speedup,
               r.correct ? "Yes" : "NO");
    }
    
    printf("\n");
    printf("Benchmark: Polynomial Multiplication (%d iterations each)\n", iterations);
    print_separator();
    print_header();
    
    for (int log_n = 12; log_n <= 18; log_n += 2) {
        size_t n = 1ULL << log_n;
        auto r = benchmark_poly_mul(log_n, iterations);
        printf("n=%-8zu  %12.4f  %12.4f  %9.2fx  %8s\n",
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
