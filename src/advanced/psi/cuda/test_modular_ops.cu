/**
 * @file test_modular_ops.cu
 * @brief Test CUDA modular arithmetic correctness
 */

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdint>
#include <random>

#ifdef _MSC_VER
#include <intrin.h>
#endif

// NTT prime: use a smaller prime that fits in 60 bits for easier verification
// q = 1152921504606846883 = 2^60 + 2^8 + 3 (prime)
// Actually, let's use a well-known prime: 2^61 - 1 = 2305843009213693951 (Mersenne prime)
// For simplicity, use: q = 4611686018427387847 (a prime < 2^62)

// Use a simpler approach: 50-bit prime for guaranteed no overflow issues
constexpr uint64_t TEST_PRIME = 1125899906842679ULL;  // A 50-bit prime

// CPU reference implementation
#ifdef _MSC_VER
inline uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    
    // For 50-bit prime, product can be up to 100 bits
    // We need precise 128-bit mod
    
    if (hi == 0) {
        return lo % mod;
    }
    
    // Reduce using double precision for quotient estimation
    // This gives an approximate quotient, then we correct
    long double dhi = static_cast<long double>(hi);
    long double dlo = static_cast<long double>(lo);
    long double dmod = static_cast<long double>(mod);
    
    // 2^64 as long double
    long double two64 = 18446744073709551616.0L;
    long double dval = dhi * two64 + dlo;
    
    // Approximate quotient
    uint64_t q = static_cast<uint64_t>(dval / dmod);
    
    // Compute q * mod using _umul128
    uint64_t prod_hi;
    uint64_t prod_lo = _umul128(q, mod, &prod_hi);
    
    // Subtract: (hi:lo) - (prod_hi:prod_lo)
    uint64_t result_lo = lo - prod_lo;
    uint64_t borrow = (lo < prod_lo) ? 1 : 0;
    uint64_t result_hi = hi - prod_hi - borrow;
    
    // If result is negative, add mod back
    if (result_hi != 0 || result_lo >= mod) {
        // This shouldn't happen with correct quotient, but handle edge cases
        while (result_hi != 0 || result_lo >= mod) {
            result_lo -= mod;
            if (result_lo > UINT64_MAX - mod) {
                // Underflow
                result_lo += mod;
                break;
            }
        }
    }
    
    return result_lo;
}
#else
inline uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod) {
    unsigned __int128 product = static_cast<unsigned __int128>(a) * b;
    return static_cast<uint64_t>(product % mod);
}
#endif

// GPU implementation using the same approach
__device__ __forceinline__ void mul64_full(uint64_t a, uint64_t b, 
                                           uint64_t& lo, uint64_t& hi) {
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));
}

__device__ uint64_t mulmod_gpu(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t lo, hi;
    mul64_full(a, b, lo, hi);
    
    if (hi == 0) {
        return lo % mod;
    }
    
    // Use double approximation (same as CPU)
    double dhi = static_cast<double>(hi);
    double dlo = static_cast<double>(lo);
    double dmod = static_cast<double>(mod);
    double dval = dhi * 18446744073709551616.0 + dlo;
    uint64_t q = static_cast<uint64_t>(dval / dmod);
    
    uint64_t r = lo - q * mod;
    
    // Correct if needed
    while (r >= mod) r -= mod;
    
    return r;
}

__global__ void test_mulmod_kernel(
    const uint64_t* a,
    const uint64_t* b,
    uint64_t* result,
    uint64_t mod,
    size_t n)
{
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;
    
    result[idx] = mulmod_gpu(a[idx], b[idx], mod);
}

int main() {
    printf("\n====================================================================\n");
    printf("  CUDA Modular Arithmetic Test\n");
    printf("  Prime: %llu (50-bit)\n", TEST_PRIME);
    printf("====================================================================\n\n");
    
    const size_t N = 10000;
    
    // Generate random test data
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint64_t> dist(0, TEST_PRIME - 1);
    
    std::vector<uint64_t> a(N), b(N), cpu_result(N);
    for (size_t i = 0; i < N; ++i) {
        a[i] = dist(rng);
        b[i] = dist(rng);
        cpu_result[i] = mulmod_cpu(a[i], b[i], TEST_PRIME);
    }
    
    // GPU computation
    uint64_t *d_a, *d_b, *d_result;
    cudaMalloc(&d_a, N * sizeof(uint64_t));
    cudaMalloc(&d_b, N * sizeof(uint64_t));
    cudaMalloc(&d_result, N * sizeof(uint64_t));
    
    cudaMemcpy(d_a, a.data(), N * sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_b, b.data(), N * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    int block_size = 256;
    int grid_size = (N + block_size - 1) / block_size;
    
    test_mulmod_kernel<<<grid_size, block_size>>>(d_a, d_b, d_result, TEST_PRIME, N);
    cudaDeviceSynchronize();
    
    std::vector<uint64_t> gpu_result(N);
    cudaMemcpy(gpu_result.data(), d_result, N * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    
    // Verify
    int mismatches = 0;
    for (size_t i = 0; i < N && mismatches < 10; ++i) {
        if (gpu_result[i] != cpu_result[i]) {
            printf("MISMATCH at %zu: a=%llu, b=%llu, CPU=%llu, GPU=%llu\n",
                   i, a[i], b[i], cpu_result[i], gpu_result[i]);
            mismatches++;
        }
    }
    
    if (mismatches == 0) {
        printf("SUCCESS: All %zu mulmod operations matched!\n", N);
    } else {
        printf("\nFAILED: %d mismatches found\n", mismatches);
    }
    
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_result);
    
    printf("\n");
    return mismatches > 0 ? 1 : 0;
}
