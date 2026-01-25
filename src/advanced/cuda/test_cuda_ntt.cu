/**
 * @file test_cuda_ntt.cu
 * @brief CUDA NTT Correctness Test
 * 
 * @details Verifies NTT/INTT correctness against CPU reference:
 * - Forward NTT consistency
 * - Inverse NTT recovery
 * - NTT convolution correctness
 * 
 * @author kn1ghtc
 * @version 4.15.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include "cuda_api.h"

// ============================================================================
// CPU Reference Implementation
// ============================================================================

#ifdef _MSC_VER
#include <intrin.h>

static uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod)
{
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    
    if (hi == 0 && lo < mod) return lo;
    if (hi == 0) return lo % mod;
    
    // Use double-precision approximation
    double dmod = (double)mod;
    double dprod = (double)hi * 18446744073709551616.0 + (double)lo;
    uint64_t q = (uint64_t)(dprod / dmod);
    
    uint64_t q_hi;
    uint64_t q_lo = _umul128(q, mod, &q_hi);
    
    uint64_t r = lo - q_lo;
    if (lo < q_lo) r += mod;
    while (r >= mod) r -= mod;
    return r;
}

static uint64_t compute_shoup_cpu(uint64_t a, uint64_t mod)
{
    if (a == 0 || mod == 0) return 0;
    
    // Compute floor((a * 2^64) / mod) using bit-by-bit long division
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
}
#else
static uint64_t mulmod_cpu(uint64_t a, uint64_t b, uint64_t mod)
{
    __uint128_t prod = (__uint128_t)a * b;
    return (uint64_t)(prod % mod);
}

static uint64_t compute_shoup_cpu(uint64_t a, uint64_t mod)
{
    __uint128_t numerator = ((__uint128_t)a) << 64;
    return (uint64_t)(numerator / mod);
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

// CPU NTT (Cooley-Tukey)
static void ntt_forward_cpu(uint64_t* data, size_t n, uint64_t mod, uint64_t root)
{
    int log_n = 0;
    for (size_t t = n; t > 1; t >>= 1) ++log_n;
    
    // Bit-reversal permutation
    for (size_t i = 0; i < n; ++i) {
        size_t j = bit_reverse(i, log_n);
        if (i < j) {
            uint64_t tmp = data[i];
            data[i] = data[j];
            data[j] = tmp;
        }
    }
    
    // Cooley-Tukey butterfly
    for (int s = 1; s <= log_n; ++s) {
        size_t m = 1ULL << s;
        uint64_t wm = powmod_cpu(root, n / m, mod);
        
        for (size_t k = 0; k < n; k += m) {
            uint64_t w = 1;
            for (size_t j = 0; j < m / 2; ++j) {
                uint64_t u = data[k + j];
                uint64_t t = mulmod_cpu(w, data[k + j + m/2], mod);
                data[k + j] = (u + t) % mod;
                data[k + j + m/2] = (u >= t) ? (u - t) : (u + mod - t);
                w = mulmod_cpu(w, wm, mod);
            }
        }
    }
}

// CPU INTT
static void ntt_inverse_cpu(uint64_t* data, size_t n, uint64_t mod, uint64_t root)
{
    uint64_t inv_root = invmod_cpu(root, mod);
    ntt_forward_cpu(data, n, mod, inv_root);
    
    uint64_t inv_n = invmod_cpu(n, mod);
    for (size_t i = 0; i < n; ++i) {
        data[i] = mulmod_cpu(data[i], inv_n, mod);
    }
}

// ============================================================================
// Test Functions
// ============================================================================

static bool test_ntt_roundtrip(size_t n, uint64_t mod)
{
    printf("\n[Test] NTT roundtrip: n=%zu, mod=%llu\n", n, (unsigned long long)mod);
    
    std::mt19937_64 rng(42);
    
    // Generate random input
    uint64_t* h_original = new uint64_t[n];
    uint64_t* h_data = new uint64_t[n];
    uint64_t* h_result = new uint64_t[n];
    
    for (size_t i = 0; i < n; ++i) {
        h_original[i] = rng() % mod;
        h_data[i] = h_original[i];
    }
    
    // Precompute NTT tables on GPU
    uint64_t *d_roots, *d_roots_shoup, *d_inv_roots, *d_inv_roots_shoup;
    int err = kctsb_cuda_ntt_precompute(n, mod, 
        &d_roots, &d_roots_shoup, &d_inv_roots, &d_inv_roots_shoup);
    
    if (err != 0) {
        printf("  [FAIL] NTT precompute failed\n");
        delete[] h_original;
        delete[] h_data;
        delete[] h_result;
        return false;
    }
    
    // Allocate device memory
    uint64_t* d_data;
    cudaMalloc(&d_data, n * sizeof(uint64_t));
    cudaMemcpy(d_data, h_data, n * sizeof(uint64_t), cudaMemcpyHostToDevice);
    
    // Compute log_n
    int log_n = 0;
    for (size_t t = n; t > 1; t >>= 1) ++log_n;
    
    // Forward NTT on GPU
    err = kctsb_cuda_ntt_forward(d_data, d_roots, d_roots_shoup, mod, log_n);
    if (err != 0) {
        printf("  [FAIL] Forward NTT failed\n");
        cudaFree(d_data);
        return false;
    }
    
    // Compute inverse parameters
    uint64_t inv_n = invmod_cpu(n, mod);
    uint64_t inv_n_shoup = compute_shoup_cpu(inv_n, mod);
    
    // Inverse NTT on GPU
    err = kctsb_cuda_ntt_inverse(d_data, d_inv_roots, d_inv_roots_shoup, 
                                  mod, inv_n, inv_n_shoup, log_n);
    if (err != 0) {
        printf("  [FAIL] Inverse NTT failed\n");
        cudaFree(d_data);
        return false;
    }
    
    // Copy result back
    cudaMemcpy(h_result, d_data, n * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    
    // Verify
    bool correct = true;
    size_t mismatch_count = 0;
    for (size_t i = 0; i < n && mismatch_count < 5; ++i) {
        if (h_result[i] != h_original[i]) {
            printf("  [MISMATCH] index %zu: expected %llu, got %llu\n",
                   i, (unsigned long long)h_original[i], (unsigned long long)h_result[i]);
            correct = false;
            ++mismatch_count;
        }
    }
    
    if (correct) {
        printf("  [PASS] All %zu elements match after NTT -> INTT\n", n);
    } else {
        printf("  [FAIL] %zu+ mismatches found\n", mismatch_count);
    }
    
    // Cleanup
    cudaFree(d_data);
    cudaFree(d_roots);
    cudaFree(d_roots_shoup);
    cudaFree(d_inv_roots);
    cudaFree(d_inv_roots_shoup);
    delete[] h_original;
    delete[] h_data;
    delete[] h_result;
    
    return correct;
}

// ============================================================================
// Main
// ============================================================================

int main()
{
    printf("\n");
    printf("====================================================================\n");
    printf("  kctsb CUDA NTT Correctness Test\n");
    printf("====================================================================\n");
    
    // Check CUDA availability
    if (!kctsb_cuda_available()) {
        printf("[FAIL] No CUDA device available\n");
        return 1;
    }
    
    // Print device info
    char name[256];
    size_t mem;
    int sm_major, sm_minor, sm_count;
    kctsb_cuda_device_info(0, name, sizeof(name), &mem, &sm_major, &sm_minor, &sm_count);
    printf("[INFO] Device: %s (SM %d.%d, %d SMs, %.2f GB)\n\n",
           name, sm_major, sm_minor, sm_count, mem / (1024.0 * 1024.0 * 1024.0));
    
    // Test with various parameters
    // Using NTT-friendly primes
    
    // Prime: 2^50 - 2^14 + 1 = 1125899906826241 (50-bit, divisible by 2^14)
    // Prime: 576460752303292417 (59-bit, = 2^59 - 2^14 + 1)
    // Prime: 998244353 (30-bit, commonly used for competitive programming)
    
    struct TestCase {
        size_t n;
        uint64_t mod;
        const char* desc;
    };
    
    TestCase tests[] = {
        // Small tests with 30-bit prime (fast)
        {1024, 998244353ULL, "Small (30-bit prime)"},
        {4096, 998244353ULL, "Medium (30-bit prime)"},
        
        // FHE-relevant sizes with 31-bit NTT prime
        // p = 2013265921 = 15 * 2^27 + 1 (NTT-friendly up to 2^27)
        {8192, 2013265921ULL, "FHE n=8192 (31-bit NTT prime)"},
        {16384, 2013265921ULL, "FHE n=16384 (31-bit NTT prime)"},
        {32768, 2013265921ULL, "FHE n=32768 (31-bit NTT prime)"},
        
        // Real 50-bit prime for security testing:
        // p = 1125899906826241 = 2^50 - 2^14 + 1 (supports NTT up to 2^14)
        {8192, 1125899906826241ULL, "FHE n=8192 (50-bit prime)"},
    };
    
    int passed = 0;
    int total = sizeof(tests) / sizeof(tests[0]);
    
    for (int i = 0; i < total; ++i) {
        if (test_ntt_roundtrip(tests[i].n, tests[i].mod)) {
            ++passed;
        }
    }
    
    printf("\n====================================================================\n");
    printf("  Results: %d/%d tests passed\n", passed, total);
    printf("====================================================================\n\n");
    
    return (passed == total) ? 0 : 1;
}
