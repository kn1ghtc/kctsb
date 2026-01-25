/**
 * @file cuda_utils.cu
 * @brief CUDA Utility Functions for kctsb
 * 
 * @details Common device management and memory operations:
 * - Device detection and info
 * - Memory allocation/deallocation
 * - Host-device transfers
 * - Stream management
 * - NTT table precomputation
 * 
 * @author kn1ghtc
 * @version 4.15.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "cuda_api.h"

// ============================================================================
// Device Management
// ============================================================================

extern "C" {

int kctsb_cuda_available(void)
{
    int device_count = 0;
    cudaError_t err = cudaGetDeviceCount(&device_count);
    return (err == cudaSuccess && device_count > 0) ? 1 : 0;
}

int kctsb_cuda_device_count(int* count)
{
    if (!count) return KCTSB_CUDA_ERROR_INVALID;
    
    cudaError_t err = cudaGetDeviceCount(count);
    if (err != cudaSuccess) {
        *count = 0;
        return KCTSB_CUDA_ERROR_NO_DEVICE;
    }
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_device_info(
    int device_id,
    char* name,
    size_t name_len,
    size_t* total_mem,
    int* sm_major,
    int* sm_minor,
    int* sm_count)
{
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, device_id);
    if (err != cudaSuccess) {
        return KCTSB_CUDA_ERROR_NO_DEVICE;
    }
    
    if (name && name_len > 0) {
        strncpy(name, prop.name, name_len - 1);
        name[name_len - 1] = '\0';
    }
    if (total_mem) *total_mem = prop.totalGlobalMem;
    if (sm_major) *sm_major = prop.major;
    if (sm_minor) *sm_minor = prop.minor;
    if (sm_count) *sm_count = prop.multiProcessorCount;
    
    return KCTSB_CUDA_SUCCESS;
}

// ============================================================================
// Memory Management
// ============================================================================

int kctsb_cuda_malloc(void** ptr, size_t size)
{
    if (!ptr) return KCTSB_CUDA_ERROR_INVALID;
    
    cudaError_t err = cudaMalloc(ptr, size);
    if (err != cudaSuccess) {
        *ptr = nullptr;
        return KCTSB_CUDA_ERROR_ALLOC;
    }
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_free(void* ptr)
{
    if (!ptr) return KCTSB_CUDA_SUCCESS;  // Freeing NULL is OK
    
    cudaError_t err = cudaFree(ptr);
    if (err != cudaSuccess) {
        return KCTSB_CUDA_ERROR_KERNEL;
    }
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_memcpy_h2d(void* dst, const void* src, size_t size)
{
    if (!dst || !src) return KCTSB_CUDA_ERROR_INVALID;
    
    cudaError_t err = cudaMemcpy(dst, src, size, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) {
        return KCTSB_CUDA_ERROR_MEMCPY;
    }
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_memcpy_d2h(void* dst, const void* src, size_t size)
{
    if (!dst || !src) return KCTSB_CUDA_ERROR_INVALID;
    
    cudaError_t err = cudaMemcpy(dst, src, size, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) {
        return KCTSB_CUDA_ERROR_MEMCPY;
    }
    return KCTSB_CUDA_SUCCESS;
}

// ============================================================================
// Stream Management
// ============================================================================

struct CudaStreamWrapper {
    cudaStream_t stream;
    bool created;
};

int kctsb_cuda_stream_create(void** stream)
{
    if (!stream) return KCTSB_CUDA_ERROR_INVALID;
    
    auto* wrapper = new CudaStreamWrapper;
    cudaError_t err = cudaStreamCreate(&wrapper->stream);
    if (err != cudaSuccess) {
        delete wrapper;
        *stream = nullptr;
        return KCTSB_CUDA_ERROR_KERNEL;
    }
    
    wrapper->created = true;
    *stream = wrapper;
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_stream_destroy(void* stream)
{
    if (!stream) return KCTSB_CUDA_SUCCESS;
    
    auto* wrapper = static_cast<CudaStreamWrapper*>(stream);
    if (wrapper->created) {
        cudaStreamDestroy(wrapper->stream);
    }
    delete wrapper;
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_stream_sync(void* stream)
{
    if (!stream) return KCTSB_CUDA_SUCCESS;
    
    auto* wrapper = static_cast<CudaStreamWrapper*>(stream);
    if (wrapper->created) {
        cudaError_t err = cudaStreamSynchronize(wrapper->stream);
        if (err != cudaSuccess) {
            return KCTSB_CUDA_ERROR_KERNEL;
        }
    }
    return KCTSB_CUDA_SUCCESS;
}

// ============================================================================
// NTT Precomputation Helpers (Host-side)
// ============================================================================

#ifdef _MSC_VER
#include <intrin.h>

/**
 * @brief 128-bit multiplication with modulo for MSVC
 */
static uint64_t mulmod128_host(uint64_t a, uint64_t b, uint64_t mod)
{
    uint64_t hi;
    uint64_t lo = _umul128(a, b, &hi);
    
    if (hi == 0 && lo < mod) return lo;
    if (hi == 0) return lo % mod;
    
    // Use double-precision approximation for quotient
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

/**
 * @brief Compute Shoup precomputation value for MSVC
 * 
 * Computes floor(a * 2^64 / mod) using 128-bit arithmetic simulation
 */
static uint64_t compute_shoup_host(uint64_t a, uint64_t mod)
{
    if (a == 0 || mod == 0) return 0;
    
    // We need floor((a * 2^64) / mod)
    // Numerator = a << 64 = (a, 0) as a 128-bit number
    // 
    // Use schoolbook long division with 64-bit chunks
    // dividend_hi = a, dividend_lo = 0
    // 
    // quotient = 0
    // remainder = a  (initially high part of dividend)
    // 
    // For each bit position from 63 down to 0:
    //   remainder = remainder * 2 + next_bit_of_dividend_lo
    //   if remainder >= mod: remainder -= mod; set quotient bit
    
    uint64_t quotient = 0;
    uint64_t remainder = 0;
    
    // First, process the high 64 bits (the 'a' value)
    // Each bit shifts into remainder
    for (int i = 63; i >= 0; --i) {
        // Shift remainder left by 1 and bring in bit i of 'a'
        uint64_t bit = (a >> i) & 1ULL;
        
        // Check for overflow before shift
        if (remainder >= (1ULL << 63)) {
            // remainder * 2 will overflow
            // remainder >= 2^63, so remainder * 2 >= 2^64
            // Since mod < 2^64, remainder * 2 >= mod is guaranteed
            remainder = (remainder << 1) + bit;
            remainder -= mod;
            // This quotient bit goes into a higher position (beyond 64 bits)
            // We don't care about quotient from the first 64 bits of dividend
        } else {
            remainder = (remainder << 1) + bit;
            if (remainder >= mod) {
                remainder -= mod;
                // Same - these bits are above our desired quotient range
            }
        }
    }
    
    // Now process the low 64 bits (all zeros)
    // Each bit of the low part contributes to the actual quotient we want
    for (int i = 63; i >= 0; --i) {
        // Shift remainder left by 1 (bringing in 0 since dividend_lo = 0)
        if (remainder >= (1ULL << 63)) {
            // Will overflow - guaranteed >= mod
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
static uint64_t mulmod128_host(uint64_t a, uint64_t b, uint64_t mod)
{
    __uint128_t prod = (__uint128_t)a * b;
    return (uint64_t)(prod % mod);
}

static uint64_t compute_shoup_host(uint64_t a, uint64_t mod)
{
    __uint128_t numerator = ((__uint128_t)a) << 64;
    return (uint64_t)(numerator / mod);
}
#endif

/**
 * @brief Modular exponentiation (host)
 */
static uint64_t powmod_host(uint64_t base, uint64_t exp, uint64_t mod)
{
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = mulmod128_host(result, base, mod);
        }
        base = mulmod128_host(base, base, mod);
        exp >>= 1;
    }
    return result;
}

/**
 * @brief Modular inverse using extended Euclidean algorithm
 */
static uint64_t invmod_host(uint64_t a, uint64_t mod)
{
    int64_t t = 0, new_t = 1;
    uint64_t r = mod, new_r = a;
    
    while (new_r != 0) {
        uint64_t q = r / new_r;
        
        int64_t tmp_t = t - (int64_t)q * new_t;
        t = new_t;
        new_t = tmp_t;
        
        uint64_t tmp_r = r - q * new_r;
        r = new_r;
        new_r = tmp_r;
    }
    
    return (t < 0) ? (uint64_t)(t + (int64_t)mod) : (uint64_t)t;
}

/**
 * @brief Find primitive n-th root of unity for NTT
 * 
 * For NTT of size n, we need w such that:
 * - w^n ≡ 1 (mod p)
 * - w^(n/2) ≡ -1 (mod p)
 * 
 * Requirement: p - 1 must be divisible by n (p is NTT-friendly for this n)
 */
static uint64_t find_primitive_root_host(uint64_t mod, size_t n)
{
    // Check if n divides (mod - 1)
    if ((mod - 1) % n != 0) {
        return 0;  // Not NTT-friendly for this n
    }
    
    // k = (p - 1) / n
    uint64_t k = (mod - 1) / n;
    
    // Try small candidates as generator candidates
    // We need g such that g^k is a primitive n-th root
    for (uint64_t g = 2; g < 1000; ++g) {
        uint64_t root = powmod_host(g, k, mod);
        
        // Skip trivial root
        if (root == 1) continue;
        
        // Check: root^(n/2) == -1 (mod p)
        // This ensures root is a primitive n-th root (not a root of smaller order)
        uint64_t half_check = powmod_host(root, n / 2, mod);
        if (half_check == mod - 1) {
            // Verify: root^n == 1
            uint64_t full_check = powmod_host(root, n, mod);
            if (full_check == 1) {
                return root;
            }
        }
    }
    
    return 0;  // Failed to find root
}

/**
 * @brief Compute Shoup precomputation value: floor(a * 2^64 / mod)
 */
static uint64_t compute_shoup(uint64_t a, uint64_t mod)
{
    return compute_shoup_host(a, mod);
}

int kctsb_cuda_ntt_precompute(
    size_t n,
    uint64_t modulus,
    uint64_t** d_root_powers,
    uint64_t** d_root_powers_shoup,
    uint64_t** d_inv_root_powers,
    uint64_t** d_inv_root_powers_shoup)
{
    if (!d_root_powers || !d_root_powers_shoup ||
        !d_inv_root_powers || !d_inv_root_powers_shoup) {
        return KCTSB_CUDA_ERROR_INVALID;
    }
    
    // Find primitive 2n-th root of unity
    uint64_t root = find_primitive_root_host(modulus, n);
    if (root == 0) {
        fprintf(stderr, "[CUDA] Failed to find primitive root for modulus %lu\n",
                (unsigned long)modulus);
        return KCTSB_CUDA_ERROR_INVALID;
    }
    
    uint64_t inv_root = invmod_host(root, modulus);
    
    // Allocate host buffers (2n size for safety)
    size_t table_n = 2 * n;
    uint64_t* h_roots = new uint64_t[table_n];
    uint64_t* h_roots_shoup = new uint64_t[table_n];
    uint64_t* h_inv_roots = new uint64_t[table_n];
    uint64_t* h_inv_roots_shoup = new uint64_t[table_n];
    
    // Initialize all entries
    for (size_t i = 0; i < table_n; ++i) {
        h_roots[i] = 1;
        h_roots_shoup[i] = compute_shoup(1, modulus);
        h_inv_roots[i] = 1;
        h_inv_roots_shoup[i] = compute_shoup(1, modulus);
    }
    
    // Compute root powers in tree order for CT-NTT
    // Table layout: [1, w^{n/2}, w^{n/4}, w^{3n/4}, ...]
    // For stage s (1-indexed), roots at indices [2^{s-1}, 2^s) contain
    // w^{j * n / 2^s} for j = 0, 1, ..., 2^{s-1}-1
    for (int log_m = 1; (1ULL << log_m) <= n; ++log_m) {
        size_t m = 1ULL << log_m;
        size_t half_m = m >> 1;
        uint64_t step = n / m;  // w^step is the twiddle factor increment
        
        // Compute w^step using w^{n/m} = w^{step}
        uint64_t w_step = powmod_host(root, step, modulus);
        uint64_t w_step_inv = powmod_host(inv_root, step, modulus);
        
        uint64_t w_power = 1;
        uint64_t w_power_inv = 1;
        
        for (size_t j = 0; j < half_m; ++j) {
            size_t idx = half_m + j;  // Index in table
            h_roots[idx] = w_power;
            h_roots_shoup[idx] = compute_shoup(w_power, modulus);
            h_inv_roots[idx] = w_power_inv;
            h_inv_roots_shoup[idx] = compute_shoup(w_power_inv, modulus);
            
            w_power = mulmod128_host(w_power, w_step, modulus);
            w_power_inv = mulmod128_host(w_power_inv, w_step_inv, modulus);
        }
    }
    
    // Allocate device memory and copy (use 2n size)
    size_t table_size = table_n * sizeof(uint64_t);
    
    cudaMalloc(d_root_powers, table_size);
    cudaMalloc(d_root_powers_shoup, table_size);
    cudaMalloc(d_inv_root_powers, table_size);
    cudaMalloc(d_inv_root_powers_shoup, table_size);
    
    cudaMemcpy(*d_root_powers, h_roots, table_size, cudaMemcpyHostToDevice);
    cudaMemcpy(*d_root_powers_shoup, h_roots_shoup, table_size, cudaMemcpyHostToDevice);
    cudaMemcpy(*d_inv_root_powers, h_inv_roots, table_size, cudaMemcpyHostToDevice);
    cudaMemcpy(*d_inv_root_powers_shoup, h_inv_roots_shoup, table_size, cudaMemcpyHostToDevice);
    
    // Cleanup host buffers
    delete[] h_roots;
    delete[] h_roots_shoup;
    delete[] h_inv_roots;
    delete[] h_inv_roots_shoup;
    
    return KCTSB_CUDA_SUCCESS;
}

} // extern "C"

// ============================================================================
// Device Info Print (for debugging)
// ============================================================================

extern "C" void kctsb_cuda_print_device_info(void)
{
    int device_count = 0;
    cudaGetDeviceCount(&device_count);
    
    printf("\n====================================================================\n");
    printf("  CUDA Device Information\n");
    printf("====================================================================\n");
    
    if (device_count == 0) {
        printf("No CUDA devices found.\n");
        return;
    }
    
    for (int i = 0; i < device_count; ++i) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);
        
        printf("Device %d: %s\n", i, prop.name);
        printf("  Compute capability: %d.%d\n", prop.major, prop.minor);
        printf("  Total memory: %.2f GB\n", prop.totalGlobalMem / (1024.0 * 1024.0 * 1024.0));
        printf("  SM count: %d\n", prop.multiProcessorCount);
        printf("  Max threads per block: %d\n", prop.maxThreadsPerBlock);
        printf("  Warp size: %d\n", prop.warpSize);
        printf("  Memory clock rate: %.2f GHz\n", prop.memoryClockRate / 1e6);
        printf("  Memory bus width: %d bits\n", prop.memoryBusWidth);
        printf("\n");
    }
}
