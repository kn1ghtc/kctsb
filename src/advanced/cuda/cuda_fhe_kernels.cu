/**
 * @file cuda_fhe_kernels.cu
 * @brief CUDA FHE Kernels for BGV/BFV/CKKS Operations
 * 
 * @details GPU-accelerated FHE ciphertext operations:
 * - Ciphertext addition/subtraction
 * - Tensor product multiplication
 * - Relinearization key switching
 * - RNS base extension (BEHZ)
 * 
 * All operations work on RNS representation for efficiency.
 * 
 * @author kn1ghtc
 * @version 4.15.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <cstdint>
#include <cstdio>
#include "cuda_api.h"

// ============================================================================
// Constants
// ============================================================================

constexpr int FHE_BLOCK_SIZE = 256;

// ============================================================================
// CUDA Error Checking
// ============================================================================

#define CUDA_CHECK_FHE(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            fprintf(stderr, "[CUDA FHE Error] %s:%d - %s\n", \
                    __FILE__, __LINE__, cudaGetErrorString(err)); \
            return KCTSB_CUDA_ERROR_KERNEL; \
        } \
    } while(0)

// ============================================================================
// Device Helper Functions
// ============================================================================

/**
 * @brief 128-bit modular multiplication using PTX
 */
__device__ __forceinline__ uint64_t mulmod_device(uint64_t a, uint64_t b, uint64_t mod)
{
    uint64_t lo, hi;
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));
    
    if (hi == 0) {
        return lo % mod;
    }
    
    // Use double-precision approximation for quotient
    double dmod = (double)mod;
    double dprod = (double)hi * 18446744073709551616.0 + (double)lo;
    uint64_t q = (uint64_t)(dprod / dmod);
    
    // Compute remainder
    uint64_t q_lo, q_hi;
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(q_lo) : "l"(q), "l"(mod));
    
    uint64_t r = lo - q_lo;
    if (lo < q_lo) r += mod;
    while (r >= mod) r -= mod;
    return r;
}

/**
 * @brief Modular addition
 */
__device__ __forceinline__ uint64_t addmod_device(uint64_t a, uint64_t b, uint64_t mod)
{
    uint64_t sum = a + b;
    return (sum >= mod) ? (sum - mod) : sum;
}

/**
 * @brief Modular subtraction  
 */
__device__ __forceinline__ uint64_t submod_device(uint64_t a, uint64_t b, uint64_t mod)
{
    return (a >= b) ? (a - b) : (a + mod - b);
}

/**
 * @brief Modular negation
 */
__device__ __forceinline__ uint64_t negmod_device(uint64_t a, uint64_t mod)
{
    return (a == 0) ? 0 : (mod - a);
}

// ============================================================================
// RNS Polynomial Addition/Subtraction Kernels
// ============================================================================

/**
 * @brief RNS polynomial addition: result[l][i] = (a[l][i] + b[l][i]) mod q[l]
 * 
 * 2D grid: x = coefficient index, y = limb index
 */
__global__ void rns_poly_add_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    const uint64_t* __restrict__ moduli,
    size_t n,
    size_t L)
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t l = blockIdx.y;
    
    if (i >= n || l >= L) return;
    
    size_t idx = l * n + i;
    uint64_t q = moduli[l];
    uint64_t sum = a[idx] + b[idx];
    result[idx] = (sum >= q) ? (sum - q) : sum;
}

/**
 * @brief RNS polynomial subtraction
 */
__global__ void rns_poly_sub_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    const uint64_t* __restrict__ moduli,
    size_t n,
    size_t L)
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t l = blockIdx.y;
    
    if (i >= n || l >= L) return;
    
    size_t idx = l * n + i;
    uint64_t q = moduli[l];
    uint64_t av = a[idx];
    uint64_t bv = b[idx];
    result[idx] = (av >= bv) ? (av - bv) : (av + q - bv);
}

/**
 * @brief RNS polynomial pointwise multiplication (NTT domain)
 */
__global__ void rns_poly_mul_ntt_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    const uint64_t* __restrict__ moduli,
    size_t n,
    size_t L)
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t l = blockIdx.y;
    
    if (i >= n || l >= L) return;
    
    size_t idx = l * n + i;
    uint64_t q = moduli[l];
    result[idx] = mulmod_device(a[idx], b[idx], q);
}

// ============================================================================
// FHE Ciphertext Operations
// ============================================================================

/**
 * @brief Ciphertext addition: (c0_out, c1_out) = (c0_a + c0_b, c1_a + c1_b)
 * 
 * Both ciphertexts must be at the same level (same number of RNS limbs).
 */
__global__ void fhe_ct_add_kernel(
    uint64_t* __restrict__ ct0_out,
    uint64_t* __restrict__ ct1_out,
    const uint64_t* __restrict__ ct0_a,
    const uint64_t* __restrict__ ct1_a,
    const uint64_t* __restrict__ ct0_b,
    const uint64_t* __restrict__ ct1_b,
    const uint64_t* __restrict__ moduli,
    size_t n,
    size_t L)
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t l = blockIdx.y;
    
    if (i >= n || l >= L) return;
    
    size_t idx = l * n + i;
    uint64_t q = moduli[l];
    
    // Add c0 components
    uint64_t sum0 = ct0_a[idx] + ct0_b[idx];
    ct0_out[idx] = (sum0 >= q) ? (sum0 - q) : sum0;
    
    // Add c1 components
    uint64_t sum1 = ct1_a[idx] + ct1_b[idx];
    ct1_out[idx] = (sum1 >= q) ? (sum1 - q) : sum1;
}

/**
 * @brief Ciphertext tensor product for multiplication
 * 
 * Input: (c0_a, c1_a), (c0_b, c1_b) - both in NTT domain
 * Output: (c0', c1', c2') where:
 *   c0' = c0_a * c0_b
 *   c1' = c0_a * c1_b + c1_a * c0_b  
 *   c2' = c1_a * c1_b
 */
__global__ void fhe_ct_mul_tensor_kernel(
    uint64_t* __restrict__ ct0_out,
    uint64_t* __restrict__ ct1_out,
    uint64_t* __restrict__ ct2_out,
    const uint64_t* __restrict__ ct0_a,
    const uint64_t* __restrict__ ct1_a,
    const uint64_t* __restrict__ ct0_b,
    const uint64_t* __restrict__ ct1_b,
    const uint64_t* __restrict__ moduli,
    size_t n,
    size_t L)
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t l = blockIdx.y;
    
    if (i >= n || l >= L) return;
    
    size_t idx = l * n + i;
    uint64_t q = moduli[l];
    
    uint64_t c0a = ct0_a[idx];
    uint64_t c1a = ct1_a[idx];
    uint64_t c0b = ct0_b[idx];
    uint64_t c1b = ct1_b[idx];
    
    // c0' = c0_a * c0_b
    ct0_out[idx] = mulmod_device(c0a, c0b, q);
    
    // c1' = c0_a * c1_b + c1_a * c0_b
    uint64_t term1 = mulmod_device(c0a, c1b, q);
    uint64_t term2 = mulmod_device(c1a, c0b, q);
    ct1_out[idx] = addmod_device(term1, term2, q);
    
    // c2' = c1_a * c1_b
    ct2_out[idx] = mulmod_device(c1a, c1b, q);
}

/**
 * @brief Simple relinearization (no decomposition, for testing)
 * 
 * Reduces (c0, c1, c2) to (c0', c1') using:
 *   c0' = c0 + c2 * ksk0
 *   c1' = c1 + c2 * ksk1
 * 
 * where ksk0 + ksk1 * s = s^2
 */
__global__ void fhe_relin_simple_kernel(
    uint64_t* __restrict__ ct0_out,
    uint64_t* __restrict__ ct1_out,
    const uint64_t* __restrict__ ct0,
    const uint64_t* __restrict__ ct1,
    const uint64_t* __restrict__ ct2,
    const uint64_t* __restrict__ ksk0,
    const uint64_t* __restrict__ ksk1,
    const uint64_t* __restrict__ moduli,
    size_t n,
    size_t L)
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t l = blockIdx.y;
    
    if (i >= n || l >= L) return;
    
    size_t idx = l * n + i;
    uint64_t q = moduli[l];
    
    uint64_t c2_val = ct2[idx];
    
    // c0' = c0 + c2 * ksk0
    uint64_t term0 = mulmod_device(c2_val, ksk0[idx], q);
    ct0_out[idx] = addmod_device(ct0[idx], term0, q);
    
    // c1' = c1 + c2 * ksk1
    uint64_t term1 = mulmod_device(c2_val, ksk1[idx], q);
    ct1_out[idx] = addmod_device(ct1[idx], term1, q);
}

// ============================================================================
// CKKS-Specific Operations
// ============================================================================

/**
 * @brief CKKS rescaling: drop last RNS limb and scale by q_L^{-1}
 * 
 * This reduces noise after multiplication in CKKS.
 */
__global__ void ckks_rescale_kernel(
    uint64_t* __restrict__ ct_out,
    const uint64_t* __restrict__ ct_in,
    const uint64_t* __restrict__ q_inv_last,  // q_L^{-1} mod q_i for each limb
    const uint64_t* __restrict__ moduli,
    size_t n,
    size_t L_new)  // L - 1
{
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t l = blockIdx.y;
    
    if (i >= n || l >= L_new) return;
    
    size_t idx_in = l * n + i;
    size_t idx_out = l * n + i;
    uint64_t q = moduli[l];
    
    // Scale by q_L^{-1} mod q_l
    ct_out[idx_out] = mulmod_device(ct_in[idx_in], q_inv_last[l], q);
}

// ============================================================================
// Host API Implementation
// ============================================================================

extern "C" {

int kctsb_cuda_rns_poly_add(
    uint64_t* d_result,
    const uint64_t* d_a,
    const uint64_t* d_b,
    const uint64_t* d_moduli,
    size_t n,
    size_t L)
{
    dim3 block(FHE_BLOCK_SIZE);
    dim3 grid(((unsigned int)n + FHE_BLOCK_SIZE - 1) / FHE_BLOCK_SIZE, (unsigned int)L);
    
    rns_poly_add_kernel<<<grid, block>>>(d_result, d_a, d_b, d_moduli, n, L);
    CUDA_CHECK_FHE(cudaDeviceSynchronize());
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_rns_poly_sub(
    uint64_t* d_result,
    const uint64_t* d_a,
    const uint64_t* d_b,
    const uint64_t* d_moduli,
    size_t n,
    size_t L)
{
    dim3 block(FHE_BLOCK_SIZE);
    dim3 grid(((unsigned int)n + FHE_BLOCK_SIZE - 1) / FHE_BLOCK_SIZE, (unsigned int)L);
    
    rns_poly_sub_kernel<<<grid, block>>>(d_result, d_a, d_b, d_moduli, n, L);
    CUDA_CHECK_FHE(cudaDeviceSynchronize());
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_rns_poly_mul_ntt(
    uint64_t* d_result,
    const uint64_t* d_a,
    const uint64_t* d_b,
    const uint64_t* d_moduli,
    size_t n,
    size_t L)
{
    dim3 block(FHE_BLOCK_SIZE);
    dim3 grid(((unsigned int)n + FHE_BLOCK_SIZE - 1) / FHE_BLOCK_SIZE, (unsigned int)L);
    
    rns_poly_mul_ntt_kernel<<<grid, block>>>(d_result, d_a, d_b, d_moduli, n, L);
    CUDA_CHECK_FHE(cudaDeviceSynchronize());
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_fhe_ct_add(
    uint64_t* d_ct0_out,
    uint64_t* d_ct1_out,
    const uint64_t* d_ct0_a,
    const uint64_t* d_ct1_a,
    const uint64_t* d_ct0_b,
    const uint64_t* d_ct1_b,
    const uint64_t* d_moduli,
    size_t n,
    size_t L)
{
    dim3 block(FHE_BLOCK_SIZE);
    dim3 grid(((unsigned int)n + FHE_BLOCK_SIZE - 1) / FHE_BLOCK_SIZE, (unsigned int)L);
    
    fhe_ct_add_kernel<<<grid, block>>>(
        d_ct0_out, d_ct1_out,
        d_ct0_a, d_ct1_a,
        d_ct0_b, d_ct1_b,
        d_moduli, n, L
    );
    CUDA_CHECK_FHE(cudaDeviceSynchronize());
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_fhe_ct_mul_tensor(
    uint64_t* d_ct0_out,
    uint64_t* d_ct1_out,
    uint64_t* d_ct2_out,
    const uint64_t* d_ct0_a,
    const uint64_t* d_ct1_a,
    const uint64_t* d_ct0_b,
    const uint64_t* d_ct1_b,
    const uint64_t* d_moduli,
    size_t n,
    size_t L)
{
    dim3 block(FHE_BLOCK_SIZE);
    dim3 grid(((unsigned int)n + FHE_BLOCK_SIZE - 1) / FHE_BLOCK_SIZE, (unsigned int)L);
    
    fhe_ct_mul_tensor_kernel<<<grid, block>>>(
        d_ct0_out, d_ct1_out, d_ct2_out,
        d_ct0_a, d_ct1_a,
        d_ct0_b, d_ct1_b,
        d_moduli, n, L
    );
    CUDA_CHECK_FHE(cudaDeviceSynchronize());
    return KCTSB_CUDA_SUCCESS;
}

int kctsb_cuda_fhe_relin(
    uint64_t* d_ct0_out,
    uint64_t* d_ct1_out,
    const uint64_t* d_ct0,
    const uint64_t* d_ct1,
    const uint64_t* d_ct2,
    const uint64_t* d_relin_key,
    const uint64_t* d_moduli,
    size_t n,
    size_t L)
{
    // relin_key layout: [ksk0][ksk1] each of size L*n
    const uint64_t* d_ksk0 = d_relin_key;
    const uint64_t* d_ksk1 = d_relin_key + L * n;
    
    dim3 block(FHE_BLOCK_SIZE);
    dim3 grid(((unsigned int)n + FHE_BLOCK_SIZE - 1) / FHE_BLOCK_SIZE, (unsigned int)L);
    
    fhe_relin_simple_kernel<<<grid, block>>>(
        d_ct0_out, d_ct1_out,
        d_ct0, d_ct1, d_ct2,
        d_ksk0, d_ksk1,
        d_moduli, n, L
    );
    CUDA_CHECK_FHE(cudaDeviceSynchronize());
    return KCTSB_CUDA_SUCCESS;
}

} // extern "C"
