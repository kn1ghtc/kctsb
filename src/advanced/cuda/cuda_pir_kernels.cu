/**
 * @file cuda_pir_kernels.cu
 * @brief CUDA PIR/PSI Acceleration Kernels
 * 
 * @details GPU-accelerated operations for Private Information Retrieval:
 * - PIR inner product computation
 * - Batch query processing
 * - Database expansion
 * 
 * Migrated from src/advanced/psi/cuda/pir_cuda_kernels.cu
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

constexpr int PIR_BLOCK_SIZE = 256;

// ============================================================================
// CUDA Error Checking
// ============================================================================

#define CUDA_CHECK_PIR(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            fprintf(stderr, "[CUDA PIR Error] %s:%d - %s\n", \
                    __FILE__, __LINE__, cudaGetErrorString(err)); \
            return KCTSB_CUDA_ERROR_KERNEL; \
        } \
    } while(0)

// ============================================================================
// Device Helper Functions
// ============================================================================

/**
 * @brief Barrett modular multiplication
 */
__device__ __forceinline__ uint64_t mulmod_barrett_pir(
    uint64_t a, uint64_t b, uint64_t modulus, uint64_t barrett_k)
{
    uint64_t lo, hi;
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));
    
    uint64_t q = __umul64hi(hi, barrett_k);
    uint64_t r = lo - q * modulus;
    
    if (r >= modulus) r -= modulus;
    return r;
}

// ============================================================================
// PIR Inner Product Kernel
// ============================================================================

/**
 * @brief PIR inner product: result = sum_i (db[i] * query[i])
 * 
 * Computes encrypted inner product for PIR response.
 * Each block computes one output coefficient using parallel reduction.
 * 
 * @param result Output polynomial (n coefficients)
 * @param db_coeffs Database polynomials [db_size][n]
 * @param query_coeffs Query coefficients [db_size]
 * @param modulus Prime modulus
 * @param barrett_k Barrett precomputed constant
 * @param n Polynomial degree
 * @param db_size Number of database entries
 */
__global__ void pir_inner_product_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ db_coeffs,
    const uint64_t* __restrict__ query_coeffs,
    uint64_t modulus,
    uint64_t barrett_k,
    size_t n,
    size_t db_size)
{
    extern __shared__ uint64_t sdata[];
    
    size_t tid = threadIdx.x;
    size_t coeff_idx = blockIdx.x;
    
    if (coeff_idx >= n) return;
    
    // Each thread accumulates part of the sum
    uint64_t local_sum = 0;
    for (size_t i = tid; i < db_size; i += blockDim.x) {
        uint64_t db_val = db_coeffs[i * n + coeff_idx];
        uint64_t q_val = query_coeffs[i];
        local_sum += mulmod_barrett_pir(db_val, q_val, modulus, barrett_k);
        if (local_sum >= 2 * modulus) local_sum -= modulus;
    }
    
    sdata[tid] = local_sum;
    __syncthreads();
    
    // Parallel reduction
    for (unsigned s = blockDim.x / 2; s > 0; s >>= 1) {
        if (tid < s) {
            sdata[tid] += sdata[tid + s];
            if (sdata[tid] >= modulus) sdata[tid] -= modulus;
        }
        __syncthreads();
    }
    
    if (tid == 0) {
        result[coeff_idx] = sdata[0] % modulus;
    }
}

/**
 * @brief Batch PIR: process multiple queries simultaneously
 * 
 * Processes multiple PIR queries in parallel for better GPU utilization.
 */
__global__ void pir_batch_inner_product_kernel(
    uint64_t* __restrict__ results,      // [batch_size][n]
    const uint64_t* __restrict__ db_coeffs,    // [db_size][n]
    const uint64_t* __restrict__ queries,       // [batch_size][db_size]
    uint64_t modulus,
    uint64_t barrett_k,
    size_t n,
    size_t db_size,
    size_t batch_size)
{
    extern __shared__ uint64_t sdata[];
    
    size_t tid = threadIdx.x;
    size_t coeff_idx = blockIdx.x % n;
    size_t query_idx = blockIdx.x / n;
    
    if (query_idx >= batch_size) return;
    
    const uint64_t* query = queries + query_idx * db_size;
    uint64_t* result = results + query_idx * n;
    
    uint64_t local_sum = 0;
    for (size_t i = tid; i < db_size; i += blockDim.x) {
        uint64_t db_val = db_coeffs[i * n + coeff_idx];
        uint64_t q_val = query[i];
        local_sum += mulmod_barrett_pir(db_val, q_val, modulus, barrett_k);
        if (local_sum >= 2 * modulus) local_sum -= modulus;
    }
    
    sdata[tid] = local_sum;
    __syncthreads();
    
    for (unsigned s = blockDim.x / 2; s > 0; s >>= 1) {
        if (tid < s) {
            sdata[tid] += sdata[tid + s];
            if (sdata[tid] >= modulus) sdata[tid] -= modulus;
        }
        __syncthreads();
    }
    
    if (tid == 0) {
        result[coeff_idx] = sdata[0] % modulus;
    }
}

// ============================================================================
// Host API Implementation
// ============================================================================

extern "C" {

int kctsb_cuda_pir_inner_product(
    uint64_t* d_result,
    const uint64_t* d_db,
    const uint64_t* d_query,
    uint64_t modulus,
    size_t n,
    size_t db_size)
{
    // Compute Barrett constant: floor(2^64 / modulus)
    uint64_t barrett_k = (uint64_t)(-1) / modulus;
    
    size_t shared_mem = PIR_BLOCK_SIZE * sizeof(uint64_t);
    pir_inner_product_kernel<<<(unsigned int)n, PIR_BLOCK_SIZE, shared_mem>>>(
        d_result, d_db, d_query, modulus, barrett_k, n, db_size
    );
    CUDA_CHECK_PIR(cudaDeviceSynchronize());
    return KCTSB_CUDA_SUCCESS;
}

} // extern "C"
