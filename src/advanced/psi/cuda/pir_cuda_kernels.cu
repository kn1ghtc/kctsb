/**
 * @file pir_cuda_kernels.cu
 * @brief CUDA GPU Kernels for PIR Acceleration
 * 
 * @details Implements GPU-accelerated NTT, INTT, and homomorphic operations
 * 
 * Key Optimizations:
 * - Harvey NTT with lazy reduction on GPU
 * - Coalesced memory access patterns
 * - Shared memory for butterfly operations
 * - CUDA streams for overlapped computation
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-26
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <cstdint>
#include <cstdio>

// ============================================================================
// CUDA Error Checking
// ============================================================================

#define CUDA_CHECK(call) \
    do { \
        cudaError_t err = call; \
        if (err != cudaSuccess) { \
            fprintf(stderr, "CUDA Error at %s:%d - %s\n", \
                    __FILE__, __LINE__, cudaGetErrorString(err)); \
            return err; \
        } \
    } while(0)

// ============================================================================
// Constants
// ============================================================================

// Maximum polynomial degree supported
constexpr size_t MAX_POLY_DEGREE = 32768;

// Threads per block for NTT operations
constexpr int NTT_BLOCK_SIZE = 256;

// Shared memory per block (48KB typical)
constexpr size_t SHARED_MEM_SIZE = 49152;

// ============================================================================
// Device Helper Functions
// ============================================================================

/**
 * @brief Modular multiplication using Barrett reduction (device)
 */
__device__ __forceinline__ uint64_t mulmod_barrett(
    uint64_t a, uint64_t b, uint64_t modulus, uint64_t barrett_k)
{
    // Full 128-bit product using PTX intrinsics
    uint64_t lo, hi;
    asm("mul.lo.u64 %0, %1, %2;" : "=l"(lo) : "l"(a), "l"(b));
    asm("mul.hi.u64 %0, %1, %2;" : "=l"(hi) : "l"(a), "l"(b));
    
    // Barrett reduction: q = floor(a*b / 2^k) * m, result = a*b - q
    uint64_t q = __umul64hi(hi, barrett_k);
    uint64_t r = lo - q * modulus;
    
    // Conditional reduction
    if (r >= modulus) r -= modulus;
    return r;
}

/**
 * @brief Modular subtraction with lazy reduction
 */
__device__ __forceinline__ uint64_t submod_lazy(
    uint64_t a, uint64_t b, uint64_t twice_mod)
{
    return (a >= b) ? (a - b) : (a + twice_mod - b);
}

/**
 * @brief Modular addition with lazy reduction
 */
__device__ __forceinline__ uint64_t addmod_lazy(
    uint64_t a, uint64_t b, uint64_t twice_mod)
{
    uint64_t sum = a + b;
    return (sum >= twice_mod) ? (sum - twice_mod) : sum;
}

// ============================================================================
// NTT Kernels (Cooley-Tukey, bit-reversal in-place)
// ============================================================================

/**
 * @brief Forward NTT kernel for single RNS level
 * 
 * Implements Cooley-Tukey FFT butterfly with Harvey lazy reduction.
 * Uses shared memory for small transforms, global memory for large.
 */
__global__ void ntt_forward_kernel(
    uint64_t* __restrict__ data,
    const uint64_t* __restrict__ root_powers,
    const uint64_t* __restrict__ root_powers_shoup,
    uint64_t modulus,
    uint64_t twice_modulus,
    int log_n,
    int stage)
{
    const size_t n = 1ULL << log_n;
    const size_t m = 1ULL << stage;        // Number of groups
    const size_t half_m = m >> 1;          // Elements per group / 2
    
    // Global thread ID
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Each thread handles one butterfly
    if (tid >= n / 2) return;
    
    // Compute indices for this butterfly
    size_t group = tid / half_m;
    size_t j = tid % half_m;
    size_t i0 = group * m + j;
    size_t i1 = i0 + half_m;
    
    // Get root of unity for this stage
    size_t root_idx = (1ULL << (stage - 1)) + j;
    uint64_t w = root_powers[root_idx];
    uint64_t w_shoup = root_powers_shoup[root_idx];
    
    // Load operands
    uint64_t u = data[i0];
    uint64_t v = data[i1];
    
    // Harvey butterfly: v = v * w (mod q) using Shoup
    // Shoup multiplication: t = v * w_shoup >> 64; r = v * w - t * q
    uint64_t q = __umul64hi(v, w_shoup);
    uint64_t t = v * w - q * modulus;
    if (t >= modulus) t -= modulus;
    
    // Butterfly computation
    data[i0] = addmod_lazy(u, t, twice_modulus);
    data[i1] = submod_lazy(u, t, twice_modulus);
}

/**
 * @brief Inverse NTT kernel for single RNS level
 * 
 * Implements Gentleman-Sande INTT butterfly.
 */
__global__ void ntt_inverse_kernel(
    uint64_t* __restrict__ data,
    const uint64_t* __restrict__ inv_root_powers,
    const uint64_t* __restrict__ inv_root_powers_shoup,
    uint64_t modulus,
    uint64_t twice_modulus,
    uint64_t inv_n,
    uint64_t inv_n_shoup,
    int log_n,
    int stage)
{
    const size_t n = 1ULL << log_n;
    const size_t m = 1ULL << (log_n - stage);  // Current stage size
    const size_t half_m = m >> 1;
    
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n / 2) return;
    
    size_t group = tid / half_m;
    size_t j = tid % half_m;
    size_t i0 = group * m + j;
    size_t i1 = i0 + half_m;
    
    // Get inverse root
    size_t root_idx = (1ULL << stage) + j;
    uint64_t w = inv_root_powers[root_idx];
    uint64_t w_shoup = inv_root_powers_shoup[root_idx];
    
    // Load operands
    uint64_t u = data[i0];
    uint64_t v = data[i1];
    
    // GS butterfly: add then multiply difference
    uint64_t sum = addmod_lazy(u, v, twice_modulus);
    uint64_t diff = submod_lazy(u, v, twice_modulus);
    
    // Multiply difference by inverse root
    uint64_t q = __umul64hi(diff, w_shoup);
    uint64_t t = diff * w - q * modulus;
    if (t >= modulus) t -= modulus;
    
    data[i0] = sum;
    data[i1] = t;
}

/**
 * @brief Final scaling for INTT (multiply by n^-1)
 */
__global__ void ntt_scale_kernel(
    uint64_t* __restrict__ data,
    uint64_t inv_n,
    uint64_t inv_n_shoup,
    uint64_t modulus,
    size_t n)
{
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    
    uint64_t val = data[tid];
    
    // Reduce if needed (after lazy reductions)
    if (val >= modulus) val -= modulus;
    if (val >= modulus) val -= modulus;
    
    // Multiply by n^-1
    uint64_t q = __umul64hi(val, inv_n_shoup);
    uint64_t t = val * inv_n - q * modulus;
    if (t >= modulus) t -= modulus;
    
    data[tid] = t;
}

// ============================================================================
// Polynomial Multiplication Kernel
// ============================================================================

/**
 * @brief Pointwise polynomial multiplication in NTT domain
 */
__global__ void poly_multiply_ntt_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    uint64_t modulus,
    uint64_t barrett_k,
    size_t n)
{
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    
    result[tid] = mulmod_barrett(a[tid], b[tid], modulus, barrett_k);
}

/**
 * @brief Polynomial addition
 */
__global__ void poly_add_kernel(
    uint64_t* __restrict__ result,
    const uint64_t* __restrict__ a,
    const uint64_t* __restrict__ b,
    uint64_t modulus,
    size_t n)
{
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    
    uint64_t sum = a[tid] + b[tid];
    result[tid] = (sum >= modulus) ? (sum - modulus) : sum;
}

// ============================================================================
// PIR-Specific Kernels
// ============================================================================

/**
 * @brief Inner product for PIR: sum_i (db[i] * query[i])
 * 
 * Computes encrypted inner product for PIR response.
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
    size_t coeff_idx = blockIdx.x;  // Which coefficient of result
    
    if (coeff_idx >= n) return;
    
    // Each thread accumulates part of the sum
    uint64_t local_sum = 0;
    for (size_t i = tid; i < db_size; i += blockDim.x) {
        uint64_t db_val = db_coeffs[i * n + coeff_idx];
        uint64_t q_val = query_coeffs[i];
        local_sum += mulmod_barrett(db_val, q_val, modulus, barrett_k);
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

// ============================================================================
// Host API Functions
// ============================================================================

extern "C" {

/**
 * @brief Check if CUDA runtime is available
 */
bool kctsb_cuda_runtime_available() {
    int device_count = 0;
    cudaError_t err = cudaGetDeviceCount(&device_count);
    return (err == cudaSuccess && device_count > 0);
}

/**
 * @brief Get CUDA device info
 */
int kctsb_cuda_get_device_info(int device_id, char* name, size_t name_len,
                               size_t* total_mem, int* compute_cap_major,
                               int* compute_cap_minor)
{
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device_id));
    
    if (name && name_len > 0) {
        strncpy(name, prop.name, name_len - 1);
        name[name_len - 1] = '\0';
    }
    if (total_mem) *total_mem = prop.totalGlobalMem;
    if (compute_cap_major) *compute_cap_major = prop.major;
    if (compute_cap_minor) *compute_cap_minor = prop.minor;
    
    return 0;
}

/**
 * @brief Allocate GPU memory
 */
int kctsb_cuda_malloc(void** ptr, size_t size) {
    CUDA_CHECK(cudaMalloc(ptr, size));
    return 0;
}

/**
 * @brief Free GPU memory
 */
int kctsb_cuda_free(void* ptr) {
    CUDA_CHECK(cudaFree(ptr));
    return 0;
}

/**
 * @brief Copy host to device
 */
int kctsb_cuda_memcpy_h2d(void* dst, const void* src, size_t size) {
    CUDA_CHECK(cudaMemcpy(dst, src, size, cudaMemcpyHostToDevice));
    return 0;
}

/**
 * @brief Copy device to host
 */
int kctsb_cuda_memcpy_d2h(void* dst, const void* src, size_t size) {
    CUDA_CHECK(cudaMemcpy(dst, src, size, cudaMemcpyDeviceToHost));
    return 0;
}

/**
 * @brief Execute forward NTT on GPU
 */
int kctsb_cuda_ntt_forward(
    uint64_t* d_data,
    const uint64_t* d_root_powers,
    const uint64_t* d_root_powers_shoup,
    uint64_t modulus,
    int log_n)
{
    size_t n = 1ULL << log_n;
    uint64_t twice_mod = 2 * modulus;
    
    // Launch NTT stages
    for (int stage = 1; stage <= log_n; ++stage) {
        int blocks = (n / 2 + NTT_BLOCK_SIZE - 1) / NTT_BLOCK_SIZE;
        ntt_forward_kernel<<<blocks, NTT_BLOCK_SIZE>>>(
            d_data, d_root_powers, d_root_powers_shoup,
            modulus, twice_mod, log_n, stage
        );
    }
    
    CUDA_CHECK(cudaDeviceSynchronize());
    return 0;
}

/**
 * @brief Execute inverse NTT on GPU
 */
int kctsb_cuda_ntt_inverse(
    uint64_t* d_data,
    const uint64_t* d_inv_root_powers,
    const uint64_t* d_inv_root_powers_shoup,
    uint64_t modulus,
    uint64_t inv_n,
    uint64_t inv_n_shoup,
    int log_n)
{
    size_t n = 1ULL << log_n;
    uint64_t twice_mod = 2 * modulus;
    
    // Launch INTT stages
    for (int stage = 1; stage <= log_n; ++stage) {
        int blocks = (n / 2 + NTT_BLOCK_SIZE - 1) / NTT_BLOCK_SIZE;
        ntt_inverse_kernel<<<blocks, NTT_BLOCK_SIZE>>>(
            d_data, d_inv_root_powers, d_inv_root_powers_shoup,
            modulus, twice_mod, inv_n, inv_n_shoup, log_n, stage
        );
    }
    
    // Final scaling by n^-1
    int blocks = (n + NTT_BLOCK_SIZE - 1) / NTT_BLOCK_SIZE;
    ntt_scale_kernel<<<blocks, NTT_BLOCK_SIZE>>>(
        d_data, inv_n, inv_n_shoup, modulus, n
    );
    
    CUDA_CHECK(cudaDeviceSynchronize());
    return 0;
}

/**
 * @brief Execute polynomial multiplication on GPU
 */
int kctsb_cuda_poly_multiply(
    uint64_t* d_result,
    const uint64_t* d_a,
    const uint64_t* d_b,
    uint64_t modulus,
    uint64_t barrett_k,
    size_t n)
{
    int blocks = (n + NTT_BLOCK_SIZE - 1) / NTT_BLOCK_SIZE;
    poly_multiply_ntt_kernel<<<blocks, NTT_BLOCK_SIZE>>>(
        d_result, d_a, d_b, modulus, barrett_k, n
    );
    CUDA_CHECK(cudaDeviceSynchronize());
    return 0;
}

/**
 * @brief Execute PIR inner product on GPU
 */
int kctsb_cuda_pir_inner_product(
    uint64_t* d_result,
    const uint64_t* d_db,
    const uint64_t* d_query,
    uint64_t modulus,
    uint64_t barrett_k,
    size_t n,
    size_t db_size)
{
    // One block per coefficient, each block reduces over db_size
    size_t shared_mem = NTT_BLOCK_SIZE * sizeof(uint64_t);
    pir_inner_product_kernel<<<n, NTT_BLOCK_SIZE, shared_mem>>>(
        d_result, d_db, d_query, modulus, barrett_k, n, db_size
    );
    CUDA_CHECK(cudaDeviceSynchronize());
    return 0;
}

}  // extern "C"

// ============================================================================
// Stream-based Async Operations (for pipelining)
// ============================================================================

struct CudaStreamContext {
    cudaStream_t stream;
    bool created;
};

extern "C" {

int kctsb_cuda_stream_create(void** stream_ptr) {
    auto* ctx = new CudaStreamContext;
    cudaError_t err = cudaStreamCreate(&ctx->stream);
    if (err != cudaSuccess) {
        delete ctx;
        return -1;
    }
    ctx->created = true;
    *stream_ptr = ctx;
    return 0;
}

int kctsb_cuda_stream_destroy(void* stream_ptr) {
    auto* ctx = static_cast<CudaStreamContext*>(stream_ptr);
    if (ctx && ctx->created) {
        cudaStreamDestroy(ctx->stream);
    }
    delete ctx;
    return 0;
}

int kctsb_cuda_stream_sync(void* stream_ptr) {
    auto* ctx = static_cast<CudaStreamContext*>(stream_ptr);
    if (ctx && ctx->created) {
        CUDA_CHECK(cudaStreamSynchronize(ctx->stream));
    }
    return 0;
}

}  // extern "C"
