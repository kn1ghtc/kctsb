/**
 * @file cuda_kernels.h
 * @brief CUDA Kernel Host API Declarations
 * 
 * @details Declares CUDA kernel wrapper functions callable from C/C++
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-26
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_CUDA_KERNELS_H
#define KCTSB_CUDA_KERNELS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Runtime Detection
 * ============================================================================ */

/**
 * @brief Check if CUDA runtime is available
 * @return true if CUDA device found, false otherwise
 */
bool kctsb_cuda_runtime_available(void);

/**
 * @brief Get CUDA device info
 * @param device_id CUDA device index (0-based)
 * @param name Output buffer for device name
 * @param name_len Size of name buffer
 * @param total_mem Output for total GPU memory in bytes
 * @param compute_cap_major Output for compute capability major version
 * @param compute_cap_minor Output for compute capability minor version
 * @return 0 on success, error code otherwise
 */
int kctsb_cuda_get_device_info(int device_id, char* name, size_t name_len,
                               size_t* total_mem, int* compute_cap_major,
                               int* compute_cap_minor);

/* ============================================================================
 * Memory Management
 * ============================================================================ */

/**
 * @brief Allocate GPU memory
 * @param ptr Output pointer to allocated GPU memory
 * @param size Size in bytes to allocate
 * @return 0 on success
 */
int kctsb_cuda_malloc(void** ptr, size_t size);

/**
 * @brief Free GPU memory
 * @param ptr GPU memory pointer to free
 * @return 0 on success
 */
int kctsb_cuda_free(void* ptr);

/**
 * @brief Copy data from host to device
 * @param dst Destination GPU pointer
 * @param src Source host pointer
 * @param size Size in bytes
 * @return 0 on success
 */
int kctsb_cuda_memcpy_h2d(void* dst, const void* src, size_t size);

/**
 * @brief Copy data from device to host
 * @param dst Destination host pointer
 * @param src Source GPU pointer
 * @param size Size in bytes
 * @return 0 on success
 */
int kctsb_cuda_memcpy_d2h(void* dst, const void* src, size_t size);

/* ============================================================================
 * NTT Operations
 * ============================================================================ */

/**
 * @brief Execute forward NTT on GPU
 * @param d_data GPU pointer to polynomial coefficients (in-place)
 * @param d_root_powers GPU pointer to twiddle factors
 * @param d_root_powers_shoup GPU pointer to Shoup precomputed values
 * @param modulus NTT modulus
 * @param log_n log2(polynomial degree)
 * @return 0 on success
 */
int kctsb_cuda_ntt_forward(
    uint64_t* d_data,
    const uint64_t* d_root_powers,
    const uint64_t* d_root_powers_shoup,
    uint64_t modulus,
    int log_n);

/**
 * @brief Execute inverse NTT on GPU
 * @param d_data GPU pointer to polynomial coefficients (in-place)
 * @param d_inv_root_powers GPU pointer to inverse twiddle factors
 * @param d_inv_root_powers_shoup GPU pointer to Shoup precomputed values
 * @param modulus NTT modulus
 * @param inv_n n^-1 mod modulus
 * @param inv_n_shoup Shoup precomputed for inv_n
 * @param log_n log2(polynomial degree)
 * @return 0 on success
 */
int kctsb_cuda_ntt_inverse(
    uint64_t* d_data,
    const uint64_t* d_inv_root_powers,
    const uint64_t* d_inv_root_powers_shoup,
    uint64_t modulus,
    uint64_t inv_n,
    uint64_t inv_n_shoup,
    int log_n);

/* ============================================================================
 * Polynomial Operations
 * ============================================================================ */

/**
 * @brief Pointwise polynomial multiplication in NTT domain
 * @param d_result GPU pointer for result
 * @param d_a First polynomial (NTT form)
 * @param d_b Second polynomial (NTT form)
 * @param modulus Coefficient modulus
 * @param barrett_k Barrett constant for modulus
 * @param n Polynomial degree
 * @return 0 on success
 */
int kctsb_cuda_poly_multiply(
    uint64_t* d_result,
    const uint64_t* d_a,
    const uint64_t* d_b,
    uint64_t modulus,
    uint64_t barrett_k,
    size_t n);

/* ============================================================================
 * PIR Operations
 * ============================================================================ */

/**
 * @brief Execute PIR inner product on GPU
 * @param d_result GPU pointer for result polynomial
 * @param d_db GPU pointer to database (db_size * n coefficients)
 * @param d_query GPU pointer to query selection vector
 * @param modulus Coefficient modulus
 * @param barrett_k Barrett constant
 * @param n Polynomial degree
 * @param db_size Number of database entries
 * @return 0 on success
 */
int kctsb_cuda_pir_inner_product(
    uint64_t* d_result,
    const uint64_t* d_db,
    const uint64_t* d_query,
    uint64_t modulus,
    uint64_t barrett_k,
    size_t n,
    size_t db_size);

/* ============================================================================
 * Stream Management
 * ============================================================================ */

/**
 * @brief Create CUDA stream for async operations
 * @param stream_ptr Output pointer to stream context
 * @return 0 on success
 */
int kctsb_cuda_stream_create(void** stream_ptr);

/**
 * @brief Destroy CUDA stream
 * @param stream_ptr Stream context to destroy
 * @return 0 on success
 */
int kctsb_cuda_stream_destroy(void* stream_ptr);

/**
 * @brief Synchronize CUDA stream
 * @param stream_ptr Stream context to synchronize
 * @return 0 on success
 */
int kctsb_cuda_stream_sync(void* stream_ptr);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_CUDA_KERNELS_H */
