/**
 * @file cuda_api.h
 * @brief CUDA Acceleration Public API for kctsb
 * 
 * @details Unified C API for all GPU-accelerated operations:
 * - NTT/INTT with Harvey lazy reduction
 * - FHE polynomial operations (BGV/BFV/CKKS)
 * - PIR inner products
 * 
 * @author kn1ghtc
 * @version 4.15.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_CUDA_API_H
#define KCTSB_CUDA_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Error Codes
// ============================================================================

#define KCTSB_CUDA_SUCCESS           0
#define KCTSB_CUDA_ERROR_NO_DEVICE  -1
#define KCTSB_CUDA_ERROR_ALLOC      -2
#define KCTSB_CUDA_ERROR_MEMCPY     -3
#define KCTSB_CUDA_ERROR_KERNEL     -4
#define KCTSB_CUDA_ERROR_INVALID    -5

// ============================================================================
// Device Management
// ============================================================================

/**
 * @brief Check if CUDA runtime is available
 * @return 1 if available, 0 otherwise
 */
int kctsb_cuda_available(void);

/**
 * @brief Get number of CUDA devices
 * @param[out] count Number of devices
 * @return Error code
 */
int kctsb_cuda_device_count(int* count);

/**
 * @brief Get CUDA device information
 * @param device_id Device ID
 * @param[out] name Device name buffer
 * @param name_len Maximum name length
 * @param[out] total_mem Total memory in bytes
 * @param[out] sm_major Compute capability major version
 * @param[out] sm_minor Compute capability minor version
 * @param[out] sm_count Number of streaming multiprocessors
 * @return Error code
 */
int kctsb_cuda_device_info(int device_id, char* name, size_t name_len,
                           size_t* total_mem, int* sm_major, int* sm_minor,
                           int* sm_count);

// ============================================================================
// Memory Management
// ============================================================================

/**
 * @brief Allocate GPU memory
 */
int kctsb_cuda_malloc(void** ptr, size_t size);

/**
 * @brief Free GPU memory
 */
int kctsb_cuda_free(void* ptr);

/**
 * @brief Copy host to device
 */
int kctsb_cuda_memcpy_h2d(void* dst, const void* src, size_t size);

/**
 * @brief Copy device to host
 */
int kctsb_cuda_memcpy_d2h(void* dst, const void* src, size_t size);

// ============================================================================
// NTT Operations (Core for all FHE schemes)
// ============================================================================

/**
 * @brief Precompute NTT tables for a given modulus
 * 
 * @param n Polynomial degree (must be power of 2)
 * @param modulus NTT-friendly prime (q ≡ 1 mod 2n)
 * @param[out] d_root_powers Device pointer to forward root powers
 * @param[out] d_root_powers_shoup Device pointer to Shoup precomputed values
 * @param[out] d_inv_root_powers Device pointer to inverse root powers
 * @param[out] d_inv_root_powers_shoup Device pointer to inverse Shoup values
 * @return Error code
 */
int kctsb_cuda_ntt_precompute(size_t n, uint64_t modulus,
                              uint64_t** d_root_powers,
                              uint64_t** d_root_powers_shoup,
                              uint64_t** d_inv_root_powers,
                              uint64_t** d_inv_root_powers_shoup);

/**
 * @brief Forward NTT transform (Harvey algorithm with lazy reduction)
 * 
 * @param d_data Device pointer to polynomial coefficients (in-place)
 * @param d_root_powers Device pointer to precomputed root powers
 * @param d_root_powers_shoup Device pointer to Shoup precomputed values
 * @param modulus Prime modulus
 * @param log_n log2(polynomial degree)
 * @return Error code
 */
int kctsb_cuda_ntt_forward(uint64_t* d_data,
                           const uint64_t* d_root_powers,
                           const uint64_t* d_root_powers_shoup,
                           uint64_t modulus, int log_n);

/**
 * @brief Inverse NTT transform
 * 
 * @param d_data Device pointer to NTT coefficients (in-place)
 * @param d_inv_root_powers Device pointer to inverse root powers
 * @param d_inv_root_powers_shoup Device pointer to inverse Shoup values
 * @param modulus Prime modulus
 * @param inv_n Precomputed n^{-1} mod modulus
 * @param inv_n_shoup Shoup value for inv_n
 * @param log_n log2(polynomial degree)
 * @return Error code
 */
int kctsb_cuda_ntt_inverse(uint64_t* d_data,
                           const uint64_t* d_inv_root_powers,
                           const uint64_t* d_inv_root_powers_shoup,
                           uint64_t modulus,
                           uint64_t inv_n, uint64_t inv_n_shoup,
                           int log_n);

// ============================================================================
// RNS Polynomial Operations (Multi-limb for large modulus chain)
// ============================================================================

/**
 * @brief Forward NTT on RNS polynomial (all limbs)
 * 
 * @param d_rns_poly Device pointer to RNS polynomial [L][n]
 * @param d_ntt_tables Device pointer to NTT tables for each limb
 * @param n Polynomial degree
 * @param L Number of RNS limbs
 * @return Error code
 */
int kctsb_cuda_rns_ntt_forward(uint64_t* d_rns_poly,
                               const void* d_ntt_tables,
                               size_t n, size_t L);

/**
 * @brief Inverse NTT on RNS polynomial (all limbs)
 */
int kctsb_cuda_rns_ntt_inverse(uint64_t* d_rns_poly,
                               const void* d_ntt_tables,
                               size_t n, size_t L);

/**
 * @brief Pointwise RNS polynomial multiplication in NTT domain
 */
int kctsb_cuda_rns_poly_mul_ntt(uint64_t* d_result,
                                const uint64_t* d_a,
                                const uint64_t* d_b,
                                const uint64_t* d_moduli,
                                size_t n, size_t L);

/**
 * @brief RNS polynomial addition
 */
int kctsb_cuda_rns_poly_add(uint64_t* d_result,
                            const uint64_t* d_a,
                            const uint64_t* d_b,
                            const uint64_t* d_moduli,
                            size_t n, size_t L);

/**
 * @brief RNS polynomial subtraction
 */
int kctsb_cuda_rns_poly_sub(uint64_t* d_result,
                            const uint64_t* d_a,
                            const uint64_t* d_b,
                            const uint64_t* d_moduli,
                            size_t n, size_t L);

// ============================================================================
// FHE Ciphertext Operations
// ============================================================================

/**
 * @brief BFV/BGV ciphertext addition: (c0, c1) + (d0, d1)
 */
int kctsb_cuda_fhe_ct_add(uint64_t* d_ct0_out, uint64_t* d_ct1_out,
                          const uint64_t* d_ct0_a, const uint64_t* d_ct1_a,
                          const uint64_t* d_ct0_b, const uint64_t* d_ct1_b,
                          const uint64_t* d_moduli,
                          size_t n, size_t L);

/**
 * @brief BFV/BGV ciphertext multiplication (before relinearization)
 * 
 * Computes tensor product:
 *   c0' = c0_a * c0_b
 *   c1' = c0_a * c1_b + c1_a * c0_b
 *   c2' = c1_a * c1_b
 * 
 * All operations in NTT domain.
 */
int kctsb_cuda_fhe_ct_mul_tensor(uint64_t* d_ct0_out,
                                 uint64_t* d_ct1_out,
                                 uint64_t* d_ct2_out,
                                 const uint64_t* d_ct0_a, const uint64_t* d_ct1_a,
                                 const uint64_t* d_ct0_b, const uint64_t* d_ct1_b,
                                 const uint64_t* d_moduli,
                                 size_t n, size_t L);

/**
 * @brief BFV/BGV relinearization: reduce degree-3 to degree-2 ciphertext
 */
int kctsb_cuda_fhe_relin(uint64_t* d_ct0_out, uint64_t* d_ct1_out,
                         const uint64_t* d_ct0, const uint64_t* d_ct1,
                         const uint64_t* d_ct2,
                         const uint64_t* d_relin_key,
                         const uint64_t* d_moduli,
                         size_t n, size_t L);

// ============================================================================
// PIR/PSI Operations
// ============================================================================

/**
 * @brief PIR inner product: result = sum_i (db[i] * query[i])
 */
int kctsb_cuda_pir_inner_product(uint64_t* d_result,
                                 const uint64_t* d_db,
                                 const uint64_t* d_query,
                                 uint64_t modulus,
                                 size_t n, size_t db_size);

// ============================================================================
// Stream Management (for async operations)
// ============================================================================

/**
 * @brief Create a CUDA stream
 */
int kctsb_cuda_stream_create(void** stream);

/**
 * @brief Destroy a CUDA stream
 */
int kctsb_cuda_stream_destroy(void* stream);

/**
 * @brief Synchronize a CUDA stream
 */
int kctsb_cuda_stream_sync(void* stream);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_CUDA_API_H */
