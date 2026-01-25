/**
 * @file accelerator.h
 * @brief Hardware Acceleration Detection and Selection API
 *
 * @details Provides runtime detection of hardware acceleration capabilities
 * and automatic selection of optimal compute path:
 * 
 * Priority Order:
 * 1. CUDA GPU acceleration (if available and beneficial)
 * 2. AVX-512 CPU vectorization
 * 3. AVX2 CPU vectorization
 * 4. Scalar CPU fallback
 *
 * The accelerator automatically selects the best path based on:
 * - Hardware availability
 * - Problem size (GPU overhead vs speedup)
 * - Memory constraints
 *
 * @author knightc
 * @version 4.15.0
 * @date 2026-01-25
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_ACCELERATOR_H
#define KCTSB_ACCELERATOR_H

#include "kctsb/core/common.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Acceleration Backend Types
// ============================================================================

/**
 * @brief Enumeration of available acceleration backends
 */
typedef enum {
    KCTSB_ACCEL_NONE     = 0,  ///< No acceleration (scalar CPU)
    KCTSB_ACCEL_AVX2     = 1,  ///< AVX2 CPU vectorization
    KCTSB_ACCEL_AVX512   = 2,  ///< AVX-512 CPU vectorization
    KCTSB_ACCEL_CUDA     = 3,  ///< NVIDIA CUDA GPU
} kctsb_accel_backend_t;

/**
 * @brief Acceleration capability flags
 */
typedef enum {
    KCTSB_CAP_NONE       = 0,
    KCTSB_CAP_AVX2       = (1 << 0),  ///< AVX2 supported
    KCTSB_CAP_AVX512F    = (1 << 1),  ///< AVX-512F supported
    KCTSB_CAP_AVX512VL   = (1 << 2),  ///< AVX-512VL supported
    KCTSB_CAP_AVX512IFMA = (1 << 3),  ///< AVX-512IFMA supported (integer fma)
    KCTSB_CAP_AES_NI     = (1 << 4),  ///< AES-NI supported
    KCTSB_CAP_PCLMULQDQ  = (1 << 5),  ///< PCLMULQDQ supported
    KCTSB_CAP_CUDA       = (1 << 8),  ///< CUDA runtime available
} kctsb_accel_caps_t;

/**
 * @brief GPU device information
 */
typedef struct {
    int device_id;              ///< CUDA device ID
    char name[256];             ///< Device name
    size_t total_memory;        ///< Total GPU memory in bytes
    int sm_count;               ///< Number of streaming multiprocessors
    int compute_major;          ///< Compute capability major version
    int compute_minor;          ///< Compute capability minor version
} kctsb_gpu_info_t;

/**
 * @brief Accelerator context for a specific operation type
 */
typedef struct {
    kctsb_accel_backend_t backend;  ///< Selected backend
    kctsb_accel_caps_t caps;        ///< Available capabilities
    int gpu_device_id;              ///< Selected GPU device (-1 if not using GPU)
    size_t min_size_for_gpu;        ///< Minimum problem size for GPU benefit
} kctsb_accel_ctx_t;

// ============================================================================
// Detection and Initialization
// ============================================================================

/**
 * @brief Detect all available acceleration capabilities
 *
 * Probes CPU SIMD features (AVX2/AVX-512) and CUDA GPU availability.
 * Results are cached for subsequent calls.
 *
 * @return Bitmask of available capabilities (kctsb_accel_caps_t)
 */
KCTSB_API uint32_t kctsb_accel_detect(void);

/**
 * @brief Check if a specific capability is available
 *
 * @param cap Capability to check
 * @return 1 if available, 0 otherwise
 */
KCTSB_API int kctsb_accel_has_cap(kctsb_accel_caps_t cap);

/**
 * @brief Get GPU device count
 *
 * @return Number of CUDA devices (0 if CUDA not available)
 */
KCTSB_API int kctsb_accel_gpu_count(void);

/**
 * @brief Get GPU device information
 *
 * @param device_id GPU device ID
 * @param[out] info Device information structure
 * @return 0 on success, -1 on error
 */
KCTSB_API int kctsb_accel_gpu_info(int device_id, kctsb_gpu_info_t* info);

// ============================================================================
// Backend Selection
// ============================================================================

/**
 * @brief Automatically select optimal backend for NTT operations
 *
 * Selection logic:
 * - n >= 8192 and CUDA available: Use GPU
 * - AVX-512 available: Use AVX-512
 * - AVX2 available: Use AVX2
 * - Otherwise: Scalar CPU
 *
 * @param n Polynomial degree
 * @param L Number of RNS limbs
 * @return Recommended backend
 */
KCTSB_API kctsb_accel_backend_t kctsb_accel_select_ntt(size_t n, size_t L);

/**
 * @brief Automatically select optimal backend for FHE operations
 *
 * FHE operations (encryption, multiplication, relinearization) have higher
 * computational complexity, making GPU more beneficial at smaller sizes.
 *
 * @param n Polynomial degree
 * @param L Number of RNS limbs
 * @return Recommended backend
 */
KCTSB_API kctsb_accel_backend_t kctsb_accel_select_fhe(size_t n, size_t L);

/**
 * @brief Get human-readable name for a backend
 *
 * @param backend Backend type
 * @return Static string with backend name
 */
KCTSB_API const char* kctsb_accel_backend_name(kctsb_accel_backend_t backend);

// ============================================================================
// Manual Override
// ============================================================================

/**
 * @brief Force a specific backend (ignoring auto-detection)
 *
 * Use with caution - forcing an unavailable backend will cause errors.
 *
 * @param backend Backend to force
 */
KCTSB_API void kctsb_accel_force_backend(kctsb_accel_backend_t backend);

/**
 * @brief Clear forced backend (return to automatic selection)
 */
KCTSB_API void kctsb_accel_clear_force(void);

/**
 * @brief Check if a backend is forced
 *
 * @return Forced backend, or KCTSB_ACCEL_NONE if automatic
 */
KCTSB_API kctsb_accel_backend_t kctsb_accel_get_forced(void);

// ============================================================================
// Status and Diagnostics
// ============================================================================

/**
 * @brief Print acceleration capabilities to stdout
 *
 * Useful for debugging and verification.
 */
KCTSB_API void kctsb_accel_print_status(void);

/**
 * @brief Get string representation of all detected capabilities
 *
 * @param[out] buffer Output buffer
 * @param buffer_size Buffer size in bytes
 * @return Number of bytes written (excluding null terminator)
 */
KCTSB_API int kctsb_accel_status_string(char* buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* KCTSB_ACCELERATOR_H */
