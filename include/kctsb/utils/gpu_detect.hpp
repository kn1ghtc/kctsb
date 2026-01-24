/**
 * @file gpu_detect.hpp
 * @brief GPU/CUDA Detection and Status Reporting
 * 
 * Provides runtime detection of GPU availability and CUDA support.
 * Works on systems with or without CUDA installed.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.12.0
 */

#ifndef KCTSB_UTILS_GPU_DETECT_HPP
#define KCTSB_UTILS_GPU_DETECT_HPP

#include <string>
#include <vector>

namespace kctsb {
namespace utils {

/**
 * @brief GPU device information
 */
struct GPUDevice {
    std::string name;           ///< Device name (e.g., "NVIDIA GeForce RTX 4090")
    size_t memory_total;        ///< Total memory in bytes
    size_t memory_free;         ///< Free memory in bytes
    int compute_capability_major; ///< CUDA compute capability major version
    int compute_capability_minor; ///< CUDA compute capability minor version
    int multiprocessor_count;   ///< Number of SMs
    bool is_available;          ///< Whether device is usable
};

/**
 * @brief GPU/CUDA status information
 */
struct GPUStatus {
    bool cuda_available;        ///< CUDA runtime available
    bool cuda_compiled;         ///< Compiled with CUDA support
    int cuda_driver_version;    ///< Driver version (e.g., 12020 for 12.2)
    int cuda_runtime_version;   ///< Runtime version
    int device_count;           ///< Number of CUDA devices
    std::vector<GPUDevice> devices; ///< Device details
    std::string error_message;  ///< Error message if detection failed
};

/**
 * @brief Detect CUDA/GPU status at runtime
 * @return GPUStatus with all available information
 * 
 * @note This function works even if CUDA is not installed:
 *       - On Windows: Attempts to load nvcuda.dll
 *       - On Linux: Attempts to load libcuda.so
 *       - Returns cuda_available=false if not found
 */
GPUStatus detect_gpu_status();

/**
 * @brief Print GPU status to console
 * @param status GPU status to print
 * 
 * Formats and prints GPU information in a user-friendly way.
 */
void print_gpu_status(const GPUStatus& status);

/**
 * @brief Check if GPU acceleration is enabled in kctsb
 * @return true if kctsb was compiled with CUDA support
 * 
 * This is a compile-time check using KCTSB_HAS_CUDA macro.
 */
inline bool is_gpu_enabled() {
#ifdef KCTSB_HAS_CUDA
    return true;
#else
    return false;
#endif
}

/**
 * @brief Get CUDA compute capability string
 * @param major Major version
 * @param minor Minor version
 * @return String like "8.6" for Ampere
 */
inline std::string compute_capability_string(int major, int minor) {
    return std::to_string(major) + "." + std::to_string(minor);
}

}  // namespace utils
}  // namespace kctsb

#endif  // KCTSB_UTILS_GPU_DETECT_HPP
