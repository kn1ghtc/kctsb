/**
 * @file gpu_detect.cpp
 * @brief GPU/CUDA Detection Implementation
 * 
 * Runtime detection of CUDA availability without requiring CUDA at compile time.
 * Uses dynamic library loading to detect CUDA driver.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.12.0
 */

#include "kctsb/utils/gpu_detect.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace kctsb {
namespace utils {

// CUDA driver API types (for dynamic loading)
typedef int CUresult;
typedef int CUdevice;

// Function pointer types for CUDA driver API
typedef CUresult (*cuInit_t)(unsigned int);
typedef CUresult (*cuDeviceGetCount_t)(int*);
typedef CUresult (*cuDeviceGet_t)(CUdevice*, int);
typedef CUresult (*cuDeviceGetName_t)(char*, int, CUdevice);
typedef CUresult (*cuDeviceTotalMem_t)(size_t*, CUdevice);
typedef CUresult (*cuDeviceGetAttribute_t)(int*, int, CUdevice);
typedef CUresult (*cuDriverGetVersion_t)(int*);

// CUDA device attribute constants
constexpr int CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 75;
constexpr int CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 76;
constexpr int CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT = 16;
constexpr int CU_DEVICE_ATTRIBUTE_TOTAL_MEMORY = 0;  // Not used directly

GPUStatus detect_gpu_status() {
    GPUStatus status = {};
    
    // Check compile-time CUDA support
#ifdef KCTSB_HAS_CUDA
    status.cuda_compiled = true;
#else
    status.cuda_compiled = false;
#endif

    // Attempt to load CUDA driver dynamically
#ifdef _WIN32
    HMODULE cuda_lib = LoadLibraryA("nvcuda.dll");
    if (!cuda_lib) {
        status.cuda_available = false;
        status.error_message = "CUDA driver not found (nvcuda.dll)";
        return status;
    }
    
    #define GET_PROC(name) reinterpret_cast<name##_t>(GetProcAddress(cuda_lib, #name))
#else
    void* cuda_lib = dlopen("libcuda.so.1", RTLD_LAZY);
    if (!cuda_lib) {
        cuda_lib = dlopen("libcuda.so", RTLD_LAZY);
    }
    if (!cuda_lib) {
        status.cuda_available = false;
        status.error_message = "CUDA driver not found (libcuda.so)";
        return status;
    }
    
    #define GET_PROC(name) reinterpret_cast<name##_t>(dlsym(cuda_lib, #name))
#endif

    // Load function pointers
    auto cuInit = GET_PROC(cuInit);
    auto cuDeviceGetCount = GET_PROC(cuDeviceGetCount);
    auto cuDeviceGet = GET_PROC(cuDeviceGet);
    auto cuDeviceGetName = GET_PROC(cuDeviceGetName);
    auto cuDeviceTotalMem = GET_PROC(cuDeviceTotalMem);
    auto cuDeviceGetAttribute = GET_PROC(cuDeviceGetAttribute);
    auto cuDriverGetVersion = GET_PROC(cuDriverGetVersion);

    if (!cuInit || !cuDeviceGetCount || !cuDeviceGet || 
        !cuDeviceGetName || !cuDeviceTotalMem || !cuDeviceGetAttribute) {
        status.cuda_available = false;
        status.error_message = "Failed to load CUDA driver functions";
#ifdef _WIN32
        FreeLibrary(cuda_lib);
#else
        dlclose(cuda_lib);
#endif
        return status;
    }

    // Initialize CUDA
    CUresult result = cuInit(0);
    if (result != 0) {
        status.cuda_available = false;
        status.error_message = "cuInit failed with error: " + std::to_string(result);
#ifdef _WIN32
        FreeLibrary(cuda_lib);
#else
        dlclose(cuda_lib);
#endif
        return status;
    }

    status.cuda_available = true;

    // Get driver version
    if (cuDriverGetVersion) {
        cuDriverGetVersion(&status.cuda_driver_version);
    }

    // Get device count
    int device_count = 0;
    result = cuDeviceGetCount(&device_count);
    if (result != 0 || device_count == 0) {
        status.device_count = 0;
        status.error_message = "No CUDA devices found";
#ifdef _WIN32
        FreeLibrary(cuda_lib);
#else
        dlclose(cuda_lib);
#endif
        return status;
    }

    status.device_count = device_count;

    // Get device details
    for (int i = 0; i < device_count; ++i) {
        GPUDevice device = {};
        CUdevice cu_device;
        
        result = cuDeviceGet(&cu_device, i);
        if (result != 0) continue;

        // Get device name
        char name[256] = {0};
        cuDeviceGetName(name, 255, cu_device);
        device.name = name;

        // Get total memory
        size_t total_mem = 0;
        cuDeviceTotalMem(&total_mem, cu_device);
        device.memory_total = total_mem;
        device.memory_free = total_mem;  // Approximate (need CUDA runtime for accurate free)

        // Get compute capability
        cuDeviceGetAttribute(&device.compute_capability_major, 
                            CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, cu_device);
        cuDeviceGetAttribute(&device.compute_capability_minor, 
                            CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, cu_device);

        // Get multiprocessor count
        cuDeviceGetAttribute(&device.multiprocessor_count, 
                            CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, cu_device);

        device.is_available = true;
        status.devices.push_back(device);
    }

#ifdef _WIN32
    FreeLibrary(cuda_lib);
#else
    dlclose(cuda_lib);
#endif

    return status;
}

void print_gpu_status(const GPUStatus& status) {
    std::cout << "\n  [GPU/CUDA Status]\n";
    
    if (status.cuda_compiled) {
        std::cout << "  - kctsb CUDA Support:  ENABLED (compiled with KCTSB_HAS_CUDA)\n";
    } else {
        std::cout << "  - kctsb CUDA Support:  DISABLED (CPU-only build)\n";
    }

    if (status.cuda_available) {
        std::cout << "  - CUDA Driver:         AVAILABLE\n";
        
        // Format driver version (e.g., 12020 -> 12.2)
        int major = status.cuda_driver_version / 1000;
        int minor = (status.cuda_driver_version % 1000) / 10;
        std::cout << "  - Driver Version:      " << major << "." << minor << "\n";
        std::cout << "  - Device Count:        " << status.device_count << "\n";

        for (size_t i = 0; i < status.devices.size(); ++i) {
            const auto& dev = status.devices[i];
            std::cout << "\n  GPU " << i << ": " << dev.name << "\n";
            std::cout << "    - Memory:            " 
                      << std::fixed << std::setprecision(1) 
                      << (dev.memory_total / (1024.0 * 1024.0 * 1024.0)) << " GB\n";
            std::cout << "    - Compute Capability: " 
                      << dev.compute_capability_major << "." 
                      << dev.compute_capability_minor << "\n";
            std::cout << "    - SMs:               " << dev.multiprocessor_count << "\n";
        }
    } else {
        std::cout << "  - CUDA Driver:         NOT AVAILABLE\n";
        if (!status.error_message.empty()) {
            std::cout << "  - Reason:              " << status.error_message << "\n";
        }
    }
    std::cout << "\n";
}

}  // namespace utils
}  // namespace kctsb
