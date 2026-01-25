/**
 * @file accelerator.c
 * @brief Hardware Acceleration Detection and Selection Implementation
 *
 * @details Runtime detection of CPU SIMD features and CUDA availability.
 * Automatically selects optimal compute path based on problem size and
 * available hardware.
 *
 * @author knightc
 * @version 4.15.0
 * @date 2026-01-25
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/advanced/accelerator.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <intrin.h>
#else
#include <cpuid.h>
#endif

// ============================================================================
// Static State
// ============================================================================

static uint32_t g_detected_caps = 0;
static int g_detection_done = 0;
static kctsb_accel_backend_t g_forced_backend = KCTSB_ACCEL_NONE;
static int g_force_active = 0;

// CUDA function pointers (dynamically loaded)
typedef int (*cuda_available_fn)(void);
typedef int (*cuda_device_count_fn)(int*);
typedef int (*cuda_device_info_fn)(int, char*, size_t, size_t*, int*, int*, int*);

static cuda_available_fn g_cuda_available = NULL;
static cuda_device_count_fn g_cuda_device_count = NULL;
static cuda_device_info_fn g_cuda_device_info = NULL;
static int g_cuda_loaded = 0;

// ============================================================================
// CPU Feature Detection
// ============================================================================

#ifdef _WIN32
static void get_cpuid(int regs[4], int func_id, int subfunc_id)
{
    __cpuidex(regs, func_id, subfunc_id);
}
#else
static void get_cpuid(int regs[4], int func_id, int subfunc_id)
{
    __cpuid_count(func_id, subfunc_id, regs[0], regs[1], regs[2], regs[3]);
}
#endif

static uint32_t detect_cpu_features(void)
{
    uint32_t caps = 0;
    int regs[4];
    
    // Get CPU vendor and max function
    get_cpuid(regs, 0, 0);
    int max_func = regs[0];
    
    if (max_func < 1) {
        return caps;
    }
    
    // Function 1: Basic features
    get_cpuid(regs, 1, 0);
    
    // Check AES-NI (ECX bit 25)
    if (regs[2] & (1 << 25)) {
        caps |= KCTSB_CAP_AES_NI;
    }
    
    // Check PCLMULQDQ (ECX bit 1)
    if (regs[2] & (1 << 1)) {
        caps |= KCTSB_CAP_PCLMULQDQ;
    }
    
    if (max_func >= 7) {
        // Function 7: Extended features
        get_cpuid(regs, 7, 0);
        
        // Check AVX2 (EBX bit 5)
        if (regs[1] & (1 << 5)) {
            caps |= KCTSB_CAP_AVX2;
        }
        
        // Check AVX-512F (EBX bit 16)
        if (regs[1] & (1 << 16)) {
            caps |= KCTSB_CAP_AVX512F;
        }
        
        // Check AVX-512VL (EBX bit 31)
        if (regs[1] & (1 << 31)) {
            caps |= KCTSB_CAP_AVX512VL;
        }
        
        // Check AVX-512IFMA (EBX bit 21)
        if (regs[1] & (1 << 21)) {
            caps |= KCTSB_CAP_AVX512IFMA;
        }
    }
    
    return caps;
}

// ============================================================================
// CUDA Detection (Dynamic Loading)
// ============================================================================

#ifdef _WIN32
#include <windows.h>
typedef HMODULE lib_handle_t;
#define LIB_OPEN(name) LoadLibraryA(name)
#define LIB_SYM(h, name) GetProcAddress(h, name)
#define LIB_CLOSE(h) FreeLibrary(h)
#else
#include <dlfcn.h>
typedef void* lib_handle_t;
#define LIB_OPEN(name) dlopen(name, RTLD_LAZY)
#define LIB_SYM(h, name) dlsym(h, name)
#define LIB_CLOSE(h) dlclose(h)
#endif

static lib_handle_t g_cuda_lib = NULL;

static int load_cuda_library(void)
{
    if (g_cuda_loaded) {
        return g_cuda_lib != NULL ? 1 : 0;
    }
    g_cuda_loaded = 1;
    
    // Try to load kctsb_cuda library
#ifdef _WIN32
    const char* lib_names[] = {
        "kctsb_cuda.dll",
        ".\\kctsb_cuda.dll",
        "bin\\kctsb_cuda.dll",
    };
#else
    const char* lib_names[] = {
        "libkctsb_cuda.so",
        "./libkctsb_cuda.so",
        "lib/libkctsb_cuda.so",
    };
#endif
    
    for (size_t i = 0; i < sizeof(lib_names) / sizeof(lib_names[0]); ++i) {
        g_cuda_lib = LIB_OPEN(lib_names[i]);
        if (g_cuda_lib) {
            break;
        }
    }
    
    if (!g_cuda_lib) {
        return 0;
    }
    
    // Load function pointers
    g_cuda_available = (cuda_available_fn)LIB_SYM(g_cuda_lib, "kctsb_cuda_available");
    g_cuda_device_count = (cuda_device_count_fn)LIB_SYM(g_cuda_lib, "kctsb_cuda_device_count");
    g_cuda_device_info = (cuda_device_info_fn)LIB_SYM(g_cuda_lib, "kctsb_cuda_device_info");
    
    if (!g_cuda_available || !g_cuda_device_count || !g_cuda_device_info) {
        LIB_CLOSE(g_cuda_lib);
        g_cuda_lib = NULL;
        g_cuda_available = NULL;
        g_cuda_device_count = NULL;
        g_cuda_device_info = NULL;
        return 0;
    }
    
    return 1;
}

static int detect_cuda(void)
{
    if (!load_cuda_library()) {
        return 0;
    }
    
    if (g_cuda_available && g_cuda_available()) {
        return 1;
    }
    
    return 0;
}

// ============================================================================
// Public API Implementation
// ============================================================================

KCTSB_API uint32_t kctsb_accel_detect(void)
{
    if (g_detection_done) {
        return g_detected_caps;
    }
    
    // Detect CPU features
    g_detected_caps = detect_cpu_features();
    
    // Detect CUDA
    if (detect_cuda()) {
        g_detected_caps |= KCTSB_CAP_CUDA;
    }
    
    g_detection_done = 1;
    return g_detected_caps;
}

KCTSB_API int kctsb_accel_has_cap(kctsb_accel_caps_t cap)
{
    kctsb_accel_detect();  // Ensure detection is done
    return (g_detected_caps & cap) != 0;
}

KCTSB_API int kctsb_accel_gpu_count(void)
{
    kctsb_accel_detect();
    
    if (!(g_detected_caps & KCTSB_CAP_CUDA)) {
        return 0;
    }
    
    int count = 0;
    if (g_cuda_device_count && g_cuda_device_count(&count) == 0) {
        return count;
    }
    
    return 0;
}

KCTSB_API int kctsb_accel_gpu_info(int device_id, kctsb_gpu_info_t* info)
{
    if (!info) {
        return -1;
    }
    
    kctsb_accel_detect();
    
    if (!(g_detected_caps & KCTSB_CAP_CUDA)) {
        return -1;
    }
    
    if (!g_cuda_device_info) {
        return -1;
    }
    
    info->device_id = device_id;
    int result = g_cuda_device_info(
        device_id,
        info->name, sizeof(info->name),
        &info->total_memory,
        &info->compute_major,
        &info->compute_minor,
        &info->sm_count
    );
    
    return (result == 0) ? 0 : -1;
}

KCTSB_API kctsb_accel_backend_t kctsb_accel_select_ntt(size_t n, size_t L)
{
    // Check for forced backend
    if (g_force_active) {
        return g_forced_backend;
    }
    
    kctsb_accel_detect();
    
    // GPU is beneficial for n >= 8192 with multiple limbs
    // Based on benchmark results: GPU shows speedup at n >= 8192, L >= 3
    size_t total_ops = n * L;
    
    if ((g_detected_caps & KCTSB_CAP_CUDA) && n >= 8192 && total_ops >= 24576) {
        // n=8192, L=3 minimum for GPU benefit
        return KCTSB_ACCEL_CUDA;
    }
    
    if (g_detected_caps & KCTSB_CAP_AVX512F) {
        return KCTSB_ACCEL_AVX512;
    }
    
    if (g_detected_caps & KCTSB_CAP_AVX2) {
        return KCTSB_ACCEL_AVX2;
    }
    
    return KCTSB_ACCEL_NONE;
}

KCTSB_API kctsb_accel_backend_t kctsb_accel_select_fhe(size_t n, size_t L)
{
    // FHE operations are more compute-intensive, GPU beneficial earlier
    if (g_force_active) {
        return g_forced_backend;
    }
    
    kctsb_accel_detect();
    
    // For FHE (tensor multiply, relin), GPU beneficial at n >= 4096
    size_t total_ops = n * L;
    
    if ((g_detected_caps & KCTSB_CAP_CUDA) && n >= 4096 && total_ops >= 12288) {
        return KCTSB_ACCEL_CUDA;
    }
    
    if (g_detected_caps & KCTSB_CAP_AVX512F) {
        return KCTSB_ACCEL_AVX512;
    }
    
    if (g_detected_caps & KCTSB_CAP_AVX2) {
        return KCTSB_ACCEL_AVX2;
    }
    
    return KCTSB_ACCEL_NONE;
}

KCTSB_API const char* kctsb_accel_backend_name(kctsb_accel_backend_t backend)
{
    switch (backend) {
        case KCTSB_ACCEL_NONE:   return "Scalar CPU";
        case KCTSB_ACCEL_AVX2:   return "AVX2 CPU";
        case KCTSB_ACCEL_AVX512: return "AVX-512 CPU";
        case KCTSB_ACCEL_CUDA:   return "CUDA GPU";
        default:                 return "Unknown";
    }
}

KCTSB_API void kctsb_accel_force_backend(kctsb_accel_backend_t backend)
{
    g_forced_backend = backend;
    g_force_active = 1;
}

KCTSB_API void kctsb_accel_clear_force(void)
{
    g_force_active = 0;
    g_forced_backend = KCTSB_ACCEL_NONE;
}

KCTSB_API kctsb_accel_backend_t kctsb_accel_get_forced(void)
{
    return g_force_active ? g_forced_backend : KCTSB_ACCEL_NONE;
}

KCTSB_API void kctsb_accel_print_status(void)
{
    kctsb_accel_detect();
    
    printf("kctsb Acceleration Status:\n");
    printf("==========================\n");
    printf("CPU Features:\n");
    printf("  AVX2:       %s\n", (g_detected_caps & KCTSB_CAP_AVX2) ? "Yes" : "No");
    printf("  AVX-512F:   %s\n", (g_detected_caps & KCTSB_CAP_AVX512F) ? "Yes" : "No");
    printf("  AVX-512VL:  %s\n", (g_detected_caps & KCTSB_CAP_AVX512VL) ? "Yes" : "No");
    printf("  AVX-512IFMA:%s\n", (g_detected_caps & KCTSB_CAP_AVX512IFMA) ? "Yes" : "No");
    printf("  AES-NI:     %s\n", (g_detected_caps & KCTSB_CAP_AES_NI) ? "Yes" : "No");
    printf("  PCLMULQDQ:  %s\n", (g_detected_caps & KCTSB_CAP_PCLMULQDQ) ? "Yes" : "No");
    printf("\n");
    
    printf("GPU Acceleration:\n");
    if (g_detected_caps & KCTSB_CAP_CUDA) {
        int gpu_count = kctsb_accel_gpu_count();
        printf("  CUDA:       Yes (%d device%s)\n", gpu_count, gpu_count > 1 ? "s" : "");
        
        for (int i = 0; i < gpu_count && i < 4; ++i) {
            kctsb_gpu_info_t info;
            if (kctsb_accel_gpu_info(i, &info) == 0) {
                printf("  GPU %d:      %s (SM %d.%d, %zu MB, %d SMs)\n",
                       i, info.name,
                       info.compute_major, info.compute_minor,
                       info.total_memory / (1024 * 1024),
                       info.sm_count);
            }
        }
    } else {
        printf("  CUDA:       No\n");
    }
    printf("\n");
    
    printf("Recommended Backends:\n");
    printf("  NTT (n=8192,  L=3):  %s\n", kctsb_accel_backend_name(kctsb_accel_select_ntt(8192, 3)));
    printf("  NTT (n=16384, L=12): %s\n", kctsb_accel_backend_name(kctsb_accel_select_ntt(16384, 12)));
    printf("  NTT (n=32768, L=12): %s\n", kctsb_accel_backend_name(kctsb_accel_select_ntt(32768, 12)));
    printf("  FHE (n=8192,  L=3):  %s\n", kctsb_accel_backend_name(kctsb_accel_select_fhe(8192, 3)));
    printf("\n");
    
    if (g_force_active) {
        printf("Forced Backend: %s\n", kctsb_accel_backend_name(g_forced_backend));
    }
}

KCTSB_API int kctsb_accel_status_string(char* buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0) {
        return 0;
    }
    
    kctsb_accel_detect();
    
    int written = snprintf(buffer, buffer_size,
        "Caps: AVX2=%d AVX512F=%d CUDA=%d | GPU=%d",
        (g_detected_caps & KCTSB_CAP_AVX2) ? 1 : 0,
        (g_detected_caps & KCTSB_CAP_AVX512F) ? 1 : 0,
        (g_detected_caps & KCTSB_CAP_CUDA) ? 1 : 0,
        kctsb_accel_gpu_count()
    );
    
    return (written >= 0 && (size_t)written < buffer_size) ? written : 0;
}
