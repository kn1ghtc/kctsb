/**
 * @file test_cuda_runtime.cu
 * @brief CUDA Runtime Verification Test
 * 
 * @details Verifies CUDA environment is working correctly:
 * - Device detection
 * - Memory allocation/transfer
 * - Simple kernel execution
 * 
 * @author kn1ghtc
 * @version 4.15.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Simple vector add kernel
__global__ void vector_add_kernel(float* a, float* b, float* c, int n)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        c[i] = a[i] + b[i];
    }
}

int main()
{
    printf("\n");
    printf("====================================================================\n");
    printf("  kctsb CUDA Runtime Verification Test\n");
    printf("====================================================================\n\n");
    
    // 1. Check device count
    int device_count = 0;
    cudaError_t err = cudaGetDeviceCount(&device_count);
    
    if (err != cudaSuccess) {
        printf("[FAIL] cudaGetDeviceCount: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    if (device_count == 0) {
        printf("[FAIL] No CUDA devices found\n");
        return 1;
    }
    
    printf("[PASS] Found %d CUDA device(s)\n", device_count);
    
    // 2. Get device properties
    cudaDeviceProp prop;
    err = cudaGetDeviceProperties(&prop, 0);
    
    if (err != cudaSuccess) {
        printf("[FAIL] cudaGetDeviceProperties: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    printf("[INFO] Device 0: %s\n", prop.name);
    printf("[INFO]   Compute capability: SM %d.%d\n", prop.major, prop.minor);
    printf("[INFO]   Total memory: %.2f GB\n", prop.totalGlobalMem / (1024.0 * 1024.0 * 1024.0));
    printf("[INFO]   SM count: %d\n", prop.multiProcessorCount);
    printf("[INFO]   Max threads/block: %d\n", prop.maxThreadsPerBlock);
    
    // 3. Test memory allocation
    const int N = 1024;
    const size_t size = N * sizeof(float);
    
    float *h_a, *h_b, *h_c;
    float *d_a, *d_b, *d_c;
    
    h_a = (float*)malloc(size);
    h_b = (float*)malloc(size);
    h_c = (float*)malloc(size);
    
    // Initialize host arrays
    for (int i = 0; i < N; ++i) {
        h_a[i] = (float)i;
        h_b[i] = (float)(i * 2);
    }
    
    err = cudaMalloc(&d_a, size);
    if (err != cudaSuccess) {
        printf("[FAIL] cudaMalloc d_a: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    err = cudaMalloc(&d_b, size);
    if (err != cudaSuccess) {
        printf("[FAIL] cudaMalloc d_b: %s\n", cudaGetErrorString(err));
        cudaFree(d_a);
        return 1;
    }
    
    err = cudaMalloc(&d_c, size);
    if (err != cudaSuccess) {
        printf("[FAIL] cudaMalloc d_c: %s\n", cudaGetErrorString(err));
        cudaFree(d_a);
        cudaFree(d_b);
        return 1;
    }
    
    printf("[PASS] GPU memory allocation (3 x %zu bytes)\n", size);
    
    // 4. Test memory transfer H2D
    err = cudaMemcpy(d_a, h_a, size, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) {
        printf("[FAIL] cudaMemcpy H2D a: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    err = cudaMemcpy(d_b, h_b, size, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) {
        printf("[FAIL] cudaMemcpy H2D b: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    printf("[PASS] Host-to-Device memory transfer\n");
    
    // 5. Test kernel execution
    int block_size = 256;
    int grid_size = (N + block_size - 1) / block_size;
    
    vector_add_kernel<<<grid_size, block_size>>>(d_a, d_b, d_c, N);
    
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("[FAIL] Kernel launch: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        printf("[FAIL] cudaDeviceSynchronize: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    printf("[PASS] Kernel execution (vector_add)\n");
    
    // 6. Test memory transfer D2H
    err = cudaMemcpy(h_c, d_c, size, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) {
        printf("[FAIL] cudaMemcpy D2H: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    printf("[PASS] Device-to-Host memory transfer\n");
    
    // 7. Verify results
    bool correct = true;
    for (int i = 0; i < N && correct; ++i) {
        float expected = h_a[i] + h_b[i];
        if (h_c[i] != expected) {
            printf("[FAIL] Result mismatch at index %d: expected %.2f, got %.2f\n",
                   i, expected, h_c[i]);
            correct = false;
        }
    }
    
    if (correct) {
        printf("[PASS] Computation result verification\n");
    }
    
    // Cleanup
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_c);
    free(h_a);
    free(h_b);
    free(h_c);
    
    printf("\n====================================================================\n");
    if (correct) {
        printf("  [ALL TESTS PASSED] CUDA runtime is working correctly\n");
    } else {
        printf("  [TESTS FAILED] CUDA runtime has issues\n");
    }
    printf("====================================================================\n\n");
    
    return correct ? 0 : 1;
}
