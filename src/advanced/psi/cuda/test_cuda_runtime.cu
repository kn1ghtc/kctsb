/**
 * @file test_cuda_runtime.cu
 * @brief Simple CUDA runtime test
 * 
 * @details Verifies CUDA runtime is working correctly
 */

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdint>

// Forward declaration of our kernel functions
extern "C" {
    bool kctsb_cuda_runtime_available();
    int kctsb_cuda_get_device_info(int device_id, char* name, size_t name_len,
                                   size_t* total_mem, int* compute_cap_major,
                                   int* compute_cap_minor);
}

// Simple vector add kernel to verify CUDA works
__global__ void vector_add_kernel(const float* a, const float* b, float* c, int n) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        c[idx] = a[idx] + b[idx];
    }
}

int main() {
    printf("\n");
    printf("====================================================================\n");
    printf("  kctsb CUDA Runtime Test\n");
    printf("====================================================================\n\n");
    
    // Check CUDA devices
    int device_count = 0;
    cudaError_t err = cudaGetDeviceCount(&device_count);
    if (err != cudaSuccess) {
        printf("ERROR: cudaGetDeviceCount failed: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    printf("Found %d CUDA device(s)\n\n", device_count);
    
    for (int i = 0; i < device_count; ++i) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);
        
        printf("Device %d: %s\n", i, prop.name);
        printf("  Compute Capability: SM %d.%d\n", prop.major, prop.minor);
        printf("  Total Memory: %.2f GB\n", prop.totalGlobalMem / 1024.0 / 1024.0 / 1024.0);
        printf("  SM Count: %d\n", prop.multiProcessorCount);
        printf("  Max Threads/Block: %d\n", prop.maxThreadsPerBlock);
        printf("  Memory Clock: %.2f GHz\n", prop.memoryClockRate / 1e6);
        printf("  Memory Bus Width: %d bits\n", prop.memoryBusWidth);
        printf("\n");
    }
    
    // Test simple kernel execution
    const int N = 1024;
    float *h_a, *h_b, *h_c;
    float *d_a, *d_b, *d_c;
    
    // Allocate host memory
    h_a = new float[N];
    h_b = new float[N];
    h_c = new float[N];
    
    // Initialize data
    for (int i = 0; i < N; ++i) {
        h_a[i] = static_cast<float>(i);
        h_b[i] = static_cast<float>(i * 2);
    }
    
    // Allocate device memory
    cudaMalloc(&d_a, N * sizeof(float));
    cudaMalloc(&d_b, N * sizeof(float));
    cudaMalloc(&d_c, N * sizeof(float));
    
    // Copy to device
    cudaMemcpy(d_a, h_a, N * sizeof(float), cudaMemcpyHostToDevice);
    cudaMemcpy(d_b, h_b, N * sizeof(float), cudaMemcpyHostToDevice);
    
    // Launch kernel
    int threads_per_block = 256;
    int blocks = (N + threads_per_block - 1) / threads_per_block;
    vector_add_kernel<<<blocks, threads_per_block>>>(d_a, d_b, d_c, N);
    
    // Check for errors
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("ERROR: Kernel launch failed: %s\n", cudaGetErrorString(err));
        return 1;
    }
    
    // Synchronize
    cudaDeviceSynchronize();
    
    // Copy result back
    cudaMemcpy(h_c, d_c, N * sizeof(float), cudaMemcpyDeviceToHost);
    
    // Verify result
    bool correct = true;
    for (int i = 0; i < N; ++i) {
        float expected = h_a[i] + h_b[i];
        if (h_c[i] != expected) {
            printf("ERROR: Verification failed at index %d: expected %.2f, got %.2f\n",
                   i, expected, h_c[i]);
            correct = false;
            break;
        }
    }
    
    if (correct) {
        printf("✓ Vector add kernel: PASSED\n");
    }
    
    // Cleanup
    cudaFree(d_a);
    cudaFree(d_b);
    cudaFree(d_c);
    delete[] h_a;
    delete[] h_b;
    delete[] h_c;
    
    printf("\n");
    printf("====================================================================\n");
    printf("  CUDA Runtime Test: SUCCESS\n");
    printf("====================================================================\n\n");
    
    return 0;
}
