#include <cuda_runtime.h>
#include <cstdio>
#include <cstdint>

__global__ void test_access(uint64_t* data, size_t n) {
    size_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid < n) data[tid] = tid;
}

int main() {
    size_t n = 1024;
    uint64_t* d_data;
    
    cudaError_t err = cudaMalloc(&d_data, n * sizeof(uint64_t));
    printf("Alloc: %s\n", cudaGetErrorString(err));
    
    int blocks = (n + 255) / 256;
    test_access<<<blocks, 256>>>(d_data, n);
    
    err = cudaDeviceSynchronize();
    printf("Kernel: %s\n", cudaGetErrorString(err));
    
    cudaFree(d_data);
    return 0;
}
