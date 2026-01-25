# ============================================================================
# kctsb CUDA Acceleration Library - Unified Build System
# ============================================================================
# Standalone CUDA build system for all GPU-accelerated algorithms:
# - NTT/INTT with Harvey lazy reduction
# - FHE operations (BGV/BFV/CKKS)
# - PIR inner products
# - Polynomial arithmetic
#
# CUDA requires MSVC on Windows, while main library uses GCC for __int128.
# This library is built separately and linked at runtime.
#
# Build Instructions (from kctsb root directory):
#   1. Open Developer Command Prompt for VS 2022
#   2. cmake -B build-cuda -S src/advanced/cuda -G Ninja -DCMAKE_BUILD_TYPE=Release
#   3. cmake --build build-cuda --parallel
#
# ============================================================================

cmake_minimum_required(VERSION 3.20)

project(kctsb_cuda
    VERSION 4.15.0
    DESCRIPTION "CUDA GPU acceleration for kctsb FHE/PIR/PSI operations"
    LANGUAGES CXX CUDA
)

# ============================================================================
# CUDA Configuration
# ============================================================================

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CUDA architectures for modern GPUs
# SM 80: A100, SM 86: RTX 3090, SM 89: RTX 4060/4090
set(CMAKE_CUDA_ARCHITECTURES "80;86;89" CACHE STRING "CUDA architectures")

find_package(CUDAToolkit REQUIRED)

message(STATUS "")
message(STATUS "====================================================================")
message(STATUS "kctsb CUDA Unified Acceleration Library v${PROJECT_VERSION}")
message(STATUS "====================================================================")
message(STATUS "CUDA Compiler: ${CMAKE_CUDA_COMPILER}")
message(STATUS "CUDA Version: ${CMAKE_CUDA_COMPILER_VERSION}")
message(STATUS "CUDA Toolkit: ${CUDAToolkit_VERSION}")
message(STATUS "CUDA Architectures: ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "")

# ============================================================================
# Source Files
# ============================================================================

set(CUDA_CORE_SOURCES
    # Core NTT kernels (shared by all FHE schemes)
    cuda_ntt_kernels.cu
    
    # FHE scheme-specific kernels
    cuda_fhe_kernels.cu
    
    # PIR/PSI specific kernels
    cuda_pir_kernels.cu
    
    # Utility functions
    cuda_utils.cu
)

# ============================================================================
# Main CUDA Library
# ============================================================================

add_library(kctsb_cuda STATIC ${CUDA_CORE_SOURCES})

target_include_directories(kctsb_cuda
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../include
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# CUDA compile options - maximum optimization
target_compile_options(kctsb_cuda PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        --expt-relaxed-constexpr
        --extended-lambda
        -O3
        --use_fast_math
        -Xptxas -O3
        -lineinfo
    >
)

target_link_libraries(kctsb_cuda
    PUBLIC
        CUDA::cudart
)

set_target_properties(kctsb_cuda PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME kctsb_cuda
)

# Windows-specific definitions
if(WIN32)
    target_compile_definitions(kctsb_cuda PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

# ============================================================================
# Unified CUDA Benchmark (FHE security parameters)
# ============================================================================

add_executable(benchmark_cuda_fhe benchmark_cuda_fhe.cu)
target_link_libraries(benchmark_cuda_fhe PRIVATE kctsb_cuda CUDA::cudart)
set_target_properties(benchmark_cuda_fhe PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================================
# Test Executables
# ============================================================================

add_executable(test_cuda_runtime test_cuda_runtime.cu)
target_link_libraries(test_cuda_runtime PRIVATE CUDA::cudart)
set_target_properties(test_cuda_runtime PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

add_executable(test_cuda_ntt test_cuda_ntt.cu)
target_link_libraries(test_cuda_ntt PRIVATE kctsb_cuda CUDA::cudart)
set_target_properties(test_cuda_ntt PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS kctsb_cuda
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES
    cuda_api.h
    DESTINATION include/kctsb/cuda
)

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "Build targets:")
message(STATUS "  - kctsb_cuda          : Static library")
message(STATUS "  - benchmark_cuda_fhe  : FHE CUDA benchmark (n=8K/16K/32K)")
message(STATUS "  - test_cuda_runtime   : CUDA runtime verification")
message(STATUS "  - test_cuda_ntt       : NTT correctness test")
message(STATUS "")
message(STATUS "Output directory: ${CMAKE_BINARY_DIR}")
message(STATUS "")
