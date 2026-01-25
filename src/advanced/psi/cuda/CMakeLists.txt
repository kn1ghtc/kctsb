# ============================================================================
# kctsb CUDA Kernels - Standalone Build
# ============================================================================
# This CMakeLists.txt builds CUDA kernels separately from the main library
# because CUDA requires MSVC on Windows, while the main library uses GCC
# for __int128 support.
#
# Build Instructions (from kctsb root directory):
#   1. Open Developer Command Prompt for VS 2022
#   2. cmake -B build-cuda -S src/advanced/psi/cuda -G Ninja
#   3. cmake --build build-cuda
#
# The resulting kctsb_cuda.lib can be linked with the main library.
# ============================================================================

cmake_minimum_required(VERSION 3.20)

project(kctsb_cuda
    VERSION 1.0.0
    DESCRIPTION "CUDA kernels for kctsb PIR/PSI acceleration"
    LANGUAGES CXX CUDA
)

# ============================================================================
# CUDA Configuration
# ============================================================================

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CUDA architectures: RTX 4060 (SM 8.9), RTX 3090 (SM 8.6), A100 (SM 8.0)
set(CMAKE_CUDA_ARCHITECTURES "80;86;89" CACHE STRING "CUDA architectures")

find_package(CUDAToolkit REQUIRED)

message(STATUS "")
message(STATUS "====================================================================")
message(STATUS "kctsb CUDA Kernels - Standalone Build")
message(STATUS "====================================================================")
message(STATUS "CUDA Compiler: ${CMAKE_CUDA_COMPILER}")
message(STATUS "CUDA Version: ${CMAKE_CUDA_COMPILER_VERSION}")
message(STATUS "CUDA Toolkit: ${CUDAToolkit_VERSION}")
message(STATUS "CUDA Architectures: ${CMAKE_CUDA_ARCHITECTURES}")
message(STATUS "")

# ============================================================================
# CUDA Source Files
# ============================================================================

set(CUDA_SOURCES
    pir_cuda_kernels.cu
)

# ============================================================================
# CUDA Library Target
# ============================================================================

add_library(kctsb_cuda STATIC ${CUDA_SOURCES})

# ============================================================================
# CUDA Runtime Test Executable
# ============================================================================

add_executable(cuda_runtime_test test_cuda_runtime.cu)
target_link_libraries(cuda_runtime_test PRIVATE CUDA::cudart)
set_target_properties(cuda_runtime_test PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

# ============================================================================
# GPU NTT Benchmark Executable
# ============================================================================

add_executable(benchmark_ntt_gpu benchmark_ntt_gpu.cu)
target_link_libraries(benchmark_ntt_gpu PRIVATE CUDA::cudart)
set_target_properties(benchmark_ntt_gpu PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

# ============================================================================
# Optimized NTT Benchmark Executable
# ============================================================================

add_executable(benchmark_ntt_optimized benchmark_ntt_optimized.cu)
target_link_libraries(benchmark_ntt_optimized PRIVATE CUDA::cudart)
set_target_properties(benchmark_ntt_optimized PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

# ============================================================================
# Modular Operations Test
# ============================================================================

add_executable(test_modular_ops test_modular_ops.cu)
target_link_libraries(test_modular_ops PRIVATE CUDA::cudart)
set_target_properties(test_modular_ops PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

# ============================================================================
# Final NTT Benchmark
# ============================================================================

add_executable(benchmark_ntt_final benchmark_ntt_final.cu)
target_link_libraries(benchmark_ntt_final PRIVATE CUDA::cudart)
set_target_properties(benchmark_ntt_final PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
)

target_include_directories(kctsb_cuda
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include
)

# CUDA compile options
target_compile_options(kctsb_cuda PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:
        --expt-relaxed-constexpr
        --extended-lambda
        -O3
    >
)

# Link CUDA runtime
target_link_libraries(kctsb_cuda
    PUBLIC
        CUDA::cudart
)

# Enable separable compilation for device linking
set_target_properties(kctsb_cuda PROPERTIES
    CUDA_SEPARABLE_COMPILATION ON
    CUDA_RESOLVE_DEVICE_SYMBOLS ON
    POSITION_INDEPENDENT_CODE ON
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
# Installation
# ============================================================================

install(TARGETS kctsb_cuda
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../include/kctsb/advanced/psi/cuda/cuda_kernels.h
    DESTINATION include/kctsb/cuda
)

message(STATUS "")
message(STATUS "Build target: kctsb_cuda (static library)")
message(STATUS "Output directory: ${CMAKE_BINARY_DIR}")
message(STATUS "")
