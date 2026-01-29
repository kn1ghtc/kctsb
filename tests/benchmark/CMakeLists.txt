# ==============================================================================
# kctsb/tests/benchmark - Single-Algorithm Benchmark Tests
# Independent build for development-time performance optimization
#
# Purpose:
#   These benchmarks use HARDCODED baselines for quick feedback during
#   algorithm optimization. The baseline values come from third-party library
#   measurements (SEAL, OpenSSL) captured in benchmarks/ directory.
#
# Build Instructions:
#   cd D:\pyproject\kctsb\tests\benchmark
#   cmake -B build -G Ninja
#   cmake --build build --parallel
#   ./build/bin/test_bfv_benchmark
#
# ==============================================================================

cmake_minimum_required(VERSION 3.20)

project(kctsb_algorithm_benchmarks
    VERSION 5.1.0
    DESCRIPTION "Single-algorithm performance benchmarks with hardcoded baselines"
    LANGUAGES CXX
)

# ==============================================================================
# C++ Configuration
# ==============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ==============================================================================
# Platform Detection
# ==============================================================================

if(WIN32)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        set(PLATFORM_SUFFIX "win-x64")
    else()
        set(PLATFORM_SUFFIX "win-arm64")
    endif()
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(PLATFORM_SUFFIX "macos-arm64")
    else()
        set(PLATFORM_SUFFIX "macos-x64")
    endif()
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(PLATFORM_SUFFIX "linux-arm64")
    else()
        set(PLATFORM_SUFFIX "linux-x64")
    endif()
endif()

message(STATUS "Platform: ${PLATFORM_SUFFIX}")

# ==============================================================================
# Paths
# ==============================================================================

set(KCTSB_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(KCTSB_INCLUDE_DIR ${KCTSB_ROOT}/include)
set(KCTSB_SRC_DIR ${KCTSB_ROOT}/src)

# ==============================================================================
# kctsb Static Library
# ==============================================================================

# Try to find pre-built library
set(KCTSB_LIB_PATHS
    ${KCTSB_ROOT}/build/lib
    ${KCTSB_ROOT}/release/${PLATFORM_SUFFIX}/lib
)

find_library(KCTSB_STATIC_LIB
    NAMES kctsb libkctsb kctsb_static
    PATHS ${KCTSB_LIB_PATHS}
    NO_DEFAULT_PATH
)

if(NOT KCTSB_STATIC_LIB)
    message(FATAL_ERROR 
        "kctsb static library not found.\n"
        "Please build main project first:\n"
        "  cd ${KCTSB_ROOT}\n"
        "  cmake -B build -G Ninja -DKCTSB_BUILD_STATIC=ON\n"
        "  cmake --build build --parallel"
    )
endif()

message(STATUS "Using kctsb library: ${KCTSB_STATIC_LIB}")

# ==============================================================================
# GoogleTest
# ==============================================================================

find_package(GTest REQUIRED)

# ==============================================================================
# Compiler Flags
# ==============================================================================

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-O3 -march=native -Wall -Wextra)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-DNDEBUG)
    endif()
elseif(MSVC)
    add_compile_options(/O2 /W4)
endif()

# ==============================================================================
# Benchmark Executables
# ==============================================================================

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Individual benchmark tests
set(BENCHMARK_SOURCES
    test_bfv_benchmark.cpp
    test_bgv_benchmark.cpp
    test_ckks_benchmark.cpp
)

foreach(BENCH_SRC IN LISTS BENCHMARK_SOURCES)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${BENCH_SRC}")
        get_filename_component(BENCH_NAME ${BENCH_SRC} NAME_WE)
        
        add_executable(${BENCH_NAME} ${BENCH_SRC})
        
        target_include_directories(${BENCH_NAME} PRIVATE
            ${KCTSB_INCLUDE_DIR}
            ${KCTSB_SRC_DIR}
        )
        
        target_link_libraries(${BENCH_NAME} PRIVATE
            ${KCTSB_STATIC_LIB}
            GTest::gtest
        )
        
        # Platform-specific linking
        if(WIN32)
            target_link_libraries(${BENCH_NAME} PRIVATE ws2_32 bcrypt)
        elseif(UNIX AND NOT APPLE)
            target_link_libraries(${BENCH_NAME} PRIVATE pthread)
        endif()
        
        add_test(NAME ${BENCH_NAME} COMMAND ${BENCH_NAME})
        
        message(STATUS "✓ Benchmark: ${BENCH_NAME}")
    endif()
endforeach()

# ==============================================================================
# Summary
# ==============================================================================

message(STATUS "")
message(STATUS "=== Algorithm Benchmark Tests ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "kctsb library: ${KCTSB_STATIC_LIB}")
message(STATUS "")
message(STATUS "Run individual benchmarks:")
message(STATUS "  ./build/bin/test_bfv_benchmark")
message(STATUS "  ./build/bin/test_bgv_benchmark")
message(STATUS "  ./build/bin/test_ckks_benchmark")
message(STATUS "")
