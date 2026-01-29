# ============================================================================
# kctsb/benchmarks - 独立三方库性能对比基准测试
#
# 本目录完全独立于主编译系统，通过库级别 API 进行实际性能对比
# 不依赖内部头文件，仅使用公共 API (kctsb_api.h)
#
# 支持的对比目标:
#   - OpenSSL 3.6.0: AES-GCM, ChaCha20-Poly1305, SHA3, RSA, ECC
#   - SEAL 4.1.2: BFV, BGV, CKKS 同态加密
#   - GmSSL: SM2, SM3, SM4 国密算法
#   - CUDA: GPU 加速 NTT/FHE 对比
#
# 构建方式 (独立于主编译):
#   cd kctsb/benchmarks
#   cmake -B build -G Ninja
#   cmake --build build --parallel
#
# 运行:
#   ./build/benchmark_suite openssl
#   ./build/benchmark_suite seal
#   ./build/benchmark_suite gmssl
#   ./build/benchmark_suite cuda
#   ./build/benchmark_suite all
#
# 依赖:
#   - kctsb 主编译产物: ../build/lib/libkctsb.a
#   - thirdparty 静态库: ../thirdparty/{platform}/lib/
#   - deps 源码编译的三方库
#
# Copyright (c) 2019-2026 knightc. All rights reserved.
# Licensed under Apache License 2.0
# ============================================================================

cmake_minimum_required(VERSION 3.20)

project(kctsb_benchmarks
    VERSION 5.1.0
    DESCRIPTION "kctsb Third-party Library Performance Comparison"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# 平台检测
# ============================================================================

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

message(STATUS "")
message(STATUS "=== kctsb Benchmarks - Independent Build ===")
message(STATUS "Platform: ${PLATFORM_SUFFIX}")

# ============================================================================
# 路径配置 - 使用主编译产物和 thirdparty 库
# ============================================================================

# 主编译产物路径
set(KCTSB_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../build" CACHE PATH "kctsb main build directory")
set(KCTSB_RELEASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../release/${PLATFORM_SUFFIX}" CACHE PATH "kctsb release directory")

# 公共头文件路径 (仅使用 kctsb_api.h)
set(KCTSB_PUBLIC_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../include")

# thirdparty 库路径
set(THIRDPARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/${PLATFORM_SUFFIX}")
set(THIRDPARTY_LIB_DIR "${THIRDPARTY_DIR}/lib")

# deps 源码路径 (用于编译三方库)
set(DEPS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../deps")

# ============================================================================
# 查找 kctsb 静态库
# ============================================================================

# 优先使用 build 目录（最新编译产物），其次 release 目录（发布产物）
find_library(KCTSB_LIBRARY
    NAMES kctsb libkctsb
    PATHS
        "${KCTSB_BUILD_DIR}/lib"
        "${KCTSB_RELEASE_DIR}/lib"
    NO_DEFAULT_PATH
)

if(KCTSB_LIBRARY)
    message(STATUS "✓ kctsb library found: ${KCTSB_LIBRARY}")
else()
    message(FATAL_ERROR "✗ kctsb library not found! Please build the main project first:\n"
        "  cd ${CMAKE_CURRENT_SOURCE_DIR}/..\n"
        "  cmake -B build -G Ninja -DKCTSB_BUILD_STATIC=ON\n"
        "  cmake --build build --parallel")
endif()

# ============================================================================
# 查找 OpenSSL (用于 benchmark_openssl)
# ============================================================================

option(BENCHMARK_OPENSSL "Enable OpenSSL benchmark" ON)

if(BENCHMARK_OPENSSL)
    # 检查 thirdparty 预编译库
    find_library(OPENSSL_CRYPTO_LIB
        NAMES crypto libcrypto
        PATHS "${THIRDPARTY_LIB_DIR}"
        NO_DEFAULT_PATH
    )
    find_library(OPENSSL_SSL_LIB
        NAMES ssl libssl
        PATHS "${THIRDPARTY_LIB_DIR}"
        NO_DEFAULT_PATH
    )

    if(OPENSSL_CRYPTO_LIB AND OPENSSL_SSL_LIB)
        set(OPENSSL_FOUND TRUE)
        set(OPENSSL_LIBRARIES ${OPENSSL_CRYPTO_LIB} ${OPENSSL_SSL_LIB})
        set(OPENSSL_INCLUDE_DIR "${DEPS_DIR}/openssl-3.6.0/include")
        message(STATUS "✓ OpenSSL found (thirdparty): ${OPENSSL_CRYPTO_LIB}")
    else()
        # 尝试系统安装的 OpenSSL
        find_package(OpenSSL 3.0 QUIET)
        if(OpenSSL_FOUND)
            set(OPENSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
            message(STATUS "✓ OpenSSL found (system): ${OPENSSL_VERSION}")
        else()
            message(STATUS "⚠ OpenSSL not found - benchmark_openssl will be skipped")
            set(BENCHMARK_OPENSSL OFF)
        endif()
    endif()
endif()

# ============================================================================
# 查找 SEAL 4.1.2 (用于 benchmark_seal)
# ============================================================================

option(BENCHMARK_SEAL "Enable SEAL benchmark" ON)

if(BENCHMARK_SEAL)
    find_library(SEAL_LIBRARY
        NAMES seal-4.1 libseal-4.1
        PATHS "${THIRDPARTY_LIB_DIR}"
        NO_DEFAULT_PATH
    )

    if(SEAL_LIBRARY)
        set(SEAL_FOUND TRUE)
        # SEAL头文件安装在thirdparty/win-x64/include/SEAL-4.1
        set(SEAL_INCLUDE_DIR "${THIRDPARTY_DIR}/include/SEAL-4.1")
        message(STATUS "✓ SEAL found: ${SEAL_LIBRARY}")
        message(STATUS "  SEAL include: ${SEAL_INCLUDE_DIR}")
    else()
        message(STATUS "⚠ SEAL not found - benchmark_seal will be skipped")
        set(BENCHMARK_SEAL OFF)
    endif()
endif()

# ============================================================================
# 查找 GmSSL (用于 benchmark_gmssl)
# ============================================================================

option(BENCHMARK_GMSSL "Enable GmSSL benchmark" ON)

if(BENCHMARK_GMSSL)
    find_library(GMSSL_LIBRARY
        NAMES gmssl libgmssl
        PATHS "${THIRDPARTY_LIB_DIR}"
        NO_DEFAULT_PATH
    )

    if(GMSSL_LIBRARY)
        set(GMSSL_FOUND TRUE)
        set(GMSSL_INCLUDE_DIR "${DEPS_DIR}/gmssl/include")
        message(STATUS "✓ GmSSL found: ${GMSSL_LIBRARY}")
    else()
        message(STATUS "⚠ GmSSL not found - benchmark_gmssl will be skipped")
        set(BENCHMARK_GMSSL OFF)
    endif()
endif()

# ============================================================================
# 查找 CUDA 库 (用于 benchmark_cuda)
# ============================================================================

option(BENCHMARK_CUDA "Enable CUDA benchmark" ON)

if(BENCHMARK_CUDA)
    # 查找 kctsb CUDA 库
    set(KCTSB_CUDA_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../build-cuda")
    find_library(KCTSB_CUDA_LIBRARY
        NAMES kctsb_cuda
        PATHS "${KCTSB_CUDA_BUILD_DIR}"
        NO_DEFAULT_PATH
    )

    find_package(CUDAToolkit QUIET)

    if(KCTSB_CUDA_LIBRARY AND CUDAToolkit_FOUND)
        set(CUDA_BENCHMARK_FOUND TRUE)
        message(STATUS "✓ CUDA benchmark enabled: ${KCTSB_CUDA_LIBRARY}")
    else()
        message(STATUS "⚠ CUDA library not found - benchmark_cuda will be skipped")
        set(BENCHMARK_CUDA OFF)
    endif()
endif()

# ============================================================================
# 编译选项
# ============================================================================

if(MSVC)
    add_compile_options(/O2 /Oi /Ot /fp:fast /utf-8)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        add_compile_options(/arch:AVX2)
    endif()
else()
    add_compile_options(
        -O3
        -march=native
        -mtune=native
        -fPIC
        -finput-charset=UTF-8
    )
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        add_compile_options(-fexec-charset=UTF-8)
    endif()
endif()

# ============================================================================
# 通用 benchmark 辅助头文件
# ============================================================================

set(BENCHMARK_COMMON_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/benchmark_common.hpp
)

# ============================================================================
# 主程序: benchmark_suite
# ============================================================================

add_executable(benchmark_suite
    benchmark_main.cpp
    $<$<BOOL:${BENCHMARK_OPENSSL}>:benchmark_openssl.cpp>
    $<$<BOOL:${BENCHMARK_SEAL}>:benchmark_seal.cpp>
    $<$<BOOL:${BENCHMARK_GMSSL}>:benchmark_gmssl.cpp>
    $<$<BOOL:${BENCHMARK_CUDA}>:benchmark_cuda.cpp>
)

target_include_directories(benchmark_suite PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${KCTSB_PUBLIC_INCLUDE}
)

target_link_libraries(benchmark_suite PRIVATE ${KCTSB_LIBRARY})

# 平台特定链接
if(WIN32)
    target_link_libraries(benchmark_suite PRIVATE bcrypt ws2_32)
elseif(APPLE)
    target_link_libraries(benchmark_suite PRIVATE "-framework Security")
endif()

find_package(Threads REQUIRED)
target_link_libraries(benchmark_suite PRIVATE Threads::Threads)

# 条件编译定义
if(BENCHMARK_OPENSSL)
    target_compile_definitions(benchmark_suite PRIVATE BENCHMARK_HAS_OPENSSL=1)
    target_include_directories(benchmark_suite PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(benchmark_suite PRIVATE ${OPENSSL_LIBRARIES})
endif()

if(BENCHMARK_SEAL)
    target_compile_definitions(benchmark_suite PRIVATE BENCHMARK_HAS_SEAL=1)
    target_include_directories(benchmark_suite PRIVATE
        ${SEAL_INCLUDE_DIR}
        "${THIRDPARTY_DIR}/include"  # For GSL headers
    )
    target_link_libraries(benchmark_suite PRIVATE ${SEAL_LIBRARY})
    # SEAL dependencies: zlib, zstd, bcrypt (Windows)
    find_library(ZLIB_STATIC_LIB NAMES zlibstatic libzlibstatic z libz PATHS "${THIRDPARTY_LIB_DIR}" NO_DEFAULT_PATH)
    find_library(ZSTD_STATIC_LIB NAMES zstd libzstd PATHS "${THIRDPARTY_LIB_DIR}" NO_DEFAULT_PATH)
    if(ZLIB_STATIC_LIB)
        target_link_libraries(benchmark_suite PRIVATE ${ZLIB_STATIC_LIB})
    endif()
    if(ZSTD_STATIC_LIB)
        target_link_libraries(benchmark_suite PRIVATE ${ZSTD_STATIC_LIB})
    endif()
    # SEAL uses BCryptGenRandom on Windows
    if(WIN32)
        target_link_libraries(benchmark_suite PRIVATE bcrypt)
    endif()
endif()

if(BENCHMARK_GMSSL)
    target_compile_definitions(benchmark_suite PRIVATE BENCHMARK_HAS_GMSSL=1)
    target_include_directories(benchmark_suite PRIVATE ${GMSSL_INCLUDE_DIR})
    target_link_libraries(benchmark_suite PRIVATE ${GMSSL_LIBRARY})
endif()

if(BENCHMARK_CUDA)
    target_compile_definitions(benchmark_suite PRIVATE BENCHMARK_HAS_CUDA=1)
    target_link_libraries(benchmark_suite PRIVATE ${KCTSB_CUDA_LIBRARY} CUDA::cudart)
endif()

set_target_properties(benchmark_suite PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================================
# 输出配置摘要
# ============================================================================

message(STATUS "")
message(STATUS "Benchmark Configuration Summary:")
message(STATUS "  OpenSSL:  ${BENCHMARK_OPENSSL}")
message(STATUS "  SEAL:     ${BENCHMARK_SEAL}")
message(STATUS "  GmSSL:    ${BENCHMARK_GMSSL}")
message(STATUS "  CUDA:     ${BENCHMARK_CUDA}")
message(STATUS "")
message(STATUS "Build command:")
message(STATUS "  cmake --build ${CMAKE_BINARY_DIR} --parallel")
message(STATUS "")
message(STATUS "Run command:")
message(STATUS "  ${CMAKE_BINARY_DIR}/bin/benchmark_suite [openssl|seal|gmssl|cuda|all]")
message(STATUS "")

