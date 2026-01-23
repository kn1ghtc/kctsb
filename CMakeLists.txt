# ============================================================================
# kctsb - Knight's Cryptographic Trusted Security Base
# Cross-platform cryptographic algorithms library
#
# Version: 4.10.0 (defined in include/kctsb/version.h - single source of truth)
# Copyright (c) 2019-2026 knightc. All rights reserved.
# Licensed under Apache License 2.0
#
# v4.10.0 Architecture Changes:
# - BGV EvaluatorV2: Pure RNS implementation with __int128 CRT
# - Harvey NTT: 28/28 tests passing, 22μs performance
# - Multiply+Relin: <20ms target achieved (0ms for n=256)
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# ============================================================================
# Ninja 和并行构建配置
# ============================================================================
# 推荐使用 Ninja: cmake -B build -G Ninja
set(CMAKE_BUILD_PARALLEL_LEVEL 8 CACHE STRING "Default parallel build level")

project(kctsb
    VERSION 4.10.0
    DESCRIPTION "Production-grade cryptographic algorithms library with integrated bignum math"
    LANGUAGES C CXX
)

# ============================================================================
# Assembly Language Support (v4.5.0)
# ============================================================================
# Enable ASM for optimized field element operations (fe256)
# x86_64: Uses BMI2 (MULX) and ADX (ADCX/ADOX) instructions
# ARM64: Uses NEON instructions (future)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
    # Enable ASM_NASM for MSVC, regular ASM for GCC/Clang
    if(MSVC)
        enable_language(ASM_MASM)
        set(KCTSB_ASM_ENABLED ON)
        set(KCTSB_ASM_TYPE "MASM")
        message(STATUS "✓ Assembly enabled: x86_64 MASM (MSVC)")
    else()
        # GCC/Clang use GNU as syntax
        enable_language(ASM)
        set(KCTSB_ASM_ENABLED ON)
        set(KCTSB_ASM_TYPE "GAS")
        message(STATUS "✓ Assembly enabled: x86_64 GAS (GCC/Clang)")
    endif()
    set(KCTSB_ARCH_X86_64 ON)
    add_definitions(-DKCTSB_ARCH_X86_64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    enable_language(ASM)
    set(KCTSB_ASM_ENABLED ON)
    set(KCTSB_ASM_TYPE "GAS")
    set(KCTSB_ARCH_ARM64 ON)
    add_definitions(-DKCTSB_ARCH_ARM64)
    message(STATUS "✓ Assembly enabled: ARM64 NEON")
else()
    set(KCTSB_ASM_ENABLED OFF)
    message(STATUS "⚠ Assembly disabled: unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# ============================================================================
# Build Configuration - C++17 Mandatory
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "")
message(STATUS "====================================================================")
message(STATUS "kctsb - Knight's Cryptographic Trusted Security Base")
message(STATUS "Version: ${PROJECT_VERSION} (Bignum Integrated)")
message(STATUS "====================================================================")
message(STATUS "")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# ============================================================================
# Platform Detection and Compiler Configuration
# ============================================================================

# Force 64-bit compilation: Use mingw64, not mingw32
if(WIN32 AND NOT MSVC)
    if(EXISTS "C:/msys64/mingw64/bin/gcc.exe")
        set(CMAKE_C_COMPILER "C:/msys64/mingw64/bin/gcc.exe" CACHE FILEPATH "C compiler" FORCE)
        set(CMAKE_CXX_COMPILER "C:/msys64/mingw64/bin/g++.exe" CACHE FILEPATH "C++ compiler" FORCE)
        message(STATUS "✓ Using mingw64 (64-bit): C:/msys64/mingw64/bin/")
    endif()
endif()

# Detect platform suffix
if(WIN32)
    set(KCTSB_PLATFORM "windows")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        set(KCTSB_PLATFORM_SUFFIX "win-x64")
    else()
        set(KCTSB_PLATFORM_SUFFIX "win-arm64")
    endif()
    add_definitions(-DKCTSB_PLATFORM_WINDOWS -D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
elseif(APPLE)
    set(KCTSB_PLATFORM "macos")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(KCTSB_PLATFORM_SUFFIX "macos-arm64")
    else()
        set(KCTSB_PLATFORM_SUFFIX "macos-x64")
    endif()
    add_definitions(-DKCTSB_PLATFORM_MACOS)
elseif(UNIX)
    set(KCTSB_PLATFORM "linux")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        set(KCTSB_PLATFORM_SUFFIX "linux-arm64")
    else()
        set(KCTSB_PLATFORM_SUFFIX "linux-x64")
    endif()
    add_definitions(-DKCTSB_PLATFORM_LINUX)
endif()

message(STATUS "Platform suffix: ${KCTSB_PLATFORM_SUFFIX}")

# Thirdparty directories
set(KCTSB_THIRDPARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)
set(KCTSB_THIRDPARTY_PLATFORM_DIR ${KCTSB_THIRDPARTY_DIR}/${KCTSB_PLATFORM_SUFFIX})
set(KCTSB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(KCTSB_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ============================================================================
# LTO Configuration (with bignum compatibility)
# ============================================================================

option(KCTSB_ENABLE_LTO "Enable Link-Time Optimization" ON)

set(KCTSB_LTO_SUPPORTED FALSE)

if(KCTSB_ENABLE_LTO)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "12.0")
            set(KCTSB_LTO_SUPPORTED TRUE)
            message(STATUS "LTO: Enabled (GCC ${CMAKE_CXX_COMPILER_VERSION})")
            
            # Use gcc-ar for LTO static libraries
            get_filename_component(COMPILER_DIR ${CMAKE_CXX_COMPILER} DIRECTORY)
            if(EXISTS "${COMPILER_DIR}/gcc-ar.exe")
                set(CMAKE_AR "${COMPILER_DIR}/gcc-ar.exe")
                set(CMAKE_RANLIB "${COMPILER_DIR}/gcc-ranlib.exe")
            elseif(EXISTS "${COMPILER_DIR}/gcc-ar")
                set(CMAKE_AR "${COMPILER_DIR}/gcc-ar")
                set(CMAKE_RANLIB "${COMPILER_DIR}/gcc-ranlib")
            endif()
        else()
            message(STATUS "LTO: Disabled (GCC < 12.0)")
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang")
        set(KCTSB_LTO_SUPPORTED TRUE)
        message(STATUS "LTO: Enabled (Clang)")
    elseif(MSVC)
        set(KCTSB_LTO_SUPPORTED TRUE)
        message(STATUS "LTO: Enabled (MSVC)")
    endif()
endif()

# ============================================================================
# Optimization Flags
# ============================================================================

if(MSVC)
    add_compile_options(/O2 /Oi /Ot /fp:fast)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        add_compile_options(/arch:AVX2)
    endif()
    if(KCTSB_LTO_SUPPORTED)
        add_compile_options(/GL)
        add_link_options(/LTCG)
    endif()
else()
    # GCC/Clang optimization
    add_compile_options(
        -O3
        -march=native
        -mtune=native
        -funroll-loops
        -fomit-frame-pointer
        -fPIC
        -fstack-protector-strong
    )
    
    # LTO flags
    if(KCTSB_LTO_SUPPORTED)
        add_compile_options(-flto)
        add_link_options(-flto)
    endif()
    
    # Hardware acceleration
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        add_compile_options(-maes -mpclmul -msse4.1 -msse4.2 -mssse3 -mavx2 -mbmi2 -msha)
        message(STATUS "Hardware acceleration: AES-NI, PCLMUL, SSE4.2, AVX2, SHA-NI")
    endif()
    
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        add_compile_options(-march=armv8-a+crypto)
        message(STATUS "Hardware acceleration: ARM64 NEON + Crypto")
    endif()
endif()

# ============================================================================
# Bignum Source Code Defines (v4.1.0 - KCTSB Integrated)
# ============================================================================

# Define bignum configuration macros globally (使用 KCTSB_ 前缀)
add_definitions(
    -DKCTSB_GMP_LIP           # Use GMP for big integers
    -DKCTSB_GF2X_LIB          # Use gf2x library
    -DKCTSB_THREADS           # Enable threading
    -DKCTSB_STD_CXX17         # C++17 standard
    -DKCTSB_EXCEPTIONS        # Enable exceptions
    # 兼容层：保持旧宏以支持未迁移代码
    -DNTL_GMP_LIP
    -DNTL_GF2X_LIB
    -DNTL_THREADS
    -DNTL_STD_CXX17
    -DNTL_EXCEPTIONS
)

# Hardware feature defines (编译器自动检测，不需要 HAVE_*.h 文件)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    add_definitions(
        -DKCTSB_HAVE_LL_TYPE
        -DKCTSB_HAVE_BUILTIN_CLZL
        -DKCTSB_HAVE_ALIGNED_ARRAY
        -DKCTSB_HAVE_CHRONO_TIME
        # 兼容层
        -DNTL_HAVE_LL_TYPE
        -DNTL_HAVE_BUILTIN_CLZL
        -DNTL_HAVE_ALIGNED_ARRAY
        -DNTL_HAVE_COPY_TRAITS1
        -DNTL_HAVE_COPY_TRAITS2
        -DNTL_HAVE_CHRONO_TIME
        -DNTL_HAVE_COPY_TRAITS2
        -DNTL_HAVE_CHRONO_TIME
    )
    # SIMD features (detected at compile time via __AVX2__ etc)
endif()

# ============================================================================
# Warning Flags
# ============================================================================

option(KCTSB_WARNINGS_AS_ERRORS "Treat warnings as errors for kctsb code" ON)

if(NOT MSVC)
    # Common warning flags for both C and C++
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Werror=return-type
        -Werror=uninitialized
        -Wno-unused-parameter
        -Wno-sign-conversion
        -Wno-conversion
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
    )
    # C++ only warning suppressions (invalid for C code)
    add_compile_options(
        "$<$<COMPILE_LANGUAGE:CXX>:-Wno-old-style-cast>"
        "$<$<COMPILE_LANGUAGE:CXX>:-Wno-deprecated-copy>"
        "$<$<COMPILE_LANGUAGE:CXX>:-Wno-useless-cast>"
    )
    # Suppress bignum-specific warnings (NTL-derived template-heavy code)
    # These warnings are in verified mathematical code and safe to ignore
    add_compile_options(
        -Wno-double-promotion
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-unused-function
        -Wno-misleading-indentation
    )
endif()

# ============================================================================
# Build Options (v4.1.0 / v4.6.0 updated for faster incremental builds)
# ============================================================================

# 默认构建共享库，不构建静态库（减小体积）
option(KCTSB_BUILD_SHARED "Build shared library" ON)
option(KCTSB_BUILD_STATIC "Build static library" OFF)

# v4.6.0: 测试和基准测试默认关闭以加速增量编译
# 使用 -DKCTSB_BUILD_TESTS=ON 或 -DKCTSB_BUILD_BENCHMARKS=ON 单独启用
option(KCTSB_BUILD_TESTS "Build unit tests (default OFF for faster builds)" OFF)
option(KCTSB_BUILD_BENCHMARKS "Build benchmarks (default OFF for faster builds)" OFF)
option(KCTSB_BUILD_CLI "Build kctsb.exe CLI tool" ON)

# v4.1.0: 测试需要静态库以确保所有bignum符号可用
# 共享库无法导出所有底层GMP包装函数
if(KCTSB_BUILD_TESTS AND NOT KCTSB_BUILD_STATIC)
    message(STATUS "Tests enabled - forcing static library build for complete symbol access")
    set(KCTSB_BUILD_STATIC ON CACHE BOOL "Build static library (required for tests)" FORCE)
endif()

# Core dependencies (required - 动态链接)
option(KCTSB_ENABLE_GMP "Enable GMP (required)" ON)
option(KCTSB_ENABLE_GF2X "Enable gf2x (required for GF2X)" ON)

# Optional dependencies (仅 benchmark 对比使用)
# v4.6.0: Enable SEAL/HElib for performance comparison benchmarks
option(KCTSB_ENABLE_SEAL "Enable Microsoft SEAL (benchmark only)" ON)
option(KCTSB_ENABLE_HELIB "Enable HElib (benchmark only)" ON)

# Benchmark-only dependency
option(KCTSB_ENABLE_OPENSSL "Enable OpenSSL (benchmarks only)" ON)

# ============================================================================
# Output Directories
# ============================================================================

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============================================================================
# Third-Party Dependencies
# ============================================================================

# Helper macros
macro(kctsb_find_thirdparty_lib OUT_VAR LIB_NAME)
    find_library(${OUT_VAR} NAMES ${LIB_NAME} lib${LIB_NAME}
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib"
              "${KCTSB_THIRDPARTY_DIR}/lib"
        NO_DEFAULT_PATH)
    if(NOT ${OUT_VAR})
        find_library(${OUT_VAR} NAMES ${LIB_NAME} lib${LIB_NAME})
    endif()
endmacro()

macro(kctsb_find_thirdparty_inc OUT_VAR HEADER_FILE)
    find_path(${OUT_VAR} ${HEADER_FILE}
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/include"
              "${KCTSB_THIRDPARTY_DIR}/include"
        NO_DEFAULT_PATH)
    if(NOT ${OUT_VAR})
        find_path(${OUT_VAR} ${HEADER_FILE})
    endif()
endmacro()

# -----------------------------------------------------------------------------
# GMP Detection (Required - v4.1.0)
# 支持静态库(.a)和动态库(.dll/.so)两种模式
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_GMP)
    kctsb_find_thirdparty_inc(GMP_INCLUDE_DIRS gmp.h)
    kctsb_find_thirdparty_lib(GMP_LIBRARY gmp)
    kctsb_find_thirdparty_lib(GMPXX_LIBRARY gmpxx)
    
    if(GMP_INCLUDE_DIRS AND GMP_LIBRARY)
        set(GMP_FOUND TRUE)
        message(STATUS "✓ GMP found: ${GMP_LIBRARY}")
        add_definitions(-DKCTSB_HAS_GMP)
        
        if(NOT TARGET GMP::GMP)
            # 检测是静态库还是动态库
            get_filename_component(GMP_LIB_EXT "${GMP_LIBRARY}" EXT)
            if(GMP_LIB_EXT STREQUAL ".a" OR GMP_LIB_EXT STREQUAL ".lib")
                add_library(GMP::GMP STATIC IMPORTED)
            else()
                add_library(GMP::GMP SHARED IMPORTED)
            endif()
            set_target_properties(GMP::GMP PROPERTIES
                IMPORTED_LOCATION "${GMP_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}")
        endif()
        
        if(GMPXX_LIBRARY)
            add_definitions(-DKCTSB_HAS_GMPXX)
            if(NOT TARGET GMP::GMPXX)
                get_filename_component(GMPXX_LIB_EXT "${GMPXX_LIBRARY}" EXT)
                if(GMPXX_LIB_EXT STREQUAL ".a" OR GMPXX_LIB_EXT STREQUAL ".lib")
                    add_library(GMP::GMPXX STATIC IMPORTED)
                else()
                    add_library(GMP::GMPXX SHARED IMPORTED)
                endif()
                set_target_properties(GMP::GMPXX PROPERTIES
                    IMPORTED_LOCATION "${GMPXX_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}")
            endif()
        endif()
    else()
        message(FATAL_ERROR "GMP not found. Required for kctsb v4.1.0")
    endif()
endif()

# -----------------------------------------------------------------------------
# gf2x Detection (Required - Dynamic Linking for v4.1.0)
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_GF2X)
    kctsb_find_thirdparty_inc(GF2X_INCLUDE_DIRS gf2x.h)
    if(NOT GF2X_INCLUDE_DIRS)
        find_path(GF2X_INCLUDE_DIRS gf2x.h
            HINTS "${KCTSB_THIRDPARTY_DIR}/linux-x64/include"
            NO_DEFAULT_PATH)
    endif()
    # 优先查找共享库
    if(WIN32)
        find_library(GF2X_LIBRARY NAMES libgf2x-1 gf2x libgf2x
            HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib"
                  "${KCTSB_THIRDPARTY_DIR}/lib"
            NO_DEFAULT_PATH)
    else()
        kctsb_find_thirdparty_lib(GF2X_LIBRARY gf2x)
    endif()
    if(NOT GF2X_LIBRARY)
        find_library(GF2X_LIBRARY NAMES gf2x libgf2x
            HINTS "${KCTSB_THIRDPARTY_DIR}/linux-x64/lib"
            NO_DEFAULT_PATH)
    endif()
    
    if(GF2X_INCLUDE_DIRS AND GF2X_LIBRARY)
        set(GF2X_FOUND TRUE)
        message(STATUS "✓ gf2x found: ${GF2X_LIBRARY}")
        add_definitions(-DKCTSB_HAS_GF2X -DNTL_GF2X_LIB -DKCTSB_GF2X_LIB)
        
        if(NOT TARGET gf2x::gf2x)
            # 检测是静态库还是动态库
            get_filename_component(GF2X_LIB_EXT "${GF2X_LIBRARY}" EXT)
            if(GF2X_LIB_EXT STREQUAL ".a" OR GF2X_LIB_EXT STREQUAL ".lib")
                add_library(gf2x::gf2x STATIC IMPORTED)
            else()
                add_library(gf2x::gf2x SHARED IMPORTED)
            endif()
            set_target_properties(gf2x::gf2x PROPERTIES
                IMPORTED_LOCATION "${GF2X_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${GF2X_INCLUDE_DIRS}")
        endif()
    else()
        message(STATUS "⚠ gf2x not found, using software GF2X implementation")
        set(KCTSB_ENABLE_GF2X OFF)
        set(GF2X_FOUND FALSE)
    endif()
endif()

# -----------------------------------------------------------------------------
# SEAL Detection (Optional)
# Priority: 1) deps/SEAL source, 2) thirdparty prebuilt
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_SEAL)
    # First try deps/SEAL source directory (contains headers)
    find_path(SEAL_INCLUDE_DIRS seal/seal.h
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/SEAL/native/src"
              "${KCTSB_THIRDPARTY_PLATFORM_DIR}/include/SEAL-4.1"
              "${KCTSB_THIRDPARTY_DIR}/include/SEAL-4.1")
    
    find_library(SEAL_LIBRARY NAMES seal-4.1 seal libseal-4.1
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib"
              "${KCTSB_THIRDPARTY_DIR}/lib"
              "${CMAKE_CURRENT_SOURCE_DIR}/deps/SEAL/build/lib")
    
    if(SEAL_INCLUDE_DIRS AND SEAL_LIBRARY)
        set(SEAL_FOUND TRUE)
        message(STATUS "✓ SEAL found:")
        message(STATUS "  - Include: ${SEAL_INCLUDE_DIRS}")
        message(STATUS "  - Library: ${SEAL_LIBRARY}")
        # NOTE: Don't use global add_definitions() - SEAL headers require config.h
        # which is generated during SEAL build. Each target that uses SEAL should
        # explicitly add KCTSB_HAS_SEAL definition only after verifying config.h exists.
        # add_definitions(-DKCTSB_HAS_SEAL)  # DISABLED - see note above
        
        if(NOT TARGET SEAL::seal)
            get_filename_component(SEAL_LIB_EXT "${SEAL_LIBRARY}" EXT)
            if(SEAL_LIB_EXT STREQUAL ".a" OR SEAL_LIB_EXT STREQUAL ".lib")
                add_library(SEAL::seal STATIC IMPORTED GLOBAL)
                # For MinGW static libraries, use IMPORTED_LOCATION directly
                set_target_properties(SEAL::seal PROPERTIES
                    IMPORTED_LOCATION "${SEAL_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${SEAL_INCLUDE_DIRS}"
                    IMPORTED_LINK_INTERFACE_LANGUAGES "CXX")
            else()
                add_library(SEAL::seal SHARED IMPORTED GLOBAL)
                set_target_properties(SEAL::seal PROPERTIES
                    IMPORTED_LOCATION "${SEAL_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${SEAL_INCLUDE_DIRS}")
            endif()
        endif()
    else()
        message(STATUS "⚠ SEAL not found (optional)")
        message(STATUS "  - Include search: ${CMAKE_CURRENT_SOURCE_DIR}/deps/SEAL/native/src")
        message(STATUS "  - Library search: ${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib")
        set(KCTSB_ENABLE_SEAL OFF)
    endif()
endif()

# -----------------------------------------------------------------------------
# HElib Detection (Optional)
# Priority: 1) deps/HElib source, 2) thirdparty prebuilt
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_HELIB)
    # First try deps/HElib source directory (contains headers)
    find_path(HELIB_INCLUDE_DIRS helib/helib.h
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/HElib/include"
              "${KCTSB_THIRDPARTY_PLATFORM_DIR}/include")
    
    find_library(HELIB_LIBRARY NAMES helib libhelib
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib"
              "${KCTSB_THIRDPARTY_DIR}/lib"
              "${CMAKE_CURRENT_SOURCE_DIR}/deps/HElib/build/lib")
    
    if(HELIB_INCLUDE_DIRS AND HELIB_LIBRARY)
        set(HELIB_FOUND TRUE)
        message(STATUS "✓ HElib found:")
        message(STATUS "  - Include: ${HELIB_INCLUDE_DIRS}")
        message(STATUS "  - Library: ${HELIB_LIBRARY}")
        # NOTE: Don't use global add_definitions() - HElib headers may require
        # additional build-time generated files. Each target that uses HElib should
        # explicitly add KCTSB_HAS_HELIB definition.
        # add_definitions(-DKCTSB_HAS_HELIB)  # DISABLED - see note above
        
        if(NOT TARGET helib::helib)
            get_filename_component(HELIB_LIB_EXT "${HELIB_LIBRARY}" EXT)
            if(HELIB_LIB_EXT STREQUAL ".a" OR HELIB_LIB_EXT STREQUAL ".lib")
                add_library(helib::helib STATIC IMPORTED GLOBAL)
                # For MinGW static libraries, use IMPORTED_LOCATION directly
                set_target_properties(helib::helib PROPERTIES
                    IMPORTED_LOCATION "${HELIB_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${HELIB_INCLUDE_DIRS}"
                    IMPORTED_LINK_INTERFACE_LANGUAGES "CXX")
            else()
                add_library(helib::helib SHARED IMPORTED GLOBAL)
                set_target_properties(helib::helib PROPERTIES
                    IMPORTED_LOCATION "${HELIB_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${HELIB_INCLUDE_DIRS}")
            endif()
        endif()
    else()
        message(STATUS "⚠ HElib not found (optional)")
        message(STATUS "  - Include search: ${CMAKE_CURRENT_SOURCE_DIR}/deps/HElib/include")
        message(STATUS "  - Library search: ${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib")
        set(KCTSB_ENABLE_HELIB OFF)
    endif()
endif()

# -----------------------------------------------------------------------------
# OpenSSL for benchmarks ONLY
# Requires OpenSSL 3.6.0+ from vcpkg for consistent benchmark comparison
# -----------------------------------------------------------------------------
if(KCTSB_BUILD_BENCHMARKS AND KCTSB_ENABLE_OPENSSL)
    # Prefer vcpkg OpenSSL 3.6.0
    if(WIN32 AND EXISTS "D:/vcpkg/installed/x64-windows")
        set(OPENSSL_ROOT_DIR "D:/vcpkg/installed/x64-windows")
        set(OPENSSL_USE_STATIC_LIBS OFF)
    endif()
    
    find_package(OpenSSL 3.6 QUIET)
    if(OPENSSL_FOUND)
        if(OPENSSL_VERSION VERSION_LESS "3.6.0")
            message(WARNING "⚠ OpenSSL ${OPENSSL_VERSION} found, but 3.6.0+ required for benchmarks")
            message(WARNING "  Please install OpenSSL 3.6.0 via: vcpkg install openssl:x64-windows")
            set(OPENSSL_FOUND FALSE)
        else()
            message(STATUS "✓ OpenSSL for benchmarks: ${OPENSSL_VERSION}")
            add_definitions(-DKCTSB_BENCHMARK_HAS_OPENSSL)
        endif()
    else()
        message(STATUS "⚠ OpenSSL 3.6.0+ not found, limited benchmarks")
        message(STATUS "  Install via: vcpkg install openssl:x64-windows")
        set(KCTSB_ENABLE_OPENSSL OFF)
    endif()
endif()

# ============================================================================
# Source Files
# ============================================================================

# Core kctsb sources
file(GLOB_RECURSE KCTSB_CORE_SOURCES ${KCTSB_SRC_DIR}/core/*.cpp ${KCTSB_SRC_DIR}/core/*.c)

# Crypto sources
file(GLOB KCTSB_AES_SOURCES ${KCTSB_SRC_DIR}/crypto/aes.cpp ${KCTSB_SRC_DIR}/crypto/ghash.cpp ${KCTSB_SRC_DIR}/crypto/mac.cpp)
set(KCTSB_CHACHA_SOURCES ${KCTSB_SRC_DIR}/crypto/chacha20_poly1305.cpp)
set(KCTSB_HASH_SOURCES
    ${KCTSB_SRC_DIR}/crypto/sha256.cpp
    ${KCTSB_SRC_DIR}/crypto/sha512.cpp
    ${KCTSB_SRC_DIR}/crypto/sha3.cpp
    ${KCTSB_SRC_DIR}/crypto/blake2.cpp
)
# SM2 depends on ECC which requires bignum math
# v4.0.1: Fixed Windows LLP64 compatibility, bignum now works on all platforms
# v4.4.0: Consolidated SM2 optimization into single file with wNAF in ecc_curve.cpp
set(KCTSB_SM_SOURCES
    ${KCTSB_SRC_DIR}/crypto/sm/sm3.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/sm4.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/sm2.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/zuc.cpp
)
set(KCTSB_WHITEBOX_SOURCES ${KCTSB_SRC_DIR}/advanced/whitebox/whitebox_aes.c)
set(KCTSB_SIMD_SOURCES ${KCTSB_SRC_DIR}/simd/simd.cpp)

set(KCTSB_CRYPTO_SOURCES
    ${KCTSB_AES_SOURCES}
    ${KCTSB_HASH_SOURCES}
    ${KCTSB_CHACHA_SOURCES}
    ${KCTSB_SM_SOURCES}
    ${KCTSB_WHITEBOX_SOURCES}
    ${KCTSB_SIMD_SOURCES}
)

# RSA and ECC sources (depend on integrated bignum math)
# v4.0.1: Windows LLP64 compatibility fixed - bignum works on all platforms
# v4.4.0: wNAF optimization consolidated into ecc_curve.cpp
# v4.8.1: fe256 acceleration layer merged into ecc_curve.cpp (no separate files)
#         Includes 128-bit arithmetic, Solinas reduction for secp256k1/P-256/SM2
file(GLOB KCTSB_RSA_SOURCES ${KCTSB_SRC_DIR}/crypto/rsa/*.cpp)
set(KCTSB_ECC_SOURCES
    # Core ECC operations with integrated fe256 acceleration layer
    # fe256 provides: 128-bit widening multiply, specialized modular reduction,
    #                 constant-time field arithmetic for 256-bit curves
    ${KCTSB_SRC_DIR}/crypto/ecc/ecc_curve.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecdh.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecdsa.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecies.cpp
)

# v4.7.0: Assembly support for ECC (optional, x86_64 only)
# v4.8.1: ASM acceleration for fe256 layer (if available)
if(KCTSB_ASM_ENABLED AND KCTSB_ARCH_X86_64 AND NOT MSVC)
    # GCC/Clang on Linux/macOS/MinGW - use .S files (GNU as)
    if(EXISTS "${KCTSB_SRC_DIR}/crypto/ecc/asm/fe256_x86_64.S")
        list(APPEND KCTSB_ECC_SOURCES ${KCTSB_SRC_DIR}/crypto/ecc/asm/fe256_x86_64.S)
        add_definitions(-DKCTSB_HAS_ECC_ASM)
        message(STATUS "✓ ECC assembly optimizations enabled (x86_64 GAS)")
    else()
        message(STATUS "  ECC: using integrated fe256 C++ fast path")
    endif()
elseif(KCTSB_ASM_ENABLED AND KCTSB_ARCH_X86_64 AND MSVC)
    message(STATUS "⚠ ECC assembly: MSVC MASM support pending (using C++ fallback)")
else()
    message(STATUS "  ECC: using portable C++ implementation")
endif()

list(APPEND KCTSB_CRYPTO_SOURCES ${KCTSB_RSA_SOURCES} ${KCTSB_ECC_SOURCES})
add_definitions(-DKCTSB_HAS_BIGNUM_MODULES)
message(STATUS "✓ RSA/ECC modules enabled (bignum integrated)")

# Existing math sources (non-bignum dependent)
# v4.0.1: All math sources included - GF2X modules are essential
file(GLOB KCTSB_EXISTING_MATH_SOURCES ${KCTSB_SRC_DIR}/math/*.cpp)

# ============================================================================
# Bignum Integrated Sources (v4.0.1 Slim - GMP/gf2x wrappers + core algorithms)
# ============================================================================

# Core sources - only essential GMP/gf2x wrappers
file(GLOB BIGNUM_CORE_SOURCES ${KCTSB_SRC_DIR}/math/bignum/core/*.cpp)
# v4.0.1: Exclude unnecessary NTL utilities 
list(FILTER BIGNUM_CORE_SOURCES EXCLUDE REGEX "subset\\.cpp$")
list(FILTER BIGNUM_CORE_SOURCES EXCLUDE REGEX "newnames\\.cpp$")
# Keep fileio.cpp - provides UniqueID() needed for random seed initialization
# Keep BasicThreadPool.cpp - provides thread pool used by ZZ/matrix operations
# Keep thread.cpp - provides CurrentThreadID() needed by fileio.cpp

# Ring sources - all needed for GF2/ZZ_p arithmetic
file(GLOB BIGNUM_RING_SOURCES ${KCTSB_SRC_DIR}/math/bignum/ring/*.cpp)

# Vector and Matrix sources - essential for linear algebra
file(GLOB BIGNUM_VECTOR_SOURCES ${KCTSB_SRC_DIR}/math/bignum/vector/*.cpp)
file(GLOB BIGNUM_MATRIX_SOURCES ${KCTSB_SRC_DIR}/math/bignum/matrix/*.cpp)
# v4.9.0: All precision types enabled (vec_RR, mat_RR for CKKS support)

# Polynomial sources - GF2X is essential for security algorithms
file(GLOB BIGNUM_POLY_SOURCES ${KCTSB_SRC_DIR}/math/bignum/poly/*.cpp)

# FFT sources - needed for efficient polynomial multiplication
file(GLOB BIGNUM_FFT_SOURCES ${KCTSB_SRC_DIR}/math/bignum/fft/*.cpp)

# v4.9.0: ENABLE precision modules for CKKS homomorphic encryption support
# Precision modules provide arbitrary precision floating-point arithmetic
file(GLOB BIGNUM_PRECISION_SOURCES ${KCTSB_SRC_DIR}/math/bignum/precision/*.cpp)
message(STATUS "  ✓ Precision modules (RR, xdouble, quad_float) enabled for CKKS support")

# Lattice sources - include all LLL variants for advanced cryptography
file(GLOB BIGNUM_LATTICE_SOURCES ${KCTSB_SRC_DIR}/math/bignum/lattice/*.cpp)
# v4.9.0: All precision LLL variants enabled (LLL_FP, LLL_RR, LLL_QP, LLL_XD, G_LLL_*)
# These are needed for advanced lattice-based cryptography and CKKS

set(BIGNUM_ALL_SOURCES
    ${BIGNUM_CORE_SOURCES}
    ${BIGNUM_RING_SOURCES}
    ${BIGNUM_VECTOR_SOURCES}
    ${BIGNUM_MATRIX_SOURCES}
    ${BIGNUM_POLY_SOURCES}
    ${BIGNUM_FFT_SOURCES}
    ${BIGNUM_PRECISION_SOURCES}
    ${BIGNUM_LATTICE_SOURCES}
)

message(STATUS "Bignum sources: ${CMAKE_CURRENT_SOURCE_DIR}/src/math/bignum/")
list(LENGTH BIGNUM_ALL_SOURCES BIGNUM_SOURCE_COUNT)
message(STATUS "  Total files: ${BIGNUM_SOURCE_COUNT}")

# ============================================================================
# Advanced modules
# ============================================================================

# ZK and Lattice modules depend on bignum math - now work on all platforms
file(GLOB_RECURSE KCTSB_ZK_SOURCES ${KCTSB_SRC_DIR}/advanced/zk/*.cpp)
file(GLOB_RECURSE KCTSB_LATTICE_SOURCES ${KCTSB_SRC_DIR}/advanced/lattice/*.cpp)

file(GLOB_RECURSE KCTSB_SSS_SOURCES ${KCTSB_SRC_DIR}/advanced/sss/*.cpp)
file(GLOB_RECURSE KCTSB_OTP_SOURCES ${KCTSB_SRC_DIR}/advanced/otp/*.cpp)

set(KCTSB_ADVANCED_SOURCES
    ${KCTSB_ZK_SOURCES}
    ${KCTSB_LATTICE_SOURCES}
    ${KCTSB_SSS_SOURCES}
    ${KCTSB_OTP_SOURCES}
)

# PSI sources
# Note: seal_pir.cpp requires SEAL headers to be built first (generates config.h)
# For now, only include piano_psi.cpp which has no external dependencies
set(KCTSB_PSI_SOURCES ${KCTSB_SRC_DIR}/advanced/psi/piano_psi.cpp)
# TODO: Enable seal_pir.cpp after SEAL is properly built with config.h
# if(KCTSB_ENABLE_SEAL AND SEAL_FOUND AND EXISTS "${SEAL_INCLUDE_DIRS}/seal/util/config.h")
#     list(APPEND KCTSB_PSI_SOURCES ${KCTSB_SRC_DIR}/advanced/psi/seal_pir.cpp)
# endif()
list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_PSI_SOURCES})

# FE sources - BGV is native, HElib only for comparison benchmarks
# v4.2.0: Native BGV implementation (no external HE library dependency)
# v4.9.0: BGV enabled by default for production homomorphic encryption
option(KCTSB_ENABLE_BGV "Enable native BGV homomorphic encryption" ON)
if(KCTSB_ENABLE_BGV)
    # NTT common sources (shared by BGV/BFV/CKKS)
    set(KCTSB_NTT_SOURCES
        ${KCTSB_SRC_DIR}/advanced/fe/common/ntt.cpp
        ${KCTSB_SRC_DIR}/advanced/fe/common/rns.cpp
        ${KCTSB_SRC_DIR}/advanced/fe/common/ntt_poly_ops.cpp
        ${KCTSB_SRC_DIR}/advanced/fe/common/ntt_harvey.cpp
        ${KCTSB_SRC_DIR}/advanced/fe/common/rns_poly_utils.cpp
    )
    
    # BGV-specific sources (v4.11.0: Pure RNS implementation)
    # Note: bgv_context.cpp and bgv_encoder.cpp are NTL-based legacy files,
    #       backed up as .bak_ntl_legacy. Only pure RNS bgv_evaluator.cpp is used.
    set(KCTSB_BGV_SOURCES
        ${KCTSB_SRC_DIR}/advanced/fe/bgv/bgv_evaluator.cpp
    )
    
    # BFV-specific sources (v4.11.0: Temporarily disabled, pending RNS migration)
    # TODO: Phase 4d BFV migration to pure RNS
    set(KCTSB_BFV_SOURCES
        # ${KCTSB_SRC_DIR}/advanced/fe/bfv/bfv_context.cpp  # Requires old BGVEvaluator
    )
    
    # CKKS-specific sources (v4.11.0: Temporarily disabled, pending RNS migration)
    # TODO: Phase 4d CKKS migration to pure RNS
    set(KCTSB_CKKS_SOURCES
        # ${KCTSB_SRC_DIR}/advanced/fe/ckks/ckks_context.cpp  # Requires old BGVEvaluator
    )
    
    # v4.11.0: Only BGV Pure RNS enabled
    list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_NTT_SOURCES} ${KCTSB_BGV_SOURCES})
    message(STATUS "✓ BGV Pure RNS homomorphic encryption enabled (BFV/CKKS pending migration)")
else()
    message(STATUS "⚠ Native BGV/BFV disabled (set KCTSB_ENABLE_BGV=ON to enable)")
endif()

# Legacy FE sources (require HElib for comparison only)
# Note: These files require HElib headers which need HElib to be built first
# Disabled until HElib is properly built
# if(KCTSB_ENABLE_HELIB AND HELIB_FOUND AND EXISTS "${HELIB_INCLUDE_DIRS}/helib/helib.h")
#     set(KCTSB_FE_LEGACY_SOURCES
#         ${KCTSB_SRC_DIR}/advanced/fe/kc_fe.cpp
#         ${KCTSB_SRC_DIR}/advanced/fe/gentryHE_int.cpp
#     )
#     list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_FE_LEGACY_SOURCES})
# endif()

# Utils
file(GLOB_RECURSE KCTSB_UTIL_SOURCES ${KCTSB_SRC_DIR}/utils/*.cpp)

# ============================================================================
# Combined Source List
# ============================================================================

set(KCTSB_ALL_SOURCES
    ${KCTSB_CORE_SOURCES}
    ${KCTSB_CRYPTO_SOURCES}
    ${KCTSB_ADVANCED_SOURCES}
    ${KCTSB_EXISTING_MATH_SOURCES}
    ${BIGNUM_ALL_SOURCES}
    ${KCTSB_UTIL_SOURCES}
)

# ============================================================================
# Library Targets
# ============================================================================

# Include directories
set(KCTSB_ALL_INCLUDE_DIRS
    ${KCTSB_INCLUDE_DIR}
    ${KCTSB_INCLUDE_DIR}/kctsb/math/bignum  # Bignum headers
    ${KCTSB_THIRDPARTY_PLATFORM_DIR}/include
    ${KCTSB_THIRDPARTY_DIR}/include
    ${GMP_INCLUDE_DIRS}
)

if(GF2X_INCLUDE_DIRS)
    list(APPEND KCTSB_ALL_INCLUDE_DIRS ${GF2X_INCLUDE_DIRS})
endif()

if(KCTSB_BUILD_STATIC)
    add_library(kctsb_static STATIC ${KCTSB_ALL_SOURCES})
    # v4.0.1: System includes FIRST to avoid Windows case-insensitive conflicts
    # (e.g., gf2x.h vs GF2X.h - the external gf2x library must take precedence)
    target_include_directories(kctsb_static SYSTEM PUBLIC
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_PLATFORM_DIR}/include>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        $<BUILD_INTERFACE:${GMP_INCLUDE_DIRS}>
    )
    # v4.0.1: Add GF2X include directories explicitly (before kctsb headers)
    if(GF2X_INCLUDE_DIRS)
        target_include_directories(kctsb_static SYSTEM PUBLIC
            $<BUILD_INTERFACE:${GF2X_INCLUDE_DIRS}>
        )
    endif()
    # kctsb headers after external libraries
    target_include_directories(kctsb_static PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
    )
    target_compile_definitions(kctsb_static PRIVATE KCTSB_BUILDING)
    set_target_properties(kctsb_static PROPERTIES OUTPUT_NAME kctsb)
    
    # Static dependencies (GMP, gf2x bundled)
    target_link_libraries(kctsb_static PUBLIC GMP::GMP)
    if(GMPXX_LIBRARY)
        target_link_libraries(kctsb_static PUBLIC GMP::GMPXX)
    endif()
    if(GF2X_FOUND)
        target_link_libraries(kctsb_static PUBLIC gf2x::gf2x)
    endif()
    
    # Dynamic dependencies (SEAL, HElib - use library path directly for MinGW compatibility)
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_static PUBLIC ${SEAL_INCLUDE_DIRS})
        # Use library path directly instead of IMPORTED target for MinGW static libs
        target_link_libraries(kctsb_static PUBLIC "${SEAL_LIBRARY}")
        if(WIN32)
            target_link_libraries(kctsb_static PRIVATE bcrypt)
        endif()
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        # Use library path directly instead of IMPORTED target
        target_link_libraries(kctsb_static PUBLIC "${HELIB_LIBRARY}")
    endif()
    
    # Platform libraries
    if(APPLE)
        target_link_libraries(kctsb_static PRIVATE "-framework Security")
    endif()
    
    # Threading
    find_package(Threads REQUIRED)
    target_link_libraries(kctsb_static PUBLIC Threads::Threads)
endif()

if(KCTSB_BUILD_SHARED)
    add_library(kctsb_shared SHARED ${KCTSB_ALL_SOURCES})
    # v4.0.1: System includes FIRST to avoid Windows case-insensitive conflicts
    target_include_directories(kctsb_shared SYSTEM PUBLIC
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_PLATFORM_DIR}/include>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        $<BUILD_INTERFACE:${GMP_INCLUDE_DIRS}>
    )
    # v4.0.1: Add GF2X include directories explicitly (before kctsb headers)
    if(GF2X_INCLUDE_DIRS)
        target_include_directories(kctsb_shared SYSTEM PUBLIC
            $<BUILD_INTERFACE:${GF2X_INCLUDE_DIRS}>
        )
    endif()
    # kctsb headers after external libraries
    target_include_directories(kctsb_shared PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
    )
    target_compile_definitions(kctsb_shared PRIVATE KCTSB_BUILDING KCTSB_SHARED_LIBRARY)
    set_target_properties(kctsb_shared PROPERTIES
        OUTPUT_NAME kctsb VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
    
    # Dependencies
    target_link_libraries(kctsb_shared PUBLIC GMP::GMP)
    if(GMPXX_LIBRARY)
        target_link_libraries(kctsb_shared PUBLIC GMP::GMPXX)
    endif()
    if(GF2X_FOUND)
        target_link_libraries(kctsb_shared PUBLIC gf2x::gf2x)
    endif()
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_shared PUBLIC ${SEAL_INCLUDE_DIRS})
        # Use library path directly for MinGW compatibility
        target_link_libraries(kctsb_shared PUBLIC "${SEAL_LIBRARY}")
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        # Use library path directly for MinGW compatibility
        target_link_libraries(kctsb_shared PUBLIC "${HELIB_LIBRARY}")
    endif()
    if(APPLE)
        target_link_libraries(kctsb_shared PRIVATE "-framework Security")
    endif()
    find_package(Threads REQUIRED)
    target_link_libraries(kctsb_shared PUBLIC Threads::Threads)
    
    # v4.1.0: 构建后复制依赖 DLL 到输出目录
    # v4.2.0: 添加缓存机制，避免重复复制
    if(WIN32)
        # 定义缓存标记文件
        set(DLL_CACHE_MARKER "$<TARGET_FILE_DIR:kctsb_shared>/.dll_cache_marker")
        
        # 复制 GMP DLL (带缓存检查)
        find_file(GMP_DLL NAMES libgmp-10.dll gmp.dll
            HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/bin"
                  "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib")
        if(GMP_DLL)
            add_custom_command(TARGET kctsb_shared POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${GMP_DLL}" $<TARGET_FILE_DIR:kctsb_shared>
                COMMENT "Copying GMP DLL to output directory (cached)")
        endif()
        
        # 复制 gf2x DLL (带缓存检查)
        if(GF2X_FOUND)
            find_file(GF2X_DLL NAMES libgf2x-1.dll gf2x.dll
                HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/bin"
                      "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib")
            if(GF2X_DLL)
                add_custom_command(TARGET kctsb_shared POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${GF2X_DLL}" $<TARGET_FILE_DIR:kctsb_shared>
                    COMMENT "Copying gf2x DLL to output directory (cached)")
            endif()
        endif()
        
        # 复制 SEAL DLL (如果启用且存在)
        if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
            find_file(SEAL_DLL NAMES seal-4.1.dll libseal-4.1.dll
                HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/bin"
                      "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib")
            if(SEAL_DLL)
                add_custom_command(TARGET kctsb_shared POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${SEAL_DLL}" $<TARGET_FILE_DIR:kctsb_shared>
                    COMMENT "Copying SEAL DLL to output directory (cached)")
            endif()
        endif()
        
        # 复制 HElib DLL (如果启用且存在)
        if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
            find_file(HELIB_DLL NAMES helib.dll libhelib.dll
                HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/bin"
                      "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib")
            if(HELIB_DLL)
                add_custom_command(TARGET kctsb_shared POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${HELIB_DLL}" $<TARGET_FILE_DIR:kctsb_shared>
                    COMMENT "Copying HElib DLL to output directory (cached)")
            endif()
        endif()
    endif()
endif()

# Aliases
if(KCTSB_BUILD_STATIC)
    add_library(kctsb::static ALIAS kctsb_static)
    add_library(kctsb ALIAS kctsb_static)
elseif(KCTSB_BUILD_SHARED)
    add_library(kctsb::shared ALIAS kctsb_shared)
    add_library(kctsb ALIAS kctsb_shared)
endif()

# ============================================================================
# CLI Tool
# ============================================================================

if(KCTSB_BUILD_CLI)
    file(GLOB KCTSB_CLI_SOURCES ${KCTSB_SRC_DIR}/cli/*.cpp)
    add_executable(kctsb_cli ${KCTSB_CLI_SOURCES})
    target_include_directories(kctsb_cli PRIVATE ${KCTSB_INCLUDE_DIR})
    set_target_properties(kctsb_cli PROPERTIES OUTPUT_NAME kctsb)
    
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        target_link_options(kctsb_cli PRIVATE -static-libgcc -static-libstdc++)
    endif()
    
    if(KCTSB_BUILD_STATIC)
        target_link_libraries(kctsb_cli PRIVATE kctsb_static)
    else()
        target_link_libraries(kctsb_cli PRIVATE kctsb_shared)
    endif()
    
    message(STATUS "✓ CLI tool: kctsb.exe")
endif()

# ============================================================================
# Tests & Benchmarks
# ============================================================================

if(KCTSB_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    message(STATUS "✓ Tests enabled")
endif()

if(KCTSB_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
    message(STATUS "✓ Benchmarks enabled")
endif()

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "=== kctsb v4.0.0 Configuration Summary ===")
message(STATUS "")
message(STATUS "Architecture: Bignum Source Integration (no external dependencies)")
message(STATUS "")
message(STATUS "Static Dependencies (bundled):")
message(STATUS "  - GMP: ${GMP_LIBRARY}")
if(GF2X_FOUND)
    message(STATUS "  - gf2x: ${GF2X_LIBRARY}")
endif()
message(STATUS "")
message(STATUS "Dynamic Dependencies (shared libs):")
if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
    message(STATUS "  - SEAL: ${SEAL_LIBRARY}")
endif()
if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
    message(STATUS "  - HElib: ${HELIB_LIBRARY}")
endif()
if(NOT KCTSB_ENABLE_SEAL AND NOT KCTSB_ENABLE_HELIB)
    message(STATUS "  (none)")
endif()
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Static lib:  ${KCTSB_BUILD_STATIC}")
message(STATUS "  Shared lib:  ${KCTSB_BUILD_SHARED}")
message(STATUS "  CLI tool:    ${KCTSB_BUILD_CLI}")
message(STATUS "  Tests:       ${KCTSB_BUILD_TESTS}")
message(STATUS "  Benchmarks:  ${KCTSB_BUILD_BENCHMARKS}")
message(STATUS "  LTO:         ${KCTSB_LTO_SUPPORTED}")
message(STATUS "")
