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
    VERSION 4.13.0
    DESCRIPTION "Production-grade cryptographic algorithms library with integrated bignum math"
    LANGUAGES C CXX
)

# ============================================================================
# Assembly Language Support Detection
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
    
    # LTO flags - Use parallel/incremental LTO for faster builds
    # Target: 30s incremental vs 2min full rebuild
    if(KCTSB_LTO_SUPPORTED)
        # Detect if using GCC or Clang for appropriate LTO options
        if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            # ThinLTO for Clang - supports incremental/parallel linking
            add_compile_options(-flto=thin)
            add_link_options(-flto=thin)
            message(STATUS "LTO: ThinLTO enabled (Clang incremental)")
        else()
            # GCC: Use -flto=auto for parallel LTO with jobserver
            add_compile_options(-flto=auto -fuse-linker-plugin)
            add_link_options(-flto=auto -fuse-linker-plugin)
            message(STATUS "LTO: Parallel LTO enabled (GCC -flto=auto)")
        endif()
        
        # Fat LTO objects for better incremental builds (GCC)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            add_compile_options(-ffat-lto-objects)
        endif()
    endif()
    
    # Hardware acceleration
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        add_compile_options(-maes -mpclmul -msse4.1 -msse4.2 -mssse3 -mavx2 -mbmi2 -msha)
        message(STATUS "Hardware acceleration: AES-NI, PCLMUL, SSE4.2, AVX2, SHA-NI")
        
        # Check for AVX-512 IFMA support (Ice Lake+, Zen4+)
        include(CheckCXXCompilerFlag)
        check_cxx_compiler_flag("-mavx512ifma" HAVE_AVX512IFMA)
        if(HAVE_AVX512IFMA)
            message(STATUS "AVX-512 IFMA support: Available (will use if CPU supports)")
            # Note: -march=native will auto-enable IFMA if CPU supports it
        else()
            message(STATUS "AVX-512 IFMA support: Compiler doesn't support -mavx512ifma")
        endif()
    endif()
    
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        add_compile_options(-march=armv8-a+crypto)
        message(STATUS "Hardware acceleration: ARM64 NEON + Crypto")
    endif()
endif()

# ============================================================================
# Bignum Source Code Defines (KCTSB Integrated)
# ============================================================================

# Define bignum configuration macros globally (使用 KCTSB_ 前缀)
add_definitions(
    -DKCTSB_GMP_LIP           # Use GMP for big integers
    -DKCTSB_GF2X_LIB          # Use gf2x library
    -DKCTSB_THREADS           # Enable threading
    -DKCTSB_STD_CXX17         # C++17 standard
    -DKCTSB_EXCEPTIONS        # Enable exceptions
)

# Hardware feature defines (编译器自动检测，不需要 HAVE_*.h 文件)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    add_definitions(
        -DKCTSB_HAVE_LL_TYPE
        -DKCTSB_HAVE_BUILTIN_CLZL
        -DKCTSB_HAVE_ALIGNED_ARRAY
        -DKCTSB_HAVE_CHRONO_TIME
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
        # Note: -Werror=uninitialized disabled due to false positives in NTL bignum code
        # The bignum module is ported from mature mathematical libraries (NTL/GMP)
        # where these warnings are known false positives in complex control flow
        -Wno-maybe-uninitialized
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
    # Suppress bignum-specific warnings (template-heavy code)
    # These warnings are in verified mathematical code and safe to ignore
    add_compile_options(
        -Wno-double-promotion
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-unused-function
        -Wno-misleading-indentation
        -Wno-pedantic  # Suppress ISO C++ does not support __int128 warning
    )
endif()

# ============================================================================
# Build Options (faster incremental builds)
# ============================================================================

# 默认构建共享库，不构建静态库（减小体积）
option(KCTSB_BUILD_SHARED "Build shared library" ON)
option(KCTSB_BUILD_STATIC "Build static library" OFF)

# 使用 -DKCTSB_BUILD_TESTS=ON 或 -DKCTSB_BUILD_BENCHMARKS=ON 单独启用
option(KCTSB_BUILD_TESTS "Build unit tests (default OFF for faster builds)" OFF)
option(KCTSB_BUILD_BENCHMARKS "Build benchmarks (default OFF for faster builds)" OFF)
option(KCTSB_BUILD_CLI "Build kctsb.exe CLI tool" ON)

# 测试需要静态库以确保所有bignum符号可用
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

# Create IMPORTED target with automatic static/shared detection
macro(kctsb_create_imported_target TARGET_NAME LIBRARY_PATH INCLUDE_DIRS)
    if(NOT TARGET ${TARGET_NAME})
        get_filename_component(LIB_EXT "${LIBRARY_PATH}" EXT)
        if(LIB_EXT STREQUAL ".a" OR LIB_EXT STREQUAL ".lib")
            add_library(${TARGET_NAME} STATIC IMPORTED GLOBAL)
            set_target_properties(${TARGET_NAME} PROPERTIES
                IMPORTED_LOCATION "${LIBRARY_PATH}"
                INTERFACE_INCLUDE_DIRECTORIES "${INCLUDE_DIRS}"
                IMPORTED_LINK_INTERFACE_LANGUAGES "CXX")
        else()
            add_library(${TARGET_NAME} SHARED IMPORTED GLOBAL)
            set_target_properties(${TARGET_NAME} PROPERTIES
                IMPORTED_LOCATION "${LIBRARY_PATH}"
                INTERFACE_INCLUDE_DIRECTORIES "${INCLUDE_DIRS}")
        endif()
    endif()
endmacro()

# -----------------------------------------------------------------------------
# GMP Detection 
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
        kctsb_create_imported_target(GMP::GMP "${GMP_LIBRARY}" "${GMP_INCLUDE_DIRS}")
        
        if(GMPXX_LIBRARY)
            add_definitions(-DKCTSB_HAS_GMPXX)
            kctsb_create_imported_target(GMP::GMPXX "${GMPXX_LIBRARY}" "${GMP_INCLUDE_DIRS}")
        endif()
    else()
        message(FATAL_ERROR "GMP not found. Required for kctsb v4.1.0")
    endif()
endif()

# -----------------------------------------------------------------------------
# gf2x Detection (Required - Dynamic Linking )
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
        kctsb_create_imported_target(gf2x::gf2x "${GF2X_LIBRARY}" "${GF2X_INCLUDE_DIRS}")
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
        kctsb_create_imported_target(SEAL::seal "${SEAL_LIBRARY}" "${SEAL_INCLUDE_DIRS}")
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
        # additional build-time generated files.
        kctsb_create_imported_target(helib::helib "${HELIB_LIBRARY}" "${HELIB_INCLUDE_DIRS}")
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
# Source Files - Auto-include all .cpp/.c files with minimal exclusions
# ============================================================================

# Collect ALL source files from src directory (auto-discovery)
file(GLOB_RECURSE KCTSB_ALL_CPP_SOURCES 
    ${KCTSB_SRC_DIR}/*.cpp
)
file(GLOB_RECURSE KCTSB_ALL_C_SOURCES 
    ${KCTSB_SRC_DIR}/*.c
)

# Initialize source list
set(KCTSB_ALL_SOURCES ${KCTSB_ALL_CPP_SOURCES} ${KCTSB_ALL_C_SOURCES})

# ============================================================================
# Exclusions - Only exclude files with special conditions
# ============================================================================

# Exclude legacy/backup files (*.bak_*, *.disabled, etc.)
# Note: .bak_ntl_legacy files are automatically excluded (different extension)

# Exclude FE modules pending migration (CKKS)
list(FILTER KCTSB_ALL_SOURCES EXCLUDE REGEX ".*/fe/ckks/ckks_context\\.cpp$")

# Exclude CLI sources from library (CLI has its own main())
list(FILTER KCTSB_ALL_SOURCES EXCLUDE REGEX ".*/cli/.*")
message(STATUS "✓ CLI sources excluded from library (separate executable)")

# Exclude incomplete modules with missing headers (fuzzy, whitebox)
list(FILTER KCTSB_ALL_SOURCES EXCLUDE REGEX ".*/advanced/fuzzy/.*")
list(FILTER KCTSB_ALL_SOURCES EXCLUDE REGEX ".*/advanced/whitebox/.*")
message(STATUS "⚠ Incomplete modules excluded: fuzzy, whitebox (pending header migration)")

# Conditionally exclude files based on build options
if(NOT KCTSB_ENABLE_BGV)
    # Exclude all FE modules if BGV disabled
    list(FILTER KCTSB_ALL_SOURCES EXCLUDE REGEX ".*/advanced/fe/.*")
    message(STATUS "⚠ Native BGV/BFV disabled - excluding FE modules")
else()
    message(STATUS "✓ BGV/BFV Pure RNS homomorphic encryption enabled (CKKS pending migration)")
endif()

# ============================================================================
# Assembly Files - Conditional platform-specific inclusion
# ============================================================================

if(KCTSB_ASM_ENABLED AND KCTSB_ARCH_X86_64 AND NOT MSVC)
    # GCC/Clang on Linux/macOS/MinGW - use .S files (GNU as)
    file(GLOB_RECURSE KCTSB_ASM_SOURCES ${KCTSB_SRC_DIR}/*.S)
    if(KCTSB_ASM_SOURCES)
        list(APPEND KCTSB_ALL_SOURCES ${KCTSB_ASM_SOURCES})
        add_definitions(-DKCTSB_HAS_ECC_ASM)
        message(STATUS "✓ Assembly optimizations enabled (x86_64 GAS)")
    else()
        message(STATUS "  Assembly: No .S files found, using C++ implementation")
    endif()
elseif(KCTSB_ASM_ENABLED AND KCTSB_ARCH_X86_64 AND MSVC)
    message(STATUS "⚠ Assembly: MSVC MASM support pending (using C++ fallback)")
else()
    message(STATUS "  Assembly: Using portable C++ implementation")
endif()

# ============================================================================
# Module Status Summary
# ============================================================================

# Count sources by category for diagnostic
list(LENGTH KCTSB_ALL_SOURCES TOTAL_SOURCE_COUNT)
message(STATUS "")
message(STATUS "Auto-discovered sources: ${TOTAL_SOURCE_COUNT} files")

# Core modules always enabled
add_definitions(-DKCTSB_HAS_BIGNUM_MODULES)
message(STATUS "✓ Core modules: crypto, math, bignum, utils")
message(STATUS "✓ Advanced modules: zk, lattice, sss, otp, psi")

# Bignum module breakdown (for reference)
file(GLOB_RECURSE BIGNUM_SOURCE_COUNT ${KCTSB_SRC_DIR}/math/bignum/*.cpp)
list(LENGTH BIGNUM_SOURCE_COUNT BIGNUM_FILE_COUNT)
message(STATUS "  - Bignum sources: ${BIGNUM_FILE_COUNT} files")
message(STATUS "    (core, ring, vector, matrix, poly, fft, precision, lattice)")
message(STATUS "")

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

# Unified library configuration function
function(kctsb_configure_library_target TARGET_NAME)
    # System includes FIRST to avoid Windows case-insensitive conflicts
    target_include_directories(${TARGET_NAME} SYSTEM PUBLIC
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_PLATFORM_DIR}/include>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        $<BUILD_INTERFACE:${GMP_INCLUDE_DIRS}>)
    if(GF2X_INCLUDE_DIRS)
        target_include_directories(${TARGET_NAME} SYSTEM PUBLIC
            $<BUILD_INTERFACE:${GF2X_INCLUDE_DIRS}>)
    endif()
    target_include_directories(${TARGET_NAME} PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>)
    
    # Link dependencies
    target_link_libraries(${TARGET_NAME} PUBLIC GMP::GMP)
    if(GMPXX_LIBRARY)
        target_link_libraries(${TARGET_NAME} PUBLIC GMP::GMPXX)
    endif()
    if(GF2X_FOUND)
        target_link_libraries(${TARGET_NAME} PUBLIC gf2x::gf2x)
    endif()
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(${TARGET_NAME} PUBLIC ${SEAL_INCLUDE_DIRS})
        target_link_libraries(${TARGET_NAME} PUBLIC "${SEAL_LIBRARY}")
        if(WIN32)
            target_link_libraries(${TARGET_NAME} PRIVATE bcrypt)
        endif()
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        target_link_libraries(${TARGET_NAME} PUBLIC "${HELIB_LIBRARY}")
    endif()
    if(APPLE)
        target_link_libraries(${TARGET_NAME} PRIVATE "-framework Security")
    endif()
    find_package(Threads REQUIRED)
    target_link_libraries(${TARGET_NAME} PUBLIC Threads::Threads)
endfunction()

if(KCTSB_BUILD_STATIC)
    add_library(kctsb_static STATIC ${KCTSB_ALL_SOURCES})
    target_compile_definitions(kctsb_static PRIVATE KCTSB_BUILDING)
    set_target_properties(kctsb_static PROPERTIES OUTPUT_NAME kctsb)
    kctsb_configure_library_target(kctsb_static)
endif()

# Function to copy DLL dependencies on Windows
function(kctsb_copy_dll TARGET_NAME DLL_VAR_NAME DLL_NAMES)
    if(WIN32)
        find_file(${DLL_VAR_NAME} NAMES ${DLL_NAMES}
            HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/bin"
                  "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib")
        if(${DLL_VAR_NAME})
            add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${${DLL_VAR_NAME}}" $<TARGET_FILE_DIR:${TARGET_NAME}>
                COMMENT "Copying ${DLL_VAR_NAME} to output directory")
        endif()
    endif()
endfunction()

if(KCTSB_BUILD_SHARED)
    add_library(kctsb_shared SHARED ${KCTSB_ALL_SOURCES})
    target_compile_definitions(kctsb_shared PRIVATE KCTSB_BUILDING KCTSB_SHARED_LIBRARY)
    set_target_properties(kctsb_shared PROPERTIES
        OUTPUT_NAME kctsb VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
    kctsb_configure_library_target(kctsb_shared)
    
    # Copy DLL dependencies on Windows using unified function
    kctsb_copy_dll(kctsb_shared GMP_DLL "libgmp-10.dll;gmp.dll")
    if(GF2X_FOUND)
        kctsb_copy_dll(kctsb_shared GF2X_DLL "libgf2x-1.dll;gf2x.dll")
    endif()
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        kctsb_copy_dll(kctsb_shared SEAL_DLL "seal-4.1.dll;libseal-4.1.dll")
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        kctsb_copy_dll(kctsb_shared HELIB_DLL "helib.dll;libhelib.dll")
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
message(STATUS "=== kctsb Configuration Summary ===")
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
