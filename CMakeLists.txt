# ============================================================================
# kctsb - Knight's Cryptographic Trusted Security Base
# Cross-platform cryptographic algorithms library
#
# Version: 4.0.0 (defined in include/kctsb/version.h - single source of truth)
# Copyright (c) 2019-2026 knightc. All rights reserved.
# Licensed under Apache License 2.0
#
# v4.0.0 Architecture Changes:
# - Bignum (high-precision math) source code integration
# - Static linking: GMP, gf2x (bundled into kctsb)
# - Dynamic linking: SEAL, HElib (shared libraries)
# - Removed: External math library dependencies
# - LTO compatibility fixes for integrated bignum code
# ============================================================================

cmake_minimum_required(VERSION 3.20)

project(kctsb
    VERSION 4.0.0
    DESCRIPTION "Production-grade cryptographic algorithms library with integrated bignum math"
    LANGUAGES C CXX
)

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
# Bignum Source Code Defines (v4.0.0 - Integrated)
# ============================================================================

# Define bignum configuration macros globally
add_definitions(
    -DNTL_GMP_LIP           # Use GMP for big integers
    -DNTL_GF2X_LIB          # Use gf2x library
    -DNTL_THREADS           # Enable threading
    -DNTL_STD_CXX17         # C++17 standard
    -DNTL_EXCEPTIONS        # Enable exceptions
)

# Hardware feature defines based on compiler flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    add_definitions(
        -DNTL_HAVE_LL_TYPE
        -DNTL_HAVE_BUILTIN_CLZL
        -DNTL_HAVE_ALIGNED_ARRAY
        -DNTL_HAVE_COPY_TRAITS1
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
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Werror=return-type
        -Werror=uninitialized
        -Wno-unused-parameter
        -Wno-sign-conversion
        -Wno-conversion
        -Wno-old-style-cast
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
    )
    # Suppress bignum-specific warnings (template-heavy code)
    add_compile_options(
        -Wno-useless-cast
        -Wno-double-promotion
    )
endif()

# ============================================================================
# Build Options
# ============================================================================

option(KCTSB_BUILD_SHARED "Build shared library" ON)
option(KCTSB_BUILD_STATIC "Build static library" ON)
option(KCTSB_BUILD_TESTS "Build tests" ON)
option(KCTSB_BUILD_BENCHMARKS "Build benchmarks" ON)
option(KCTSB_BUILD_CLI "Build kctsb.exe CLI tool" ON)

# Core dependencies (required)
option(KCTSB_ENABLE_GMP "Enable GMP (required)" ON)
option(KCTSB_ENABLE_GF2X "Enable gf2x (required for GF2X)" ON)

# Optional dependencies (dynamic linking)
option(KCTSB_ENABLE_SEAL "Enable Microsoft SEAL (dynamic)" OFF)
option(KCTSB_ENABLE_HELIB "Enable HElib (dynamic)" OFF)

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
# GMP Detection (Required - Static Linking)
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
            add_library(GMP::GMP STATIC IMPORTED)
            set_target_properties(GMP::GMP PROPERTIES
                IMPORTED_LOCATION "${GMP_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}")
        endif()
        
        if(GMPXX_LIBRARY)
            add_definitions(-DKCTSB_HAS_GMPXX)
            if(NOT TARGET GMP::GMPXX)
                add_library(GMP::GMPXX STATIC IMPORTED)
                set_target_properties(GMP::GMPXX PROPERTIES
                    IMPORTED_LOCATION "${GMPXX_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}")
            endif()
        endif()
    else()
        message(FATAL_ERROR "GMP not found. Required for kctsb v4.0.0")
    endif()
endif()

# -----------------------------------------------------------------------------
# gf2x Detection (Optional - Static Linking)
# Bignum can use software fallback for GF2X if gf2x not available
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_GF2X)
    # Also search in linux-x64 for cross-compile scenarios
    kctsb_find_thirdparty_inc(GF2X_INCLUDE_DIRS gf2x.h)
    if(NOT GF2X_INCLUDE_DIRS)
        find_path(GF2X_INCLUDE_DIRS gf2x.h
            HINTS "${KCTSB_THIRDPARTY_DIR}/linux-x64/include"
            NO_DEFAULT_PATH)
    endif()
    kctsb_find_thirdparty_lib(GF2X_LIBRARY gf2x)
    if(NOT GF2X_LIBRARY)
        find_library(GF2X_LIBRARY NAMES gf2x libgf2x
            HINTS "${KCTSB_THIRDPARTY_DIR}/linux-x64/lib"
            NO_DEFAULT_PATH)
    endif()
    
    if(GF2X_INCLUDE_DIRS AND GF2X_LIBRARY)
        set(GF2X_FOUND TRUE)
        message(STATUS "✓ gf2x found: ${GF2X_LIBRARY}")
        # v4.0.1: Define both NTL_GF2X_LIB (legacy) and KCTSB_GF2X_LIB (new)
        add_definitions(-DKCTSB_HAS_GF2X -DNTL_GF2X_LIB -DKCTSB_GF2X_LIB)
        
        if(NOT TARGET gf2x::gf2x)
            add_library(gf2x::gf2x STATIC IMPORTED)
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
# SEAL Detection (Optional - Dynamic Linking)
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_SEAL)
    find_path(SEAL_INCLUDE_DIRS seal/seal.h
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/include/SEAL-4.1"
              "${KCTSB_THIRDPARTY_DIR}/include/SEAL-4.1")
    
    # Look for shared library
    find_library(SEAL_LIBRARY NAMES seal-4.1 seal
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib"
              "${KCTSB_THIRDPARTY_DIR}/lib")
    
    if(SEAL_INCLUDE_DIRS AND SEAL_LIBRARY)
        set(SEAL_FOUND TRUE)
        message(STATUS "✓ SEAL found (dynamic): ${SEAL_LIBRARY}")
        add_definitions(-DKCTSB_HAS_SEAL)
        
        if(NOT TARGET SEAL::seal)
            add_library(SEAL::seal SHARED IMPORTED)
            set_target_properties(SEAL::seal PROPERTIES
                IMPORTED_LOCATION "${SEAL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${SEAL_INCLUDE_DIRS}")
        endif()
    else()
        message(STATUS "⚠ SEAL not found (optional)")
        set(KCTSB_ENABLE_SEAL OFF)
    endif()
endif()

# -----------------------------------------------------------------------------
# HElib Detection (Optional - Dynamic Linking)
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_HELIB)
    kctsb_find_thirdparty_inc(HELIB_INCLUDE_DIRS helib/helib.h)
    find_library(HELIB_LIBRARY NAMES helib
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib"
              "${KCTSB_THIRDPARTY_DIR}/lib")
    
    if(HELIB_INCLUDE_DIRS AND HELIB_LIBRARY)
        set(HELIB_FOUND TRUE)
        message(STATUS "✓ HElib found (dynamic): ${HELIB_LIBRARY}")
        add_definitions(-DKCTSB_HAS_HELIB)
        
        if(NOT TARGET helib::helib)
            add_library(helib::helib SHARED IMPORTED)
            set_target_properties(helib::helib PROPERTIES
                IMPORTED_LOCATION "${HELIB_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${HELIB_INCLUDE_DIRS}")
        endif()
    else()
        message(STATUS "⚠ HElib not found (optional)")
        set(KCTSB_ENABLE_HELIB OFF)
    endif()
endif()

# -----------------------------------------------------------------------------
# OpenSSL for benchmarks ONLY
# -----------------------------------------------------------------------------
if(KCTSB_BUILD_BENCHMARKS AND KCTSB_ENABLE_OPENSSL)
    find_package(OpenSSL QUIET)
    if(OPENSSL_FOUND)
        message(STATUS "✓ OpenSSL for benchmarks: ${OPENSSL_VERSION}")
        add_definitions(-DKCTSB_BENCHMARK_HAS_OPENSSL)
    else()
        message(STATUS "⚠ OpenSSL not found, limited benchmarks")
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
file(GLOB KCTSB_RSA_SOURCES ${KCTSB_SRC_DIR}/crypto/rsa/*.cpp)
set(KCTSB_ECC_SOURCES
    ${KCTSB_SRC_DIR}/crypto/ecc/ecc_curve.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecdh.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecdsa.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecies.cpp
)
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
# v4.0.1: Exclude unnecessary NTL utilities - use system threading/timing
list(FILTER BIGNUM_CORE_SOURCES EXCLUDE REGEX "BasicThreadPool\\.cpp$")
list(FILTER BIGNUM_CORE_SOURCES EXCLUDE REGEX "thread\\.cpp$")
list(FILTER BIGNUM_CORE_SOURCES EXCLUDE REGEX "subset\\.cpp$")
list(FILTER BIGNUM_CORE_SOURCES EXCLUDE REGEX "fileio\\.cpp$")
list(FILTER BIGNUM_CORE_SOURCES EXCLUDE REGEX "newnames\\.cpp$")

# Ring sources - all needed for GF2/ZZ_p arithmetic
file(GLOB BIGNUM_RING_SOURCES ${KCTSB_SRC_DIR}/math/bignum/ring/*.cpp)

# Vector and Matrix sources - essential for linear algebra
file(GLOB BIGNUM_VECTOR_SOURCES ${KCTSB_SRC_DIR}/math/bignum/vector/*.cpp)
file(GLOB BIGNUM_MATRIX_SOURCES ${KCTSB_SRC_DIR}/math/bignum/matrix/*.cpp)

# Polynomial sources - GF2X is essential for security algorithms
file(GLOB BIGNUM_POLY_SOURCES ${KCTSB_SRC_DIR}/math/bignum/poly/*.cpp)

# FFT sources - needed for efficient polynomial multiplication
file(GLOB BIGNUM_FFT_SOURCES ${KCTSB_SRC_DIR}/math/bignum/fft/*.cpp)

# v4.0.1: EXCLUDE precision directory entirely (RR, xdouble, quad_float not needed)
# These are arbitrary precision real numbers - kctsb uses integer arithmetic only
set(BIGNUM_PRECISION_SOURCES "")
message(STATUS "  Note: Precision modules (RR, xdouble, quad_float) excluded - not needed")

# Lattice sources - only basic LLL needed, exclude extended precision variants
file(GLOB BIGNUM_LATTICE_SOURCES ${KCTSB_SRC_DIR}/math/bignum/lattice/*.cpp)
# Exclude Givens rotation variants and extended precision LLL
list(FILTER BIGNUM_LATTICE_SOURCES EXCLUDE REGEX "G_LLL_.*\\.cpp$")
list(FILTER BIGNUM_LATTICE_SOURCES EXCLUDE REGEX "LLL_QP\\.cpp$")
list(FILTER BIGNUM_LATTICE_SOURCES EXCLUDE REGEX "LLL_RR\\.cpp$")
list(FILTER BIGNUM_LATTICE_SOURCES EXCLUDE REGEX "LLL_XD\\.cpp$")

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
set(KCTSB_PSI_SOURCES ${KCTSB_SRC_DIR}/advanced/psi/piano_psi.cpp)
if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
    list(APPEND KCTSB_PSI_SOURCES ${KCTSB_SRC_DIR}/advanced/psi/seal_pir.cpp)
endif()
list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_PSI_SOURCES})

# FE sources (requires HElib)
if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
    file(GLOB_RECURSE KCTSB_FE_SOURCES ${KCTSB_SRC_DIR}/advanced/fe/*.cpp)
    list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_FE_SOURCES})
endif()

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
    
    # Dynamic dependencies (SEAL, HElib as shared)
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_static PUBLIC ${SEAL_INCLUDE_DIRS})
        target_link_libraries(kctsb_static PUBLIC SEAL::seal)
        if(WIN32)
            target_link_libraries(kctsb_static PRIVATE bcrypt)
        endif()
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        target_link_libraries(kctsb_static PUBLIC helib::helib)
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
        target_link_libraries(kctsb_shared PUBLIC SEAL::seal)
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        target_link_libraries(kctsb_shared PUBLIC helib::helib)
    endif()
    if(APPLE)
        target_link_libraries(kctsb_shared PRIVATE "-framework Security")
    endif()
    find_package(Threads REQUIRED)
    target_link_libraries(kctsb_shared PUBLIC Threads::Threads)
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
