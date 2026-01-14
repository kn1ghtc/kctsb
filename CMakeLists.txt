# ============================================================================
# kctsb - Knight's Cryptographic Trusted Security Base
# Cross-platform cryptographic algorithms library
#
# Version: 3.3.3 (defined in include/kctsb/version.h - single source of truth)
# Copyright (c) 2019-2026 knightc. All rights reserved.
# Licensed under Apache License 2.0
#
# Design Goal: Replace OpenSSL with native implementations
# ============================================================================

cmake_minimum_required(VERSION 3.20)

project(kctsb
    VERSION 3.3.3
    DESCRIPTION "Production-grade cryptographic algorithms library - OpenSSL replacement"
    LANGUAGES C CXX
)

# ============================================================================
# Build Configuration
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

message(STATUS "")
message(STATUS "====================================================================")
message(STATUS "kctsb - Knight's Cryptographic Trusted Security Base")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "====================================================================")
message(STATUS "")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# ============================================================================
# Performance Optimization (Maximum Speed + Security)
# ============================================================================

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        add_compile_options(/O2 /Oi /Ot /GL /fp:fast)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
            add_compile_options(/arch:AVX2)
        endif()
        add_link_options(/LTCG)
    else()
        if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            # MinGW LTO frequently triggers unresolved symbols with large static archives
            add_compile_options(
                -O3 -march=native -mtune=native
                -ffast-math -funroll-loops -fomit-frame-pointer
                -fPIC
                -fstack-protector-strong
            )
        else()
            add_compile_options(
                -O3 -march=native -mtune=native
                -ffast-math -funroll-loops -fomit-frame-pointer
                -flto -fPIC
                -fstack-protector-strong
                # Hardware acceleration instructions
                -maes -mpclmul -msse4.1 -msse4.2 -mavx2
            )
            add_link_options(-flto)
        endif()
        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()
endif()

# ============================================================================
# Hardware Feature Detection and Defines
# ============================================================================

# Check for AES-NI support
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-maes" COMPILER_SUPPORTS_AESNI)
if(COMPILER_SUPPORTS_AESNI)
    message(STATUS "AES-NI: Enabled")
    add_compile_definitions(KCTSB_HAS_AESNI=1)
else()
    message(STATUS "AES-NI: Not available")
endif()

# Check for PCLMUL (for GCM/GHASH)
check_cxx_compiler_flag("-mpclmul" COMPILER_SUPPORTS_PCLMUL)
if(COMPILER_SUPPORTS_PCLMUL)
    message(STATUS "PCLMUL: Enabled")
    add_compile_definitions(KCTSB_HAS_PCLMUL=1)
endif()

# ============================================================================
# Warning Flags and UTF-8 Encoding
# ============================================================================

# Platform detection
if(WIN32)
    set(KCTSB_PLATFORM "windows")
    add_definitions(-DKCTSB_PLATFORM_WINDOWS -D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
    if(MSVC)
        # MSVC warning flags
        add_compile_options(
            /W4                     # Warning level 4
            /utf-8                  # UTF-8 source and execution charset
            /permissive-            # Standards conformance
        )
        # Treat specific warnings as errors
        add_compile_options(/we4715)  # Not all control paths return a value
    else()
        # MinGW/GCC on Windows
        add_compile_options(
            -Wall -Wextra -Wpedantic
            -Werror=return-type
            -Werror=uninitialized
            -Wno-unused-parameter      # Allow unused params in interface functions
            -Wno-array-bounds          # Suppress NTL false positives on vector bounds
            -Wno-stringop-overflow     # Suppress NTL vec memset false positives
            -finput-charset=UTF-8      # Input encoding
            -fexec-charset=UTF-8       # Output encoding
        )
    endif()
elseif(APPLE)
    set(KCTSB_PLATFORM "macos")
    add_definitions(-DKCTSB_PLATFORM_MACOS)
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Werror=return-type
        -Werror=uninitialized
        -Wno-unused-parameter
        -Wno-array-bounds          # Suppress NTL false positives on vector bounds
        -Wno-deprecated-copy       # Suppress NTL GF2.h implicit copy warning
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
    )
elseif(UNIX)
    set(KCTSB_PLATFORM "linux")
    add_definitions(-DKCTSB_PLATFORM_LINUX)
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Werror=return-type
        -Werror=uninitialized
        -Wno-unused-parameter
        -Wno-array-bounds          # Suppress NTL false positives on vector bounds
        -Wno-stringop-overflow     # Suppress NTL vec memset false positives
        -Wno-stringop-overflow     # Suppress NTL vec memset false positives
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
    )
endif()

# ============================================================================
# Build Options
# ============================================================================

option(KCTSB_BUILD_SHARED "Build shared library" ON)
option(KCTSB_BUILD_STATIC "Build static library" ON)
option(KCTSB_BUILD_TESTS "Build tests" ON)
option(KCTSB_BUILD_BENCHMARKS "Build benchmarks (requires OpenSSL)" ON)
option(KCTSB_BUILD_CLI "Build kctsb.exe CLI tool" ON)
option(KCTSB_BUILD_EXAMPLES "Build C++ examples" ON)
option(KCTSB_INSTALL "Generate install target" ON)

# Core dependencies (always required)
option(KCTSB_ENABLE_NTL "Enable NTL (required for ECC/RSA)" ON)
option(KCTSB_ENABLE_GMP "Enable GMP (required for NTL)" ON)

# Optional dependencies
option(KCTSB_ENABLE_SEAL "Enable Microsoft SEAL for HE" ON)
option(KCTSB_ENABLE_HELIB "Enable HElib for FE" ON)
option(KCTSB_ENABLE_ZLIB "Enable zlib compression" ON)
option(KCTSB_ENABLE_ZSTD "Enable zstd compression" ON)

# Benchmark-only dependency
option(KCTSB_ENABLE_OPENSSL "Enable OpenSSL (ONLY for benchmarks)" ON)

# ============================================================================
# Output Directories
# ============================================================================

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============================================================================
# Third-Party Dependencies (Cross-Platform: thirdparty/ first, then system)
# ============================================================================

set(KCTSB_THIRDPARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)
set(KCTSB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(KCTSB_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Platform-specific library paths
if(APPLE)
    set(KCTSB_SYSTEM_LIB_HINTS "/usr/local/lib" "/opt/homebrew/lib" "/usr/lib")
    set(KCTSB_SYSTEM_INC_HINTS "/usr/local/include" "/opt/homebrew/include" "/usr/include")
elseif(UNIX)
    set(KCTSB_SYSTEM_LIB_HINTS "/usr/local/lib" "/usr/lib" "/usr/lib/x86_64-linux-gnu")
    set(KCTSB_SYSTEM_INC_HINTS "/usr/local/include" "/usr/include")
else()
    set(KCTSB_SYSTEM_LIB_HINTS "")
    set(KCTSB_SYSTEM_INC_HINTS "")
endif()

# NTL Detection (thirdparty first, then system)
if(KCTSB_ENABLE_NTL)
    set(NTL_FOUND FALSE)

    # Try thirdparty first
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/NTL/ZZ.h")
        set(NTL_INCLUDE_DIRS "${KCTSB_THIRDPARTY_DIR}/include")
        find_library(NTL_LIBRARY NAMES ntl libntl
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib" NO_DEFAULT_PATH)
        if(NTL_LIBRARY)
            set(NTL_FOUND TRUE)
            message(STATUS "✓ NTL found (thirdparty): ${NTL_LIBRARY}")
        endif()
    endif()

    # Fallback to system paths
    if(NOT NTL_FOUND)
        find_path(NTL_INCLUDE_DIRS NTL/ZZ.h HINTS ${KCTSB_SYSTEM_INC_HINTS})
        find_library(NTL_LIBRARY NAMES ntl libntl HINTS ${KCTSB_SYSTEM_LIB_HINTS})
        if(NTL_INCLUDE_DIRS AND NTL_LIBRARY)
            set(NTL_FOUND TRUE)
            message(STATUS "✓ NTL found (system): ${NTL_LIBRARY}")
        endif()
    endif()

    if(NTL_FOUND)
        add_definitions(-DKCTSB_HAS_NTL)
        if(NOT TARGET NTL::NTL)
            add_library(NTL::NTL STATIC IMPORTED)
            set_target_properties(NTL::NTL PROPERTIES
                IMPORTED_LOCATION "${NTL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${NTL_INCLUDE_DIRS}")
        endif()
    else()
        message(FATAL_ERROR "NTL not found. Install via: brew install ntl (macOS) or to thirdparty/")
    endif()
endif()

# GMP Detection (thirdparty first, then system)
if(KCTSB_ENABLE_GMP)
    set(GMP_FOUND FALSE)

    # Try thirdparty first
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/gmp.h")
        set(GMP_INCLUDE_DIRS "${KCTSB_THIRDPARTY_DIR}/include")
        find_library(GMP_LIBRARY NAMES gmp libgmp
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib" NO_DEFAULT_PATH)
        find_library(GMPXX_LIBRARY NAMES gmpxx libgmpxx
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib" NO_DEFAULT_PATH)
        if(GMP_LIBRARY)
            set(GMP_FOUND TRUE)
            message(STATUS "✓ GMP found (thirdparty): ${GMP_LIBRARY}")
        endif()
    endif()

    # Fallback to system paths
    if(NOT GMP_FOUND)
        find_path(GMP_INCLUDE_DIRS gmp.h HINTS ${KCTSB_SYSTEM_INC_HINTS})
        find_library(GMP_LIBRARY NAMES gmp libgmp HINTS ${KCTSB_SYSTEM_LIB_HINTS})
        find_library(GMPXX_LIBRARY NAMES gmpxx libgmpxx HINTS ${KCTSB_SYSTEM_LIB_HINTS})
        if(GMP_INCLUDE_DIRS AND GMP_LIBRARY)
            set(GMP_FOUND TRUE)
            message(STATUS "✓ GMP found (system): ${GMP_LIBRARY}")
        endif()
    endif()

    if(GMP_FOUND)
        set(GMP_LIBRARIES ${GMP_LIBRARY})
        if(GMPXX_LIBRARY)
            list(APPEND GMP_LIBRARIES ${GMPXX_LIBRARY})
            add_definitions(-DKCTSB_HAS_GMPXX)
        endif()
        add_definitions(-DKCTSB_HAS_GMP)
        if(NOT TARGET GMP::GMP)
            add_library(GMP::GMP STATIC IMPORTED)
            set_target_properties(GMP::GMP PROPERTIES
                IMPORTED_LOCATION "${GMP_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}")
        endif()
    else()
        message(FATAL_ERROR "GMP not found. Install via: brew install gmp (macOS) or to thirdparty/")
    endif()
endif()

# SEAL Detection (thirdparty first, then system)
if(KCTSB_ENABLE_SEAL)
    set(SEAL_FOUND FALSE)

    # Try thirdparty first
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/SEAL-4.1/seal/seal.h")
        set(SEAL_INCLUDE_DIRS "${KCTSB_THIRDPARTY_DIR}/include/SEAL-4.1")
        find_library(SEAL_LIBRARY NAMES seal-4.1 libseal-4.1
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib" NO_DEFAULT_PATH)
        if(SEAL_LIBRARY)
            set(SEAL_FOUND TRUE)
            message(STATUS "✓ SEAL found (thirdparty): ${SEAL_LIBRARY}")
        endif()
    endif()

    # Fallback to system paths
    if(NOT SEAL_FOUND)
        find_path(SEAL_INCLUDE_DIRS seal/seal.h
            HINTS ${KCTSB_SYSTEM_INC_HINTS}
            PATH_SUFFIXES SEAL-4.1)
        find_library(SEAL_LIBRARY NAMES seal-4.1 seal
            HINTS ${KCTSB_SYSTEM_LIB_HINTS})
        if(SEAL_INCLUDE_DIRS AND SEAL_LIBRARY)
            set(SEAL_FOUND TRUE)
            message(STATUS "✓ SEAL found (system): ${SEAL_LIBRARY}")
        endif()
    endif()

    if(SEAL_FOUND)
        add_definitions(-DKCTSB_HAS_SEAL)
        if(NOT TARGET SEAL::seal)
            add_library(SEAL::seal STATIC IMPORTED)
            set_target_properties(SEAL::seal PROPERTIES
                IMPORTED_LOCATION "${SEAL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${SEAL_INCLUDE_DIRS}")
        endif()
    else()
        message(STATUS "⚠ SEAL not found (optional)")
        set(KCTSB_ENABLE_SEAL OFF)
    endif()
endif()

# HElib Detection (thirdparty first, then system)
if(KCTSB_ENABLE_HELIB)
    set(HELIB_FOUND FALSE)

    # Try thirdparty first
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/helib/helib.h")
        set(HELIB_INCLUDE_DIRS "${KCTSB_THIRDPARTY_DIR}/include")
        find_library(HELIB_LIBRARY NAMES helib libhelib
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib" NO_DEFAULT_PATH)
        if(HELIB_LIBRARY)
            set(HELIB_FOUND TRUE)
            message(STATUS "✓ HElib found (thirdparty): ${HELIB_LIBRARY}")
        endif()
    endif()

    # Fallback to system paths
    if(NOT HELIB_FOUND)
        find_path(HELIB_INCLUDE_DIRS helib/helib.h HINTS ${KCTSB_SYSTEM_INC_HINTS})
        find_library(HELIB_LIBRARY NAMES helib HINTS ${KCTSB_SYSTEM_LIB_HINTS})
        if(HELIB_INCLUDE_DIRS AND HELIB_LIBRARY)
            set(HELIB_FOUND TRUE)
            message(STATUS "✓ HElib found (system): ${HELIB_LIBRARY}")
        endif()
    endif()

    if(HELIB_FOUND)
        add_definitions(-DKCTSB_HAS_HELIB)
        if(NOT TARGET helib)
            add_library(helib STATIC IMPORTED)
            set_target_properties(helib PROPERTIES
                IMPORTED_LOCATION "${HELIB_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${HELIB_INCLUDE_DIRS}")
        endif()
    else()
        message(FATAL_ERROR "HElib not found. Build thirdparty dependency via scripts/build_helib.ps1 (MSYS2 MinGW) or scripts/build_helib.sh, or disable explicitly with -DKCTSB_ENABLE_HELIB=OFF if you acknowledge the risk.")
    endif()
endif()

# OpenSSL for benchmarks ONLY
if(KCTSB_BUILD_BENCHMARKS AND KCTSB_ENABLE_OPENSSL)
    # macOS: Use Homebrew OpenSSL
    if(APPLE)
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
        set(OPENSSL_INCLUDE_DIR "/usr/local/opt/openssl@3/include")
    endif()
    find_package(OpenSSL QUIET)
    if(OPENSSL_FOUND)
        message(STATUS "✓ OpenSSL for benchmarks: ${OPENSSL_VERSION}")
        add_definitions(-DKCTSB_BENCHMARK_HAS_OPENSSL)
    else()
        message(STATUS "⚠ OpenSSL not found, limited benchmarks")
        set(KCTSB_ENABLE_OPENSSL OFF)
    endif()
endif()

# zlib/zstd
if(KCTSB_ENABLE_ZLIB)
    find_package(ZLIB QUIET)
    if(ZLIB_FOUND)
        message(STATUS "✓ zlib found")
        add_definitions(-DKCTSB_HAS_ZLIB)
    else()
        set(KCTSB_ENABLE_ZLIB OFF)
    endif()
endif()

# ============================================================================
# Source Files (Native Implementations Only - NO OpenSSL in src/)
# ============================================================================

file(GLOB_RECURSE KCTSB_CORE_SOURCES
    ${KCTSB_SRC_DIR}/core/*.cpp
    ${KCTSB_SRC_DIR}/core/*.c
)

file(GLOB KCTSB_AES_SOURCES
    ${KCTSB_SRC_DIR}/crypto/aes/*.cpp
    ${KCTSB_SRC_DIR}/crypto/aes/*.c
)

# ChaCha20 - native implementation only
set(KCTSB_CHACHA_SOURCES
    ${KCTSB_SRC_DIR}/crypto/chacha20/chacha20_poly1305.cpp
)

set(KCTSB_HASH_SOURCES
    ${KCTSB_SRC_DIR}/crypto/hash/keccak.cpp
    ${KCTSB_SRC_DIR}/crypto/hash/blake2.c
    ${KCTSB_SRC_DIR}/crypto/hash/sha256.cpp
    ${KCTSB_SRC_DIR}/crypto/hash/sha512.c
)

set(KCTSB_SM_SOURCES
    ${KCTSB_SRC_DIR}/crypto/sm/sm3.c
    ${KCTSB_SRC_DIR}/crypto/sm/sm4.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/sm_api.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/zuc.c
)

set(KCTSB_WHITEBOX_SOURCES
    ${KCTSB_SRC_DIR}/advanced/whitebox/whitebox_aes.c
)

# SIMD acceleration sources
set(KCTSB_SIMD_SOURCES
    ${KCTSB_SRC_DIR}/simd/simd.cpp
)

set(KCTSB_CRYPTO_SOURCES
    ${KCTSB_AES_SOURCES}
    ${KCTSB_HASH_SOURCES}
    ${KCTSB_CHACHA_SOURCES}
    ${KCTSB_SM_SOURCES}
    ${KCTSB_WHITEBOX_SOURCES}
    ${KCTSB_SIMD_SOURCES}
)

# NTL-dependent modules
if(KCTSB_ENABLE_NTL)
    file(GLOB KCTSB_RSA_SOURCES ${KCTSB_SRC_DIR}/crypto/rsa/*.cpp)
    list(APPEND KCTSB_CRYPTO_SOURCES ${KCTSB_RSA_SOURCES})

    # ECC - NTL-based (replaces MIRACL)
    set(KCTSB_ECC_SOURCES
        ${KCTSB_SRC_DIR}/crypto/ecc/ecc_curve.cpp
        ${KCTSB_SRC_DIR}/crypto/ecc/ecdh.cpp
        ${KCTSB_SRC_DIR}/crypto/ecc/ecdsa.cpp
        ${KCTSB_SRC_DIR}/crypto/ecc/ecies.cpp
    )
    list(APPEND KCTSB_CRYPTO_SOURCES ${KCTSB_ECC_SOURCES})

    file(GLOB_RECURSE KCTSB_MATH_SOURCES ${KCTSB_SRC_DIR}/math/*.cpp)
    file(GLOB_RECURSE KCTSB_ZK_SOURCES ${KCTSB_SRC_DIR}/advanced/zk/*.cpp)
    file(GLOB_RECURSE KCTSB_LATTICE_SOURCES ${KCTSB_SRC_DIR}/advanced/lattice/*.cpp)
    file(GLOB_RECURSE KCTSB_SSS_SOURCES ${KCTSB_SRC_DIR}/advanced/sss/*.cpp)

    set(KCTSB_ADVANCED_SOURCES ${KCTSB_ZK_SOURCES} ${KCTSB_LATTICE_SOURCES} ${KCTSB_SSS_SOURCES})
endif()

# PSI/PIR - Private Set Intersection / Private Information Retrieval
set(KCTSB_PSI_SOURCES
    ${KCTSB_SRC_DIR}/advanced/psi/piano_psi.cpp
)

# SEAL-dependent PIR implementation (only if SEAL is available)
if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
    list(APPEND KCTSB_PSI_SOURCES ${KCTSB_SRC_DIR}/advanced/psi/seal_pir.cpp)
endif()

list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_PSI_SOURCES})

if(KCTSB_ENABLE_HELIB)
    file(GLOB_RECURSE KCTSB_FE_SOURCES ${KCTSB_SRC_DIR}/advanced/fe/*.cpp)
    list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_FE_SOURCES})
endif()

file(GLOB_RECURSE KCTSB_UTIL_SOURCES ${KCTSB_SRC_DIR}/utils/*.cpp)

set(KCTSB_ALL_SOURCES
    ${KCTSB_CORE_SOURCES}
    ${KCTSB_CRYPTO_SOURCES}
    ${KCTSB_ADVANCED_SOURCES}
    ${KCTSB_MATH_SOURCES}
    ${KCTSB_UTIL_SOURCES}
)

# ============================================================================
# Library Targets
# ============================================================================

if(KCTSB_BUILD_STATIC)
    add_library(kctsb_static STATIC ${KCTSB_ALL_SOURCES})
    target_include_directories(kctsb_static PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_compile_definitions(kctsb_static PRIVATE KCTSB_BUILDING)
    # Add SEAL include directory explicitly if available
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_static PUBLIC ${SEAL_INCLUDE_DIRS})
    endif()
    set_target_properties(kctsb_static PROPERTIES OUTPUT_NAME kctsb)

    if(WIN32)
        target_link_libraries(kctsb_static PRIVATE bcrypt)
    elseif(APPLE)
        # Link Security framework for SecRandomCopyBytes
        target_link_libraries(kctsb_static PRIVATE "-framework Security")
    endif()
    if(KCTSB_ENABLE_NTL AND NTL_FOUND)
        target_link_libraries(kctsb_static PUBLIC NTL::NTL)
    endif()
    if(KCTSB_ENABLE_GMP AND GMP_FOUND)
        target_link_libraries(kctsb_static PUBLIC GMP::GMP)
        if(GMPXX_LIBRARY)
            target_link_libraries(kctsb_static PUBLIC ${GMPXX_LIBRARY})
        endif()
    endif()
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_link_libraries(kctsb_static PUBLIC SEAL::seal)
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        target_link_libraries(kctsb_static PUBLIC helib)
    endif()
    if(KCTSB_ENABLE_ZLIB AND ZLIB_FOUND)
        target_link_libraries(kctsb_static PUBLIC ZLIB::ZLIB)
    endif()
endif()

if(KCTSB_BUILD_SHARED)
    add_library(kctsb_shared SHARED ${KCTSB_ALL_SOURCES})
    target_include_directories(kctsb_shared PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    # Add SEAL include directory explicitly if available
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_shared PUBLIC ${SEAL_INCLUDE_DIRS})
    endif()
    target_compile_definitions(kctsb_shared PRIVATE KCTSB_BUILDING KCTSB_SHARED_LIBRARY)
    set_target_properties(kctsb_shared PROPERTIES
        OUTPUT_NAME kctsb VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

    if(WIN32)
        target_link_libraries(kctsb_shared PRIVATE bcrypt)
    elseif(APPLE)
        # Link Security framework for SecRandomCopyBytes
        target_link_libraries(kctsb_shared PRIVATE "-framework Security")
    endif()
    if(KCTSB_ENABLE_NTL AND NTL_FOUND)
        target_link_libraries(kctsb_shared PUBLIC NTL::NTL)
    endif()
    if(KCTSB_ENABLE_GMP AND GMP_FOUND)
        target_link_libraries(kctsb_shared PUBLIC GMP::GMP)
    endif()
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_link_libraries(kctsb_shared PUBLIC SEAL::seal)
    endif()
    if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
        target_link_libraries(kctsb_shared PUBLIC helib)
    endif()
endif()

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
    target_include_directories(kctsb_cli PRIVATE
        ${KCTSB_INCLUDE_DIR}
        ${KCTSB_THIRDPARTY_DIR}/include
    )
    set_target_properties(kctsb_cli PROPERTIES OUTPUT_NAME kctsb)

    if(KCTSB_BUILD_STATIC)
        target_link_libraries(kctsb_cli PRIVATE kctsb_static)
    else()
        target_link_libraries(kctsb_cli PRIVATE kctsb_shared)
    endif()

    if(KCTSB_ENABLE_OPENSSL AND OPENSSL_FOUND)
        target_link_libraries(kctsb_cli PRIVATE OpenSSL::SSL OpenSSL::Crypto)
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
# Installation
# ============================================================================

if(KCTSB_INSTALL)
    include(GNUInstallDirs)
    install(DIRECTORY ${KCTSB_INCLUDE_DIR}/kctsb
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
    if(KCTSB_BUILD_STATIC)
        install(TARGETS kctsb_static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
    endif()
    if(KCTSB_BUILD_SHARED)
        install(TARGETS kctsb_shared
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
    if(KCTSB_BUILD_CLI)
        install(TARGETS kctsb_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endif()

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "=== Configuration Summary ===")
message(STATUS "Static lib:   ${KCTSB_BUILD_STATIC}")
message(STATUS "Shared lib:   ${KCTSB_BUILD_SHARED}")
message(STATUS "CLI tool:     ${KCTSB_BUILD_CLI}")
message(STATUS "Tests:        ${KCTSB_BUILD_TESTS}")
message(STATUS "Benchmarks:   ${KCTSB_BUILD_BENCHMARKS}")
message(STATUS "")
message(STATUS "Dependencies (thirdparty/):")
message(STATUS "  NTL:    ${KCTSB_ENABLE_NTL}")
message(STATUS "  GMP:    ${KCTSB_ENABLE_GMP}")
message(STATUS "  SEAL:   ${KCTSB_ENABLE_SEAL}")
message(STATUS "  HElib:  ${KCTSB_ENABLE_HELIB}")
message(STATUS "")
