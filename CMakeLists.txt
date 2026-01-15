# ============================================================================
# kctsb - Knight's Cryptographic Trusted Security Base
# Cross-platform cryptographic algorithms library
#
# Version: 3.4.0 (defined in include/kctsb/version.h - single source of truth)
# Copyright (c) 2019-2026 knightc. All rights reserved.
# Licensed under Apache License 2.0
#
# Architecture: C++ Core + C ABI (v3.4.0+)
# Design Goal: Replace OpenSSL with native implementations
#
# v3.4.0 Changes:
# - Unified public API header (kctsb_api.h)
# - Platform-specific thirdparty: thirdparty/{win-x64,linux-x64,macos-x64}/
# - Single-file static library distribution (all deps bundled)
# - LTO enabled with compiler version detection
# ============================================================================

cmake_minimum_required(VERSION 3.20)

project(kctsb
    VERSION 3.4.0
    DESCRIPTION "Production-grade cryptographic algorithms library - OpenSSL replacement"
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
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "====================================================================")
message(STATUS "")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# ============================================================================
# Platform Detection and Thirdparty Path Setup
# ============================================================================

# Detect platform suffix for thirdparty directory
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

# Thirdparty directories (platform-specific first, then common)
set(KCTSB_THIRDPARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)
set(KCTSB_THIRDPARTY_PLATFORM_DIR ${KCTSB_THIRDPARTY_DIR}/${KCTSB_PLATFORM_SUFFIX})
set(KCTSB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(KCTSB_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# System library paths (fallback)
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

# ============================================================================
# LTO Configuration (with compiler version detection)
# ============================================================================

option(KCTSB_ENABLE_LTO "Enable Link-Time Optimization" ON)

set(KCTSB_LTO_SUPPORTED FALSE)

if(KCTSB_ENABLE_LTO)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        # GCC 12+ recommended for LTO with NTL templates
        if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "12.0")
            set(KCTSB_LTO_SUPPORTED TRUE)
            message(STATUS "LTO: Enabled (GCC ${CMAKE_CXX_COMPILER_VERSION})")
        elseif(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "11.0")
            # GCC 11 may have issues with NTL templates, try anyway
            set(KCTSB_LTO_SUPPORTED TRUE)
            message(STATUS "LTO: Enabled (GCC ${CMAKE_CXX_COMPILER_VERSION} - may have issues with NTL)")
        else()
            message(STATUS "LTO: Disabled (GCC < 11.0)")
        endif()
        
        # For GCC LTO, use gcc-ar and gcc-ranlib to handle LTO object files
        if(KCTSB_LTO_SUPPORTED)
            find_program(GCC_AR NAMES gcc-ar gcc-ar-13 gcc-ar-12 HINTS ${CMAKE_CXX_COMPILER_DIR})
            find_program(GCC_RANLIB NAMES gcc-ranlib gcc-ranlib-13 gcc-ranlib-12 HINTS ${CMAKE_CXX_COMPILER_DIR})
            if(GCC_AR AND GCC_RANLIB)
                set(CMAKE_AR ${GCC_AR})
                set(CMAKE_RANLIB ${GCC_RANLIB})
                message(STATUS "LTO: Using gcc-ar (${GCC_AR}) and gcc-ranlib (${GCC_RANLIB})")
            else()
                # Fallback: try with full path from compiler directory
                get_filename_component(COMPILER_DIR ${CMAKE_CXX_COMPILER} DIRECTORY)
                if(EXISTS "${COMPILER_DIR}/gcc-ar.exe")
                    set(CMAKE_AR "${COMPILER_DIR}/gcc-ar.exe")
                    set(CMAKE_RANLIB "${COMPILER_DIR}/gcc-ranlib.exe")
                    message(STATUS "LTO: Using gcc-ar from compiler directory")
                elseif(EXISTS "${COMPILER_DIR}/gcc-ar")
                    set(CMAKE_AR "${COMPILER_DIR}/gcc-ar")
                    set(CMAKE_RANLIB "${COMPILER_DIR}/gcc-ranlib")
                    message(STATUS "LTO: Using gcc-ar from compiler directory")
                else()
                    message(WARNING "LTO: gcc-ar/gcc-ranlib not found, static library may fail")
                endif()
            endif()
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang")
        set(KCTSB_LTO_SUPPORTED TRUE)
        message(STATUS "LTO: Enabled (Clang ${CMAKE_CXX_COMPILER_VERSION})")
        # For Clang, use llvm-ar
        find_program(LLVM_AR NAMES llvm-ar)
        if(LLVM_AR)
            set(CMAKE_AR ${LLVM_AR})
            message(STATUS "LTO: Using llvm-ar")
        endif()
    elseif(MSVC)
        set(KCTSB_LTO_SUPPORTED TRUE)
        message(STATUS "LTO: Enabled (MSVC)")
    endif()
endif()

# ============================================================================
# Performance Optimization
# ============================================================================

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        add_compile_options(
            /O2 /Oi /Ot /GL      # Maximum optimization
            /fp:fast              # Fast floating-point
            /GR-                  # Disable RTTI
            /EHs-c-               # Disable exceptions
        )
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
            add_compile_options(/arch:AVX2)
        endif()
        if(KCTSB_LTO_SUPPORTED)
            add_link_options(/LTCG)
        endif()
    else()
        # GCC/Clang unified optimization flags
        add_compile_options(
            -O3
            -march=native
            -mtune=native
            -ffast-math
            -funroll-loops
            -fomit-frame-pointer
            -fPIC
            -fstack-protector-strong
        )

        # C++ only flags (RTTI disabled for smaller binary)
        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)

        # LTO flags
        if(KCTSB_LTO_SUPPORTED)
            add_compile_options(-flto)
            add_link_options(-flto)
        endif()

        # Hardware acceleration (x86_64)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
            add_compile_options(-maes -mpclmul -msse4.1 -msse4.2 -mavx2)
        endif()

        # ARM64 NEON
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
            add_compile_options(-march=armv8-a+crypto)
        endif()

        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()
endif()

# ============================================================================
# Hardware Feature Detection
# ============================================================================

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-maes" COMPILER_SUPPORTS_AESNI)
if(COMPILER_SUPPORTS_AESNI)
    message(STATUS "AES-NI: Enabled")
    add_compile_definitions(KCTSB_HAS_AESNI=1)
else()
    message(STATUS "AES-NI: Not available")
endif()

check_cxx_compiler_flag("-mpclmul" COMPILER_SUPPORTS_PCLMUL)
if(COMPILER_SUPPORTS_PCLMUL)
    message(STATUS "PCLMUL: Enabled")
    add_compile_definitions(KCTSB_HAS_PCLMUL=1)
endif()

# ============================================================================
# Warning Flags - STRICT MODE (Zero warnings policy)
# ============================================================================

option(KCTSB_ENABLE_CLANG_TIDY "Enable clang-tidy static analysis" OFF)
option(KCTSB_ENABLE_SANITIZERS "Enable Address/Undefined sanitizers" OFF)
option(KCTSB_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)

# Clang-Tidy integration
if(KCTSB_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES "clang-tidy" "clang-tidy-15" "clang-tidy-16" "clang-tidy-17")
    if(CLANG_TIDY_EXE)
        message(STATUS "✓ clang-tidy found: ${CLANG_TIDY_EXE}")
        # Only apply to project sources, not thirdparty
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE};--config-file=${CMAKE_SOURCE_DIR}/.clang-tidy")
    else()
        message(WARNING "clang-tidy not found, static analysis disabled")
    endif()
endif()

# Sanitizers (Debug builds only)
if(KCTSB_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(STATUS "✓ Sanitizers enabled (ASan + UBSan)")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

# Strict warning flags for project code
if(WIN32)
    if(MSVC)
        add_compile_options(
            /W4                     # High warning level
            /utf-8                  # UTF-8 source and execution charset
            /permissive-            # Strict C++ conformance
            /we4715                 # Not all control paths return a value
            /we4716                 # Function must return a value
            /we4834                 # Discarding return value with [[nodiscard]]
            /we4172                 # Returning address of local variable
            /wd4100                 # Unreferenced formal parameter (allow)
        )
        if(KCTSB_WARNINGS_AS_ERRORS)
            add_compile_options(/WX)
        endif()
    else()
        # MinGW/GCC on Windows - Full strict mode
        add_compile_options(
            # Core warnings
            -Wall -Wextra -Wpedantic
            # Fatal errors for critical issues
            -Werror=return-type
            -Werror=uninitialized
            -Werror=format
            -Werror=format-security
            # Modern C++ best practices
            -Wshadow                    # Variable shadowing
            -Wnon-virtual-dtor          # Missing virtual destructor
            -Wold-style-cast            # C-style casts (prefer static_cast)
            -Woverloaded-virtual        # Unintended virtual overloading
            -Wcast-align                # Pointer cast alignment
            -Wconversion                # Implicit type conversion
            -Wsign-conversion           # Sign conversion
            -Wdouble-promotion          # Float to double implicit conversion
            -Wformat=2                  # Printf format string issues
            -Wnull-dereference          # Null pointer dereference
            -Wunused                    # Unused entities
            -Wduplicated-cond           # Duplicated if-else conditions
            -Wduplicated-branches       # Duplicated if-else branches
            -Wlogical-op                # Suspicious logical operations
            -Wuseless-cast              # Useless casts
            # Suppress noisy warnings from thirdparty
            -Wno-unused-parameter
            -Wno-array-bounds
            -Wno-stringop-overflow
            # Charset
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
        )
        if(KCTSB_WARNINGS_AS_ERRORS)
            add_compile_options(-Werror)
        endif()
    endif()
elseif(APPLE)
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Werror=return-type
        -Werror=uninitialized
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Woverloaded-virtual
        -Wcast-align
        -Wconversion
        -Wsign-conversion
        -Wdouble-promotion
        -Wformat=2
        -Wnull-dereference
        -Wunused
        -Wno-unused-parameter
        -Wno-array-bounds
        -Wno-deprecated-copy
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
    )
    if(KCTSB_WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif()
elseif(UNIX)
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Werror=return-type
        -Werror=uninitialized
        -Werror=format
        -Werror=format-security
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Woverloaded-virtual
        -Wcast-align
        -Wconversion
        -Wsign-conversion
        -Wdouble-promotion
        -Wformat=2
        -Wnull-dereference
        -Wunused
        -Wduplicated-cond
        -Wduplicated-branches
        -Wlogical-op
        -Wuseless-cast
        -Wno-unused-parameter
        -Wno-array-bounds
        -Wno-stringop-overflow
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
    )
    if(KCTSB_WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif()
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

# Core dependencies
option(KCTSB_ENABLE_NTL "Enable NTL (required for ECC/RSA)" ON)
option(KCTSB_ENABLE_GMP "Enable GMP (required for NTL)" ON)

# Optional dependencies
option(KCTSB_ENABLE_SEAL "Enable Microsoft SEAL for HE" ON)
option(KCTSB_ENABLE_HELIB "Enable HElib for FE" ON)
option(KCTSB_ENABLE_ZLIB "Enable zlib compression" ON)
option(KCTSB_ENABLE_ZSTD "Enable zstd compression" ON)

# Benchmark-only dependency
option(KCTSB_ENABLE_OPENSSL "Enable OpenSSL (ONLY for benchmarks)" ON)

# Distribution option: bundle all deps into single static library
option(KCTSB_BUNDLE_DEPS "Bundle dependencies into single static library" ON)

# ============================================================================
# Output Directories
# ============================================================================

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ============================================================================
# Third-Party Dependencies (Platform thirdparty FIRST, then common, then system)
# ============================================================================

# Helper macro: Find library in thirdparty (platform-specific first, then common)
macro(kctsb_find_thirdparty_lib OUT_VAR LIB_NAME)
    # 1. Try platform-specific thirdparty first
    find_library(${OUT_VAR} NAMES ${LIB_NAME} lib${LIB_NAME}
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/lib"
        NO_DEFAULT_PATH)
    
    # 2. Then try common thirdparty
    if(NOT ${OUT_VAR})
        find_library(${OUT_VAR} NAMES ${LIB_NAME} lib${LIB_NAME}
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib"
            NO_DEFAULT_PATH)
    endif()
    
    # 3. Finally try system paths
    if(NOT ${OUT_VAR})
        find_library(${OUT_VAR} NAMES ${LIB_NAME} lib${LIB_NAME}
            HINTS ${KCTSB_SYSTEM_LIB_HINTS})
    endif()
endmacro()

# Helper macro: Find include in thirdparty
macro(kctsb_find_thirdparty_inc OUT_VAR HEADER_FILE)
    # 1. Try platform-specific thirdparty first
    find_path(${OUT_VAR} ${HEADER_FILE}
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/include"
        NO_DEFAULT_PATH)
    
    # 2. Then try common thirdparty
    if(NOT ${OUT_VAR})
        find_path(${OUT_VAR} ${HEADER_FILE}
            HINTS "${KCTSB_THIRDPARTY_DIR}/include"
            NO_DEFAULT_PATH)
    endif()
    
    # 3. Finally try system paths
    if(NOT ${OUT_VAR})
        find_path(${OUT_VAR} ${HEADER_FILE}
            HINTS ${KCTSB_SYSTEM_INC_HINTS})
    endif()
endmacro()

# Collect all dependency libraries for bundling
set(KCTSB_BUNDLED_LIBS "")

# -----------------------------------------------------------------------------
# NTL Detection
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_NTL)
    set(NTL_FOUND FALSE)
    
    kctsb_find_thirdparty_inc(NTL_INCLUDE_DIRS NTL/ZZ.h)
    kctsb_find_thirdparty_lib(NTL_LIBRARY ntl)
    
    # gf2x is required by NTL when compiled with NTL_GF2X_LIB=on
    kctsb_find_thirdparty_lib(GF2X_LIBRARY gf2x)
    
    if(NTL_INCLUDE_DIRS AND NTL_LIBRARY)
        set(NTL_FOUND TRUE)
        message(STATUS "✓ NTL found: ${NTL_LIBRARY}")
        add_definitions(-DKCTSB_HAS_NTL)
        
        # Build NTL link libraries list (NTL depends on gf2x and gmp)
        set(NTL_LINK_LIBRARIES "${NTL_LIBRARY}")
        if(GF2X_LIBRARY)
            list(APPEND NTL_LINK_LIBRARIES "${GF2X_LIBRARY}")
            message(STATUS "✓ gf2x found: ${GF2X_LIBRARY}")
        endif()
        
        if(NOT TARGET NTL::NTL)
            add_library(NTL::NTL STATIC IMPORTED)
            set_target_properties(NTL::NTL PROPERTIES
                IMPORTED_LOCATION "${NTL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${NTL_INCLUDE_DIRS}")
            # NTL requires gf2x when compiled with NTL_GF2X_LIB
            if(GF2X_LIBRARY)
                set_target_properties(NTL::NTL PROPERTIES
                    INTERFACE_LINK_LIBRARIES "${GF2X_LIBRARY}")
            endif()
        endif()
        
        list(APPEND KCTSB_BUNDLED_LIBS ${NTL_LINK_LIBRARIES})
    else()
        message(FATAL_ERROR "NTL not found. Place in thirdparty/${KCTSB_PLATFORM_SUFFIX}/ or thirdparty/")
    endif()
endif()

# -----------------------------------------------------------------------------
# GMP Detection
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_GMP)
    set(GMP_FOUND FALSE)
    
    kctsb_find_thirdparty_inc(GMP_INCLUDE_DIRS gmp.h)
    kctsb_find_thirdparty_lib(GMP_LIBRARY gmp)
    kctsb_find_thirdparty_lib(GMPXX_LIBRARY gmpxx)
    
    if(GMP_INCLUDE_DIRS AND GMP_LIBRARY)
        set(GMP_FOUND TRUE)
        message(STATUS "✓ GMP found: ${GMP_LIBRARY}")
        add_definitions(-DKCTSB_HAS_GMP)
        
        set(GMP_LIBRARIES ${GMP_LIBRARY})
        if(GMPXX_LIBRARY)
            list(APPEND GMP_LIBRARIES ${GMPXX_LIBRARY})
            add_definitions(-DKCTSB_HAS_GMPXX)
        endif()
        
        if(NOT TARGET GMP::GMP)
            add_library(GMP::GMP STATIC IMPORTED)
            set_target_properties(GMP::GMP PROPERTIES
                IMPORTED_LOCATION "${GMP_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}")
        endif()
        
        list(APPEND KCTSB_BUNDLED_LIBS "${GMP_LIBRARY}")
        if(GMPXX_LIBRARY)
            list(APPEND KCTSB_BUNDLED_LIBS "${GMPXX_LIBRARY}")
        endif()
    else()
        message(FATAL_ERROR "GMP not found. Place in thirdparty/${KCTSB_PLATFORM_SUFFIX}/ or thirdparty/")
    endif()
endif()

# -----------------------------------------------------------------------------
# SEAL Detection (optional)
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_SEAL)
    set(SEAL_FOUND FALSE)
    
    # Try platform-specific first
    find_path(SEAL_INCLUDE_DIRS seal/seal.h
        HINTS "${KCTSB_THIRDPARTY_PLATFORM_DIR}/include/SEAL-4.1"
              "${KCTSB_THIRDPARTY_DIR}/include/SEAL-4.1"
        NO_DEFAULT_PATH)
    
    if(NOT SEAL_INCLUDE_DIRS)
        find_path(SEAL_INCLUDE_DIRS seal/seal.h
            HINTS ${KCTSB_SYSTEM_INC_HINTS}
            PATH_SUFFIXES SEAL-4.1)
    endif()
    
    kctsb_find_thirdparty_lib(SEAL_LIBRARY seal-4.1)
    
    if(SEAL_INCLUDE_DIRS AND SEAL_LIBRARY)
        set(SEAL_FOUND TRUE)
        message(STATUS "✓ SEAL found: ${SEAL_LIBRARY}")
        add_definitions(-DKCTSB_HAS_SEAL)
        
        if(NOT TARGET SEAL::seal)
            add_library(SEAL::seal STATIC IMPORTED)
            set_target_properties(SEAL::seal PROPERTIES
                IMPORTED_LOCATION "${SEAL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${SEAL_INCLUDE_DIRS}")
        endif()
        
        list(APPEND KCTSB_BUNDLED_LIBS "${SEAL_LIBRARY}")
    else()
        message(STATUS "⚠ SEAL not found (optional)")
        set(KCTSB_ENABLE_SEAL OFF)
    endif()
endif()

# -----------------------------------------------------------------------------
# HElib Detection (optional)
# -----------------------------------------------------------------------------
if(KCTSB_ENABLE_HELIB)
    set(HELIB_FOUND FALSE)
    
    kctsb_find_thirdparty_inc(HELIB_INCLUDE_DIRS helib/helib.h)
    kctsb_find_thirdparty_lib(HELIB_LIBRARY helib)
    
    if(HELIB_INCLUDE_DIRS AND HELIB_LIBRARY)
        set(HELIB_FOUND TRUE)
        message(STATUS "✓ HElib found: ${HELIB_LIBRARY}")
        add_definitions(-DKCTSB_HAS_HELIB)
        
        if(NOT TARGET helib)
            add_library(helib STATIC IMPORTED)
            set_target_properties(helib PROPERTIES
                IMPORTED_LOCATION "${HELIB_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${HELIB_INCLUDE_DIRS}")
        endif()
        
        list(APPEND KCTSB_BUNDLED_LIBS "${HELIB_LIBRARY}")
    else()
        message(STATUS "⚠ HElib not found (optional, use -DKCTSB_ENABLE_HELIB=OFF to disable)")
        set(KCTSB_ENABLE_HELIB OFF)
    endif()
endif()

# -----------------------------------------------------------------------------
# OpenSSL for benchmarks ONLY
# -----------------------------------------------------------------------------
if(KCTSB_BUILD_BENCHMARKS AND KCTSB_ENABLE_OPENSSL)
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

# zlib (optional)
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
# Source Files
# ============================================================================

file(GLOB_RECURSE KCTSB_CORE_SOURCES
    ${KCTSB_SRC_DIR}/core/*.cpp
    ${KCTSB_SRC_DIR}/core/*.c
)

file(GLOB KCTSB_AES_SOURCES
    ${KCTSB_SRC_DIR}/crypto/aes.cpp
    ${KCTSB_SRC_DIR}/crypto/ghash.cpp
    ${KCTSB_SRC_DIR}/crypto/mac.cpp
)

set(KCTSB_CHACHA_SOURCES
    ${KCTSB_SRC_DIR}/crypto/chacha20_poly1305.cpp
)

set(KCTSB_HASH_SOURCES
    ${KCTSB_SRC_DIR}/crypto/sha256.cpp
    ${KCTSB_SRC_DIR}/crypto/sha512.cpp
    ${KCTSB_SRC_DIR}/crypto/sha3.cpp
    ${KCTSB_SRC_DIR}/crypto/blake2.cpp
)

set(KCTSB_SM_SOURCES
    ${KCTSB_SRC_DIR}/crypto/sm/sm3.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/sm4.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/sm2.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/zuc.cpp
)

set(KCTSB_WHITEBOX_SOURCES
    ${KCTSB_SRC_DIR}/advanced/whitebox/whitebox_aes.c
)

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

# PSI/PIR
set(KCTSB_PSI_SOURCES
    ${KCTSB_SRC_DIR}/advanced/psi/piano_psi.cpp
)

if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
    list(APPEND KCTSB_PSI_SOURCES ${KCTSB_SRC_DIR}/advanced/psi/seal_pir.cpp)
endif()

list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_PSI_SOURCES})

# OTP (One-Time Password) - always included
file(GLOB_RECURSE KCTSB_OTP_SOURCES ${KCTSB_SRC_DIR}/advanced/otp/*.cpp)
list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_OTP_SOURCES})

if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
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

# Include directories for both thirdparty locations
set(KCTSB_THIRDPARTY_INCLUDE_DIRS
    ${KCTSB_THIRDPARTY_PLATFORM_DIR}/include
    ${KCTSB_THIRDPARTY_DIR}/include
)

if(KCTSB_BUILD_STATIC)
    add_library(kctsb_static STATIC ${KCTSB_ALL_SOURCES})
    target_include_directories(kctsb_static PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_PLATFORM_DIR}/include>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_compile_definitions(kctsb_static PRIVATE KCTSB_BUILDING)
    
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_static PUBLIC ${SEAL_INCLUDE_DIRS})
    endif()
    set_target_properties(kctsb_static PROPERTIES OUTPUT_NAME kctsb)

    # Platform-specific system libraries (always needed, not bundled)
    if(WIN32)
        target_link_libraries(kctsb_static PRIVATE bcrypt)
    elseif(APPLE)
        target_link_libraries(kctsb_static PRIVATE "-framework Security")
    endif()
    
    # Link dependencies
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
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_PLATFORM_DIR}/include>
        $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_shared PUBLIC ${SEAL_INCLUDE_DIRS})
    endif()
    target_compile_definitions(kctsb_shared PRIVATE KCTSB_BUILDING KCTSB_SHARED_LIBRARY)
    set_target_properties(kctsb_shared PROPERTIES
        OUTPUT_NAME kctsb VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

    if(WIN32)
        target_link_libraries(kctsb_shared PRIVATE bcrypt)
    elseif(APPLE)
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
# Bundled Static Library (like OpenSSL - single file distribution)
# ============================================================================

# Note: CMake doesn't directly support merging static libraries.
# The bundled library is created by the build scripts (build.ps1, build.sh)
# using platform-specific tools (ar, lib.exe).
# 
# For distribution, users only need:
#   - libkctsb.a (static) or libkctsb.so/.dll (shared)
#   - kctsb_api.h (public header)
#   - Link with: -lkctsb -lstdc++ [-lbcrypt on Windows]

# ============================================================================
# CLI Tool
# ============================================================================

if(KCTSB_BUILD_CLI)
    file(GLOB KCTSB_CLI_SOURCES ${KCTSB_SRC_DIR}/cli/*.cpp)
    add_executable(kctsb_cli ${KCTSB_CLI_SOURCES})
    target_include_directories(kctsb_cli PRIVATE
        ${KCTSB_INCLUDE_DIR}
        ${KCTSB_THIRDPARTY_PLATFORM_DIR}/include
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

    # Install ONLY the unified public API header
    install(FILES ${KCTSB_INCLUDE_DIR}/kctsb/kctsb_api.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        RENAME kctsb_api.h)

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
message(STATUS "Static lib:       ${KCTSB_BUILD_STATIC}")
message(STATUS "Shared lib:       ${KCTSB_BUILD_SHARED}")
message(STATUS "CLI tool:         ${KCTSB_BUILD_CLI}")
message(STATUS "Tests:            ${KCTSB_BUILD_TESTS}")
message(STATUS "Benchmarks:       ${KCTSB_BUILD_BENCHMARKS}")
message(STATUS "LTO:              ${KCTSB_LTO_SUPPORTED}")
message(STATUS "")
message(STATUS "Thirdparty search order:")
message(STATUS "  1. ${KCTSB_THIRDPARTY_PLATFORM_DIR}")
message(STATUS "  2. ${KCTSB_THIRDPARTY_DIR}")
message(STATUS "  3. System paths")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  NTL:    ${KCTSB_ENABLE_NTL}")
message(STATUS "  GMP:    ${KCTSB_ENABLE_GMP}")
message(STATUS "  SEAL:   ${KCTSB_ENABLE_SEAL}")
message(STATUS "  HElib:  ${KCTSB_ENABLE_HELIB}")
message(STATUS "")
message(STATUS "Distribution (like OpenSSL):")
message(STATUS "  Header:  kctsb_api.h (single public header)")
message(STATUS "  Library: libkctsb.a / libkctsb.so / kctsb.dll")
message(STATUS "  Link:    -lkctsb -lstdc++ [-lbcrypt on Windows]")
message(STATUS "")
