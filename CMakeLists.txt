# ============================================================================
# kctsb - Knight's Cryptographic Toolset and Security Base
# Cross-platform cryptographic algorithms library
#
# Copyright (c) 2019-2026 knightc. All rights reserved.
# Licensed under Apache License 2.0
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# Project definition
project(kctsb 
    VERSION 3.0.0
    DESCRIPTION "Production-grade cryptographic algorithms library"
    LANGUAGES C CXX
)

# ============================================================================
# Build Configuration
# ============================================================================

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# C Standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Position Independent Code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type defaults
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS 
        "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# ============================================================================
# Platform-Specific Configuration
# ============================================================================

# Platform detection
if(WIN32)
    set(KCTSB_PLATFORM "windows")
    add_definitions(-DKCTSB_PLATFORM_WINDOWS)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DNOMINMAX)
    # Windows specific compiler flags
    if(MSVC)
        add_compile_options(/W4 /utf-8)
        add_definitions(-D_WIN32_WINNT=0x0601)
    else()
        # MinGW/GCC on Windows
        add_compile_options(-Wall -Wextra -Wpedantic)
    endif()
    set(KCTSB_LIB_SUFFIX ".dll")
elseif(APPLE)
    set(KCTSB_PLATFORM "macos")
    add_definitions(-DKCTSB_PLATFORM_MACOS)
    add_compile_options(-Wall -Wextra -Wpedantic)
    set(KCTSB_LIB_SUFFIX ".dylib")
elseif(UNIX)
    set(KCTSB_PLATFORM "linux")
    add_definitions(-DKCTSB_PLATFORM_LINUX)
    add_compile_options(-Wall -Wextra -Wpedantic)
    set(KCTSB_LIB_SUFFIX ".so")
endif()

# ============================================================================
# Build Options
# ============================================================================

option(KCTSB_BUILD_SHARED "Build shared library" ON)
option(KCTSB_BUILD_STATIC "Build static library" ON)
option(KCTSB_BUILD_TESTS "Build tests" ON)
option(KCTSB_BUILD_EXAMPLES "Build examples" ON)
option(KCTSB_BUILD_BENCHMARKS "Build benchmarks for performance comparison" ON)
option(KCTSB_ENABLE_NTL "Enable NTL support for ECC/RSA/Lattice/ZK" ON)
option(KCTSB_ENABLE_GMP "Enable GMP support for high-precision arithmetic" ON)
option(KCTSB_ENABLE_OPENSSL "Enable OpenSSL support for performance benchmarks" ON)
option(KCTSB_ENABLE_SEAL "Enable Microsoft SEAL support for HE" ON)  # SEAL 4.1.2 available at D:\libs\seal
option(KCTSB_ENABLE_HELIB "Enable HElib support for FE" ON)
option(KCTSB_ENABLE_MIRACL "Enable MIRACL support" ON)
option(KCTSB_INSTALL "Generate install target" ON)

# ============================================================================
# vcpkg Integration (for GMP, OpenSSL, SEAL dependencies)
# ============================================================================
# vcpkg toolchain should be set via CMAKE_TOOLCHAIN_FILE
# Example: cmake -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake ..
if(DEFINED ENV{VCPKG_ROOT} AND NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
    message(STATUS "Using vcpkg from VCPKG_ROOT: $ENV{VCPKG_ROOT}")
endif()

# NTL installation path (source compiled, not vcpkg)
set(NTL_ROOT "" CACHE PATH "Path to NTL installation (from source compilation)")
if(NTL_ROOT AND EXISTS "${NTL_ROOT}/include/NTL")
    message(STATUS "Using NTL from NTL_ROOT: ${NTL_ROOT}")
endif()

# ============================================================================
# Output Directories
# ============================================================================

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Third-party include directory (defined early for dependency detection)
set(KCTSB_THIRDPARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)

# ============================================================================
# Early Dependency Detection (before source collection)
# ============================================================================
# HElib detection (before source collection)
if(KCTSB_ENABLE_HELIB)
    set(helib_FOUND FALSE)
    
    # Priority 1: Check thirdparty directory (unified dependency location)
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/helib/helib.h")
        set(HELIB_INCLUDE_DIRS "${KCTSB_THIRDPARTY_DIR}/include")
        find_library(HELIB_LIBRARY NAMES helib libhelib
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib"
            NO_DEFAULT_PATH)
        if(HELIB_LIBRARY)
            set(helib_FOUND TRUE)
            message(STATUS "HElib found in thirdparty: ${HELIB_LIBRARY}")
            add_definitions(-DKCTSB_HAS_HELIB)
            # Create imported target
            if(NOT TARGET helib)
                add_library(helib STATIC IMPORTED)
                set_target_properties(helib PROPERTIES
                    IMPORTED_LOCATION "${HELIB_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${HELIB_INCLUDE_DIRS}"
                )
            endif()
        endif()
    endif()
    
    # Priority 2: Try system config package
    if(NOT helib_FOUND)
        find_package(helib QUIET CONFIG)
        if(helib_FOUND)
            message(STATUS "HElib found via config (early detection)")
            add_definitions(-DKCTSB_HAS_HELIB)
        endif()
    endif()
    
    if(NOT helib_FOUND)
        message(WARNING "HElib not found, disabling HElib support")
        set(KCTSB_ENABLE_HELIB OFF)
    endif()
endif()

# ============================================================================
# Source Files Collection
# ============================================================================

# Include directories
set(KCTSB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(KCTSB_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Collect source files
file(GLOB_RECURSE KCTSB_CORE_SOURCES
    ${KCTSB_SRC_DIR}/core/*.cpp
    ${KCTSB_SRC_DIR}/core/*.c
)

# Core crypto sources (no external deps)
# Note: Only include files that don't depend on external frameworks
file(GLOB KCTSB_AES_SOURCES
    ${KCTSB_SRC_DIR}/crypto/aes/*.cpp
    ${KCTSB_SRC_DIR}/crypto/aes/*.c
)

# Hash module - self-contained implementations (SHA-256/384/512, BLAKE2, Keccak/SHA3)
set(KCTSB_HASH_SOURCES
    ${KCTSB_SRC_DIR}/crypto/hash/Keccak.cpp
    ${KCTSB_SRC_DIR}/crypto/hash/blake2.c
    ${KCTSB_SRC_DIR}/crypto/hash/sha256.c   # FIPS 180-4 compliant SHA-256
    ${KCTSB_SRC_DIR}/crypto/hash/sha512.c   # FIPS 180-4 compliant SHA-384/512
)

# ChaCha20-Poly1305 AEAD - production-grade stream cipher
file(GLOB KCTSB_CHACHA_SOURCES
    ${KCTSB_SRC_DIR}/crypto/chacha20/*.cpp
    ${KCTSB_SRC_DIR}/crypto/chacha20/*.c
)

# SM module - only include files with available headers
set(KCTSB_SM_SOURCES
    ${KCTSB_SRC_DIR}/crypto/sm/sm3.c
    ${KCTSB_SRC_DIR}/crypto/sm/sm4.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/zuc.c
    # Exclude sm2_enc.c (needs miracl.h)
    # Exclude sm_util.c (needs smUtil.h and miracl.h)
)

# Whitebox module - self-contained implementation
set(KCTSB_WHITEBOX_SOURCES
    ${KCTSB_SRC_DIR}/advanced/whitebox/whitebox_aes.c
)

set(KCTSB_CRYPTO_SOURCES
    ${KCTSB_AES_SOURCES}
    ${KCTSB_HASH_SOURCES}
    ${KCTSB_CHACHA_SOURCES}
    ${KCTSB_SM_SOURCES}
    ${KCTSB_WHITEBOX_SOURCES}
)

# RSA module (may need GMP for large numbers)
if(KCTSB_ENABLE_GMP OR NOT EXISTS "${KCTSB_SRC_DIR}/crypto/rsa")
    file(GLOB KCTSB_RSA_SOURCES ${KCTSB_SRC_DIR}/crypto/rsa/*.cpp)
    list(APPEND KCTSB_CRYPTO_SOURCES ${KCTSB_RSA_SOURCES})
endif()

# ECC module requires NTL
if(KCTSB_ENABLE_NTL)
    file(GLOB KCTSB_ECC_SOURCES ${KCTSB_SRC_DIR}/crypto/ecc/*.cpp)
    list(APPEND KCTSB_CRYPTO_SOURCES ${KCTSB_ECC_SOURCES})
endif()

# Advanced modules (many require external deps)
# Currently only include self-contained modules
set(KCTSB_ADVANCED_SOURCES "")

# ZK/Lattice/FE modules require NTL
if(KCTSB_ENABLE_NTL)
    file(GLOB_RECURSE KCTSB_ZK_SOURCES ${KCTSB_SRC_DIR}/advanced/zk/*.cpp)
    file(GLOB_RECURSE KCTSB_LATTICE_SOURCES ${KCTSB_SRC_DIR}/advanced/lattice/*.cpp)
    list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_ZK_SOURCES} ${KCTSB_LATTICE_SOURCES})
endif()

# FE module requires HElib
if(KCTSB_ENABLE_HELIB)
    file(GLOB_RECURSE KCTSB_FE_SOURCES ${KCTSB_SRC_DIR}/advanced/fe/*.cpp)
    list(APPEND KCTSB_ADVANCED_SOURCES ${KCTSB_FE_SOURCES})
endif()

# Math module requires NTL
set(KCTSB_MATH_SOURCES "")
if(KCTSB_ENABLE_NTL)
    file(GLOB_RECURSE KCTSB_MATH_SOURCES
        ${KCTSB_SRC_DIR}/math/*.cpp
    )
endif()

file(GLOB_RECURSE KCTSB_UTIL_SOURCES
    ${KCTSB_SRC_DIR}/utils/*.cpp
)

# Combine all sources
set(KCTSB_ALL_SOURCES
    ${KCTSB_CORE_SOURCES}
    ${KCTSB_CRYPTO_SOURCES}
    ${KCTSB_ADVANCED_SOURCES}
    ${KCTSB_MATH_SOURCES}
    ${KCTSB_UTIL_SOURCES}
)

# ============================================================================
# Dependencies
# ============================================================================

# Third-party include directory
set(KCTSB_THIRDPARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)

# Find packages based on options
if(KCTSB_ENABLE_NTL)
    set(NTL_FOUND FALSE)
    
    # Priority 1: User-specified NTL_ROOT (source compiled)
    if(NTL_ROOT AND EXISTS "${NTL_ROOT}/include/NTL/ZZ.h")
        set(NTL_INCLUDE_DIRS ${NTL_ROOT}/include)
        set(NTL_LIBRARY_DIRS ${NTL_ROOT}/lib)
        find_library(NTL_LIBRARY NAMES ntl libntl 
            HINTS ${NTL_ROOT}/lib ${NTL_ROOT}/lib64
            NO_DEFAULT_PATH)
        if(NTL_LIBRARY)
            set(NTL_LIBRARIES ${NTL_LIBRARY})
            set(NTL_FOUND TRUE)
            message(STATUS "NTL found at NTL_ROOT: ${NTL_ROOT}")
        endif()
    endif()
    
    # Priority 2: deps/ntl directory (locally compiled)
    if(NOT NTL_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/deps/ntl/include/NTL/ZZ.h")
        set(NTL_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/deps/ntl/include)
        find_library(NTL_LIBRARY NAMES ntl libntl
            HINTS ${CMAKE_SOURCE_DIR}/deps/ntl/lib
            NO_DEFAULT_PATH)
        if(NTL_LIBRARY)
            set(NTL_LIBRARIES ${NTL_LIBRARY})
            set(NTL_FOUND TRUE)
            message(STATUS "NTL found in deps/ntl directory: ${NTL_LIBRARY}")
        endif()
    endif()
    
    # Priority 3: thirdparty directory
    if(NOT NTL_FOUND AND EXISTS "${KCTSB_THIRDPARTY_DIR}/include/NTL/ZZ.h")
        set(NTL_INCLUDE_DIRS ${KCTSB_THIRDPARTY_DIR}/include)
        find_library(NTL_LIBRARY NAMES ntl libntl
            HINTS ${KCTSB_THIRDPARTY_DIR}/lib ${KCTSB_THIRDPARTY_DIR}/lib64)
        if(NTL_LIBRARY)
            set(NTL_LIBRARIES ${NTL_LIBRARY})
            set(NTL_FOUND TRUE)
            message(STATUS "NTL found in thirdparty directory")
        endif()
    endif()
    
    # Priority 4: System package manager / vcpkg
    if(NOT NTL_FOUND)
        find_package(NTL QUIET CONFIG)
        if(NOT NTL_FOUND)
            find_package(PkgConfig QUIET)
            if(PKG_CONFIG_FOUND)
                pkg_check_modules(NTL QUIET ntl)
            endif()
        endif()
    endif()
    
    if(NTL_FOUND)
        add_definitions(-DKCTSB_HAS_NTL)
        message(STATUS "NTL enabled: ${NTL_INCLUDE_DIRS}")
        
        # Create imported target if not already defined
        if(NOT TARGET NTL::NTL)
            add_library(NTL::NTL STATIC IMPORTED)
            set_target_properties(NTL::NTL PROPERTIES
                IMPORTED_LOCATION "${NTL_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${NTL_INCLUDE_DIRS}"
            )
        endif()
    else()
        message(WARNING "NTL not found. Please compile from source or set NTL_ROOT.")
        message(STATUS "  See docs/third-party-dependencies.md for installation guide")
        set(KCTSB_ENABLE_NTL OFF)
    endif()
endif()

if(KCTSB_ENABLE_GMP)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
    
    # Priority 1: Check thirdparty directory (unified dependency location)
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/gmpxx.h")
        set(GMP_INCLUDE_DIRS "${KCTSB_THIRDPARTY_DIR}/include")
        find_library(GMPXX_LIBRARY NAMES gmpxx libgmpxx
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib"
            NO_DEFAULT_PATH)
        find_library(GMP_LIBRARY NAMES gmp libgmp
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib"
            NO_DEFAULT_PATH)
        if(GMPXX_LIBRARY AND GMP_LIBRARY)
            set(GMP_LIBRARIES ${GMPXX_LIBRARY} ${GMP_LIBRARY})
            set(GMP_FOUND TRUE)
            message(STATUS "GMP with C++ support found in thirdparty")
            message(STATUS "  gmpxx: ${GMPXX_LIBRARY}")
            message(STATUS "  gmp: ${GMP_LIBRARY}")
            add_definitions(-DKCTSB_HAS_GMP)
            add_definitions(-DKCTSB_HAS_GMPXX)
            # Create imported targets
            if(NOT TARGET GMP::GMPXX)
                add_library(GMP::GMPXX STATIC IMPORTED)
                set_target_properties(GMP::GMPXX PROPERTIES
                    IMPORTED_LOCATION "${GMPXX_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}"
                )
            endif()
            if(NOT TARGET GMP::GMP)
                add_library(GMP::GMP STATIC IMPORTED)
                set_target_properties(GMP::GMP PROPERTIES
                    IMPORTED_LOCATION "${GMP_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}"
                )
            endif()
        endif()
    endif()
    
    # Priority 2: Check thirdparty directory (C only, no gmpxx)
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/gmp.h")
        set(GMP_INCLUDE_DIRS ${KCTSB_THIRDPARTY_DIR}/include)
        find_library(GMP_LIBRARY NAMES gmp libgmp
            HINTS ${KCTSB_THIRDPARTY_DIR}/lib)
        if(GMP_LIBRARY)
            set(GMP_LIBRARIES ${GMP_LIBRARY})
            set(GMP_FOUND TRUE)
            message(STATUS "GMP found in thirdparty: ${GMP_LIBRARY}")
            # Create imported target
            if(NOT TARGET GMP::GMP)
                add_library(GMP::GMP STATIC IMPORTED)
                set_target_properties(GMP::GMP PROPERTIES
                    IMPORTED_LOCATION "${GMP_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIRS}"
                )
            endif()
        endif()
    endif()
    
    # Priority 2: Try system package manager
    if(NOT GMP_FOUND)
        find_package(GMP QUIET)
        if(NOT GMP_FOUND)
            # Try vcpkg naming convention
            find_package(gmp CONFIG QUIET)
            if(gmp_FOUND)
                set(GMP_FOUND TRUE)
                set(GMP_LIBRARIES gmp::gmp)
            endif()
        endif()
    endif()
    
    if(GMP_FOUND)
        message(STATUS "GMP found: ${GMP_INCLUDE_DIRS}")
        message(STATUS "GMP library: ${GMP_LIBRARIES}")
        add_definitions(-DKCTSB_HAS_GMP)
    else()
        message(WARNING "GMP not found. Install via: vcpkg install gmp:x64-windows")
        set(KCTSB_ENABLE_GMP OFF)
    endif()
endif()

if(KCTSB_ENABLE_OPENSSL)
    find_package(OpenSSL QUIET)
    if(OPENSSL_FOUND)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
        message(STATUS "OpenSSL includes: ${OPENSSL_INCLUDE_DIR}")
        add_definitions(-DKCTSB_HAS_OPENSSL)
    else()
        message(WARNING "OpenSSL not found. Install via: vcpkg install openssl:x64-windows")
        set(KCTSB_ENABLE_OPENSSL OFF)
    endif()
endif()

if(KCTSB_ENABLE_SEAL)
    # Priority 1: Check thirdparty directory (unified dependency location)
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/SEAL-4.1/seal/seal.h")
        set(SEAL_INCLUDE_DIRS "${KCTSB_THIRDPARTY_DIR}/include/SEAL-4.1")
        find_library(SEAL_LIBRARY NAMES seal-4.1 libseal-4.1
            HINTS "${KCTSB_THIRDPARTY_DIR}/lib"
            NO_DEFAULT_PATH)
        if(SEAL_LIBRARY)
            set(SEAL_FOUND TRUE)
            message(STATUS "Microsoft SEAL found in thirdparty: ${SEAL_LIBRARY}")
            add_definitions(-DKCTSB_HAS_SEAL)
            # Create imported target
            if(NOT TARGET SEAL::seal)
                add_library(SEAL::seal STATIC IMPORTED)
                set_target_properties(SEAL::seal PROPERTIES
                    IMPORTED_LOCATION "${SEAL_LIBRARY}"
                    INTERFACE_INCLUDE_DIRECTORIES "${SEAL_INCLUDE_DIRS}"
                )
            endif()
        endif()
    endif()
    
    # Priority 2: Try system/vcpkg SEAL
    if(NOT SEAL_FOUND)
        find_package(SEAL 4.1 QUIET CONFIG)
        if(SEAL_FOUND)
            message(STATUS "Microsoft SEAL found via config: ${SEAL_VERSION}")
            add_definitions(-DKCTSB_HAS_SEAL)
        endif()
    endif()
    
    if(NOT SEAL_FOUND)
        message(WARNING "Microsoft SEAL not found, disabling SEAL support")
        set(KCTSB_ENABLE_SEAL OFF)
    endif()
endif()

# HElib detection already done earlier (before source collection)

# ============================================================================
# Library Targets
# ============================================================================

# Core library (always built, no external deps)
set(KCTSB_CORE_ONLY_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/export.cpp
)

# Check if we have any sources
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src")
    message(STATUS "Source directory not found, will be created during restructure")
endif()

# Static library
if(KCTSB_BUILD_STATIC)
    add_library(kctsb_static STATIC ${KCTSB_ALL_SOURCES})
    target_include_directories(kctsb_static PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<BUILD_INTERFACE:${KCTSB_SRC_DIR}>
        $<INSTALL_INTERFACE:include>
    )
    # Add thirdparty includes if using NTL/GMP
    if((KCTSB_ENABLE_NTL OR KCTSB_ENABLE_GMP) AND EXISTS "${KCTSB_THIRDPARTY_DIR}/include")
        target_include_directories(kctsb_static PUBLIC
            $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        )
    endif()
    # Add NTL include path if available
    if(KCTSB_ENABLE_NTL AND NTL_INCLUDE_DIRS)
        target_include_directories(kctsb_static PUBLIC
            $<BUILD_INTERFACE:${NTL_INCLUDE_DIRS}>
        )
    endif()
    # Add GMP include path if available
    if(KCTSB_ENABLE_GMP AND GMP_INCLUDE_DIRS)
        target_include_directories(kctsb_static PUBLIC
            $<BUILD_INTERFACE:${GMP_INCLUDE_DIRS}>
        )
    endif()
    # Add HElib include path if available
    if(KCTSB_ENABLE_HELIB AND HELIB_INCLUDE_DIRS)
        target_include_directories(kctsb_static PUBLIC
            $<BUILD_INTERFACE:${HELIB_INCLUDE_DIRS}>
        )
    endif()
    # Add SEAL include path if available
    if(KCTSB_ENABLE_SEAL AND SEAL_INCLUDE_DIRS)
        target_include_directories(kctsb_static PUBLIC
            $<BUILD_INTERFACE:${SEAL_INCLUDE_DIRS}>
        )
    endif()
    set_target_properties(kctsb_static PROPERTIES
        OUTPUT_NAME kctsb
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    )
    
    # Platform-specific dependencies
    if(WIN32)
        target_link_libraries(kctsb_static PRIVATE bcrypt)
    endif()
    
    # Link dependencies
    if(KCTSB_ENABLE_NTL AND NTL_FOUND)
        target_link_libraries(kctsb_static PUBLIC NTL::NTL)
    endif()
    if(KCTSB_ENABLE_GMP AND GMP_FOUND)
        target_link_libraries(kctsb_static PUBLIC GMP::GMP)
    endif()
    if(KCTSB_ENABLE_OPENSSL AND OPENSSL_FOUND)
        target_link_libraries(kctsb_static PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_link_libraries(kctsb_static PUBLIC SEAL::seal)
    endif()
    if(KCTSB_ENABLE_HELIB AND helib_FOUND)
        target_link_libraries(kctsb_static PUBLIC helib)
    endif()
endif()

# Shared library
if(KCTSB_BUILD_SHARED)
    add_library(kctsb_shared SHARED ${KCTSB_ALL_SOURCES})
    target_include_directories(kctsb_shared PUBLIC
        $<BUILD_INTERFACE:${KCTSB_INCLUDE_DIR}>
        $<BUILD_INTERFACE:${KCTSB_SRC_DIR}>
        $<INSTALL_INTERFACE:include>
    )
    # Add thirdparty includes if using NTL/GMP
    if((KCTSB_ENABLE_NTL OR KCTSB_ENABLE_GMP) AND EXISTS "${KCTSB_THIRDPARTY_DIR}/include")
        target_include_directories(kctsb_shared PUBLIC
            $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
        )
    endif()
    # Add NTL include path if available
    if(KCTSB_ENABLE_NTL AND NTL_INCLUDE_DIRS)
        target_include_directories(kctsb_shared PUBLIC
            $<BUILD_INTERFACE:${NTL_INCLUDE_DIRS}>
        )
    endif()
    # Add GMP include path if available
    if(KCTSB_ENABLE_GMP AND GMP_INCLUDE_DIRS)
        target_include_directories(kctsb_shared PUBLIC
            $<BUILD_INTERFACE:${GMP_INCLUDE_DIRS}>
        )
    endif()
    # Add HElib include path if available
    if(KCTSB_ENABLE_HELIB AND HELIB_INCLUDE_DIRS)
        target_include_directories(kctsb_shared PUBLIC
            $<BUILD_INTERFACE:${HELIB_INCLUDE_DIRS}>
        )
    endif()
    # Add SEAL include path if available
    if(KCTSB_ENABLE_SEAL AND SEAL_INCLUDE_DIRS)
        target_include_directories(kctsb_shared PUBLIC
            $<BUILD_INTERFACE:${SEAL_INCLUDE_DIRS}>
        )
    endif()
    target_compile_definitions(kctsb_shared PRIVATE KCTSB_EXPORTS KCTSB_SHARED_LIBRARY KCTSB_BUILDING)
    set_target_properties(kctsb_shared PROPERTIES
        OUTPUT_NAME kctsb
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    
    # Platform-specific dependencies
    if(WIN32)
        target_link_libraries(kctsb_shared PRIVATE bcrypt)
    endif()
    
    # Link dependencies
    if(KCTSB_ENABLE_NTL AND NTL_FOUND)
        target_link_libraries(kctsb_shared PUBLIC NTL::NTL)
    endif()
    if(KCTSB_ENABLE_GMP AND GMP_FOUND)
        target_link_libraries(kctsb_shared PUBLIC GMP::GMP)
    endif()
    if(KCTSB_ENABLE_OPENSSL AND OPENSSL_FOUND)
        target_link_libraries(kctsb_shared PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_link_libraries(kctsb_shared PUBLIC SEAL::seal)
    endif()
endif()

# Create alias targets
if(KCTSB_BUILD_STATIC)
    add_library(kctsb::static ALIAS kctsb_static)
endif()
if(KCTSB_BUILD_SHARED)
    add_library(kctsb::shared ALIAS kctsb_shared)
endif()

# Default target
if(KCTSB_BUILD_SHARED)
    add_library(kctsb ALIAS kctsb_shared)
elseif(KCTSB_BUILD_STATIC)
    add_library(kctsb ALIAS kctsb_static)
endif()

# ============================================================================
# Tests
# ============================================================================

if(KCTSB_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ============================================================================
# Examples
# ============================================================================

if(KCTSB_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ============================================================================
# Benchmarks (OpenSSL Performance Comparison)
# ============================================================================

if(KCTSB_BUILD_BENCHMARKS AND KCTSB_ENABLE_OPENSSL AND OPENSSL_FOUND)
    add_subdirectory(benchmarks)
    message(STATUS "Benchmarks enabled: OpenSSL performance comparison")
endif()

# ============================================================================
# CLI Tool (kctsb.exe)
# ============================================================================

option(KCTSB_BUILD_CLI "Build kctsb command-line tool" OFF)  # Temporarily disabled: header fixes needed

if(KCTSB_BUILD_CLI)
    add_subdirectory(src/cli)
    message(STATUS "CLI tool enabled: kctsb.exe")
endif()

# ============================================================================
# Installation
# ============================================================================

if(KCTSB_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)
    
    # Install headers
    install(DIRECTORY ${KCTSB_INCLUDE_DIR}/kctsb
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
    )
    
    # Install libraries
    if(KCTSB_BUILD_STATIC)
        install(TARGETS kctsb_static
            EXPORT kctsbTargets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
    endif()
    
    if(KCTSB_BUILD_SHARED)
        install(TARGETS kctsb_shared
            EXPORT kctsbTargets
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
    
    # Generate and install package config
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/kctsbConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    
    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/kctsbConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/kctsbConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kctsb
    )
    
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/kctsbConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/kctsbConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kctsb
    )
    
    install(EXPORT kctsbTargets
        FILE kctsbTargets.cmake
        NAMESPACE kctsb::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/kctsb
    )
endif()

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "=== kctsb Configuration Summary ===")
message(STATUS "Version:        ${PROJECT_VERSION}")
message(STATUS "Platform:       ${KCTSB_PLATFORM}")
message(STATUS "Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "")
message(STATUS "Build Options:")
message(STATUS "  Shared lib:   ${KCTSB_BUILD_SHARED}")
message(STATUS "  Static lib:   ${KCTSB_BUILD_STATIC}")
message(STATUS "  Tests:        ${KCTSB_BUILD_TESTS}")
message(STATUS "  Examples:     ${KCTSB_BUILD_EXAMPLES}")
message(STATUS "  Benchmarks:   ${KCTSB_BUILD_BENCHMARKS}")
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  NTL:          ${KCTSB_ENABLE_NTL}")
message(STATUS "  GMP:          ${KCTSB_ENABLE_GMP}")
message(STATUS "  OpenSSL:      ${KCTSB_ENABLE_OPENSSL}")
message(STATUS "  SEAL:         ${KCTSB_ENABLE_SEAL}")
message(STATUS "  HElib:        ${KCTSB_ENABLE_HELIB}")
message(STATUS "")
