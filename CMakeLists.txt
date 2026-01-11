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
    VERSION 2.0.0
    DESCRIPTION "Cross-platform cryptographic algorithms library"
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
option(KCTSB_ENABLE_NTL "Enable NTL support" OFF)
option(KCTSB_ENABLE_GMP "Enable GMP support" OFF)
option(KCTSB_ENABLE_OPENSSL "Enable OpenSSL support" OFF)
option(KCTSB_ENABLE_SEAL "Enable Microsoft SEAL support" OFF)
option(KCTSB_ENABLE_HELIB "Enable HElib support" OFF)
option(KCTSB_ENABLE_MIRACL "Enable MIRACL support" OFF)
option(KCTSB_INSTALL "Generate install target" ON)

# ============================================================================
# Output Directories
# ============================================================================

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

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

# Hash module - self-contained implementations
set(KCTSB_HASH_SOURCES
    ${KCTSB_SRC_DIR}/crypto/hash/Keccak.cpp
    ${KCTSB_SRC_DIR}/crypto/hash/blake2.c
    ${KCTSB_SRC_DIR}/crypto/hash/chacha20.c
)

# SM module - check for self-contained files
file(GLOB KCTSB_SM_SOURCES
    ${KCTSB_SRC_DIR}/crypto/sm/*.cpp
    ${KCTSB_SRC_DIR}/crypto/sm/*.c
)

# Whitebox module - self-contained implementation
set(KCTSB_WHITEBOX_SOURCES
    ${KCTSB_SRC_DIR}/advanced/whitebox/whitebox_aes.c
)

set(KCTSB_CRYPTO_SOURCES
    ${KCTSB_AES_SOURCES}
    ${KCTSB_HASH_SOURCES}
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
    # First check if we have NTL headers in thirdparty
    if(EXISTS "${KCTSB_THIRDPARTY_DIR}/include/NTL")
        message(STATUS "Using NTL headers from thirdparty/include/NTL")
        set(NTL_INCLUDE_DIRS ${KCTSB_THIRDPARTY_DIR}/include)
        add_definitions(-DKCTSB_HAS_NTL)
        # Note: NTL library needs to be built separately
        # For now, just enable header-only features
    else()
        find_package(NTL QUIET)
        if(NTL_FOUND)
            message(STATUS "NTL found: ${NTL_INCLUDE_DIRS}")
            add_definitions(-DKCTSB_HAS_NTL)
        else()
            message(WARNING "NTL not found, disabling NTL support")
            set(KCTSB_ENABLE_NTL OFF)
        endif()
    endif()
endif()

if(KCTSB_ENABLE_GMP)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
    find_package(GMP QUIET)
    if(GMP_FOUND)
        message(STATUS "GMP found: ${GMP_INCLUDE_DIRS}")
        message(STATUS "GMP library: ${GMP_LIBRARIES}")
        add_definitions(-DKCTSB_HAS_GMP)
    else()
        message(WARNING "GMP not found, disabling GMP support")
        set(KCTSB_ENABLE_GMP OFF)
    endif()
endif()

if(KCTSB_ENABLE_OPENSSL)
    find_package(OpenSSL QUIET)
    if(OPENSSL_FOUND)
        message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
        add_definitions(-DKCTSB_HAS_OPENSSL)
    else()
        message(WARNING "OpenSSL not found, disabling OpenSSL support")
        set(KCTSB_ENABLE_OPENSSL OFF)
    endif()
endif()

if(KCTSB_ENABLE_SEAL)
    find_package(SEAL 4.1 QUIET CONFIG)
    if(SEAL_FOUND)
        message(STATUS "Microsoft SEAL found: ${SEAL_VERSION}")
        add_definitions(-DKCTSB_HAS_SEAL)
    else()
        message(WARNING "Microsoft SEAL not found, disabling SEAL support")
        set(KCTSB_ENABLE_SEAL OFF)
    endif()
endif()

if(KCTSB_ENABLE_HELIB)
    find_package(helib QUIET CONFIG)
    if(helib_FOUND)
        message(STATUS "HElib found")
        add_definitions(-DKCTSB_HAS_HELIB)
    else()
        message(WARNING "HElib not found, disabling HElib support")
        set(KCTSB_ENABLE_HELIB OFF)
    endif()
endif()

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
    if(KCTSB_ENABLE_NTL AND EXISTS "${KCTSB_THIRDPARTY_DIR}/include")
        target_include_directories(kctsb_static PUBLIC
            $<BUILD_INTERFACE:${KCTSB_THIRDPARTY_DIR}/include>
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
        $<INSTALL_INTERFACE:include>
    )
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
message(STATUS "")
message(STATUS "Dependencies:")
message(STATUS "  NTL:          ${KCTSB_ENABLE_NTL}")
message(STATUS "  GMP:          ${KCTSB_ENABLE_GMP}")
message(STATUS "  OpenSSL:      ${KCTSB_ENABLE_OPENSSL}")
message(STATUS "  SEAL:         ${KCTSB_ENABLE_SEAL}")
message(STATUS "  HElib:        ${KCTSB_ENABLE_HELIB}")
message(STATUS "")
