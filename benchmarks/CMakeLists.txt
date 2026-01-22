# ============================================================================
# kctsb Benchmarks - OpenSSL Performance Comparison
#
# Compares kctsb implementations against OpenSSL for validation:
# - AES-256-GCM: AEAD encryption/decryption throughput
# - ChaCha20-Poly1305: Stream cipher AEAD throughput
# - SHA3-256/BLAKE2b: Hash function throughput
# - ECC: ECDSA/ECDH/Key Generation
# - RSA: OAEP/PSS/Key Generation
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# Require OpenSSL for main benchmarks (vs OpenSSL comparison)
# BGV benchmark does NOT require OpenSSL and is configured separately below
if(NOT OPENSSL_FOUND)
    message(WARNING "OpenSSL not found, main benchmarks will not be built")
    # Do NOT return() - still build BGV benchmark below
    set(SKIP_MAIN_BENCHMARKS TRUE)
else()
    set(SKIP_MAIN_BENCHMARKS FALSE)
endif()

if(NOT SKIP_MAIN_BENCHMARKS)

# Benchmark sources - all algorithms (RSA/ECC/SM2 bignum modules are always built)
# Note: v4.1+ integrates NTL/GMP source code, so bignum modules are always available
set(BENCHMARK_SOURCES
    benchmark_main.cpp
    benchmark_aes_gcm.cpp
    benchmark_chacha20.cpp
    benchmark_hash.cpp
    benchmark_mac.cpp
    benchmark_sm.cpp
    benchmark_ecc.cpp
    benchmark_rsa.cpp
)

# Benchmark executable
add_executable(kctsb_benchmark ${BENCHMARK_SOURCES})

target_include_directories(kctsb_benchmark PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/thirdparty/include
    ${CMAKE_SOURCE_DIR}/thirdparty/include/SEAL-4.1
    ${OPENSSL_INCLUDE_DIR}
)

# macOS: Ensure Homebrew OpenSSL is found
if(APPLE AND NOT OPENSSL_INCLUDE_DIR)
    set(OPENSSL_INCLUDE_DIR "/usr/local/opt/openssl@3/include")
endif()

# Link libraries
target_link_libraries(kctsb_benchmark PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Link kctsb if available
if(TARGET kctsb_static)
    target_link_libraries(kctsb_benchmark PRIVATE kctsb_static)
    # Define macros to enable kctsb implementations in benchmarks
    # v4.1+ integrates bignum source code, all modules are always available
    target_compile_definitions(kctsb_benchmark PRIVATE
        KCTSB_HAS_AES_GCM=1
        KCTSB_HAS_AES_128=1
        KCTSB_HAS_CHACHA20_POLY1305=1
        KCTSB_HAS_SHA3=1
        KCTSB_HAS_BLAKE2=1
        KCTSB_HAS_SM3=1
        KCTSB_HAS_SM4=1
        KCTSB_HAS_RSA=1
        KCTSB_HAS_ECC=1
        KCTSB_HAS_SM2=1
    )
elseif(TARGET kctsb_shared)
    target_link_libraries(kctsb_benchmark PRIVATE kctsb_shared)
    target_compile_definitions(kctsb_benchmark PRIVATE
        KCTSB_HAS_AES_GCM=1
        KCTSB_HAS_AES_128=1
        KCTSB_HAS_CHACHA20_POLY1305=1
        KCTSB_HAS_SHA3=1
        KCTSB_HAS_BLAKE2=1
        KCTSB_HAS_SM3=1
        KCTSB_HAS_SM4=1
        KCTSB_HAS_RSA=1
        KCTSB_HAS_ECC=1
        KCTSB_HAS_SM2=1
    )
endif()

# Platform-specific: bcrypt.dll loaded at runtime on Windows
# No static linking required for OS system DLLs

# Set output directory
set_target_properties(kctsb_benchmark PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Windows: Copy OpenSSL 3.6.0 DLLs to ensure correct version is loaded at runtime
# This prevents loading older OpenSSL from System32 or other PATH locations
if(WIN32 AND EXISTS "D:/vcpkg/installed/x64-windows/bin")
    add_custom_command(TARGET kctsb_benchmark POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "D:/vcpkg/installed/x64-windows/bin/libcrypto-3-x64.dll"
            "$<TARGET_FILE_DIR:kctsb_benchmark>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "D:/vcpkg/installed/x64-windows/bin/libssl-3-x64.dll"
            "$<TARGET_FILE_DIR:kctsb_benchmark>"
        COMMENT "Copying OpenSSL 3.6.0 DLLs for benchmark runtime"
    )
endif()

# Compiler flags for performance
if(MSVC)
    target_compile_options(kctsb_benchmark PRIVATE /O2 /fp:fast /utf-8)
else()
    target_compile_options(kctsb_benchmark PRIVATE
        -O3 -march=native
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
        # Disable conversion warnings for benchmarks (intentional size_t -> double conversions)
        -Wno-conversion
        -Wno-sign-conversion
        -Wno-unused-function
    )
endif()

message(STATUS "Benchmarks configured: kctsb vs OpenSSL comparison")

endif()  # SKIP_MAIN_BENCHMARKS

# ============================================================================
# BGV Homomorphic Encryption Benchmark (standalone, no OpenSSL required)
# TODO: Re-enable after fixing kctsb bignum API compatibility
# ============================================================================

if(KCTSB_ENABLE_BGV)
    add_executable(kctsb_benchmark_bgv benchmark_bgv.cpp)

    target_include_directories(kctsb_benchmark_bgv PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/thirdparty/include
    )

    # Link kctsb
    if(TARGET kctsb_static)
        target_link_libraries(kctsb_benchmark_bgv PRIVATE kctsb_static)
    elseif(TARGET kctsb_shared)
        target_link_libraries(kctsb_benchmark_bgv PRIVATE kctsb_shared)
    endif()

    # SEAL/HElib comparison DISABLED until headers are properly built
    # SEAL requires seal/util/config.h which is generated during SEAL build
    # HElib requires built helib headers
    # For now, only benchmark native kctsb BGV implementation
    # TODO: Build SEAL and HElib from source to enable comparison benchmarks
    #
    # if(KCTSB_ENABLE_SEAL AND SEAL_FOUND AND EXISTS "${SEAL_INCLUDE_DIRS}/seal/util/config.h")
    #     target_include_directories(kctsb_benchmark_bgv PRIVATE ${SEAL_INCLUDE_DIRS})
    #     target_link_libraries(kctsb_benchmark_bgv PRIVATE "${SEAL_LIBRARY}")
    #     target_compile_definitions(kctsb_benchmark_bgv PRIVATE KCTSB_HAS_SEAL=1)
    #     if(WIN32)
    #         target_link_libraries(kctsb_benchmark_bgv PRIVATE bcrypt)
    #     endif()
    # endif()
    #
    # if(KCTSB_ENABLE_HELIB AND HELIB_FOUND)
    #     target_link_libraries(kctsb_benchmark_bgv PRIVATE "${HELIB_LIBRARY}")
    #     target_compile_definitions(kctsb_benchmark_bgv PRIVATE KCTSB_HAS_HELIB=1)
    # endif()

    set_target_properties(kctsb_benchmark_bgv PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

    if(MSVC)
        target_compile_options(kctsb_benchmark_bgv PRIVATE /O2 /fp:fast /utf-8)
    else()
        target_compile_options(kctsb_benchmark_bgv PRIVATE
            -O3 -march=native
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
            -Wno-conversion
            -Wno-sign-conversion
        )
    endif()

    message(STATUS "BGV benchmark configured: kctsb native BGV")
else()
    message(STATUS "BGV benchmark skipped: KCTSB_ENABLE_BGV is OFF")
endif()

# ============================================================================
# BFV Benchmark (Phase 2 - placeholder until BFV module is implemented)
# ============================================================================

if(KCTSB_ENABLE_BFV OR KCTSB_HAS_SEAL)
    add_executable(kctsb_benchmark_bfv benchmark_bfv.cpp)

    target_include_directories(kctsb_benchmark_bfv PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/thirdparty/include
    )

    if(TARGET kctsb_static)
        target_link_libraries(kctsb_benchmark_bfv PRIVATE kctsb_static)
    elseif(TARGET kctsb_shared)
        target_link_libraries(kctsb_benchmark_bfv PRIVATE kctsb_shared)
    endif()

    # SEAL comparison (if available)
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
        target_include_directories(kctsb_benchmark_bfv PRIVATE ${SEAL_INCLUDE_DIRS})
        target_link_libraries(kctsb_benchmark_bfv PRIVATE "${SEAL_LIBRARY}")
        target_compile_definitions(kctsb_benchmark_bfv PRIVATE KCTSB_HAS_SEAL=1)
        if(WIN32)
            target_link_libraries(kctsb_benchmark_bfv PRIVATE bcrypt)
        endif()
    endif()

    set_target_properties(kctsb_benchmark_bfv PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

    if(MSVC)
        target_compile_options(kctsb_benchmark_bfv PRIVATE /O2 /fp:fast /utf-8)
    else()
        target_compile_options(kctsb_benchmark_bfv PRIVATE
            -O3 -march=native
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
            -Wno-conversion
            -Wno-sign-conversion
        )
    endif()

    message(STATUS "BFV benchmark configured")
else()
    message(STATUS "BFV benchmark skipped: KCTSB_ENABLE_BFV is OFF and no SEAL")
endif()

# ============================================================================
# CKKS Benchmark (Phase 3 - native CKKS implementation)
# ============================================================================

# CKKS is enabled when BGV is enabled (they share infrastructure)
option(KCTSB_ENABLE_CKKS "Enable native CKKS benchmark" ON)

if(KCTSB_ENABLE_CKKS OR KCTSB_HAS_SEAL)
    add_executable(kctsb_benchmark_ckks benchmark_ckks.cpp)

    target_include_directories(kctsb_benchmark_ckks PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/thirdparty/include
    )
    
    # Enable native CKKS when BGV is enabled (CKKS uses BGV infrastructure)
    if(KCTSB_ENABLE_BGV)
        target_compile_definitions(kctsb_benchmark_ckks PRIVATE KCTSB_HAS_CKKS=1)
    endif()

    if(TARGET kctsb_static)
        target_link_libraries(kctsb_benchmark_ckks PRIVATE kctsb_static)
    elseif(TARGET kctsb_shared)
        target_link_libraries(kctsb_benchmark_ckks PRIVATE kctsb_shared)
    endif()

    # SEAL comparison (if available AND properly built)
    # SEAL requires seal/util/config.h which is generated during SEAL build
    if(KCTSB_ENABLE_SEAL AND SEAL_FOUND AND EXISTS "${SEAL_INCLUDE_DIRS}/seal/util/config.h")
        target_include_directories(kctsb_benchmark_ckks PRIVATE ${SEAL_INCLUDE_DIRS})
        target_link_libraries(kctsb_benchmark_ckks PRIVATE "${SEAL_LIBRARY}")
        target_compile_definitions(kctsb_benchmark_ckks PRIVATE KCTSB_HAS_SEAL=1)
        if(WIN32)
            target_link_libraries(kctsb_benchmark_ckks PRIVATE bcrypt)
        endif()
    endif()

    set_target_properties(kctsb_benchmark_ckks PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )

    if(MSVC)
        target_compile_options(kctsb_benchmark_ckks PRIVATE /O2 /fp:fast /utf-8)
    else()
        target_compile_options(kctsb_benchmark_ckks PRIVATE
            -O3 -march=native
            -finput-charset=UTF-8
            -fexec-charset=UTF-8
            -Wno-conversion
            -Wno-sign-conversion
        )
    endif()

    message(STATUS "CKKS benchmark configured")
else()
    message(STATUS "CKKS benchmark skipped: KCTSB_ENABLE_CKKS is OFF and no SEAL")
endif()
