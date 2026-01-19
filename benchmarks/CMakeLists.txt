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

# Require OpenSSL for benchmarks
if(NOT OPENSSL_FOUND)
    message(WARNING "OpenSSL not found, benchmarks will not be built")
    return()
endif()

# Benchmark sources - conditionally include RSA/ECC based on NTL availability
set(BENCHMARK_SOURCES
    benchmark_main.cpp
    benchmark_aes_gcm.cpp
    benchmark_chacha20.cpp
    benchmark_hash.cpp
    benchmark_mac.cpp
    benchmark_sm.cpp
)

# Add RSA/ECC benchmarks only when bignum modules are available
if(NOT WIN32 OR KCTSB_FORCE_BIGNUM_MODULES)
    list(APPEND BENCHMARK_SOURCES
        benchmark_ecc.cpp
        benchmark_rsa.cpp
    )
endif()

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
    target_compile_definitions(kctsb_benchmark PRIVATE
        KCTSB_HAS_AES_GCM=1
        KCTSB_HAS_AES_128=1
        KCTSB_HAS_CHACHA20_POLY1305=1
        KCTSB_HAS_SHA3=1
        KCTSB_HAS_BLAKE2=1
        KCTSB_HAS_SM3=1
        KCTSB_HAS_SM4=1
    )
    # Enable RSA/ECC/SM2 only when bignum modules are available
    if(NOT WIN32 OR KCTSB_FORCE_BIGNUM_MODULES)
        target_compile_definitions(kctsb_benchmark PRIVATE
            KCTSB_HAS_RSA=1
            KCTSB_HAS_ECC=1
            KCTSB_HAS_SM2=1
        )
    endif()
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
    )
    if(NOT WIN32 OR KCTSB_FORCE_BIGNUM_MODULES)
        target_compile_definitions(kctsb_benchmark PRIVATE
            KCTSB_HAS_RSA=1
            KCTSB_HAS_ECC=1
            KCTSB_HAS_SM2=1
        )
    endif()
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
