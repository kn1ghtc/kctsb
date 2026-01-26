# ============================================================================
# kctsb v5.1 Benchmarks - Performance Testing with OpenSSL Comparison
#
# v5.1 Architecture: Real-time comparison with OpenSSL 3.6.0
# Benchmark Categories:
# - AES-256-GCM: AEAD encryption/decryption throughput
# - ChaCha20-Poly1305: Stream cipher AEAD throughput  
# - SHA3-256/BLAKE2b: Hash function throughput
# - SM3/SM4: Chinese cryptographic standards
# - ECC: ECDSA/ECDH/Key Generation (secp256k1, P-256)
# - RSA: OAEP/PSS/Key Generation
# ============================================================================

cmake_minimum_required(VERSION 3.20)

message(STATUS "")
message(STATUS "=== kctsb v5.1 Benchmark Configuration ===")
message(STATUS "Mode: Runtime comparison with OpenSSL 3.6.0")

# ============================================================================
# Find OpenSSL for real-time comparison
# ============================================================================
find_package(OpenSSL 3.0 QUIET)
if(OpenSSL_FOUND)
    message(STATUS "✓ OpenSSL ${OPENSSL_VERSION} found for runtime comparison")
    set(BENCHMARK_HAS_OPENSSL TRUE)
else()
    message(STATUS "⚠ OpenSSL not found - will use hardcoded baselines")
    set(BENCHMARK_HAS_OPENSSL FALSE)
endif()

# ============================================================================
# Main Benchmark - kctsb vs Hardcoded Baselines
# ============================================================================

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

add_executable(kctsb_benchmark ${BENCHMARK_SOURCES})

target_include_directories(kctsb_benchmark PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/thirdparty/include
    ${CMAKE_CURRENT_SOURCE_DIR}  # For baseline_data.hpp
)

# v5.0: Use hardcoded baselines instead of runtime OpenSSL comparison
target_compile_definitions(kctsb_benchmark PRIVATE
    KCTSB_V5_SELF_CONTAINED=1
    KCTSB_BENCHMARK_USE_BASELINE_DATA=1
)

# Link kctsb library
if(TARGET kctsb_static)
    target_link_libraries(kctsb_benchmark PRIVATE kctsb_static)
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
else()
    message(FATAL_ERROR "kctsb library target not found - cannot build benchmarks")
endif()

# Link OpenSSL for real-time comparison
if(BENCHMARK_HAS_OPENSSL)
    target_link_libraries(kctsb_benchmark PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(kctsb_benchmark PRIVATE KCTSB_BENCHMARK_WITH_OPENSSL=1)
endif()

set_target_properties(kctsb_benchmark PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Compiler flags for performance
if(MSVC)
    target_compile_options(kctsb_benchmark PRIVATE /O2 /fp:fast /utf-8)
else()
    target_compile_options(kctsb_benchmark PRIVATE
        -O3 -march=native
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
        -Wno-conversion
        -Wno-sign-conversion
        -Wno-unused-function
    )
endif()

message(STATUS "✓ Main benchmark: kctsb vs baseline_data.hpp")

# ============================================================================
# BGV Homomorphic Encryption Benchmark (v5.0 Self-Contained)
# ============================================================================

if(KCTSB_ENABLE_BGV)
    add_executable(kctsb_benchmark_bgv benchmark_bgv.cpp)

    target_include_directories(kctsb_benchmark_bgv PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/thirdparty/include
        ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_compile_definitions(kctsb_benchmark_bgv PRIVATE
        KCTSB_V5_SELF_CONTAINED=1
        KCTSB_BENCHMARK_USE_BASELINE_DATA=1
    )

    if(TARGET kctsb_static)
        target_link_libraries(kctsb_benchmark_bgv PRIVATE kctsb_static)
    elseif(TARGET kctsb_shared)
        target_link_libraries(kctsb_benchmark_bgv PRIVATE kctsb_shared)
    endif()

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

    message(STATUS "✓ BGV benchmark: kctsb native BGV vs baseline")
else()
    message(STATUS "⚠ BGV benchmark skipped: KCTSB_ENABLE_BGV is OFF")
endif()

# ============================================================================
# PSI/PIR Benchmark (v5.0 Self-Contained)
# ============================================================================

add_executable(bench_psi_pir benchmark_psi_pir.cpp)

target_include_directories(bench_psi_pir PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/thirdparty/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(bench_psi_pir PRIVATE
    KCTSB_V5_SELF_CONTAINED=1
    KCTSB_BENCHMARK_USE_BASELINE_DATA=1
)

if(TARGET kctsb_static)
    target_link_libraries(bench_psi_pir PRIVATE kctsb_static)
elseif(TARGET kctsb_shared)
    target_link_libraries(bench_psi_pir PRIVATE kctsb_shared)
endif()

set_target_properties(bench_psi_pir PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

if(MSVC)
    target_compile_options(bench_psi_pir PRIVATE /O2 /fp:fast /utf-8)
else()
    target_compile_options(bench_psi_pir PRIVATE
        -O3 -march=native
        -finput-charset=UTF-8
        -fexec-charset=UTF-8
        -Wno-conversion
        -Wno-sign-conversion
        -Wno-unused-parameter
    )
endif()

message(STATUS "✓ PSI/PIR benchmark: Piano-PSI, OT-PSI, Native PIR vs baseline")

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "Benchmark suite configured:")
message(STATUS "  - kctsb_benchmark: Main crypto algorithms")
if(KCTSB_ENABLE_BGV)
    message(STATUS "  - kctsb_benchmark_bgv: BGV homomorphic encryption")
endif()
message(STATUS "  - bench_psi_pir: PSI/PIR protocols")
message(STATUS "")
message(STATUS "Run benchmarks: ./build/bin/kctsb_benchmark")
message(STATUS "")

