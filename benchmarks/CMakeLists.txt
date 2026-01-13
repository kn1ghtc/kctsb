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

# Benchmark executable
add_executable(kctsb_benchmark
    benchmark_main.cpp
    benchmark_aes_gcm.cpp
    benchmark_chacha20.cpp
    benchmark_hash.cpp
    benchmark_ecc.cpp
    benchmark_rsa.cpp
)

target_include_directories(kctsb_benchmark PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(kctsb_benchmark PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Link kctsb if available
if(TARGET kctsb_static)
    target_link_libraries(kctsb_benchmark PRIVATE kctsb_static)
elseif(TARGET kctsb_shared)
    target_link_libraries(kctsb_benchmark PRIVATE kctsb_shared)
endif()

# Platform-specific
if(WIN32)
    target_link_libraries(kctsb_benchmark PRIVATE bcrypt)
endif()

# Set output directory
set_target_properties(kctsb_benchmark PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Compiler flags for performance
if(MSVC)
    target_compile_options(kctsb_benchmark PRIVATE /O2 /fp:fast)
else()
    target_compile_options(kctsb_benchmark PRIVATE -O3 -march=native)
endif()

message(STATUS "Benchmarks configured: kctsb vs OpenSSL comparison")
