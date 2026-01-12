# ============================================================================
# kctsb CLI Tool - CMakeLists.txt
#
# Builds the kctsb command-line executable (similar to openssl.exe)
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# CLI executable sources
set(CLI_SOURCES
    kctsb_main.cpp
    cmd_aes.cpp
    cmd_hash.cpp
    cmd_rsa.cpp
    cmd_ecc.cpp
    cmd_chacha20.cpp
    cmd_benchmark.cpp
)

add_executable(kctsb ${CLI_SOURCES})

# Include directories
target_include_directories(kctsb PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Link kctsb static library
target_link_libraries(kctsb PRIVATE kctsb_static)

# Link NTL if available (for RSA/ECC)
if(KCTSB_ENABLE_NTL AND NTL_FOUND)
    target_link_libraries(kctsb PRIVATE NTL::NTL)
endif()

# Link OpenSSL for benchmarks
if(OPENSSL_FOUND)
    target_link_libraries(kctsb PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(kctsb PRIVATE KCTSB_ENABLE_OPENSSL)
endif()

# Link SEAL if available
if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
    target_link_libraries(kctsb PRIVATE SEAL::seal)
    target_compile_definitions(kctsb PRIVATE KCTSB_ENABLE_SEAL)
endif()

# Link benchmark library (for cmd_benchmark.cpp)
if(TARGET kctsb_benchmark)
    # If benchmark target exists, link it
    # Note: This creates a circular dependency issue
    # Better approach: Extract benchmark logic into a library
    message(STATUS "Note: Benchmark functionality will be linked separately")
endif()

# Install target
install(TARGETS kctsb
    RUNTIME DESTINATION bin
    COMPONENT runtime
)

# Windows-specific: Copy DLLs if needed
if(WIN32 AND OPENSSL_FOUND)
    # Copy OpenSSL DLLs to output directory
    # This is handled by vcpkg automatically
endif()

message(STATUS "kctsb CLI tool configured")
