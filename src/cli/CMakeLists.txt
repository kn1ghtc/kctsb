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

# Use kctsb_cli as internal target name, rename to kctsb at install
add_executable(kctsb_cli ${CLI_SOURCES})

# Set output name to kctsb.exe
set_target_properties(kctsb_cli PROPERTIES
    OUTPUT_NAME kctsb
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Include directories
target_include_directories(kctsb_cli PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Link kctsb static library
target_link_libraries(kctsb_cli PRIVATE kctsb_static)

# Link NTL if available (for RSA/ECC)
if(KCTSB_ENABLE_NTL AND KCTSB_FOUND)
    target_link_libraries(kctsb_cli PRIVATE NTL::NTL)
endif()

# Link OpenSSL for benchmarks
if(OPENSSL_FOUND)
    target_link_libraries(kctsb_cli PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(kctsb_cli PRIVATE KCTSB_ENABLE_OPENSSL)
endif()

# Link SEAL if available
if(KCTSB_ENABLE_SEAL AND SEAL_FOUND)
    # Use library path directly for MinGW compatibility
    target_link_libraries(kctsb_cli PRIVATE "${SEAL_LIBRARY}")
    target_compile_definitions(kctsb_cli PRIVATE KCTSB_ENABLE_SEAL)
endif()

# Link benchmark library (for cmd_benchmark.cpp)
if(TARGET kctsb_benchmark)
    message(STATUS "Note: Benchmark functionality will be linked separately")
endif()

# Install target
install(TARGETS kctsb_cli
    RUNTIME DESTINATION bin
    COMPONENT runtime
)

# Windows-specific: Copy DLLs if needed
if(WIN32 AND OPENSSL_FOUND)
    # Copy OpenSSL DLLs to output directory
    # This is handled by vcpkg automatically
endif()

message(STATUS "kctsb CLI tool configured")
