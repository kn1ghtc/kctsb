# ============================================================================
# kctsb Tests CMakeLists.txt
# ============================================================================

# Try to find system-installed GoogleTest first (e.g., from Homebrew)
find_package(GTest CONFIG QUIET)

if(NOT GTest_FOUND)
    message(STATUS "System GoogleTest not found, using FetchContent")
    include(FetchContent)

    set(_kctsb_gtest_repo "https://github.com/google/googletest.git")
    if(DEFINED ENV{KCTSB_GTEST_MIRROR} AND NOT "$ENV{KCTSB_GTEST_MIRROR}" STREQUAL "")
        set(_kctsb_gtest_repo "$ENV{KCTSB_GTEST_MIRROR}")
        message(STATUS "Using GoogleTest mirror: ${_kctsb_gtest_repo}")
    endif()

    set(_kctsb_gtest_local "")
    if(EXISTS "${CMAKE_SOURCE_DIR}/thirdparty/googletest/CMakeLists.txt")
        set(_kctsb_gtest_local "${CMAKE_SOURCE_DIR}/thirdparty/googletest")
    elseif(DEFINED ENV{KCTSB_GTEST_SOURCE_DIR} AND EXISTS "$ENV{KCTSB_GTEST_SOURCE_DIR}/CMakeLists.txt")
        file(TO_CMAKE_PATH "$ENV{KCTSB_GTEST_SOURCE_DIR}" _kctsb_gtest_local)
    endif()

    if(_kctsb_gtest_local)
        message(STATUS "Using local GoogleTest source: ${_kctsb_gtest_local}")
        set(FETCHCONTENT_SOURCE_DIR_GOOGLETEST "${_kctsb_gtest_local}")
        set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
    endif()

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY ${_kctsb_gtest_repo}
        GIT_TAG v1.14.0
        GIT_SHALLOW TRUE
    )

    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    # Disable install for GTest
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(googletest)
else()
    message(STATUS "Using system GoogleTest: ${GTest_VERSION}")
endif()

# Enable testing
include(GoogleTest)

# ============================================================================
# Core Tests
# ============================================================================

# AES tests
add_executable(test_aes
    unit/crypto/test_aes.cpp
)
target_link_libraries(test_aes
    PRIVATE
        kctsb
        GTest::gtest_main
)
target_include_directories(test_aes PRIVATE ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(test_aes)

# Hash tests
add_executable(test_hash
    unit/crypto/test_hash.cpp
)
target_link_libraries(test_hash
    PRIVATE
        kctsb_static
        GTest::gtest_main
)
target_include_directories(test_hash PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
gtest_discover_tests(test_hash)

# SHA family tests (SHA-256/384/512)
add_executable(test_sha
    unit/crypto/test_sha.cpp
)
target_link_libraries(test_sha
    PRIVATE
        kctsb_static
        GTest::gtest_main
)
target_include_directories(test_sha PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
gtest_discover_tests(test_sha)

# RSA tests (requires NTL)
# NOTE: Temporarily disabled - test file uses legacy API (rsa_getKey, rsa_enc, rsa_decy)
# if(KCTSB_ENABLE_NTL AND NTL_FOUND)
#     add_executable(test_rsa
#         unit/crypto/test_rsa.cpp
#     )
#     target_link_libraries(test_rsa
#         PRIVATE
#             kctsb_static
#             GTest::gtest_main
#             NTL::NTL
#     )
#     target_include_directories(test_rsa PRIVATE
#         ${CMAKE_SOURCE_DIR}/include
#         ${CMAKE_SOURCE_DIR}/src
#         ${CMAKE_SOURCE_DIR}/src/crypto/rsa
#     )
#     gtest_discover_tests(test_rsa)
# endif()

# ECC tests (requires NTL)
# NOTE: Temporarily disabled - test file uses legacy API (kc_eccGroup)
# if(KCTSB_ENABLE_NTL AND NTL_FOUND)
#     add_executable(test_ecc
#         unit/crypto/test_ecc.cpp
#     )
#     target_link_libraries(test_ecc
#         PRIVATE
#             kctsb_static
#             GTest::gtest_main
#             NTL::NTL
#     )
#     target_include_directories(test_ecc PRIVATE
#         ${CMAKE_SOURCE_DIR}/include
#         ${CMAKE_SOURCE_DIR}/src
#         ${CMAKE_SOURCE_DIR}/src/crypto/ecc
#     )
#     gtest_discover_tests(test_ecc)
# endif()

# SM tests (Chinese National Standards)
add_executable(test_sm
    unit/crypto/test_sm.cpp
)
target_link_libraries(test_sm
    PRIVATE
        kctsb_static
        GTest::gtest_main
)
target_include_directories(test_sm PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
gtest_discover_tests(test_sm)

# PQC tests (Post-Quantum Cryptography - Kyber, Dilithium)
# NOTE: Temporarily disabled - API needs to be updated to match current implementation
# if(KCTSB_ENABLE_NTL AND NTL_FOUND)
#     add_executable(test_pqc
#         unit/crypto/test_pqc.cpp
#     )
#     target_link_libraries(test_pqc
#         PRIVATE
#             kctsb_static
#             GTest::gtest_main
#             NTL::NTL
#     )
#     target_include_directories(test_pqc PRIVATE
#         ${CMAKE_SOURCE_DIR}/include
#         ${CMAKE_SOURCE_DIR}/src
#     )
#     gtest_discover_tests(test_pqc)
# endif()

# ZKP tests (Zero-Knowledge Proofs - Groth16)
# NOTE: Temporarily disabled - API needs to be updated to match current implementation
# if(KCTSB_ENABLE_NTL AND NTL_FOUND)
#     add_executable(test_zkp
#         unit/crypto/test_zkp.cpp
#     )
#     target_link_libraries(test_zkp
#         PRIVATE
#             kctsb_static
#             GTest::gtest_main
#             NTL::NTL
#     )
#     target_include_directories(test_zkp PRIVATE
#         ${CMAKE_SOURCE_DIR}/include
#         ${CMAKE_SOURCE_DIR}/src
#     )
#     gtest_discover_tests(test_zkp)
# endif()

# SIMD tests (Hardware Acceleration)
# NOTE: Temporarily disabled - API needs to be updated to match current implementation
# add_executable(test_simd
#     unit/crypto/test_simd.cpp
# )
# target_link_libraries(test_simd
#     PRIVATE
#         kctsb_static
#         GTest::gtest_main
# )
# target_include_directories(test_simd PRIVATE
#     ${CMAKE_SOURCE_DIR}/include
#     ${CMAKE_SOURCE_DIR}/src
# )
# gtest_discover_tests(test_simd)

# Math tests
add_executable(test_math
    unit/math/test_math.cpp
)
target_link_libraries(test_math
    PRIVATE
        kctsb
        GTest::gtest_main
)
target_include_directories(test_math PRIVATE ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(test_math)

# ============================================================================
# Integration Tests
# ============================================================================

add_executable(test_integration
    integration/test_integration.cpp
)
target_link_libraries(test_integration
    PRIVATE
        kctsb_static
        GTest::gtest_main
)
if(WIN32)
    target_link_libraries(test_integration PRIVATE bcrypt)
endif()
target_include_directories(test_integration PRIVATE ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(test_integration)

# ============================================================================
# Benchmark Tests
# ============================================================================

add_executable(test_benchmark
    benchmark/test_benchmark.cpp
)
target_link_libraries(test_benchmark
    PRIVATE
        kctsb_static
        GTest::gtest_main
)
target_include_directories(test_benchmark PRIVATE ${CMAKE_SOURCE_DIR}/include)
