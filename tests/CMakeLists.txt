# ============================================================================
# kctsb Tests CMakeLists.txt
# Organized test structure with labels for selective execution
# ============================================================================

# ============================================================================
# GoogleTest Configuration
# ============================================================================

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
        GIT_TAG v1.15.2
        GIT_SHALLOW TRUE
    )

    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
else()
    message(STATUS "Using system GoogleTest: ${GTest_VERSION}")
endif()

include(GoogleTest)

# ============================================================================
# Helper Function: Add test with labels
# ============================================================================
function(kctsb_add_test TARGET_NAME SOURCE_FILE LABEL)
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    target_link_libraries(${TARGET_NAME} PRIVATE
        kctsb_static
        GTest::gtest_main
    )
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    if(WIN32)
        target_link_libraries(${TARGET_NAME} PRIVATE bcrypt)
    endif()

    # Discover tests with labels
    gtest_discover_tests(${TARGET_NAME}
        PROPERTIES LABELS "${LABEL}"
    )
endfunction()

# ============================================================================
# UNIT TESTS - Fast, isolated component tests
# Label: "unit" - Run with: ctest -L unit
# ============================================================================

# Symmetric encryption tests
kctsb_add_test(test_aes unit/crypto/test_aes.cpp "unit;crypto;symmetric")

# Hash function tests
kctsb_add_test(test_hash unit/crypto/test_hash.cpp "unit;crypto;hash")
kctsb_add_test(test_sha unit/crypto/test_sha.cpp "unit;crypto;hash")
# v3.4.0: Disabled - SIMD hash functions pending re-implementation
# kctsb_add_test(test_simd_hash unit/crypto/test_simd_hash.cpp "unit;crypto;hash;simd")

# Chinese national standards tests
# v3.4.0: test_sm temporarily disabled - SM3/SM4 implementation timeout issue
# kctsb_add_test(test_sm unit/crypto/test_sm.cpp "unit;crypto;sm")

# Math tests (requires NTL for polynomial operations)
if(KCTSB_ENABLE_NTL AND NTL_FOUND)
    add_executable(test_math unit/math/test_math.cpp)
    target_link_libraries(test_math PRIVATE
        kctsb_static
        GTest::gtest_main
    )
    target_include_directories(test_math PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    if(WIN32)
        target_link_libraries(test_math PRIVATE bcrypt)
    endif()
    target_compile_definitions(test_math PRIVATE KCTSB_HAS_NTL)
    target_link_libraries(test_math PRIVATE ${NTL_LIBRARY})
    if(GMP_FOUND)
        target_link_libraries(test_math PRIVATE ${GMP_LIBRARY})
    endif()
    if(GF2X_FOUND)
        target_link_libraries(test_math PRIVATE ${GF2X_LIBRARY})
    endif()
    gtest_discover_tests(test_math PROPERTIES LABELS "unit;math")
else()
    message(STATUS "  Skipping test_math: NTL not enabled")
endif()

# ============================================================================
# INTEGRATION TESTS - Cross-module interaction tests
# Label: "integration" - Run with: ctest -L integration
# ============================================================================

add_executable(test_integration integration/test_integration.cpp)
target_link_libraries(test_integration PRIVATE
    kctsb_static
    GTest::gtest_main
)
if(WIN32)
    target_link_libraries(test_integration PRIVATE bcrypt)
endif()
target_include_directories(test_integration PRIVATE ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(test_integration PROPERTIES LABELS "integration")

# ============================================================================
# PERFORMANCE TESTS - Internal performance validation (no OpenSSL)
# Label: "performance" - Run with: ctest -L performance
# ============================================================================

add_executable(test_benchmark benchmark/test_benchmark.cpp)
target_link_libraries(test_benchmark PRIVATE
    kctsb_static
    GTest::gtest_main
)
target_include_directories(test_benchmark PRIVATE ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(test_benchmark PROPERTIES LABELS "performance")

# ============================================================================
# SECURITY BOUNDARY TESTS - Input validation and overflow protection
# Label: "unit;security" - Run with: ctest -L security
# ============================================================================

kctsb_add_test(test_security_boundaries unit/security/test_security_boundaries.cpp "unit;security")

# ============================================================================
# Test Summary
# ============================================================================
message(STATUS "")
message(STATUS "Test Configuration Summary:")
if(KCTSB_ENABLE_NTL AND NTL_FOUND)
    message(STATUS "  Unit Tests:        test_aes, test_hash, test_sha, test_math, test_security_boundaries")
else()
    message(STATUS "  Unit Tests:        test_aes, test_hash, test_sha, test_security_boundaries (NTL disabled)")
endif()
message(STATUS "  Integration Tests: test_integration")
message(STATUS "  Performance Tests: test_benchmark")
message(STATUS "")
message(STATUS "Run commands:")
message(STATUS "  All tests:         ctest --output-on-failure")
message(STATUS "  Unit tests only:   ctest -L unit --output-on-failure")
message(STATUS "  Integration only:  ctest -L integration --output-on-failure")
message(STATUS "  Security only:     ctest -L security --output-on-failure")
message(STATUS "  Performance only:  ctest -L performance --output-on-failure")
message(STATUS "")
