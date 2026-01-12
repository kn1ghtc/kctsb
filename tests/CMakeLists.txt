# ============================================================================
# kctsb Tests CMakeLists.txt
# ============================================================================

# Find Google Test
include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

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
