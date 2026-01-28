# Tests CMake configuration for kctsb
# Builds unit/integration/performance tests with GoogleTest.

find_package(GTest REQUIRED)

file(GLOB_RECURSE KCTSB_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/**/test_*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/**/test_*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/performance/**/test_*.cpp"
)

list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/fhe/")
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/crypto/test_zkp.cpp")
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/crypto/test_simd.cpp")
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/advanced/test_psi_pir.cpp")
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/crypto/test_ecc.cpp")
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/crypto/test_ecc_debug.cpp")
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/crypto/test_sha.cpp")

if (KCTSB_TEST_SOURCES STREQUAL "")
    message(WARNING "No test sources found under ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

add_executable(kctsb_tests ${KCTSB_TEST_SOURCES})

target_include_directories(kctsb_tests PRIVATE
    ${KCTSB_INCLUDE_DIR}
)

target_link_libraries(kctsb_tests PRIVATE
    kctsb
    GTest::gtest_main
)

include(GoogleTest)

gtest_discover_tests(kctsb_tests)
