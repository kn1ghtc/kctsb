# Tests CMake configuration for kctsb
# Builds unit/integration/performance tests with GoogleTest.
#
# Directory Structure (v5.1.0):
# - benchmark/: Independent build system for single-algorithm performance optimization
# - integration/: Integration tests for full system verification
# - unit/: Unit tests organized by module:
#   - unit/crypto/: Cryptographic primitive tests (AES, SHA, MAC, ECC, RSA, etc.)
#   - unit/fhe/: Homomorphic encryption tests (BFV, BGV, CKKS, NTT, RNS)
#   - unit/math/: Mathematical operation tests
#   - unit/security/: Security-related tests
#   - unit/advanced/: Advanced feature tests:
#     - unit/advanced/fhe/: FHE evaluator tests (bfv/, bgv/, ckks/, common/)
#     - unit/advanced/test_psi_pir.cpp: PSI/PIR protocol tests

find_package(GTest REQUIRED)

# Collect test sources from unit, integration directories
# Excludes benchmark/ which has independent build system
file(GLOB_RECURSE KCTSB_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/**/test_*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/integration/**/test_*.cpp"
)

# Exclude incompatible tests (temporarily)
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/crypto/test_zkp.cpp")
list(FILTER KCTSB_TEST_SOURCES EXCLUDE REGEX "/unit/crypto/test_simd.cpp")

# Tests that define their own main() must be built as standalone executables
set(KCTSB_TESTS_WITH_MAIN
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/advanced/test_psi_pir.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/crypto/test_ecc.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/crypto/test_ecc_debug.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/crypto/test_sha.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/fhe/test_bgv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/fhe/test_bfv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/fhe/test_ckks.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/fhe/test_ntt.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/fhe/test_ntt_harvey.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/fhe/test_rns.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/fhe/test_bgv_evaluator.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/advanced/fhe/common/test_behz_rns_tool.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/advanced/fhe/bgv/test_bgv_relin_debug.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/advanced/fhe/bgv/test_multiply_isolated.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/advanced/fhe/bfv/test_behz_bfv_integration.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/advanced/fhe/bfv/test_bfv_evaluator.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit/advanced/fhe/ckks/test_ckks_evaluator.cpp"
)

list(REMOVE_ITEM KCTSB_TEST_SOURCES ${KCTSB_TESTS_WITH_MAIN})

if (KCTSB_TEST_SOURCES STREQUAL "")
    message(WARNING "No test sources found under ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

add_executable(kctsb_tests ${KCTSB_TEST_SOURCES})

target_include_directories(kctsb_tests PRIVATE
    ${KCTSB_INCLUDE_DIR}
    ${KCTSB_SRC_DIR}
)

target_link_libraries(kctsb_tests PRIVATE
    kctsb
    GTest::gtest_main
)

include(GoogleTest)

gtest_discover_tests(kctsb_tests)

foreach(TEST_SRC IN LISTS KCTSB_TESTS_WITH_MAIN)
    if(EXISTS ${TEST_SRC})
        get_filename_component(TEST_NAME ${TEST_SRC} NAME_WE)
        set(TARGET_NAME "${TEST_NAME}_standalone")
        add_executable(${TARGET_NAME} ${TEST_SRC})
        target_include_directories(${TARGET_NAME} PRIVATE ${KCTSB_INCLUDE_DIR} ${KCTSB_SRC_DIR})
        target_link_libraries(${TARGET_NAME} PRIVATE kctsb GTest::gtest)
        add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
        list(APPEND KCTSB_STANDALONE_TARGETS ${TARGET_NAME})
    endif()
endforeach()

if(KCTSB_STANDALONE_TARGETS)
    add_custom_target(kctsb_standalone_tests ALL DEPENDS ${KCTSB_STANDALONE_TARGETS})
endif()
