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
    
    # Exempt GoogleTest from -Werror (external library with legacy code patterns)
    if(NOT MSVC)
        target_compile_options(gtest PRIVATE -Wno-error=useless-cast -Wno-useless-cast)
        target_compile_options(gtest_main PRIVATE -Wno-error=useless-cast -Wno-useless-cast)
    else()
        target_compile_options(gtest PRIVATE /wd4800)  # MSVC equivalent
        target_compile_options(gtest_main PRIVATE /wd4800)
    endif()
else()
    message(STATUS "Using system GoogleTest: ${GTest_VERSION}")
endif()

include(GoogleTest)

# ============================================================================
# Helper Function: Add test with labels
# v4.1.0: Tests use static library for complete bignum symbol access
# ============================================================================
function(kctsb_add_test TARGET_NAME SOURCE_FILE LABEL)
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    # v4.1.0: Always use static library for tests (bignum symbols not exported from DLL)
    if(TARGET kctsb_static)
        target_link_libraries(${TARGET_NAME} PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(${TARGET_NAME} PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    # Note: bcrypt.dll loaded at runtime, no static link needed

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

# MAC (Message Authentication Code) tests
kctsb_add_test(test_mac unit/crypto/test_mac.cpp "unit;crypto;mac")

# ChaCha20-Poly1305 AEAD tests (RFC 8439)
kctsb_add_test(test_chacha20_poly1305 unit/crypto/test_chacha20_poly1305.cpp "unit;crypto;aead")

# Random number generation tests
kctsb_add_test(test_random unit/crypto/test_random.cpp "unit;crypto;random")

# Chinese national standards tests (SM3/SM4)
# SM2 tests conditionally compiled when bignum modules available
add_executable(test_sm unit/crypto/test_sm.cpp)
# v4.1.0: Use static library for tests
if(TARGET kctsb_static)
    target_link_libraries(test_sm PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_sm PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_sm PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
# v4.0.1: Bignum modules now work on all platforms
target_compile_definitions(test_sm PRIVATE KCTSB_HAS_BIGNUM_MODULES)
gtest_discover_tests(test_sm PROPERTIES LABELS "unit;crypto;sm")

# Math tests (requires bignum for polynomial operations)
# v4.0.1: Fixed LLP64 compatibility, now works on all platforms
add_executable(test_math unit/math/test_math.cpp)
# v4.1.0: Use static library for tests
if(TARGET kctsb_static)
    target_link_libraries(test_math PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_math PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_math PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
# Note: bcrypt.dll loaded at runtime, no static link needed
target_compile_definitions(test_math PRIVATE KCTSB_HAS_BIGNUM_MODULES)
# v5.0: GMP/GF2X removed - now self-contained
# if(GMP_FOUND)
#     target_link_libraries(test_math PRIVATE ${GMP_LIBRARY})
# endif()
# if(GF2X_FOUND)
#     target_link_libraries(test_math PRIVATE ${GF2X_LIBRARY})
# endif()
gtest_discover_tests(test_math PROPERTIES LABELS "unit;math")

# ============================================================================
# INTEGRATION TESTS - Cross-module interaction tests
# Label: "integration" - Run with: ctest -L integration
# ============================================================================

add_executable(test_integration integration/test_integration.cpp)
# v4.1.0: Use static library for tests
if(TARGET kctsb_static)
    target_link_libraries(test_integration PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_integration PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
# Note: bcrypt.dll loaded at runtime, no static link needed
target_include_directories(test_integration PRIVATE ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(test_integration PROPERTIES LABELS "integration")

# ============================================================================
# PERFORMANCE TESTS - Internal performance validation (no OpenSSL)
# Label: "performance" - Run with: ctest -L performance
# ============================================================================

add_executable(test_benchmark benchmark/test_benchmark.cpp)
# v4.1.0: Use static library for tests
if(TARGET kctsb_static)
    target_link_libraries(test_benchmark PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_benchmark PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_benchmark PRIVATE ${CMAKE_SOURCE_DIR}/include)
gtest_discover_tests(test_benchmark PROPERTIES LABELS "performance")

# BGV Benchmark Tests (v4.11.0: Temporarily disabled, pending Pure RNS API update)
# TODO: Update test_bgv_benchmark.cpp to use new BGVEvaluator API
# Old API: BGVContext, BGVEncoder, multiply_relin -> New: RNSContext, BGVEvaluator
# add_executable(test_bgv_benchmark benchmark/test_bgv_benchmark.cpp)
# if(TARGET kctsb_static)
#     target_link_libraries(test_bgv_benchmark PRIVATE
#         kctsb_static
#         GTest::gtest_main
#     )
# else()
#     target_link_libraries(test_bgv_benchmark PRIVATE
#         kctsb
#         GTest::gtest_main
#     )
# endif()
# target_include_directories(test_bgv_benchmark PRIVATE ${CMAKE_SOURCE_DIR}/include)
# # Use 300s timeout for large parameter benchmark tests (n=8192+)
# gtest_discover_tests(test_bgv_benchmark 
#     PROPERTIES 
#         LABELS "performance;fhe"
#         TIMEOUT 300
# )

# BFV Benchmark Tests (v4.11.0: Temporarily disabled, pending RNS migration)
# TODO: Re-enable after BFV is migrated to pure RNS
# add_executable(test_bfv_benchmark benchmark/test_bfv_benchmark.cpp)
# if(TARGET kctsb_static)
#     target_link_libraries(test_bfv_benchmark PRIVATE
#         kctsb_static
#         GTest::gtest_main
#     )
# else()
#     target_link_libraries(test_bfv_benchmark PRIVATE
#         kctsb
#         GTest::gtest_main
#     )
# endif()
# target_include_directories(test_bfv_benchmark PRIVATE ${CMAKE_SOURCE_DIR}/include)
# gtest_discover_tests(test_bfv_benchmark PROPERTIES LABELS "performance;fhe")

# ============================================================================
# SECURITY BOUNDARY TESTS - Input validation and overflow protection
# Label: "unit;security" - Run with: ctest -L security
# ============================================================================

kctsb_add_test(test_security_boundaries unit/security/test_security_boundaries.cpp "unit;security")

# ============================================================================
# ECC TESTS - Elliptic Curve Cryptography (v4.8.1)
# Label: "unit;ecc" - Run with: ctest -L ecc
# v4.8.1: fe256 acceleration layer merged into ecc_curve.cpp
#         Tests migrated to unit/crypto/test_ecc.cpp
# ============================================================================

# ECC comprehensive tests (includes migrated fe256 acceleration tests)
# Tests cover: secp256k1, P-256, SM2 curves
# Features tested: Montgomery ladder, point operations, field arithmetic
add_executable(test_ecc unit/crypto/test_ecc.cpp)
if(TARGET kctsb_static)
    target_link_libraries(test_ecc PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_ecc PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_ecc PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_compile_definitions(test_ecc PRIVATE KCTSB_HAS_BIGNUM_MODULES)
gtest_discover_tests(test_ecc PROPERTIES LABELS "unit;crypto;ecc")

# fe256 Debug Tests - Enable KCTSB_DEBUG_FE256 for fe256 path validation
add_executable(test_fe256_debug unit/crypto/test_fe256_debug.cpp)
if(TARGET kctsb_static)
    target_link_libraries(test_fe256_debug PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_fe256_debug PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_fe256_debug PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_compile_definitions(test_fe256_debug PRIVATE KCTSB_HAS_BIGNUM_MODULES KCTSB_DEBUG_FE256=1)
gtest_discover_tests(test_fe256_debug PROPERTIES LABELS "unit;crypto;debug")

# SM2 Montgomery Debug Tests - Isolates Montgomery component issues
add_executable(test_sm2_mont_debug unit/crypto/test_sm2_mont_debug.cpp)
if(TARGET kctsb_static)
    target_link_libraries(test_sm2_mont_debug PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_sm2_mont_debug PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_sm2_mont_debug PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
gtest_discover_tests(test_sm2_mont_debug PROPERTIES LABELS "unit;crypto;sm2;debug")

# ============================================================================
# ADVANCED CRYPTOGRAPHY TESTS - BGV Homomorphic Encryption (v4.7.0)
# Label: "unit;fhe" - Run with: ctest -L fhe
# Note: test_bgv.cpp moved to unit/fhe/ directory for better organization
# ============================================================================

if(KCTSB_ENABLE_BGV)
    # NTT (Number Theoretic Transform) tests (v4.6.0 Phase 1)
    add_executable(test_ntt unit/fhe/test_ntt.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_ntt PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_ntt PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_ntt PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_ntt PROPERTIES LABELS "unit;fhe;ntt")
    
    # RNS (Residue Number System) tests (v4.6.0 Phase 1)
    add_executable(test_rns unit/fhe/test_rns.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_rns PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_rns PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_rns PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_rns PROPERTIES LABELS "unit;fhe;rns")
    
    # NTT Polynomial Operations tests (v4.6.0 Phase 1)
    add_executable(test_ntt_poly_ops unit/fhe/test_ntt_poly_ops.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_ntt_poly_ops PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_ntt_poly_ops PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_ntt_poly_ops PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_ntt_poly_ops PROPERTIES LABELS "unit;fhe;ntt_poly_ops")
    
    # BGV Homomorphic Encryption tests (v4.2.0)
    # v4.11.0: Temporarily disabled - uses NTL-based BGVContext API (replaced by pure RNS)
    # TODO: Migrate test_bgv.cpp to use new BGVEvaluator pure RNS API
    # add_executable(test_bgv unit/fhe/test_bgv.cpp)
    # # BGV requires static library for full NTL/bignum access
    # if(TARGET kctsb_static)
    #     target_link_libraries(test_bgv PRIVATE
    #         kctsb_static
    #         GTest::gtest_main
    #     )
    # else()
    #     target_link_libraries(test_bgv PRIVATE
    #         kctsb
    #         GTest::gtest_main
    #     )
    # endif()
    # target_include_directories(test_bgv PRIVATE
    #     ${CMAKE_SOURCE_DIR}/include
    #     ${CMAKE_SOURCE_DIR}/src
    # )
    # # Link NTL if available
    # if(NTL_FOUND)
    #     target_link_libraries(test_bgv PRIVATE ${NTL_LIBRARY})
    #     if(GMP_FOUND)
    #         target_link_libraries(test_bgv PRIVATE ${GMP_LIBRARY})
    #     endif()
    # endif()
    # gtest_discover_tests(test_bgv PROPERTIES LABELS "unit;fhe;bgv")
    
    # BGV Evaluator Pure RNS tests (v4.11.0 Phase 4d)
    add_executable(test_bgv_evaluator test_bgv_evaluator.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_bgv_evaluator PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_bgv_evaluator PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_bgv_evaluator PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_bgv_evaluator PROPERTIES LABELS "unit;fhe;bgv;rns")
    
    # BFV Evaluator Pure RNS tests (v4.11.0 Phase 4d)
    add_executable(test_bfv_evaluator advanced/fe/bfv/test_bfv_evaluator.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_bfv_evaluator PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_bfv_evaluator PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_bfv_evaluator PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_bfv_evaluator PROPERTIES LABELS "unit;fhe;bfv;rns")
    
    # BEHZ RNS Tool tests (v4.12.0)
    add_executable(test_behz_rns_tool advanced/fe/common/test_behz_rns_tool.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_behz_rns_tool PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_behz_rns_tool PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_behz_rns_tool PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_behz_rns_tool PROPERTIES LABELS "unit;fhe;behz;rns")
    
    # BEHZ BFV Integration tests (v4.13.0 - Diagnostic tests for multiply_and_rescale)
    add_executable(test_behz_bfv_integration advanced/fe/bfv/test_behz_bfv_integration.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_behz_bfv_integration PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_behz_bfv_integration PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_behz_bfv_integration PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_behz_bfv_integration PROPERTIES LABELS "unit;fhe;behz;bfv")
    
    # Legacy BFV Homomorphic Encryption tests (v4.11.0: Disabled, NTL-based)
    # TODO: Re-enable after BFV is migrated to pure RNS
    # add_executable(test_bfv unit/fhe/test_bfv.cpp)
    # if(TARGET kctsb_static)
    #     target_link_libraries(test_bfv PRIVATE
    #         kctsb_static
    #         GTest::gtest_main
    #     )
    # else()
    #     target_link_libraries(test_bfv PRIVATE
    #         kctsb
    #         GTest::gtest_main
    #     )
    # endif()
    # target_include_directories(test_bfv PRIVATE
    #     ${CMAKE_SOURCE_DIR}/include
    #     ${CMAKE_SOURCE_DIR}/src
    # )
    # if(NTL_FOUND)
    #     target_link_libraries(test_bfv PRIVATE ${NTL_LIBRARY})
    #     if(GMP_FOUND)
    #         target_link_libraries(test_bfv PRIVATE ${GMP_LIBRARY})
    #     endif()
    # endif()
    # gtest_discover_tests(test_bfv PROPERTIES LABELS "unit;fhe;bfv")
    
    # CKKS Evaluator Pure RNS tests (v4.14.0 - NEW)
    add_executable(test_ckks_evaluator advanced/fe/ckks/test_ckks_evaluator.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_ckks_evaluator PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_ckks_evaluator PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_ckks_evaluator PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    gtest_discover_tests(test_ckks_evaluator PROPERTIES LABELS "unit;fhe;ckks;rns")
    
    # Harvey NTT Optimized Implementation tests (v4.9.1 Phase 4b)
    add_executable(test_ntt_harvey test_ntt_harvey.cpp)
    if(TARGET kctsb_static)
        target_link_libraries(test_ntt_harvey PRIVATE
            kctsb_static
            GTest::gtest_main
        )
    else()
        target_link_libraries(test_ntt_harvey PRIVATE
            kctsb
            GTest::gtest_main
        )
    endif()
    target_include_directories(test_ntt_harvey PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    # Enable AVX2 if available
    if(NOT MSVC)
        target_compile_options(test_ntt_harvey PRIVATE -mavx2)
    else()
        target_compile_options(test_ntt_harvey PRIVATE /arch:AVX2)
    endif()
    gtest_discover_tests(test_ntt_harvey PROPERTIES LABELS "unit;fhe;ntt_harvey")
endif()

# ============================================================================
# PSI/PIR TESTS - Private Set Intersection & Private Information Retrieval
# Label: "unit;psi" or "unit;pir" - Run with: ctest -L psi
# v4.14.0: Tests for Piano-PSI, OT-PSI, Native PIR
# ============================================================================

add_executable(test_psi_pir unit/advanced/test_psi_pir.cpp)
if(TARGET kctsb_static)
    target_link_libraries(test_psi_pir PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_psi_pir PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_psi_pir PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
gtest_discover_tests(test_psi_pir PROPERTIES LABELS "unit;advanced;psi;pir")

# ============================================================================
# CORE TESTS - Self-contained cryptographic implementations
# Label: "core" - Run with: ctest -L core
# ============================================================================

add_executable(test_core test_core.cpp)
if(TARGET kctsb_static)
    target_link_libraries(test_core PRIVATE
        kctsb_static
        GTest::gtest_main
    )
else()
    target_link_libraries(test_core PRIVATE
        kctsb
        GTest::gtest_main
    )
endif()
target_include_directories(test_core PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
gtest_discover_tests(test_core PROPERTIES LABELS "unit;core")
message(STATUS "✓ Core Tests: BigInt, Fe256, RSA, ECC, SM2, DH")

# ============================================================================
# Test Summary
# ============================================================================
message(STATUS "")
message(STATUS "Test Configuration Summary:")
if(NOT WIN32 OR KCTSB_FORCE_BIGNUM_MODULES)
    message(STATUS "  Unit Tests:        test_aes, test_hash, test_sha, test_math, test_security_boundaries")
else()
    message(STATUS "  Unit Tests:        test_aes, test_hash, test_sha, test_security_boundaries (bignum disabled)")
endif()
if(KCTSB_ENABLE_BGV)
    message(STATUS "  FHE Tests:         test_bgv, test_bfv, test_ckks (BGV/BFV/CKKS homomorphic encryption)")
else()
    message(STATUS "  FHE Tests:         (disabled - set KCTSB_ENABLE_BGV=ON)")
endif()
message(STATUS "  Integration Tests: test_integration")
message(STATUS "  Performance Tests: test_benchmark")
message(STATUS "")
message(STATUS "Run commands:")
message(STATUS "  All tests:         ctest --output-on-failure")
message(STATUS "  Unit tests only:   ctest -L unit --output-on-failure")
message(STATUS "  FHE tests only:    ctest -L fhe --output-on-failure")
message(STATUS "  Integration only:  ctest -L integration --output-on-failure")
message(STATUS "  Security only:     ctest -L security --output-on-failure")
message(STATUS "  Performance only:  ctest -L performance --output-on-failure")
message(STATUS "")
