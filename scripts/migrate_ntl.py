#!/usr/bin/env python3
"""
NTL to kctsb Migration Script

This script migrates NTL (Number Theory Library) source code to kctsb's
src/math/ntl directory, organizing files by mathematical function category.

The migration:
1. Copies core algorithm files (excluding tests, checks, build tools)
2. Organizes into subdirectories: core/, ring/, vector/, matrix/, poly/, fft/, precision/, lattice/
3. Copies header files to include/kctsb/math/ntl/
4. Creates a unified config header for kctsb integration

Usage:
    python scripts/migrate_ntl.py

Author: kctsb Security Research Team
Date: 2026-01-18
Version: 4.0.0
"""

import shutil
import os
from pathlib import Path


# Base paths
KCTSB_ROOT = Path(__file__).parent.parent
NTL_SRC = KCTSB_ROOT / "deps" / "ntl-11.6.0" / "src"
NTL_INC = KCTSB_ROOT / "deps" / "ntl-11.6.0" / "include" / "NTL"
MATH_SRC = KCTSB_ROOT / "src" / "math" / "ntl"
MATH_INC = KCTSB_ROOT / "include" / "kctsb" / "math" / "ntl"


# File categorization based on NTL source analysis
# Files marked with ❌ are excluded (tests, checks, build tools)
# Files marked with ✅ are included

# Core arithmetic and utilities (Layer 0-1)
CORE_FILES = [
    "lip.cpp",          # Big integer implementation (GMP wrapper)
    "tools.cpp",        # Utility functions
    "ctools.cpp",       # C utility functions
    "fileio.cpp",       # File I/O utilities
    "thread.cpp",       # Threading support
    "BasicThreadPool.cpp",  # Thread pool
    "WordVector.cpp",   # Word vector operations
    "ZZ.cpp",           # Big integers
    "ZZVec.cpp",        # Big integer vectors (internal)
]

# Ring elements (Layer 2)
RING_FILES = [
    "ZZ_p.cpp",         # Modular integers Z/pZ
    "ZZ_pE.cpp",        # Extension field Z_p[X]/f(X)
    "lzz_p.cpp",        # Single-precision modular integers
    "lzz_pE.cpp",       # Single-precision extension field
    "GF2.cpp",          # Binary field GF(2)
    "GF2E.cpp",         # Extension field GF(2^k)
]

# Vector operations (Layer 2.5)
VECTOR_FILES = [
    "vec_ZZ.cpp",       # Vectors over ZZ
    "vec_ZZ_p.cpp",     # Vectors over Z_p
    "vec_ZZ_pE.cpp",    # Vectors over Z_pE
    "vec_lzz_p.cpp",    # Vectors over lzz_p
    "vec_lzz_pE.cpp",   # Vectors over lzz_pE
    "vec_GF2.cpp",      # Vectors over GF(2)
    "vec_GF2E.cpp",     # Vectors over GF(2^k)
    "vec_RR.cpp",       # Vectors over RR
]

# Matrix operations (Layer 3)
MATRIX_FILES = [
    "mat_ZZ.cpp",       # Matrices over ZZ
    "mat_ZZ_p.cpp",     # Matrices over Z_p
    "mat_ZZ_pE.cpp",    # Matrices over Z_pE
    "mat_lzz_p.cpp",    # Matrices over lzz_p
    "mat_lzz_pE.cpp",   # Matrices over lzz_pE
    "mat_GF2.cpp",      # Matrices over GF(2)
    "mat_GF2E.cpp",     # Matrices over GF(2^k)
    "mat_RR.cpp",       # Matrices over RR
    "mat_poly_ZZ.cpp",  # Matrix polynomials over ZZ
    "mat_poly_ZZ_p.cpp",  # Matrix polynomials over Z_p
    "mat_poly_lzz_p.cpp", # Matrix polynomials over lzz_p
    "MatPrime.cpp",     # Prime matrix operations
]

# Polynomial operations (Layer 4)
POLY_FILES = [
    "ZZX.cpp",          # Polynomials over ZZ
    "ZZX1.cpp",         # ZZX part 2
    "ZZXCharPoly.cpp",  # Characteristic polynomials over ZZ
    "ZZXFactoring.cpp", # Polynomial factorization over ZZ
    "ZZ_pX.cpp",        # Polynomials over Z_p
    "ZZ_pX1.cpp",       # Z_pX part 2
    "ZZ_pXCharPoly.cpp",  # Characteristic polynomials over Z_p
    "ZZ_pXFactoring.cpp", # Polynomial factorization over Z_p
    "ZZ_pEX.cpp",       # Polynomials over Z_pE
    "ZZ_pEXFactoring.cpp",  # Factorization over Z_pE
    "lzz_pX.cpp",       # Polynomials over lzz_p
    "lzz_pX1.cpp",      # lzz_pX part 2
    "lzz_pXCharPoly.cpp",   # Characteristic polynomials
    "lzz_pXFactoring.cpp",  # Factorization
    "lzz_pEX.cpp",      # Polynomials over lzz_pE
    "lzz_pEXFactoring.cpp", # Factorization
    "GF2X.cpp",         # Polynomials over GF(2)
    "GF2X1.cpp",        # GF2X part 2
    "GF2XFactoring.cpp",  # Factorization over GF(2)
    "GF2XVec.cpp",      # GF2X vectors
    "GF2EX.cpp",        # Polynomials over GF(2^k)
    "GF2EXFactoring.cpp",  # Factorization
]

# FFT operations (Layer 1.5)
FFT_FILES = [
    "FFT.cpp",          # Fast Fourier Transform
    "pd_FFT.cpp",       # Partial-degree FFT
]

# Precision types (Layer 1)
PRECISION_FILES = [
    "RR.cpp",           # Arbitrary precision reals
    "xdouble.cpp",      # Extended double precision
    "quad_float.cpp",   # Quad precision float
    "quad_float1.cpp",  # Quad float part 2
]

# Lattice algorithms (Layer 5)
LATTICE_FILES = [
    "LLL.cpp",          # LLL lattice reduction
    "LLL_FP.cpp",       # LLL with floating point
    "LLL_QP.cpp",       # LLL with quad precision
    "LLL_RR.cpp",       # LLL with RR
    "LLL_XD.cpp",       # LLL with xdouble
    "G_LLL_FP.cpp",     # Gram-Schmidt LLL FP
    "G_LLL_QP.cpp",     # Gram-Schmidt LLL QP
    "G_LLL_RR.cpp",     # Gram-Schmidt LLL RR
    "G_LLL_XD.cpp",     # Gram-Schmidt LLL XD
    "HNF.cpp",          # Hermite Normal Form
    "FacVec.cpp",       # Factored vectors
]

# Additional utility files
UTIL_FILES = [
    "subset.cpp",       # Subset operations
    "newnames.cpp",     # Name mapping
]

# Test files (excluded from migration, converted to unit tests)
TEST_FILES = [
    "BerlekampTest.cpp", "BitMatTest.cpp", "CanZassTest.cpp",
    "CharPolyTest.cpp", "ExceptionTest.cpp", "GF2EXGCDTest.cpp",
    "GF2EXTest.cpp", "GF2XTest.cpp", "GF2XTimeTest.cpp",
    "lzz_pEXGCDTest.cpp", "lzz_pEXTest.cpp", "lzz_pXTest.cpp",
    "mat_lzz_pTest.cpp", "MoreFacTest.cpp", "QuadTest.cpp",
    "QuickTest.cpp", "RRTest.cpp", "SSMulTest.cpp",
    "ThreadTest.cpp", "LLLTest.cpp", "MatrixTest.cpp",
    "ZZTest.cpp", "ZZXFacTest.cpp", "ZZ_pEXGCDTest.cpp",
    "ZZ_pEXTest.cpp", "ZZ_pXTest.cpp",
    # Time tests
    "Poly1TimeTest.cpp", "Poly2TimeTest.cpp", "Poly3TimeTest.cpp",
    "Timing.cpp",
]

# Check/config files (excluded)
CHECK_FILES = [
    "CheckAES_NI.cpp", "CheckALIGNED_ARRAY.cpp", "CheckAVX.cpp",
    "CheckAVX2.cpp", "CheckAVX512F.cpp", "CheckBUILTIN_CLZL.cpp",
    "CheckCHRONO_TIME.cpp", "CheckCompile.cpp", "CheckContract.cpp",
    "CheckCOPY_TRAITS1.cpp", "CheckCOPY_TRAITS2.cpp", "CheckFMA.cpp",
    "CheckGMP.cpp", "CheckKMA.cpp", "CheckLL_TYPE.cpp",
    "CheckMACOS_TIME.cpp", "CheckPCLMUL.cpp", "CheckPOSIX_TIME.cpp",
    "CheckSSSE3.cpp", "CheckThreads.cpp",
]

# Build/config files (excluded)
BUILD_FILES = [
    "MakeDesc.cpp", "MakeDescAux.cpp", "MakeCheckFeatures",
    "MakeGetPID", "MakeGetTime", "DispSettings.cpp",
    "GenConfigInfo.cpp", "gen_gmp_aux.cpp", "InitSettings.cpp",
    "GetPID1.cpp", "GetPID2.cpp",
    "GetTime0.cpp", "GetTime1.cpp", "GetTime2.cpp",
    "GetTime3.cpp", "GetTime4.cpp", "GetTime5.cpp",
    "TestGetPID.cpp", "TestGetTime.cpp",
]

# Headers to exclude (auto-generated or platform-specific)
EXCLUDE_HEADERS = [
    "config.h", "mach_desc.h",  # Generated by configure
    "gmp_aux.h",  # GMP auxiliary (internal)
    "config_log.txt", "CONFIG_LOG.txt",
    "USER_MAKEFILE.txt",
]


def ensure_dir(path: Path) -> None:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)


def copy_file(src: Path, dst: Path) -> None:
    """Copy file with logging."""
    if src.exists():
        shutil.copy2(src, dst)
        print(f"  ✓ {src.name} -> {dst}")
    else:
        print(f"  ✗ {src.name} not found")


def migrate_source_files() -> None:
    """Migrate NTL source files to kctsb structure."""
    print("\n=== Migrating NTL Source Files ===\n")
    
    # Create target directories
    categories = {
        "core": CORE_FILES,
        "ring": RING_FILES,
        "vector": VECTOR_FILES,
        "matrix": MATRIX_FILES,
        "poly": POLY_FILES,
        "fft": FFT_FILES,
        "precision": PRECISION_FILES,
        "lattice": LATTICE_FILES,
    }
    
    for category, files in categories.items():
        target_dir = MATH_SRC / category
        ensure_dir(target_dir)
        print(f"\n[{category.upper()}] -> {target_dir}")
        
        for filename in files:
            src_file = NTL_SRC / filename
            dst_file = target_dir / filename
            copy_file(src_file, dst_file)
    
    # Copy utility files to core
    print(f"\n[UTILS] -> {MATH_SRC / 'core'}")
    for filename in UTIL_FILES:
        src_file = NTL_SRC / filename
        dst_file = MATH_SRC / "core" / filename
        copy_file(src_file, dst_file)


def migrate_header_files() -> None:
    """Migrate NTL header files to kctsb include directory."""
    print("\n=== Migrating NTL Header Files ===\n")
    
    ensure_dir(MATH_INC)
    
    copied = 0
    skipped = 0
    
    for header in NTL_INC.glob("*.h"):
        if header.name in EXCLUDE_HEADERS:
            print(f"  - {header.name} (excluded)")
            skipped += 1
            continue
        
        dst_file = MATH_INC / header.name
        copy_file(header, dst_file)
        copied += 1
    
    print(f"\nCopied: {copied}, Skipped: {skipped}")


def create_kctsb_config() -> None:
    """Create kctsb-specific NTL configuration header."""
    print("\n=== Creating kctsb NTL Config ===\n")
    
    config_content = '''/**
 * @file kctsb_ntl_config.h
 * @brief kctsb-specific NTL configuration
 * 
 * This header provides NTL configuration for kctsb integration.
 * It replaces NTL's configure-generated headers with compile-time
 * detection that matches kctsb's build system.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_NTL_CONFIG_H
#define KCTSB_NTL_CONFIG_H

// ============================================================================
// Platform Detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
    #define NTL_WINPACK
    #define KCTSB_PLATFORM_WINDOWS 1
#elif defined(__APPLE__)
    #define KCTSB_PLATFORM_MACOS 1
#elif defined(__linux__)
    #define KCTSB_PLATFORM_LINUX 1
#endif

// ============================================================================
// Compiler Detection
// ============================================================================

#if defined(_MSC_VER)
    #define KCTSB_COMPILER_MSVC 1
#elif defined(__GNUC__)
    #define KCTSB_COMPILER_GCC 1
#elif defined(__clang__)
    #define KCTSB_COMPILER_CLANG 1
#endif

// ============================================================================
// Architecture Detection
// ============================================================================

#if defined(__x86_64__) || defined(_M_X64)
    #define KCTSB_ARCH_X64 1
    #define NTL_BITS_PER_LONG 64
    #define NTL_BITS_PER_INT 32
#elif defined(__i386__) || defined(_M_IX86)
    #define KCTSB_ARCH_X86 1
    #define NTL_BITS_PER_LONG 32
    #define NTL_BITS_PER_INT 32
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define KCTSB_ARCH_ARM64 1
    #define NTL_BITS_PER_LONG 64
    #define NTL_BITS_PER_INT 32
#endif

#define NTL_BITS_PER_SIZE_T (sizeof(size_t) * 8)

// ============================================================================
// GMP Integration (Required)
// ============================================================================

// Force GMP usage - we do not use NTL's internal big integer implementation
#define NTL_GMP_LIP 1

// GMP limb configuration
#if NTL_BITS_PER_LONG == 64
    #define NTL_BITS_PER_LIMB_T 64
    #define NTL_ZZ_NBITS 60
#else
    #define NTL_BITS_PER_LIMB_T 32
    #define NTL_ZZ_NBITS 30
#endif

#define NTL_ZZ_FRADIX ((double)(1L << NTL_ZZ_NBITS))
#define NTL_ZZ_WIDE_FRADIX ((double)(1L << NTL_ZZ_NBITS))

// ============================================================================
// gf2x Library (Required)
// ============================================================================

// Force gf2x library usage for GF(2) polynomial multiplication
#define NTL_GF2X_LIB 1

// ============================================================================
// C++ Standard
// ============================================================================

// kctsb requires C++17
#define NTL_CXX_STANDARD 2017
#define NTL_STD_CXX17 1

// Enable noexcept declarations
#define NTL_NOEXCEPT noexcept
#define NTL_FAKE_NOEXCEPT noexcept

// ============================================================================
// Hardware Acceleration (auto-detected)
// ============================================================================

// 64-bit integer type support
#if defined(__GNUC__) || defined(_MSC_VER)
    #define NTL_HAVE_LL_TYPE 1
#endif

// x86_64 SIMD features
#if defined(KCTSB_ARCH_X64)
    #ifdef __AES__
        #define NTL_HAVE_AES_NI 1
    #endif
    #ifdef __PCLMUL__
        #define NTL_HAVE_PCLMUL 1
    #endif
    #ifdef __SSE4_1__
        #define NTL_HAVE_SSSE3 1
    #endif
    #ifdef __AVX__
        #define NTL_HAVE_AVX 1
    #endif
    #ifdef __AVX2__
        #define NTL_HAVE_AVX2 1
    #endif
    #ifdef __AVX512F__
        #define NTL_HAVE_AVX512F 1
    #endif
    #ifdef __FMA__
        #define NTL_HAVE_FMA 1
    #endif
    
    // GCC/Clang builtin_clzl
    #if defined(__GNUC__) || defined(__clang__)
        #define NTL_HAVE_BUILTIN_CLZL 1
    #endif
#endif

// Aligned array support (C++17 alignas)
#define NTL_HAVE_ALIGNED_ARRAY 1

// Copy traits (C++17 type traits)
#define NTL_HAVE_COPY_TRAITS1 1
#define NTL_HAVE_COPY_TRAITS2 1

// ============================================================================
// Threading Configuration
// ============================================================================

// Enable thread support using C++11 threads
#define NTL_THREADS 1

// Use <chrono> for timing (C++11)
#define NTL_HAVE_CHRONO_TIME 1

// ============================================================================
// Safe Vectors (bounds checking in debug mode)
// ============================================================================

#ifdef KCTSB_DEBUG
    #define NTL_SAFE_VECTORS 1
#endif

// ============================================================================
// Performance Tuning
// ============================================================================

// FFT threshold settings (optimized for modern CPUs)
#define NTL_FFT_THRESH 16
#define NTL_FFT_BIGTAB_THRESH 4096

// Enable AVX FFT for large transforms
#if defined(NTL_HAVE_AVX2) && defined(NTL_HAVE_FMA)
    #define NTL_ENABLE_AVX_FFT 1
#endif

// ============================================================================
// Numeric Limits
// ============================================================================

#define NTL_NBITS_MAX ((NTL_BITS_PER_LONG) - 2)
#define NTL_WNBITS_MAX 52

// Maximum allocation block size
#define NTL_MAX_ALLOC_BLOCK 40000
#define NTL_RELEASE_THRESH 128

// ============================================================================
// Namespace Configuration
// ============================================================================

// NTL uses the "NTL" namespace
#define NTL_NAMESPACE NTL
#define NTL_OPEN_NNS namespace NTL {
#define NTL_CLOSE_NNS }
#define NTL_USE_NNS using namespace NTL;
#define NTL_NNS NTL::

#endif // KCTSB_NTL_CONFIG_H
'''
    
    config_path = MATH_INC / "kctsb_ntl_config.h"
    with open(config_path, 'w', encoding='utf-8') as f:
        f.write(config_content)
    print(f"  ✓ Created {config_path}")


def create_ntl_wrapper_header() -> None:
    """Create a wrapper header that includes all NTL headers."""
    print("\n=== Creating NTL Wrapper Header ===\n")
    
    wrapper_content = '''/**
 * @file ntl.h
 * @brief Unified NTL include header for kctsb
 *
 * This header provides a single include point for all NTL functionality
 * integrated into kctsb. Include this header instead of individual NTL headers.
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_NTL_H
#define KCTSB_MATH_NTL_H

// kctsb NTL configuration (must be first)
#include "kctsb_ntl_config.h"

// Core types
#include "ZZ.h"
#include "ZZ_p.h"
#include "ZZ_pE.h"

// Single-precision types
#include "lzz_p.h"
#include "lzz_pE.h"

// GF(2) types
#include "GF2.h"
#include "GF2E.h"

// Polynomials
#include "ZZX.h"
#include "ZZ_pX.h"
#include "ZZ_pEX.h"
#include "lzz_pX.h"
#include "lzz_pEX.h"
#include "GF2X.h"
#include "GF2EX.h"

// Matrices
#include "mat_ZZ.h"
#include "mat_ZZ_p.h"
#include "mat_lzz_p.h"
#include "mat_GF2.h"

// Vectors
#include "vec_ZZ.h"
#include "vec_ZZ_p.h"
#include "vec_lzz_p.h"
#include "vec_GF2.h"

// Precision types
#include "RR.h"
#include "xdouble.h"
#include "quad_float.h"

// Lattice algorithms
#include "LLL.h"
#include "HNF.h"

// Factorization
#include "ZZXFactoring.h"
#include "ZZ_pXFactoring.h"
#include "GF2XFactoring.h"

// FFT
#include "FFT.h"

#endif // KCTSB_MATH_NTL_H
'''
    
    wrapper_path = MATH_INC / "ntl.h"
    with open(wrapper_path, 'w', encoding='utf-8') as f:
        f.write(wrapper_content)
    print(f"  ✓ Created {wrapper_path}")


def print_summary() -> None:
    """Print migration summary."""
    print("\n" + "=" * 70)
    print("  NTL to kctsb Migration Complete")
    print("=" * 70)
    
    total_src = (len(CORE_FILES) + len(RING_FILES) + len(VECTOR_FILES) + 
                 len(MATRIX_FILES) + len(POLY_FILES) + len(FFT_FILES) + 
                 len(PRECISION_FILES) + len(LATTICE_FILES) + len(UTIL_FILES))
    
    print(f"""
Source Files Migrated: {total_src}
  - Core:      {len(CORE_FILES)}
  - Ring:      {len(RING_FILES)}
  - Vector:    {len(VECTOR_FILES)}
  - Matrix:    {len(MATRIX_FILES)}
  - Poly:      {len(POLY_FILES)}
  - FFT:       {len(FFT_FILES)}
  - Precision: {len(PRECISION_FILES)}
  - Lattice:   {len(LATTICE_FILES)}

Files Excluded:
  - Tests:     {len(TEST_FILES)} (to be converted to unit tests)
  - Checks:    {len(CHECK_FILES)} (kctsb handles feature detection)
  - Build:     {len(BUILD_FILES)} (kctsb uses CMake)

Next Steps:
  1. Update CMakeLists.txt to build src/math/ntl/
  2. Create config.h and mach_desc.h stubs
  3. Update header include paths
  4. Create unit tests from NTL test files
  5. Build and verify
""")


def main() -> None:
    """Main migration entry point."""
    print("=" * 70)
    print("  NTL to kctsb Migration Script")
    print("  Version 4.0.0")
    print("=" * 70)
    
    # Verify paths exist
    if not NTL_SRC.exists():
        print(f"ERROR: NTL source not found at {NTL_SRC}")
        return
    
    if not NTL_INC.exists():
        print(f"ERROR: NTL include not found at {NTL_INC}")
        return
    
    # Run migration steps
    migrate_source_files()
    migrate_header_files()
    create_kctsb_config()
    create_ntl_wrapper_header()
    print_summary()


if __name__ == "__main__":
    main()
