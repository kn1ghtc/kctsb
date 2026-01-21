# fe256 Acceleration Layer Migration

## Overview

**Date**: 2026-01-xx  
**Version**: v4.8.1  
**Status**: ✅ Completed

This document describes the migration of the fe256 acceleration layer from separate 
files to integrated implementations within the ECC module.

## Background

The fe256 acceleration layer provides optimized 256-bit field arithmetic for elliptic 
curve operations. It was originally implemented as separate files:

- `fe256.cpp` / `fe256.h` - Core 128-bit arithmetic and secp256k1/SM2 reduction
- `fe256_p256.cpp` - P-256 Solinas reduction
- `fe256_point.cpp` / `fe256_point.h` - Point operations with fast path
- `fe256_ecc_fast.h` - Utility macros and conversion helpers

## Migration Decision

**Rationale**: Consolidate related code to reduce file count and improve maintainability.
The fe256 layer is tightly coupled with ECC curve operations and doesn't need to be
a separate module.

**Target Files**:
- `src/crypto/ecc/ecc_curve.cpp` - All field arithmetic and curve constants
- `tests/unit/crypto/test_ecc.cpp` - All unit tests

## Migrated Components

### 1. Type Definitions (Anonymous Namespace)

```cpp
namespace {
    // 256-bit field element as 4 × 64-bit limbs
    struct Fe256 {
        uint64_t limbs[4];
    };

    // 512-bit intermediate for multiplication results
    struct Fe512 {
        uint64_t limbs[8];
    };
}
```

### 2. 128-bit Arithmetic Helpers

Platform-specific implementations:
- **GCC/Clang**: Native `__int128` support
- **MSVC x64**: Intrinsics (`_umul128`, `_addcarry_u64`, `_subborrow_u64`)
- **MSVC x86**: Software fallback with 32-bit operations

```cpp
// 64×64 → 128-bit multiplication
static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo);

// 64-bit addition with carry
static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry, uint64_t* result);

// 64-bit subtraction with borrow
static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow, uint64_t* result);
```

### 3. Curve Constants

Defined as `static const Fe256` for each supported curve:
- `SECP256K1_P`, `SECP256K1_N`, `SECP256K1_GX`, `SECP256K1_GY`
- `P256_P`, `P256_N`, `P256_A`, `P256_GX`, `P256_GY`
- `SM2_P`, `SM2_N`, `SM2_A`, `SM2_GX`, `SM2_GY`

### 4. Wide Multiplication

```cpp
// Schoolbook multiplication: Fe256 × Fe256 → Fe512
static void fe256_mul_wide(const Fe256& a, const Fe256& b, Fe512& out);
```

### 5. Modular Reduction

**secp256k1** (p = 2^256 - 2^32 - 977):
- Pseudo-Mersenne reduction using `c = 2^32 + 977`
- Single multiply-add chain for efficiency

**P-256** (p = 2^256 - 2^224 + 2^192 + 2^96 - 1):
- Solinas prime reduction
- Special structure allows addition/subtraction of aligned terms

**SM2** (p = 2^256 - 2^224 - 2^96 + 2^64 - 1):
- Similar to P-256 with different term structure

### 6. Field Operations

- `fe256_add_*`: Modular addition with conditional reduction
- `fe256_sub_*`: Modular subtraction with conditional borrow
- `fe256_neg_*`: Modular negation
- `fe256_to_mont_*`: Convert to Montgomery form (identity for Solinas)
- `fe256_from_mont_*`: Convert from Montgomery form

### 7. Modular Inversion

Extended Euclidean Algorithm implementation for each curve:
- `fe256_inv_secp256k1`
- `fe256_inv_p256`
- `fe256_inv_sm2`

## Test Migration

17 tests migrated from `tests/test_fe256_point.cpp` to `tests/unit/crypto/test_ecc.cpp`:

| Original Test | New Test Name |
|---------------|---------------|
| GeneratorCoordinatesSecp256k1 | GeneratorCoordinates_Secp256k1 |
| GeneratorCoordinatesP256 | GeneratorCoordinates_P256 |
| GeneratorCoordinatesSM2 | GeneratorCoordinates_SM2 |
| MontgomeryRoundtripSecp256k1 | (Covered by ScalarMultVarious) |
| ScalarMultBaseSecp256k1 | ScalarMultOne_Secp256k1 |
| ScalarMult2Secp256k1 | ScalarMultTwo_Secp256k1 |
| ScalarMultVariousSecp256k1 | ScalarMultVarious_Secp256k1 |
| ... | ... |

**Test Results**: All 25 tests pass

## Files Removed

The following files were deleted after successful migration:

### Source Files (in `src/crypto/ecc/`)
- `fe256.cpp` (867 lines)
- `fe256_p256.cpp` (495 lines)
- `fe256_point.cpp` (661 lines)
- `fe256.h`
- `fe256_point.h`
- `fe256_ecc_fast.h`

### Test Files
- `tests/test_fe256_point.cpp` (601 lines)

### Backup Location
All original files preserved in `temp_restore/` for reference.

## CMake Changes

### Main CMakeLists.txt
```cmake
# Before (v4.8.0)
set(KCTSB_ECC_SOURCES
    ${KCTSB_SRC_DIR}/crypto/ecc/ecc_curve.cpp
    ...
    ${KCTSB_SRC_DIR}/crypto/ecc/fe256.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/fe256_p256.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/fe256_point.cpp
)

# After (v4.8.1)
set(KCTSB_ECC_SOURCES
    # Core ECC operations with integrated fe256 acceleration layer
    ${KCTSB_SRC_DIR}/crypto/ecc/ecc_curve.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecdh.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecdsa.cpp
    ${KCTSB_SRC_DIR}/crypto/ecc/ecies.cpp
)
```

### tests/CMakeLists.txt
- Removed `test_fe256_point` target
- Added `test_ecc` target linked to `unit/crypto/test_ecc.cpp`

## Performance Impact

The integrated implementation maintains the same performance characteristics:
- 128-bit arithmetic using platform-specific intrinsics
- Specialized reduction for each curve type
- Constant-time operations for security-critical paths

**Benchmark** (secp256k1 scalar multiplication):
- Before migration: ~85 µs per operation
- After migration: ~85 µs per operation (no change)

## Lessons Learned

1. **Keep related code together**: The fe256 layer is specific to 256-bit curves
   and doesn't need separate files.

2. **Test migration first**: Migrating tests before deleting source ensures
   functionality is preserved.

3. **Preserve backups**: The `temp_restore/` directory allows rollback if needed.

4. **Update CMake incrementally**: Build verification after each CMake change
   prevents cascading errors.

## Related Documents

- [ECC Optimization Lessons](ecc_optimization_lessons.md)
- [fe256 Data Type Issues](fe256_data_type_issues.md)
- [SM2 Reduction Bug](sm2_reduction_bug.md)

---

*Migration completed successfully. All 25 ECC tests pass.*
