# NTL Precision Files Migration

## Issue Description

During the NTL to kctsb bignum integration (v3.0.0 - v3.2.0), several precision arithmetic 
files were not migrated from `deps/ntl-11.6.0/src/` to `src/math/bignum/`. These files are 
required for:

1. **LLL Lattice Reduction** - Multiple precision variants for numerical stability
2. **CKKS Approximate Homomorphic Encryption** - Requires arbitrary precision real numbers
3. **Floating-point computation** - Extended precision for cryptographic applications

## Current Status

**Status**: 🟡 Partially Complete (v4.8.1)

- ✅ xdouble constants defined in kctsb_bignum_config.h (pending)
- ❌ RR.cpp not yet migrated
- ❌ xdouble.cpp not yet migrated
- ❌ quad_float.cpp not yet migrated
- ❌ LLL precision variants not yet migrated

## Missing Files

The following files need to be migrated from `deps/ntl-11.6.0/src/` to appropriate
subdirectories under `src/math/bignum/`:

### Core Precision Types (→ `core/`)

| NTL Source | Target | Lines | Description |
|------------|--------|-------|-------------|
| `RR.cpp` | `core/RR.cpp` | 1980 | Arbitrary precision real numbers |
| `xdouble.cpp` | `core/xdouble.cpp` | 914 | Extended double precision |
| `quad_float.cpp` | `core/quad_float.cpp` | 742 | Quad-precision floating point |
| `quad_float1.cpp` | `core/quad_float1.cpp` | 230 | Quad-float helpers |

### Vector/Matrix Types (→ `vector/`, `matrix/`)

| NTL Source | Target | Lines | Description |
|------------|--------|-------|-------------|
| `vec_RR.cpp` | `vector/vec_RR.cpp` | 186 | RR vector operations |
| `mat_RR.cpp` | `matrix/mat_RR.cpp` | 284 | RR matrix operations |

### LLL Precision Variants (→ `lattice/`)

| NTL Source | Target | Lines | Description |
|------------|--------|-------|-------------|
| `LLL_FP.cpp` | `lattice/LLL_FP.cpp` | ~1000 | LLL with floating-point |
| `LLL_QP.cpp` | `lattice/LLL_QP.cpp` | ~1200 | LLL with quad-precision |
| `LLL_RR.cpp` | `lattice/LLL_RR.cpp` | ~1400 | LLL with arbitrary precision |
| `LLL_XD.cpp` | `lattice/LLL_XD.cpp` | ~1200 | LLL with xdouble |
| `G_LLL_FP.cpp` | `lattice/G_LLL_FP.cpp` | ~800 | Gram-based LLL (FP) |
| `G_LLL_QP.cpp` | `lattice/G_LLL_QP.cpp` | ~1000 | Gram-based LLL (QP) |
| `G_LLL_RR.cpp` | `lattice/G_LLL_RR.cpp` | ~1200 | Gram-based LLL (RR) |
| `G_LLL_XD.cpp` | `lattice/G_LLL_XD.cpp` | ~1000 | Gram-based LLL (XD) |

## Migration Requirements

### Namespace Changes

All files require the following namespace adaptation:

```cpp
// Original NTL
NTL_START_IMPL
...
NTL_END_IMPL

// Target kctsb
namespace kctsb {
...
} // namespace kctsb
```

### Macro Replacements

| NTL Macro | kctsb Replacement |
|-----------|-------------------|
| `NTL_START_IMPL` | `namespace kctsb {` |
| `NTL_END_IMPL` | `} // namespace kctsb` |
| `NTL_CHEAP_THREAD_LOCAL` | `thread_local` |
| `NTL_OVERFLOW(a, b, c)` | Custom overflow check |
| `ResourceError(msg)` | `throw std::runtime_error(msg)` |
| `LogicError(msg)` | `throw std::logic_error(msg)` |

### Include Path Changes

```cpp
// Original
#include <NTL/RR.h>
#include <NTL/xdouble.h>

// Target
#include "kctsb/math/bignum/RR.h"
#include "kctsb/math/bignum/xdouble.h"
```

## Impact on FHE Modules

### CKKS (Approximate HE)

- Requires `RR.cpp` for encoding/decoding real numbers
- Needs `xdouble.cpp` for extended precision intermediate calculations
- Without these files, CKKS tests will fail with undefined symbol errors

### LLL Lattice Reduction

- Core `LLL.cpp` exists but lacks precision variants
- For RLWE parameter generation, need `LLL_FP.cpp` or `LLL_XD.cpp`
- BKZ algorithm requires higher precision (`LLL_RR.cpp`)

### BGV/BFV

- Not directly affected (uses integer arithmetic)
- However, noise estimation may benefit from RR precision

## Workaround (Temporary)

Until migration is complete, FHE modules requiring precision arithmetic should:

1. Disable CKKS tests that depend on RR
2. Use basic LLL without precision variants
3. Mark precision-dependent tests as `DISABLED_`

## Migration Priority

1. **High**: `RR.cpp`, `xdouble.cpp` - Required for CKKS
2. **Medium**: `LLL_FP.cpp`, `LLL_XD.cpp` - Improved LLL stability
3. **Low**: `quad_float.cpp`, Gram-based variants - Optional enhancements

## Related Issues

- BGV RNV implementation depends on stable LLL for parameter generation
- SEAL integration requires RR for CKKS encoder compatibility

---

*Document created: 2026-01-xx*
*Status: In Progress*
*Assigned: v3.3.0 milestone*
