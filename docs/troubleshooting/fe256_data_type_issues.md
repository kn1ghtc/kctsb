# Windows 64-bit Data Type Issues in fe256

> **Date Discovered**: 2026-01-19 (Beijing Time)
> **Severity**: Critical - causes field arithmetic failures on Windows
> **Status**: RESOLVED

## Problem Description

### Symptom
- P-256 field arithmetic tests failing on Windows
- Solinas reduction producing incorrect results
- Tests passing on Linux but failing on Windows

### Root Cause
The `fe256_reduce_p256` function was using `long` type for accumulators in the Solinas reduction algorithm. On Windows 64-bit, `long` is 32 bits, while on Linux 64-bit, `long` is 64 bits.

```cpp
// INCORRECT - 'long' is 32-bit on Windows!
long t[9] = {0};
t[0] = (long)c[0];  // Truncates to 32 bits on Windows
```

### Data Type Sizes Across Platforms

| Type | Windows 64-bit | Linux 64-bit | macOS 64-bit |
|------|----------------|--------------|--------------|
| `char` | 8 bits | 8 bits | 8 bits |
| `short` | 16 bits | 16 bits | 16 bits |
| `int` | 32 bits | 32 bits | 32 bits |
| `long` | **32 bits** | 64 bits | 64 bits |
| `long long` | 64 bits | 64 bits | 64 bits |
| `int64_t` | 64 bits | 64 bits | 64 bits |
| `size_t` | 64 bits | 64 bits | 64 bits |

## Solution

Use fixed-width integer types from `<cstdint>`:

```cpp
// CORRECT - Use int64_t for cross-platform consistency
int64_t t[9] = {0};
t[0] = (int64_t)c[0];  // Always 64 bits
```

### Code Changes

**Before (Buggy)**:
```cpp
void fe256_reduce_p256(fe256* r, const fe512* a) {
    uint64_t c[16];
    // ...
    long t[9] = {0};  // BUG: 32-bit on Windows!
    t[0] = (long)c[0];
    // ...
}
```

**After (Fixed)**:
```cpp
void fe256_reduce_p256(fe256* r, const fe512* a) {
    uint64_t c[16];
    // ...
    int64_t t[9] = {0};  // CORRECT: Always 64-bit
    t[0] = (int64_t)c[0];
    // ...
}
```

## Prevention Guidelines

### Development Rules (Added to AGENTS.md)

1. **NEVER use `long` or `unsigned long`** in cryptographic code
   - Exception: NTL/GMP library interfaces that require them
   
2. **Use fixed-width types from `<cstdint>`**:
   - `int8_t`, `int16_t`, `int32_t`, `int64_t` for signed integers
   - `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t` for unsigned integers
   
3. **For signed arithmetic that may go negative** (like Solinas reduction):
   - Use `int64_t` for accumulators
   - Use explicit casts: `(int64_t)value`

4. **Test on multiple platforms** before committing field arithmetic changes

### Header Include
```cpp
#include <cstdint>  // For int64_t, uint64_t, etc.
```

## Testing

After the fix, all 186 tests pass on Windows:
```powershell
ctest --test-dir build --output-on-failure
# Result: 186/186 tests passed
```

## Related Files

- `src/crypto/ecc/fe256_p256.cpp` - P-256 Solinas reduction
- `src/crypto/ecc/fe256.cpp` - General fe256 operations
- `tests/test_fe256_point.cpp` - P-256 field arithmetic tests

## References

- [Microsoft Data Type Ranges](https://docs.microsoft.com/en-us/cpp/cpp/data-type-ranges)
- [LP64 vs LLP64 Data Models](https://en.wikipedia.org/wiki/64-bit_computing#64-bit_data_models)
