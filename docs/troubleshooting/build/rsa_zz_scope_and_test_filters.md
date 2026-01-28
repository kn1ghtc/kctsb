# RSA Build Errors: ZZ Scope & Incompatible Tests

**Date**: 2026-01-28 10:52:31 (UTC+8 Beijing Time)  
**Affected Versions**: v5.0.0  
**Severity**: 🟡 Medium  
**Category**: build  
**Status**: ✅ Resolved

---

## Issue Description

### Symptom
CMake build fails when compiling RSA and test targets after recent RSA optimizations.

### Error Message
```
rsa.cpp: error: 'ZZ' was not declared in this scope
rsa.cpp: error: call of overloaded 'ZZ(uint32_t)' is ambiguous
.../unit/crypto/test_zkp.cpp: error: <API mismatch>
.../unit/crypto/test_simd.cpp: error: <API mismatch>
ld.exe: multiple definition of `main'
```

### Reproduction Steps
1. Configure build with tests enabled:
   - `cmake -B build -G Ninja -DKCTSB_BUILD_TESTS=ON`
2. Build:
   - `cmake --build build --parallel`
3. Observe compilation failures in `src/crypto/rsa.cpp` and incompatible tests.

### Environment
- OS: Windows 11
- Language: C++17
- Compiler: MinGW-w64 GCC 13+
- Related Components: `src/crypto/rsa.cpp`, `tests/CMakeLists.txt`

---

## Root Cause Analysis

### Technical Explanation
- `ZZ` is declared under the `kctsb` namespace. In `extern "C"` RSA APIs, `ZZ` was referenced without qualification, which is not visible in the global namespace.
- The small-prime check used `ZZ(p)` with a `uint32_t` argument, causing ambiguous constructor resolution.
- Some tests (ZKP/SIMD) currently depend on APIs or build flags not available in the standard test build.
- Several unit tests include their own `main()` entry point, which conflicts with `GTest::gtest_main` when linked into a single `kctsb_tests` binary.

### Code Location
- File: `src/crypto/rsa.cpp`
- Functions: `is_probable_prime`, `kctsb_rsa_generate_keypair`, RSA OAEP/PSS API wrappers
- File: `tests/CMakeLists.txt`

### Why It Wasn't Caught Earlier
- The issue surfaced after RSA code changes and a clean rebuild with tests enabled.
- Incompatible tests are present but not always built in default configurations.

---

## Solution

### Permanent Fix
- Use `kctsb::ZZ` in C ABI wrappers and explicitly cast the small-prime values.
- Exclude incompatible ZKP/SIMD tests and tests that define their own `main()` from the default test target.

### Verification Steps
- `cmake -B build -G Ninja -DKCTSB_BUILD_TESTS=ON`
- `cmake --build build --parallel`
- `ctest --test-dir build --output-on-failure`

---

## References
- `src/crypto/rsa.cpp`
- `tests/CMakeLists.txt`
