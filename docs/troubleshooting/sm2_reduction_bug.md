# SM2 Modular Reduction Bug

> **Date Discovered**: 2026-01-20 (Beijing Time)
> **Severity**: Critical - causes ~30% signature verification failure
> **Status**: FIXING

## Problem Description

### Symptom
- SM2_SignVerify test fails intermittently (~30% failure rate)
- Error code: KCTSB_ERROR_VERIFICATION_FAILED (-8)
- Only affects SM2 curve, P-256 and secp256k1 work correctly

### Root Cause
The `fe256_reduce_sm2` function in `fe256.cpp` is **incomplete**. The implementation has a comment stating "For now, do a simpler but less optimal reduction" but the simplified version is actually incorrect.

**SM2 Prime Structure**:
```
p = 2^256 - 2^224 - 2^96 + 2^64 - 1
  = 0xFFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
```

**Reduction Identity**:
```
2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
```

### Buggy Code Analysis

```cpp
void fe256_reduce_sm2(fe256* r, const fe512* a) {
    // Copy low 256 bits - CORRECT
    r->limb[0] = a->limb[0];
    // ...

    // Add h[0..3] (the +1 term) - PARTIALLY CORRECT
    r->limb[0] = adc64(r->limb[0], a->limb[4], 0, &carry);
    // ...

    // BUG: Only handling part of the 2^224 term
    r->limb[3] = adc64(r->limb[3], (a->limb[4] << 32), 0, &carry);
    
    // BUG: 2^96 and -2^64 terms not properly implemented!
    // The comment says "This needs careful handling of the sign"
    // but the implementation just skips them!
    
    // Final conditional subtractions - May not be enough
    for (int i = 0; i < 3; i++) {
        // ...
    }
}
```

### Missing Implementation
1. **2^224 term**: Only partially implemented (only handles h[4] shift)
2. **2^96 term**: Not implemented at all
3. **-2^64 term**: Not implemented (subtraction required)
4. **Carry propagation**: Incomplete between terms

## Solution

Implement correct SM2 Solinas reduction following NIST-style approach:

```cpp
/**
 * SM2 Solinas reduction for 512-bit input
 * 
 * p = 2^256 - 2^224 - 2^96 + 2^64 - 1
 * 
 * For input c = (c7, c6, c5, c4, c3, c2, c1, c0) as 64-bit words:
 * Result = T + S1 + S2 + S3 + S4 - D1 - D2 (mod p)
 */
void fe256_reduce_sm2(fe256* r, const fe512* a) {
    // Extract 32-bit words for precise control
    uint64_t c[16];
    for (int i = 0; i < 8; i++) {
        c[2*i] = (uint32_t)a->limb[i];
        c[2*i + 1] = (uint32_t)(a->limb[i] >> 32);
    }
    
    // Use int64_t accumulators (NOT long - see fe256_data_type_issues.md)
    int64_t t[9] = {0};
    
    // T = (c7, c6, c5, c4, c3, c2, c1, c0)
    for (int i = 0; i < 8; i++) {
        t[i] = (int64_t)c[i];
    }
    
    // Add reduction terms based on SM2 prime structure
    // (Implementation details based on GM/T 0003.5-2012)
    // ...
}
```

## Testing

Run SM2 tests repeatedly to verify fix:
```powershell
ctest --test-dir build -R "SM2_SignVerify" --repeat until-fail:100
```

Expected result after fix: 100% pass rate.

## Related Files

- `src/crypto/ecc/fe256.cpp:fe256_reduce_sm2()` - Buggy function
- `src/crypto/ecc/fe256_p256.cpp:fe256_reduce_p256()` - Reference (working)
- `tests/unit/crypto/test_sm.cpp` - SM2 tests

## References

- GB/T 32918.1-2016 (SM2 specification)
- GM/T 0003.5-2012 (SM2 parameters)
- NIST FIPS 186-4 Appendix D.2 (similar reduction technique)
