#!/usr/bin/env python3
"""
Verify P-256 Solinas reduction formula.

This script tests different implementations of NIST P-256 Solinas reduction
to find the correct formula matching NIST FIPS 186-4 Appendix D.2.3.

References:
- NIST FIPS 186-4: https://csrc.nist.gov/publications/detail/fips/186/4/final
- IACR eprint 2015/1225: "ECC on Your Fingertips"
- NIST SP 800-186: https://csrc.nist.gov/pubs/sp/800/186/final
"""

import sys

# P-256 Prime
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF


def extract_32bit_words(n, num_words=16):
    """Extract 32-bit words from a big integer (little-endian order)."""
    words = []
    for i in range(num_words):
        words.append((n >> (32 * i)) & 0xFFFFFFFF)
    return words


def combine_32bit_words(words):
    """Combine 32-bit words into a big integer (little-endian order)."""
    result = 0
    for i, w in enumerate(words):
        result |= (w & 0xFFFFFFFF) << (32 * i)
    return result


def current_implementation_reduction(c):
    """
    Current implementation (WRONG) - from fe256_p256.cpp.
    
    Uses formula: T = base + 2*s1 + 2*s2 + s3 + s4 - s5 - s6 - s7 - s8
    Where the s_i are defined as in the current code.
    """
    # t[0..7] holds 32-bit words, where t[i] is at position i
    t = [0] * 8
    
    # Base value: c = (c7, c6, c5, c4, c3, c2, c1, c0)
    for i in range(8):
        t[i] = c[i]
    
    # 2*s1 = 2 * (c15, c14, c13, c12, c11, 0, 0, 0)
    t[3] += 2 * c[11]
    t[4] += 2 * c[12]
    t[5] += 2 * c[13]
    t[6] += 2 * c[14]
    t[7] += 2 * c[15]
    
    # 2*s2 = 2 * (0, c15, c14, c13, c12, 0, 0, 0)
    t[3] += 2 * c[12]
    t[4] += 2 * c[13]
    t[5] += 2 * c[14]
    t[6] += 2 * c[15]
    
    # s3 = (c15, c14, 0, 0, 0, c10, c9, c8)
    t[0] += c[8]
    t[1] += c[9]
    t[2] += c[10]
    t[6] += c[14]
    t[7] += c[15]
    
    # s4 = (c8, c13, c15, c14, c13, c11, c10, c9)
    t[0] += c[9]
    t[1] += c[10]
    t[2] += c[11]
    t[3] += c[13]
    t[4] += c[14]
    t[5] += c[15]
    t[6] += c[13]
    t[7] += c[8]
    
    # -s5 = -(c10, c8, 0, 0, 0, c13, c12, c11)
    t[0] -= c[11]
    t[1] -= c[12]
    t[2] -= c[13]
    t[6] -= c[8]
    t[7] -= c[10]
    
    # -s6 = -(c11, c9, 0, 0, c15, c14, c13, c12)
    t[0] -= c[12]
    t[1] -= c[13]
    t[2] -= c[14]
    t[3] -= c[15]
    t[6] -= c[9]
    t[7] -= c[11]
    
    # -s7 = -(c12, 0, c10, c9, c8, c15, c14, c13)
    t[0] -= c[13]
    t[1] -= c[14]
    t[2] -= c[15]
    t[3] -= c[8]
    t[4] -= c[9]
    t[5] -= c[10]
    t[7] -= c[12]
    
    # -s8 = -(c13, 0, c11, c10, c9, 0, c15, c14)
    t[0] -= c[14]
    t[1] -= c[15]
    t[3] -= c[9]
    t[4] -= c[10]
    t[5] -= c[11]
    t[7] -= c[13]
    
    # Carry propagation
    carry = 0
    for i in range(8):
        t[i] += carry
        carry = t[i] >> 32
        t[i] &= 0xFFFFFFFF
    
    # Convert to integer and reduce mod p
    result = combine_32bit_words(t[:8])
    
    # Handle carry
    while carry > 0:
        result -= P256_P
        carry -= 1
    while carry < 0:
        result += P256_P
        carry += 1
    
    # Final reduction
    result %= P256_P
    return result


def nist_fips_reduction_v1(c):
    """
    NIST FIPS 186-4 Appendix D.2.3 formula - Version 1.
    
    From IACR eprint 2015/1225 "ECC on Your Fingertips":
    T  = (C7||C6||C5||C4||C3||C2||C1||C0)
    S1 = (C15||C14||C13||C12||C11||0||0||0)
    S2 = (0||C15||C14||C13||C12||0||0||0)
    S3 = (C15||C14||0||0||0||C10||C9||C8)
    S4 = (C8||C13||C15||C14||C13||C11||C10||C9)
    D1 = (C10||C8||0||0||0||C13||C12||C11)
    D2 = (C11||C9||0||0||C15||C14||C13||C12)
    D3 = (C12||0||C10||C9||C8||C15||C14||C13)
    D4 = (C13||0||C11||C10||C9||0||C15||C14)
    
    P = T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4 (mod P-256)
    
    NOTE: (A7||A6||A5||A4||A3||A2||A1||A0) means A7 is the HIGH 32-bit word!
    So the representation is BIG-ENDIAN conceptually.
    """
    # Build integers directly from the formula using big-endian interpretation
    # (C7||C6||C5||C4||C3||C2||C1||C0) means: result = c7*2^224 + c6*2^192 + ... + c0
    
    def make_256(a7, a6, a5, a4, a3, a2, a1, a0):
        return (a7 << 224) | (a6 << 192) | (a5 << 160) | (a4 << 128) | \
               (a3 << 96) | (a2 << 64) | (a1 << 32) | a0
    
    T = make_256(c[7], c[6], c[5], c[4], c[3], c[2], c[1], c[0])
    S1 = make_256(c[15], c[14], c[13], c[12], c[11], 0, 0, 0)
    S2 = make_256(0, c[15], c[14], c[13], c[12], 0, 0, 0)
    S3 = make_256(c[15], c[14], 0, 0, 0, c[10], c[9], c[8])
    S4 = make_256(c[8], c[13], c[15], c[14], c[13], c[11], c[10], c[9])
    D1 = make_256(c[10], c[8], 0, 0, 0, c[13], c[12], c[11])
    D2 = make_256(c[11], c[9], 0, 0, c[15], c[14], c[13], c[12])
    D3 = make_256(c[12], 0, c[10], c[9], c[8], c[15], c[14], c[13])
    D4 = make_256(c[13], 0, c[11], c[10], c[9], 0, c[15], c[14])
    
    result = T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4
    
    # Reduce mod p
    result %= P256_P
    return result


def nist_fips_reduction_v2(c):
    """
    Corrected NIST formula - matching the new C implementation.
    
    Maps NIST big-endian notation to our little-endian t[] array:
    (A7||A6||A5||A4||A3||A2||A1||A0) where A7 is at bits 224-255
    maps to t[7]=A7, t[6]=A6, ..., t[0]=A0
    """
    t = [0] * 8
    
    # T = (c7, c6, c5, c4, c3, c2, c1, c0)
    for i in range(8):
        t[i] = c[i]
    
    # 2*S1 = 2 * (c15, c14, c13, c12, c11, 0, 0, 0)
    # Position: c15->t[7], c14->t[6], c13->t[5], c12->t[4], c11->t[3]
    t[7] += 2 * c[15]
    t[6] += 2 * c[14]
    t[5] += 2 * c[13]
    t[4] += 2 * c[12]
    t[3] += 2 * c[11]
    
    # 2*S2 = 2 * (0, c15, c14, c13, c12, 0, 0, 0)
    # Position: c15->t[6], c14->t[5], c13->t[4], c12->t[3]
    t[6] += 2 * c[15]
    t[5] += 2 * c[14]
    t[4] += 2 * c[13]
    t[3] += 2 * c[12]
    
    # S3 = (c15, c14, 0, 0, 0, c10, c9, c8)
    # Position: c15->t[7], c14->t[6], c10->t[2], c9->t[1], c8->t[0]
    t[7] += c[15]
    t[6] += c[14]
    t[2] += c[10]
    t[1] += c[9]
    t[0] += c[8]
    
    # S4 = (c8, c13, c15, c14, c13, c11, c10, c9)
    # Position: c8->t[7], c13->t[6], c15->t[5], c14->t[4], c13->t[3], c11->t[2], c10->t[1], c9->t[0]
    t[7] += c[8]
    t[6] += c[13]
    t[5] += c[15]
    t[4] += c[14]
    t[3] += c[13]
    t[2] += c[11]
    t[1] += c[10]
    t[0] += c[9]
    
    # -D1 = -(c10, c8, 0, 0, 0, c13, c12, c11)
    # Position: c10->t[7], c8->t[6], c13->t[2], c12->t[1], c11->t[0]
    t[7] -= c[10]
    t[6] -= c[8]
    t[2] -= c[13]
    t[1] -= c[12]
    t[0] -= c[11]
    
    # -D2 = -(c11, c9, 0, 0, c15, c14, c13, c12)
    # Position: c11->t[7], c9->t[6], c15->t[3], c14->t[2], c13->t[1], c12->t[0]
    t[7] -= c[11]
    t[6] -= c[9]
    t[3] -= c[15]
    t[2] -= c[14]
    t[1] -= c[13]
    t[0] -= c[12]
    
    # -D3 = -(c12, 0, c10, c9, c8, c15, c14, c13)
    # Position: c12->t[7], c10->t[5], c9->t[4], c8->t[3], c15->t[2], c14->t[1], c13->t[0]
    t[7] -= c[12]
    t[5] -= c[10]
    t[4] -= c[9]
    t[3] -= c[8]
    t[2] -= c[15]
    t[1] -= c[14]
    t[0] -= c[13]
    
    # -D4 = -(c13, 0, c11, c10, c9, 0, c15, c14)
    # Position: c13->t[7], c11->t[5], c10->t[4], c9->t[3], c15->t[1], c14->t[0]
    t[7] -= c[13]
    t[5] -= c[11]
    t[4] -= c[10]
    t[3] -= c[9]
    t[1] -= c[15]
    t[0] -= c[14]
    
    # Debug: print intermediate values before carry
    print(f"  Before carry: t = {[hex(x & 0xFFFFFFFFFFFFFFFF) for x in t]}")
    
    # Carry propagation with signed values
    # The issue is Python's >> on negative numbers gives floor division
    # We need to simulate C's arithmetic right shift behavior
    carry = 0
    for i in range(8):
        t[i] += carry
        # Python's >> on negative gives floor division, which is correct for signed
        if t[i] >= 0:
            carry = t[i] >> 32
        else:
            # For negative, simulate arithmetic right shift
            carry = -(((-t[i]) + 0xFFFFFFFF) >> 32)
        t[i] &= 0xFFFFFFFF
    
    print(f"  After carry: t = {[hex(x) for x in t]}, final carry = {carry}")
    
    # Convert to integer
    result = combine_32bit_words(t[:8])
    
    # Handle carry
    while carry > 0:
        result -= P256_P
        carry -= 1
    while carry < 0:
        result += P256_P
        carry += 1
    
    # Final reduction
    result %= P256_P
    return result


def direct_reduction(value):
    """Direct modular reduction using Python's native mod."""
    return value % P256_P


def test_reduction():
    """Test reduction algorithms with known test vectors."""
    print("=" * 80)
    print("P-256 Solinas Reduction Verification")
    print("=" * 80)
    print(f"\nP-256 Prime: 0x{P256_P:064x}")
    print()
    
    # Test case from debugging: a = 0xffff8b3a00009f6f000061970000bec60000c8f0ffffd82bffff83b27fff5897
    a = 0xffff8b3a00009f6f000061970000bec60000c8f0ffffd82bffff83b27fff5897
    
    # a^2 (512-bit wide multiplication result from the C code)
    a_squared = 0xffff1674354548016e8d8b7a0a44c218cb853a8c5b819e52b0117be8672782ab0b04faea33122d7488936116498c53381fde39aa70726f5ee29314936d7a2911
    
    print(f"Test input a: 0x{a:064x}")
    print(f"a^2 (512-bit): 0x{a_squared:0128x}")
    print()
    
    # Expected result from Python (correct)
    expected = direct_reduction(a_squared)
    print(f"Expected (a^2 mod p): 0x{expected:064x}")
    print()
    
    # Extract 32-bit words from a_squared
    c = extract_32bit_words(a_squared, 16)
    print("32-bit words c[0..15]:")
    for i in range(16):
        print(f"  c[{i:2d}] = 0x{c[i]:08x}")
    print()
    
    # Test each implementation
    print("-" * 80)
    print("Testing implementations:")
    print("-" * 80)
    
    # Method 1: Current implementation (from C code)
    result1 = current_implementation_reduction(c)
    match1 = "✓" if result1 == expected else "✗"
    print(f"[{match1}] Current C implementation: 0x{result1:064x}")
    if result1 != expected:
        diff = expected - result1
        print(f"    Difference: {diff} (0x{diff & ((1 << 256) - 1):064x})")
    
    # Method 2: NIST FIPS 186-4 formula (big-endian interpretation)
    result2 = nist_fips_reduction_v1(c)
    match2 = "✓" if result2 == expected else "✗"
    print(f"[{match2}] NIST FIPS v1 (big-endian): 0x{result2:064x}")
    if result2 != expected:
        diff = expected - result2
        print(f"    Difference: {diff} (0x{diff & ((1 << 256) - 1):064x})")
    
    # Method 3: Little-endian interpretation
    result3 = nist_fips_reduction_v2(c)
    match3 = "✓" if result3 == expected else "✗"
    print(f"[{match3}] NIST FIPS v2 (little-endian): 0x{result3:064x}")
    if result3 != expected:
        diff = expected - result3
        print(f"    Difference: {diff} (0x{diff & ((1 << 256) - 1):064x})")
    
    print()
    print("=" * 80)
    
    # Additional test cases
    print("\nAdditional test cases:")
    print("-" * 80)
    
    # Test with simple values
    test_cases = [
        (2, "2^2 = 4"),
        (3, "3^2 = 9"),
        (1 << 128, "(2^128)^2"),
        (P256_P - 1, "(p-1)^2"),
    ]
    
    for value, desc in test_cases:
        squared = value * value
        expected = squared % P256_P
        c = extract_32bit_words(squared, 16)
        
        r1 = current_implementation_reduction(c)
        r2 = nist_fips_reduction_v1(c)
        r3 = nist_fips_reduction_v2(c)
        
        m1 = "✓" if r1 == expected else "✗"
        m2 = "✓" if r2 == expected else "✗"
        m3 = "✓" if r3 == expected else "✗"
        
        print(f"\n{desc}:")
        print(f"  Expected: 0x{expected:064x}")
        print(f"  [{m1}] Current:     0x{r1:064x}")
        print(f"  [{m2}] NIST v1:     0x{r2:064x}")
        print(f"  [{m3}] NIST v2:     0x{r3:064x}")
    
    print()
    print("=" * 80)
    print("Summary:")
    print("-" * 80)
    print("If NIST FIPS v1 (big-endian) passes all tests, use that formula.")
    print("The key insight is that NIST notation (C7||C6||...||C0) is big-endian,")
    print("meaning C7 is at bit position 224-255 (the highest 32 bits).")
    print("=" * 80)


if __name__ == "__main__":
    test_reduction()
