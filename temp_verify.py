#!/usr/bin/env python3
"""Verify Montgomery constants for secp256k1"""

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
R = 2**256

print("secp256k1 Montgomery constants verification:")
print(f"p = 0x{p:064x}")
print(f"R = 2^256")
print(f"R mod p = 0x{R % p:064x}")
print(f"  = {R % p}")

R2_mod_p = (R * R) % p
print(f"\nR^2 mod p = 0x{R2_mod_p:064x}")
print(f"  limb[0] = 0x{R2_mod_p & 0xFFFFFFFFFFFFFFFF:016x}")
print(f"  limb[1] = 0x{(R2_mod_p >> 64) & 0xFFFFFFFFFFFFFFFF:016x}")
print(f"  limb[2] = 0x{(R2_mod_p >> 128) & 0xFFFFFFFFFFFFFFFF:016x}")
print(f"  limb[3] = 0x{(R2_mod_p >> 192) & 0xFFFFFFFFFFFFFFFF:016x}")

n0 = (-pow(p, -1, 2**64)) % (2**64)
print(f"\nn0 = -p^(-1) mod 2^64 = 0x{n0:016x}")

# Expected values from code (after fix):
expected_r2_limb0 = 0x000007a2000e90a1
expected_r2_limb1 = 0x0000000000000001
expected_n0 = 0xD838091DD2253531

print(f"\nExpected R^2 limb[0] = 0x{expected_r2_limb0:016x}")
print(f"Expected R^2 limb[1] = 0x{expected_r2_limb1:016x}")
print(f"Expected n0 = 0x{expected_n0:016x}")

print(f"\nMatches: R2_limb0={expected_r2_limb0 == (R2_mod_p & 0xFFFFFFFFFFFFFFFF)}, R2_limb1={expected_r2_limb1 == ((R2_mod_p >> 64) & 0xFFFFFFFFFFFFFFFF)}, n0={expected_n0 == n0}")
