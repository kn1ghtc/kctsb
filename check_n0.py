# secp256k1 verification
p_k1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n0_k1 = pow(-p_k1, -1, 2**64)
print("=== secp256k1 ===")
print("n0 calculated:", hex(n0_k1))
print("n0 in code:    0xd838091dd2253531")
print("match:", n0_k1 == 0xD838091DD2253531)

R = 2**256
R2_k1 = (R * R) % p_k1
print("\nsecp256k1 R^2 mod p:", hex(R2_k1))
limbs_k1 = []
val = R2_k1
for i in range(4):
    limbs_k1.append(val & 0xFFFFFFFFFFFFFFFF)
    val >>= 64
print("Calculated limbs:", [hex(l) for l in limbs_k1])
code_R2_k1 = [0x000007a2000e90a1, 0x0000000000000001, 0x0, 0x0]
print("Code limbs:      ", [hex(l) for l in code_R2_k1])
print("Match:", limbs_k1 == code_R2_k1)

# P-256 verification
p_256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
n0_256 = pow(-p_256, -1, 2**64)
print("\n=== P-256 ===")
print("n0 calculated:", hex(n0_256))

R2_256 = (R * R) % p_256
print("P-256 R^2 mod p:", hex(R2_256))
limbs_256 = []
val = R2_256
for i in range(4):
    limbs_256.append(val & 0xFFFFFFFFFFFFFFFF)
    val >>= 64
print("Calculated limbs:", [hex(l) for l in limbs_256])

# THIS IS THE ACTUAL CODE VALUE (from line 283-286):
code_R2_256 = [0x0000000000000003, 0xFFFFFFFBFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0x00000004FFFFFFFD]
print("Code limbs:      ", [hex(l) for l in code_R2_256])
print("Match:", limbs_256 == code_R2_256)
