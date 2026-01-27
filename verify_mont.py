"""
Montgomery reduction verification for secp256k1
"""

def mont_reduce_v2(t_512bit, p, n0, R_bits=256, debug=False):
    """
    Montgomery reduction with extended working space
    Handles overflow correctly
    """
    # Convert to 9 limbs (64-bit each) - extra limb for overflow
    t = []
    val = t_512bit
    for _ in range(8):
        t.append(val & ((1 << 64) - 1))
        val >>= 64
    t.append(0)  # Extra limb for overflow
    
    if debug:
        print(f"Initial t: {[hex(x) for x in t]}")
    
    mask64 = (1 << 64) - 1
    
    for i in range(4):
        m = (t[i] * n0) & mask64
        if debug:
            print(f"  i={i}, t[{i}]={hex(t[i])}, m={hex(m)}")
        
        carry = 0
        for j in range(4):
            p_limb = (p >> (64 * j)) & mask64
            prod = m * p_limb + t[i + j] + carry
            t[i + j] = prod & mask64
            carry = prod >> 64
        
        # Propagate carry through ALL remaining limbs (not just to 8)
        for k in range(i + 4, 9):
            if carry == 0:
                break
            sum_val = t[k] + carry
            t[k] = sum_val & mask64
            carry = sum_val >> 64
            
        if debug:
            print(f"  After iteration {i}: t[4:9] = {[hex(x) for x in t[4:]]}")
    
    # Result is in limbs 4-8
    # If there's overflow in limb 8, we need to handle it
    result = t[4] | (t[5] << 64) | (t[6] << 128) | (t[7] << 192)
    
    # Handle overflow in limb 8: add t[8] * 2^256 mod p back
    # For secp256k1: 2^256 ≡ 2^32 + 977 (mod p)
    # So t[8] * 2^256 ≡ t[8] * (2^32 + 977) (mod p)
    if t[8] > 0:
        if debug:
            print(f"Handling overflow in limb 8: {hex(t[8])}")
        # Add t[8] * (2^32 + 977) to result
        # secp256k1 reduction constant: c = 2^32 + 977 = 0x1000003d1
        c = 0x1000003d1
        result += t[8] * c
        # May need reduction
        while result >= p:
            result -= p
    
    if debug:
        print(f"Result after overflow handling: {hex(result)}")
    
    # Conditional subtraction (may already be done above)
    if result >= p:
        result -= p
        if debug:
            print(f"After subtracting p: {hex(result)}")
    
    return result


def mont_reduce_correct(t_512bit, p, n0):
    """
    Correct Montgomery reduction using modular arithmetic
    mont_reduce(t) = t * R^(-1) mod p
    """
    R = 1 << 256
    R_inv = pow(R, -1, p)  # R^(-1) mod p
    return (t_512bit * R_inv) % p


# secp256k1 parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n0 = 0xD838091DD2253531
R = 1 << 256
R2 = (R * R) % p

gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

print("=== Testing mont_reduce correctness ===\n")

# Test 1: Simple case - mont_reduce(x) should give x * R^(-1) mod p
test_val = gx
expected = mont_reduce_correct(test_val, p, n0)
got = mont_reduce_v2(test_val, p, n0, debug=False)
print(f"mont_reduce({hex(test_val)[:20]}...)")
print(f"  Expected: {hex(expected)}")
print(f"  Got:      {hex(got)}")
print(f"  Match: {expected == got}")

# Test 2: gx^2 in Montgomery form pipeline
print("\n=== Full pipeline debug ===")
gx_mont = (gx * R) % p  # Correct Montgomery form
print(f"gx_mont (correct) = {hex(gx_mont)}")

gx_squared_mont_wide = gx_mont * gx_mont
print(f"gx_mont^2 (512-bit) = {hex(gx_squared_mont_wide)}")

# Apply mont_reduce to get gx^2 * R mod p
gx_squared_mont = mont_reduce_v2(gx_squared_mont_wide, p, n0, debug=True)
print(f"mont_reduce result = {hex(gx_squared_mont)}")

# Expected: (gx^2 * R) mod p
gx_squared_mont_expected = ((gx * gx) * R) % p
print(f"Expected (gx^2 * R) mod p = {hex(gx_squared_mont_expected)}")

# Try correct method
gx_squared_mont_correct = mont_reduce_correct(gx_squared_mont_wide, p, n0)
print(f"Correct mont_reduce = {hex(gx_squared_mont_correct)}")
print(f"Difference: {gx_squared_mont_expected - gx_squared_mont_correct}")
