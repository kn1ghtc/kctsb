/**
 * @brief Test using EXACT ecc_curve.cpp logic
 */
#include <cstdint>
#include <cstdio>

using uint128_t = unsigned __int128;

int main() {
    // X_mont^2 wide product (from Python)
    uint64_t tmp[9] = {
        0xc2a05ea508ca1911ULL,
        0x6dffad2a01cb1831ULL,
        0x7544cf78c6e0c6faULL,
        0x163ccf5471cf56aeULL,
        0xb1ba6331d583f42fULL,
        0x41a8a1f0cfa7a5c5ULL,
        0x993fb62b1f9704a1ULL,
        0x5c0c87270c1b41d4ULL,
        0x0000000000000000ULL
    };
    
    uint64_t p_limbs[4] = {
        0xFFFFFFFEFFFFFC2FULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL
    };
    uint64_t n0 = 0xD838091DD2253531ULL;
    
    printf("Using EXACT ecc_curve.cpp logic:\n\n");
    
    for (int i = 0; i < 4; i++) {
        uint64_t m = tmp[i] * n0;
        printf("Iteration %d: m = 0x%016llx\n", i, (unsigned long long)m);
        uint64_t carry = 0;

        for (int j = 0; j < 4; j++) {
            uint128_t prod = (uint128_t)m * p_limbs[j];
            uint128_t sum = prod + tmp[i + j] + carry;
            tmp[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
            printf("  j=%d: tmp[%d]=0x%016llx, carry=0x%016llx\n",
                   j, i+j, (unsigned long long)tmp[i+j], (unsigned long long)carry);
        }

        // Propagate carry to tmp[i+4] and beyond
        uint128_t sum = (uint128_t)tmp[i + 4] + carry;
        tmp[i + 4] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        printf("  propagate to tmp[%d]=0x%016llx, carry=0x%016llx\n",
               i+4, (unsigned long long)tmp[i+4], (unsigned long long)carry);

        // Continue propagating through remaining limbs
        for (int k = i + 5; k <= 8 && carry != 0; k++) {
            sum = (uint128_t)tmp[k] + carry;
            tmp[k] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
            printf("  propagate to tmp[%d]=0x%016llx, carry=0x%016llx\n",
                   k, (unsigned long long)tmp[k], (unsigned long long)carry);
        }
    }
    
    printf("\nFinal result:\n");
    printf("  tmp[4] = 0x%016llx\n", (unsigned long long)tmp[4]);
    printf("  tmp[5] = 0x%016llx\n", (unsigned long long)tmp[5]);
    printf("  tmp[6] = 0x%016llx\n", (unsigned long long)tmp[6]);
    printf("  tmp[7] = 0x%016llx\n", (unsigned long long)tmp[7]);
    printf("  tmp[8] = 0x%016llx\n", (unsigned long long)tmp[8]);
    
    printf("\nExpected tmp[4] = 0x2293294c46231dc7\n");
    printf("Got      tmp[4] = 0x%016llx\n", (unsigned long long)tmp[4]);
    if (tmp[4] == 0x2293294c46231dc7ULL) {
        printf("MATCH!\n");
    } else {
        printf("MISMATCH! Diff = %lld\n", (long long)(0x2293294c46231dc7ULL - tmp[4]));
    }
    
    return 0;
}
