/**
 * @brief Detailed trace of Montgomery reduction
 */
#include <cstdint>
#include <cstdio>

struct Fe256 { uint64_t limb[4]; };
struct Fe512 { uint64_t limb[8]; };

static const Fe256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
static const uint64_t SECP256K1_N0 = 0xD838091DD2253531ULL;

using uint128_t = unsigned __int128;

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t r = (uint128_t)a * b;
    *lo = (uint64_t)r;
    *hi = (uint64_t)(r >> 64);
}

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
    
    printf("Initial tmp[0:8]:\n");
    for (int i = 0; i < 8; i++) {
        printf("  tmp[%d] = 0x%016llx\n", i, (unsigned long long)tmp[i]);
    }
    
    for (int it = 0; it < 4; ++it) {
        uint64_t u = tmp[it] * n0;
        printf("\nIteration %d: u = 0x%016llx\n", it, (unsigned long long)u);
        
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t hi, lo;
            mul64x64(u, p_limbs[j], &hi, &lo);
            uint128_t sum = (uint128_t)tmp[it + j] + lo + carry;
            tmp[it + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64) + hi;
            printf("  j=%d: product=0x%016llx%016llx, tmp[%d]=0x%016llx, carry=0x%llx\n",
                   j, (unsigned long long)hi, (unsigned long long)lo,
                   it+j, (unsigned long long)tmp[it+j], (unsigned long long)carry);
        }
        
        // Propagate carry
        for (int j = 4; it + j < 9; ++j) {
            uint128_t sum = (uint128_t)tmp[it + j] + carry;
            tmp[it + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
            printf("  propagate j=%d: tmp[%d]=0x%016llx, carry=0x%llx\n",
                   j, it+j, (unsigned long long)tmp[it+j], (unsigned long long)carry);
            if (carry == 0) break;
        }
    }
    
    printf("\nFinal tmp[4:9]:\n");
    for (int i = 4; i < 9; i++) {
        printf("  tmp[%d] = 0x%016llx\n", i, (unsigned long long)tmp[i]);
    }
    
    printf("\nExpected tmp[4] = 0x2293294c46231dc7\n");
    printf("Got      tmp[4] = 0x%016llx\n", (unsigned long long)tmp[4]);
    printf("Diff = %lld\n", (long long)(0x2293294c46231dc7ULL - tmp[4]));
    
    return 0;
}
