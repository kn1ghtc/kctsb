#include <cstdint>
#include <cstdio>

using uint128_t = unsigned __int128;

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t r = (uint128_t)a * b;
    *lo = (uint64_t)r;
    *hi = (uint64_t)(r >> 64);
}

int main() {
    // Test values from iteration 3, j=1
    uint64_t u = 0xa6b5252cdce9ef1dULL;
    uint64_t p_j = 0xFFFFFFFFFFFFFFFFULL;  // p[1]
    uint64_t tmp_ij = 0x2293294cecd84570ULL;  // tmp[4] before this j
    uint64_t carry_in = 0xa6b5252c3634c774ULL;  // carry from j=0
    
    // Method 1: debug_mont3 approach
    uint64_t hi1, lo1;
    mul64x64(u, p_j, &hi1, &lo1);
    uint128_t sum1 = (uint128_t)tmp_ij + lo1 + carry_in;
    uint64_t result1 = (uint64_t)sum1;
    uint64_t carry1 = (uint64_t)(sum1 >> 64) + hi1;
    
    // Method 2: ecc_curve.cpp approach  
    uint128_t prod2 = (uint128_t)u * p_j;
    uint128_t sum2 = prod2 + tmp_ij + carry_in;
    uint64_t result2 = (uint64_t)sum2;
    uint64_t carry2 = (uint64_t)(sum2 >> 64);
    
    printf("u     = 0x%016llx\n", (unsigned long long)u);
    printf("p[j]  = 0x%016llx\n", (unsigned long long)p_j);
    printf("tmp   = 0x%016llx\n", (unsigned long long)tmp_ij);
    printf("carry = 0x%016llx\n\n", (unsigned long long)carry_in);
    
    printf("Method 1 (debug): hi=0x%llx, lo=0x%llx\n", (unsigned long long)hi1, (unsigned long long)lo1);
    printf("  result = 0x%016llx, carry_out = 0x%016llx\n", (unsigned long long)result1, (unsigned long long)carry1);
    
    printf("\nMethod 2 (ecc_curve): prod=0x%llx%016llx\n", 
           (unsigned long long)(prod2 >> 64), (unsigned long long)prod2);
    printf("  result = 0x%016llx, carry_out = 0x%016llx\n", (unsigned long long)result2, (unsigned long long)carry2);
    
    printf("\nDiff result: %lld, Diff carry: %lld\n", 
           (long long)(result1 - result2), (long long)(carry1 - carry2));
    
    return 0;
}
