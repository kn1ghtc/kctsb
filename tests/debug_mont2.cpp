/**
 * @brief Debug Montgomery operations for fe256 - minimal test
 */
#include <cstdint>
#include <cstdio>
#include <cstring>

struct Fe256 { uint64_t limb[4]; };
struct Fe512 { uint64_t limb[8]; };

static const Fe256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
static const Fe256 SECP256K1_R2 = {{
    0x000007a2000e90a1ULL, 0x0000000000000001ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL
}};
static const uint64_t SECP256K1_N0 = 0xD838091DD2253531ULL;

using uint128_t = unsigned __int128;

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t r = (uint128_t)a * b;
    *lo = (uint64_t)r;
    *hi = (uint64_t)(r >> 64);
}

static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t bin, uint64_t* bout) {
    uint128_t r = (uint128_t)a - b - bin;
    *bout = (r >> 64) ? 1 : 0;
    return (uint64_t)r;
}

static void fe256_mul_wide(Fe512* r, const Fe256* a, const Fe256* b) {
    uint128_t accum = 0;
    for (int k = 0; k < 8; ++k) {
        for (int i = (k < 4 ? 0 : k - 3); i <= (k < 4 ? k : 3); ++i) {
            int j = k - i;
            accum += (uint128_t)a->limb[i] * b->limb[j];
        }
        r->limb[k] = (uint64_t)accum;
        accum >>= 64;
    }
}

static void fe256_montgomery_reduce(Fe256* result, const Fe512* t, const Fe256* p, uint64_t n0) {
    uint64_t tmp[9];
    for (int i = 0; i < 8; ++i) tmp[i] = t->limb[i];
    tmp[8] = 0;
    
    for (int i = 0; i < 4; ++i) {
        uint64_t u = tmp[i] * n0;
        uint64_t carry = 0;
        
        for (int j = 0; j < 4; ++j) {
            uint64_t hi, lo;
            mul64x64(u, p->limb[j], &hi, &lo);
            uint128_t sum = (uint128_t)tmp[i + j] + lo + carry;
            tmp[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64) + hi;
        }
        
        for (int j = 4; i + j < 9; ++j) {
            uint128_t sum = (uint128_t)tmp[i + j] + carry;
            tmp[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
            if (carry == 0) break;
        }
    }
    
    printf("After reduction loop:\n");
    for (int i = 4; i < 9; i++) {
        printf("  tmp[%d] = 0x%016llx\n", i, (unsigned long long)tmp[i]);
    }
    
    result->limb[0] = tmp[4];
    result->limb[1] = tmp[5];
    result->limb[2] = tmp[6];
    result->limb[3] = tmp[7];
    
    if (tmp[8] != 0) {
        printf("OVERFLOW! tmp[8] = 0x%llx\n", (unsigned long long)tmp[8]);
        const uint64_t c = 0x1000003d1ULL;
        uint64_t carry = 0;
        uint128_t sum = (uint128_t)result->limb[0] + tmp[8] * c;
        result->limb[0] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        
        for (int i = 1; i < 4 && carry; ++i) {
            sum = (uint128_t)result->limb[i] + carry;
            result->limb[i] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }
    } else {
        printf("No overflow (tmp[8] = 0)\n");
    }
    
    // Final reduction
    uint64_t borrow = 0;
    Fe256 reduced;
    reduced.limb[0] = sbb64(result->limb[0], p->limb[0], 0, &borrow);
    reduced.limb[1] = sbb64(result->limb[1], p->limb[1], borrow, &borrow);
    reduced.limb[2] = sbb64(result->limb[2], p->limb[2], borrow, &borrow);
    reduced.limb[3] = sbb64(result->limb[3], p->limb[3], borrow, &borrow);
    if (borrow == 0) *result = reduced;
}

static void fe256_mul_mont(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_montgomery_reduce(r, &wide, &SECP256K1_P, SECP256K1_N0);
}

int main() {
    Fe256 G_x = {{
        0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
        0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
    }};
    
    printf("G.x = 0x%016llx%016llx%016llx%016llx\n",
           (unsigned long long)G_x.limb[3], (unsigned long long)G_x.limb[2],
           (unsigned long long)G_x.limb[1], (unsigned long long)G_x.limb[0]);
    
    // Convert to Montgomery
    Fe256 X_mont;
    printf("\n--- to_mont ---\n");
    fe256_mul_mont(&X_mont, &G_x, &SECP256K1_R2);
    printf("X_mont = 0x%016llx%016llx%016llx%016llx\n",
           (unsigned long long)X_mont.limb[3], (unsigned long long)X_mont.limb[2],
           (unsigned long long)X_mont.limb[1], (unsigned long long)X_mont.limb[0]);
    
    // Square
    Fe256 A;
    printf("\n--- square ---\n");
    fe256_mul_mont(&A, &X_mont, &X_mont);
    printf("A = X^2 = 0x%016llx%016llx%016llx%016llx\n",
           (unsigned long long)A.limb[3], (unsigned long long)A.limb[2],
           (unsigned long long)A.limb[1], (unsigned long long)A.limb[0]);
    
    printf("\nExpected: 0x02c1ac53e90530f1f2457dd8d5ccc625a561deaaa7b691ae2293294d46232198\n");
    
    Fe256 expected = {{0x2293294d46232198ULL, 0xa561deaaa7b691aeULL,
                       0xf2457dd8d5ccc625ULL, 0x02c1ac53e90530f1ULL}};
    bool ok = memcmp(&A, &expected, sizeof(Fe256)) == 0;
    printf("Match: %s\n", ok ? "YES" : "NO");
    
    return ok ? 0 : 1;
}
