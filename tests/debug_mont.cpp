/**
 * @brief Debug Montgomery operations and point doubling for fe256
 * Compile: g++ -std=c++17 -O0 -g debug_mont.cpp -o debug_mont
 */
#include <cstdint>
#include <cstdio>
#include <cstring>

// Fe256 structure
struct Fe256 {
    uint64_t limb[4];
};

struct Fe512 {
    uint64_t limb[8];
};

// Constants for secp256k1
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

// Basic operations
static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out) {
    uint128_t sum = (uint128_t)a + b + carry_in;
    *carry_out = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
}

static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out) {
    uint128_t full = (uint128_t)a - b - borrow_in;
    *borrow_out = (full >> 64) ? 1 : 0;
    return (uint64_t)full;
}

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t result = (uint128_t)a * b;
    *lo = (uint64_t)result;
    *hi = (uint64_t)(result >> 64);
}

// Wide multiplication
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

// Montgomery reduction
static void fe256_montgomery_reduce(Fe256* result, const Fe512* t, const Fe256* p, uint64_t n0) {
    uint64_t tmp[9];
    for (int i = 0; i < 8; ++i) tmp[i] = t->limb[i];
    tmp[8] = 0;
    
    printf("Initial tmp:\n");
    for (int i = 0; i < 9; i++) {
        printf("  tmp[%d] = 0x%016llx\n", i, (unsigned long long)tmp[i]);
    }
    
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
        
        printf("After iteration %d, tmp[4:9] = [", i);
        for (int k = 4; k < 9; k++) {
            printf("0x%016llx%s", (unsigned long long)tmp[k], k < 8 ? ", " : "]\n");
        }
    }
    
    printf("tmp[8] (overflow) = 0x%016llx\n", (unsigned long long)tmp[8]);
    
    result->limb[0] = tmp[4];
    result->limb[1] = tmp[5];
    result->limb[2] = tmp[6];
    result->limb[3] = tmp[7];
    
    // Handle overflow
    if (tmp[8] != 0) {
        printf("OVERFLOW DETECTED! Adding 0x%llx * 0x1000003d1\n", (unsigned long long)tmp[8]);
        const uint64_t c = 0x1000003d1ULL;
        uint64_t carry = 0;
        uint128_t sum = (uint128_t)result->limb[0] + tmp[8] * c;
        result->limb[0] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        
        sum = (uint128_t)result->limb[1] + carry;
        result->limb[1] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        
        sum = (uint128_t)result->limb[2] + carry;
        result->limb[2] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        
        sum = (uint128_t)result->limb[3] + carry;
        result->limb[3] = (uint64_t)sum;
        
        print_fe256("After overflow fix", result);
    } else {
        printf("No overflow detected\n");
    }
    
    // Final reduction if result >= p
    uint64_t borrow = 0;
    Fe256 reduced;
    reduced.limb[0] = sbb64(result->limb[0], p->limb[0], 0, &borrow);
    reduced.limb[1] = sbb64(result->limb[1], p->limb[1], borrow, &borrow);
    reduced.limb[2] = sbb64(result->limb[2], p->limb[2], borrow, &borrow);
    reduced.limb[3] = sbb64(result->limb[3], p->limb[3], borrow, &borrow);
    
    if (borrow == 0) {
        printf("Final reduction applied\n");
        *result = reduced;
    }
}

static void fe256_mul_mont(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_montgomery_reduce(r, &wide, &SECP256K1_P, SECP256K1_N0);
}

static void fe256_sqr_mont(Fe256* r, const Fe256* a) {
    fe256_mul_mont(r, a, a);
}

static void fe256_add(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t carry = 0;
    uint64_t borrow = 0;
    Fe256 tmp;
    
    r->limb[0] = adc64(a->limb[0], b->limb[0], 0, &carry);
    r->limb[1] = adc64(a->limb[1], b->limb[1], carry, &carry);
    r->limb[2] = adc64(a->limb[2], b->limb[2], carry, &carry);
    r->limb[3] = adc64(a->limb[3], b->limb[3], carry, &carry);
    
    tmp.limb[0] = sbb64(r->limb[0], SECP256K1_P.limb[0], 0, &borrow);
    tmp.limb[1] = sbb64(r->limb[1], SECP256K1_P.limb[1], borrow, &borrow);
    tmp.limb[2] = sbb64(r->limb[2], SECP256K1_P.limb[2], borrow, &borrow);
    tmp.limb[3] = sbb64(r->limb[3], SECP256K1_P.limb[3], borrow, &borrow);
    
    int use_reduced = (carry || !borrow) ? 1 : 0;
    if (use_reduced) *r = tmp;
}

static void fe256_sub(Fe256* r, const Fe256* a, const Fe256* b) {
    uint64_t borrow = 0;
    
    r->limb[0] = sbb64(a->limb[0], b->limb[0], 0, &borrow);
    r->limb[1] = sbb64(a->limb[1], b->limb[1], borrow, &borrow);
    r->limb[2] = sbb64(a->limb[2], b->limb[2], borrow, &borrow);
    r->limb[3] = sbb64(a->limb[3], b->limb[3], borrow, &borrow);
    
    Fe256 tmp;
    uint64_t carry = 0;
    tmp.limb[0] = adc64(r->limb[0], SECP256K1_P.limb[0], 0, &carry);
    tmp.limb[1] = adc64(r->limb[1], SECP256K1_P.limb[1], carry, &carry);
    tmp.limb[2] = adc64(r->limb[2], SECP256K1_P.limb[2], carry, &carry);
    tmp.limb[3] = adc64(r->limb[3], SECP256K1_P.limb[3], carry, &carry);
    
    if (borrow) *r = tmp;
}

static void print_fe256(const char* name, const Fe256* a) {
    printf("%s = 0x", name);
    for (int i = 3; i >= 0; --i) {
        printf("%016llx", (unsigned long long)a->limb[i]);
    }
    printf("\n");
}

// Point structure
struct Fe256Point {
    Fe256 X, Y, Z;
    int is_infinity;
};

// Point doubling (a=0 for secp256k1)
static void point_double(Fe256Point* r, const Fe256Point* p) {
    if (p->is_infinity) {
        r->is_infinity = 1;
        return;
    }
    
    Fe256 A, B, C, D, E, F, X3, Y3, Z3;
    Fe256 tmp1, tmp2;
    
    // A = X1²
    fe256_sqr_mont(&A, &p->X);
    // B = Y1²
    fe256_sqr_mont(&B, &p->Y);
    // C = B²
    fe256_sqr_mont(&C, &B);
    // D = 2*((X1+B)² - A - C)
    fe256_add(&tmp1, &p->X, &B);
    fe256_sqr_mont(&tmp2, &tmp1);
    fe256_sub(&tmp2, &tmp2, &A);
    fe256_sub(&tmp2, &tmp2, &C);
    fe256_add(&D, &tmp2, &tmp2);
    // E = 3*A (a=0)
    fe256_add(&E, &A, &A);
    fe256_add(&E, &E, &A);
    // F = E²
    fe256_sqr_mont(&F, &E);
    // X3 = F - 2*D
    fe256_add(&tmp1, &D, &D);
    fe256_sub(&X3, &F, &tmp1);
    // Y3 = E*(D - X3) - 8*C
    fe256_sub(&tmp1, &D, &X3);
    fe256_mul_mont(&tmp2, &E, &tmp1);
    fe256_add(&tmp1, &C, &C);  // 2C
    fe256_add(&tmp1, &tmp1, &tmp1);  // 4C
    fe256_add(&tmp1, &tmp1, &tmp1);  // 8C
    fe256_sub(&Y3, &tmp2, &tmp1);
    // Z3 = 2*Y1*Z1
    fe256_mul_mont(&tmp1, &p->Y, &p->Z);
    fe256_add(&Z3, &tmp1, &tmp1);
    
    r->X = X3;
    r->Y = Y3;
    r->Z = Z3;
    r->is_infinity = 0;
}

int main() {
    // G for secp256k1 (little-endian limbs)
    Fe256 G_x = {{
        0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
        0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
    }};
    
    printf("Testing Montgomery square for secp256k1:\n\n");
    print_fe256("G.x", &G_x);
    
    // Convert to Montgomery form
    Fe256 X_mont;
    fe256_mul_mont(&X_mont, &G_x, &SECP256K1_R2);
    print_fe256("X_mont", &X_mont);
    
    // Expected from Python:
    printf("Expected: 0x9981e643e9089f48979f48c033fd129c231e295329bc66dbd7362e5a487e2097\n\n");
    
    // A = X^2 in Montgomery domain
    Fe256 A;
    fe256_sqr_mont(&A, &X_mont);
    print_fe256("A = X^2 (mont)", &A);
    printf("Expected: 0x02c1ac53e90530f1f2457dd8d5ccc625a561deaaa7b691ae2293294d46232198\n");
    
    // Check if they match
    Fe256 expected_A = {{
        0x2293294d46232198ULL, 0xa561deaaa7b691aeULL,
        0xf2457dd8d5ccc625ULL, 0x02c1ac53e90530f1ULL
    }};
    bool match = (memcmp(&A, &expected_A, sizeof(Fe256)) == 0);
    printf("\nA matches: %s\n", match ? "YES" : "NO");
    
    if (!match) {
        printf("Limbs comparison:\n");
        for (int i = 0; i < 4; i++) {
            printf("  limb[%d]: got 0x%016llx, expected 0x%016llx %s\n",
                   i, (unsigned long long)A.limb[i], (unsigned long long)expected_A.limb[i],
                   A.limb[i] == expected_A.limb[i] ? "OK" : "MISMATCH");
        }
    }
    
    return match ? 0 : 1;
}

