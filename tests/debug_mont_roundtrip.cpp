/**
 * @brief Debug test for fe256 Montgomery ladder with k=1
 */
#include <cstdint>
#include <cstdio>
#include <cstring>

using uint128_t = unsigned __int128;

struct Fe256 { 
    uint64_t limb[4]; 
    bool operator==(const Fe256& other) const {
        return limb[0] == other.limb[0] && limb[1] == other.limb[1] &&
               limb[2] == other.limb[2] && limb[3] == other.limb[3];
    }
};
struct Fe512 { uint64_t limb[8]; };

// secp256k1 parameters
static const Fe256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
static const Fe256 SECP256K1_R2 = {{
    0x000007a2000e90a1ULL, 0x0000000000000001ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL
}};
static const uint64_t SECP256K1_N0 = 0xD838091DD2253531ULL;

// Generator Gx, Gy (normal form, not Montgomery)
static const Fe256 SECP256K1_GX = {{
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
}};
static const Fe256 SECP256K1_GY = {{
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
}};

void fe256_copy(Fe256* r, const Fe256* a) {
    memcpy(r->limb, a->limb, 32);
}

void fe256_zero(Fe256* r) {
    memset(r->limb, 0, 32);
}

void fe256_one(Fe256* r) {
    r->limb[0] = 1;
    r->limb[1] = 0;
    r->limb[2] = 0;
    r->limb[3] = 0;
}

int fe256_is_zero(const Fe256* a) {
    return (a->limb[0] | a->limb[1] | a->limb[2] | a->limb[3]) == 0;
}

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t r = (uint128_t)a * b;
    *lo = (uint64_t)r;
    *hi = (uint64_t)(r >> 64);
}

void fe256_mul_wide(Fe512* r, const Fe256* a, const Fe256* b) {
    uint64_t hi, lo;
    uint64_t carry;
    
    // Schoolbook multiplication
    mul64x64(a->limb[0], b->limb[0], &hi, &lo);
    r->limb[0] = lo;
    uint64_t acc0 = hi;
    
    // Column 1
    carry = 0;
    mul64x64(a->limb[0], b->limb[1], &hi, &lo);
    acc0 += lo;
    if (acc0 < lo) carry = 1;
    uint64_t acc1 = hi + carry;
    carry = 0;
    
    mul64x64(a->limb[1], b->limb[0], &hi, &lo);
    acc0 += lo;
    if (acc0 < lo) carry = 1;
    acc1 += hi + carry;
    if (acc1 < hi + carry) carry = 1; else carry = 0;
    uint64_t acc2 = carry;
    
    r->limb[1] = acc0;
    
    // Continue with full schoolbook...
    // For brevity, use simple 128-bit approach
    uint128_t t[8] = {0};
    for (int i = 0; i < 4; i++) {
        uint128_t c = 0;
        for (int j = 0; j < 4; j++) {
            c += t[i+j] + (uint128_t)a->limb[i] * b->limb[j];
            t[i+j] = (uint64_t)c;
            c >>= 64;
        }
        t[i+4] += c;
    }
    for (int i = 0; i < 8; i++) r->limb[i] = (uint64_t)t[i];
}

void fe256_montgomery_reduce(Fe256* r, const Fe512* t, const Fe256* p, uint64_t n0) {
    uint64_t tmp[9];
    for (int i = 0; i < 8; i++) tmp[i] = t->limb[i];
    tmp[8] = 0;
    
    for (int i = 0; i < 4; i++) {
        uint64_t m = tmp[i] * n0;
        uint64_t carry = 0;
        
        for (int j = 0; j < 4; j++) {
            uint128_t prod = (uint128_t)m * p->limb[j];
            uint128_t sum = prod + tmp[i + j] + carry;
            tmp[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }
        
        uint128_t sum = (uint128_t)tmp[i + 4] + carry;
        tmp[i + 4] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        
        for (int k = i + 5; k <= 8 && carry != 0; k++) {
            sum = (uint128_t)tmp[k] + carry;
            tmp[k] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }
    }
    
    // Handle overflow
    if (tmp[8] != 0) {
        const uint64_t c = 0x1000003d1ULL;
        uint128_t sum = (uint128_t)tmp[4] + tmp[8] * c;
        r->limb[0] = (uint64_t)sum;
        uint64_t carry = (uint64_t)(sum >> 64);
        
        sum = (uint128_t)tmp[5] + carry;
        r->limb[1] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        
        sum = (uint128_t)tmp[6] + carry;
        r->limb[2] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        
        sum = (uint128_t)tmp[7] + carry;
        r->limb[3] = (uint64_t)sum;
    } else {
        r->limb[0] = tmp[4];
        r->limb[1] = tmp[5];
        r->limb[2] = tmp[6];
        r->limb[3] = tmp[7];
    }
    
    // Conditional subtraction
    uint64_t borrow = 0;
    Fe256 reduced;
    reduced.limb[0] = r->limb[0] - p->limb[0];
    borrow = (reduced.limb[0] > r->limb[0]) ? 1 : 0;
    
    uint64_t diff = r->limb[1] - p->limb[1];
    if (borrow) { diff--; if (diff == 0xFFFFFFFFFFFFFFFFULL) borrow = 1; else borrow = 0; }
    else borrow = (diff > r->limb[1]) ? 1 : 0;
    reduced.limb[1] = diff;
    
    diff = r->limb[2] - p->limb[2];
    if (borrow) { diff--; if (diff == 0xFFFFFFFFFFFFFFFFULL) borrow = 1; else borrow = 0; }
    else borrow = (diff > r->limb[2]) ? 1 : 0;
    reduced.limb[2] = diff;
    
    diff = r->limb[3] - p->limb[3];
    if (borrow) { diff--; if (diff == 0xFFFFFFFFFFFFFFFFULL) borrow = 1; else borrow = 0; }
    else borrow = (diff > r->limb[3]) ? 1 : 0;
    reduced.limb[3] = diff;
    
    if (borrow == 0) fe256_copy(r, &reduced);
}

void fe256_mul_mont(Fe256* r, const Fe256* a, const Fe256* b) {
    Fe512 wide;
    fe256_mul_wide(&wide, a, b);
    fe256_montgomery_reduce(r, &wide, &SECP256K1_P, SECP256K1_N0);
}

void fe256_to_mont(Fe256* r, const Fe256* a) {
    fe256_mul_mont(r, a, &SECP256K1_R2);
}

void fe256_from_mont(Fe256* r, const Fe256* a) {
    Fe256 one;
    fe256_one(&one);
    fe256_mul_mont(r, a, &one);
}

void print_fe256(const char* name, const Fe256* a) {
    printf("%s = 0x", name);
    for (int i = 3; i >= 0; i--) {
        printf("%016llx", (unsigned long long)a->limb[i]);
    }
    printf("\n");
}

int main() {
    printf("=== fe256 Montgomery Form Test ===\n\n");
    
    // Step 1: Convert Gx to Montgomery form
    Fe256 gx_mont;
    fe256_to_mont(&gx_mont, &SECP256K1_GX);
    print_fe256("Gx (normal)", &SECP256K1_GX);
    print_fe256("Gx (mont)  ", &gx_mont);
    
    // Step 2: Convert back from Montgomery form
    Fe256 gx_back;
    fe256_from_mont(&gx_back, &gx_mont);
    print_fe256("Gx (back)  ", &gx_back);
    
    printf("\nGx roundtrip: %s\n", (gx_back == SECP256K1_GX) ? "PASS" : "FAIL");
    
    // Step 3: Test multiplication in Montgomery form
    printf("\n=== Test a * 1 in Montgomery form ===\n");
    Fe256 one_mont;
    Fe256 one_normal;
    fe256_one(&one_normal);
    fe256_to_mont(&one_mont, &one_normal);
    print_fe256("1 (mont)", &one_mont);
    
    Fe256 gx_times_one;
    fe256_mul_mont(&gx_times_one, &gx_mont, &one_mont);
    print_fe256("Gx * 1 (mont)", &gx_times_one);
    
    printf("Gx * 1 == Gx (mont): %s\n", (gx_times_one == gx_mont) ? "PASS" : "FAIL");
    
    return 0;
}
