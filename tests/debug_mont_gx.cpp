/**
 * @brief Debug Montgomery reduction for Gx * R^2
 */
#include <cstdint>
#include <cstdio>

using uint128_t = unsigned __int128;

struct Fe256 { uint64_t limb[4]; };
struct Fe512 { uint64_t limb[8]; };

static const Fe256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
}};
static const uint64_t SECP256K1_N0 = 0xD838091DD2253531ULL;

void fe256_copy(Fe256* r, const Fe256* a) {
    for (int i = 0; i < 4; i++) r->limb[i] = a->limb[i];
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
    
    printf("After Montgomery iterations:\n");
    for (int i = 0; i < 9; i++) {
        printf("  tmp[%d] = 0x%016llx\n", i, (unsigned long long)tmp[i]);
    }
    
    // Handle overflow
    if (tmp[8] != 0) {
        printf("Overflow detected: tmp[8] = %llu\n", (unsigned long long)tmp[8]);
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
    
    printf("Before conditional subtraction:\n");
    for (int i = 0; i < 4; i++) {
        printf("  r->limb[%d] = 0x%016llx\n", i, (unsigned long long)r->limb[i]);
    }
    
    // Conditional subtraction
    uint64_t borrow = 0;
    Fe256 reduced;
    
    // Use proper subtraction with borrow
    uint128_t diff = (uint128_t)r->limb[0] - p->limb[0];
    reduced.limb[0] = (uint64_t)diff;
    borrow = (diff >> 64) ? 1 : 0;  // Check sign bit
    
    diff = (uint128_t)r->limb[1] - p->limb[1] - borrow;
    reduced.limb[1] = (uint64_t)diff;
    borrow = (diff >> 64) ? 1 : 0;
    
    diff = (uint128_t)r->limb[2] - p->limb[2] - borrow;
    reduced.limb[2] = (uint64_t)diff;
    borrow = (diff >> 64) ? 1 : 0;
    
    diff = (uint128_t)r->limb[3] - p->limb[3] - borrow;
    reduced.limb[3] = (uint64_t)diff;
    borrow = (diff >> 64) ? 1 : 0;
    
    printf("After subtraction (borrow=%llu):\n", (unsigned long long)borrow);
    for (int i = 0; i < 4; i++) {
        printf("  reduced.limb[%d] = 0x%016llx\n", i, (unsigned long long)reduced.limb[i]);
    }
    
    if (borrow == 0) {
        printf("Applying reduction\n");
        fe256_copy(r, &reduced);
    } else {
        printf("NOT applying reduction\n");
    }
}

int main() {
    // Gx * R^2 wide product
    Fe512 wide = {{
        0x5ee5eef6499c5698ULL,
        0x2fd81d3da57c4f6aULL,
        0xdae1b8228bf22f35ULL,
        0xc1c86874f1872ccaULL,
        0x79be6a20392dfe0cULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL
    }};
    
    Fe256 result;
    fe256_montgomery_reduce(&result, &wide, &SECP256K1_P, SECP256K1_N0);
    
    printf("\nFinal result:\n");
    for (int i = 0; i < 4; i++) {
        printf("  limb[%d] = 0x%016llx\n", i, (unsigned long long)result.limb[i]);
    }
    
    printf("\nExpected (Python):\n");
    printf("  limb[0] = 0xd7362e5a487e2097\n");
    printf("  limb[1] = 0x231e295329bc66db\n");
    printf("  limb[2] = 0x979f48c033fd129c\n");
    printf("  limb[3] = 0x9981e643e9089f48\n");
    
    bool match = (result.limb[0] == 0xd7362e5a487e2097ULL) &&
                 (result.limb[1] == 0x231e295329bc66dbULL) &&
                 (result.limb[2] == 0x979f48c033fd129cULL) &&
                 (result.limb[3] == 0x9981e643e9089f48ULL);
    printf("\nMatch: %s\n", match ? "PASS" : "FAIL");
    
    return 0;
}
