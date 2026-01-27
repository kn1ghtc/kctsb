/**
 * @brief Debug fe256_mul_wide
 */
#include <cstdint>
#include <cstdio>

using uint128_t = unsigned __int128;

struct Fe256 { uint64_t limb[4]; };
struct Fe512 { uint64_t limb[8]; };

void fe256_mul_wide(Fe512* r, const Fe256* a, const Fe256* b) {
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

int main() {
    // Gx in little-endian limbs
    Fe256 gx = {{
        0x59F2815B16F81798ULL,  // limb[0] = LSB
        0x029BFCDB2DCE28D9ULL,
        0x55A06295CE870B07ULL,
        0x79BE667EF9DCBBACULL   // limb[3] = MSB
    }};
    
    // R^2 mod p
    Fe256 r2 = {{
        0x000007a2000e90a1ULL,
        0x0000000000000001ULL,
        0x0000000000000000ULL,
        0x0000000000000000ULL
    }};
    
    Fe512 wide;
    fe256_mul_wide(&wide, &gx, &r2);
    
    printf("C++ Gx * R^2:\n");
    for (int i = 0; i < 8; i++) {
        printf("  limb[%d] = 0x%016llx\n", i, (unsigned long long)wide.limb[i]);
    }
    
    // Expected from Python
    printf("\nExpected (Python):\n");
    printf("  limb[0] = 0x5ee5eef6499c5698\n");
    printf("  limb[1] = 0x2fd81d3da57c4f6a\n");
    printf("  limb[2] = 0xdae1b8228bf22f35\n");
    printf("  limb[3] = 0xc1c86874f1872cca\n");
    printf("  limb[4] = 0x79be6a20392dfe0c\n");
    printf("  limb[5] = 0x0000000000000000\n");
    printf("  limb[6] = 0x0000000000000000\n");
    printf("  limb[7] = 0x0000000000000000\n");
    
    // Check match
    bool match = (wide.limb[0] == 0x5ee5eef6499c5698ULL) &&
                 (wide.limb[1] == 0x2fd81d3da57c4f6aULL) &&
                 (wide.limb[2] == 0xdae1b8228bf22f35ULL) &&
                 (wide.limb[3] == 0xc1c86874f1872ccaULL) &&
                 (wide.limb[4] == 0x79be6a20392dfe0cULL) &&
                 (wide.limb[5] == 0x0000000000000000ULL) &&
                 (wide.limb[6] == 0x0000000000000000ULL) &&
                 (wide.limb[7] == 0x0000000000000000ULL);
    printf("\nMatch: %s\n", match ? "PASS" : "FAIL");
    
    return 0;
}
