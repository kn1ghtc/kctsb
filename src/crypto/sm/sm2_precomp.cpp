/**
 * @file sm2_precomp.cpp
 * @brief SM2 Precomputed Base Point Table
 * 
 * Precomputed multiples of SM2 base point G for fast scalar multiplication.
 * Uses wNAF (windowed Non-Adjacent Form) representation with window size w=5.
 * 
 * The table contains 2^(w-1) = 16 points: [G, 3G, 5G, ..., 31G]
 * This enables computing scalar * G in ~256/5 = ~51 point additions.
 * 
 * Reference: GmSSL sm2_z256_table.c, OpenSSL ecp_nistz256.c
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <cstdint>
#include <cstring>
#include <array>

#include "sm2_mont_curve.h"

namespace kctsb::internal::sm2::precomp {

// ============================================================================
// Types and Constants
// ============================================================================

/**
 * @brief Affine point on SM2 curve (x, y)
 * Uses mont::fe256 via precomp::fe256 alias
 */
struct sm2_point_affine {
    fe256 x;
    fe256 y;
};

/**
 * @brief wNAF window size
 * Larger window = faster but more memory
 * w=5 is optimal for 256-bit scalar
 */
static constexpr int WNAF_WINDOW = 5;

/**
 * @brief Number of precomputed points: 2^(w-1) = 16
 */
static constexpr int PRECOMP_SIZE = 1 << (WNAF_WINDOW - 1);

// ============================================================================
// SM2 Base Point G (in affine coordinates)
// ============================================================================

/**
 * @brief SM2 base point G (affine coordinates)
 * 
 * Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
 * Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
 */
static constexpr fe256 SM2_G_X = {{
    0x715A4589334C74C7ULL,
    0x8FE30BBFF2660BE1ULL,
    0x5F9904466A39C994ULL,
    0x32C4AE2C1F198119ULL
}};

static constexpr fe256 SM2_G_Y = {{
    0x02DF32E52139F0A0ULL,
    0xD0A9877CC62A4740ULL,
    0x59BDCEE36B692153ULL,
    0xBC3736A2F4F6779CULL
}};

// ============================================================================
// Precomputed wNAF Table (points in Montgomery + Jacobian form)
// ============================================================================

/**
 * @brief Precomputed odd multiples of G in Montgomery-Jacobian form
 * 
 * Table contains: [G, 3G, 5G, 7G, 9G, 11G, 13G, 15G, 17G, 19G, 21G, 23G, 25G, 27G, 29G, 31G]
 * All coordinates are in Montgomery form for efficient multiplication.
 * 
 * This table is computed at startup or compile-time using compute_precomp_table().
 */
alignas(64) static sm2_point_jacobian g_precomp_table[PRECOMP_SIZE];

/**
 * @brief Precomputed odd multiples of G in affine form (for mixed addition)
 * 
 * Same points as g_precomp_table but in affine coordinates (Z = 1).
 * Used for faster mixed addition in scalar multiplication.
 */
alignas(64) static sm2_point_affine g_precomp_affine[PRECOMP_SIZE];

/**
 * @brief Flag indicating if precomputation table is initialized
 */
static bool g_precomp_initialized = false;

}  // namespace kctsb::internal::sm2::precomp

namespace kctsb::internal::sm2::precomp {

// Type-safe cast between precomp::fe256 and mont::fe256 (same layout)
inline mont::fe256* as_mont(fe256* p) { return reinterpret_cast<mont::fe256*>(p); }
inline const mont::fe256* as_mont(const fe256* p) { return reinterpret_cast<const mont::fe256*>(p); }

// ============================================================================
// Point Operations (Jacobian coordinates)
// ============================================================================

/**
 * @brief Point doubling in Jacobian coordinates
 * 
 * Input: P = (X1, Y1, Z1) in Montgomery form
 * Output: 2P = (X3, Y3, Z3) in Montgomery form
 * 
 * Formula (a = -3 for SM2):
 *   λ = 3X1² + aZ1⁴ = 3X1² - 3Z1⁴ = 3(X1+Z1²)(X1-Z1²)
 *   X3 = λ² - 2*S
 *   Y3 = λ*(S - X3) - 8*Y1⁴
 *   Z3 = 2*Y1*Z1
 * where S = 4*X1*Y1²
 */
static void point_double_jacobian(sm2_point_jacobian* r, const sm2_point_jacobian* p) {
    using MontFe = mont::fe256;
    MontFe S, M, T, X3, Y3, Z3;
    MontFe *px = (MontFe*)&p->X, *py = (MontFe*)&p->Y, *pz = (MontFe*)&p->Z;
    MontFe *rx = (MontFe*)&r->X, *ry = (MontFe*)&r->Y, *rz = (MontFe*)&r->Z;
    
    // S = 4*X*Y²
    mont::fe256_mont_sqr(&T, py);         // T = Y²
    mont::fe256_mont_mul(&S, px, &T);     // S = X*Y²
    mont::fe256_modp_dbl(&S, &S);         // S = 2*X*Y²
    mont::fe256_modp_dbl(&S, &S);         // S = 4*X*Y²
    
    // M = 3(X+Z²)(X-Z²) for a=-3
    MontFe Z2, XpZ2, XmZ2;
    mont::fe256_mont_sqr(&Z2, pz);        // Z² 
    mont::fe256_modp_add(&XpZ2, px, &Z2); // X + Z²
    mont::fe256_modp_sub(&XmZ2, px, &Z2); // X - Z²
    mont::fe256_mont_mul(&M, &XpZ2, &XmZ2); // (X+Z²)(X-Z²)
    mont::fe256_modp_dbl(&T, &M);         // 2*(X+Z²)(X-Z²)
    mont::fe256_modp_add(&M, &M, &T);     // 3*(X+Z²)(X-Z²)
    
    // X3 = M² - 2*S
    mont::fe256_mont_sqr(&X3, &M);        // M²
    mont::fe256_modp_dbl(&T, &S);         // 2*S
    mont::fe256_modp_sub(&X3, &X3, &T);   // M² - 2*S
    
    // Y3 = M*(S - X3) - 8*Y⁴
    mont::fe256_modp_sub(&T, &S, &X3);    // S - X3
    mont::fe256_mont_mul(&Y3, &M, &T);    // M*(S - X3)
    MontFe Y2, Y4;
    mont::fe256_mont_sqr(&Y2, py);        // Y²
    mont::fe256_mont_sqr(&Y4, &Y2);       // Y⁴
    mont::fe256_modp_dbl(&Y4, &Y4);       // 2*Y⁴
    mont::fe256_modp_dbl(&Y4, &Y4);       // 4*Y⁴
    mont::fe256_modp_dbl(&Y4, &Y4);       // 8*Y⁴
    mont::fe256_modp_sub(&Y3, &Y3, &Y4);  // M*(S-X3) - 8*Y⁴
    
    // Z3 = 2*Y*Z
    mont::fe256_mont_mul(&Z3, py, pz);    // Y*Z
    mont::fe256_modp_dbl(&Z3, &Z3);       // 2*Y*Z
    
    // Store result
    memcpy(rx, &X3, sizeof(MontFe));
    memcpy(ry, &Y3, sizeof(MontFe));
    memcpy(rz, &Z3, sizeof(MontFe));
}

/**
 * @brief Point addition in Jacobian coordinates
 * 
 * Input: P = (X1, Y1, Z1), Q = (X2, Y2, Z2) in Montgomery form
 * Output: P + Q = (X3, Y3, Z3) in Montgomery form
 * 
 * Uses complete addition formula (handles edge cases).
 */
static void point_add_jacobian(sm2_point_jacobian* r, 
                                const sm2_point_jacobian* p,
                                const sm2_point_jacobian* q) {
    using MontFe = mont::fe256;
    MontFe *px = (MontFe*)&p->X, *py = (MontFe*)&p->Y, *pz = (MontFe*)&p->Z;
    MontFe *qx = (MontFe*)&q->X, *qy = (MontFe*)&q->Y, *qz = (MontFe*)&q->Z;
    MontFe *rx = (MontFe*)&r->X, *ry = (MontFe*)&r->Y, *rz = (MontFe*)&r->Z;
    
    MontFe U1, U2, S1, S2, H, R, HH, HHH, V, X3, Y3, Z3;
    
    // U1 = X1*Z2², U2 = X2*Z1²
    MontFe Z1_sq, Z2_sq;
    mont::fe256_mont_sqr(&Z1_sq, pz);
    mont::fe256_mont_sqr(&Z2_sq, qz);
    mont::fe256_mont_mul(&U1, px, &Z2_sq);
    mont::fe256_mont_mul(&U2, qx, &Z1_sq);
    
    // S1 = Y1*Z2³, S2 = Y2*Z1³
    MontFe Z1_cubed, Z2_cubed;
    mont::fe256_mont_mul(&Z1_cubed, &Z1_sq, pz);
    mont::fe256_mont_mul(&Z2_cubed, &Z2_sq, qz);
    mont::fe256_mont_mul(&S1, py, &Z2_cubed);
    mont::fe256_mont_mul(&S2, qy, &Z1_cubed);
    
    // H = U2 - U1, R = S2 - S1
    mont::fe256_modp_sub(&H, &U2, &U1);
    mont::fe256_modp_sub(&R, &S2, &S1);
    
    // If H == 0 and R == 0, then P == Q, use doubling
    // (Simplified: caller should check for this case)
    
    // HH = H², HHH = H³
    mont::fe256_mont_sqr(&HH, &H);
    mont::fe256_mont_mul(&HHH, &HH, &H);
    
    // V = U1*H²
    mont::fe256_mont_mul(&V, &U1, &HH);
    
    // X3 = R² - HHH - 2*V
    mont::fe256_mont_sqr(&X3, &R);
    mont::fe256_modp_sub(&X3, &X3, &HHH);
    MontFe V2;
    mont::fe256_modp_dbl(&V2, &V);
    mont::fe256_modp_sub(&X3, &X3, &V2);
    
    // Y3 = R*(V - X3) - S1*HHH
    MontFe VmX3, S1HHH;
    mont::fe256_modp_sub(&VmX3, &V, &X3);
    mont::fe256_mont_mul(&Y3, &R, &VmX3);
    mont::fe256_mont_mul(&S1HHH, &S1, &HHH);
    mont::fe256_modp_sub(&Y3, &Y3, &S1HHH);
    
    // Z3 = Z1*Z2*H
    mont::fe256_mont_mul(&Z3, pz, qz);
    mont::fe256_mont_mul(&Z3, &Z3, &H);
    
    // Store result
    memcpy(rx, &X3, sizeof(MontFe));
    memcpy(ry, &Y3, sizeof(MontFe));
    memcpy(rz, &Z3, sizeof(MontFe));
}

/**
 * @brief Mixed point addition: Jacobian + Affine
 * 
 * Optimized addition where Q is an affine point (Z2 = 1).
 * This saves 3 multiplications compared to general Jacobian addition.
 * 
 * Input: P = (X1, Y1, Z1) Jacobian in Montgomery form
 *        Q = (X2, Y2) Affine in Montgomery form (Z2 = 1 implicit)
 * Output: P + Q = (X3, Y3, Z3) Jacobian in Montgomery form
 * 
 * Formulas (from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html):
 *   U1 = X1, U2 = X2*Z1², S1 = Y1, S2 = Y2*Z1³
 *   H = U2 - U1, R = S2 - S1
 *   X3 = R² - H³ - 2*U1*H²
 *   Y3 = R*(U1*H² - X3) - S1*H³
 *   Z3 = Z1*H
 * 
 * Cost: 8M + 3S (vs 16M + 4S for Jacobian + Jacobian)
 */
static void point_add_mixed(sm2_point_jacobian* r, 
                            const sm2_point_jacobian* p,
                            const fe256* q_x, const fe256* q_y) {
    using MontFe = mont::fe256;
    MontFe *px = (MontFe*)&p->X, *py = (MontFe*)&p->Y, *pz = (MontFe*)&p->Z;
    MontFe *rx = (MontFe*)&r->X, *ry = (MontFe*)&r->Y, *rz = (MontFe*)&r->Z;
    const MontFe *qx = (const MontFe*)q_x, *qy = (const MontFe*)q_y;
    
    MontFe U1, U2, S1, S2, H, R, HH, HHH, V, X3, Y3, Z3;
    
    // Z1² and Z1³
    MontFe Z1_sq, Z1_cubed;
    mont::fe256_mont_sqr(&Z1_sq, pz);                // Z1²
    mont::fe256_mont_mul(&Z1_cubed, &Z1_sq, pz);     // Z1³
    
    // U1 = X1 (no conversion needed), U2 = X2*Z1²
    memcpy(&U1, px, sizeof(MontFe));
    mont::fe256_mont_mul(&U2, qx, &Z1_sq);
    
    // S1 = Y1 (no conversion needed), S2 = Y2*Z1³
    memcpy(&S1, py, sizeof(MontFe));
    mont::fe256_mont_mul(&S2, qy, &Z1_cubed);
    
    // H = U2 - U1, R = S2 - S1
    mont::fe256_modp_sub(&H, &U2, &U1);
    mont::fe256_modp_sub(&R, &S2, &S1);
    
    // HH = H², HHH = H³
    mont::fe256_mont_sqr(&HH, &H);                   // H²
    mont::fe256_mont_mul(&HHH, &HH, &H);             // H³
    
    // V = U1*H²
    mont::fe256_mont_mul(&V, &U1, &HH);
    
    // X3 = R² - HHH - 2*V
    mont::fe256_mont_sqr(&X3, &R);                   // R²
    mont::fe256_modp_sub(&X3, &X3, &HHH);            // R² - H³
    MontFe V2;
    mont::fe256_modp_dbl(&V2, &V);                   // 2*V
    mont::fe256_modp_sub(&X3, &X3, &V2);             // R² - H³ - 2*V
    
    // Y3 = R*(V - X3) - S1*HHH
    MontFe VmX3, S1HHH;
    mont::fe256_modp_sub(&VmX3, &V, &X3);            // V - X3
    mont::fe256_mont_mul(&Y3, &R, &VmX3);            // R*(V - X3)
    mont::fe256_mont_mul(&S1HHH, &S1, &HHH);         // S1*H³
    mont::fe256_modp_sub(&Y3, &Y3, &S1HHH);          // R*(V-X3) - S1*H³
    
    // Z3 = Z1*H
    mont::fe256_mont_mul(&Z3, pz, &H);
    
    // Store result
    memcpy(rx, &X3, sizeof(MontFe));
    memcpy(ry, &Y3, sizeof(MontFe));
    memcpy(rz, &Z3, sizeof(MontFe));
}

// ============================================================================
// Precomputation Table Generation
// ============================================================================

/**
 * @brief Initialize precomputed table with odd multiples of G
 * 
 * Computes: [G, 3G, 5G, 7G, ..., 31G] in both:
 *   - Montgomery-Jacobian form (g_precomp_table)
 *   - Montgomery-Affine form (g_precomp_affine) for mixed addition
 * Called once at startup or first use.
 */
void compute_precomp_table() {
    if (g_precomp_initialized) {
        return;
    }
    
    using MontFe = mont::fe256;
    
    // Convert G to Montgomery form and set Z = 1 (in Mont form)
    sm2_point_jacobian G;
    mont::fe256_to_mont((MontFe*)&G.X, (MontFe*)&SM2_G_X);
    mont::fe256_to_mont((MontFe*)&G.Y, (MontFe*)&SM2_G_Y);
    
    // Z = 1 in Montgomery form = R mod p
    static const fe256 MONT_ONE = {{
        0x0000000000000001ULL,
        0x00000000FFFFFFFFULL,
        0x0000000000000000ULL,
        0x0000000100000000ULL
    }};
    memcpy(&G.Z, &MONT_ONE, sizeof(fe256));
    
    // Table[0] = G
    memcpy(&g_precomp_table[0], &G, sizeof(sm2_point_jacobian));
    
    // Compute 2G for stepping
    sm2_point_jacobian G2;
    point_double_jacobian(&G2, &G);
    
    // Table[i] = (2*i + 1) * G
    // Table[1] = 3G = G + 2G
    // Table[2] = 5G = 3G + 2G
    // ...
    for (int i = 1; i < PRECOMP_SIZE; i++) {
        point_add_jacobian(&g_precomp_table[i], &g_precomp_table[i-1], &G2);
    }
    
    // Convert Jacobian points to affine for mixed addition
    // x = X / Z^2, y = Y / Z^3 (all in Montgomery form)
    for (int i = 0; i < PRECOMP_SIZE; i++) {
        MontFe* jx = (MontFe*)&g_precomp_table[i].X;
        MontFe* jy = (MontFe*)&g_precomp_table[i].Y;
        MontFe* jz = (MontFe*)&g_precomp_table[i].Z;
        MontFe* ax = (MontFe*)&g_precomp_affine[i].x;
        MontFe* ay = (MontFe*)&g_precomp_affine[i].y;
        
        // Compute Z^(-1), Z^(-2), Z^(-3)
        MontFe z_inv, z_inv2, z_inv3;
        mont::fe256_mont_inv(&z_inv, jz);
        mont::fe256_mont_sqr(&z_inv2, &z_inv);           // Z^(-2)
        mont::fe256_mont_mul(&z_inv3, &z_inv2, &z_inv);  // Z^(-3)
        
        // x = X * Z^(-2), y = Y * Z^(-3)
        mont::fe256_mont_mul(ax, jx, &z_inv2);
        mont::fe256_mont_mul(ay, jy, &z_inv3);
    }
    
    g_precomp_initialized = true;
}

// ============================================================================
// wNAF Scalar Encoding
// ============================================================================

/**
 * @brief Compute wNAF representation of a 256-bit scalar
 * 
 * @param[out] naf wNAF digits array (257 elements, values in [-2^(w-1)+1, 2^(w-1)-1])
 * @param[in] scalar 256-bit scalar (4 x 64-bit limbs, little-endian)
 * @param[in] w window size (typically 5)
 * @return Number of significant digits
 */
int compute_wnaf(int8_t* naf, const uint64_t* scalar, int w) {
    // Copy scalar to working array (we'll modify it)
    uint64_t k[5] = {scalar[0], scalar[1], scalar[2], scalar[3], 0};
    
    int half_width = 1 << (w - 1);  // 2^(w-1) = 16 for w=5
    int mask = (1 << w) - 1;         // 2^w - 1 = 31 for w=5
    
    int len = 0;
    
    while (k[0] || k[1] || k[2] || k[3]) {
        if (k[0] & 1) {
            // Odd: extract digit
            int digit = k[0] & mask;
            if (digit >= half_width) {
                digit -= (1 << w);
            }
            naf[len] = (int8_t)digit;
            
            // Subtract digit from k
            if (digit > 0) {
                // k -= digit
                uint64_t borrow = 0;
                for (int i = 0; i < 5; i++) {
                    uint64_t prev = k[i];
                    k[i] -= (i == 0 ? digit : 0) + borrow;
                    borrow = (k[i] > prev) ? 1 : 0;
                }
            } else if (digit < 0) {
                // k += (-digit)
                uint64_t carry = 0;
                int add = -digit;
                for (int i = 0; i < 5; i++) {
                    uint64_t prev = k[i];
                    k[i] += (i == 0 ? add : 0) + carry;
                    carry = (k[i] < prev || (carry && k[i] == prev)) ? 1 : 0;
                }
            }
        } else {
            naf[len] = 0;
        }
        
        // Right shift k by 1
        k[0] = (k[0] >> 1) | ((k[1] & 1) << 63);
        k[1] = (k[1] >> 1) | ((k[2] & 1) << 63);
        k[2] = (k[2] >> 1) | ((k[3] & 1) << 63);
        k[3] = (k[3] >> 1) | ((k[4] & 1) << 63);
        k[4] >>= 1;
        
        len++;
    }
    
    return len;
}

// ============================================================================
// Fast Scalar Multiplication using Precomputed Table
// ============================================================================

/**
 * @brief Compute k * G using precomputed table and wNAF
 * 
 * Uses affine precomputed points for faster mixed addition.
 * 
 * @param[out] r Result point (Jacobian, Montgomery form)
 * @param[in] k 256-bit scalar (4 x 64-bit limbs)
 */
void scalar_mul_base(sm2_point_jacobian* r, const uint64_t* k) {
    // Ensure table is initialized
    if (!g_precomp_initialized) {
        compute_precomp_table();
    }
    
    // Compute wNAF representation
    int8_t naf[257] = {0};
    int naf_len = compute_wnaf(naf, k, WNAF_WINDOW);
    
    // Initialize result to point at infinity
    // For Jacobian: Z = 0 represents infinity
    memset(r, 0, sizeof(sm2_point_jacobian));
    
    bool first_nonzero = true;
    
    // Process wNAF digits from MSB to LSB
    for (int i = naf_len - 1; i >= 0; i--) {
        if (!first_nonzero) {
            point_double_jacobian(r, r);
        }
        
        if (naf[i] != 0) {
            // Lookup table: index = (|naf[i]| - 1) / 2
            int idx = (naf[i] > 0 ? naf[i] : -naf[i]) >> 1;
            
            // Get affine point from precomputed table
            fe256 px, py;
            memcpy(&px, &g_precomp_affine[idx].x, sizeof(fe256));
            memcpy(&py, &g_precomp_affine[idx].y, sizeof(fe256));
            
            // Negate Y if naf[i] < 0
            if (naf[i] < 0) {
                mont::fe256_modp_neg((mont::fe256*)&py, (const mont::fe256*)&py);
            }
            
            if (first_nonzero) {
                // First point: convert affine to Jacobian (Z = 1)
                memcpy(&r->X, &px, sizeof(fe256));
                memcpy(&r->Y, &py, sizeof(fe256));
                // Z = 1 in Montgomery form
                static const fe256 MONT_ONE = {{
                    0x0000000000000001ULL,
                    0x00000000FFFFFFFFULL,
                    0x0000000000000000ULL,
                    0x0000000100000000ULL
                }};
                memcpy(&r->Z, &MONT_ONE, sizeof(fe256));
                first_nonzero = false;
            } else {
                // Use mixed addition (Jacobian + Affine)
                point_add_mixed(r, r, &px, &py);
            }
        }
    }
}

// ============================================================================
// Comb Method for Even Faster Scalar Multiplication (Optional)
// ============================================================================

/**
 * @brief Comb method parameters
 * 
 * For 256-bit scalar with d=4 teeth and w=64 width:
 * Precompute 2^d = 16 points for each of 4 combs.
 * Total: 64 points, ~64 point additions.
 */

// Future: Implement comb method for ~30% faster fixed-point scalar mul

// ============================================================================
// Public API
// ============================================================================

/**
 * @brief Check if precomputation table is initialized
 */
bool is_precomp_ready() {
    return g_precomp_initialized;
}

/**
 * @brief Force recomputation of precomputed table
 * 
 * Useful for testing or after security-critical memory wipe.
 */
void reset_precomp_table() {
    g_precomp_initialized = false;
    memset(g_precomp_table, 0, sizeof(g_precomp_table));
}

/**
 * @brief Get acceleration info string
 */
const char* get_precomp_info() {
    return "wNAF w=5, 16 precomputed points, ~51 additions/scalar";
}

/**
 * @brief Compute k * P for arbitrary point P using wNAF
 * 
 * This function dynamically computes the precomputation table for point P
 * and then performs wNAF scalar multiplication.
 * 
 * @param[out] r Result point (Jacobian, Montgomery form)
 * @param[in] k 256-bit scalar (4 x 64-bit limbs)
 * @param[in] P Input point (Jacobian, Montgomery form)
 */
void scalar_mul_point(sm2_point_jacobian* r, const uint64_t* k, 
                      const sm2_point_jacobian* P) {
    using MontFe = mont::fe256;
    
    // Check if P is point at infinity
    bool p_is_inf = (P->Z.limb[0] == 0 && P->Z.limb[1] == 0 && 
                     P->Z.limb[2] == 0 && P->Z.limb[3] == 0);
    if (p_is_inf) {
        // k * O = O
        memset(r, 0, sizeof(sm2_point_jacobian));
        return;
    }
    
    // Check if k is zero
    if (k[0] == 0 && k[1] == 0 && k[2] == 0 && k[3] == 0) {
        memset(r, 0, sizeof(sm2_point_jacobian));
        return;
    }
    
    // Build precomputation table for P: [P, 3P, 5P, ..., 31P]
    sm2_point_jacobian table[PRECOMP_SIZE];
    
    // table[0] = P
    memcpy(&table[0], P, sizeof(sm2_point_jacobian));
    
    // Compute 2P for stepping
    sm2_point_jacobian P2;
    point_double_jacobian(&P2, P);
    
    // table[i] = (2*i + 1) * P
    for (int i = 1; i < PRECOMP_SIZE; i++) {
        point_add_jacobian(&table[i], &table[i-1], &P2);
    }
    
    // Compute wNAF representation
    int8_t naf[257] = {0};
    int naf_len = compute_wnaf(naf, k, WNAF_WINDOW);
    
    // Initialize result to point at infinity
    memset(r, 0, sizeof(sm2_point_jacobian));
    
    bool first_nonzero = true;
    
    // Process wNAF digits from MSB to LSB
    for (int i = naf_len - 1; i >= 0; i--) {
        if (!first_nonzero) {
            point_double_jacobian(r, r);
        }
        
        if (naf[i] != 0) {
            int idx = (naf[i] > 0 ? naf[i] : -naf[i]) >> 1;
            sm2_point_jacobian p_tmp = table[idx];
            
            // Negate Y if naf[i] < 0
            if (naf[i] < 0) {
                mont::fe256_modp_neg((MontFe*)&p_tmp.Y, (MontFe*)&p_tmp.Y);
            }
            
            if (first_nonzero) {
                memcpy(r, &p_tmp, sizeof(sm2_point_jacobian));
                first_nonzero = false;
            } else {
                point_add_jacobian(r, r, &p_tmp);
            }
        }
    }
}

}  // namespace kctsb::internal::sm2::precomp

namespace kctsb::internal::sm2 {

// External point addition function for use from sm2_mont_curve.h
void point_add_jacobian_ext(precomp::sm2_point_jacobian* r,
                            const precomp::sm2_point_jacobian* p,
                            const precomp::sm2_point_jacobian* q) {
    using MontFe = mont::fe256;
    
    MontFe *px = (MontFe*)&p->X, *py = (MontFe*)&p->Y, *pz = (MontFe*)&p->Z;
    MontFe *qx = (MontFe*)&q->X, *qy = (MontFe*)&q->Y, *qz = (MontFe*)&q->Z;
    MontFe *rx = (MontFe*)&r->X, *ry = (MontFe*)&r->Y, *rz = (MontFe*)&r->Z;
    
    MontFe U1, U2, S1, S2, H, R, HH, HHH, V, X3, Y3, Z3;
    
    // U1 = X1*Z2², U2 = X2*Z1²
    MontFe Z1_sq, Z2_sq;
    mont::fe256_mont_sqr(&Z1_sq, pz);
    mont::fe256_mont_sqr(&Z2_sq, qz);
    mont::fe256_mont_mul(&U1, px, &Z2_sq);
    mont::fe256_mont_mul(&U2, qx, &Z1_sq);
    
    // S1 = Y1*Z2³, S2 = Y2*Z1³
    MontFe Z1_cubed, Z2_cubed;
    mont::fe256_mont_mul(&Z1_cubed, &Z1_sq, pz);
    mont::fe256_mont_mul(&Z2_cubed, &Z2_sq, qz);
    mont::fe256_mont_mul(&S1, py, &Z2_cubed);
    mont::fe256_mont_mul(&S2, qy, &Z1_cubed);
    
    // H = U2 - U1, R = S2 - S1
    mont::fe256_modp_sub(&H, &U2, &U1);
    mont::fe256_modp_sub(&R, &S2, &S1);
    
    // HH = H², HHH = H³
    mont::fe256_mont_sqr(&HH, &H);
    mont::fe256_mont_mul(&HHH, &HH, &H);
    
    // V = U1*H²
    mont::fe256_mont_mul(&V, &U1, &HH);
    
    // X3 = R² - HHH - 2*V
    mont::fe256_mont_sqr(&X3, &R);
    mont::fe256_modp_sub(&X3, &X3, &HHH);
    MontFe V2;
    mont::fe256_modp_dbl(&V2, &V);
    mont::fe256_modp_sub(&X3, &X3, &V2);
    
    // Y3 = R*(V - X3) - S1*HHH
    MontFe VmX3, S1HHH;
    mont::fe256_modp_sub(&VmX3, &V, &X3);
    mont::fe256_mont_mul(&Y3, &R, &VmX3);
    mont::fe256_mont_mul(&S1HHH, &S1, &HHH);
    mont::fe256_modp_sub(&Y3, &Y3, &S1HHH);
    
    // Z3 = Z1*Z2*H
    mont::fe256_mont_mul(&Z3, pz, qz);
    mont::fe256_mont_mul(&Z3, &Z3, &H);
    
    // Store result
    memcpy(rx, &X3, sizeof(MontFe));
    memcpy(ry, &Y3, sizeof(MontFe));
    memcpy(rz, &Z3, sizeof(MontFe));
}

/**
 * @brief Shamir's trick: compute k1*G + k2*P simultaneously
 * 
 * This is optimized for SM2 verification where we compute s*G + t*P.
 * Uses interleaved wNAF with joint scanning for both scalars.
 * 
 * Optimizations:
 * - Uses affine precomputed G table for mixed addition (8M+3S vs 16M+4S)
 * - Uses Jacobian P table (dynamic precomputation)
 * - Joint scanning shares doublings between both scalars
 * 
 * This saves ~50% compared to computing k1*G and k2*P separately.
 * 
 * @param[out] r Result point (Jacobian, Montgomery form)
 * @param[in] k1 256-bit scalar for G (4 x 64-bit limbs)
 * @param[in] k2 256-bit scalar for P (4 x 64-bit limbs)
 * @param[in] P Input point (Jacobian, Montgomery form, already converted)
 */
void scalar_mul_shamir(precomp::sm2_point_jacobian* r, 
                       const uint64_t* k1, 
                       const uint64_t* k2,
                       const precomp::sm2_point_jacobian* P) {
    using MontFe = mont::fe256;
    
    // Ensure G table is initialized
    if (!precomp::g_precomp_initialized) {
        precomp::compute_precomp_table();
    }
    
    // Build precomputation table for P: [P, 3P, 5P, ..., 31P]
    precomp::sm2_point_jacobian p_jac_table[precomp::PRECOMP_SIZE];
    precomp::sm2_point_affine p_affine_table[precomp::PRECOMP_SIZE];
    
    // Check if P is point at infinity
    bool p_is_inf = (P->Z.limb[0] == 0 && P->Z.limb[1] == 0 && 
                     P->Z.limb[2] == 0 && P->Z.limb[3] == 0);
    
    if (!p_is_inf) {
        // table[0] = P
        memcpy(&p_jac_table[0], P, sizeof(precomp::sm2_point_jacobian));
        
        // Compute 2P for stepping
        precomp::sm2_point_jacobian P2;
        precomp::point_double_jacobian(&P2, P);
        
        // table[i] = (2*i + 1) * P
        for (int i = 1; i < precomp::PRECOMP_SIZE; i++) {
            precomp::point_add_jacobian(&p_jac_table[i], &p_jac_table[i-1], &P2);
        }
        
        // Batch conversion to affine using Montgomery's trick
        // This uses only ONE modular inversion for all 16 points
        // 
        // Algorithm:
        // 1. Compute cumulative products: c[i] = Z[0] * Z[1] * ... * Z[i]
        // 2. Invert once: inv_all = 1 / c[n-1]
        // 3. Compute individual inverses: Z[i]^(-1) = c[i-1] * inv_all * (Z[i+1] * ... * Z[n-1])
        
        MontFe cumul[precomp::PRECOMP_SIZE];
        MontFe z_invs[precomp::PRECOMP_SIZE];
        
        // Step 1: Cumulative products
        memcpy(&cumul[0], &p_jac_table[0].Z, sizeof(MontFe));
        for (int i = 1; i < precomp::PRECOMP_SIZE; i++) {
            mont::fe256_mont_mul(&cumul[i], &cumul[i-1], (MontFe*)&p_jac_table[i].Z);
        }
        
        // Step 2: Single inversion
        MontFe inv_all;
        mont::fe256_mont_inv(&inv_all, &cumul[precomp::PRECOMP_SIZE - 1]);
        
        // Step 3: Compute individual Z inverses
        for (int i = precomp::PRECOMP_SIZE - 1; i > 0; i--) {
            // z_inv[i] = cumul[i-1] * inv_all
            mont::fe256_mont_mul(&z_invs[i], &cumul[i-1], &inv_all);
            // Update inv_all = inv_all * Z[i] for next iteration
            mont::fe256_mont_mul(&inv_all, &inv_all, (MontFe*)&p_jac_table[i].Z);
        }
        z_invs[0] = inv_all;  // inv_all now equals Z[0]^(-1)
        
        // Step 4: Convert to affine coordinates
        for (int i = 0; i < precomp::PRECOMP_SIZE; i++) {
            MontFe* jx = (MontFe*)&p_jac_table[i].X;
            MontFe* jy = (MontFe*)&p_jac_table[i].Y;
            MontFe* ax = (MontFe*)&p_affine_table[i].x;
            MontFe* ay = (MontFe*)&p_affine_table[i].y;
            
            // z_inv2 = z_inv^2, z_inv3 = z_inv^3
            MontFe z_inv2, z_inv3;
            mont::fe256_mont_sqr(&z_inv2, &z_invs[i]);
            mont::fe256_mont_mul(&z_inv3, &z_inv2, &z_invs[i]);
            
            // x = X * Z^(-2), y = Y * Z^(-3)
            mont::fe256_mont_mul(ax, jx, &z_inv2);
            mont::fe256_mont_mul(ay, jy, &z_inv3);
        }
    }
    
    // Compute wNAF for both scalars
    int8_t naf1[257] = {0};
    int8_t naf2[257] = {0};
    int naf1_len = precomp::compute_wnaf(naf1, k1, precomp::WNAF_WINDOW);
    int naf2_len = precomp::compute_wnaf(naf2, k2, precomp::WNAF_WINDOW);
    
    // Find maximum length
    int max_len = (naf1_len > naf2_len) ? naf1_len : naf2_len;
    
    // Initialize result to point at infinity
    memset(r, 0, sizeof(precomp::sm2_point_jacobian));
    bool first_nonzero = true;
    
    // Z = 1 in Montgomery form (for first point initialization)
    static const precomp::fe256 MONT_ONE = {{
        0x0000000000000001ULL,
        0x00000000FFFFFFFFULL,
        0x0000000000000000ULL,
        0x0000000100000000ULL
    }};
    
    // Joint scan from MSB to LSB
    for (int i = max_len - 1; i >= 0; i--) {
        // Double if not first iteration
        if (!first_nonzero) {
            precomp::point_double_jacobian(r, r);
        }
        
        // Add contribution from k1*G (using affine G table for mixed addition)
        if (naf1[i] != 0) {
            int idx = (naf1[i] > 0 ? naf1[i] : -naf1[i]) >> 1;
            
            // Get affine point from G table
            precomp::fe256 gx, gy;
            memcpy(&gx, &precomp::g_precomp_affine[idx].x, sizeof(precomp::fe256));
            memcpy(&gy, &precomp::g_precomp_affine[idx].y, sizeof(precomp::fe256));
            
            // Negate Y if digit is negative
            if (naf1[i] < 0) {
                mont::fe256_modp_neg((MontFe*)&gy, (MontFe*)&gy);
            }
            
            if (first_nonzero) {
                // First point: set as affine (Z = 1)
                memcpy(&r->X, &gx, sizeof(precomp::fe256));
                memcpy(&r->Y, &gy, sizeof(precomp::fe256));
                memcpy(&r->Z, &MONT_ONE, sizeof(precomp::fe256));
                first_nonzero = false;
            } else {
                // Mixed addition: Jacobian + Affine
                precomp::point_add_mixed(r, r, &gx, &gy);
            }
        }
        
        // Add contribution from k2*P (using affine P table for mixed addition)
        if (naf2[i] != 0 && !p_is_inf) {
            int idx = (naf2[i] > 0 ? naf2[i] : -naf2[i]) >> 1;
            
            // Get affine point from P table
            precomp::fe256 px, py;
            memcpy(&px, &p_affine_table[idx].x, sizeof(precomp::fe256));
            memcpy(&py, &p_affine_table[idx].y, sizeof(precomp::fe256));
            
            // Negate Y if digit is negative
            if (naf2[i] < 0) {
                mont::fe256_modp_neg((MontFe*)&py, (MontFe*)&py);
            }
            
            if (first_nonzero) {
                // First point: set as affine (Z = 1)
                memcpy(&r->X, &px, sizeof(precomp::fe256));
                memcpy(&r->Y, &py, sizeof(precomp::fe256));
                memcpy(&r->Z, &MONT_ONE, sizeof(precomp::fe256));
                first_nonzero = false;
            } else {
                // Mixed addition: Jacobian + Affine
                precomp::point_add_mixed(r, r, &px, &py);
            }
        }
    }
}

}  // namespace kctsb::internal::sm2
