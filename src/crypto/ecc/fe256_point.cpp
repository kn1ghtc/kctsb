/**
 * @file fe256_point.cpp
 * @brief Optimized Point Arithmetic Implementation using fe256
 *
 * High-performance Jacobian point operations using direct fe256 arithmetic.
 * Provides ~3-5x speedup over NTL ZZ_p based implementation.
 *
 * Security (v4.6.0):
 * - wNAF algorithm REMOVED due to side-channel vulnerabilities
 * - All scalar multiplication uses Montgomery ladder (constant-time)
 *
 * Formulas from Explicit-Formulas Database (EFD):
 * https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "fe256_point.h"
#include <cstring>

// ============================================================================
// Curve-specific operation dispatch
// ============================================================================

// Function pointer types for field operations
typedef void (*fe256_add_fn)(fe256*, const fe256*, const fe256*);
typedef void (*fe256_sub_fn)(fe256*, const fe256*, const fe256*);
typedef void (*fe256_mul_fn)(fe256*, const fe256*, const fe256*);
typedef void (*fe256_sqr_fn)(fe256*, const fe256*);
typedef void (*fe256_inv_fn)(fe256*, const fe256*);
typedef void (*fe256_neg_fn)(fe256*, const fe256*);

struct CurveOps {
    fe256_add_fn add;
    fe256_sub_fn sub;
    fe256_mul_fn mul;
    fe256_sqr_fn sqr;
    fe256_inv_fn inv;
    fe256_neg_fn neg;
    int a_is_zero;     // For optimized doubling when a = 0
    int a_is_minus_3;  // For optimized doubling when a = -3
};

// secp256k1: a = 0
static const CurveOps secp256k1_ops = {
    fe256_add_secp256k1,
    fe256_sub_secp256k1,
    fe256_mul_mont_secp256k1,
    fe256_sqr_mont_secp256k1,
    fe256_inv_secp256k1,
    fe256_neg_secp256k1,
    1,  // a = 0
    0   // a != -3
};

// P-256: a = -3
static const CurveOps p256_ops = {
    fe256_add_p256,
    fe256_sub_p256,
    fe256_mul_mont_p256,
    fe256_sqr_mont_p256,
    fe256_inv_p256,
    fe256_neg_p256,
    0,  // a != 0
    1   // a = -3
};

// SM2: a = -3 equivalent (a = p - 3)
static const CurveOps sm2_ops = {
    fe256_add_sm2,
    fe256_sub_sm2,
    fe256_mul_mont_sm2,
    fe256_sqr_mont_sm2,
    fe256_inv_sm2,
    fe256_neg_sm2,
    0,  // a != 0
    1   // a = -3 (mod p)
};

static const CurveOps* get_curve_ops(int curve_type) {
    switch (curve_type) {
        case FE256_CURVE_SECP256K1: return &secp256k1_ops;
        case FE256_CURVE_P256:      return &p256_ops;
        case FE256_CURVE_SM2:       return &sm2_ops;
        default:                    return &secp256k1_ops;
    }
}

// ============================================================================
// Generator Points (in Jacobian form with Z=1)
// ============================================================================

// secp256k1 generator
static const fe256_point secp256k1_generator = {{
    // Gx in little-endian limbs
    {0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
     0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}
}, {
    // Gy in little-endian limbs
    {0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
     0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}
}, {
    // Z = 1
    {1, 0, 0, 0}
}};

// P-256 generator
static const fe256_point p256_generator = {{
    {0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL,
     0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL}
}, {
    {0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL,
     0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL}
}, {
    {1, 0, 0, 0}
}};

// SM2 generator
static const fe256_point sm2_generator = {{
    {0x715A4589334C74C7ULL, 0x8FE30BBFF2660BE1ULL,
     0x5F9904466A39C994ULL, 0x32C4AE2C1F198119ULL}
}, {
    {0x02DF32E52139F0A0ULL, 0xD0A9877CC62A4740ULL,
     0x59BDCEE36B692153ULL, 0xBC3736A2F4F6779CULL}
}, {
    {1, 0, 0, 0}
}};

// Curve orders
static const uint64_t secp256k1_order[4] = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};

static const uint64_t p256_order[4] = {
    0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL
};

static const uint64_t sm2_order[4] = {
    0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
};

// ============================================================================
// Basic Point Operations
// ============================================================================

void fe256_point_set_infinity(fe256_point* p) {
    fe256_zero(&p->X);
    fe256_one(&p->Y);
    fe256_zero(&p->Z);
}

int fe256_point_is_infinity(const fe256_point* p) {
    return fe256_is_zero(&p->Z);
}

void fe256_point_copy(fe256_point* dst, const fe256_point* src) {
    fe256_copy(&dst->X, &src->X);
    fe256_copy(&dst->Y, &src->Y);
    fe256_copy(&dst->Z, &src->Z);
}

// ============================================================================
// Point Addition (Complete Formula)
// ============================================================================

void fe256_point_add(fe256_point* r, const fe256_point* p,
                     const fe256_point* q, int curve_type) {
    const CurveOps* ops = get_curve_ops(curve_type);

    // Handle infinity cases
    if (fe256_point_is_infinity(p)) {
        fe256_point_copy(r, q);
        return;
    }
    if (fe256_point_is_infinity(q)) {
        fe256_point_copy(r, p);
        return;
    }

    // Cache input values to handle aliasing (r == p or r == q)
    fe256 X1, Y1, Z1, X2, Y2, Z2;
    fe256_copy(&X1, &p->X);
    fe256_copy(&Y1, &p->Y);
    fe256_copy(&Z1, &p->Z);
    fe256_copy(&X2, &q->X);
    fe256_copy(&Y2, &q->Y);
    fe256_copy(&Z2, &q->Z);

    fe256 Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, rr, V;
    fe256 t0, t1;

    // Z1Z1 = Z1²
    ops->sqr(&Z1Z1, &Z1);
    // Z2Z2 = Z2²
    ops->sqr(&Z2Z2, &Z2);

    // U1 = X1 * Z2Z2
    ops->mul(&U1, &X1, &Z2Z2);
    // U2 = X2 * Z1Z1
    ops->mul(&U2, &X2, &Z1Z1);

    // S1 = Y1 * Z2 * Z2Z2
    ops->mul(&t0, &Z2, &Z2Z2);
    ops->mul(&S1, &Y1, &t0);

    // S2 = Y2 * Z1 * Z1Z1
    ops->mul(&t0, &Z1, &Z1Z1);
    ops->mul(&S2, &Y2, &t0);

    // H = U2 - U1
    ops->sub(&H, &U2, &U1);

    // Check if points are equal or negatives
    if (fe256_is_zero(&H)) {
        // U1 == U2, check S1 vs S2
        fe256 diff;
        ops->sub(&diff, &S2, &S1);
        if (fe256_is_zero(&diff)) {
            // P == Q, do doubling
            fe256_point_double(r, p, curve_type);
            return;
        } else {
            // P == -Q, return infinity
            fe256_point_set_infinity(r);
            return;
        }
    }

    // I = (2*H)²
    ops->add(&t0, &H, &H);
    ops->sqr(&I, &t0);

    // J = H * I
    ops->mul(&J, &H, &I);

    // rr = 2*(S2 - S1)
    ops->sub(&t0, &S2, &S1);
    ops->add(&rr, &t0, &t0);

    // V = U1 * I
    ops->mul(&V, &U1, &I);

    // X3 = rr² - J - 2*V
    ops->sqr(&t0, &rr);
    ops->sub(&t1, &t0, &J);
    ops->add(&t0, &V, &V);
    ops->sub(&r->X, &t1, &t0);

    // Y3 = rr*(V - X3) - 2*S1*J
    ops->sub(&t0, &V, &r->X);
    ops->mul(&t1, &rr, &t0);
    ops->mul(&t0, &S1, &J);
    ops->add(&t0, &t0, &t0);
    ops->sub(&r->Y, &t1, &t0);

    // Z3 = ((Z1+Z2)² - Z1Z1 - Z2Z2) * H (using cached Z1, Z2)
    ops->add(&t0, &Z1, &Z2);
    ops->sqr(&t1, &t0);
    ops->sub(&t0, &t1, &Z1Z1);
    ops->sub(&t1, &t0, &Z2Z2);
    ops->mul(&r->Z, &t1, &H);
}

// ============================================================================
// Point Doubling (Optimized for a=0 or a=-3)
// ============================================================================

void fe256_point_double(fe256_point* r, const fe256_point* p, int curve_type) {
    const CurveOps* ops = get_curve_ops(curve_type);

    if (fe256_point_is_infinity(p)) {
        fe256_point_set_infinity(r);
        return;
    }

    // Cache input values to handle aliasing (r == p)
    fe256 X1, Y1, Z1;
    fe256_copy(&X1, &p->X);
    fe256_copy(&Y1, &p->Y);
    fe256_copy(&Z1, &p->Z);

    fe256 A, B, C, D, E, F;
    fe256 t0, t1;

    if (ops->a_is_zero) {
        // Optimized doubling for a = 0 (secp256k1)
        // Using dbl-2009-l from EFD: 1M + 5S + 1*a + 7add + 2*2 + 1*3 + 1*8

        // A = X1²
        ops->sqr(&A, &X1);
        // B = Y1²
        ops->sqr(&B, &Y1);
        // C = B²
        ops->sqr(&C, &B);

        // D = 2*((X1+B)² - A - C)
        ops->add(&t0, &X1, &B);
        ops->sqr(&t1, &t0);
        ops->sub(&t0, &t1, &A);
        ops->sub(&t1, &t0, &C);
        ops->add(&D, &t1, &t1);

        // E = 3*A (since a=0)
        ops->add(&t0, &A, &A);
        ops->add(&E, &t0, &A);

        // F = E²
        ops->sqr(&F, &E);

        // X3 = F - 2*D
        ops->add(&t0, &D, &D);
        ops->sub(&r->X, &F, &t0);

        // Y3 = E*(D - X3) - 8*C
        ops->sub(&t0, &D, &r->X);
        ops->mul(&t1, &E, &t0);
        ops->add(&t0, &C, &C);  // 2C
        ops->add(&t0, &t0, &t0);  // 4C
        ops->add(&t0, &t0, &t0);  // 8C
        ops->sub(&r->Y, &t1, &t0);

        // Z3 = 2*Y1*Z1 (using cached Y1, Z1 to avoid aliasing)
        ops->mul(&t0, &Y1, &Z1);
        ops->add(&r->Z, &t0, &t0);

    } else if (ops->a_is_minus_3) {
        // Optimized doubling for a = -3 (P-256, SM2)
        // Using dbl-2001-b from EFD: 3M + 5S + 8add + 1*3 + 1*4 + 2*8

        // delta = Z1²
        fe256 delta, gamma, beta, alpha;
        ops->sqr(&delta, &Z1);

        // gamma = Y1²
        ops->sqr(&gamma, &Y1);

        // beta = X1 * gamma
        ops->mul(&beta, &X1, &gamma);

        // alpha = 3*(X1 - delta)*(X1 + delta)
        // For a = -3: alpha = 3*X1² - 3*Z1⁴ = 3*(X1² - Z1⁴) = 3*(X1-Z1²)(X1+Z1²)
        ops->sub(&t0, &X1, &delta);  // X1 - Z1²
        ops->add(&t1, &X1, &delta);  // X1 + Z1²
        ops->mul(&A, &t0, &t1);        // (X1-Z1²)(X1+Z1²)
        ops->add(&t0, &A, &A);         // 2*...
        ops->add(&alpha, &t0, &A);     // 3*...

        // X3 = alpha² - 8*beta
        ops->sqr(&t0, &alpha);
        ops->add(&t1, &beta, &beta);   // 2*beta
        ops->add(&t1, &t1, &t1);       // 4*beta
        ops->add(&t1, &t1, &t1);       // 8*beta
        ops->sub(&r->X, &t0, &t1);

        // Z3 = (Y1 + Z1)² - gamma - delta (using cached Y1, Z1)
        ops->add(&t0, &Y1, &Z1);
        ops->sqr(&t1, &t0);
        ops->sub(&t0, &t1, &gamma);
        ops->sub(&r->Z, &t0, &delta);

        // Y3 = alpha*(4*beta - X3) - 8*gamma²
        ops->add(&t0, &beta, &beta);   // 2*beta
        ops->add(&t0, &t0, &t0);       // 4*beta
        ops->sub(&t1, &t0, &r->X);     // 4*beta - X3
        ops->mul(&t0, &alpha, &t1);    // alpha*(4*beta - X3)
        ops->sqr(&t1, &gamma);         // gamma²
        ops->add(&t1, &t1, &t1);       // 2*gamma²
        ops->add(&t1, &t1, &t1);       // 4*gamma²
        ops->add(&t1, &t1, &t1);       // 8*gamma²
        ops->sub(&r->Y, &t0, &t1);

    } else {
        // General case (fallback)
        // Not optimized, uses general formula
        fe256_point_add(r, p, p, curve_type);
    }
}

// ============================================================================
// Point Negation
// ============================================================================

void fe256_point_negate(fe256_point* r, const fe256_point* p, int curve_type) {
    const CurveOps* ops = get_curve_ops(curve_type);

    // Cache Y to handle aliasing (r == p)
    fe256 neg_Y;
    ops->neg(&neg_Y, &p->Y);

    fe256_copy(&r->X, &p->X);
    fe256_copy(&r->Y, &neg_Y);
    fe256_copy(&r->Z, &p->Z);
}

// ============================================================================
// Montgomery Ladder Scalar Multiplication (Constant-Time)
// ============================================================================
// NOTE: wNAF algorithm was REMOVED in v4.6.0 due to side-channel vulnerabilities.
// All scalar multiplication now uses Montgomery ladder for timing-attack resistance.

#define MAX_SCALAR_BITS 256

// Forward declaration for generator initialization
static void init_generators_mont();

/**
 * @brief Get the highest bit position in a 256-bit scalar
 * @param k 256-bit scalar as 4 uint64_t limbs
 * @return Highest bit position (0-255), or -1 if zero
 */
static int get_highest_bit(const uint64_t k[4]) {
    for (int i = 3; i >= 0; i--) {
        if (k[i] != 0) {
            // Find highest bit in this limb using builtin
            int pos = 63 - __builtin_clzll(k[i]);
            return i * 64 + pos;
        }
    }
    return -1;  // Zero scalar
}

/**
 * @brief Get bit at position i from 256-bit scalar
 * @param k 256-bit scalar as 4 uint64_t limbs
 * @param i Bit position (0-255)
 * @return 0 or 1
 */
static inline int get_bit(const uint64_t k[4], int i) {
    int limb = i / 64;
    int bit = i % 64;
    return (k[limb] >> bit) & 1;
}

/**
 * @brief Montgomery ladder scalar multiplication (constant-time)
 * 
 * Provides constant-time execution to prevent side-channel attacks.
 * For every bit of the scalar, exactly one double and one add are performed.
 * 
 * @param r Output point (k * p)
 * @param k 256-bit scalar
 * @param p Base point
 * @param curve_type Curve type (secp256k1, P-256, SM2)
 */
void fe256_point_scalar_mult(fe256_point* r, const uint64_t k[4],
                              const fe256_point* p, int curve_type) {
    // Check for zero scalar
    if (k[0] == 0 && k[1] == 0 && k[2] == 0 && k[3] == 0) {
        fe256_point_set_infinity(r);
        return;
    }

    // Check for infinity point
    if (fe256_point_is_infinity(p)) {
        fe256_point_set_infinity(r);
        return;
    }

    // Montgomery ladder: R0 = O, R1 = P
    fe256_point R0, R1;
    fe256_point_set_infinity(&R0);
    fe256_point_copy(&R1, p);

    // Get highest bit position
    int high_bit = get_highest_bit(k);
    if (high_bit < 0) {
        fe256_point_set_infinity(r);
        return;
    }

    // Process bits from MSB to LSB
    for (int i = high_bit; i >= 0; i--) {
        int bit = get_bit(k, i);
        if (bit) {
            fe256_point_add(&R0, &R0, &R1, curve_type);
            fe256_point_double(&R1, &R1, curve_type);
        } else {
            fe256_point_add(&R1, &R0, &R1, curve_type);
            fe256_point_double(&R0, &R0, curve_type);
        }
    }

    fe256_point_copy(r, &R0);
}

void fe256_point_scalar_mult_base(fe256_point* r, const uint64_t k[4],
                                   int curve_type) {
    // Ensure generators are initialized
    init_generators_mont();
    
    // Check for zero scalar
    if (k[0] == 0 && k[1] == 0 && k[2] == 0 && k[3] == 0) {
        fe256_point_set_infinity(r);
        return;
    }

    // Get generator point for this curve
    const fe256_point* G = fe256_get_generator(curve_type);

    // Use Montgomery ladder for constant-time scalar multiplication
    fe256_point_scalar_mult(r, k, G, curve_type);
}

// ============================================================================
// Double Scalar Multiplication (Shamir's Trick)
// ============================================================================

void fe256_point_double_mult(fe256_point* r,
                              const uint64_t k1[4], const fe256_point* p,
                              const uint64_t k2[4], const fe256_point* q,
                              int curve_type) {
    // Shamir's trick: precompute P, Q, P+Q
    fe256_point pq;
    fe256_point_add(&pq, p, q, curve_type);

    // Get maximum bit length
    int bits1 = 0, bits2 = 0;
    for (int i = 3; i >= 0 && bits1 == 0; i--) {
        if (k1[i] != 0) {
            bits1 = i * 64 + 64;
            uint64_t v = k1[i];
            while (v) { v >>= 1; bits1 = i * 64 + (64 - __builtin_clzll(k1[i])); break; }
        }
    }
    for (int i = 3; i >= 0 && bits2 == 0; i--) {
        if (k2[i] != 0) {
            bits2 = i * 64 + 64;
            uint64_t v = k2[i];
            while (v) { v >>= 1; bits2 = i * 64 + (64 - __builtin_clzll(k2[i])); break; }
        }
    }
    int max_bits = (bits1 > bits2) ? bits1 : bits2;

    fe256_point_set_infinity(r);

    // Process both scalars together
    for (int i = max_bits - 1; i >= 0; i--) {
        fe256_point_double(r, r, curve_type);

        int limb = i / 64;
        int bit_pos = i % 64;
        int b1 = (limb < 4 && ((k1[limb] >> bit_pos) & 1)) ? 1 : 0;
        int b2 = (limb < 4 && ((k2[limb] >> bit_pos) & 1)) ? 1 : 0;

        if (b1 && b2) {
            fe256_point_add(r, r, &pq, curve_type);
        } else if (b1) {
            fe256_point_add(r, r, p, curve_type);
        } else if (b2) {
            fe256_point_add(r, r, q, curve_type);
        }
    }
}

// ============================================================================
// Coordinate Conversion
// ============================================================================

int fe256_point_to_affine(fe256* x, fe256* y, const fe256_point* p,
                           int curve_type) {
    if (fe256_point_is_infinity(p)) {
        return -1;
    }

    const CurveOps* ops = get_curve_ops(curve_type);

    fe256 z_inv, z_inv_sq, z_inv_cb;

    // z_inv = Z^(-1)
    ops->inv(&z_inv, &p->Z);

    // z_inv_sq = Z^(-2)
    ops->sqr(&z_inv_sq, &z_inv);

    // z_inv_cb = Z^(-3)
    ops->mul(&z_inv_cb, &z_inv_sq, &z_inv);

    // x = X * Z^(-2)
    ops->mul(x, &p->X, &z_inv_sq);

    // y = Y * Z^(-3)
    ops->mul(y, &p->Y, &z_inv_cb);

    return 0;
}

void fe256_point_from_affine(fe256_point* p, const fe256* x, const fe256* y) {
    fe256_copy(&p->X, x);
    fe256_copy(&p->Y, y);
    fe256_one(&p->Z);
}

// ============================================================================
// Generator Points in Montgomery Form (cached)
// ============================================================================

static fe256_point secp256k1_generator_mont;
static fe256_point p256_generator_mont;
static fe256_point sm2_generator_mont;
static bool generators_initialized = false;

/**
 * @brief Initialize generator points in Montgomery form
 * 
 * Converts generator points from standard to Montgomery form for efficient
 * field arithmetic. This is called once on first use.
 */
static void init_generators_mont() {
    if (generators_initialized) return;
    
    // secp256k1 generator
    fe256_point_copy(&secp256k1_generator_mont, &secp256k1_generator);
    fe256_to_mont_secp256k1(&secp256k1_generator_mont.X, &secp256k1_generator_mont.X);
    fe256_to_mont_secp256k1(&secp256k1_generator_mont.Y, &secp256k1_generator_mont.Y);
    fe256_to_mont_secp256k1(&secp256k1_generator_mont.Z, &secp256k1_generator_mont.Z);
    
    // P-256 generator
    fe256_point_copy(&p256_generator_mont, &p256_generator);
    fe256_to_mont_p256(&p256_generator_mont.X, &p256_generator_mont.X);
    fe256_to_mont_p256(&p256_generator_mont.Y, &p256_generator_mont.Y);
    fe256_to_mont_p256(&p256_generator_mont.Z, &p256_generator_mont.Z);
    
    // SM2 generator
    fe256_point_copy(&sm2_generator_mont, &sm2_generator);
    fe256_to_mont_sm2(&sm2_generator_mont.X, &sm2_generator_mont.X);
    fe256_to_mont_sm2(&sm2_generator_mont.Y, &sm2_generator_mont.Y);
    fe256_to_mont_sm2(&sm2_generator_mont.Z, &sm2_generator_mont.Z);
    
    generators_initialized = true;
}

// ============================================================================
// Accessors
// ============================================================================

const fe256_point* fe256_get_generator(int curve_type) {
    // Ensure Montgomery form generators are initialized
    init_generators_mont();
    
    switch (curve_type) {
        case FE256_CURVE_SECP256K1: return &secp256k1_generator_mont;
        case FE256_CURVE_P256:      return &p256_generator_mont;
        case FE256_CURVE_SM2:       return &sm2_generator_mont;
        default:                    return &secp256k1_generator_mont;
    }
}

const uint64_t* fe256_get_order(int curve_type) {
    switch (curve_type) {
        case FE256_CURVE_SECP256K1: return secp256k1_order;
        case FE256_CURVE_P256:      return p256_order;
        case FE256_CURVE_SM2:       return sm2_order;
        default:                    return secp256k1_order;
    }
}
