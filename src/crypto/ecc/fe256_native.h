/**
 * @file fe256_native.h
 * @brief Pure Native 256-bit Field Element Operations
 * 
 * Self-contained implementation with NO external dependencies.
 * Zero NTL/ZZ overhead - pure fixed-size arithmetic.
 * 
 * Features:
 * - 4 x 64-bit limb representation (256-bit)
 * - Montgomery multiplication for all curves
 * - Constant-time operations for side-channel resistance
 * - Hardware acceleration via __int128 on GCC/Clang
 * 
 * Supported curves:
 * - secp256k1 (a = 0)
 * - P-256/secp256r1 (a = -3)
 * - SM2 (a = -3)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_FE256_NATIVE_H
#define KCTSB_FE256_NATIVE_H

#include <cstdint>
#include <cstring>
#include <array>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace kctsb {
namespace ecc {
namespace native {

// ============================================================================
// 128-bit Arithmetic Helpers
// ============================================================================

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    uint128_t product = (uint128_t)a * b;
    *lo = (uint64_t)product;
    *hi = (uint64_t)(product >> 64);
}

static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t c_in, uint64_t* c_out) {
    uint128_t sum = (uint128_t)a + b + c_in;
    *c_out = (uint64_t)(sum >> 64);
    return (uint64_t)sum;
}

static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t b_in, uint64_t* b_out) {
    uint128_t diff = (uint128_t)a - b - b_in;
    *b_out = (diff >> 64) != 0 ? 1 : 0;
    return (uint64_t)diff;
}

#elif defined(_MSC_VER) && defined(_M_X64)

static inline void mul64x64(uint64_t a, uint64_t b, uint64_t* hi, uint64_t* lo) {
    *lo = _umul128(a, b, hi);
}

static inline uint64_t adc64(uint64_t a, uint64_t b, uint64_t c_in, uint64_t* c_out) {
    unsigned char c = 0;
    uint64_t sum;
    c = _addcarry_u64((unsigned char)c_in, a, b, &sum);
    *c_out = c;
    return sum;
}

static inline uint64_t sbb64(uint64_t a, uint64_t b, uint64_t b_in, uint64_t* b_out) {
    unsigned char c = 0;
    uint64_t diff;
    c = _subborrow_u64((unsigned char)b_in, a, b, &diff);
    *b_out = c;
    return diff;
}

#else
#error "Require 128-bit arithmetic support (__int128 or MSVC intrinsics)"
#endif

// ============================================================================
// Fe256 - 256-bit Field Element (4 x 64-bit limbs, little-endian)
// ============================================================================

struct alignas(32) Fe256 {
    uint64_t d[4];  // d[0] = LSW, d[3] = MSW
    
    Fe256() { d[0] = d[1] = d[2] = d[3] = 0; }
    Fe256(uint64_t v) { d[0] = v; d[1] = d[2] = d[3] = 0; }
    Fe256(uint64_t d0, uint64_t d1, uint64_t d2, uint64_t d3) {
        d[0] = d0; d[1] = d1; d[2] = d2; d[3] = d3;
    }
    
    bool is_zero() const {
        return (d[0] | d[1] | d[2] | d[3]) == 0;
    }
    
    bool operator==(const Fe256& other) const {
        return d[0] == other.d[0] && d[1] == other.d[1] &&
               d[2] == other.d[2] && d[3] == other.d[3];
    }
    
    static Fe256 from_bytes_be(const uint8_t* in);
    void to_bytes_be(uint8_t* out) const;
};

// ============================================================================
// Curve Constants (All in Montgomery domain where applicable)
// ============================================================================

enum class CurveId {
    SECP256K1,
    P256,
    SM2
};

// Curve parameter structure
struct CurveParams {
    Fe256 p;           // Field prime
    Fe256 n;           // Curve order
    Fe256 R2;          // R^2 mod p for Montgomery conversion
    Fe256 R2_n;        // R^2 mod n for scalar Montgomery
    uint64_t n0_p;     // -p^(-1) mod 2^64
    uint64_t n0_n;     // -n^(-1) mod 2^64
    Fe256 Gx;          // Generator X (Montgomery)
    Fe256 Gy;          // Generator Y (Montgomery)
    Fe256 a;           // Curve parameter a (Montgomery), or zero
    Fe256 b;           // Curve parameter b (Montgomery)
    int a_is_zero;     // Optimization: a = 0 (secp256k1)
    int a_is_minus_3;  // Optimization: a = -3 (P-256, SM2)
};

extern const CurveParams SECP256K1_PARAMS;
extern const CurveParams P256_PARAMS;
extern const CurveParams SM2_PARAMS;

const CurveParams* get_curve_params(CurveId id);

// ============================================================================
// Fe256 Field Arithmetic (Generic - uses curve params)
// ============================================================================

void fe256_add(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* p);
void fe256_sub(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* p);
void fe256_neg(Fe256* r, const Fe256* a, const Fe256* p);
void fe256_mul_mont(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* p, uint64_t n0);
void fe256_sqr_mont(Fe256* r, const Fe256* a, const Fe256* p, uint64_t n0);
void fe256_inv(Fe256* r, const Fe256* a, const Fe256* p, uint64_t n0);
void fe256_to_mont(Fe256* r, const Fe256* a, const Fe256* R2, const Fe256* p, uint64_t n0);
void fe256_from_mont(Fe256* r, const Fe256* a, const Fe256* p, uint64_t n0);

// Compare: returns -1, 0, or 1
int fe256_cmp(const Fe256* a, const Fe256* b);

// Constant-time conditional move: r = cond ? a : r
void fe256_cmov(Fe256* r, const Fe256* a, uint64_t cond);

// ============================================================================
// Jacobian Point
// ============================================================================

struct Fe256Point {
    Fe256 X, Y, Z;
    int is_infinity;
    
    Fe256Point() : is_infinity(1) {}
    Fe256Point(const Fe256& x, const Fe256& y, const Fe256& z, int inf = 0)
        : X(x), Y(y), Z(z), is_infinity(inf) {}
};

// ============================================================================
// Point Operations (uses CurveParams)
// ============================================================================

void point_double(Fe256Point* r, const Fe256Point* p, const CurveParams* curve);
void point_add(Fe256Point* r, const Fe256Point* p, const Fe256Point* q, const CurveParams* curve);
void point_neg(Fe256Point* r, const Fe256Point* p, const CurveParams* curve);

// Constant-time scalar multiplication using Montgomery ladder
void scalar_mult(Fe256Point* r, const Fe256* k, const Fe256Point* p, const CurveParams* curve);
void scalar_mult_base(Fe256Point* r, const Fe256* k, const CurveParams* curve);

// Double scalar multiplication: r = k1*G + k2*P (for ECDSA verify)
void double_scalar_mult(Fe256Point* r, const Fe256* k1, const Fe256* k2, 
                        const Fe256Point* p, const CurveParams* curve);

// Constant-time point swap
void point_cswap(Fe256Point* a, Fe256Point* b, uint64_t swap);

// Convert Jacobian to Affine (X, Y) by computing X/Z^2, Y/Z^3
void point_to_affine(Fe256* x, Fe256* y, const Fe256Point* p, const CurveParams* curve);

// ============================================================================
// Scalar Modular Arithmetic (mod n, for ECDSA)
// ============================================================================

void scalar_add(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* n);
void scalar_sub(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* n);
void scalar_mul_mont(Fe256* r, const Fe256* a, const Fe256* b, const Fe256* n, uint64_t n0);
void scalar_inv(Fe256* r, const Fe256* a, const Fe256* n, uint64_t n0);
void scalar_reduce(Fe256* r, const uint8_t* hash, size_t hash_len, const Fe256* n);

// ============================================================================
// High-Level ECDSA Operations (Pure Native)
// ============================================================================

struct EcdsaSignature {
    Fe256 r;
    Fe256 s;
};

struct EcdsaKeyPair {
    Fe256 private_key;       // Scalar (not Montgomery)
    Fe256Point public_key;   // In Montgomery domain
};

// Key generation
void ecdsa_keygen(EcdsaKeyPair* kp, const uint8_t* random32, CurveId curve_id);

// Sign: returns 0 on success
int ecdsa_sign(EcdsaSignature* sig, const uint8_t* hash, size_t hash_len,
               const Fe256* private_key, const uint8_t* k32, CurveId curve_id);

// Verify: returns 0 if valid
int ecdsa_verify(const EcdsaSignature* sig, const uint8_t* hash, size_t hash_len,
                 const Fe256Point* public_key, CurveId curve_id);

// ============================================================================
// High-Level ECDH Operations (Pure Native)
// ============================================================================

// Compute shared secret: x-coordinate of k*P
int ecdh_compute(uint8_t* shared_secret, const Fe256* private_key,
                 const Fe256Point* peer_public, CurveId curve_id);

} // namespace native
} // namespace ecc
} // namespace kctsb

#endif // KCTSB_FE256_NATIVE_H
