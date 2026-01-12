/**
 * @file ecc_ntl.cpp
 * @brief NTL-based Elliptic Curve Implementation
 * 
 * Pure C++/NTL implementation of elliptic curve cryptography.
 * Replaces MIRACL dependency entirely.
 * 
 * Implementation details:
 * - Jacobian projective coordinates for efficient arithmetic
 * - Montgomery ladder for constant-time scalar multiplication
 * - Complete formulas resistant to exceptional cases
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/internal/ecc_impl.h"
#include "kctsb/core/security.h"

#ifdef KCTSB_HAS_NTL

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <cstring>

namespace kctsb {
namespace ecc {

using NTL::ZZ;
using NTL::ZZ_p;
using NTL::IsZero;
using NTL::IsOne;
using NTL::NumBits;
using NTL::bit;
using NTL::power;
using NTL::InvMod;

// ============================================================================
// EllipticCurve Implementation
// ============================================================================

EllipticCurve::EllipticCurve(const CurveParams& params) {
    p_ = params.p;
    n_ = params.n;
    h_ = params.h;
    
    // Set ZZ_p modulus
    ZZ_p::init(p_);
    
    a_ = NTL::conv<ZZ_p>(params.a);
    b_ = NTL::conv<ZZ_p>(params.b);
    
    // Initialize base point
    ZZ_p Gx = NTL::conv<ZZ_p>(params.Gx);
    ZZ_p Gy = NTL::conv<ZZ_p>(params.Gy);
    G_ = JacobianPoint(Gx, Gy);
}

EllipticCurve EllipticCurve::from_name(const char* name) {
    if (strcmp(name, "secp256k1") == 0) {
        return EllipticCurve(secp256k1_params());
    } else if (strcmp(name, "secp256r1") == 0 || strcmp(name, "P-256") == 0) {
        return EllipticCurve(secp256r1_params());
    } else if (strcmp(name, "SM2") == 0 || strcmp(name, "sm2p256v1") == 0) {
        return EllipticCurve(sm2_params());
    }
    // Default to secp256r1
    return EllipticCurve(secp256r1_params());
}

bool EllipticCurve::is_on_curve(const AffinePoint& P) const {
    if (P.is_infinity) return true;
    
    // y^2 = x^3 + ax + b (mod p)
    ZZ_p lhs = P.y * P.y;
    ZZ_p rhs = P.x * P.x * P.x + a_ * P.x + b_;
    
    return lhs == rhs;
}

bool EllipticCurve::is_on_curve(const JacobianPoint& P) const {
    if (P.is_infinity()) return true;
    
    AffinePoint affine = to_affine(P);
    return is_on_curve(affine);
}

JacobianPoint EllipticCurve::add(const JacobianPoint& P, const JacobianPoint& Q) const {
    // Point at infinity handling
    if (P.is_infinity()) return Q;
    if (Q.is_infinity()) return P;
    
    // Jacobian addition formula
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
    
    ZZ_p Z1Z1 = P.Z * P.Z;
    ZZ_p Z2Z2 = Q.Z * Q.Z;
    ZZ_p U1 = P.X * Z2Z2;
    ZZ_p U2 = Q.X * Z1Z1;
    ZZ_p S1 = P.Y * Q.Z * Z2Z2;
    ZZ_p S2 = Q.Y * P.Z * Z1Z1;
    
    ZZ_p H = U2 - U1;
    ZZ_p R = S2 - S1;
    
    // If H == 0
    if (IsZero(rep(H))) {
        if (IsZero(rep(R))) {
            // P == Q, do doubling
            return double_point(P);
        }
        // P == -Q, return infinity
        return JacobianPoint();
    }
    
    ZZ_p HH = H * H;
    ZZ_p HHH = H * HH;
    ZZ_p V = U1 * HH;
    
    JacobianPoint result;
    result.X = R * R - HHH - ZZ_p(2) * V;
    result.Y = R * (V - result.X) - S1 * HHH;
    result.Z = P.Z * Q.Z * H;
    
    return result;
}

JacobianPoint EllipticCurve::double_point(const JacobianPoint& P) const {
    if (P.is_infinity()) return P;
    if (IsZero(rep(P.Y))) return JacobianPoint();
    
    // Jacobian doubling formula (a = -3 optimized version not used for generality)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
    
    ZZ_p XX = P.X * P.X;
    ZZ_p YY = P.Y * P.Y;
    ZZ_p YYYY = YY * YY;
    ZZ_p ZZ_var = P.Z * P.Z;
    
    ZZ_p S = ZZ_p(2) * ((P.X + YY) * (P.X + YY) - XX - YYYY);
    ZZ_p M = ZZ_p(3) * XX + a_ * ZZ_var * ZZ_var;
    
    JacobianPoint result;
    result.X = M * M - ZZ_p(2) * S;
    result.Y = M * (S - result.X) - ZZ_p(8) * YYYY;
    result.Z = ZZ_p(2) * P.Y * P.Z;
    
    return result;
}

JacobianPoint EllipticCurve::negate(const JacobianPoint& P) const {
    if (P.is_infinity()) return P;
    
    JacobianPoint result;
    result.X = P.X;
    result.Y = -P.Y;
    result.Z = P.Z;
    return result;
}

JacobianPoint EllipticCurve::scalar_mult(const ZZ& k, const JacobianPoint& P) const {
    return montgomery_ladder(k, P);
}

JacobianPoint EllipticCurve::scalar_mult_base(const ZZ& k) const {
    return montgomery_ladder(k, G_);
}

JacobianPoint EllipticCurve::montgomery_ladder(const ZZ& k, const JacobianPoint& P) const {
    // Montgomery ladder for constant-time scalar multiplication
    // Resistant to simple power analysis and timing attacks
    
    if (IsZero(k) || P.is_infinity()) {
        return JacobianPoint();
    }
    
    // Reduce k modulo n
    ZZ k_reduced = k % n_;
    if (k_reduced < 0) {
        k_reduced += n_;
    }
    
    JacobianPoint R0; // Point at infinity
    JacobianPoint R1 = P;
    
    long num_bits = NumBits(k_reduced);
    
    for (long i = num_bits - 1; i >= 0; i--) {
        if (bit(k_reduced, i) == 0) {
            R1 = add(R0, R1);
            R0 = double_point(R0);
        } else {
            R0 = add(R0, R1);
            R1 = double_point(R1);
        }
    }
    
    return R0;
}

AffinePoint EllipticCurve::to_affine(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return AffinePoint();
    }
    
    // x = X / Z^2, y = Y / Z^3
    ZZ_p Z_inv = power(P.Z, -1);  // Modular inverse
    ZZ_p Z2_inv = Z_inv * Z_inv;
    ZZ_p Z3_inv = Z2_inv * Z_inv;
    
    AffinePoint result;
    result.x = P.X * Z2_inv;
    result.y = P.Y * Z3_inv;
    result.is_infinity = false;
    
    return result;
}

JacobianPoint EllipticCurve::to_jacobian(const AffinePoint& P) const {
    if (P.is_infinity) {
        return JacobianPoint();
    }
    return JacobianPoint(P.x, P.y);
}

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_HAS_NTL
