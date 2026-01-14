/**
 * @file ecc_impl.h
 * @brief Elliptic Curve Cryptography Implementation - NTL-based
 * 
 * Native ECC implementation using NTL (Number Theory Library).
 * Replaces MIRACL dependency with pure C/C++ + NTL implementation.
 * 
 * Supported curves:
 * - secp256k1 (Bitcoin)
 * - secp256r1 (NIST P-256)
 * - secp384r1 (NIST P-384)
 * - secp521r1 (NIST P-521)
 * - SM2 (Chinese National Standard)
 * 
 * Security features:
 * - Constant-time scalar multiplication
 * - Side-channel resistant point operations
 * - Secure memory handling
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_INTERNAL_ECC_IMPL_H
#define KCTSB_INTERNAL_ECC_IMPL_H

#include "kctsb/core/common.h"

#ifdef KCTSB_HAS_NTL
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>

namespace kctsb {
namespace ecc {

using NTL::ZZ;
using NTL::ZZ_p;

/**
 * @brief Elliptic curve parameters
 * 
 * Defines a curve in short Weierstrass form: y^2 = x^3 + ax + b (mod p)
 */
struct CurveParams {
    ZZ p;       // Prime modulus
    ZZ a;       // Curve coefficient a
    ZZ b;       // Curve coefficient b
    ZZ n;       // Order of the base point
    ZZ h;       // Cofactor
    ZZ Gx;      // Base point x-coordinate
    ZZ Gy;      // Base point y-coordinate
    const char* name;
};

/**
 * @brief Affine point representation
 */
struct AffinePoint {
    ZZ_p x;
    ZZ_p y;
    bool is_infinity;
    
    AffinePoint() : is_infinity(true) {}
    AffinePoint(const ZZ_p& x_, const ZZ_p& y_) : x(x_), y(y_), is_infinity(false) {}
};

/**
 * @brief Jacobian projective point (X:Y:Z) where x=X/Z^2, y=Y/Z^3
 * 
 * Using Jacobian coordinates for faster point addition and doubling.
 */
struct JacobianPoint {
    ZZ_p X;
    ZZ_p Y;
    ZZ_p Z;
    
    JacobianPoint() {
        X = ZZ_p(0);
        Y = ZZ_p(1);
        Z = ZZ_p(0);
    }
    
    JacobianPoint(const ZZ_p& x, const ZZ_p& y) : X(x), Y(y) {
        Z = ZZ_p(1);
    }
    
    bool is_infinity() const {
        return IsZero(Z);
    }
};

/**
 * @brief Elliptic Curve class with NTL implementation
 */
class EllipticCurve {
public:
    /**
     * @brief Construct curve from parameters
     */
    explicit EllipticCurve(const CurveParams& params);
    
    /**
     * @brief Get standard curve by name
     */
    static EllipticCurve from_name(const char* name);
    
    /**
     * @brief Check if point is on curve
     */
    bool is_on_curve(const AffinePoint& P) const;
    bool is_on_curve(const JacobianPoint& P) const;
    
    /**
     * @brief Point addition: R = P + Q
     */
    JacobianPoint add(const JacobianPoint& P, const JacobianPoint& Q) const;
    
    /**
     * @brief Point doubling: R = 2P
     */
    JacobianPoint double_point(const JacobianPoint& P) const;
    
    /**
     * @brief Scalar multiplication: R = k * P
     * 
     * Uses Montgomery ladder for constant-time execution.
     */
    JacobianPoint scalar_mult(const ZZ& k, const JacobianPoint& P) const;
    
    /**
     * @brief Scalar multiplication with base point: R = k * G
     */
    JacobianPoint scalar_mult_base(const ZZ& k) const;
    
    /**
     * @brief Convert Jacobian to Affine coordinates
     */
    AffinePoint to_affine(const JacobianPoint& P) const;
    
    /**
     * @brief Convert Affine to Jacobian coordinates
     */
    JacobianPoint to_jacobian(const AffinePoint& P) const;
    
    /**
     * @brief Get the base point G
     */
    const JacobianPoint& get_base_point() const { return G_; }
    
    /**
     * @brief Get the curve order n
     */
    const ZZ& get_order() const { return n_; }
    
    /**
     * @brief Get the prime p
     */
    const ZZ& get_prime() const { return p_; }
    
    /**
     * @brief Point negation: -P
     */
    JacobianPoint negate(const JacobianPoint& P) const;
    
private:
    ZZ p_;          // Prime modulus
    ZZ_p a_;        // Curve coefficient a
    ZZ_p b_;        // Curve coefficient b
    ZZ n_;          // Order
    ZZ h_;          // Cofactor
    JacobianPoint G_; // Base point in Jacobian form
    
    /**
     * @brief Montgomery ladder scalar multiplication (constant-time)
     */
    JacobianPoint montgomery_ladder(const ZZ& k, const JacobianPoint& P) const;
};

// ============================================================================
// Standard Curve Parameters
// ============================================================================

/**
 * @brief secp256k1 curve parameters (Bitcoin)
 */
inline CurveParams secp256k1_params() {
    CurveParams p;
    p.p = NTL::conv<ZZ>("115792089237316195423570985008687907853269984665640564039457584007908834671663");
    p.a = ZZ(0);
    p.b = ZZ(7);
    p.n = NTL::conv<ZZ>("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    p.h = ZZ(1);
    p.Gx = NTL::conv<ZZ>("55066263022277343669578718895168534326250603453777594175500187360389116729240");
    p.Gy = NTL::conv<ZZ>("32670510020758816978083085130507043184471273380659243275938904335757337482424");
    p.name = "secp256k1";
    return p;
}

/**
 * @brief secp256r1/P-256 curve parameters (NIST)
 */
inline CurveParams secp256r1_params() {
    CurveParams p;
    p.p = NTL::conv<ZZ>("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    p.a = NTL::conv<ZZ>("115792089210356248762697446949407573530086143415290314195533631308867097853948");
    p.b = NTL::conv<ZZ>("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    p.n = NTL::conv<ZZ>("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    p.h = ZZ(1);
    p.Gx = NTL::conv<ZZ>("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    p.Gy = NTL::conv<ZZ>("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    p.name = "secp256r1";
    return p;
}

/**
 * @brief SM2 curve parameters (Chinese National Standard)
 */
inline CurveParams sm2_params() {
    CurveParams p;
    p.p = NTL::conv<ZZ>("115792089210356248756420345214020892766250353991924191454421193933289684991999");
    p.a = NTL::conv<ZZ>("115792089210356248756420345214020892766250353991924191454421193933289684991996");
    p.b = NTL::conv<ZZ>("18505919022281880113072981827955639221458448578012075254857346196103069175443");
    p.n = NTL::conv<ZZ>("115792089210356248756420345214020892766061623724957744567843809356293439045923");
    p.h = ZZ(1);
    p.Gx = NTL::conv<ZZ>("22963146547237050559479531362550074578802567295341616970375194840604139615431");
    p.Gy = NTL::conv<ZZ>("85132369209828568825618990617112496413088388631904505083283536607588877201568");
    p.name = "SM2";
    return p;
}

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_HAS_NTL

#endif /* KCTSB_INTERNAL_ECC_IMPL_H */
