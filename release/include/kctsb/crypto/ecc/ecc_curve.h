/**
 * @file ecc_curve.h
 * @brief Elliptic Curve Definitions and Core Operations - NTL Implementation
 * 
 * This header provides complete elliptic curve definitions including:
 * - Standard curves (secp256k1, secp256r1/P-256, secp384r1/P-384, SM2)
 * - Point representation (Affine and Jacobian coordinates)
 * - Core point arithmetic operations
 * 
 * All operations use NTL (Number Theory Library) for arbitrary precision arithmetic.
 * Constant-time implementations protect against timing side-channel attacks.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_ECC_CURVE_H
#define KCTSB_CRYPTO_ECC_CURVE_H

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <string>
#include <cstring>
#include <memory>

namespace kctsb {
namespace ecc {

using NTL::ZZ;
using NTL::ZZ_p;

// ============================================================================
// Forward Declarations
// ============================================================================

struct CurveParams;
struct AffinePoint;
struct JacobianPoint;
class ECCurve;

// ============================================================================
// Curve Type Enumeration
// ============================================================================

/**
 * @brief Supported elliptic curve types
 */
enum class CurveType : int {
    SECP256K1 = 0,      // Bitcoin/Ethereum curve
    SECP256R1 = 1,      // NIST P-256
    SECP384R1 = 2,      // NIST P-384
    SECP521R1 = 3,      // NIST P-521
    SM2       = 4,      // Chinese National Standard
    CURVE25519 = 5,     // Montgomery curve for ECDH
    ED25519   = 6       // Edwards curve for signatures
};

// ============================================================================
// Curve Parameters
// ============================================================================

/**
 * @brief Elliptic curve parameters structure
 * 
 * Defines a curve in short Weierstrass form: y² = x³ + ax + b (mod p)
 */
struct CurveParams {
    ZZ p;               // Prime modulus
    ZZ a;               // Curve coefficient a
    ZZ b;               // Curve coefficient b
    ZZ n;               // Order of the base point G
    ZZ h;               // Cofactor (n * h = total curve order)
    ZZ Gx;              // Base point G x-coordinate
    ZZ Gy;              // Base point G y-coordinate
    std::string name;   // Curve name identifier
    int bit_size;       // Security level in bits
    
    CurveParams() : bit_size(0) {}
};

// ============================================================================
// Point Representations
// ============================================================================

/**
 * @brief Affine point representation (x, y)
 * 
 * Standard representation where coordinates are field elements.
 * Point at infinity is represented by is_infinity = true.
 */
struct AffinePoint {
    ZZ_p x;
    ZZ_p y;
    bool is_infinity;
    
    AffinePoint() : is_infinity(true) {}
    
    AffinePoint(const ZZ_p& x_, const ZZ_p& y_) 
        : x(x_), y(y_), is_infinity(false) {}
    
    bool operator==(const AffinePoint& other) const {
        if (is_infinity && other.is_infinity) return true;
        if (is_infinity || other.is_infinity) return false;
        return (x == other.x) && (y == other.y);
    }
    
    bool operator!=(const AffinePoint& other) const {
        return !(*this == other);
    }
};

/**
 * @brief Jacobian projective coordinates (X : Y : Z)
 * 
 * Represents point (x, y) as (X/Z², Y/Z³).
 * Point at infinity has Z = 0.
 * 
 * Jacobian coordinates provide faster addition and doubling
 * by avoiding costly field inversions.
 */
struct JacobianPoint {
    ZZ_p X;
    ZZ_p Y;
    ZZ_p Z;
    
    // Point at infinity (0 : 1 : 0)
    JacobianPoint() {
        X = ZZ_p(0);
        Y = ZZ_p(1);
        Z = ZZ_p(0);
    }
    
    // From affine coordinates
    JacobianPoint(const ZZ_p& x, const ZZ_p& y) : X(x), Y(y) {
        Z = ZZ_p(1);
    }
    
    // Full constructor
    JacobianPoint(const ZZ_p& X_, const ZZ_p& Y_, const ZZ_p& Z_)
        : X(X_), Y(Y_), Z(Z_) {}
    
    bool is_infinity() const {
        return IsZero(Z);
    }
    
    void set_infinity() {
        X = ZZ_p(0);
        Y = ZZ_p(1);
        Z = ZZ_p(0);
    }
};

// ============================================================================
// Elliptic Curve Class
// ============================================================================

/**
 * @brief Main elliptic curve class providing all operations
 * 
 * This class encapsulates curve parameters and provides:
 * - Point addition, doubling, negation
 * - Scalar multiplication (constant-time Montgomery ladder)
 * - Point validation
 * - Coordinate conversions
 */
class ECCurve {
public:
    /**
     * @brief Construct curve from parameters
     * @param params Curve parameters structure
     */
    explicit ECCurve(const CurveParams& params);
    
    /**
     * @brief Construct curve by type
     * @param type Predefined curve type
     */
    explicit ECCurve(CurveType type);
    
    /**
     * @brief Get curve by name string
     * @param name Curve name (e.g., "secp256k1", "P-256", "SM2")
     * @return ECCurve instance
     */
    static ECCurve from_name(const std::string& name);
    
    // ========================================================================
    // Getters
    // ========================================================================
    
    const ZZ& get_prime() const { return p_; }
    const ZZ& get_order() const { return n_; }
    const ZZ& get_cofactor() const { return h_; }
    const ZZ_p& get_a() const { return a_; }
    const ZZ_p& get_b() const { return b_; }
    const JacobianPoint& get_generator() const { return G_; }
    const std::string& get_name() const { return name_; }
    int get_bit_size() const { return bit_size_; }
    
    // ========================================================================
    // Point Validation
    // ========================================================================
    
    /**
     * @brief Check if affine point is on the curve
     * @param P Affine point to check
     * @return true if P is on the curve or is infinity
     */
    bool is_on_curve(const AffinePoint& P) const;
    
    /**
     * @brief Check if Jacobian point is on the curve
     * @param P Jacobian point to check
     * @return true if P is on the curve or is infinity
     */
    bool is_on_curve(const JacobianPoint& P) const;
    
    /**
     * @brief Validate point for cryptographic use
     * 
     * Checks:
     * 1. Point is on curve
     * 2. Point is in the correct subgroup (n*P = O)
     * 3. Point is not at infinity
     * 
     * @param P Point to validate
     * @return true if point is valid for crypto operations
     */
    bool validate_point(const JacobianPoint& P) const;
    
    // ========================================================================
    // Point Arithmetic
    // ========================================================================
    
    /**
     * @brief Point addition: R = P + Q
     * 
     * Uses unified addition formulas that handle:
     * - P = O (return Q)
     * - Q = O (return P)
     * - P = Q (performs doubling)
     * - P = -Q (returns O)
     * 
     * @param P First point
     * @param Q Second point
     * @return P + Q
     */
    JacobianPoint add(const JacobianPoint& P, const JacobianPoint& Q) const;
    
    /**
     * @brief Point doubling: R = 2P
     * @param P Point to double
     * @return 2P
     */
    JacobianPoint double_point(const JacobianPoint& P) const;
    
    /**
     * @brief Point negation: R = -P
     * @param P Point to negate
     * @return -P
     */
    JacobianPoint negate(const JacobianPoint& P) const;
    
    /**
     * @brief Point subtraction: R = P - Q
     * @param P First point
     * @param Q Second point
     * @return P - Q
     */
    JacobianPoint subtract(const JacobianPoint& P, const JacobianPoint& Q) const;
    
    // ========================================================================
    // Scalar Multiplication
    // ========================================================================
    
    /**
     * @brief Scalar multiplication: R = k * P
     * 
     * Uses Montgomery ladder for constant-time execution.
     * Resistant to simple power analysis and timing attacks.
     * 
     * @param k Scalar value
     * @param P Base point
     * @return k * P
     */
    JacobianPoint scalar_mult(const ZZ& k, const JacobianPoint& P) const;
    
    /**
     * @brief Scalar multiplication with generator: R = k * G
     * @param k Scalar value
     * @return k * G
     */
    JacobianPoint scalar_mult_base(const ZZ& k) const;
    
    /**
     * @brief Double scalar multiplication: R = k1*P + k2*Q
     * 
     * Uses Shamir's trick for efficiency.
     * 
     * @param k1 First scalar
     * @param P First point
     * @param k2 Second scalar
     * @param Q Second point
     * @return k1*P + k2*Q
     */
    JacobianPoint double_scalar_mult(const ZZ& k1, const JacobianPoint& P,
                                     const ZZ& k2, const JacobianPoint& Q) const;
    
    // ========================================================================
    // Coordinate Conversions
    // ========================================================================
    
    /**
     * @brief Convert Jacobian to Affine coordinates
     * @param P Jacobian point
     * @return Affine point
     */
    AffinePoint to_affine(const JacobianPoint& P) const;
    
    /**
     * @brief Convert Affine to Jacobian coordinates
     * @param P Affine point
     * @return Jacobian point
     */
    JacobianPoint to_jacobian(const AffinePoint& P) const;
    
    // ========================================================================
    // Serialization
    // ========================================================================
    
    /**
     * @brief Serialize point to bytes (uncompressed format)
     * @param P Point to serialize
     * @param out Output buffer (must be at least 1 + 2*field_size bytes)
     * @param out_len Output buffer length
     * @return Number of bytes written, or -1 on error
     */
    int point_to_bytes(const AffinePoint& P, unsigned char* out, size_t out_len) const;
    
    /**
     * @brief Deserialize point from bytes
     * @param in Input buffer
     * @param in_len Input length
     * @return Deserialized point
     */
    AffinePoint point_from_bytes(const unsigned char* in, size_t in_len) const;
    
private:
    ZZ p_;              // Prime modulus
    ZZ_p a_;            // Curve coefficient a
    ZZ_p b_;            // Curve coefficient b
    ZZ n_;              // Order of base point
    ZZ h_;              // Cofactor
    JacobianPoint G_;   // Generator point
    std::string name_;  // Curve name
    int bit_size_;      // Bit size (e.g., 256 for P-256)
    
    /**
     * @brief Montgomery ladder (constant-time scalar multiplication)
     */
    JacobianPoint montgomery_ladder(const ZZ& k, const JacobianPoint& P) const;
    
    /**
     * @brief Initialize ZZ_p modulus
     */
    void init_modulus();
};

// ============================================================================
// Standard Curve Parameter Functions
// ============================================================================

CurveParams get_secp256k1_params();
CurveParams get_secp256r1_params();
CurveParams get_secp384r1_params();
CurveParams get_secp521r1_params();
CurveParams get_sm2_params();

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_CRYPTO_ECC_CURVE_H
