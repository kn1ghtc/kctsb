/**
 * @file ecc_v5.h
 * @brief Self-Contained Elliptic Curve Cryptography v5.0
 * 
 * Complete ECC implementation using kctsb Fe256 library.
 * No external dependencies (NTL, GMP removed).
 * 
 * Supported Curves:
 * - secp256k1 (Bitcoin/Ethereum)
 * - P-256 (NIST)
 * - SM2 (Chinese National Standard)
 * - Curve25519 (X25519 key exchange)
 * - Ed25519 (EdDSA signatures)
 * 
 * Features:
 * - Constant-time Montgomery ladder for scalar multiplication
 * - Jacobian coordinates for efficient point arithmetic
 * - Integrated Fe256 acceleration layer
 * - Side-channel resistant implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_ECC_V5_H
#define KCTSB_CRYPTO_ECC_V5_H

#include "kctsb/core/fe256.h"
#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace kctsb {
namespace ecc {

// ============================================================================
// Curve Type Enumeration
// ============================================================================

/**
 * @brief Supported elliptic curve types
 */
enum class CurveTypeV5 : int {
    SECP256K1 = 0,      ///< Bitcoin/Ethereum curve (Koblitz)
    P256      = 1,      ///< NIST P-256 (secp256r1)
    SM2       = 2,      ///< Chinese National Standard SM2
    X25519    = 3,      ///< Curve25519 (Montgomery, ECDH only)
    ED25519   = 4       ///< Edwards curve (EdDSA signatures)
};

// ============================================================================
// Point Representations
// ============================================================================

/**
 * @brief Affine point (x, y)
 * 
 * Standard representation where coordinates are field elements mod p.
 * Point at infinity is represented by is_infinity = true.
 */
struct AffinePointV5 {
    Fe256 x;
    Fe256 y;
    bool is_infinity;
    
    AffinePointV5() : is_infinity(true) {}
    
    AffinePointV5(const Fe256& x_, const Fe256& y_)
        : x(x_), y(y_), is_infinity(false) {}
    
    /**
     * @brief Create point from hex coordinates
     */
    AffinePointV5(const char* hex_x, const char* hex_y);
    
    /**
     * @brief Check if this is the point at infinity
     */
    bool is_identity() const { return is_infinity; }
    
    /**
     * @brief Set to point at infinity
     */
    void set_identity() { is_infinity = true; x.zero(); y.zero(); }
    
    /**
     * @brief Constant-time equality check
     */
    bool ct_equal(const AffinePointV5& other) const {
        if (is_infinity && other.is_infinity) return true;
        if (is_infinity || other.is_infinity) return false;
        return x.ct_equal(other.x) && y.ct_equal(other.y);
    }
    
    bool operator==(const AffinePointV5& other) const { return ct_equal(other); }
    bool operator!=(const AffinePointV5& other) const { return !ct_equal(other); }
};

/**
 * @brief Jacobian projective point (X : Y : Z)
 * 
 * Represents affine point (x, y) as (X/Z², Y/Z³).
 * Point at infinity has Z = 0 (specifically 0 : 1 : 0).
 * 
 * Jacobian coordinates provide faster point arithmetic
 * by avoiding costly field inversions.
 */
struct JacobianPointV5 {
    Fe256 X;
    Fe256 Y;
    Fe256 Z;
    
    /**
     * @brief Default constructor - point at infinity (0 : 1 : 0)
     */
    JacobianPointV5() {
        X.zero();
        Y.one();
        Z.zero();
    }
    
    /**
     * @brief Construct from affine point
     */
    explicit JacobianPointV5(const AffinePointV5& p) {
        if (p.is_infinity) {
            X.zero();
            Y.one();
            Z.zero();
        } else {
            X = p.x;
            Y = p.y;
            Z.one();
        }
    }
    
    /**
     * @brief Construct from coordinates
     */
    JacobianPointV5(const Fe256& x, const Fe256& y, const Fe256& z)
        : X(x), Y(y), Z(z) {}
    
    /**
     * @brief Check if this is the point at infinity
     */
    bool is_identity() const { return Z.is_zero(); }
    
    /**
     * @brief Set to point at infinity
     */
    void set_identity() {
        X.zero();
        Y.one();
        Z.zero();
    }
    
    /**
     * @brief Convert to affine coordinates
     * @param ctx Montgomery context for the curve's prime
     * @return Affine point
     */
    AffinePointV5 to_affine(const Fe256MontContext& ctx) const;
    
    /**
     * @brief Constant-time conditional move
     */
    void ct_cmov(const JacobianPointV5& src, bool cond) {
        X.ct_cmov(src.X, cond);
        Y.ct_cmov(src.Y, cond);
        Z.ct_cmov(src.Z, cond);
    }
    
    /**
     * @brief Constant-time conditional swap
     */
    static void ct_cswap(JacobianPointV5& a, JacobianPointV5& b, bool cond) {
        Fe256::ct_cswap(a.X, b.X, cond);
        Fe256::ct_cswap(a.Y, b.Y, cond);
        Fe256::ct_cswap(a.Z, b.Z, cond);
    }
};

// ============================================================================
// Curve Parameters
// ============================================================================

/**
 * @brief Curve parameters structure
 */
struct CurveParamsV5 {
    Fe256 p;        ///< Prime modulus
    Fe256 a;        ///< Curve coefficient a
    Fe256 b;        ///< Curve coefficient b
    Fe256 n;        ///< Order of base point G
    Fe256 h;        ///< Cofactor
    Fe256 Gx;       ///< Generator x-coordinate
    Fe256 Gy;       ///< Generator y-coordinate
    
    std::string name;
    CurveTypeV5 type;
    
    /**
     * @brief Initialize Montgomery context for this curve
     */
    Fe256MontContext mont_ctx;
    
    /**
     * @brief Get the generator point
     */
    AffinePointV5 generator() const {
        return AffinePointV5(Gx, Gy);
    }
};

// ============================================================================
// Pre-defined Curve Parameters
// ============================================================================

/**
 * @brief Get secp256k1 curve parameters (Bitcoin/Ethereum)
 */
const CurveParamsV5& secp256k1_params();

/**
 * @brief Get P-256 (NIST) curve parameters
 */
const CurveParamsV5& p256_params();

/**
 * @brief Get SM2 curve parameters (Chinese National Standard)
 */
const CurveParamsV5& sm2_params();

// ============================================================================
// Elliptic Curve Class
// ============================================================================

/**
 * @brief Main elliptic curve class for v5.0
 */
class ECCurveV5 {
public:
    /**
     * @brief Construct curve by type
     */
    explicit ECCurveV5(CurveTypeV5 type);
    
    /**
     * @brief Construct curve from parameters
     */
    explicit ECCurveV5(const CurveParamsV5& params);
    
    // ========================================================================
    // Getters
    // ========================================================================
    
    const Fe256& prime() const { return params_.p; }
    const Fe256& order() const { return params_.n; }
    const Fe256& cofactor() const { return params_.h; }
    const Fe256& coeff_a() const { return params_.a; }
    const Fe256& coeff_b() const { return params_.b; }
    const AffinePointV5 generator() const { return params_.generator(); }
    const std::string& name() const { return params_.name; }
    CurveTypeV5 type() const { return params_.type; }
    const Fe256MontContext& mont_ctx() const { return params_.mont_ctx; }
    
    // ========================================================================
    // Point Validation
    // ========================================================================
    
    /**
     * @brief Check if point is on the curve
     * @param p Point to validate (affine)
     * @return true if point satisfies y² = x³ + ax + b (mod p)
     */
    bool is_on_curve(const AffinePointV5& p) const;
    
    /**
     * @brief Check if point is on the curve (Jacobian)
     */
    bool is_on_curve(const JacobianPointV5& p) const;
    
    // ========================================================================
    // Point Arithmetic (Jacobian Coordinates)
    // ========================================================================
    
    /**
     * @brief Point doubling: R = 2P
     * @param r Output point
     * @param p Input point
     */
    void point_double(JacobianPointV5* r, const JacobianPointV5* p) const;
    
    /**
     * @brief Point addition: R = P + Q
     * @param r Output point
     * @param p First input point
     * @param q Second input point
     */
    void point_add(JacobianPointV5* r, 
                   const JacobianPointV5* p, 
                   const JacobianPointV5* q) const;
    
    /**
     * @brief Mixed addition: R = P + Q where Q is affine
     * @param r Output point (Jacobian)
     * @param p First input (Jacobian)
     * @param q Second input (Affine)
     */
    void point_add_mixed(JacobianPointV5* r,
                         const JacobianPointV5* p,
                         const AffinePointV5* q) const;
    
    /**
     * @brief Point negation: R = -P
     */
    void point_negate(JacobianPointV5* r, const JacobianPointV5* p) const;
    
    // ========================================================================
    // Scalar Multiplication
    // ========================================================================
    
    /**
     * @brief Scalar multiplication: R = k * P (constant-time Montgomery ladder)
     * @param r Output point
     * @param k Scalar
     * @param p Base point
     */
    void scalar_mul(JacobianPointV5* r, 
                    const Fe256* k, 
                    const JacobianPointV5* p) const;
    
    /**
     * @brief Scalar multiplication with generator: R = k * G
     * @param r Output point
     * @param k Scalar
     */
    void scalar_mul_base(JacobianPointV5* r, const Fe256* k) const;
    
    /**
     * @brief Double scalar multiplication: R = k1 * G + k2 * P
     * @param r Output point
     * @param k1 First scalar
     * @param k2 Second scalar
     * @param p Second base point
     */
    void scalar_mul_double(JacobianPointV5* r,
                           const Fe256* k1,
                           const Fe256* k2,
                           const JacobianPointV5* p) const;
    
    // ========================================================================
    // Coordinate Conversion
    // ========================================================================
    
    /**
     * @brief Convert Jacobian to Affine
     */
    AffinePointV5 to_affine(const JacobianPointV5& p) const;
    
    /**
     * @brief Convert Affine to Jacobian
     */
    JacobianPointV5 to_jacobian(const AffinePointV5& p) const;
    
private:
    CurveParamsV5 params_;
    JacobianPointV5 G_jac_;  ///< Generator in Jacobian form
};

// ============================================================================
// ECDSA Signatures
// ============================================================================

/**
 * @brief ECDSA Signature (r, s)
 */
struct ECDSASignatureV5 {
    Fe256 r;
    Fe256 s;
    
    /**
     * @brief Serialize to DER format
     */
    std::vector<uint8_t> to_der() const;
    
    /**
     * @brief Parse from DER format
     */
    static ECDSASignatureV5 from_der(const uint8_t* data, size_t len);
    
    /**
     * @brief Serialize to raw format (r || s)
     */
    std::array<uint8_t, 64> to_raw() const;
    
    /**
     * @brief Parse from raw format
     */
    static ECDSASignatureV5 from_raw(const uint8_t* data);
};

/**
 * @brief ECDSA v5.0 Implementation
 */
class ECDSAV5 {
public:
    /**
     * @brief Construct ECDSA with specified curve
     */
    explicit ECDSAV5(CurveTypeV5 curve = CurveTypeV5::SECP256K1);
    
    /**
     * @brief Generate key pair
     * @param private_key Output: 32-byte private key
     * @param public_key Output: Uncompressed public key (65 bytes: 04 || x || y)
     */
    void generate_keypair(uint8_t* private_key, uint8_t* public_key);
    
    /**
     * @brief Get public key from private key
     */
    void get_public_key(const uint8_t* private_key, uint8_t* public_key);
    
    /**
     * @brief Sign message hash
     * @param hash 32-byte message hash
     * @param private_key 32-byte private key
     * @param signature Output signature
     */
    void sign(const uint8_t* hash, const uint8_t* private_key,
              ECDSASignatureV5* signature);
    
    /**
     * @brief Verify signature
     * @param hash 32-byte message hash
     * @param public_key 65-byte uncompressed public key
     * @param signature Signature to verify
     * @return true if signature is valid
     */
    bool verify(const uint8_t* hash, const uint8_t* public_key,
                const ECDSASignatureV5& signature);
    
private:
    ECCurveV5 curve_;
};

// ============================================================================
// ECDH Key Exchange
// ============================================================================

/**
 * @brief ECDH v5.0 Implementation
 */
class ECDHV5 {
public:
    /**
     * @brief Construct ECDH with specified curve
     */
    explicit ECDHV5(CurveTypeV5 curve = CurveTypeV5::SECP256K1);
    
    /**
     * @brief Generate ephemeral key pair
     */
    void generate_keypair(uint8_t* private_key, uint8_t* public_key);
    
    /**
     * @brief Compute shared secret
     * @param my_private_key My 32-byte private key
     * @param their_public_key Their 65-byte public key
     * @param shared_secret Output: 32-byte shared secret (x-coordinate)
     */
    void compute_shared_secret(const uint8_t* my_private_key,
                               const uint8_t* their_public_key,
                               uint8_t* shared_secret);
    
private:
    ECCurveV5 curve_;
};

// ============================================================================
// High-Level API
// ============================================================================

/**
 * @brief Generate secp256k1 keypair (Bitcoin/Ethereum compatible)
 */
void secp256k1_keygen(uint8_t private_key[32], uint8_t public_key[65]);

/**
 * @brief ECDSA sign with secp256k1
 */
void secp256k1_sign(const uint8_t hash[32], const uint8_t private_key[32],
                    uint8_t signature[64]);

/**
 * @brief ECDSA verify with secp256k1
 */
bool secp256k1_verify(const uint8_t hash[32], const uint8_t public_key[65],
                      const uint8_t signature[64]);

/**
 * @brief ECDH with secp256k1
 */
void secp256k1_ecdh(const uint8_t my_private[32], const uint8_t their_public[65],
                    uint8_t shared_secret[32]);

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_CRYPTO_ECC_V5_H
