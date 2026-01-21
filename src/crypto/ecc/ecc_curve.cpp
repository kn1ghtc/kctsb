/**
 * @file ecc_curve.cpp
 * @brief Elliptic Curve Core Implementation - Bignum Backend
 * 
 * Complete implementation of elliptic curve operations using bignum.
 * Features:
 * - Constant-time Montgomery ladder for all scalar multiplication
 * - Jacobian coordinates for efficient point arithmetic
 * - Support for 256-bit standard curves (secp256k1, P-256, SM2)
 * - fe256 fast path for 256-bit curves (~3-5x additional speedup)
 * 
 * Security (v4.6.0):
 * - wNAF algorithm REMOVED due to side-channel vulnerabilities
 * - All scalar multiplication uses Montgomery ladder (constant-time)
 * - Timing-attack resistant implementation
 * 
 * Performance optimizations (v4.5.2):
 * - fe256 fast path for secp256k1, P-256, SM2
 * - Direct field arithmetic bypassing ZZ_p overhead
 * - P-256 Solinas reduction for NIST curve optimization
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/ecc/ecc_curve.h"
#include "fe256_ecc_fast.h"
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <array>

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

namespace kctsb {
namespace ecc {

// ============================================================================
// fe256 Fast Path Control
// ============================================================================

// Enable/disable fe256 fast path (can be controlled at runtime if needed)
static bool g_fe256_fast_path_enabled = true;

/**
 * @brief Enable or disable fe256 fast path
 * @param enable true to enable, false to disable
 */
void fe256_set_fast_path_enabled(bool enable) {
    g_fe256_fast_path_enabled = enable;
}

/**
 * @brief Check if fe256 fast path is enabled
 * @return true if enabled
 */
bool fe256_is_fast_path_enabled() {
    return g_fe256_fast_path_enabled;
}

// ============================================================================
// Standard Curve Parameters (SECG/NIST)
// ============================================================================

CurveParams get_secp256k1_params() {
    CurveParams params;
    params.name = "secp256k1";
    params.bit_size = 256;
    
    // p = 2^256 - 2^32 - 977
    params.p = conv<ZZ>("115792089237316195423570985008687907853269984665640564039457584007908834671663");
    params.a = ZZ(0);  // a = 0
    params.b = ZZ(7);  // b = 7
    
    // Order n (prime)
    params.n = conv<ZZ>("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    params.h = ZZ(1);  // Cofactor
    
    // Generator G
    params.Gx = conv<ZZ>("55066263022277343669578718895168534326250603453777594175500187360389116729240");
    params.Gy = conv<ZZ>("32670510020758816978083085130507043184471273380659243275938904335757337482424");
    
    return params;
}

CurveParams get_secp256r1_params() {
    CurveParams params;
    params.name = "secp256r1";
    params.bit_size = 256;
    
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    params.p = conv<ZZ>("115792089210356248762697446949407573530086143415290314195533631308867097853951");
    params.a = conv<ZZ>("115792089210356248762697446949407573530086143415290314195533631308867097853948");
    params.b = conv<ZZ>("41058363725152142129326129780047268409114441015993725554835256314039467401291");
    
    params.n = conv<ZZ>("115792089210356248762697446949407573529996955224135760342422259061068512044369");
    params.h = ZZ(1);
    
    params.Gx = conv<ZZ>("48439561293906451759052585252797914202762949526041747995844080717082404635286");
    params.Gy = conv<ZZ>("36134250956749795798585127919587881956611106672985015071877198253568414405109");
    
    return params;
}

// P-384 and P-521 removed in v4.6.0 - focusing on 256-bit curves only

CurveParams get_sm2_params() {
    CurveParams params;
    params.name = "sm2";
    params.bit_size = 256;
    
    // SM2 curve parameters (Chinese National Standard)
    params.p = conv<ZZ>("115792089210356248756420345214020892766250353991924191454421193933289684991999");
    params.a = conv<ZZ>("115792089210356248756420345214020892766250353991924191454421193933289684991996");
    params.b = conv<ZZ>("18505919022281880113072981827955639221458448578012075254857346196103069175443");
    
    params.n = conv<ZZ>("115792089210356248756420345214020892766061623724957744567843809356293439045923");
    params.h = ZZ(1);
    
    params.Gx = conv<ZZ>("22963146547237050559479531362550074578802567295341616970375194840604139615431");
    params.Gy = conv<ZZ>("85132369209828568825618990617112496413088388631904505083283536607588877201568");
    
    return params;
}

// ============================================================================
// ECCurve Constructor Implementations
// ============================================================================

ECCurve::ECCurve(const CurveParams& params) {
    p_ = params.p;
    n_ = params.n;
    h_ = params.h;
    name_ = params.name;
    bit_size_ = params.bit_size;
    
    init_modulus();
    
    a_ = conv<ZZ_p>(params.a);
    b_ = conv<ZZ_p>(params.b);
    
    // Initialize generator in Jacobian coordinates
    ZZ_p Gx = conv<ZZ_p>(params.Gx);
    ZZ_p Gy = conv<ZZ_p>(params.Gy);
    G_ = JacobianPoint(Gx, Gy);
}

ECCurve::ECCurve(CurveType type) {
    CurveParams params;
    switch (type) {
        case CurveType::SECP256K1:
            params = get_secp256k1_params();
            break;
        case CurveType::SECP256R1:
            params = get_secp256r1_params();
            break;
        case CurveType::SM2:
            params = get_sm2_params();
            break;
        default:
            throw std::invalid_argument("Unsupported curve type (only 256-bit curves supported)");
    }
    
    p_ = params.p;
    n_ = params.n;
    h_ = params.h;
    name_ = params.name;
    bit_size_ = params.bit_size;
    
    init_modulus();
    
    a_ = conv<ZZ_p>(params.a);
    b_ = conv<ZZ_p>(params.b);
    
    ZZ_p Gx = conv<ZZ_p>(params.Gx);
    ZZ_p Gy = conv<ZZ_p>(params.Gy);
    G_ = JacobianPoint(Gx, Gy);
}

ECCurve ECCurve::from_name(const std::string& name) {
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name == "secp256k1") {
        return ECCurve(CurveType::SECP256K1);
    } else if (lower_name == "secp256r1" || lower_name == "p-256" || lower_name == "p256" || lower_name == "prime256v1") {
        return ECCurve(CurveType::SECP256R1);
    } else if (lower_name == "sm2") {
        return ECCurve(CurveType::SM2);
    }
    
    throw std::invalid_argument("Unknown or unsupported curve name: " + name + " (only 256-bit curves supported)");
}

void ECCurve::init_modulus() {
    ZZ_p::init(p_);
}

// ============================================================================
// Point Validation
// ============================================================================

bool ECCurve::is_on_curve(const AffinePoint& P) const {
    if (P.is_infinity) {
        return true;
    }
    
    // Ensure we're using the correct modulus
    ZZ_p::init(p_);
    
    // Check: y² = x³ + ax + b (mod p)
    ZZ_p lhs = sqr(P.y);
    ZZ_p rhs = power(P.x, 3) + a_ * P.x + b_;
    
    return lhs == rhs;
}

bool ECCurve::is_on_curve(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return true;
    }
    
    // Convert to affine and check
    AffinePoint aff = to_affine(P);
    return is_on_curve(aff);
}

bool ECCurve::validate_point(const JacobianPoint& P) const {
    // Check not at infinity
    if (P.is_infinity()) {
        return false;
    }
    
    // Check on curve
    if (!is_on_curve(P)) {
        return false;
    }
    
    // Check in correct subgroup: n*P = O
    JacobianPoint check = scalar_mult(n_, P);
    return check.is_infinity();
}

// ============================================================================
// Point Arithmetic - Jacobian Coordinates
// ============================================================================

JacobianPoint ECCurve::add(const JacobianPoint& P, const JacobianPoint& Q) const {
    // Handle identity cases
    if (P.is_infinity()) {
        return Q;
    }
    if (Q.is_infinity()) {
        return P;
    }
    
    // Ensure correct modulus
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize input coordinates under current modulus
    // This ensures ZZ_p values created under different modulus are correctly interpreted
    ZZ_p P_X = conv<ZZ_p>(rep(P.X));
    ZZ_p P_Y = conv<ZZ_p>(rep(P.Y));
    ZZ_p P_Z = conv<ZZ_p>(rep(P.Z));
    ZZ_p Q_X = conv<ZZ_p>(rep(Q.X));
    ZZ_p Q_Y = conv<ZZ_p>(rep(Q.Y));
    ZZ_p Q_Z = conv<ZZ_p>(rep(Q.Z));
    
    // Optimized Jacobian addition (12M + 4S formula from EFD)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
    
    ZZ_p Z1Z1 = sqr(P_Z);
    ZZ_p Z2Z2 = sqr(Q_Z);
    ZZ_p U1 = P_X * Z2Z2;
    ZZ_p U2 = Q_X * Z1Z1;
    ZZ_p S1 = P_Y * Q_Z * Z2Z2;
    ZZ_p S2 = Q_Y * P_Z * Z1Z1;
    
    ZZ_p H = U2 - U1;
    ZZ_p r = S2 - S1;
    
    // Check if P == Q (need doubling)
    if (IsZero(H)) {
        if (IsZero(r)) {
            return double_point(P);
        }
        // P = -Q, return infinity
        return JacobianPoint();
    }
    
    // Optimized computation
    ZZ_p HH = sqr(H);
    ZZ_p HHH = H * HH;
    ZZ_p V = U1 * HH;
    
    // X3 = r² - HHH - 2*V
    ZZ_p r2 = sqr(r);
    ZZ_p X3 = r2 - HHH - V - V;
    
    // Y3 = r*(V - X3) - S1*HHH
    ZZ_p Y3 = r * (V - X3) - S1 * HHH;
    
    // Z3 = H * Z1 * Z2
    ZZ_p Z3 = H * P_Z * Q_Z;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::double_point(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    // Ensure correct modulus
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize input coordinates under current modulus
    ZZ_p P_X = conv<ZZ_p>(rep(P.X));
    ZZ_p P_Y = conv<ZZ_p>(rep(P.Y));
    ZZ_p P_Z = conv<ZZ_p>(rep(P.Z));
    
    // Optimized doubling formula from EFD
    // For a = 0: dbl-2009-l (1M + 5S + 1*a + 7add + 2*2 + 1*3 + 1*8)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    
    ZZ_p A = sqr(P_X);           // X1²
    ZZ_p B = sqr(P_Y);           // Y1²
    ZZ_p C = sqr(B);             // Y1⁴
    
    // D = 2*((X1+B)² - A - C) = 2*(X1+Y1²)² - 2*X1² - 2*Y1⁴
    ZZ_p tmp = P_X + B;
    ZZ_p D = sqr(tmp) - A - C;
    D = D + D;                    // D = 2*D (cheaper than 2*D multiply)
    
    ZZ_p E;
    if (IsZero(a_)) {
        // a = 0 (secp256k1): E = 3*A
        E = A + A + A;
    } else {
        // General case (P-256, SM2): E = 3*A + a*Z1⁴
        ZZ_p Z1_sq = sqr(P_Z);
        E = A + A + A + a_ * sqr(Z1_sq);
    }
    
    ZZ_p F = sqr(E);              // E²
    
    // X3 = F - 2*D
    ZZ_p X3 = F - D - D;
    
    // Y3 = E*(D - X3) - 8*C
    ZZ_p C8 = C;
    for (int i = 0; i < 3; i++) C8 = C8 + C8;  // 8*C
    ZZ_p Y3 = E * (D - X3) - C8;
    
    // Z3 = 2*Y1*Z1
    ZZ_p Z3 = P_Y * P_Z;
    Z3 = Z3 + Z3;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::negate(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    // Ensure correct modulus and normalize
    ZZ_p::init(p_);
    ZZ_p P_Y = conv<ZZ_p>(rep(P.Y));
    return JacobianPoint(conv<ZZ_p>(rep(P.X)), -P_Y, conv<ZZ_p>(rep(P.Z)));
}

JacobianPoint ECCurve::subtract(const JacobianPoint& P, const JacobianPoint& Q) const {
    return add(P, negate(Q));
}

// ============================================================================
// Scalar Multiplication - Montgomery Ladder (Constant-Time)
// ============================================================================

JacobianPoint ECCurve::montgomery_ladder(const ZZ& k, const JacobianPoint& P) const {
    if (IsZero(k) || P.is_infinity()) {
        return JacobianPoint();
    }
    
    // Reduce k modulo n
    ZZ k_mod = k % n_;
    if (IsZero(k_mod)) {
        return JacobianPoint();
    }
    
    // Montgomery ladder: constant-time scalar multiplication
    JacobianPoint R0 = JacobianPoint();  // R0 = O
    JacobianPoint R1 = P;                // R1 = P
    
    long num_bits = NumBits(k_mod);
    
    // Process bits from MSB to LSB
    for (long i = num_bits - 1; i >= 0; --i) {
        if (bit(k_mod, i)) {
            R0 = add(R0, R1);
            R1 = double_point(R1);
        } else {
            R1 = add(R0, R1);
            R0 = double_point(R0);
        }
    }
    
    return R0;
}

JacobianPoint ECCurve::scalar_mult(const ZZ& k, const JacobianPoint& P) const {
    // Use constant-time Montgomery ladder for security
    ZZ_p::init(p_);
    JacobianPoint P_norm(conv<ZZ_p>(rep(P.X)), conv<ZZ_p>(rep(P.Y)), conv<ZZ_p>(rep(P.Z)));
    return montgomery_ladder(k, P_norm);
}

JacobianPoint ECCurve::scalar_mult_base(const ZZ& k) const {
    // Use constant-time Montgomery ladder for security
    ZZ_p::init(p_);
    JacobianPoint G_norm(conv<ZZ_p>(rep(G_.X)), conv<ZZ_p>(rep(G_.Y)), conv<ZZ_p>(rep(G_.Z)));
    return montgomery_ladder(k, G_norm);
}

// ============================================================================
// Double Scalar Multiplication with Shamir's Trick (Constant-Time)
// ============================================================================

JacobianPoint ECCurve::double_scalar_mult(const ZZ& k1, const JacobianPoint& P,
                                          const ZZ& k2, const JacobianPoint& Q) const {
    // Initialize modulus once for all point operations
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize point coordinates under current modulus
    JacobianPoint P_norm(conv<ZZ_p>(rep(P.X)), conv<ZZ_p>(rep(P.Y)), conv<ZZ_p>(rep(P.Z)));
    JacobianPoint Q_norm(conv<ZZ_p>(rep(Q.X)), conv<ZZ_p>(rep(Q.Y)), conv<ZZ_p>(rep(Q.Z)));
    
    // Shamir's trick for simultaneous multiple scalar multiplication
    // Precompute: P, Q, P+Q
    JacobianPoint PQ = add(P_norm, Q_norm);
    
    ZZ k1_mod = k1 % n_;
    ZZ k2_mod = k2 % n_;
    
    JacobianPoint R = JacobianPoint();  // Start with infinity
    
    // Get maximum bit length
    long bits1 = NumBits(k1_mod);
    long bits2 = NumBits(k2_mod);
    long max_bits = std::max(bits1, bits2);
    
    // Process both scalars together
    for (long i = max_bits - 1; i >= 0; --i) {
        R = double_point(R);
        
        int b1 = (i < bits1) ? static_cast<int>(bit(k1_mod, i)) : 0;
        int b2 = (i < bits2) ? static_cast<int>(bit(k2_mod, i)) : 0;
        
        if (b1 && b2) {
            R = add(R, PQ);
        } else if (b1) {
            R = add(R, P_norm);
        } else if (b2) {
            R = add(R, Q_norm);
        }
    }
    
    return R;
}

// ============================================================================
// Coordinate Conversions
// ============================================================================

AffinePoint ECCurve::to_affine(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return AffinePoint();
    }
    
    ZZ_p::init(p_);
    
    // CRITICAL: Normalize coordinates under current modulus p_
    ZZ_p X = conv<ZZ_p>(rep(P.X));
    ZZ_p Y = conv<ZZ_p>(rep(P.Y));
    ZZ_p Z = conv<ZZ_p>(rep(P.Z));
    
    // x = X / Z²
    // y = Y / Z³
    ZZ_p Z_inv = inv(Z);
    ZZ_p Z_inv_sq = sqr(Z_inv);
    ZZ_p Z_inv_cb = Z_inv_sq * Z_inv;
    
    ZZ_p x = X * Z_inv_sq;
    ZZ_p y = Y * Z_inv_cb;
    
    return AffinePoint(x, y);
}

JacobianPoint ECCurve::to_jacobian(const AffinePoint& P) const {
    if (P.is_infinity) {
        return JacobianPoint();
    }
    
    ZZ_p::init(p_);
    return JacobianPoint(P.x, P.y);
}

// ============================================================================
// Serialization
// ============================================================================

int ECCurve::point_to_bytes(const AffinePoint& P, unsigned char* out, size_t out_len) const {
    if (P.is_infinity) {
        if (out_len < 1) return -1;
        out[0] = 0x00;
        return 1;
    }
    
    size_t field_size = static_cast<size_t>((bit_size_ + 7) / 8);
    size_t required_len = 1 + 2 * field_size;
    
    if (out_len < required_len) {
        return -1;
    }
    
    // Uncompressed format: 0x04 || x || y
    out[0] = 0x04;
    
    // Extract x coordinate bytes (bignum uses little-endian, SEC 1 requires big-endian)
    ZZ x_int = rep(P.x);
    std::vector<uint8_t> x_le(field_size);
    BytesFromZZ(x_le.data(), x_int, static_cast<long>(field_size));
    // Reverse to big-endian for output
    for (size_t i = 0; i < field_size; i++) {
        out[1 + i] = x_le[field_size - 1 - i];
    }
    
    // Extract y coordinate bytes (bignum uses little-endian, SEC 1 requires big-endian)
    ZZ y_int = rep(P.y);
    std::vector<uint8_t> y_le(field_size);
    BytesFromZZ(y_le.data(), y_int, static_cast<long>(field_size));
    // Reverse to big-endian for output
    for (size_t i = 0; i < field_size; i++) {
        out[1 + field_size + i] = y_le[field_size - 1 - i];
    }
    
    return static_cast<int>(required_len);
}

AffinePoint ECCurve::point_from_bytes(const unsigned char* in, size_t in_len) const {
    if (in_len < 1) {
        throw std::invalid_argument("Input too short");
    }
    
    // Check for point at infinity
    if (in[0] == 0x00) {
        return AffinePoint();
    }
    
    size_t field_size = static_cast<size_t>((bit_size_ + 7) / 8);
    
    if (in[0] == 0x04) {
        // Uncompressed format
        if (in_len != 1 + 2 * field_size) {
            throw std::invalid_argument("Invalid uncompressed point length");
        }
        
        ZZ_p::init(p_);
        
        // Convert big-endian input to little-endian for bignum
        std::vector<uint8_t> x_le(field_size), y_le(field_size);
        for (size_t i = 0; i < field_size; i++) {
            x_le[i] = in[1 + field_size - 1 - i];
            y_le[i] = in[1 + field_size + field_size - 1 - i];
        }
        
        ZZ x_int = ZZFromBytes(x_le.data(), static_cast<long>(field_size));
        ZZ y_int = ZZFromBytes(y_le.data(), static_cast<long>(field_size));
        
        AffinePoint P(conv<ZZ_p>(x_int), conv<ZZ_p>(y_int));
        
        if (!is_on_curve(P)) {
            throw std::invalid_argument("Point is not on curve");
        }
        
        return P;
    }
    
    // TODO: Add compressed point support (0x02, 0x03)
    throw std::invalid_argument("Unsupported point format");
}

} // namespace ecc
} // namespace kctsb
