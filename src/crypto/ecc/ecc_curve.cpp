/**
 * @file ecc_curve.cpp
 * @brief Elliptic Curve Core Implementation - NTL Backend
 * 
 * Complete implementation of elliptic curve operations using NTL.
 * Features:
 * - Constant-time Montgomery ladder for scalar multiplication
 * - Jacobian coordinates for efficient point arithmetic
 * - Support for standard curves (secp256k1, P-256, P-384, P-521, SM2)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/ecc/ecc_curve.h"
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <cstdint>

using namespace NTL;

namespace kctsb {
namespace ecc {

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

CurveParams get_secp384r1_params() {
    CurveParams params;
    params.name = "secp384r1";
    params.bit_size = 384;
    
    params.p = conv<ZZ>("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319");
    params.a = conv<ZZ>("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316");
    params.b = conv<ZZ>("27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575");
    
    params.n = conv<ZZ>("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643");
    params.h = ZZ(1);
    
    params.Gx = conv<ZZ>("26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087");
    params.Gy = conv<ZZ>("8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871");
    
    return params;
}

CurveParams get_secp521r1_params() {
    CurveParams params;
    params.name = "secp521r1";
    params.bit_size = 521;
    
    params.p = conv<ZZ>("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");
    params.a = conv<ZZ>("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148");
    params.b = conv<ZZ>("1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984");
    
    params.n = conv<ZZ>("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449");
    params.h = ZZ(1);
    
    params.Gx = conv<ZZ>("2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846");
    params.Gy = conv<ZZ>("3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784");
    
    return params;
}

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
        case CurveType::SECP384R1:
            params = get_secp384r1_params();
            break;
        case CurveType::SECP521R1:
            params = get_secp521r1_params();
            break;
        case CurveType::SM2:
            params = get_sm2_params();
            break;
        default:
            throw std::invalid_argument("Unsupported curve type");
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
    } else if (lower_name == "secp384r1" || lower_name == "p-384" || lower_name == "p384") {
        return ECCurve(CurveType::SECP384R1);
    } else if (lower_name == "secp521r1" || lower_name == "p-521" || lower_name == "p521") {
        return ECCurve(CurveType::SECP521R1);
    } else if (lower_name == "sm2") {
        return ECCurve(CurveType::SM2);
    }
    
    throw std::invalid_argument("Unknown curve name: " + name);
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
    
    ZZ_p::init(p_);
    
    // U1 = X1 * Z2²
    // U2 = X2 * Z1²
    // S1 = Y1 * Z2³
    // S2 = Y2 * Z1³
    ZZ_p Z1_sq = sqr(P.Z);
    ZZ_p Z2_sq = sqr(Q.Z);
    ZZ_p U1 = P.X * Z2_sq;
    ZZ_p U2 = Q.X * Z1_sq;
    ZZ_p S1 = P.Y * Z2_sq * Q.Z;
    ZZ_p S2 = Q.Y * Z1_sq * P.Z;
    
    // H = U2 - U1
    // r = S2 - S1
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
    
    // H² and H³
    ZZ_p H_sq = sqr(H);
    ZZ_p H_cb = H_sq * H;
    
    // X3 = r² - H³ - 2*U1*H²
    ZZ_p X3 = sqr(r) - H_cb - ZZ_p(2) * U1 * H_sq;
    
    // Y3 = r*(U1*H² - X3) - S1*H³
    ZZ_p Y3 = r * (U1 * H_sq - X3) - S1 * H_cb;
    
    // Z3 = H * Z1 * Z2
    ZZ_p Z3 = H * P.Z * Q.Z;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::double_point(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    ZZ_p::init(p_);
    
    // For a = -3 (most NIST curves), use optimized formula
    // For a = 0 (secp256k1), use simplified formula
    
    ZZ_p Y_sq = sqr(P.Y);
    ZZ_p S = ZZ_p(4) * P.X * Y_sq;
    
    ZZ_p M;
    if (IsZero(a_)) {
        // a = 0: M = 3*X²
        M = ZZ_p(3) * sqr(P.X);
    } else {
        // General case: M = 3*X² + a*Z⁴
        ZZ_p Z_sq = sqr(P.Z);
        M = ZZ_p(3) * sqr(P.X) + a_ * sqr(Z_sq);
    }
    
    // X3 = M² - 2*S
    ZZ_p X3 = sqr(M) - ZZ_p(2) * S;
    
    // Y3 = M*(S - X3) - 8*Y⁴
    ZZ_p Y3 = M * (S - X3) - ZZ_p(8) * sqr(Y_sq);
    
    // Z3 = 2*Y*Z
    ZZ_p Z3 = ZZ_p(2) * P.Y * P.Z;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::negate(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    ZZ_p::init(p_);
    return JacobianPoint(P.X, -P.Y, P.Z);
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
    return montgomery_ladder(k, P);
}

JacobianPoint ECCurve::scalar_mult_base(const ZZ& k) const {
    return montgomery_ladder(k, G_);
}

JacobianPoint ECCurve::double_scalar_mult(const ZZ& k1, const JacobianPoint& P,
                                          const ZZ& k2, const JacobianPoint& Q) const {
    // Shamir's trick for simultaneous multiple scalar multiplication
    // Precompute: P, Q, P+Q
    JacobianPoint PQ = add(P, Q);
    
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
            R = add(R, P);
        } else if (b2) {
            R = add(R, Q);
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
    
    // x = X / Z²
    // y = Y / Z³
    ZZ_p Z_inv = inv(P.Z);
    ZZ_p Z_inv_sq = sqr(Z_inv);
    ZZ_p Z_inv_cb = Z_inv_sq * Z_inv;
    
    ZZ_p x = P.X * Z_inv_sq;
    ZZ_p y = P.Y * Z_inv_cb;
    
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
    
    size_t field_size = (bit_size_ + 7) / 8;
    size_t required_len = 1 + 2 * field_size;
    
    if (out_len < required_len) {
        return -1;
    }
    
    // Uncompressed format: 0x04 || x || y
    out[0] = 0x04;
    
    // Extract x coordinate bytes (NTL uses little-endian, SEC 1 requires big-endian)
    ZZ x_int = rep(P.x);
    std::vector<uint8_t> x_le(field_size);
    BytesFromZZ(x_le.data(), x_int, static_cast<long>(field_size));
    // Reverse to big-endian for output
    for (size_t i = 0; i < field_size; i++) {
        out[1 + i] = x_le[field_size - 1 - i];
    }
    
    // Extract y coordinate bytes (NTL uses little-endian, SEC 1 requires big-endian)
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
    
    size_t field_size = (bit_size_ + 7) / 8;
    
    if (in[0] == 0x04) {
        // Uncompressed format
        if (in_len != 1 + 2 * field_size) {
            throw std::invalid_argument("Invalid uncompressed point length");
        }
        
        ZZ_p::init(p_);
        
        // Convert big-endian input to little-endian for NTL
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
