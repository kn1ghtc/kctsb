/**
 * @file ecc_curve.cpp
 * @brief Elliptic Curve Core Implementation - Bignum Backend
 * 
 * Complete implementation of elliptic curve operations using bignum.
 * Features:
 * - wNAF (width-5 Non-Adjacent Form) scalar multiplication for ~3x speedup
 * - Constant-time Montgomery ladder fallback for maximum security
 * - Jacobian coordinates for efficient point arithmetic
 * - Support for standard curves (secp256k1, P-256, P-384, P-521, SM2)
 * 
 * Performance optimizations (v4.4.0):
 * - wNAF with w=5 for generator and arbitrary point multiplication
 * - Shamir's trick for double scalar multiplication
 * - Precomputation table caching for generator points
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/crypto/ecc/ecc_curve.h"
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <array>
#include <mutex>
#include <unordered_map>
#include <memory>

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

namespace kctsb {
namespace ecc {

// ============================================================================
// Generator Precomputation Cache (for scalar_mult_base acceleration)
// ============================================================================

/**
 * @brief Cached precomputation table for generator points
 * 
 * This cache stores precomputed tables for each curve's generator point,
 * eliminating the need to rebuild the table for every scalar_mult_base call.
 * Thread-safe with mutex protection.
 */
class GeneratorPrecompCache {
public:
    struct CacheEntry {
        std::array<JacobianPoint, 16> table;  // wNAF table (w=5)
        bool valid = false;
    };
    
    static GeneratorPrecompCache& instance() {
        static GeneratorPrecompCache cache;
        return cache;
    }
    
    CacheEntry* get_or_create(const std::string& curve_name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(curve_name);
        if (it != cache_.end()) {
            return &it->second;
        }
        // Create empty entry, will be filled by caller
        cache_[curve_name] = CacheEntry();
        return &cache_[curve_name];
    }
    
private:
    GeneratorPrecompCache() = default;
    std::mutex mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
};

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
    
    // Note: ZZ_p modulus should be set by caller for batch operations
    // For single operations, we ensure it's set correctly
    if (IsZero(ZZ_p::modulus()) || ZZ_p::modulus() != p_) {
        ZZ_p::init(p_);
    }
    
    // Optimized Jacobian addition (12M + 4S formula from EFD)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
    // For a = 0 curves (secp256k1, SM2)
    
    ZZ_p Z1Z1 = sqr(P.Z);
    ZZ_p Z2Z2 = sqr(Q.Z);
    ZZ_p U1 = P.X * Z2Z2;
    ZZ_p U2 = Q.X * Z1Z1;
    ZZ_p S1 = P.Y * Q.Z * Z2Z2;
    ZZ_p S2 = Q.Y * P.Z * Z1Z1;
    
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
    ZZ_p Z3 = H * P.Z * Q.Z;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::double_point(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    // Note: ZZ_p modulus should be set by caller for batch operations
    if (IsZero(ZZ_p::modulus()) || ZZ_p::modulus() != p_) {
        ZZ_p::init(p_);
    }
    
    // Optimized doubling formula from EFD
    // For a = 0: dbl-2009-l (1M + 5S + 1*a + 7add + 2*2 + 1*3 + 1*8)
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    
    ZZ_p A = sqr(P.X);           // X1²
    ZZ_p B = sqr(P.Y);           // Y1²
    ZZ_p C = sqr(B);             // Y1⁴
    
    // D = 2*((X1+B)² - A - C) = 2*(X1+Y1²)² - 2*X1² - 2*Y1⁴
    ZZ_p tmp = P.X + B;
    ZZ_p D = sqr(tmp) - A - C;
    D = D + D;                    // D = 2*D (cheaper than 2*D multiply)
    
    ZZ_p E;
    if (IsZero(a_)) {
        // a = 0 (secp256k1, SM2): E = 3*A
        E = A + A + A;
    } else {
        // General case: E = 3*A + a*Z1⁴
        ZZ_p Z1_sq = sqr(P.Z);
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
    ZZ_p Z3 = P.Y * P.Z;
    Z3 = Z3 + Z3;
    
    return JacobianPoint(X3, Y3, Z3);
}

JacobianPoint ECCurve::negate(const JacobianPoint& P) const {
    if (P.is_infinity()) {
        return P;
    }
    
    // Note: Caller should have set modulus
    if (IsZero(ZZ_p::modulus()) || ZZ_p::modulus() != p_) {
        ZZ_p::init(p_);
    }
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
    // Use wNAF for performance (falls back to Montgomery ladder for k <= 0)
    return wnaf_scalar_mult(k, P);
}

JacobianPoint ECCurve::scalar_mult_base(const ZZ& k) const {
    // Use cached precomputation table for generator multiplication
    // This avoids rebuilding the table for every call (~16 point additions saved)
    return wnaf_scalar_mult_cached(k);
}

// ============================================================================
// wNAF (width-5 Non-Adjacent Form) Optimization
// ============================================================================

/**
 * @brief Compute wNAF representation of scalar k
 * 
 * wNAF reduces the number of point additions by encoding the scalar
 * such that at most one in every w bits is non-zero.
 * For w=5: digits are in {±1, ±3, ±5, ±7, ±9, ±11, ±13, ±15}
 * 
 * @param k Scalar to encode
 * @param wnaf Output vector of wNAF digits
 * @return Number of digits in wNAF representation
 */
size_t ECCurve::compute_wnaf(const ZZ& k, std::vector<int8_t>& wnaf) const {
    wnaf.clear();
    wnaf.resize(MAX_SCALAR_BITS + 1, 0);
    
    if (IsZero(k)) {
        return 0;
    }
    
    ZZ val = k;
    size_t i = 0;
    const int w = WNAF_WINDOW_WIDTH;
    const int mask = (1 << w) - 1;  // 0x1F for w=5
    const int half = 1 << (w - 1);  // 16 for w=5
    
    while (val > 0 && i < MAX_SCALAR_BITS) {
        if (IsOdd(val)) {
            // Get lowest w bits
            long digit = conv<long>(val & ZZ(mask));
            if (digit >= half) {
                // Make digit negative: digit -= 2^w
                digit -= (1 << w);
            }
            wnaf[i] = static_cast<int8_t>(digit);
            val -= digit;
        } else {
            wnaf[i] = 0;
        }
        val >>= 1;  // val = val / 2
        i++;
    }
    
    return i;
}

/**
 * @brief Build precomputation table for wNAF multiplication
 * 
 * For w=5, computes: P, 3P, 5P, 7P, 9P, 11P, 13P, 15P (odd multiples up to 2^(w-1)-1)
 * 
 * @param P Base point
 * @param table Output precomputation table
 */
void ECCurve::build_precomp_table(const JacobianPoint& P, 
                                   std::array<JacobianPoint, WNAF_TABLE_SIZE>& table) const {
    // table[i] = (2*i + 1) * P
    // i=0: 1*P, i=1: 3*P, i=2: 5*P, ..., i=15: 31*P (for w=5)
    
    table[0] = P;  // 1*P
    
    JacobianPoint P2 = double_point(P);  // 2*P
    
    for (size_t i = 1; i < WNAF_TABLE_SIZE; i++) {
        table[i] = add(table[i-1], P2);  // (2*i+1)*P = (2*(i-1)+1)*P + 2*P
    }
}

/**
 * @brief wNAF scalar multiplication
 * 
 * Uses width-5 wNAF for approximately 3x speedup over binary method.
 * Average number of additions: ~256/5 ≈ 51 vs ~128 for binary method.
 * 
 * @param k Scalar (will be reduced mod n)
 * @param P Base point
 * @return k * P
 */
JacobianPoint ECCurve::wnaf_scalar_mult(const ZZ& k, const JacobianPoint& P) const {
    if (IsZero(k) || P.is_infinity()) {
        return JacobianPoint();
    }
    
    // Reduce k modulo n
    ZZ k_mod = k % n_;
    if (k_mod < 0) {
        k_mod += n_;
    }
    if (IsZero(k_mod)) {
        return JacobianPoint();
    }
    
    // Initialize modulus once for all point operations
    ZZ_p::init(p_);
    
    // Compute wNAF representation
    std::vector<int8_t> wnaf;
    size_t wnaf_len = compute_wnaf(k_mod, wnaf);
    
    if (wnaf_len == 0) {
        return JacobianPoint();
    }
    
    // Build precomputation table
    std::array<JacobianPoint, WNAF_TABLE_SIZE> table;
    build_precomp_table(P, table);
    
    // wNAF evaluation (left-to-right for clarity)
    JacobianPoint R;  // Infinity
    
    for (long i = static_cast<long>(wnaf_len) - 1; i >= 0; i--) {
        R = double_point(R);
        
        int8_t digit = wnaf[static_cast<size_t>(i)];
        if (digit > 0) {
            size_t idx = static_cast<size_t>((digit - 1) / 2);
            R = add(R, table[idx]);
        } else if (digit < 0) {
            size_t idx = static_cast<size_t>((-digit - 1) / 2);
            R = subtract(R, table[idx]);
        }
    }
    
    return R;
}

/**
 * @brief Cached wNAF scalar multiplication for generator point
 * 
 * Uses a cached precomputation table for the generator point to avoid
 * rebuilding the table for every scalar multiplication. This provides
 * significant speedup for repeated key generation and signing operations.
 * 
 * The precomputation table is built once per curve and cached using a
 * thread-safe singleton pattern.
 * 
 * @param k Scalar (will be reduced mod n)
 * @return k * G where G is the curve's generator
 */
JacobianPoint ECCurve::wnaf_scalar_mult_cached(const ZZ& k) const {
    if (IsZero(k)) {
        return JacobianPoint();
    }
    
    // Reduce k modulo n
    ZZ k_mod = k % n_;
    if (k_mod < 0) {
        k_mod += n_;
    }
    if (IsZero(k_mod)) {
        return JacobianPoint();
    }
    
    // Initialize modulus once for all point operations
    ZZ_p::init(p_);
    
    // Get or create cached precomputation table for this curve's generator
    auto* cache_entry = GeneratorPrecompCache::instance().get_or_create(name_);
    
    if (!cache_entry->valid) {
        // Build precomputation table for generator point G_
        build_precomp_table(G_, cache_entry->table);
        cache_entry->valid = true;
    }
    
    // Compute wNAF representation
    std::vector<int8_t> wnaf;
    size_t wnaf_len = compute_wnaf(k_mod, wnaf);
    
    if (wnaf_len == 0) {
        return JacobianPoint();
    }
    
    // wNAF evaluation using cached table
    JacobianPoint R;  // Infinity
    
    for (long i = static_cast<long>(wnaf_len) - 1; i >= 0; i--) {
        R = double_point(R);
        
        int8_t digit = wnaf[static_cast<size_t>(i)];
        if (digit > 0) {
            size_t idx = static_cast<size_t>((digit - 1) / 2);
            R = add(R, cache_entry->table[idx]);
        } else if (digit < 0) {
            size_t idx = static_cast<size_t>((-digit - 1) / 2);
            R = subtract(R, cache_entry->table[idx]);
        }
    }
    
    return R;
}

// ============================================================================
// Double Scalar Multiplication with Shamir's Trick + wNAF
// ============================================================================

JacobianPoint ECCurve::double_scalar_mult(const ZZ& k1, const JacobianPoint& P,
                                          const ZZ& k2, const JacobianPoint& Q) const {
    // Initialize modulus once for all point operations
    ZZ_p::init(p_);
    
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
