/**
 * @file ckks_context.cpp
 * @brief CKKS context, encoder, and evaluator implementation
 * 
 * CKKS enables homomorphic computation on encrypted floating-point numbers.
 * This implementation uses O(N²) DFT for correctness verification; Phase 4
 * will optimize to FFT.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/advanced/fe/ckks/ckks.hpp"
#include <stdexcept>
#include <cmath>

namespace kctsb::fhe::ckks {

// Use BGV's to_ZZ helper for uint64_t conversion
using bgv::to_ZZ;

// Math constants
constexpr double PI = 3.14159265358979323846;

// ============================================================================
// CKKSParams Implementation
// ============================================================================

ZZ CKKSParams::scale_zz() const {
    // 2^log_scale as ZZ
    ZZ result = ZZ(1);
    long log_s = static_cast<long>(log_scale);
    result <<= log_s;
    return result;
}

bgv::BGVParams CKKSParams::to_bgv_params() const {
    bgv::BGVParams bgv_params;
    bgv_params.m = m;
    bgv_params.n = n;
    // CKKS doesn't use plaintext modulus t, but BGV validation requires t > 0
    // Use a dummy value (65537 is common in HE implementations)
    bgv_params.t = 65537;
    bgv_params.q = q;
    bgv_params.primes = primes;
    bgv_params.L = static_cast<uint32_t>(L);
    bgv_params.sigma = sigma;
    bgv_params.security = security;
    return bgv_params;
}

bool CKKSParams::validate() const {
    if (n == 0 || (n & (n - 1)) != 0) {
        return false;  // n must be power of 2
    }
    if (m != 2 * n) {
        return false;  // m = 2n for cyclotomic
    }
    if (L == 0) {
        return false;  // Need at least 1 level
    }
    if (log_scale <= 0.0 || log_scale > 60.0) {
        return false;  // Reasonable scale range
    }
    if (IsZero(q) || q < 2) {
        return false;  // q must be > 1 for ZZ_pContext
    }
    if (primes.empty()) {
        return false;  // Need primes for modulus chain
    }
    return true;
}

// ============================================================================
// Standard Parameter Sets
// ============================================================================

CKKSParams StandardParams::TOY_PARAMS() {
    CKKSParams params;
    params.n = 256;
    params.m = 512;
    params.L = 2;  // Supports 2 multiplications (levels: 2 -> 1 -> 0)
    params.log_scale = 20.0;  // 2^20 scale (smaller to avoid overflow)
    params.sigma = 3.2;
    params.security = bgv::SecurityLevel::NONE;
    
    // For CKKS with L=2:
    // - Need L+1 = 3 primes in the chain
    // - Each prime ≈ 2^20 (matching scale)
    // - Total q ≈ 2^60, allowing scale^2 * value to fit
    // Primes must be 1 mod 2n = 1 mod 512 for NTT compatibility
    params.primes = {
        1048577,    // 2^20 + 1 (prime, and 1 mod 512)
        1049089,    // another ~20-bit prime ≡ 1 mod 512
        1049601     // another ~20-bit prime ≡ 1 mod 512
    };
    
    // Compute q = product of primes
    params.q = ZZ(1);
    for (auto p : params.primes) {
        params.q *= to_ZZ(p);
    }
    // q ≈ 2^60, scale ≈ 2^20, so scale^2 ≈ 2^40 << q
    
    return params;
}

CKKSParams StandardParams::SECURITY_128_DEPTH_3() {
    CKKSParams params;
    params.n = 4096;
    params.m = 8192;
    params.L = 3;
    params.log_scale = 40.0;  // 2^40 scale
    params.sigma = 3.2;
    params.security = bgv::SecurityLevel::CLASSICAL_128;
    
    // 60-bit primes for 128-bit security
    params.primes = {
        1152921504606584833ULL,
        1152921504598720513ULL,
        1152921504597016577ULL
    };
    
    params.q = ZZ(1);
    for (auto p : params.primes) {
        params.q *= to_ZZ(p);
    }
    
    return params;
}

CKKSParams StandardParams::SECURITY_128() {
    CKKSParams params;
    params.n = 8192;
    params.m = 16384;
    params.L = 5;
    params.log_scale = 40.0;
    params.sigma = 3.2;
    params.security = bgv::SecurityLevel::CLASSICAL_128;
    
    // 60-bit primes for deep computation
    params.primes = {
        1152921504606584833ULL,
        1152921504598720513ULL,
        1152921504597016577ULL,
        1152921504595443713ULL,
        1152921504593870849ULL
    };
    
    params.q = ZZ(1);
    for (auto p : params.primes) {
        params.q *= to_ZZ(p);
    }
    
    return params;
}

// ============================================================================
// CKKSPlaintext Implementation
// ============================================================================

long CKKSPlaintext::degree() const {
    return deg(poly_);
}

void CKKSPlaintext::set_coeff(long i, const ZZ_p& c) {
    SetCoeff(poly_, i, c);
}

ZZ_p CKKSPlaintext::coeff(long i) const {
    return kctsb::coeff(poly_, i);
}

// ============================================================================
// CKKSContext Implementation
// ============================================================================

CKKSContext::CKKSContext(const CKKSParams& params)
    : params_(params)
{
    if (!params.validate()) {
        throw std::invalid_argument("Invalid CKKS parameters");
    }
    
    // Create BGV context for key generation and crypto operations
    bgv_ctx_ = std::make_unique<bgv::BGVContext>(params.to_bgv_params());
    
    // Initialize modulus chain
    init_modulus_chain();
}

void CKKSContext::init_modulus_chain() {
    // Build modulus chain: q_L = full modulus, q_{L-1} = q_L / p_L, etc.
    // primes[] indexed from 0 to L: primes[i] is the prime for level i
    // q_L = p_0 * p_1 * ... * p_L
    // q_{i-1} = q_i / p_i  (removing prime p_i when going from level i to i-1)
    modulus_chain_.resize(params_.L + 1);
    
    modulus_chain_[params_.L] = params_.q;
    
    for (size_t i = params_.L; i > 0; i--) {
        // To go from level i to level i-1, divide by primes[i]
        if (i < params_.primes.size()) {
            ZZ prime = to_ZZ(params_.primes[i]);
            modulus_chain_[i - 1] = modulus_chain_[i] / prime;
        } else {
            // Fallback: divide by scale
            modulus_chain_[i - 1] = modulus_chain_[i] / params_.scale_zz();
        }
    }
}

ZZ CKKSContext::modulus_at_level(size_t level) const {
    if (level > params_.L) {
        throw std::out_of_range("Level exceeds maximum");
    }
    return modulus_chain_[level];
}

SecretKey CKKSContext::generate_secret_key() {
    return bgv_ctx_->generate_secret_key();
}

PublicKey CKKSContext::generate_public_key(const SecretKey& sk) {
    // CKKS public key generation: b = -a*s + e (NO t factor unlike BGV!)
    // This is critical for CKKS because the message is not scaled by t
    
    PublicKey pk;
    
    ZZ_p::init(params_.q);
    
    // Convert secret key to ZZ_pX
    ZZ_pX s;
    long sk_deg = sk.degree();
    for (long j = 0; j <= sk_deg; j++) {
        ZZ coef = sk.coefficients()[static_cast<size_t>(j)];
        if (coef < 0) coef += params_.q;
        SetCoeff(s, j, conv<ZZ_p>(coef));
    }
    
    // Build cyclotomic polynomial X^n + 1
    ZZ_pX cyclotomic;
    SetCoeff(cyclotomic, static_cast<long>(params_.n), 1);
    SetCoeff(cyclotomic, 0, 1);
    
    // Sample uniform a
    ZZ_pX a;
    for (size_t i = 0; i < params_.n; i++) {
        ZZ_p coef;
        random(coef);
        SetCoeff(a, static_cast<long>(i), coef);
    }
    
    // Sample error e (discrete Gaussian approximation)
    ZZ_pX e;
    int bound = static_cast<int>(params_.sigma * 6);
    for (size_t i = 0; i < params_.n; i++) {
        int err = (rand() % (2 * bound + 1)) - bound;
        if (err != 0) SetCoeff(e, static_cast<long>(i), conv<ZZ_p>(err));
    }
    
    // b = -a*s + e (mod X^n + 1) - NO t factor!
    ZZ_pX as;
    PlainMul(as, a, s);
    PlainRem(as, as, cyclotomic);
    
    ZZ_pX b = -as + e;
    PlainRem(b, b, cyclotomic);
    
    pk.a_.poly() = a;
    pk.b_.poly() = b;
    
    return pk;
}

RelinKey CKKSContext::generate_relin_key(const SecretKey& sk) {
    return bgv_ctx_->generate_relin_key(sk);
}

CKKSCiphertext CKKSContext::encrypt(const PublicKey& pk, const CKKSPlaintext& pt) {
    // CKKS encryption: c = (c_0, c_1) where
    // c_0 = b*u + e_0 + m  (no t factor unlike BGV!)
    // c_1 = a*u + e_1
    
    ZZ_p::init(params_.q);
    
    // Convert plaintext to mod q
    ZZ_pX pt_q;
    for (long i = 0; i <= pt.degree(); i++) {
        ZZ_p coef_p = pt.coeff(i);
        ZZ coef = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
        SetCoeff(pt_q, i, conv<ZZ_p>(coef));
    }
    
    // Get public key components and convert to current modulus
    ZZ_pX pk_b, pk_a;
    for (long j = 0; j <= pk.b().degree(); j++) {
        ZZ coef = IsZero(pk.b().coeff(j)) ? ZZ(0) : rep(pk.b().coeff(j));
        SetCoeff(pk_b, j, conv<ZZ_p>(coef));
    }
    for (long j = 0; j <= pk.a().degree(); j++) {
        ZZ coef = IsZero(pk.a().coeff(j)) ? ZZ(0) : rep(pk.a().coeff(j));
        SetCoeff(pk_a, j, conv<ZZ_p>(coef));
    }
    
    // Build cyclotomic polynomial X^n + 1
    ZZ_pX cyclotomic;
    SetCoeff(cyclotomic, static_cast<long>(params_.n), 1);
    SetCoeff(cyclotomic, 0, 1);
    
    // Sample random u ∈ {-1, 0, 1}^n (ternary)
    ZZ_pX u;
    for (size_t i = 0; i < params_.n; i++) {
        int r = (rand() % 3) - 1;  // -1, 0, or 1
        if (r != 0) {
            SetCoeff(u, static_cast<long>(i), conv<ZZ_p>(r));
        }
    }
    
    // Sample errors e_0, e_1 from discrete Gaussian (simplified: use small uniform)
    ZZ_pX e0, e1;
    int bound = static_cast<int>(params_.sigma * 6);  // 6σ bound
    for (size_t i = 0; i < params_.n; i++) {
        int err0 = (rand() % (2 * bound + 1)) - bound;
        int err1 = (rand() % (2 * bound + 1)) - bound;
        if (err0 != 0) SetCoeff(e0, static_cast<long>(i), conv<ZZ_p>(err0));
        if (err1 != 0) SetCoeff(e1, static_cast<long>(i), conv<ZZ_p>(err1));
    }
    
    // c_0 = b*u + e_0 + m (mod X^n + 1)
    ZZ_pX bu, c0;
    PlainMul(bu, pk_b, u);
    PlainRem(bu, bu, cyclotomic);
    c0 = bu + e0 + pt_q;
    PlainRem(c0, c0, cyclotomic);
    
    // c_1 = a*u + e_1 (mod X^n + 1)
    ZZ_pX au, c1;
    PlainMul(au, pk_a, u);
    PlainRem(au, au, cyclotomic);
    c1 = au + e1;
    PlainRem(c1, c1, cyclotomic);
    
    // Build result
    CKKSCiphertext result(params_.L, pt.scale());
    RingElement r0, r1;
    r0.poly() = c0;
    r1.poly() = c1;
    result.push_back(r0);
    result.push_back(r1);
    
    return result;
}

CKKSCiphertext CKKSContext::encrypt_symmetric(const SecretKey& sk, const CKKSPlaintext& pt) {
    // CKKS symmetric encryption: c = (-a*s + e + m, a)
    
    ZZ_p::init(params_.q);
    
    // Convert plaintext to mod q
    ZZ_pX pt_q;
    for (long i = 0; i <= pt.degree(); i++) {
        ZZ_p coef_p = pt.coeff(i);
        ZZ coef = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
        SetCoeff(pt_q, i, conv<ZZ_p>(coef));
    }
    
    // Build cyclotomic polynomial X^n + 1
    ZZ_pX cyclotomic;
    SetCoeff(cyclotomic, static_cast<long>(params_.n), 1);
    SetCoeff(cyclotomic, 0, 1);
    
    // Convert secret key to ZZ_pX
    ZZ_pX s;
    long sk_deg = sk.degree();
    for (long j = 0; j <= sk_deg; j++) {
        ZZ coef = sk.coefficients()[static_cast<size_t>(j)];
        if (coef < 0) coef += params_.q;
        SetCoeff(s, j, conv<ZZ_p>(coef));
    }
    
    // Sample random a
    ZZ_pX a;
    for (size_t i = 0; i < params_.n; i++) {
        ZZ_p coef;
        random(coef);
        SetCoeff(a, static_cast<long>(i), coef);
    }
    
    // Sample error e
    ZZ_pX e;
    int bound = static_cast<int>(params_.sigma * 6);
    for (size_t i = 0; i < params_.n; i++) {
        int err = (rand() % (2 * bound + 1)) - bound;
        if (err != 0) SetCoeff(e, static_cast<long>(i), conv<ZZ_p>(err));
    }
    
    // c_0 = -a*s + e + m (mod X^n + 1)
    ZZ_pX as, c0;
    PlainMul(as, a, s);
    PlainRem(as, as, cyclotomic);
    c0 = -as + e + pt_q;
    PlainRem(c0, c0, cyclotomic);
    
    // c_1 = a
    
    CKKSCiphertext result(params_.L, pt.scale());
    RingElement r0, r1;
    r0.poly() = c0;
    r1.poly() = a;
    result.push_back(r0);
    result.push_back(r1);
    
    return result;
}

CKKSPlaintext CKKSContext::decrypt(const SecretKey& sk, const CKKSCiphertext& ct) {
    // CKKS decryption: compute c_0 + c_1*s mod (X^n + 1, q)
    // Unlike BGV, we do NOT reduce mod t!
    
    if (ct.size() < 2) {
        throw std::invalid_argument("Invalid ciphertext size");
    }
    
    // Set modulus to the current level's modulus
    ZZ q = modulus_at_level(ct.level());
    ZZ_p::init(q);
    
    // Convert secret key coefficients to ZZ_pX
    ZZ_pX s_q;
    long sk_degree = sk.degree();
    for (long j = 0; j <= sk_degree; j++) {
        ZZ coef = sk.coefficients()[static_cast<size_t>(j)];
        if (coef < 0) {
            coef += q;  // Convert negative to positive mod q
        }
        SetCoeff(s_q, j, conv<ZZ_p>(coef));
    }
    
    // Build cyclotomic polynomial X^n + 1
    size_t n = ring_degree();
    ZZ_pX cyclotomic;
    SetCoeff(cyclotomic, static_cast<long>(n), 1);
    SetCoeff(cyclotomic, 0, 1);
    
    // Compute m = c_0 + c_1*s + c_2*s^2 + ... (mod Φ_m(X), mod q)
    // Using Horner's method
    ZZ_pX result;
    
    for (long k = static_cast<long>(ct.size()) - 1; k >= 0; k--) {
        // Convert c[k] to current modulus
        ZZ_pX ck_q;
        for (long j = 0; j <= ct[static_cast<size_t>(k)].degree(); j++) {
            ZZ coef = IsZero(ct[static_cast<size_t>(k)].coeff(j)) ? 
                      ZZ(0) : rep(ct[static_cast<size_t>(k)].coeff(j));
            // Reduce mod q for the current level
            coef = coef % q;
            SetCoeff(ck_q, j, conv<ZZ_p>(coef));
        }
        
        if (k == static_cast<long>(ct.size()) - 1) {
            result = ck_q;
        } else {
            ZZ_pX temp;
            PlainMul(temp, result, s_q);
            PlainRem(temp, temp, cyclotomic);
            result = temp + ck_q;
            PlainRem(result, result, cyclotomic);
        }
    }
    
    // Convert result to CKKS plaintext - NO mod t reduction!
    // Set level so decode() knows which modulus to use for signed conversion
    CKKSPlaintext pt(ct.scale(), ct.level());
    for (long i = 0; i <= deg(result); i++) {
        pt.set_coeff(i, coeff(result, i));
    }
    
    return pt;
}

// ============================================================================
// CKKSEncoder Implementation
// ============================================================================

CKKSEncoder::CKKSEncoder(const CKKSContext& ctx)
    : ctx_(ctx)
    , n_(ctx.ring_degree())
    , slots_(ctx.slot_count())
{
    precompute_roots();
}

void CKKSEncoder::precompute_roots() {
    // Precompute N-th roots of unity for DFT
    // For CKKS, we use ζ = e^{2πi/2N} (primitive 2N-th root)
    roots_.resize(n_);
    
    for (size_t j = 0; j < n_; j++) {
        // Use odd indices for canonical embedding: ζ^(2j+1)
        double angle = 2.0 * PI * (2 * j + 1) / (2.0 * n_);
        roots_[j] = Complex(std::cos(angle), std::sin(angle));
    }
}

std::vector<Complex> CKKSEncoder::inverse_dft(const std::vector<Complex>& values) {
    // Inverse DFT: from evaluation points back to coefficients
    // coeffs[k] = (1/N) * sum_{j=0}^{N-1} values[j] * ζ^{-jk}
    
    size_t N = values.size();
    std::vector<Complex> coeffs(N);
    
    for (size_t k = 0; k < N; k++) {
        coeffs[k] = Complex(0.0, 0.0);
        for (size_t j = 0; j < N; j++) {
            // ζ^{-(2j+1)*k} = e^{-2πi(2j+1)k/(2N)}
            double angle = -2.0 * PI * (2 * j + 1) * k / (2.0 * N);
            Complex w(std::cos(angle), std::sin(angle));
            coeffs[k] += values[j] * w;
        }
        coeffs[k] /= static_cast<double>(N);
    }
    
    return coeffs;
}

std::vector<Complex> CKKSEncoder::forward_dft(const std::vector<Complex>& coeffs) {
    // Forward DFT: from coefficients to evaluation points
    // values[j] = sum_{k=0}^{N-1} coeffs[k] * ζ^{jk}
    
    size_t N = coeffs.size();
    std::vector<Complex> values(N);
    
    for (size_t j = 0; j < N; j++) {
        values[j] = Complex(0.0, 0.0);
        for (size_t k = 0; k < N; k++) {
            // ζ^{(2j+1)*k} = e^{2πi(2j+1)k/(2N)}
            double angle = 2.0 * PI * (2 * j + 1) * k / (2.0 * N);
            Complex w(std::cos(angle), std::sin(angle));
            values[j] += coeffs[k] * w;
        }
    }
    
    return values;
}

CKKSPlaintext CKKSEncoder::encode(const std::vector<Complex>& values, double scale) {
    if (scale == 0.0) {
        scale = ctx_.scale();
    }
    
    if (values.size() > slots_) {
        throw std::invalid_argument("Too many values for encoding (max " + 
                                    std::to_string(slots_) + ")");
    }
    
    // Simplified CKKS encoding for Phase 3:
    // Directly encode values as scaled polynomial coefficients
    // Full canonical embedding (FFT) will be implemented in Phase 4
    
    ZZ_p::init(ctx_.params().q);
    
    CKKSPlaintext pt(scale);
    
    for (size_t i = 0; i < values.size(); i++) {
        // Scale the real part
        double scaled_real = values[i].real() * scale;
        
        // Round to nearest integer
        int64_t rounded = static_cast<int64_t>(std::round(scaled_real));
        
        // Handle negative values
        ZZ coef_zz;
        if (rounded >= 0) {
            coef_zz = to_ZZ(static_cast<uint64_t>(rounded));
        } else {
            // Negative: add q to get positive representative
            coef_zz = ctx_.params().q - to_ZZ(static_cast<uint64_t>(-rounded));
        }
        
        pt.set_coeff(static_cast<long>(i), conv<ZZ_p>(coef_zz));
    }
    
    return pt;
}

CKKSPlaintext CKKSEncoder::encode_real(const std::vector<double>& values, double scale) {
    std::vector<Complex> complex_vals(values.size());
    for (size_t i = 0; i < values.size(); i++) {
        complex_vals[i] = Complex(values[i], 0.0);
    }
    return encode(complex_vals, scale);
}

CKKSPlaintext CKKSEncoder::encode_single(double value, double scale) {
    // For Phase 3 simplified encoding:
    // A single value is encoded as a CONSTANT polynomial: p(X) = value * scale
    // This allows correct multiplication: (a*s) * (b*s) = a*b*s²
    // Full SIMD packing (multiple slots) will be implemented in Phase 4 with FFT
    
    if (scale == 0.0) {
        scale = ctx_.scale();
    }
    
    ZZ_p::init(ctx_.params().q);
    
    CKKSPlaintext pt(scale);
    
    // Only set coefficient 0 (constant term)
    double scaled_real = value * scale;
    int64_t rounded = static_cast<int64_t>(std::round(scaled_real));
    
    ZZ coef_zz;
    if (rounded >= 0) {
        coef_zz = to_ZZ(static_cast<uint64_t>(rounded));
    } else {
        coef_zz = ctx_.params().q - to_ZZ(static_cast<uint64_t>(-rounded));
    }
    
    pt.set_coeff(0, conv<ZZ_p>(coef_zz));
    
    return pt;
}

std::vector<Complex> CKKSEncoder::decode(const CKKSPlaintext& pt) {
    double scale = pt.scale();
    if (scale <= 0.0) {
        scale = ctx_.scale();
    }
    
    // Simplified CKKS decoding for Phase 3:
    // Directly decode polynomial coefficients as values
    // Full canonical embedding (FFT) will be implemented in Phase 4
    
    // Use the correct modulus based on the plaintext's level
    ZZ q;
    size_t level = pt.level();
    if (level == SIZE_MAX || level > ctx_.params().L) {
        q = ctx_.params().q;  // Use full modulus q_L
    } else {
        q = ctx_.modulus_at_level(level);
    }
    ZZ q_half = q / 2;
    
    std::vector<Complex> result(slots_, Complex(0.0, 0.0));
    
    for (size_t i = 0; i < slots_; i++) {
        ZZ_p coef_p = pt.coeff(static_cast<long>(i));
        ZZ coef = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
        
        // Coefficients from decryption are already in range [0, q_level)
        // Need to reduce mod q_level in case rep() returned something larger
        coef = coef % q;
        
        // Convert to signed representation
        double val;
        if (coef > q_half) {
            val = -conv<double>(q - coef);
        } else {
            val = conv<double>(coef);
        }
        
        // Divide by scale to get original value
        result[i] = Complex(val / scale, 0.0);
    }
    
    return result;
}

std::vector<double> CKKSEncoder::decode_real(const CKKSPlaintext& pt) {
    std::vector<Complex> complex_vals = decode(pt);
    std::vector<double> result(complex_vals.size());
    for (size_t i = 0; i < complex_vals.size(); i++) {
        result[i] = complex_vals[i].real();
    }
    return result;
}

// ============================================================================
// CKKSEvaluator Implementation
// ============================================================================

CKKSEvaluator::CKKSEvaluator(const CKKSContext& ctx)
    : ctx_(ctx)
    , bgv_eval_(std::make_unique<bgv::BGVEvaluator>(ctx.bgv_context()))
{
}

bgv::BGVCiphertext CKKSEvaluator::to_bgv_ct(const CKKSCiphertext& ct) const {
    bgv::BGVCiphertext bgv_ct;
    for (size_t i = 0; i < ct.size(); i++) {
        bgv_ct.push_back(ct[i]);
    }
    return bgv_ct;
}

CKKSCiphertext CKKSEvaluator::from_bgv_ct(const bgv::BGVCiphertext& ct,
                                           size_t level, double scale) const {
    CKKSCiphertext result(level, scale);
    for (size_t i = 0; i < ct.size(); i++) {
        result.push_back(ct[i]);
    }
    return result;
}

CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    // Check scales match
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for addition");
    }
    
    // Delegate to BGV
    bgv::BGVCiphertext bgv_ct = bgv_eval_->add(to_bgv_ct(ct1), to_bgv_ct(ct2));
    
    // Use minimum level
    size_t new_level = std::min(ct1.level(), ct2.level());
    return from_bgv_ct(bgv_ct, new_level, ct1.scale());
}

CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt) {
    // Convert plaintext
    bgv::BGVPlaintext bgv_pt;
    bgv_pt.data().poly() = pt.data();
    
    bgv::BGVCiphertext bgv_ct = bgv_eval_->add_plain(to_bgv_ct(ct), bgv_pt);
    return from_bgv_ct(bgv_ct, ct.level(), ct.scale());
}

CKKSCiphertext CKKSEvaluator::sub(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for subtraction");
    }
    
    bgv::BGVCiphertext bgv_ct = bgv_eval_->sub(to_bgv_ct(ct1), to_bgv_ct(ct2));
    
    size_t new_level = std::min(ct1.level(), ct2.level());
    return from_bgv_ct(bgv_ct, new_level, ct1.scale());
}

CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    // Multiply using BGV
    bgv::BGVCiphertext bgv_ct = bgv_eval_->multiply(to_bgv_ct(ct1), to_bgv_ct(ct2));
    
    // New scale = scale1 * scale2
    double new_scale = ct1.scale() * ct2.scale();
    size_t new_level = std::min(ct1.level(), ct2.level());
    
    return from_bgv_ct(bgv_ct, new_level, new_scale);
}

CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt) {
    bgv::BGVPlaintext bgv_pt;
    bgv_pt.data().poly() = pt.data();
    
    bgv::BGVCiphertext bgv_ct = bgv_eval_->multiply_plain(to_bgv_ct(ct), bgv_pt);
    
    double new_scale = ct.scale() * pt.scale();
    return from_bgv_ct(bgv_ct, ct.level(), new_scale);
}

CKKSCiphertext CKKSEvaluator::rescale(const CKKSCiphertext& ct) {
    if (ct.level() == 0) {
        throw std::runtime_error("Cannot rescale: already at level 0");
    }
    
    // Get the prime to divide by: p_{level} (the prime being removed)
    // Going from level i to level i-1 requires dividing by primes[i]
    size_t level = ct.level();
    ZZ divisor;
    
    if (level < ctx_.params().primes.size()) {
        divisor = to_ZZ(ctx_.params().primes[level]);
    } else {
        divisor = ctx_.params().scale_zz();
    }
    
    // Current modulus (for reading coefficients)
    ZZ old_q = ctx_.modulus_at_level(level);
    // New modulus (for output)
    ZZ new_q = ctx_.modulus_at_level(level - 1);
    
    // CRITICAL: First extract all coefficients as ZZ values BEFORE changing ZZ_p modulus
    // because ZZ_pX coefficients become invalid after ZZ_p::init() with different modulus
    std::vector<std::vector<ZZ>> coefficients_zz(ct.size());
    
    ZZ_p::init(old_q);  // Ensure correct modulus for reading
    for (size_t i = 0; i < ct.size(); i++) {
        const ZZ_pX& poly = ct[i].poly();
        long d = deg(poly);
        coefficients_zz[i].resize(static_cast<size_t>(d + 1));
        for (long j = 0; j <= d; j++) {
            ZZ_p coef_p = coeff(poly, j);
            coefficients_zz[i][static_cast<size_t>(j)] = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
        }
    }
    
    // Now switch to new modulus
    ZZ_p::init(new_q);
    
    CKKSCiphertext result(level - 1, ct.scale() / conv<double>(divisor));
    
    for (size_t i = 0; i < ct.size(); i++) {
        RingElement re;
        
        for (size_t j = 0; j < coefficients_zz[i].size(); j++) {
            ZZ c = coefficients_zz[i][j];
            
            // Round: floor((2*coef + divisor) / (2*divisor))
            ZZ numerator = 2 * c + divisor;
            ZZ rounded = numerator / (2 * divisor);
            
            // Reduce to new modulus
            rounded = rounded % new_q;
            
            SetCoeff(re.poly(), static_cast<long>(j), conv<ZZ_p>(rounded));
        }
        
        result.push_back(re);
    }
    
    return result;
}

CKKSCiphertext CKKSEvaluator::relinearize(const CKKSCiphertext& ct, const RelinKey& rk) {
    bgv::BGVCiphertext bgv_ct = bgv_eval_->relinearize(to_bgv_ct(ct), rk);
    return from_bgv_ct(bgv_ct, ct.level(), ct.scale());
}

CKKSCiphertext CKKSEvaluator::multiply_relin_rescale(const CKKSCiphertext& ct1,
                                                      const CKKSCiphertext& ct2,
                                                      const RelinKey& rk) {
    CKKSCiphertext product = multiply(ct1, ct2);
    CKKSCiphertext relined = relinearize(product, rk);
    return rescale(relined);
}

CKKSCiphertext CKKSEvaluator::mod_switch(const CKKSCiphertext& ct) {
    // Mod switch: reduce modulus without changing scale
    // This is similar to rescale but preserves scale
    
    if (ct.level() == 0) {
        throw std::runtime_error("Cannot mod switch: already at level 0");
    }
    
    // Get divisor: primes[level] for going from level to level-1
    size_t level = ct.level();
    ZZ divisor;
    
    if (level < ctx_.params().primes.size()) {
        divisor = to_ZZ(ctx_.params().primes[level]);
    } else {
        divisor = ctx_.params().scale_zz();
    }
    
    ZZ old_q = ctx_.modulus_at_level(level);
    ZZ new_q = ctx_.modulus_at_level(level - 1);
    
    // Extract coefficients as ZZ before changing modulus
    std::vector<std::vector<ZZ>> coefficients_zz(ct.size());
    
    ZZ_p::init(old_q);
    for (size_t i = 0; i < ct.size(); i++) {
        const ZZ_pX& poly = ct[i].poly();
        long d = deg(poly);
        coefficients_zz[i].resize(static_cast<size_t>(d + 1));
        for (long j = 0; j <= d; j++) {
            ZZ_p coef_p = coeff(poly, j);
            coefficients_zz[i][static_cast<size_t>(j)] = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
        }
    }
    
    ZZ_p::init(new_q);
    
    // Keep original scale
    CKKSCiphertext result(level - 1, ct.scale());
    
    for (size_t i = 0; i < ct.size(); i++) {
        RingElement re;
        
        for (size_t j = 0; j < coefficients_zz[i].size(); j++) {
            ZZ c = coefficients_zz[i][j];
            
            // Round
            ZZ numerator = 2 * c + divisor;
            ZZ rounded = numerator / (2 * divisor);
            rounded = rounded % new_q;
            
            SetCoeff(re.poly(), static_cast<long>(j), conv<ZZ_p>(rounded));
        }
        
        result.push_back(re);
    }
    
    return result;
}

bool CKKSEvaluator::scales_match(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2,
                                  double tolerance) const {
    double ratio = ct1.scale() / ct2.scale();
    return std::abs(ratio - 1.0) < tolerance;
}

}  // namespace kctsb::fhe::ckks
