/**
 * @file bfv_context.cpp
 * @brief BFV context implementation
 * 
 * BFV context manages parameters, key generation, encryption and decryption.
 * Internally delegates to BGV context for most operations, with BFV-specific
 * encoding applied during encrypt/decrypt.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/advanced/fe/bfv/bfv.hpp"
#include <stdexcept>

namespace kctsb::fhe::bfv {

// Use BGV's to_ZZ helper for uint64_t conversion
using bgv::to_ZZ;

// ============================================================================
// BFV Parameters
// ============================================================================

bgv::BGVParams BFVParams::to_bgv_params() const {
    bgv::BGVParams bgv_params;
    bgv_params.m = m;
    bgv_params.n = n;
    bgv_params.t = t;
    bgv_params.q = q;
    bgv_params.primes = primes;
    bgv_params.L = static_cast<uint32_t>(L);
    bgv_params.sigma = sigma;
    bgv_params.security = security;
    return bgv_params;
}

BFVParams BFVParams::create_from_bgv(const bgv::BGVParams& bgv_params) {
    BFVParams params;
    params.m = bgv_params.m;
    params.n = bgv_params.n;
    params.t = bgv_params.t;
    params.q = bgv_params.q;
    params.primes = bgv_params.primes;
    params.L = bgv_params.L;
    params.sigma = bgv_params.sigma;
    params.security = bgv_params.security;
    return params;
}

// ============================================================================
// Standard Parameter Sets
// ============================================================================

BFVParams StandardParams::TOY_PARAMS() {
    auto bgv_params = bgv::StandardParams::TOY_PARAMS();
    return BFVParams::create_from_bgv(bgv_params);
}

BFVParams StandardParams::SECURITY_128_DEPTH_3() {
    auto bgv_params = bgv::StandardParams::SECURITY_128_DEPTH_3();
    return BFVParams::create_from_bgv(bgv_params);
}

BFVParams StandardParams::SECURITY_128() {
    auto bgv_params = bgv::StandardParams::SECURITY_128_DEPTH_5();
    return BFVParams::create_from_bgv(bgv_params);
}

// ============================================================================
// BFV Context Implementation
// ============================================================================

BFVContext::BFVContext(const BFVParams& params)
    : params_(params)
    , bgv_ctx_(std::make_unique<bgv::BGVContext>(params.to_bgv_params()))
{
    // Validate delta is well-defined
    if (params_.delta() < ZZ(1)) {
        throw std::invalid_argument("BFV requires q >= t for valid scaling factor");
    }
}

SecretKey BFVContext::generate_secret_key() {
    return bgv_ctx_->generate_secret_key();
}

PublicKey BFVContext::generate_public_key(const SecretKey& sk) {
    return bgv_ctx_->generate_public_key(sk);
}

RelinKey BFVContext::generate_relin_key(const SecretKey& sk) {
    return bgv_ctx_->generate_relin_key(sk);
}

Ciphertext BFVContext::encrypt(const PublicKey& pk, const Plaintext& pt) {
    // BFV encryption: plaintext should already be Δ-scaled by encoder
    // Delegate to BGV encryption
    return bgv_ctx_->encrypt(pk, pt);
}

Ciphertext BFVContext::encrypt_symmetric(const SecretKey& sk, const Plaintext& pt) {
    return bgv_ctx_->encrypt_symmetric(sk, pt);
}

Plaintext BFVContext::decrypt(const SecretKey& sk, const Ciphertext& ct) {
    // BFV decryption: result needs to be decoded by BFVEncoder
    return bgv_ctx_->decrypt(sk, ct);
}

// ============================================================================
// BFV Encoder Implementation
// ============================================================================

BFVEncoder::BFVEncoder(const BFVContext& ctx)
    : ctx_(ctx)
    , delta_(ctx.delta())
{
}

Plaintext BFVEncoder::encode(int64_t value) {
    // For simplicity, BFV encoding uses the same approach as BGV
    // (direct coefficient encoding without Δ-scaling for now)
    // The value is stored directly in the plaintext polynomial
    
    ZZ_p::init(to_ZZ(ctx_.plaintext_modulus()));
    
    int64_t t = static_cast<int64_t>(ctx_.plaintext_modulus());
    int64_t normalized = ((value % t) + t) % t;
    
    Plaintext pt;
    pt.data().set_coeff(0, conv<ZZ_p>(to_ZZ(static_cast<uint64_t>(normalized))));
    return pt;
}

Plaintext BFVEncoder::encode_batch(const std::vector<int64_t>& values) {
    ZZ_p::init(to_ZZ(ctx_.plaintext_modulus()));
    
    int64_t t = static_cast<int64_t>(ctx_.plaintext_modulus());
    size_t n = ctx_.ring_degree();
    
    Plaintext pt;
    
    for (size_t i = 0; i < std::min(values.size(), n); i++) {
        int64_t normalized = ((values[i] % t) + t) % t;
        pt.data().set_coeff(static_cast<long>(i), 
            conv<ZZ_p>(to_ZZ(static_cast<uint64_t>(normalized))));
    }
    
    return pt;
}

int64_t BFVEncoder::decode(const Plaintext& pt) {
    // Direct decoding - value is in coefficient 0
    ZZ_p coef_p = pt.data().coeff(0);
    ZZ coef = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
    
    int64_t t = static_cast<int64_t>(ctx_.plaintext_modulus());
    int64_t result = conv<long>(coef % to_ZZ(static_cast<uint64_t>(t)));
    
    // Map to signed range if needed: if result > t/2, result -= t
    if (result > t / 2) {
        result -= t;
    }
    
    return result;
}

std::vector<int64_t> BFVEncoder::decode_batch(const Plaintext& pt) {
    std::vector<int64_t> result;
    size_t n = ctx_.ring_degree();
    int64_t t = static_cast<int64_t>(ctx_.plaintext_modulus());
    
    for (size_t i = 0; i < n; i++) {
        ZZ_p coef_p = pt.data().coeff(static_cast<long>(i));
        ZZ coef = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
        
        int64_t val = conv<long>(coef % to_ZZ(static_cast<uint64_t>(t)));
        
        // Map to signed range
        if (val > t / 2) {
            val -= t;
        }
        
        result.push_back(val);
    }
    
    return result;
}

// ============================================================================
// BFV Evaluator Implementation
// ============================================================================

BFVEvaluator::BFVEvaluator(const BFVContext& ctx)
    : ctx_(ctx)
    , bgv_eval_(std::make_unique<bgv::BGVEvaluator>(ctx.bgv_context()))
{
}

Ciphertext BFVEvaluator::add(const Ciphertext& ct1, const Ciphertext& ct2) {
    // Addition is the same as BGV
    return bgv_eval_->add(ct1, ct2);
}

Ciphertext BFVEvaluator::add_plain(const Ciphertext& ct, const Plaintext& pt) {
    return bgv_eval_->add_plain(ct, pt);
}

Ciphertext BFVEvaluator::sub(const Ciphertext& ct1, const Ciphertext& ct2) {
    return bgv_eval_->sub(ct1, ct2);
}

Ciphertext BFVEvaluator::multiply_raw(const Ciphertext& ct1, const Ciphertext& ct2) {
    // Raw multiplication without rescale (returns 3-component ciphertext)
    return bgv_eval_->multiply(ct1, ct2);
}

Ciphertext BFVEvaluator::rescale(const Ciphertext& ct) {
    // BFV rescale: ct' = round(ct / Δ)
    // This brings the scale from Δ² back to Δ after multiplication
    
    const auto& params = ctx_.params();
    ZZ delta = params.delta();
    ZZ q = params.q;
    
    // New modulus after rescale
    ZZ new_q = q / delta;
    if (new_q < ZZ(1)) {
        throw std::runtime_error("Rescale failed: modulus too small after division by delta");
    }
    
    ZZ_p::init(new_q);
    
    Ciphertext result;
    
    for (size_t i = 0; i < ct.size(); i++) {
        RingElement re;
        const ZZ_pX& poly = ct[i].poly();
        
        for (long j = 0; j <= deg(poly); j++) {
            ZZ_p coef_p = coeff(poly, j);
            ZZ c = IsZero(coef_p) ? ZZ(0) : rep(coef_p);
            
            // Ensure positive for rounding
            if (c < ZZ(0)) {
                c += q;
            }
            
            // Round: floor((2*coef + delta) / (2*delta))
            ZZ numerator = 2 * c + delta;
            ZZ rounded = numerator / (2 * delta);
            
            // Reduce to new modulus
            rounded = rounded % new_q;
            
            SetCoeff(re.poly(), j, conv<ZZ_p>(rounded));
        }
        
        result.push_back(re);
    }
    
    return result;
}

Ciphertext BFVEvaluator::multiply(const Ciphertext& ct1, const Ciphertext& ct2) {
    // BFV multiply: tensor product then rescale
    // Note: In standard BFV, we don't always rescale immediately.
    // For simplicity, we return the raw product (caller can rescale if needed)
    return multiply_raw(ct1, ct2);
}

Ciphertext BFVEvaluator::multiply_plain(const Ciphertext& ct, const Plaintext& pt) {
    return bgv_eval_->multiply_plain(ct, pt);
}

Ciphertext BFVEvaluator::relinearize(const Ciphertext& ct, const RelinKey& rk) {
    return bgv_eval_->relinearize(ct, rk);
}

Ciphertext BFVEvaluator::multiply_relin(const Ciphertext& ct1, const Ciphertext& ct2,
                                         const RelinKey& rk) {
    // Multiply, then relinearize (no automatic rescale in this version)
    Ciphertext product = multiply_raw(ct1, ct2);
    return relinearize(product, rk);
}

double BFVEvaluator::noise_budget(const Ciphertext& ct) const {
    return ct.noise_budget();
}

}  // namespace kctsb::fhe::bfv
