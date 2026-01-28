/**
 * @file ckks_evaluator.cpp
 * @brief CKKS Evaluator Implementation - Pure RNS Architecture
 *
 * High-performance CKKS implementation using:
 * - Pure RNS polynomial representation (RNSPoly)
 * - NTT for fast polynomial multiplication
 * - FFT-based canonical embedding for encode/decode
 * - Multi-precision arithmetic for large moduli
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.14.0
 */

#include "kctsb/advanced/fe/ckks/ckks_evaluator.hpp"
#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace kctsb {
namespace fhe {
namespace ckks {

// ============================================================================
// CKKSEncoder Implementation
// ============================================================================

CKKSEncoder::CKKSEncoder(const RNSContext* ctx, double default_scale)
    : context_(ctx)
    , n_(ctx ? ctx->n() : 0)
    , slots_(n_ / 2)
    , default_scale_(default_scale)
{
    if (!ctx) {
        throw std::invalid_argument("RNS context cannot be null");
    }
    precompute_roots();
}

void CKKSEncoder::precompute_roots() {
    // Precompute 2N-th roots of unity for canonical embedding
    // CKKS uses zeta^(2j+1) where zeta = exp(i*pi/N)
    roots_.resize(n_);
    roots_inv_.resize(n_);
    
    for (size_t j = 0; j < n_; ++j) {
        // zeta^(2j+1) = exp(i*pi*(2j+1)/N)
        double angle = PI * static_cast<double>(2 * j + 1) / static_cast<double>(n_);
        roots_[j] = Complex(std::cos(angle), std::sin(angle));
        roots_inv_[j] = std::conj(roots_[j]);
    }
}

void CKKSEncoder::bit_reverse_permute(std::vector<Complex>& values) {
    size_t n = values.size();
    size_t log_n = 0;
    while ((1ULL << log_n) < n) ++log_n;
    
    for (size_t i = 0; i < n; ++i) {
        size_t rev = 0;
        for (size_t j = 0; j < log_n; ++j) {
            if (i & (1ULL << j)) {
                rev |= (1ULL << (log_n - 1 - j));
            }
        }
        if (i < rev) {
            std::swap(values[i], values[rev]);
        }
    }
}

void CKKSEncoder::fft_forward(std::vector<Complex>& values) {
    size_t n = values.size();
    bit_reverse_permute(values);
    
    for (size_t len = 2; len <= n; len *= 2) {
        double angle = 2.0 * PI / static_cast<double>(len);
        Complex w_len(std::cos(angle), std::sin(angle));
        
        for (size_t i = 0; i < n; i += len) {
            Complex w(1.0, 0.0);
            for (size_t j = 0; j < len / 2; ++j) {
                Complex u = values[i + j];
                Complex v = values[i + j + len / 2] * w;
                values[i + j] = u + v;
                values[i + j + len / 2] = u - v;
                w *= w_len;
            }
        }
    }
}

void CKKSEncoder::fft_inverse(std::vector<Complex>& values) {
    size_t n = values.size();
    
    for (auto& v : values) {
        v = std::conj(v);
    }
    fft_forward(values);
    double scale = 1.0 / static_cast<double>(n);
    for (auto& v : values) {
        v = std::conj(v) * scale;
    }
}

CKKSPlaintext CKKSEncoder::encode(const std::vector<Complex>& values, double scale) {
    if (scale == 0.0) scale = default_scale_;
    if (scale == 0.0) scale = std::pow(2.0, 40.0);
    
    if (values.size() > slots_) {
        throw std::invalid_argument("Too many values for encoding");
    }
    
    // Pad input to n/2 slots
    std::vector<Complex> padded(slots_, Complex(0.0, 0.0));
    std::copy(values.begin(), values.end(), padded.begin());
    
    // CKKS canonical embedding: inverse FFT from slots to n coefficients
    // First, extend to n complex values by conjugate symmetry
    std::vector<Complex> extended(n_);
    for (size_t i = 0; i < slots_; ++i) {
        extended[i] = padded[i] * scale;
        extended[n_ - 1 - i] = std::conj(padded[i] * scale);
    }
    
    // Apply inverse FFT to get polynomial coefficients
    fft_inverse(extended);
    
    CKKSPlaintext pt(context_, scale);
    size_t L = context_->level_count();
    
    for (size_t level = 0; level < L; ++level) {
        const Modulus& mod = context_->modulus(level);
        uint64_t q = mod.value();
        
        for (size_t i = 0; i < n_; ++i) {
            double real_val = extended[i].real();
            int64_t rounded = static_cast<int64_t>(std::round(real_val));
            
            uint64_t coef;
            if (rounded >= 0) {
                coef = static_cast<uint64_t>(rounded) % q;
            } else {
                uint64_t abs_val = static_cast<uint64_t>(-rounded) % q;
                coef = (abs_val == 0) ? 0 : q - abs_val;
            }
            pt.data()(level, i) = coef;
        }
    }
    return pt;
}

CKKSPlaintext CKKSEncoder::encode_real(const std::vector<double>& values, double scale) {
    std::vector<Complex> complex_vals(values.size());
    for (size_t i = 0; i < values.size(); ++i) {
        complex_vals[i] = Complex(values[i], 0.0);
    }
    return encode(complex_vals, scale);
}

CKKSPlaintext CKKSEncoder::encode_single(double value, double scale) {
    if (scale == 0.0) scale = default_scale_;
    if (scale == 0.0) scale = std::pow(2.0, 40.0);
    
    CKKSPlaintext pt(context_, scale);
    size_t L = context_->level_count();
    
    double scaled_value = value * scale;
    int64_t rounded = static_cast<int64_t>(std::round(scaled_value));
    
    for (size_t level = 0; level < L; ++level) {
        const Modulus& mod = context_->modulus(level);
        uint64_t q = mod.value();
        
        uint64_t coef;
        if (rounded >= 0) {
            coef = static_cast<uint64_t>(rounded) % q;
        } else {
            uint64_t abs_val = static_cast<uint64_t>(-rounded) % q;
            coef = (abs_val == 0) ? 0 : q - abs_val;
        }
        
        pt.data()(level, 0) = coef;
        for (size_t i = 1; i < n_; ++i) {
            pt.data()(level, i) = 0;
        }
    }
    return pt;
}

std::vector<Complex> CKKSEncoder::decode(const CKKSPlaintext& pt) {
    double scale = pt.scale();
    if (scale <= 0.0) scale = default_scale_;
    if (scale <= 0.0) scale = std::pow(2.0, 40.0);
    
    size_t level = pt.level();
    const Modulus& mod = context_->modulus(level);
    uint64_t q = mod.value();
    uint64_t q_half = q / 2;
    
    // Convert RNS coefficients to complex numbers
    std::vector<Complex> coeffs(n_);
    for (size_t i = 0; i < n_; ++i) {
        uint64_t coef = pt.data()(level, i);
        double val;
        if (coef > q_half) {
            val = -static_cast<double>(q - coef);
        } else {
            val = static_cast<double>(coef);
        }
        coeffs[i] = Complex(val, 0.0);
    }
    
    // Apply forward FFT to get slot values
    fft_forward(coeffs);
    
    // Extract first n/2 slots and apply inverse scale
    std::vector<Complex> result(slots_);
    for (size_t i = 0; i < slots_; ++i) {
        result[i] = coeffs[i] / scale;
    }
    return result;
}

std::vector<double> CKKSEncoder::decode_real(const CKKSPlaintext& pt) {
    std::vector<Complex> complex_vals = decode(pt);
    std::vector<double> result(complex_vals.size());
    for (size_t i = 0; i < complex_vals.size(); ++i) {
        result[i] = complex_vals[i].real();
    }
    return result;
}

// ============================================================================
// CKKSEvaluator Implementation
// ============================================================================

CKKSEvaluator::CKKSEvaluator(const RNSContext* ctx, double default_scale)
    : context_(ctx)
    , default_scale_(default_scale > 0 ? default_scale : std::pow(2.0, 40.0))
{
    if (!ctx) {
        throw std::invalid_argument("RNS context cannot be null");
    }
    encoder_ = std::make_unique<CKKSEncoder>(ctx, default_scale_);
}

void CKKSEvaluator::sample_ternary_rns(RNSPoly* poly, std::mt19937_64& rng) {
    size_t n = context_->n();
    size_t L = context_->level_count();
    std::uniform_int_distribution<int> dist(-1, 1);
    
    for (size_t i = 0; i < n; ++i) {
        int val = dist(rng);
        for (size_t level = 0; level < L; ++level) {
            uint64_t q = context_->modulus(level).value();
            uint64_t coef = (val >= 0) ? static_cast<uint64_t>(val) : q - 1;
            (*poly)(level, i) = coef;
        }
    }
}

void CKKSEvaluator::sample_error_rns(RNSPoly* poly, double sigma, std::mt19937_64& rng) {
    size_t n = context_->n();
    size_t L = context_->level_count();
    std::normal_distribution<double> dist(0.0, sigma);
    
    for (size_t i = 0; i < n; ++i) {
        int64_t val = static_cast<int64_t>(std::round(dist(rng)));
        for (size_t level = 0; level < L; ++level) {
            uint64_t q = context_->modulus(level).value();
            uint64_t coef;
            if (val >= 0) {
                coef = static_cast<uint64_t>(val) % q;
            } else {
                uint64_t abs_val = static_cast<uint64_t>(-val) % q;
                coef = (abs_val == 0) ? 0 : q - abs_val;
            }
            (*poly)(level, i) = coef;
        }
    }
}

void CKKSEvaluator::sample_uniform_rns(RNSPoly* poly, std::mt19937_64& rng) {
    size_t n = context_->n();
    size_t L = context_->level_count();
    
    for (size_t level = 0; level < L; ++level) {
        uint64_t q = context_->modulus(level).value();
        std::uniform_int_distribution<uint64_t> dist(0, q - 1);
        for (size_t i = 0; i < n; ++i) {
            (*poly)(level, i) = dist(rng);
        }
    }
}

CKKSSecretKey CKKSEvaluator::generate_secret_key(std::mt19937_64& rng) {
    CKKSSecretKey sk;
    sk.s = RNSPoly(context_);
    sample_ternary_rns(&sk.s, rng);
    sk.s.ntt_transform();
    sk.is_ntt_form = true;
    return sk;
}

CKKSPublicKey CKKSEvaluator::generate_public_key(const CKKSSecretKey& sk, std::mt19937_64& rng) {
    if (!sk.is_ntt_form) {
        throw std::invalid_argument("Secret key must be in NTT form");
    }
    
    // CKKS public key: pk = (-(a*s + e), a)
    // Same formula as BFV for consistency
    
    // 1. Sample random polynomial a (uniform mod q)
    RNSPoly a(context_);
    sample_uniform_rns(&a, rng);
    a.ntt_transform();
    
    // 2. Sample small error e ~ Gaussian
    RNSPoly e(context_);
    sample_error_rns(&e, 3.2, rng);
    e.ntt_transform();
    
    // 3. Compute b = -(a*s + e) - exactly like BFV
    RNSPoly as = a * sk.s;  // NTT domain multiply
    RNSPoly b = as;
    b += e;                 // a*s + e
    b.negate();             // -(a*s + e)
    
    CKKSPublicKey pk;
    pk.b = std::move(b);
    pk.a = std::move(a);
    pk.is_ntt_form = true;
    return pk;
}

CKKSRelinKey CKKSEvaluator::generate_relin_key(const CKKSSecretKey& sk, std::mt19937_64& rng) {
    if (!sk.is_ntt_form) {
        throw std::invalid_argument("Secret key must be in NTT form");
    }
    
    CKKSRelinKey rk;
    size_t L = context_->level_count();
    
    RNSPoly s_squared = sk.s;
    s_squared *= sk.s;
    
    size_t num_components = L;
    rk.key_components.resize(num_components);
    
    for (size_t d = 0; d < num_components; ++d) {
        RNSPoly a(context_);
        sample_uniform_rns(&a, rng);
        a.ntt_transform();
        
        RNSPoly e(context_);
        sample_error_rns(&e, 3.2, rng);
        e.ntt_transform();
        
        RNSPoly b = a;
        b *= sk.s;
        b.negate();
        b += e;
        
        if (d == 0) {
            b += s_squared;
        }
        
        rk.key_components[d] = {std::move(b), std::move(a)};
    }
    
    rk.is_ntt_form = true;
    return rk;
}

CKKSCiphertext CKKSEvaluator::encrypt(const CKKSPublicKey& pk, const CKKSPlaintext& pt, std::mt19937_64& rng) {
    CKKSCiphertext ct(context_, pt.scale());
    
    // 1. Sample u from ternary {-1, 0, 1}
    RNSPoly u(context_);
    sample_ternary_rns(&u, rng);
    u.ntt_transform();
    
    // 2. Sample errors e0, e1 ~ Gaussian
    RNSPoly e0(context_), e1(context_);
    sample_error_rns(&e0, 3.2, rng);
    sample_error_rns(&e1, 3.2, rng);
    e0.ntt_transform();
    e1.ntt_transform();
    
    // 3. Prepare message
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    
    // 4. Compute ciphertext components using operator* (NTT domain)
    // c0 = b*u + e0 + m
    RNSPoly c0 = pk.b * u;  // b*u
    c0 += e0;
    c0 += m;
    
    // c1 = a*u + e1
    RNSPoly c1 = pk.a * u;  // a*u
    c1 += e1;
    
    ct.c0() = std::move(c0);
    ct.c1() = std::move(c1);
    ct.set_level(context_->level_count() - 1);
    return ct;
}

CKKSCiphertext CKKSEvaluator::encrypt_symmetric(const CKKSSecretKey& sk, const CKKSPlaintext& pt, std::mt19937_64& rng) {
    CKKSCiphertext ct(context_, pt.scale());
    
    RNSPoly a(context_);
    sample_uniform_rns(&a, rng);
    a.ntt_transform();
    
    RNSPoly e(context_);
    sample_error_rns(&e, 3.2, rng);
    e.ntt_transform();
    
    // c0 = -a*s + e + m
    ct.c0() = a;
    ct.c0() *= sk.s;
    ct.c0().negate();
    ct.c0() += e;
    
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    ct.c0() += m;
    
    ct.c1() = a;
    ct.set_level(context_->level_count() - 1);
    return ct;
}

CKKSPlaintext CKKSEvaluator::decrypt(const CKKSSecretKey& sk, const CKKSCiphertext& ct) {
    RNSPoly result = ct.c1();
    result *= sk.s;
    result += ct.c0();
    
    if (result.is_ntt_form()) {
        result.intt_transform();
    }
    
    CKKSPlaintext pt(context_, ct.scale());
    pt.data() = result;
    pt.set_level(ct.level());
    return pt;
}

CKKSCiphertext CKKSEvaluator::add(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for addition");
    }
    
    CKKSCiphertext result(context_, ct1.scale());
    result.c0() = ct1.c0();
    result.c0() += ct2.c0();
    result.c1() = ct1.c1();
    result.c1() += ct2.c1();
    result.set_level(std::min(ct1.level(), ct2.level()));
    return result;
}

CKKSCiphertext CKKSEvaluator::sub(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    if (!scales_match(ct1, ct2)) {
        throw std::invalid_argument("Scales must match for subtraction");
    }
    
    CKKSCiphertext result(context_, ct1.scale());
    result.c0() = ct1.c0();
    result.c0() -= ct2.c0();
    result.c1() = ct1.c1();
    result.c1() -= ct2.c1();
    result.set_level(std::min(ct1.level(), ct2.level()));
    return result;
}

CKKSCiphertext CKKSEvaluator::add_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt) {
    CKKSCiphertext result = ct;
    
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    result.c0() += m;
    return result;
}

CKKSCiphertext CKKSEvaluator::multiply(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2) {
    CKKSCiphertext result(context_, ct1.scale() * ct2.scale());
    
    // CKKS multiplication produces 3-component ciphertext:
    // (c0_1, c1_1) * (c0_2, c1_2) = (d0, d1, d2)
    // where:
    //   d0 = c0_1 * c0_2
    //   d1 = c0_1 * c1_2 + c1_1 * c0_2
    //   d2 = c1_1 * c1_2
    
    // d0 = c0_1 * c0_2
    result.c0() = ct1.c0();
    result.c0() *= ct2.c0();
    
    // d1 = c0_1 * c1_2 + c1_1 * c0_2
    RNSPoly temp1 = ct1.c0();
    temp1 *= ct2.c1();
    
    RNSPoly temp2 = ct1.c1();
    temp2 *= ct2.c0();
    
    result.c1() = temp1;
    result.c1() += temp2;
    
    // d2 = c1_1 * c1_2
    result.set_size(3);
    result.c2() = ct1.c1();
    result.c2() *= ct2.c1();
    
    result.set_level(std::min(ct1.level(), ct2.level()));
    return result;
}

CKKSCiphertext CKKSEvaluator::multiply_plain(const CKKSCiphertext& ct, const CKKSPlaintext& pt) {
    CKKSCiphertext result(context_, ct.scale() * pt.scale());
    
    RNSPoly m = pt.data();
    if (!m.is_ntt_form()) {
        m.ntt_transform();
    }
    
    result.c0() = ct.c0();
    result.c0() *= m;
    result.c1() = ct.c1();
    result.c1() *= m;
    result.set_level(ct.level());
    return result;
}

CKKSCiphertext CKKSEvaluator::relinearize(const CKKSCiphertext& ct, const CKKSRelinKey& rk) {
    // If already 2-component, nothing to do
    if (ct.size() <= 2) {
        return ct;
    }
    
    // Relinearization: converts (c0, c1, c2) to (c0', c1')
    // Using the relinearization key rk = (b, a) where b = -a*s + e + s^2
    // c0' = c0 + c2 * b
    // c1' = c1 + c2 * a
    
    CKKSCiphertext result(context_, ct.scale());
    
    if (rk.key_components.empty()) {
        throw std::runtime_error("Relinearization key has no components");
    }
    
    const auto& [rk_b, rk_a] = rk.key_components[0];
    
    // c0' = c0 + c2 * rk_b
    RNSPoly c2_times_b = ct.c2();
    c2_times_b *= rk_b;
    result.c0() = ct.c0();
    result.c0() += c2_times_b;
    
    // c1' = c1 + c2 * rk_a
    RNSPoly c2_times_a = ct.c2();
    c2_times_a *= rk_a;
    result.c1() = ct.c1();
    result.c1() += c2_times_a;
    
    result.set_level(ct.level());
    return result;
}

CKKSCiphertext CKKSEvaluator::rescale(const CKKSCiphertext& ct) {
    if (ct.level() == 0) {
        throw std::runtime_error("Cannot rescale: already at level 0");
    }
    
    size_t level = ct.level();
    uint64_t q_L = context_->modulus(level).value();
    double new_scale = ct.scale() / static_cast<double>(q_L);
    
    CKKSCiphertext result(context_, new_scale);
    
    RNSPoly c0 = ct.c0();
    RNSPoly c1 = ct.c1();
    
    bool was_ntt = c0.is_ntt_form();
    if (was_ntt) {
        c0.intt_transform();
        c1.intt_transform();
    }
    
    size_t n = context_->n();
    result.c0() = RNSPoly(context_);
    result.c1() = RNSPoly(context_);
    
    // CKKS rescale: For each coefficient position i:
    // result[l][i] = (c[l][i] - c[L][i]) * q_L^{-1} mod q_l
    // where q_L^{-1} is the modular inverse of q_L mod q_l
    
    for (size_t l = 0; l < level; ++l) {
        const Modulus& mod_l = context_->modulus(l);
        uint64_t q_l = mod_l.value();
        // Compute q_L^{-1} mod q_l using extended Euclidean algorithm
        uint64_t q_L_inv = inv_mod(q_L % q_l, mod_l);
        
        for (size_t i = 0; i < n; ++i) {
            // Get coefficients at level l and top level L
            uint64_t c0_l = c0(l, i);
            uint64_t c1_l = c1(l, i);
            uint64_t c0_L = c0(level, i);
            uint64_t c1_L = c1(level, i);
            
            // Reduce top-level coefficient mod q_l
            uint64_t c0_L_mod = c0_L % q_l;
            uint64_t c1_L_mod = c1_L % q_l;
            
            // Compute (c[l] - c[L] mod q_l) * q_L^{-1} mod q_l
            uint64_t diff0 = sub_uint_mod(c0_l, c0_L_mod, mod_l);
            uint64_t diff1 = sub_uint_mod(c1_l, c1_L_mod, mod_l);
            
            result.c0()(l, i) = multiply_uint_mod(diff0, q_L_inv, mod_l);
            result.c1()(l, i) = multiply_uint_mod(diff1, q_L_inv, mod_l);
        }
    }
    
    result.set_level(level - 1);
    
    if (was_ntt) {
        result.c0().ntt_transform();
        result.c1().ntt_transform();
    }
    return result;
}

CKKSCiphertext CKKSEvaluator::multiply_relin_rescale(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2, const CKKSRelinKey& rk) {
    CKKSCiphertext product = multiply(ct1, ct2);
    CKKSCiphertext relined = relinearize(product, rk);
    return rescale(relined);
}

bool CKKSEvaluator::scales_match(const CKKSCiphertext& ct1, const CKKSCiphertext& ct2, double tolerance) const {
    if (ct1.scale() == 0.0 || ct2.scale() == 0.0) {
        return ct1.scale() == ct2.scale();
    }
    double ratio = ct1.scale() / ct2.scale();
    return std::abs(ratio - 1.0) < tolerance;
}

}  // namespace ckks
}  // namespace fhe
}  // namespace kctsb
