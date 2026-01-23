/**
 * @file bgv_evaluator_v2.cpp
 * @brief BGV EvaluatorV2 Implementation (Pure RNS)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.10.0
 */

#include "kctsb/advanced/fe/bgv/bgv_evaluator_v2.hpp"
#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include <stdexcept>
#include <algorithm>
#include <cmath>

namespace kctsb {
namespace fhe {
namespace bgv {

// ============================================================================
// Constructor
// ============================================================================

BGVEvaluatorV2::BGVEvaluatorV2(const RNSContext* ctx, uint64_t plaintext_modulus)
    : context_(ctx)
    , plaintext_modulus_(plaintext_modulus)
{
    if (!ctx) {
        throw std::invalid_argument("RNS context cannot be null");
    }
    
    if (plaintext_modulus == 0 || plaintext_modulus >= ctx->modulus(0).value()) {
        throw std::invalid_argument("Invalid plaintext modulus");
    }
}

// ============================================================================
// Key Generation
// ============================================================================

BGVSecretKeyV2 BGVEvaluatorV2::generate_secret_key(std::mt19937_64& rng) {
    // Sample from ternary distribution {-1, 0, 1}
    RNSPoly s(context_);
    sample_ternary_rns(&s, rng);
    
    // Transform to NTT domain for fast operations
    s.ntt_transform();
    
    return BGVSecretKeyV2(std::move(s));
}

BGVPublicKeyV2 BGVEvaluatorV2::generate_public_key(
    const BGVSecretKeyV2& sk,
    std::mt19937_64& rng)
{
    if (!sk.is_ntt_form) {
        throw std::invalid_argument("Secret key must be in NTT form");
    }
    
    // pk = (-(a*s + e), a)
    
    // 1. Sample random polynomial a (uniform mod q)
    RNSPoly a(context_);
    sample_uniform_rns(&a, rng);
    a.ntt_transform();  // Convert to NTT
    
    // 2. Sample small error e ~ Gaussian(σ = 3.2)
    RNSPoly e(context_);
    sample_gaussian_rns(&e, rng, 3.2);
    e.ntt_transform();
    
    // 3. Compute pk0 = -(a*s + e)
    // Both a and sk.s are in NTT form, so use component-wise multiply
    RNSPoly as = a * sk.s;
    RNSPoly pk0 = as + e;
    poly_negate_inplace(pk0);
    
    return BGVPublicKeyV2(std::move(pk0), std::move(a));
}

BGVRelinKeyV2 BGVEvaluatorV2::generate_relin_key(
    const BGVSecretKeyV2& sk,
    std::mt19937_64& rng,
    uint64_t decomp_base)
{
    if (!sk.is_ntt_form) {
        throw std::invalid_argument("Secret key must be in NTT form");
    }
    
    // Compute s^2 (NTT domain component-wise multiply)
    RNSPoly s_squared = sk.s * sk.s;
    
    // Decompose s^2 into base-P digits
    // For simplicity, use a fixed number of digits based on modulus size
    size_t L = context_->level_count();
    size_t num_digits = static_cast<size_t>(std::ceil(
        static_cast<double>(L * 60) / std::log2(decomp_base)));
    
    std::vector<RNSPoly> ksk0, ksk1;
    ksk0.reserve(num_digits);
    ksk1.reserve(num_digits);
    
    // For each digit position, create a key switching key
    uint64_t current_power = 1;
    for (size_t i = 0; i < num_digits; ++i) {
        // Sample random a_i
        RNSPoly a_i(context_);
        sample_uniform_rns(&a_i, rng);
        a_i.ntt_transform();
        
        // Sample error e_i
        RNSPoly e_i(context_);
        sample_gaussian_rns(&e_i, rng, 3.2);
        e_i.ntt_transform();
        
        // ksk0_i = -(a_i * s + e_i) + P^i * s^2
        RNSPoly ais = a_i * sk.s;
        RNSPoly ksk0_i = ais + e_i;
        poly_negate_inplace(ksk0_i);
        
        // Add P^i * s^2
        RNSPoly s2_scaled = s_squared;
        poly_multiply_scalar_inplace(s2_scaled, current_power);
        poly_add_inplace(ksk0_i, s2_scaled);
        
        ksk0.push_back(std::move(ksk0_i));
        ksk1.push_back(std::move(a_i));
        
        current_power *= decomp_base;
    }
    
    return BGVRelinKeyV2(std::move(ksk0), std::move(ksk1), decomp_base);
}

// ============================================================================
// Encryption / Decryption
// ============================================================================

BGVCiphertextV2 BGVEvaluatorV2::encrypt(
    const BGVPlaintextV2& plaintext,
    const BGVPublicKeyV2& pk,
    std::mt19937_64& rng)
{
    if (!pk.is_ntt_form) {
        throw std::invalid_argument("Public key must be in NTT form");
    }
    
    // ct = pk * u + (m, e1)
    
    // 1. Convert plaintext to RNSPoly
    RNSPoly m(context_, plaintext);
    m.ntt_transform();
    
    // 2. Sample u from ternary {-1, 0, 1}
    RNSPoly u(context_);
    sample_ternary_rns(&u, rng);
    u.ntt_transform();
    
    // 3. Sample errors e0, e1 ~ Gaussian
    RNSPoly e0(context_);
    RNSPoly e1(context_);
    sample_gaussian_rns(&e0, rng, 3.2);
    sample_gaussian_rns(&e1, rng, 3.2);
    e0.ntt_transform();
    e1.ntt_transform();
    
    // 4. Compute ciphertext components (NTT domain)
    // c0 = pk0 * u + e0 + m
    RNSPoly c0 = pk.pk0 * u;
    poly_add_inplace(c0, e0);
    poly_add_inplace(c0, m);
    
    // c1 = pk1 * u + e1
    RNSPoly c1 = pk.pk1 * u;
    poly_add_inplace(c1, e1);
    
    BGVCiphertextV2 ct;
    ct.data.push_back(std::move(c0));
    ct.data.push_back(std::move(c1));
    ct.is_ntt_form = true;
    ct.level = 0;
    ct.noise_budget = initial_noise_budget();
    
    return ct;
}

BGVPlaintextV2 BGVEvaluatorV2::decrypt(
    const BGVCiphertextV2& ct,
    const BGVSecretKeyV2& sk)
{
    if (ct.size() != 2) {
        throw std::invalid_argument("Ciphertext must be size 2 for decryption (relinearize first if needed)");
    }
    
    if (!ct.is_ntt_form || !sk.is_ntt_form) {
        throw std::invalid_argument("Both ciphertext and secret key must be in NTT form");
    }
    
    // Decrypt: m ≈ c0 + c1 * s (mod q)
    
    // 1. Compute c1 * s (NTT domain)
    RNSPoly c1s = ct[1] * sk.s;
    
    // 2. Add to c0
    RNSPoly m_rns = ct[0] + c1s;
    
    // 3. Transform back to coefficient domain
    m_rns.intt_transform();
    
    // 4. CRT reconstruct to get ZZ coefficients
    size_t n = context_->n();
    std::vector<uint64_t> coeffs(n);
    crt_reconstruct_rns(m_rns, coeffs);
    
    // 5. Reduce modulo plaintext modulus
    // For BGV, the plaintext is scaled by plaintext_modulus in encryption
    // So we need to divide and round
    BGVPlaintextV2 plaintext(n);
    for (size_t i = 0; i < n; ++i) {
        // Simple modulo reduction (no scaling needed for this implementation)
        plaintext[i] = coeffs[i] % plaintext_modulus_;
        
        // Handle large values that should wrap around
        if (plaintext[i] > plaintext_modulus_ / 2) {
            plaintext[i] = plaintext_modulus_ - plaintext[i];
            plaintext[i] = plaintext_modulus_ - plaintext[i]; // Double wrap to stay positive
        }
    }
    
    return plaintext;
}

// ============================================================================
// Homomorphic Operations
// ============================================================================

BGVCiphertextV2 BGVEvaluatorV2::add(
    const BGVCiphertextV2& ct1,
    const BGVCiphertextV2& ct2)
{
    BGVCiphertextV2 result = ct1;
    add_inplace(result, ct2);
    return result;
}

void BGVEvaluatorV2::add_inplace(
    BGVCiphertextV2& ct1,
    const BGVCiphertextV2& ct2)
{
    if (!ct1.is_ntt_form || !ct2.is_ntt_form) {
        throw std::invalid_argument("Both ciphertexts must be in NTT form");
    }
    
    size_t min_size = std::min(ct1.size(), ct2.size());
    size_t max_size = std::max(ct1.size(), ct2.size());
    
    // Extend ct1 if needed
    while (ct1.size() < max_size) {
        ct1.data.push_back(RNSPoly(context_));
    }
    
    // Add component-wise
    for (size_t i = 0; i < min_size; ++i) {
        poly_add_inplace(ct1[i], ct2[i]);
    }
    
    // Copy remaining components from ct2 if it's larger
    for (size_t i = min_size; i < ct2.size(); ++i) {
        ct1[i] = ct2[i];
    }
    
    // Noise budget decreases slightly
    ct1.noise_budget = std::min(ct1.noise_budget, ct2.noise_budget) - 1;
}

BGVCiphertextV2 BGVEvaluatorV2::sub(
    const BGVCiphertextV2& ct1,
    const BGVCiphertextV2& ct2)
{
    BGVCiphertextV2 result = ct1;
    sub_inplace(result, ct2);
    return result;
}

void BGVEvaluatorV2::sub_inplace(
    BGVCiphertextV2& ct1,
    const BGVCiphertextV2& ct2)
{
    if (!ct1.is_ntt_form || !ct2.is_ntt_form) {
        throw std::invalid_argument("Both ciphertexts must be in NTT form");
    }
    
    size_t min_size = std::min(ct1.size(), ct2.size());
    size_t max_size = std::max(ct1.size(), ct2.size());
    
    while (ct1.size() < max_size) {
        ct1.data.push_back(RNSPoly(context_));
    }
    
    for (size_t i = 0; i < min_size; ++i) {
        poly_sub_inplace(ct1[i], ct2[i]);
    }
    
    // If ct2 is larger, need to negate remaining components
    for (size_t i = min_size; i < ct2.size(); ++i) {
        ct1[i] = ct2[i];
        poly_negate_inplace(ct1[i]);
    }
    
    ct1.noise_budget = std::min(ct1.noise_budget, ct2.noise_budget) - 1;
}

BGVCiphertextV2 BGVEvaluatorV2::multiply(
    const BGVCiphertextV2& ct1,
    const BGVCiphertextV2& ct2)
{
    BGVCiphertextV2 result = ct1;
    multiply_inplace(result, ct2);
    return result;
}

void BGVEvaluatorV2::multiply_inplace(
    BGVCiphertextV2& ct1,
    const BGVCiphertextV2& ct2)
{
    if (!ct1.is_ntt_form || !ct2.is_ntt_form) {
        throw std::invalid_argument("Both ciphertexts must be in NTT form");
    }
    
    size_t n1 = ct1.size();
    size_t n2 = ct2.size();
    
    // Tensor product: (c0, c1) * (d0, d1) = (c0*d0, c0*d1 + c1*d0, c1*d1)
    std::vector<RNSPoly> result;
    result.reserve(n1 + n2 - 1);
    
    // Do tensor product multiplication directly
    for (size_t i = 0; i < n1; ++i) {
        for (size_t j = 0; j < n2; ++j) {
            size_t idx = i + j;
            
            // Compute product (both are in NTT form, result is NTT)
            RNSPoly prod = ct1[i] * ct2[j];
            
            // If this is the first contribution to result[idx], assign it
            // Otherwise, add it in
            if (idx >= result.size()) {
                result.push_back(std::move(prod));
            } else {
                poly_add_inplace(result[idx], prod);
            }
        }
    }
    
    ct1.data = std::move(result);
    ct1.noise_budget -= noise_budget_after_multiply();
}

BGVCiphertextV2 BGVEvaluatorV2::relinearize(
    const BGVCiphertextV2& ct,
    const BGVRelinKeyV2& rk)
{
    BGVCiphertextV2 result = ct;
    relinearize_inplace(result, rk);
    return result;
}

void BGVEvaluatorV2::relinearize_inplace(
    BGVCiphertextV2& ct,
    const BGVRelinKeyV2& rk)
{
    if (ct.size() <= 2) {
        return;  // Already size 2, nothing to do
    }
    
    if (!ct.is_ntt_form || !rk.is_ntt_form) {
        throw std::invalid_argument("Ciphertext and relin key must be in NTT form");
    }
    
    // Relinearize c2 component using key switching
    // c2 = sum_i c2_i * P^i, then add sum_i c2_i * (ksk0_i, ksk1_i)
    
    auto decomposed = decompose_rns(ct[2], rk.decomp_base);
    
    RNSPoly c0_relin(context_);
    RNSPoly c1_relin(context_);
    
    size_t num_digits = std::min(decomposed.size(), rk.ksk0.size());
    
    for (size_t i = 0; i < num_digits; ++i) {
        // c0' += c2_i * ksk0_i
        RNSPoly term0 = decomposed[i] * rk.ksk0[i];
        poly_add_inplace(c0_relin, term0);
        
        // c1' += c2_i * ksk1_i
        RNSPoly term1 = decomposed[i] * rk.ksk1[i];
        poly_add_inplace(c1_relin, term1);
    }
    
    // Add relinearization terms to c0, c1
    poly_add_inplace(ct[0], c0_relin);
    poly_add_inplace(ct[1], c1_relin);
    
    // Remove c2
    ct.data.resize(2);
    
    // Noise budget decreases
    ct.noise_budget -= 5;  // Approximate
}

BGVCiphertextV2 BGVEvaluatorV2::negate(const BGVCiphertextV2& ct) {
    BGVCiphertextV2 result = ct;
    negate_inplace(result);
    return result;
}

void BGVEvaluatorV2::negate_inplace(BGVCiphertextV2& ct) {
    for (size_t i = 0; i < ct.size(); ++i) {
        poly_negate_inplace(ct[i]);
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

std::vector<RNSPoly> BGVEvaluatorV2::decompose_rns(
    const RNSPoly& poly,
    uint64_t base)
{
    // Decompose poly into base-P digits
    // poly = sum_i digit_i * P^i
    
    size_t L = context_->level_count();
    size_t num_digits = static_cast<size_t>(std::ceil(
        static_cast<double>(L * 60) / std::log2(base)));
    
    std::vector<RNSPoly> digits;
    digits.reserve(num_digits);
    
    // Need to work in coefficient domain for decomposition
    RNSPoly temp = poly;
    if (temp.is_ntt_form()) {
        temp.intt_transform();
    }
    
    for (size_t d = 0; d < num_digits; ++d) {
        RNSPoly digit(context_);
        
        for (size_t level = 0; level < L; ++level) {
            const uint64_t* src = temp.data(level);
            uint64_t* dst = digit.data(level);
            uint64_t* temp_dst = const_cast<uint64_t*>(src);
            
            size_t n = context_->n();
            for (size_t i = 0; i < n; ++i) {
                dst[i] = temp_dst[i] % base;
                temp_dst[i] = temp_dst[i] / base;
            }
        }
        
        // Convert digit back to NTT form
        digit.ntt_transform();
        digits.push_back(std::move(digit));
    }
    
    return digits;
}

int BGVEvaluatorV2::initial_noise_budget() const {
    // Estimate based on modulus size
    // For L moduli of ~60 bits each, total modulus Q ~ L * 60 bits
    // Fresh ciphertext has noise ~ σ * sqrt(n) ~ 3.2 * sqrt(4096) ~ 200
    // log2(Q/noise) gives noise budget
    
    size_t L = context_->level_count();
    double log_Q = L * 60.0;  // Approximate
    double log_noise = std::log2(3.2 * std::sqrt(context_->n()));
    
    return static_cast<int>(log_Q - log_noise);
}

int BGVEvaluatorV2::noise_budget_after_multiply() const {
    // Multiplication approximately doubles noise
    // Conservatively estimate 10-15 bits consumed
    return 12;
}

} // namespace bgv
} // namespace fhe
} // namespace kctsb
