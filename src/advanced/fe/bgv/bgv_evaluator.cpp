/**
 * @file bgv_evaluator.cpp
 * @brief BGV Homomorphic Evaluation Implementation
 * 
 * Implements homomorphic arithmetic operations on BGV ciphertexts.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/advanced/fe/bgv/bgv_evaluator.hpp"
#include <stdexcept>
#include <algorithm>

namespace kctsb {
namespace fhe {
namespace bgv {

// ============================================================================
// Constructor
// ============================================================================

BGVEvaluator::BGVEvaluator(const BGVContext& context) 
    : context_(context) {
}

// ============================================================================
// Addition Operations
// ============================================================================

BGVCiphertext BGVEvaluator::add(const BGVCiphertext& ct1,
                                 const BGVCiphertext& ct2) const {
    if (!is_compatible(ct1, ct2)) {
        throw std::invalid_argument("Ciphertexts not compatible for addition");
    }
    
    BGVCiphertext result;
    size_t max_size = std::max(ct1.size(), ct2.size());
    
    for (size_t i = 0; i < max_size; i++) {
        RingElement sum;
        
        if (i < ct1.size() && i < ct2.size()) {
            sum = ct1[i] + ct2[i];
        } else if (i < ct1.size()) {
            sum = ct1[i];
        } else {
            sum = ct2[i];
        }
        
        // Reduce mod cyclotomic
        PlainRem(sum.poly(), sum.poly(), context_.cyclotomic());
        result.push_back(sum);
    }
    
    result.set_level(std::max(ct1.level(), ct2.level()));
    
    // Noise grows slightly with addition
    result.set_noise_budget(std::min(ct1.noise_budget(), ct2.noise_budget()) - 1);
    
    return result;
}

BGVCiphertext BGVEvaluator::add_plain(const BGVCiphertext& ct,
                                       const BGVPlaintext& pt) const {
    BGVCiphertext result = ct;
    
    // Add plaintext to c_0 only
    result[0] = ct[0] + pt.data();
    PlainRem(result[0].poly(), result[0].poly(), context_.cyclotomic());
    
    return result;
}

void BGVEvaluator::add_inplace(BGVCiphertext& ct1,
                                const BGVCiphertext& ct2) const {
    if (!is_compatible(ct1, ct2)) {
        throw std::invalid_argument("Ciphertexts not compatible");
    }
    
    // Extend ct1 if needed
    while (ct1.size() < ct2.size()) {
        ct1.push_back(RingElement());
    }
    
    for (size_t i = 0; i < ct2.size(); i++) {
        ct1[i] += ct2[i];
        PlainRem(ct1[i].poly(), ct1[i].poly(), context_.cyclotomic());
    }
    
    ct1.set_noise_budget(std::min(ct1.noise_budget(), ct2.noise_budget()) - 1);
}

void BGVEvaluator::add_plain_inplace(BGVCiphertext& ct,
                                      const BGVPlaintext& pt) const {
    ct[0] += pt.data();
    PlainRem(ct[0].poly(), ct[0].poly(), context_.cyclotomic());
}

// ============================================================================
// Subtraction Operations
// ============================================================================

BGVCiphertext BGVEvaluator::sub(const BGVCiphertext& ct1,
                                 const BGVCiphertext& ct2) const {
    if (!is_compatible(ct1, ct2)) {
        throw std::invalid_argument("Ciphertexts not compatible");
    }
    
    BGVCiphertext result;
    size_t max_size = std::max(ct1.size(), ct2.size());
    
    for (size_t i = 0; i < max_size; i++) {
        RingElement diff;
        
        if (i < ct1.size() && i < ct2.size()) {
            diff = ct1[i] - ct2[i];
        } else if (i < ct1.size()) {
            diff = ct1[i];
        } else {
            diff = -ct2[i];
        }
        
        PlainRem(diff.poly(), diff.poly(), context_.cyclotomic());
        result.push_back(diff);
    }
    
    result.set_level(std::max(ct1.level(), ct2.level()));
    result.set_noise_budget(std::min(ct1.noise_budget(), ct2.noise_budget()) - 1);
    
    return result;
}

BGVCiphertext BGVEvaluator::sub_plain(const BGVCiphertext& ct,
                                       const BGVPlaintext& pt) const {
    BGVCiphertext result = ct;
    result[0] = ct[0] - pt.data();
    PlainRem(result[0].poly(), result[0].poly(), context_.cyclotomic());
    return result;
}

void BGVEvaluator::sub_inplace(BGVCiphertext& ct1,
                                const BGVCiphertext& ct2) const {
    while (ct1.size() < ct2.size()) {
        ct1.push_back(RingElement());
    }
    
    for (size_t i = 0; i < ct2.size(); i++) {
        ct1[i] -= ct2[i];
        PlainRem(ct1[i].poly(), ct1[i].poly(), context_.cyclotomic());
    }
}

void BGVEvaluator::sub_plain_inplace(BGVCiphertext& ct,
                                      const BGVPlaintext& pt) const {
    ct[0] -= pt.data();
    PlainRem(ct[0].poly(), ct[0].poly(), context_.cyclotomic());
}

BGVCiphertext BGVEvaluator::negate(const BGVCiphertext& ct) const {
    BGVCiphertext result;
    
    for (size_t i = 0; i < ct.size(); i++) {
        RingElement neg = -ct[i];
        result.push_back(neg);
    }
    
    result.set_level(ct.level());
    result.set_noise_budget(ct.noise_budget());
    
    return result;
}

void BGVEvaluator::negate_inplace(BGVCiphertext& ct) const {
    for (size_t i = 0; i < ct.size(); i++) {
        ct[i] = -ct[i];
    }
}

// ============================================================================
// Multiplication Operations
// ============================================================================

BGVCiphertext BGVEvaluator::multiply(const BGVCiphertext& ct1,
                                      const BGVCiphertext& ct2) const {
    if (!is_compatible(ct1, ct2)) {
        throw std::invalid_argument("Ciphertexts not compatible");
    }
    
    // CRITICAL: Set the modulus context before polynomial operations
    ZZ_p::init(context_.params().q);
    
    // Result has size = ct1.size() + ct2.size() - 1
    // For fresh ciphertexts: 2 + 2 - 1 = 3 components
    size_t result_size = ct1.size() + ct2.size() - 1;
    
    BGVCiphertext result;
    for (size_t i = 0; i < result_size; i++) {
        result.push_back(RingElement());
    }
    
    // Convert ciphertext polynomials to current modulus context
    // This ensures coefficients are correctly interpreted mod q
    std::vector<ZZ_pX> ct1_q(ct1.size()), ct2_q(ct2.size());
    for (size_t i = 0; i < ct1.size(); i++) {
        for (long j = 0; j <= ct1[i].degree(); j++) {
            ZZ coef = rep(ct1[i].coeff(j));
            SetCoeff(ct1_q[i], j, conv<ZZ_p>(coef));
        }
    }
    for (size_t i = 0; i < ct2.size(); i++) {
        for (long j = 0; j <= ct2[i].degree(); j++) {
            ZZ coef = rep(ct2[i].coeff(j));
            SetCoeff(ct2_q[i], j, conv<ZZ_p>(coef));
        }
    }
    
    // Convolution: result[k] = sum_{i+j=k} ct1[i] * ct2[j]
    std::vector<ZZ_pX> result_q(result_size);
    for (size_t i = 0; i < ct1.size(); i++) {
        for (size_t j = 0; j < ct2.size(); j++) {
            ZZ_pX product;
            PlainMul(product, ct1_q[i], ct2_q[j]);
            PlainRem(product, product, context_.cyclotomic());
            result_q[i + j] += product;
            PlainRem(result_q[i + j], result_q[i + j], context_.cyclotomic());
        }
    }
    
    // Copy back to result
    for (size_t i = 0; i < result_size; i++) {
        result[i].poly() = result_q[i];
    }
    
    result.set_level(std::max(ct1.level(), ct2.level()));
    
    // Noise grows quadratically with multiplication
    // Simplified estimate: budget roughly halves
    result.set_noise_budget(
        std::min(ct1.noise_budget(), ct2.noise_budget()) / 2 - 
        std::log2(context_.ring_degree()));
    
    return result;
}

BGVCiphertext BGVEvaluator::multiply_plain(const BGVCiphertext& ct,
                                            const BGVPlaintext& pt) const {
    BGVCiphertext result;
    
    for (size_t i = 0; i < ct.size(); i++) {
        RingElement product = ct[i] * pt.data();
        PlainRem(product.poly(), product.poly(), context_.cyclotomic());
        result.push_back(product);
    }
    
    result.set_level(ct.level());
    result.set_noise_budget(ct.noise_budget() - 
                            std::log2(context_.ring_degree()));
    
    return result;
}

void BGVEvaluator::multiply_inplace(BGVCiphertext& ct1,
                                     const BGVCiphertext& ct2) const {
    ct1 = multiply(ct1, ct2);
}

void BGVEvaluator::multiply_plain_inplace(BGVCiphertext& ct,
                                           const BGVPlaintext& pt) const {
    for (size_t i = 0; i < ct.size(); i++) {
        ct[i] *= pt.data();
        PlainRem(ct[i].poly(), ct[i].poly(), context_.cyclotomic());
    }
    ct.set_noise_budget(ct.noise_budget() - std::log2(context_.ring_degree()));
}

BGVCiphertext BGVEvaluator::square(const BGVCiphertext& ct) const {
    return multiply(ct, ct);
}

void BGVEvaluator::square_inplace(BGVCiphertext& ct) const {
    ct = multiply(ct, ct);
}

BGVCiphertext BGVEvaluator::multiply_relin(const BGVCiphertext& ct1,
                                            const BGVCiphertext& ct2,
                                            const BGVRelinKey& rk) const {
    BGVCiphertext product = multiply(ct1, ct2);
    relinearize_inplace(product, rk);
    return product;
}

// ============================================================================
// Relinearization
// ============================================================================

BGVCiphertext BGVEvaluator::relinearize(const BGVCiphertext& ct,
                                         const BGVRelinKey& rk) const {
    BGVCiphertext result = ct;
    relinearize_inplace(result, rk);
    return result;
}

void BGVEvaluator::relinearize_inplace(BGVCiphertext& ct,
                                        const BGVRelinKey& rk) const {
    if (ct.size() <= 2) {
        return;  // Already size 2
    }
    
    // CRITICAL: Set modulus to q for all operations
    ZZ_p::init(context_.params().q);
    
    // Key switching: convert c_2 * s^2 term to linear form
    // Using digit decomposition
    
    while (ct.size() > 2) {
        // Extract highest degree term
        RingElement c_high = ct[ct.size() - 1];
        
        // Decompose c_high into digits
        std::vector<RingElement> digits = decompose(c_high);
        
        // Apply key switching
        const auto& key_components = rk.data();
        
        if (digits.size() != key_components.size()) {
            throw std::runtime_error("Key/decomposition size mismatch");
        }
        
        ZZ_pX new_c0, new_c1;
        
        for (size_t i = 0; i < digits.size(); i++) {
            // Convert polynomials to current modulus context
            ZZ_pX d_i, b_i, a_i;
            for (long j = 0; j <= digits[i].degree(); j++) {
                SetCoeff(d_i, j, conv<ZZ_p>(rep(digits[i].coeff(j))));
            }
            for (long j = 0; j <= key_components[i].first.degree(); j++) {
                SetCoeff(b_i, j, conv<ZZ_p>(rep(key_components[i].first.coeff(j))));
            }
            for (long j = 0; j <= key_components[i].second.degree(); j++) {
                SetCoeff(a_i, j, conv<ZZ_p>(rep(key_components[i].second.coeff(j))));
            }
            
            // d_i * rk[i] = d_i * (b_i, a_i)
            ZZ_pX d_b, d_a;
            PlainMul(d_b, d_i, b_i);
            PlainRem(d_b, d_b, context_.cyclotomic());
            
            PlainMul(d_a, d_i, a_i);
            PlainRem(d_a, d_a, context_.cyclotomic());
            
            new_c0 += d_b;
            new_c1 += d_a;
        }
        
        PlainRem(new_c0, new_c0, context_.cyclotomic());
        PlainRem(new_c1, new_c1, context_.cyclotomic());
        
        // Update ciphertext: add key-switched terms to c_0 and c_1
        // Also convert ct[0] and ct[1] to current modulus
        ZZ_pX ct0_q, ct1_q;
        for (long j = 0; j <= ct[0].degree(); j++) {
            SetCoeff(ct0_q, j, conv<ZZ_p>(rep(ct[0].coeff(j))));
        }
        for (long j = 0; j <= ct[1].degree(); j++) {
            SetCoeff(ct1_q, j, conv<ZZ_p>(rep(ct[1].coeff(j))));
        }
        
        ct0_q += new_c0;
        ct1_q += new_c1;
        
        PlainRem(ct0_q, ct0_q, context_.cyclotomic());
        PlainRem(ct1_q, ct1_q, context_.cyclotomic());
        
        ct[0].poly() = ct0_q;
        ct[1].poly() = ct1_q;
        
        // Remove highest component
        ct.polys_.pop_back();
    }
    
    // Noise increases slightly due to key switching
    ct.set_noise_budget(ct.noise_budget() - 2);
}

std::vector<RingElement> BGVEvaluator::decompose(const RingElement& poly) const {
    // Digit decomposition for key switching
    // Split polynomial into smaller-coefficient parts
    
    // MUST match base calculation in generate_relin_key!
    const size_t num_digits = 3;  // Should match key generation
    
    // Calculate base dynamically based on q
    double log_q = kctsb::log(context_.params().q) / std::log(2.0);
    size_t base_bits = static_cast<size_t>(std::ceil(log_q / num_digits));
    ZZ base = kctsb::power(to_ZZ(2), static_cast<long>(base_bits));
    
    // CRITICAL: Create new ZZ_pX polynomials with current modulus
    ZZ_p::init(context_.params().q);
    
    std::vector<RingElement> digits(num_digits);
    
    for (long i = 0; i <= poly.degree(); i++) {
        ZZ coef = rep(poly.coeff(i));  // Get coefficient as ZZ
        
        for (size_t d = 0; d < num_digits; d++) {
            ZZ digit = coef % base;
            coef /= base;
            SetCoeff(digits[d].poly(), i, conv<ZZ_p>(digit));
        }
    }
    
    return digits;
}

// ============================================================================
// Rotation Operations
// ============================================================================

BGVCiphertext BGVEvaluator::rotate(const BGVCiphertext& ct, int steps,
                                    const BGVGaloisKey& gk) const {
    // Compute Galois element for this rotation
    uint64_t galois_elt = 1;
    uint64_t base = 5;
    uint64_t exp = (steps > 0) ? static_cast<uint64_t>(steps) 
                               : static_cast<uint64_t>(-steps);
    
    for (uint64_t i = 0; i < exp; i++) {
        galois_elt = (galois_elt * base) % context_.params().m;
    }
    
    return apply_galois(ct, galois_elt, gk);
}

void BGVEvaluator::rotate_inplace(BGVCiphertext& ct, int steps,
                                   const BGVGaloisKey& gk) const {
    ct = rotate(ct, steps, gk);
}

BGVCiphertext BGVEvaluator::rotate_rows(const BGVCiphertext& ct, int steps,
                                         const BGVGaloisKey& gk) const {
    // For matrix-like arrangements
    return rotate(ct, steps, gk);
}

BGVCiphertext BGVEvaluator::rotate_columns(const BGVCiphertext& ct,
                                            const BGVGaloisKey& gk) const {
    // Swap rows using conjugation automorphism
    // X -> X^{-1} which maps slot[i] to slot[n-1-i]
    uint64_t galois_elt = context_.params().m - 1;
    return apply_galois(ct, galois_elt, gk);
}

BGVCiphertext BGVEvaluator::apply_galois(const BGVCiphertext& ct,
                                          uint64_t galois_elt,
                                          const BGVGaloisKey& gk) const {
    if (!gk.has_key(galois_elt)) {
        throw std::invalid_argument("Galois key not available for element " +
                                    std::to_string(galois_elt));
    }
    
    // Apply automorphism σ: X -> X^{galois_elt} to each component
    BGVCiphertext result;
    
    for (size_t i = 0; i < ct.size(); i++) {
        RingElement sigma_c;
        
        // Map coefficients: c[j] -> c[j * galois_elt mod n]
        for (long j = 0; j <= ct[i].degree(); j++) {
            long new_idx = (j * galois_elt) % context_.params().n;
            sigma_c.set_coeff(new_idx, ct[i].coeff(j));
        }
        
        result.push_back(sigma_c);
    }
    
    // Need to key switch from σ(s) back to s
    result = key_switch(result, gk.get_key(galois_elt));
    
    result.set_level(ct.level());
    result.set_noise_budget(ct.noise_budget() - 2);
    
    return result;
}

BGVCiphertext BGVEvaluator::key_switch(
    const BGVCiphertext& ct,
    const std::vector<std::pair<RingElement, RingElement>>& switch_key) const {
    
    if (ct.size() != 2) {
        throw std::invalid_argument("Key switch requires size-2 ciphertext");
    }
    
    // Decompose c_1 and apply key switching
    std::vector<RingElement> digits = decompose(ct[1]);
    
    if (digits.size() != switch_key.size()) {
        throw std::runtime_error("Key/decomposition size mismatch");
    }
    
    RingElement new_c0 = ct[0];
    RingElement new_c1;
    
    for (size_t i = 0; i < digits.size(); i++) {
        RingElement d_b = digits[i] * switch_key[i].first;
        RingElement d_a = digits[i] * switch_key[i].second;
        
        PlainRem(d_b.poly(), d_b.poly(), context_.cyclotomic());
        PlainRem(d_a.poly(), d_a.poly(), context_.cyclotomic());
        
        new_c0 += d_b;
        new_c1 += d_a;
    }
    
    PlainRem(new_c0.poly(), new_c0.poly(), context_.cyclotomic());
    PlainRem(new_c1.poly(), new_c1.poly(), context_.cyclotomic());
    
    BGVCiphertext result;
    result.push_back(new_c0);
    result.push_back(new_c1);
    result.set_level(ct.level());
    result.set_noise_budget(ct.noise_budget());
    
    return result;
}

// ============================================================================
// Modulus Switching
// ============================================================================

BGVCiphertext BGVEvaluator::mod_switch(const BGVCiphertext& ct) const {
    BGVCiphertext result = ct;
    mod_switch_inplace(result);
    return result;
}

void BGVEvaluator::mod_switch_inplace(BGVCiphertext& ct) const {
    // Switch to next lower level
    mod_switch_to_inplace(ct, ct.level() + 1);
}

BGVCiphertext BGVEvaluator::mod_switch_to(const BGVCiphertext& ct,
                                           uint32_t level) const {
    BGVCiphertext result = ct;
    mod_switch_to_inplace(result, level);
    return result;
}

void BGVEvaluator::mod_switch_to_inplace(BGVCiphertext& ct,
                                          uint32_t level) const {
    if (level <= ct.level()) {
        return;  // Already at or below target level
    }
    
    if (level >= context_.params().L) {
        throw std::invalid_argument("Cannot switch beyond lowest level");
    }
    
    // For each level to switch through
    while (ct.level() < level) {
        ZZ q_current = context_.ciphertext_modulus(ct.level());
        ZZ q_next = context_.ciphertext_modulus(ct.level() + 1);
        
        // Scale factor
        ZZ scale = q_current / q_next;
        
        // Scale each component and round
        for (size_t i = 0; i < ct.size(); i++) {
            RingElement scaled;
            
            for (long j = 0; j <= ct[i].degree(); j++) {
                ZZ coef = rep(ct[i].coeff(j));
                
                // Round to nearest multiple of scale
                ZZ rounded = (coef + scale / 2) / scale;
                
                // Reduce mod new modulus
                rounded = rounded % q_next;
                
                ZZ_pPush push;
                ZZ_p::init(q_next);
                SetCoeff(scaled.poly(), j, conv<ZZ_p>(rounded));
            }
            
            ct[i] = scaled;
        }
        
        ct.set_level(ct.level() + 1);
    }
    
    // Modulus switching reduces noise
    ct.set_noise_budget(ct.noise_budget() + 
                        std::log2(to_dbl(context_.params().primes[0])));
}

// ============================================================================
// Complex Operations
// ============================================================================

BGVCiphertext BGVEvaluator::inner_product(
    const std::vector<BGVCiphertext>& ct1,
    const std::vector<BGVCiphertext>& ct2,
    const BGVRelinKey& rk) const {
    
    if (ct1.size() != ct2.size() || ct1.empty()) {
        throw std::invalid_argument("Invalid vector sizes for inner product");
    }
    
    BGVCiphertext result = multiply_relin(ct1[0], ct2[0], rk);
    
    for (size_t i = 1; i < ct1.size(); i++) {
        BGVCiphertext product = multiply_relin(ct1[i], ct2[i], rk);
        add_inplace(result, product);
    }
    
    return result;
}

BGVCiphertext BGVEvaluator::power(const BGVCiphertext& ct, uint64_t exponent,
                                   const BGVRelinKey& rk) const {
    if (exponent == 0) {
        throw std::invalid_argument("Exponent must be >= 1");
    }
    
    if (exponent == 1) {
        return ct;
    }
    
    // For small exponents, use direct multiplication for correctness
    // This avoids potential issues with square-and-multiply algorithm
    BGVCiphertext result = ct;
    
    for (uint64_t i = 1; i < exponent; i++) {
        result = multiply_relin(result, ct, rk);
    }
    
    return result;
}

// ============================================================================
// Utility
// ============================================================================

bool BGVEvaluator::is_compatible(const BGVCiphertext& ct1,
                                  const BGVCiphertext& ct2) const {
    // Check if ciphertexts can be operated on together
    // Currently just check level compatibility
    return std::abs(static_cast<int>(ct1.level()) - 
                   static_cast<int>(ct2.level())) <= 1;
}

void BGVEvaluator::rescale_inplace(BGVCiphertext& ct) const {
    // Rescaling is primarily for CKKS, optional in BGV
    // In BGV, we use modulus switching instead
    mod_switch_inplace(ct);
}

// ============================================================================
// BGVGaloisKey Implementation
// ============================================================================

const std::vector<std::pair<RingElement, RingElement>>&
BGVGaloisKey::get_key(uint64_t galois_elt) const {
    auto it = keys_.find(galois_elt);
    if (it == keys_.end()) {
        throw std::out_of_range("Galois key not found for element " + 
                                std::to_string(galois_elt));
    }
    return it->second;
}

bool BGVGaloisKey::has_key(uint64_t galois_elt) const {
    return keys_.find(galois_elt) != keys_.end();
}

} // namespace bgv
} // namespace fhe
} // namespace kctsb
