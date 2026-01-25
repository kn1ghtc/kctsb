/**
 * @file rns_poly_utils.cpp
 * @brief RNS Polynomial Utility Functions Implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.10.0
 */

#include "kctsb/advanced/fe/common/rns_poly_utils.hpp"
#include "kctsb/advanced/fe/common/modular_ops.hpp"
#include <stdexcept>
#include <cmath>
#include <algorithm>

namespace kctsb {
namespace fhe {

// ============================================================================
// Arithmetic Operations
// ============================================================================

RNSPoly poly_add(const RNSPoly& a, const RNSPoly& b) {
    RNSPoly result = a;
    result += b;
    return result;
}

void poly_add_inplace(RNSPoly& a, const RNSPoly& b) {
    a += b;
}

void poly_sub_inplace(RNSPoly& a, const RNSPoly& b) {
    a -= b;
}

void poly_negate_inplace(RNSPoly& poly) {
    poly.negate();
}

void poly_multiply_scalar_inplace(RNSPoly& poly, uint64_t scalar) {
    poly.multiply_scalar(scalar);
}

// ============================================================================
// Sampling Functions
// ============================================================================

void sample_uniform_rns(RNSPoly* out, std::mt19937_64& rng) {
    if (!out || out->empty()) {
        throw std::invalid_argument("Output polynomial must be allocated with context");
    }
    
    const RNSContext* context = out->context();
    size_t n = context->n();
    size_t L = out->current_level();
    
    for (size_t level = 0; level < L; ++level) {
        uint64_t qi = context->modulus(level).value();
        std::uniform_int_distribution<uint64_t> dist(0, qi - 1);
        
        uint64_t* data = out->data(level);
        for (size_t i = 0; i < n; ++i) {
            data[i] = dist(rng);
        }
    }
    
    // Output is in coefficient form
    // Caller should call ntt_transform() if needed
}

void sample_ternary_rns(RNSPoly* out, std::mt19937_64& rng) {
    if (!out || out->empty()) {
        throw std::invalid_argument("Output polynomial must be allocated with context");
    }
    
    const RNSContext* context = out->context();
    size_t n = context->n();
    size_t L = out->current_level();
    
    // Sample from {-1, 0, 1} with equal probability
    std::uniform_int_distribution<int> dist(-1, 1);
    
    std::vector<int64_t> coeffs(n);
    for (size_t i = 0; i < n; ++i) {
        coeffs[i] = dist(rng);
    }
    
    // Convert to RNS representation
    for (size_t level = 0; level < L; ++level) {
        uint64_t qi = context->modulus(level).value();
        uint64_t* data = out->data(level);
        
        for (size_t i = 0; i < n; ++i) {
            if (coeffs[i] >= 0) {
                data[i] = static_cast<uint64_t>(coeffs[i]);
            } else {
                // -1 -> q_i - 1 (mod q_i)
                data[i] = qi - static_cast<uint64_t>(-coeffs[i]);
            }
        }
    }
}

void sample_gaussian_rns(RNSPoly* out, std::mt19937_64& rng, double sigma) {
    if (!out || out->empty()) {
        throw std::invalid_argument("Output polynomial must be allocated with context");
    }
    
    const RNSContext* context = out->context();
    size_t n = context->n();
    size_t L = out->current_level();
    
    // Use discrete Gaussian approximation via normal distribution + rounding
    std::normal_distribution<double> gaussian(0.0, sigma);
    
    std::vector<int64_t> coeffs(n);
    for (size_t i = 0; i < n; ++i) {
        double sample = gaussian(rng);
        coeffs[i] = static_cast<int64_t>(std::round(sample));
        
        // Clamp to reasonable range to avoid overflow
        const int64_t max_noise = 1LL << 20;  // ~1M
        coeffs[i] = std::max(-max_noise, std::min(max_noise, coeffs[i]));
    }
    
    // Convert to RNS representation
    for (size_t level = 0; level < L; ++level) {
        uint64_t qi = context->modulus(level).value();
        uint64_t* data = out->data(level);
        
        for (size_t i = 0; i < n; ++i) {
            if (coeffs[i] >= 0) {
                data[i] = static_cast<uint64_t>(coeffs[i]) % qi;
            } else {
                // Negative: compute qi - |x| mod qi
                uint64_t abs_val = static_cast<uint64_t>(-coeffs[i]) % qi;
                data[i] = (qi - abs_val) % qi;
            }
        }
    }
}

// ============================================================================
// CRT Reconstruction (Multi-Precision using __int128)
// ============================================================================

void crt_reconstruct_rns(const RNSPoly& poly, std::vector<uint64_t>& out) {
    if (poly.empty()) {
        throw std::invalid_argument("Cannot reconstruct from empty polynomial");
    }
    
    if (poly.is_ntt_form()) {
        throw std::invalid_argument("Polynomial must be in coefficient form for CRT reconstruction");
    }
    
    const RNSContext* context = poly.context();
    size_t n = context->n();
    size_t L = poly.current_level();
    
    if (out.size() < n) {
        out.resize(n);
    }
    
    if (L == 1) {
        // Single modulus case - trivial
        const uint64_t* data = poly.data(0);
        std::copy(data, data + n, out.begin());
        return;
    }
    
    // Multi-modulus CRT reconstruction using __int128 for precision
    // Uses iterative CRT: start with x = x_0, then combine with x_1, x_2, ...
    // Formula: x = x_prev + Q_prev * [(x_i - x_prev) * Q_prev^{-1}]_qi
    
    // Start with first modulus
    const uint64_t* data0 = poly.data(0);
    uint64_t q0 = context->modulus(0).value();
    
    // Initialize with values from first residue
    std::vector<__int128> result(n);
    for (size_t i = 0; i < n; ++i) {
        result[i] = static_cast<__int128>(data0[i]);
    }
    
    // Accumulate product of moduli
    __int128 Q_prev = q0;
    
    // Iteratively combine with remaining moduli
    for (size_t level = 1; level < L; ++level) {
        uint64_t qi = context->modulus(level).value();
        const uint64_t* data_i = poly.data(level);
        
        // Compute Q_prev^{-1} mod qi
        Modulus mod_qi(qi);
        uint64_t Q_prev_mod_qi = static_cast<uint64_t>(Q_prev % qi);
        uint64_t Q_prev_inv = inv_mod(Q_prev_mod_qi, mod_qi);
        
        for (size_t j = 0; j < n; ++j) {
            // x_prev mod qi
            uint64_t result_mod_qi = static_cast<uint64_t>((result[j] % qi + qi) % qi);
            
            // diff = (x_i - x_prev) mod qi
            uint64_t diff = (data_i[j] + qi - result_mod_qi) % qi;
            
            // k = diff * Q_prev^{-1} mod qi
            uint64_t k = multiply_uint_mod(diff, Q_prev_inv, mod_qi);
            
            // result = x_prev + Q_prev * k
            result[j] = result[j] + Q_prev * static_cast<__int128>(k);
        }
        
        Q_prev *= qi;
    }
    
    // Store final result (may need to reduce for output)
    // Note: result[i] is in [0, Q), but we return as uint64_t
    // Caller should handle potential overflow for very large Q
    for (size_t i = 0; i < n; ++i) {
        // For values that fit in uint64_t, just cast
        // For larger values, we keep the low bits (caller will scale anyway)
        out[i] = static_cast<uint64_t>(result[i]);
    }
}

uint64_t balance_mod(uint64_t x, uint64_t modulus) {
    if (x == 0 || modulus == 0) return 0;
    
    // First reduce x modulo modulus
    x = x % modulus;
    
    // Return value in [0, modulus)
    // For signed interpretation, caller should check if x > modulus/2
    return x;
}

void crt_reconstruct_rns_128(const RNSPoly& poly, std::vector<__int128>& out) {
    if (poly.empty()) {
        throw std::invalid_argument("Cannot reconstruct from empty polynomial");
    }
    
    if (poly.is_ntt_form()) {
        throw std::invalid_argument("Polynomial must be in coefficient form for CRT reconstruction");
    }
    
    const RNSContext* context = poly.context();
    size_t n = context->n();
    size_t L = poly.current_level();
    
    if (out.size() < n) {
        out.resize(n);
    }
    
    if (L == 1) {
        const uint64_t* data = poly.data(0);
        for (size_t i = 0; i < n; ++i) {
            out[i] = static_cast<__int128>(data[i]);
        }
        return;
    }
    
    // Same algorithm as crt_reconstruct_rns but returns full __int128
    const uint64_t* data0 = poly.data(0);
    uint64_t q0 = context->modulus(0).value();
    
    for (size_t i = 0; i < n; ++i) {
        out[i] = static_cast<__int128>(data0[i]);
    }
    
    __int128 Q_prev = q0;
    
    for (size_t level = 1; level < L; ++level) {
        uint64_t qi = context->modulus(level).value();
        const uint64_t* data_i = poly.data(level);
        
        Modulus mod_qi(qi);
        uint64_t Q_prev_mod_qi = static_cast<uint64_t>(Q_prev % qi);
        uint64_t Q_prev_inv = inv_mod(Q_prev_mod_qi, mod_qi);
        
        for (size_t j = 0; j < n; ++j) {
            uint64_t result_mod_qi = static_cast<uint64_t>((out[j] % qi + qi) % qi);
            uint64_t diff = (data_i[j] + qi - result_mod_qi) % qi;
            uint64_t k = multiply_uint_mod(diff, Q_prev_inv, mod_qi);
            out[j] = out[j] + Q_prev * static_cast<__int128>(k);
        }
        
        Q_prev *= qi;
    }
}

__int128 compute_Q_product(const RNSContext* context) {
    __int128 Q = 1;
    for (size_t level = 0; level < context->level_count(); ++level) {
        Q *= context->modulus(level).value();
    }
    return Q;
}

} // namespace fhe
} // namespace kctsb
