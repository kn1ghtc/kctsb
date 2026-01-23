/**
 * @file bgv_encoder.cpp
 * @brief BGV Plaintext Encoding Implementation
 * 
 * Implements integer and batch (SIMD) encoding for BGV plaintexts.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/advanced/fe/bgv/bgv_encoder.hpp"
#include "kctsb/advanced/fe/bgv/bgv_context.hpp"
#include <stdexcept>
#include <algorithm>

namespace kctsb {
namespace fhe {
namespace bgv {

// ============================================================================
// BGVPlaintext Implementation
// ============================================================================

BGVPlaintext::BGVPlaintext(const RingElement& elem) 
    : data_(elem), is_batched_(false) {
}

BGVPlaintext::BGVPlaintext(uint64_t value) : is_batched_(false) {
    // Encode as constant polynomial
    SetCoeff(data_.poly(), 0, conv<ZZ_p>(static_cast<long>(value)));
}

BGVPlaintext::BGVPlaintext(const std::vector<int64_t>& values) 
    : is_batched_(true) {
    // This constructor is for convenience; actual encoding should use BGVEncoder
    for (size_t i = 0; i < values.size(); i++) {
        int64_t val = values[i];
        if (val < 0) {
            // Handle negative values by adding modulus (will be set later)
        }
        SetCoeff(data_.poly(), i, conv<ZZ_p>(val));
    }
}

std::vector<int64_t> BGVPlaintext::decode_slots() const {
    // Return coefficients as slot values
    // Actual CRT decoding should use BGVEncoder
    std::vector<int64_t> result;
    for (long i = 0; i <= data_.degree(); i++) {
        ZZ coef = rep(data_.coeff(i));
        result.push_back(to_long(coef));
    }
    return result;
}

int64_t BGVPlaintext::decode_single() const {
    if (data_.degree() < 0) {
        return 0;
    }
    return to_long(rep(data_.coeff(0)));
}

// ============================================================================
// BGVEncoder Implementation
// ============================================================================

BGVEncoder::BGVEncoder(const BGVContext& context)
    : context_(context)
    , t_(context.plaintext_modulus())
    , slot_count_(context.slot_count()) {
    
    // Initialize batch encoder if t supports it
    if (slot_count_ > 1) {
        initialize_batch_encoder();
    }
}

void BGVEncoder::initialize_batch_encoder() {
    // Set up CRT decomposition for Z_t[X]/(Φ_m(X))
    // This requires finding primitive roots and computing CRT basis
    
    // For simplicity, we use coefficient encoding as fallback
    // Full CRT implementation requires factoring Φ_m(X) mod t
    
    uint64_t m = context_.params().m;
    uint64_t n = context_.params().n;
    
    // Generate slot mapping for NTT-based encoding
    slot_mapping_.resize(n);
    slot_mapping_inv_.resize(n);
    
    // For power-of-2 m, the mapping is a bit-reversal permutation
    if ((m & (m - 1)) == 0) {
        for (uint64_t i = 0; i < n; i++) {
            slot_mapping_[i] = i;
            slot_mapping_inv_[i] = i;
        }
        // TODO: Compute proper bit-reversal
    }
}

// ============================================================================
// Integer Encoding
// ============================================================================

BGVPlaintext BGVEncoder::encode(int64_t value) const {
    BGVPlaintext pt;
    
    // Set modulus context to t
    ZZ_pPush push;
    ZZ_p::init(to_ZZ(t_));
    
    // Handle negative values
    int64_t reduced = value % static_cast<int64_t>(t_);
    if (reduced < 0) {
        reduced += static_cast<int64_t>(t_);
    }
    
    SetCoeff(pt.data().poly(), 0, conv<ZZ_p>(reduced));
    
    return pt;
}

BGVPlaintext BGVEncoder::encode(const ZZ& value) const {
    BGVPlaintext pt;
    
    ZZ_pPush push;
    ZZ_p::init(to_ZZ(t_));
    
    ZZ reduced = value % to_ZZ(t_);
    if (reduced < 0) {
        reduced += t_;
    }
    
    SetCoeff(pt.data().poly(), 0, conv<ZZ_p>(reduced));
    
    return pt;
}

int64_t BGVEncoder::decode_int(const BGVPlaintext& pt) const {
    if (pt.data().degree() < 0) {
        return 0;
    }
    
    ZZ coef = rep(pt.data().coeff(0));
    
    // Centered reduction
    ZZ t_half = to_ZZ(static_cast<long>(t_ / 2));
    ZZ t_zz = to_ZZ(static_cast<long>(t_));
    if (coef > t_half) {
        coef -= t_zz;
    }
    
    return to_long(coef);
}

ZZ BGVEncoder::decode_zz(const BGVPlaintext& pt) const {
    if (pt.data().degree() < 0) {
        return conv<ZZ>(0);
    }
    
    return rep(pt.data().coeff(0));
}

// ============================================================================
// Batch Encoding (SIMD)
// ============================================================================

BGVPlaintext BGVEncoder::encode_batch(const std::vector<int64_t>& values) const {
    if (values.size() > slot_count_) {
        throw std::invalid_argument("Too many values for available slots");
    }
    
    BGVPlaintext pt;
    pt.is_batched_ = true;
    
    ZZ_pPush push;
    ZZ_p::init(to_ZZ(t_));
    
    // Simple coefficient encoding (non-CRT)
    // For proper SIMD, we'd use inverse NTT
    for (size_t i = 0; i < values.size(); i++) {
        int64_t val = values[i] % static_cast<int64_t>(t_);
        if (val < 0) {
            val += static_cast<int64_t>(t_);
        }
        SetCoeff(pt.data().poly(), slot_mapping_[i], conv<ZZ_p>(val));
    }
    
    return pt;
}

BGVPlaintext BGVEncoder::encode_batch(const std::vector<uint64_t>& values) const {
    std::vector<int64_t> signed_values(values.size());
    for (size_t i = 0; i < values.size(); i++) {
        signed_values[i] = static_cast<int64_t>(values[i] % t_);
    }
    return encode_batch(signed_values);
}

BGVPlaintext BGVEncoder::encode_batch(const vec_ZZ& values) const {
    std::vector<int64_t> int_values(values.length());
    ZZ t = to_ZZ(t_);
    
    for (long i = 0; i < values.length(); i++) {
        ZZ reduced = values[i] % t;
        int_values[i] = to_long(reduced);
    }
    
    return encode_batch(int_values);
}

std::vector<int64_t> BGVEncoder::decode_batch(const BGVPlaintext& pt) const {
    std::vector<int64_t> result(slot_count_);
    
    int64_t t_half = static_cast<int64_t>(t_ / 2);
    
    for (size_t i = 0; i < slot_count_; i++) {
        long coef_idx = slot_mapping_inv_[i];
        
        ZZ coef;
        if (coef_idx <= pt.data().degree()) {
            coef = rep(pt.data().coeff(coef_idx));
        } else {
            coef = conv<ZZ>(0);
        }
        
        int64_t val = to_long(coef);
        
        // Centered reduction for signed interpretation
        if (val > t_half) {
            val -= static_cast<int64_t>(t_);
        }
        
        result[i] = val;
    }
    
    return result;
}

std::vector<uint64_t> BGVEncoder::decode_batch_unsigned(
    const BGVPlaintext& pt) const {
    
    std::vector<uint64_t> result(slot_count_);
    
    for (size_t i = 0; i < slot_count_; i++) {
        long coef_idx = slot_mapping_inv_[i];
        
        ZZ coef;
        if (coef_idx <= pt.data().degree()) {
            coef = rep(pt.data().coeff(coef_idx));
        } else {
            coef = to_ZZ(0);
        }
        
        result[i] = to_ulong(coef % to_ZZ(static_cast<long>(t_)));
    }
    
    return result;
}

vec_ZZ BGVEncoder::decode_batch_zz(const BGVPlaintext& pt) const {
    vec_ZZ result;
    result.SetLength(slot_count_);
    
    for (size_t i = 0; i < slot_count_; i++) {
        long coef_idx = slot_mapping_inv_[i];
        
        if (coef_idx <= pt.data().degree()) {
            result[i] = rep(pt.data().coeff(coef_idx));
        } else {
            result[i] = conv<ZZ>(0);
        }
    }
    
    return result;
}

// ============================================================================
// Polynomial Encoding
// ============================================================================

BGVPlaintext BGVEncoder::encode_poly(const std::vector<int64_t>& coeffs) const {
    BGVPlaintext pt;
    
    ZZ_pPush push;
    ZZ_p::init(to_ZZ(t_));
    
    for (size_t i = 0; i < coeffs.size(); i++) {
        int64_t val = coeffs[i] % static_cast<int64_t>(t_);
        if (val < 0) {
            val += static_cast<int64_t>(t_);
        }
        SetCoeff(pt.data().poly(), i, conv<ZZ_p>(val));
    }
    
    return pt;
}

std::vector<int64_t> BGVEncoder::decode_poly(const BGVPlaintext& pt) const {
    std::vector<int64_t> coeffs;
    
    int64_t t_half = static_cast<int64_t>(t_ / 2);
    
    for (long i = 0; i <= pt.data().degree(); i++) {
        ZZ coef = rep(pt.data().coeff(i));
        int64_t val = to_long(coef);
        
        if (val > t_half) {
            val -= static_cast<int64_t>(t_);
        }
        
        coeffs.push_back(val);
    }
    
    return coeffs;
}

// ============================================================================
// BGVCoeffEncoder Implementation
// ============================================================================

BGVCoeffEncoder::BGVCoeffEncoder(const BGVContext& context)
    : context_(context)
    , t_(context.plaintext_modulus())
    , n_(context.ring_degree()) {
}

BGVPlaintext BGVCoeffEncoder::encode(int64_t value) const {
    BGVPlaintext pt;
    
    ZZ_pPush push;
    ZZ_p::init(to_ZZ(t_));
    
    int64_t reduced = value % static_cast<int64_t>(t_);
    if (reduced < 0) {
        reduced += static_cast<int64_t>(t_);
    }
    
    SetCoeff(pt.data().poly(), 0, conv<ZZ_p>(reduced));
    
    return pt;
}

BGVPlaintext BGVCoeffEncoder::encode(const std::vector<int64_t>& coeffs) const {
    BGVPlaintext pt;
    
    ZZ_pPush push;
    ZZ_p::init(to_ZZ(t_));
    
    size_t max_coeffs = std::min(coeffs.size(), static_cast<size_t>(n_));
    
    for (size_t i = 0; i < max_coeffs; i++) {
        int64_t val = coeffs[i] % static_cast<int64_t>(t_);
        if (val < 0) {
            val += static_cast<int64_t>(t_);
        }
        SetCoeff(pt.data().poly(), i, conv<ZZ_p>(val));
    }
    
    return pt;
}

int64_t BGVCoeffEncoder::decode(const BGVPlaintext& pt) const {
    if (pt.data().degree() < 0) {
        return 0;
    }
    
    ZZ coef = rep(pt.data().coeff(0));
    int64_t t_half = static_cast<int64_t>(t_ / 2);
    int64_t val = to_long(coef);
    
    if (val > t_half) {
        val -= static_cast<int64_t>(t_);
    }
    
    return val;
}

std::vector<int64_t> BGVCoeffEncoder::decode_all(const BGVPlaintext& pt) const {
    std::vector<int64_t> coeffs;
    
    int64_t t_half = static_cast<int64_t>(t_ / 2);
    
    for (long i = 0; i <= pt.data().degree(); i++) {
        ZZ coef = rep(pt.data().coeff(i));
        int64_t val = to_long(coef);
        
        if (val > t_half) {
            val -= static_cast<int64_t>(t_);
        }
        
        coeffs.push_back(val);
    }
    
    // Pad to n coefficients
    while (coeffs.size() < n_) {
        coeffs.push_back(0);
    }
    
    return coeffs;
}

} // namespace bgv
} // namespace fhe
} // namespace kctsb
