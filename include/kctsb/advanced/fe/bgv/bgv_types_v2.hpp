/**
 * @file bgv_types_v2.hpp
 * @brief BGV V2 Type Definitions (Pure RNS Implementation)
 * 
 * Defines key and ciphertext types for BGV FHE using RNSPoly representation.
 * This is a zero-ZZ_pX implementation where all data stays in RNS form.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.10.0
 * @since Phase 4c optimization
 */

#ifndef KCTSB_FHE_BGV_TYPES_V2_HPP
#define KCTSB_FHE_BGV_TYPES_V2_HPP

#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include <vector>
#include <cstdint>

namespace kctsb {
namespace fhe {
namespace bgv {

/**
 * @brief BGV Secret Key V2 (Pure RNS)
 * 
 * Contains the secret polynomial s in NTT domain.
 * Always stored in NTT form for fast operations.
 */
struct BGVSecretKeyV2 {
    RNSPoly s;              ///< Secret polynomial (NTT domain)
    bool is_ntt_form;       ///< Always true
    
    BGVSecretKeyV2() : is_ntt_form(false) {}
    explicit BGVSecretKeyV2(RNSPoly&& sk) 
        : s(std::move(sk)), is_ntt_form(true) {}
};

/**
 * @brief BGV Public Key V2 (Pure RNS)
 * 
 * Contains pk = (pk0, pk1) = (-(a*s + e), a) both in NTT domain.
 * Encryption uses pk*u + noise.
 */
struct BGVPublicKeyV2 {
    RNSPoly pk0;            ///< -(a*s + e) in NTT domain
    RNSPoly pk1;            ///< a in NTT domain
    bool is_ntt_form;       ///< Always true
    
    BGVPublicKeyV2() : is_ntt_form(false) {}
    BGVPublicKeyV2(RNSPoly&& p0, RNSPoly&& p1)
        : pk0(std::move(p0)), pk1(std::move(p1)), is_ntt_form(true) {}
};

/**
 * @brief BGV Relinearization Key V2 (Pure RNS)
 * 
 * Key switching key for relinearization: (ksk0_i, ksk1_i)
 * Used to reduce ciphertext size from 3 to 2 after multiplication.
 */
struct BGVRelinKeyV2 {
    std::vector<RNSPoly> ksk0;  ///< First components (NTT domain)
    std::vector<RNSPoly> ksk1;  ///< Second components (NTT domain)
    uint64_t decomp_base;       ///< Decomposition base (typically 2^16 or 2^20)
    bool is_ntt_form;           ///< Always true
    
    BGVRelinKeyV2() : decomp_base(0), is_ntt_form(false) {}
    BGVRelinKeyV2(std::vector<RNSPoly>&& k0, std::vector<RNSPoly>&& k1, uint64_t base)
        : ksk0(std::move(k0)), ksk1(std::move(k1)), decomp_base(base), is_ntt_form(true) {}
};

/**
 * @brief BGV Ciphertext V2 (Pure RNS)
 * 
 * Contains (c0, c1) or (c0, c1, c2, ...) polynomials in NTT domain.
 * - Fresh ciphertext: size = 2
 * - After multiplication: size = 3
 * - After relinearization: size = 2 again
 */
struct BGVCiphertextV2 {
    std::vector<RNSPoly> data;  ///< Ciphertext polynomials (NTT domain)
    bool is_ntt_form;           ///< Always true
    int level;                  ///< Current modulus level (0 = highest)
    int noise_budget;           ///< Remaining noise budget (bits)
    
    BGVCiphertextV2() : is_ntt_form(false), level(0), noise_budget(0) {}
    
    size_t size() const { return data.size(); }
    
    RNSPoly& operator[](size_t i) { return data[i]; }
    const RNSPoly& operator[](size_t i) const { return data[i]; }
    
    void push_back(RNSPoly&& poly) { data.push_back(std::move(poly)); }
    void resize(size_t new_size) { data.resize(new_size); }
};

/**
 * @brief BGV Plaintext V2 (Simple uint64_t vector)
 * 
 * Plaintext data before encoding/after decoding.
 * Coefficient form, not RNS.
 */
using BGVPlaintextV2 = std::vector<uint64_t>;

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_BGV_TYPES_V2_HPP
