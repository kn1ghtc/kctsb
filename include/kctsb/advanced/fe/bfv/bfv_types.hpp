/**
 * @file bfv_types.hpp
 * @brief BFV Type Definitions (Pure RNS Implementation)
 * 
 * Defines key and ciphertext types for BFV FHE using RNSPoly representation.
 * BFV is scale-invariant and uses Δ = floor(Q/t) for encoding.
 * 
 * Key differences from BGV:
 * - Encoding: m → Δ·m (scaled by floor(q/t))
 * - Decryption: round(t·m/Q) to remove scaling
 * - Noise growth: constant per level (scale-invariant)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.11.0
 * @since Phase 4d - Pure RNS migration
 */

#ifndef KCTSB_FHE_BFV_TYPES_HPP
#define KCTSB_FHE_BFV_TYPES_HPP

#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include <vector>
#include <cstdint>

namespace kctsb {
namespace fhe {
namespace bfv {

/**
 * @brief BFV Secret Key (Pure RNS)
 * 
 * Contains the secret polynomial s in NTT domain.
 * Identical to BGV secret key structure.
 */
struct BFVSecretKey {
    RNSPoly s;              ///< Secret polynomial (NTT domain)
    bool is_ntt_form;       ///< Always true
    
    BFVSecretKey() : is_ntt_form(false) {}
    explicit BFVSecretKey(RNSPoly&& sk) 
        : s(std::move(sk)), is_ntt_form(true) {}
};

/**
 * @brief BFV Public Key (Pure RNS)
 * 
 * Contains pk = (pk0, pk1) = (-(a*s + e), a) both in NTT domain.
 * Note: BFV does NOT use t*e term (unlike BGV).
 */
struct BFVPublicKey {
    RNSPoly pk0;            ///< -(a*s + e) in NTT domain
    RNSPoly pk1;            ///< a in NTT domain
    bool is_ntt_form;       ///< Always true
    
    BFVPublicKey() : is_ntt_form(false) {}
    BFVPublicKey(RNSPoly&& p0, RNSPoly&& p1)
        : pk0(std::move(p0)), pk1(std::move(p1)), is_ntt_form(true) {}
};

/**
 * @brief BFV Relinearization Key (Pure RNS)
 * 
 * Key switching key for relinearization: (ksk0_i, ksk1_i)
 * Same structure as BGV relinearization key.
 */
struct BFVRelinKey {
    std::vector<RNSPoly> ksk0;  ///< First components (NTT domain)
    std::vector<RNSPoly> ksk1;  ///< Second components (NTT domain)
    uint64_t decomp_base;       ///< Decomposition base (typically 2^16 or 2^20)
    bool is_ntt_form;           ///< Always true
    
    BFVRelinKey() : decomp_base(0), is_ntt_form(false) {}
    BFVRelinKey(std::vector<RNSPoly>&& k0, std::vector<RNSPoly>&& k1, uint64_t base)
        : ksk0(std::move(k0)), ksk1(std::move(k1)), decomp_base(base), is_ntt_form(true) {}
};

/**
 * @brief BFV Ciphertext (Pure RNS)
 * 
 * Contains (c0, c1) or (c0, c1, c2) polynomials in NTT domain.
 * Additional fields track the scaling factor for BFV operations.
 */
struct BFVCiphertext {
    std::vector<RNSPoly> data;  ///< Ciphertext polynomials (NTT domain)
    bool is_ntt_form;           ///< Always true
    int level;                  ///< Current modulus level (0 = highest)
    int noise_budget;           ///< Remaining noise budget (bits)
    int scale_degree;           ///< Scale degree: 1=Δ (fresh), 2=Δ² (after mult), etc.
    
    BFVCiphertext() : is_ntt_form(false), level(0), noise_budget(0), scale_degree(1) {}
    
    size_t size() const { return data.size(); }
    
    RNSPoly& operator[](size_t i) { return data[i]; }
    const RNSPoly& operator[](size_t i) const { return data[i]; }
    
    void push_back(RNSPoly&& poly) { data.push_back(std::move(poly)); }
    void resize(size_t new_size) { data.resize(new_size); }
};

/**
 * @brief BFV Plaintext (Simple uint64_t vector)
 * 
 * Plaintext data before encoding/after decoding.
 * Values are integers in range [0, t-1] or [-t/2, t/2).
 */
using BFVPlaintext = std::vector<uint64_t>;

} // namespace bfv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_BFV_TYPES_HPP
