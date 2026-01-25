/**
 * @file bgv_types.hpp
 * @brief BGV Type Definitions (Pure RNS Implementation)
 * 
 * Defines key and ciphertext types for BGV FHE using RNSPoly representation.
 * This is a zero-ZZ_pX implementation where all data stays in RNS form.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.11.0
 * @since Phase 4d - Pure RNS migration
 */

#ifndef KCTSB_FHE_BGV_TYPES_HPP
#define KCTSB_FHE_BGV_TYPES_HPP

#include "kctsb/advanced/fe/common/rns_poly.hpp"
#include <vector>
#include <map>
#include <stdexcept>
#include <cstdint>

namespace kctsb {
namespace fhe {
namespace bgv {

/**
 * @brief BGV Secret Key (Pure RNS)
 * 
 * Contains the secret polynomial s in NTT domain.
 * Always stored in NTT form for fast operations.
 */
struct BGVSecretKey {
    RNSPoly s;              ///< Secret polynomial (NTT domain)
    bool is_ntt_form;       ///< Always true
    
    BGVSecretKey() : is_ntt_form(false) {}
    explicit BGVSecretKey(RNSPoly&& sk) 
        : s(std::move(sk)), is_ntt_form(true) {}
};

/**
 * @brief BGV Public Key (Pure RNS)
 * 
 * Contains pk = (pk0, pk1) = (-(a*s + t*e), a) both in NTT domain.
 * Encryption uses pk*u + t*noise + m.
 */
struct BGVPublicKey {
    RNSPoly pk0;            ///< -(a*s + t*e) in NTT domain
    RNSPoly pk1;            ///< a in NTT domain
    bool is_ntt_form;       ///< Always true
    
    BGVPublicKey() : is_ntt_form(false) {}
    BGVPublicKey(RNSPoly&& p0, RNSPoly&& p1)
        : pk0(std::move(p0)), pk1(std::move(p1)), is_ntt_form(true) {}
};

/**
 * @brief BGV Relinearization Key (Pure RNS)
 * 
 * Key switching key for relinearization: (ksk0_i, ksk1_i)
 * Used to reduce ciphertext size from 3 to 2 after multiplication.
 */
struct BGVRelinKey {
    std::vector<RNSPoly> ksk0;  ///< First components (NTT domain)
    std::vector<RNSPoly> ksk1;  ///< Second components (NTT domain)
    uint64_t decomp_base;       ///< Decomposition base (typically 2^16 or 2^20)
    bool is_ntt_form;           ///< Always true
    
    BGVRelinKey() : decomp_base(0), is_ntt_form(false) {}
    BGVRelinKey(std::vector<RNSPoly>&& k0, std::vector<RNSPoly>&& k1, uint64_t base)
        : ksk0(std::move(k0)), ksk1(std::move(k1)), decomp_base(base), is_ntt_form(true) {}
};

/**
 * @brief BGV Galois Key for Rotation Operations (Pure RNS)
 * 
 * Contains key switching keys for Galois automorphisms σ_k(x) = x^k.
 * Used for rotate_rows (k = 5^i mod 2n) and rotate_columns (k = -1).
 * 
 * Each key maps: E(m) → E(σ_k(m)) via key switching.
 * 
 * Stored in NTT domain for efficient operations.
 */
struct BGVGaloisKey {
    std::vector<RNSPoly> ksk0;  ///< First components (NTT domain)
    std::vector<RNSPoly> ksk1;  ///< Second components (NTT domain)
    uint64_t galois_elt;        ///< Galois element k: x → x^k
    uint64_t decomp_base;       ///< Decomposition base
    bool is_ntt_form;           ///< Always true
    
    BGVGaloisKey() : galois_elt(0), decomp_base(0), is_ntt_form(false) {}
    BGVGaloisKey(std::vector<RNSPoly>&& k0, std::vector<RNSPoly>&& k1,
                 uint64_t elt, uint64_t base)
        : ksk0(std::move(k0)), ksk1(std::move(k1)), 
          galois_elt(elt), decomp_base(base), is_ntt_form(true) {}
};

/**
 * @brief BGV Galois Keys Collection for All Rotations
 * 
 * Contains Galois keys for:
 * - Row rotations: powers of generator 5 mod 2n
 * - Column swap: element (2n - 1) = n*2 - 1
 * 
 * For ring degree n, row slots = n/2, column slots = 2.
 */
struct BGVGaloisKeys {
    std::map<uint64_t, BGVGaloisKey> keys;  ///< Galois element → key
    uint64_t decomp_base;                    ///< Common decomposition base
    
    BGVGaloisKeys() : decomp_base(0) {}
    
    /**
     * @brief Check if key exists for given Galois element
     */
    bool has_key(uint64_t galois_elt) const {
        return keys.find(galois_elt) != keys.end();
    }
    
    /**
     * @brief Get key for Galois element (throws if not found)
     */
    const BGVGaloisKey& get_key(uint64_t galois_elt) const {
        auto it = keys.find(galois_elt);
        if (it == keys.end()) {
            throw std::runtime_error("Galois key not found for element: " + 
                                   std::to_string(galois_elt));
        }
        return it->second;
    }
};

/**
 * @brief BGV Ciphertext (Pure RNS)
 * 
 * Contains (c0, c1) or (c0, c1, c2, ...) polynomials in NTT domain.
 * - Fresh ciphertext: size = 2
 * - After multiplication: size = 3
 * - After relinearization: size = 2 again
 */
struct BGVCiphertext {
    std::vector<RNSPoly> data;  ///< Ciphertext polynomials (NTT domain)
    bool is_ntt_form;           ///< Always true
    int level;                  ///< Current modulus level (0 = highest)
    int noise_budget;           ///< Remaining noise budget (bits)
    
    BGVCiphertext() : is_ntt_form(false), level(0), noise_budget(0) {}
    
    size_t size() const { return data.size(); }
    
    RNSPoly& operator[](size_t i) { return data[i]; }
    const RNSPoly& operator[](size_t i) const { return data[i]; }
    
    void push_back(RNSPoly&& poly) { data.push_back(std::move(poly)); }
    void resize(size_t new_size) { data.resize(new_size); }
};

/**
 * @brief BGV Plaintext (Simple uint64_t vector)
 * 
 * Plaintext data before encoding/after decoding.
 * Coefficient form, not RNS.
 */
using BGVPlaintext = std::vector<uint64_t>;

// ============================================================================
// Backward Compatibility Aliases (for v4.10.0 code)
// ============================================================================

/// @deprecated Use BGVSecretKey instead
using BGVSecretKeyV2 = BGVSecretKey;

/// @deprecated Use BGVPublicKey instead
using BGVPublicKeyV2 = BGVPublicKey;

/// @deprecated Use BGVRelinKey instead
using BGVRelinKeyV2 = BGVRelinKey;

/// @deprecated Use BGVCiphertext instead
using BGVCiphertextV2 = BGVCiphertext;

/// @deprecated Use BGVPlaintext instead
using BGVPlaintextV2 = BGVPlaintext;

} // namespace bgv
} // namespace fhe
} // namespace kctsb

#endif // KCTSB_FHE_BGV_TYPES_HPP
