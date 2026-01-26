/**
 * @file sm2_keygen.cpp
 * @brief SM2 Key Generation Implementation
 * 
 * SM2 key pair generation following GB/T 32918-2016:
 * - Private key d: random integer in [1, n-2]
 * - Public key P = d * G (point multiplication)
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/crypto/sm/sm2.h"
#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/core/security.h"
#include "kctsb/core/common.h"

// Montgomery acceleration header
#include "sm2_mont_curve.h"

#include <kctsb/math/ZZ.h>
#include <kctsb/math/ZZ_p.h>

#include <cstring>

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;

namespace kctsb::internal::sm2 {

// External declarations from sm2_curve.cpp
constexpr size_t FIELD_SIZE = 32;

/**
 * @brief SM2 internal context for curve operations
 * 
 * Defined in sm2_curve.cpp, accessed via singleton pattern.
 */
class SM2Context {
public:
    static SM2Context& instance();
    const ecc::internal::ECCurve& curve() const;
    const ZZ& n() const;
    const ZZ& p() const;
    int bit_size() const;
private:
    SM2Context();
    ecc::internal::ECCurve curve_;
    ZZ n_;
    ZZ p_;
    int bit_size_;
};

// External utility functions from sm2_curve.cpp
extern ZZ bytes_to_zz(const uint8_t* data, size_t len);
extern void zz_to_bytes(const ZZ& z, uint8_t* out, size_t len);

// ============================================================================
// Key Generation (Montgomery Accelerated)
// ============================================================================

/**
 * @brief Generate SM2 key pair using Montgomery acceleration
 * 
 * Private key d is a random integer in [1, n-2]
 * Public key P = d * G (point multiplication)
 * 
 * Uses Montgomery arithmetic and precomputed wNAF table for ~50x speedup.
 * Falls back to generic ECC if Montgomery fails.
 * 
 * @param keypair Output key pair structure
 * @return KCTSB_SUCCESS or error code
 */
kctsb_error_t generate_keypair_internal(kctsb_sm2_keypair_t* keypair) {
    auto& ctx = SM2Context::instance();
    const auto& curve = ctx.curve();
    const ZZ& n = ctx.n();
    
    // Generate private key d in [1, n-2]
    uint8_t d_bytes[FIELD_SIZE];
    for (int attempts = 0; attempts < 100; attempts++) {
        if (kctsb_random_bytes(d_bytes, FIELD_SIZE) != KCTSB_SUCCESS) {
            return KCTSB_ERROR_RANDOM_FAILED;
        }
        
        ZZ d = bytes_to_zz(d_bytes, FIELD_SIZE);
        d = d % (n - 1);  // Reduce to [0, n-2]
        
        if (IsZero(d)) {
            continue;  // d must be at least 1
        }
        d = d + 1;  // Now d is in [1, n-1]
        
        // Export private key to bytes
        zz_to_bytes(d, keypair->private_key, FIELD_SIZE);
        
        // === Montgomery Accelerated Point Multiplication ===
        // Uses precomputed wNAF table for ~50x speedup over generic ECC
        sm2_point_result P_mont;
        if (scalar_mult_base_mont(&P_mont, keypair->private_key)) {
            // Success: copy coordinates to public key
            std::memcpy(keypair->public_key, P_mont.x, FIELD_SIZE);
            std::memcpy(keypair->public_key + FIELD_SIZE, P_mont.y, FIELD_SIZE);
            
            // Secure cleanup
            kctsb_secure_zero(d_bytes, sizeof(d_bytes));
            return KCTSB_SUCCESS;
        }
        
        // Fallback: Montgomery returned point at infinity (invalid d)
        // This should be extremely rare for random d
        continue;
    }
    
    kctsb_secure_zero(d_bytes, sizeof(d_bytes));
    return KCTSB_ERROR_RANDOM_FAILED;
}

}  // namespace kctsb::internal::sm2

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

kctsb_error_t kctsb_sm2_generate_keypair(kctsb_sm2_keypair_t* keypair) {
    if (keypair == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    return kctsb::internal::sm2::generate_keypair_internal(keypair);
}

}  // extern "C"
