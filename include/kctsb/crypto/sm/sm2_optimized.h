/**
 * @file sm2_optimized.h
 * @brief Optimized SM2 Elliptic Curve Operations
 * 
 * Performance-optimized SM2 curve operations using wNAF scalar multiplication:
 * - wNAF (windowed Non-Adjacent Form) scalar multiplication
 * - Fixed-base precomputation tables for generator point
 * - Constant-time table lookups for side-channel protection
 * 
 * The SM2 curve is the Chinese National Standard (GB/T 32918-2016) and shares
 * similar structure to NIST P-256, allowing wNAF optimizations to provide
 * approximately 3-4x speedup over binary scalar multiplication.
 * 
 * Integration Points:
 * - sm2_fast_scalar_mult_base(): Replaces curve.scalar_mult_base() in sign/keygen
 * - sm2_fast_scalar_mult(): Replaces curve.scalar_mult() in verify/decrypt
 * - sm2_fast_double_scalar_mult(): Optimized for signature verification
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_SM_SM2_OPTIMIZED_H
#define KCTSB_CRYPTO_SM_SM2_OPTIMIZED_H

#include "kctsb/crypto/ecc/ecc_curve.h"
#include "kctsb/crypto/ecc/ecc_optimized.h"
#include <kctsb/math/bignum/ZZ.h>
#include <mutex>

namespace kctsb {
namespace sm2 {

// Use kctsb::ZZ (kctsb uses its own namespace for NTL types)
using kctsb::ZZ;

// ============================================================================
// SM2 Generator Point Precomputation
// ============================================================================

/**
 * @brief Cached SM2 generator precomputation table
 * 
 * Provides fast fixed-base scalar multiplication for k*G on SM2 curve.
 * Table is computed once on first use and cached for subsequent operations.
 * 
 * Thread-safe: uses std::call_once for initialization.
 */
class SM2GeneratorTable {
public:
    /**
     * @brief Get singleton instance
     * @return Reference to the cached generator table
     */
    static const ecc::wNAFPrecompTable& instance();
    
    /**
     * @brief Clear cached table (for memory cleanup or testing)
     */
    static void reset();
    
private:
    SM2GeneratorTable() = delete;
    
    // Cache both curve and table (curve must outlive table)
    static std::unique_ptr<ecc::ECCurve> curve_;
    static std::unique_ptr<ecc::wNAFPrecompTable> table_;
    static std::once_flag init_flag_;
    static std::mutex reset_mutex_;
    
    static void initialize();
};

// ============================================================================
// Optimized SM2 Scalar Multiplication
// ============================================================================

/**
 * @brief Fast generator scalar multiplication for SM2: R = k * G
 * 
 * Uses cached wNAF precomputation table for SM2 generator point.
 * Provides approximately 3-4x speedup over standard binary multiplication.
 * 
 * Usage in SM2:
 * - Key generation: P = d * G
 * - Signing: C1 = k * G
 * - Encryption: C1 = k * G
 * 
 * @param curve The SM2 curve (must be CurveType::SM2)
 * @param k Scalar multiplier
 * @return k * G (generator point multiplication)
 */
ecc::JacobianPoint sm2_fast_scalar_mult_base(const ecc::ECCurve& curve, 
                                              const ZZ& k);

/**
 * @brief Fast arbitrary point scalar multiplication for SM2: R = k * P
 * 
 * Uses wNAF encoding for improved performance over binary multiplication.
 * 
 * Usage in SM2:
 * - Verification: t * P
 * - Encryption: k * P (public key point)
 * - Decryption: d * C1
 * - Key exchange: d * P_other
 * 
 * @param curve The SM2 curve
 * @param k Scalar multiplier  
 * @param P Base point
 * @return k * P
 */
ecc::JacobianPoint sm2_fast_scalar_mult(const ecc::ECCurve& curve,
                                         const ZZ& k,
                                         const ecc::JacobianPoint& P);

/**
 * @brief Fast double scalar multiplication for SM2: R = k1*G + k2*P
 * 
 * Optimized using interleaved wNAF (Shamir's trick).
 * More efficient than computing k1*G and k2*P separately.
 * 
 * Usage in SM2:
 * - Signature verification: s*G + t*P (where t = r + s mod n)
 * 
 * @param curve The SM2 curve
 * @param k1 First scalar (for generator G)
 * @param k2 Second scalar
 * @param P Second point (typically public key)
 * @return k1*G + k2*P
 */
ecc::JacobianPoint sm2_fast_double_scalar_mult(const ecc::ECCurve& curve,
                                                const ZZ& k1,
                                                const ZZ& k2,
                                                const ecc::JacobianPoint& P);

// ============================================================================
// Performance Configuration
// ============================================================================

/**
 * @brief Check if SM2 wNAF optimization is enabled
 * @return true if optimization is enabled (always true in this build)
 */
inline bool sm2_wnaf_enabled() {
    return true;
}

/**
 * @brief Get SM2 wNAF window width
 * @return Window width (default: 5)
 */
inline int sm2_wnaf_window_width() {
    return ecc::WNAF_WINDOW_WIDTH;
}

} // namespace sm2
} // namespace kctsb

#endif // KCTSB_CRYPTO_SM_SM2_OPTIMIZED_H
