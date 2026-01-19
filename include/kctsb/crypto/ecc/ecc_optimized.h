/**
 * @file ecc_optimized.h
 * @brief Optimized Elliptic Curve Operations
 * 
 * Performance-optimized ECC operations with side-channel protection:
 * - wNAF (windowed Non-Adjacent Form) scalar multiplication
 * - Fixed-base precomputation tables
 * - Constant-time table lookups
 * - GLV endomorphism for secp256k1 (optional)
 * 
 * Design Principles:
 * 1. Security first: all operations are constant-time
 * 2. Performance: wNAF with w=5 for ~3x speedup
 * 3. Memory tradeoff: precomputation tables for base point
 * 
 * References:
 * - Joppe Bos et al., "Selecting Elliptic Curves for Cryptography"
 * - Renes, Costello, Batina, "Complete Addition Formulas for Prime Order Curves"
 * - OpenSSL 3.6 ecp_nistz256.c
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_ECC_OPTIMIZED_H
#define KCTSB_CRYPTO_ECC_OPTIMIZED_H

#include "kctsb/crypto/ecc/ecc_curve.h"
#include <array>
#include <vector>
#include <cstdint>

namespace kctsb {
namespace ecc {

// ============================================================================
// wNAF (windowed Non-Adjacent Form) Configuration
// ============================================================================

/**
 * @brief wNAF window width configuration
 * 
 * Window width affects performance and memory:
 * - w=4: 2^3 = 8 precomputed points, ~3.7x faster than binary
 * - w=5: 2^4 = 16 precomputed points, ~4.2x faster
 * - w=6: 2^5 = 32 precomputed points, ~4.5x faster
 * 
 * We use w=5 as default (good balance of speed and memory)
 */
constexpr int WNAF_WINDOW_WIDTH = 5;
constexpr int WNAF_TABLE_SIZE = 1 << (WNAF_WINDOW_WIDTH - 1);  // 2^(w-1) = 16

/**
 * @brief Maximum scalar bit length
 */
constexpr size_t MAX_SCALAR_BITS = 521;  // For P-521

// ============================================================================
// wNAF Representation
// ============================================================================

/**
 * @brief wNAF encoded scalar
 * 
 * Encodes scalar k as sum of: k = sum(d_i * 2^i)
 * where d_i in {0, ±1, ±3, ±5, ..., ±(2^(w-1)-1)}
 * 
 * Properties:
 * - Non-adjacent form: no two consecutive non-zero digits
 * - Average density: 1/(w+1) non-zero digits
 */
struct wNAFEncoding {
    std::array<int8_t, MAX_SCALAR_BITS + 1> digits;  // wNAF digits
    size_t length;                                    // Number of valid digits
    
    wNAFEncoding() : length(0) {
        digits.fill(0);
    }
};

/**
 * @brief Compute wNAF encoding of scalar
 * 
 * Algorithm:
 * while k > 0:
 *   if k is odd:
 *     d = k mod 2^w
 *     if d >= 2^(w-1): d -= 2^w
 *     k = k - d
 *   else:
 *     d = 0
 *   output d
 *   k = k / 2
 * 
 * @param k Scalar to encode
 * @param w Window width (default WNAF_WINDOW_WIDTH)
 * @return wNAF encoding
 */
wNAFEncoding compute_wnaf(const ZZ& k, int w = WNAF_WINDOW_WIDTH);

// ============================================================================
// Precomputation Table for Fixed-Base Multiplication
// ============================================================================

/**
 * @brief Precomputation table for wNAF scalar multiplication
 * 
 * For window width w, stores:
 * T[0] = P, T[1] = 3P, T[2] = 5P, ..., T[2^(w-1)-1] = (2^w-1)P
 * 
 * During scalar multiplication:
 * - Positive wNAF digit d uses T[(d-1)/2]
 * - Negative wNAF digit d uses -T[(-d-1)/2]
 */
class wNAFPrecompTable {
public:
    /**
     * @brief Construct precomputation table for point P
     * @param curve The elliptic curve
     * @param P Base point for precomputation
     * @param w Window width
     */
    wNAFPrecompTable(const ECCurve& curve, const JacobianPoint& P, 
                     int w = WNAF_WINDOW_WIDTH);
    
    /**
     * @brief Constant-time table lookup
     * 
     * Accesses ALL table entries to prevent cache timing attacks.
     * Returns T[(|digit|-1)/2] with appropriate sign.
     * 
     * @param digit wNAF digit (must be in range [-2^(w-1)+1, 2^(w-1)-1])
     * @return Corresponding precomputed point
     */
    JacobianPoint lookup(int8_t digit) const;
    
    /**
     * @brief Get the original curve
     */
    const ECCurve& curve() const { return *curve_; }
    
    /**
     * @brief Get table size
     */
    size_t size() const { return table_.size(); }
    
private:
    const ECCurve* curve_;
    std::vector<JacobianPoint> table_;
    int window_width_;
};

// ============================================================================
// Optimized Scalar Multiplication
// ============================================================================

/**
 * @brief wNAF scalar multiplication: R = k * P
 * 
 * Algorithm:
 * 1. Precompute T[i] = (2i+1)P for i in [0, 2^(w-1)-1]
 * 2. Encode k in wNAF form
 * 3. Scan from MSB to LSB:
 *    R = 2R
 *    if digit != 0: R = R + T[|digit|-1]/2 * sign(digit)
 * 
 * Constant-time: uses conditional assignment instead of branches
 * 
 * @param curve The elliptic curve
 * @param k Scalar multiplier
 * @param P Base point
 * @return k * P
 */
JacobianPoint wnaf_scalar_mult(const ECCurve& curve, const ZZ& k, 
                                const JacobianPoint& P);

/**
 * @brief Fixed-base wNAF scalar multiplication with precomputed table
 * 
 * Use when performing many multiplications with the same base point.
 * 
 * @param k Scalar multiplier
 * @param precomp Precomputation table for base point
 * @return k * Base
 */
JacobianPoint wnaf_scalar_mult_precomp(const ZZ& k, 
                                        const wNAFPrecompTable& precomp);

/**
 * @brief Optimized double scalar multiplication: R = k1*P + k2*Q
 * 
 * Uses interleaved wNAF (Shamir's trick with wNAF encoding).
 * More efficient than computing k1*P and k2*Q separately.
 * 
 * @param curve The elliptic curve
 * @param k1 First scalar
 * @param P First point
 * @param k2 Second scalar
 * @param Q Second point
 * @return k1*P + k2*Q
 */
JacobianPoint wnaf_double_scalar_mult(const ECCurve& curve,
                                       const ZZ& k1, const JacobianPoint& P,
                                       const ZZ& k2, const JacobianPoint& Q);

// ============================================================================
// Generator Point Precomputation
// ============================================================================

/**
 * @brief Precomputed table for curve generator
 * 
 * Provides fast fixed-base scalar multiplication for k*G.
 * Table is computed once per curve and cached.
 */
class GeneratorTable {
public:
    /**
     * @brief Get or create generator table for curve
     * @param curve_type The curve type
     * @return Reference to cached generator table
     */
    static const wNAFPrecompTable& get(CurveType curve_type);
    
    /**
     * @brief Clear cached tables (for memory cleanup)
     */
    static void clear_cache();
    
private:
    GeneratorTable() = delete;
};

/**
 * @brief Optimized generator scalar multiplication: R = k * G
 * 
 * Uses cached precomputation table for maximum performance.
 * 
 * @param curve The elliptic curve
 * @param k Scalar multiplier
 * @return k * G
 */
JacobianPoint fast_scalar_mult_base(const ECCurve& curve, const ZZ& k);

// ============================================================================
// Constant-Time Utility Functions
// ============================================================================

/**
 * @brief Constant-time conditional select
 * 
 * Returns a if selector == 1, b if selector == 0.
 * Executes in constant time regardless of selector value.
 * 
 * @param selector 0 or 1
 * @param a Value to return if selector == 1
 * @param b Value to return if selector == 0
 * @return a or b based on selector
 */
JacobianPoint ct_select(uint8_t selector, 
                        const JacobianPoint& a, 
                        const JacobianPoint& b);

/**
 * @brief Constant-time conditional negate
 * 
 * Returns -P if negate == 1, P if negate == 0.
 * 
 * @param curve The elliptic curve
 * @param P Point to potentially negate
 * @param negate 0 or 1
 * @return P or -P
 */
JacobianPoint ct_negate(const ECCurve& curve, 
                        const JacobianPoint& P, 
                        uint8_t negate);

// ============================================================================
// GLV Endomorphism (for secp256k1)
// ============================================================================

#ifdef KCTSB_ENABLE_GLV

/**
 * @brief GLV scalar decomposition for secp256k1
 * 
 * Decomposes scalar k into k1, k2 where:
 * k*P = k1*P + k2*lambda*P
 * 
 * where lambda is the efficiently computable endomorphism on secp256k1.
 * This allows computing k*P with two ~128-bit scalar multiplications.
 * 
 * Speedup: ~30-40% for secp256k1 only
 * 
 * @param k Original scalar
 * @param k1 Output: first half-scalar
 * @param k2 Output: second half-scalar
 */
void glv_decompose_k256(const ZZ& k, ZZ& k1, ZZ& k2);

/**
 * @brief GLV-optimized scalar multiplication for secp256k1
 * 
 * Uses the efficiently computable endomorphism:
 * lambda(x, y) = (beta * x, y) where beta^3 = 1 (mod p)
 * 
 * @param k Scalar
 * @param P Point (must be on secp256k1)
 * @return k * P
 */
JacobianPoint glv_scalar_mult_k256(const ZZ& k, const JacobianPoint& P);

#endif  // KCTSB_ENABLE_GLV

// ============================================================================
// Performance Monitoring
// ============================================================================

#ifdef KCTSB_ECC_PERF_STATS

/**
 * @brief ECC operation statistics
 */
struct ECCPerfStats {
    uint64_t field_muls;        // Field multiplications
    uint64_t field_sqrs;        // Field squarings
    uint64_t field_adds;        // Field additions
    uint64_t field_invs;        // Field inversions
    uint64_t point_adds;        // Point additions
    uint64_t point_doubles;     // Point doublings
    
    void reset();
    void print() const;
};

/**
 * @brief Get current performance statistics
 */
ECCPerfStats& get_ecc_stats();

#endif  // KCTSB_ECC_PERF_STATS

} // namespace ecc
} // namespace kctsb

#endif // KCTSB_CRYPTO_ECC_OPTIMIZED_H
