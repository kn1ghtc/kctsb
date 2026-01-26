/**
 * @file ZZ_montgomery.h
 * @brief Montgomery Modular Arithmetic API
 * 
 * Fast modular multiplication without division.
 * Essential for RSA, SM2, ECC scalar multiplication.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_MATH_ZZ_MONTGOMERY_H
#define KCTSB_MATH_ZZ_MONTGOMERY_H

#include "kctsb/core/common.h"
#include <vector>
#include <cstdint>

namespace kctsb {
namespace math {

/**
 * @brief Montgomery arithmetic context
 * 
 * Precomputes constants for fast modular reduction.
 * 
 * Usage:
 * ```cpp
 * uint64_t n[4] = {...};  // 256-bit modulus
 * MontgomeryContext ctx;
 * ctx.init(n, 4);
 * 
 * uint64_t a[4], b[4], result[4];
 * uint64_t a_mont[4], b_mont[4], res_mont[4];
 * 
 * ctx.to_montgomery(a, a_mont);
 * ctx.to_montgomery(b, b_mont);
 * ctx.mont_mul(a_mont, b_mont, res_mont);  // Fast multiply
 * ctx.from_montgomery(res_mont, result);   // Convert back
 * ```
 */
class MontgomeryContext {
public:
    /**
     * @brief Initialize Montgomery context
     * @param modulus Modulus n (must be odd)
     * @param num_words Number of 64-bit words in modulus
     */
    void init(const uint64_t* modulus, size_t num_words);

    /**
     * @brief Montgomery multiplication: (aR * bR * R^-1) mod n = (ab)R mod n
     * @param a_mont First operand in Montgomery form
     * @param b_mont Second operand in Montgomery form
     * @param result Output in Montgomery form
     */
    void mont_mul(
        const uint64_t* a_mont,
        const uint64_t* b_mont,
        uint64_t* result) const;

    /**
     * @brief Montgomery reduction: T * R^-1 mod n
     * @param t Input (2*n_words)
     * @param result Output (n_words)
     */
    void mont_reduce(
        const uint64_t* t,
        uint64_t* result) const;

    /**
     * @brief Convert to Montgomery form: a -> aR mod n
     */
    void to_montgomery(
        const uint64_t* a,
        uint64_t* a_mont) const;

    /**
     * @brief Convert from Montgomery form: aR -> a
     */
    void from_montgomery(
        const uint64_t* a_mont,
        uint64_t* a) const;

    /**
     * @brief Montgomery modular exponentiation: base^exp mod n
     * 
     * Used for RSA encryption/decryption.
     * 
     * @param base Base value
     * @param exp Exponent
     * @param exp_words Number of words in exponent
     * @param result Output: base^exp mod n
     */
    void mont_exp(
        const uint64_t* base,
        const uint64_t* exp,
        size_t exp_words,
        uint64_t* result) const;

    // Accessors
    size_t get_num_words() const { return n_words; }
    const std::vector<uint64_t>& get_modulus() const { return n; }

private:
    size_t n_words;                    ///< Number of 64-bit words
    std::vector<uint64_t> n;           ///< Modulus
    uint64_t n_prime;                  ///< -n^-1 mod 2^64
    std::vector<uint64_t> r2;          ///< R^2 mod n (for conversion)
    std::vector<uint64_t> r_mod_n;     ///< R mod n (Montgomery form of 1)
};

/**
 * @brief Batch modular inversion using Montgomery's Trick
 * 
 * Compute [a1^-1, a2^-1, ..., an^-1] mod p with only 1 inversion.
 * Cost: 1 inversion + 3n multiplications (vs n inversions).
 * 
 * Critical for batch SM2 signing performance boost.
 * 
 * @param inputs Array of input values
 * @param num_words Number of 64-bit words per value
 * @param ctx Montgomery context
 * @param outputs Output buffer for inverses
 */
void batch_mod_inverse_montgomery(
    const std::vector<const uint64_t*>& inputs,
    size_t num_words,
    const MontgomeryContext& ctx,
    std::vector<uint64_t*>& outputs);

} // namespace math
} // namespace kctsb

#endif // KCTSB_MATH_ZZ_MONTGOMERY_H
