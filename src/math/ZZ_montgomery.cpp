/**
 * @file ZZ_montgomery.cpp
 * @brief Montgomery Modular Arithmetic Optimization
 * 
 * Implements Montgomery form reduction for fast modular multiplication
 * without division. Critical for RSA, SM2, and ECC scalar multiplication.
 * 
 * Algorithm:
 * - MontgomeryForm(a) = a * R mod n (where R = 2^k > n)
 * - MontMul(aR, bR) = (aR * bR * R^-1) mod n = (ab)R mod n
 * - MontRed(aR) = (aR * R^-1) mod n = a mod n
 * 
 * Performance:
 * - Replaces expensive division with cheap shift+mask
 * - ~2x faster than naive modular multiplication
 * - Essential for modexp (RSA) and scalar mult (ECC)
 * 
 * Reference:
 * - Montgomery, "Modular Multiplication Without Trial Division" (1985)
 * - GmSSL's sm2_z256_mont_mul implementation
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/math/ZZ_montgomery.h"
#include "kctsb/core/common.h"
#include <cstring>
#include <algorithm>

namespace kctsb {
namespace math {

/**
 * @brief Compute Montgomery parameter R^2 mod n
 * 
 * R = 2^(k*64) where k = number of 64-bit words in n
 * R^2 mod n is precomputed for MontgomeryForm conversion
 */
static void compute_r2_mod_n(
    const uint64_t* n,
    size_t n_words,
    uint64_t* r2_mod_n)
{
    // R = 2^(n_words * 64)
    // R^2 = 2^(2 * n_words * 64)
    // Compute R^2 mod n using repeated doubling
    
    std::memset(r2_mod_n, 0, n_words * sizeof(uint64_t));
    r2_mod_n[0] = 1;  // Start with 1
    
    // Double (n_words * 64 * 2) times and reduce modulo n
    size_t total_bits = n_words * 64 * 2;
    for (size_t i = 0; i < total_bits; i++) {
        // Shift left by 1 (double)
        uint64_t carry = 0;
        for (size_t j = 0; j < n_words; j++) {
            uint64_t old_word = r2_mod_n[j];
            r2_mod_n[j] = (old_word << 1) | carry;
            carry = old_word >> 63;
        }
        
        // Reduce if >= n
        bool need_reduce = carry != 0;
        if (!need_reduce) {
            for (int j = static_cast<int>(n_words) - 1; j >= 0; j--) {
                if (r2_mod_n[j] > n[j]) {
                    need_reduce = true;
                    break;
                } else if (r2_mod_n[j] < n[j]) {
                    break;
                }
            }
        }
        
        if (need_reduce) {
            // Subtract n
            uint64_t borrow = 0;
            for (size_t j = 0; j < n_words; j++) {
                uint64_t old_word = r2_mod_n[j];
                r2_mod_n[j] = old_word - n[j] - borrow;
                borrow = (old_word < (n[j] + borrow)) ? 1 : 0;
            }
        }
    }
}

/**
 * @brief Compute Montgomery inverse: n' = -n^-1 mod 2^64
 * 
 * Used in Montgomery reduction: n' such that n * n' ≡ -1 (mod R)
 */
static uint64_t compute_n_prime(uint64_t n0) {
    // Extended Euclidean algorithm for modular inverse
    // Find n' such that n0 * n' ≡ -1 (mod 2^64)
    
    // Newton-Raphson iteration (faster than extended GCD)
    // x_{i+1} = x_i * (2 - n0 * x_i)
    uint64_t x = n0;  // Initial approximation
    
    // 6 iterations sufficient for 64-bit convergence
    for (int i = 0; i < 6; i++) {
        x = x * (2 - n0 * x);
    }
    
    return ~x + 1;  // Negate: -x mod 2^64
}

/**
 * @brief Initialize Montgomery context
 */
void MontgomeryContext::init(const uint64_t* modulus, size_t num_words) {
    n_words = num_words;
    n.assign(modulus, modulus + num_words);
    
    // Compute n' = -n^-1 mod 2^64
    n_prime = compute_n_prime(modulus[0]);
    
    // Compute R^2 mod n for conversion to Montgomery form
    r2.resize(n_words);
    compute_r2_mod_n(modulus, n_words, r2.data());
    
    // R mod n = 2^(n_words*64) mod n (for normalization)
    r_mod_n.resize(n_words);
    std::memset(r_mod_n.data(), 0, n_words * sizeof(uint64_t));
    r_mod_n[0] = 1;
    for (size_t i = 0; i < n_words * 64; i++) {
        // Double and reduce
        uint64_t carry = 0;
        for (size_t j = 0; j < n_words; j++) {
            uint64_t old_word = r_mod_n[j];
            r_mod_n[j] = (old_word << 1) | carry;
            carry = old_word >> 63;
        }
        
        // Reduce if >= n
        bool need_reduce = carry != 0;
        if (!need_reduce) {
            for (int j = static_cast<int>(n_words) - 1; j >= 0; j--) {
                if (r_mod_n[j] > n[j]) {
                    need_reduce = true;
                    break;
                } else if (r_mod_n[j] < n[j]) {
                    break;
                }
            }
        }
        
        if (need_reduce) {
            uint64_t borrow = 0;
            for (size_t j = 0; j < n_words; j++) {
                uint64_t old_word = r_mod_n[j];
                r_mod_n[j] = old_word - n[j] - borrow;
                borrow = (old_word < (n[j] + borrow)) ? 1 : 0;
            }
        }
    }
}

/**
 * @brief Montgomery reduction: REDC(T) = T * R^-1 mod n
 * 
 * Input: T with 2*n_words
 * Output: result = T * R^-1 mod n (n_words)
 * 
 * Algorithm (FIPS 186-4 Appendix B.1):
 * 1. m = (T mod R) * n' mod R
 * 2. t = (T + m*n) / R
 * 3. if t >= n: return t - n, else return t
 */
void MontgomeryContext::mont_reduce(
    const uint64_t* t_in,
    uint64_t* result) const
{
    // Working buffer: size 2*n_words + 1
    std::vector<uint64_t> t(2 * n_words + 1, 0);
    std::memcpy(t.data(), t_in, 2 * n_words * sizeof(uint64_t));
    
    // Montgomery reduction: eliminate lower half word by word
    for (size_t i = 0; i < n_words; i++) {
        // m = t[i] * n' mod 2^64
        uint64_t m = t[i] * n_prime;
        
        // t += m * n (starting at position i)
        uint64_t carry = 0;
        for (size_t j = 0; j < n_words; j++) {
            // Compute m * n[j] + carry
            __uint128_t prod = static_cast<__uint128_t>(m) * n[j] + carry;
            
            // Add to t[i+j]
            __uint128_t sum = static_cast<__uint128_t>(t[i + j]) + static_cast<uint64_t>(prod);
            t[i + j] = static_cast<uint64_t>(sum);
            
            carry = static_cast<uint64_t>(prod >> 64) + static_cast<uint64_t>(sum >> 64);
        }
        
        // Propagate carry
        for (size_t j = n_words; carry != 0 && (i + j) < t.size(); j++) {
            __uint128_t sum = static_cast<__uint128_t>(t[i + j]) + carry;
            t[i + j] = static_cast<uint64_t>(sum);
            carry = static_cast<uint64_t>(sum >> 64);
        }
    }
    
    // Result is t[n_words..2*n_words-1] (upper half after division by R)
    std::memcpy(result, t.data() + n_words, n_words * sizeof(uint64_t));
    
    // Final reduction: if result >= n, subtract n
    bool need_reduce = false;
    for (int i = static_cast<int>(n_words) - 1; i >= 0; i--) {
        if (result[i] > n[i]) {
            need_reduce = true;
            break;
        } else if (result[i] < n[i]) {
            break;
        }
    }
    
    if (need_reduce) {
        uint64_t borrow = 0;
        for (size_t i = 0; i < n_words; i++) {
            uint64_t old_word = result[i];
            result[i] = old_word - n[i] - borrow;
            borrow = (old_word < (n[i] + borrow)) ? 1 : 0;
        }
    }
}

/**
 * @brief Montgomery multiplication: MontMul(aR, bR) = (ab)R mod n
 */
void MontgomeryContext::mont_mul(
    const uint64_t* a_mont,
    const uint64_t* b_mont,
    uint64_t* result) const
{
    // Product buffer: size 2*n_words
    std::vector<uint64_t> prod(2 * n_words, 0);
    
    // Compute a * b (full precision)
    for (size_t i = 0; i < n_words; i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < n_words; j++) {
            __uint128_t p = static_cast<__uint128_t>(a_mont[i]) * b_mont[j];
            __uint128_t sum = static_cast<__uint128_t>(prod[i + j]) + 
                             static_cast<uint64_t>(p) + carry;
            
            prod[i + j] = static_cast<uint64_t>(sum);
            carry = static_cast<uint64_t>(p >> 64) + static_cast<uint64_t>(sum >> 64);
        }
        prod[i + n_words] = carry;
    }
    
    // Montgomery reduction: prod * R^-1 mod n
    mont_reduce(prod.data(), result);
}

/**
 * @brief Convert to Montgomery form: a -> aR mod n
 */
void MontgomeryContext::to_montgomery(
    const uint64_t* a,
    uint64_t* a_mont) const
{
    // aR = MontMul(a, R^2 mod n)
    mont_mul(a, r2.data(), a_mont);
}

/**
 * @brief Convert from Montgomery form: aR -> a
 */
void MontgomeryContext::from_montgomery(
    const uint64_t* a_mont,
    uint64_t* a) const
{
    // a = MontMul(aR, 1) = aR * R^-1 mod n
    std::vector<uint64_t> one(n_words, 0);
    one[0] = 1;
    mont_mul(a_mont, one.data(), a);
}

/**
 * @brief Montgomery modular exponentiation: base^exp mod n
 * 
 * Uses binary exponentiation in Montgomery domain.
 * Critical for RSA encryption/decryption.
 */
void MontgomeryContext::mont_exp(
    const uint64_t* base,
    const uint64_t* exp,
    size_t exp_words,
    uint64_t* result) const
{
    // Convert base to Montgomery form
    std::vector<uint64_t> base_mont(n_words);
    to_montgomery(base, base_mont.data());
    
    // Result starts as R mod n (Montgomery form of 1)
    std::vector<uint64_t> res_mont(n_words);
    std::memcpy(res_mont.data(), r_mod_n.data(), n_words * sizeof(uint64_t));
    
    // Binary exponentiation
    for (int i = static_cast<int>(exp_words) - 1; i >= 0; i--) {
        for (int j = 63; j >= 0; j--) {
            // Square
            mont_mul(res_mont.data(), res_mont.data(), res_mont.data());
            
            // Multiply if bit is set
            if ((exp[i] >> j) & 1) {
                mont_mul(res_mont.data(), base_mont.data(), res_mont.data());
            }
        }
    }
    
    // Convert result back from Montgomery form
    from_montgomery(res_mont.data(), result);
}

/**
 * @brief Batch modular inversion using Montgomery's Trick
 * 
 * Given [a1, a2, ..., an], compute [a1^-1, a2^-1, ..., an^-1] mod p
 * Cost: 1 inversion + 3n multiplications (vs n inversions)
 * 
 * Critical for batch SM2 signing and ECC operations.
 * 
 * Algorithm:
 * 1. c1 = a1, c2 = a1*a2, ..., cn = a1*a2*...*an
 * 2. u = (a1*a2*...*an)^-1 mod p (single expensive inversion)
 * 3. Work backwards:
 *    - an^-1 = u * c_{n-1}
 *    - u := u * an
 *    - a_{n-1}^-1 = u * c_{n-2}
 *    - ...
 */
void batch_mod_inverse_montgomery(
    const std::vector<const uint64_t*>& inputs,
    size_t num_words,
    const MontgomeryContext& ctx,
    std::vector<uint64_t*>& outputs)
{
    size_t n = inputs.size();
    if (n == 0) return;
    
    // Allocate working buffers
    std::vector<std::vector<uint64_t>> partials(n, std::vector<uint64_t>(num_words));
    std::vector<uint64_t> product(num_words);
    
    // Phase 1: Compute partial products
    // partials[i] = a[0] * a[1] * ... * a[i]
    std::memcpy(partials[0].data(), inputs[0], num_words * sizeof(uint64_t));
    for (size_t i = 1; i < n; i++) {
        ctx.mont_mul(partials[i - 1].data(), inputs[i], partials[i].data());
    }
    
    // Phase 2: Invert final product (single expensive operation)
    std::vector<uint64_t> inv_product(num_words);
    // TODO: Implement modular inversion (Extended GCD or Fermat's little theorem)
    // For now, assume ctx has inverse method
    // ctx.mod_inverse(partials[n-1].data(), inv_product.data());
    
    // Phase 3: Work backwards to get individual inverses
    std::vector<uint64_t> u(num_words);
    std::memcpy(u.data(), inv_product.data(), num_words * sizeof(uint64_t));
    
    for (int i = static_cast<int>(n) - 1; i >= 0; i--) {
        if (i == 0) {
            // outputs[0] = u
            std::memcpy(outputs[0], u.data(), num_words * sizeof(uint64_t));
        } else {
            // outputs[i] = u * partials[i-1]
            ctx.mont_mul(u.data(), partials[i - 1].data(), outputs[i]);
            
            // u := u * inputs[i]
            ctx.mont_mul(u.data(), inputs[i], u.data());
        }
    }
}

} // namespace math
} // namespace kctsb
