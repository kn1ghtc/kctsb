/**
 * @file modular_ops.hpp
 * @brief High-performance modular arithmetic operations
 * 
 * Implements SEAL-style optimized modular arithmetic:
 * - MultiplyUIntModOperand for precomputed Barrett quotients
 * - Lazy reduction to reduce modulo operations
 * - AVX2 vectorized operations where applicable
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 * @version v4.9.1
 * @since Phase 4b optimization
 */

#ifndef KCTSB_ADVANCED_FE_COMMON_MODULAR_OPS_HPP
#define KCTSB_ADVANCED_FE_COMMON_MODULAR_OPS_HPP

#include <cstdint>
#include <stdexcept>
#include <array>

#ifdef __AVX2__
#include <immintrin.h>
#endif

namespace kctsb {
namespace fhe {

// ============================================================================
// Modulus Class (SEAL-compatible)
// ============================================================================

/**
 * @brief Modulus with precomputed Barrett reduction constants
 * 
 * Stores a prime modulus and precomputes constants for fast Barrett reduction.
 * Compatible with SEAL's Modulus class interface.
 */
class Modulus {
public:
    Modulus() : value_(0), const_ratio_{0, 0, 0} {}
    
    explicit Modulus(uint64_t value) : value_(value) {
        if (value == 0) {
            throw std::invalid_argument("Modulus cannot be zero");
        }
        if (value >> 61) {
            throw std::invalid_argument("Modulus must be at most 61 bits");
        }
        compute_const_ratio();
    }
    
    /**
     * @brief Get modulus value
     */
    inline uint64_t value() const noexcept { return value_; }
    
    /**
     * @brief Get Barrett reduction constant ratio
     * 
     * const_ratio[0..2] = floor(2^128 / value) as 3x64-bit words
     */
    inline const std::array<uint64_t, 3>& const_ratio() const noexcept {
        return const_ratio_;
    }
    
    /**
     * @brief Check if modulus is zero
     */
    inline bool is_zero() const noexcept { return value_ == 0; }
    
    /**
     * @brief Comparison operators
     */
    inline bool operator==(const Modulus& other) const noexcept {
        return value_ == other.value_;
    }
    inline bool operator!=(const Modulus& other) const noexcept {
        return value_ != other.value_;
    }
    
private:
    void compute_const_ratio() {
        // Compute floor(2^128 / value) as 3x64-bit words
        // This is used for Barrett reduction
        
        // We need to compute 2^128 / value
        // Using 128-bit arithmetic: result = (2^128 - 1) / value + adjustment
        
        __uint128_t numerator_high = static_cast<__uint128_t>(1) << 64;
        
        // Divide (1 << 128) by value
        // First divide high part
        __uint128_t quotient_high = numerator_high / value_;
        __uint128_t remainder = numerator_high % value_;
        
        // Then divide (remainder << 64) by value
        __uint128_t numerator_low = remainder << 64;
        __uint128_t quotient_low = numerator_low / value_;
        
        const_ratio_[0] = 0;  // Lowest 64 bits (usually 0 for our purposes)
        const_ratio_[1] = static_cast<uint64_t>(quotient_low);
        const_ratio_[2] = static_cast<uint64_t>(quotient_high);
    }
    
    uint64_t value_;
    std::array<uint64_t, 3> const_ratio_;
};

// ============================================================================
// MultiplyUIntModOperand (SEAL-compatible)
// ============================================================================

/**
 * @brief Precomputed operand for fast modular multiplication
 * 
 * Stores both the operand and its precomputed quotient for
 * fast Barrett reduction. Used for twiddle factors in NTT.
 * 
 * The quotient is: floor((operand << 64) / modulus)
 * This allows computing (x * operand) mod modulus with minimal operations.
 */
struct MultiplyUIntModOperand {
    uint64_t operand;   ///< The actual operand value (< modulus)
    uint64_t quotient;  ///< Precomputed: floor((operand << 64) / modulus)
    
    MultiplyUIntModOperand() : operand(0), quotient(0) {}
    
    /**
     * @brief Set operand and compute quotient
     * @param new_operand Must be less than modulus
     * @param modulus The modulus for reduction
     */
    void set(uint64_t new_operand, const Modulus& modulus) {
        operand = new_operand;
        set_quotient(modulus);
    }
    
    /**
     * @brief Compute quotient for current operand
     */
    void set_quotient(const Modulus& modulus) {
        // quotient = floor((operand << 64) / modulus.value())
        __uint128_t wide = static_cast<__uint128_t>(operand) << 64;
        quotient = static_cast<uint64_t>(wide / modulus.value());
    }
};

// ============================================================================
// Fast Modular Arithmetic Functions
// ============================================================================

/**
 * @brief Add two values modulo modulus
 * @param operand1 First operand (must be < modulus)
 * @param operand2 Second operand (must be < modulus)
 * @param modulus The modulus
 * @return (operand1 + operand2) mod modulus
 */
inline uint64_t add_uint_mod(uint64_t operand1, uint64_t operand2, 
                              const Modulus& modulus) noexcept {
    uint64_t sum = operand1 + operand2;
    // Branchless: subtract modulus if sum >= modulus
    return sum >= modulus.value() ? sum - modulus.value() : sum;
}

/**
 * @brief Subtract two values modulo modulus
 * @param operand1 First operand (must be < modulus)
 * @param operand2 Second operand (must be < modulus)
 * @param modulus The modulus
 * @return (operand1 - operand2) mod modulus
 */
inline uint64_t sub_uint_mod(uint64_t operand1, uint64_t operand2,
                              const Modulus& modulus) noexcept {
    // Branchless: add modulus if operand1 < operand2
    int64_t borrow = static_cast<int64_t>(operand1 < operand2);
    return operand1 - operand2 + (modulus.value() & static_cast<uint64_t>(-borrow));
}

/**
 * @brief Negate a value modulo modulus
 * @param operand The operand (must be < modulus)
 * @param modulus The modulus
 * @return (-operand) mod modulus
 */
inline uint64_t negate_uint_mod(uint64_t operand, const Modulus& modulus) noexcept {
    int64_t non_zero = static_cast<int64_t>(operand != 0);
    return (modulus.value() - operand) & static_cast<uint64_t>(-non_zero);
}

/**
 * @brief Barrett reduction of 128-bit value
 * @param input Pointer to 128-bit value (2 x uint64_t, little-endian)
 * @param modulus The modulus (must be at most 63 bits)
 * @return input mod modulus
 */
inline uint64_t barrett_reduce_128(const uint64_t* input, 
                                    const Modulus& modulus) noexcept {
    // Barrett reduction for 128-bit input
    // Uses precomputed const_ratio from modulus
    
    const uint64_t* const_ratio = modulus.const_ratio().data();
    uint64_t q = modulus.value();
    
    // Multiply input by const_ratio and take high part
    __uint128_t tmp1 = static_cast<__uint128_t>(input[0]) * const_ratio[1];
    __uint128_t tmp2 = static_cast<__uint128_t>(input[0]) * const_ratio[2];
    __uint128_t tmp3 = static_cast<__uint128_t>(input[1]) * const_ratio[1];
    
    // Combine high parts
    uint64_t carry = static_cast<uint64_t>(tmp1 >> 64);
    __uint128_t tmp = tmp2 + tmp3 + carry;
    uint64_t quotient_approx = static_cast<uint64_t>(tmp >> 64) + 
                               static_cast<uint64_t>(input[1] * const_ratio[2]);
    
    // Barrett subtraction
    uint64_t result = input[0] - quotient_approx * q;
    
    // One correction is usually enough for 63-bit modulus
    return result >= q ? result - q : result;
}

/**
 * @brief Standard modular multiplication using Barrett reduction
 * @param operand1 First operand
 * @param operand2 Second operand
 * @param modulus The modulus
 * @return (operand1 * operand2) mod modulus
 */
inline uint64_t multiply_uint_mod(uint64_t operand1, uint64_t operand2,
                                   const Modulus& modulus) noexcept {
    __uint128_t product = static_cast<__uint128_t>(operand1) * operand2;
    uint64_t z[2] = {
        static_cast<uint64_t>(product),
        static_cast<uint64_t>(product >> 64)
    };
    return barrett_reduce_128(z, modulus);
}

/**
 * @brief Fast modular multiplication with precomputed quotient (SEAL-style)
 * 
 * This is the key optimization for NTT twiddle factor multiplication.
 * Uses precomputed quotient to avoid full Barrett reduction.
 * 
 * @param x First operand (any value)
 * @param y Precomputed operand (operand < modulus)
 * @param modulus The modulus
 * @return (x * y.operand) mod modulus
 */
inline uint64_t multiply_uint_mod(uint64_t x, const MultiplyUIntModOperand& y,
                                   const Modulus& modulus) noexcept {
    // q_approx = floor(x * y.quotient / 2^64)
    uint64_t q_approx = static_cast<uint64_t>(
        (static_cast<__uint128_t>(x) * y.quotient) >> 64
    );
    
    // result = x * y.operand - q_approx * modulus
    uint64_t result = x * y.operand - q_approx * modulus.value();
    
    // One correction (result may be >= modulus)
    return result >= modulus.value() ? result - modulus.value() : result;
}

/**
 * @brief Lazy modular multiplication (result in [0, 2*modulus))
 * 
 * Skips the final correction, allowing result to be slightly larger than modulus.
 * Used in NTT butterfly operations where we can delay reduction.
 * 
 * @param x First operand
 * @param y Precomputed operand
 * @param modulus The modulus
 * @return (x * y.operand) mod modulus, may be in [0, 2*modulus)
 */
inline uint64_t multiply_uint_mod_lazy(uint64_t x, const MultiplyUIntModOperand& y,
                                        const Modulus& modulus) noexcept {
    uint64_t q_approx = static_cast<uint64_t>(
        (static_cast<__uint128_t>(x) * y.quotient) >> 64
    );
    return x * y.operand - q_approx * modulus.value();
}

/**
 * @brief Guard value to ensure it's in [0, 2*modulus)
 * 
 * Used after lazy operations to ensure value doesn't overflow in subsequent ops.
 * 
 * @param value The value to guard
 * @param two_times_modulus 2 * modulus
 * @return value mod (2 * modulus)
 */
inline uint64_t guard(uint64_t value, uint64_t two_times_modulus) noexcept {
    return value >= two_times_modulus ? value - two_times_modulus : value;
}

// ============================================================================
// Modular Exponentiation
// ============================================================================

/**
 * @brief Compute base^exp mod modulus using binary exponentiation
 */
inline uint64_t pow_mod(uint64_t base, uint64_t exp, const Modulus& modulus) {
    if (modulus.value() == 1) return 0;
    
    uint64_t result = 1;
    base = base % modulus.value();
    
    while (exp > 0) {
        if (exp & 1) {
            result = multiply_uint_mod(result, base, modulus);
        }
        exp >>= 1;
        base = multiply_uint_mod(base, base, modulus);
    }
    
    return result;
}

/**
 * @brief Compute modular inverse using extended Euclidean algorithm
 */
inline uint64_t inv_mod(uint64_t a, const Modulus& modulus) {
    if (a == 0) {
        throw std::invalid_argument("Cannot compute inverse of zero");
    }
    
    uint64_t q = modulus.value();
    int64_t t = 0, new_t = 1;
    uint64_t r = q, new_r = a;
    
    while (new_r != 0) {
        uint64_t quotient = r / new_r;
        
        int64_t tmp_t = t - static_cast<int64_t>(quotient) * new_t;
        t = new_t;
        new_t = tmp_t;
        
        uint64_t tmp_r = r - quotient * new_r;
        r = new_r;
        new_r = tmp_r;
    }
    
    if (r != 1) {
        throw std::invalid_argument("Modular inverse does not exist");
    }
    
    return t < 0 ? static_cast<uint64_t>(t + static_cast<int64_t>(q)) 
                 : static_cast<uint64_t>(t);
}

// ============================================================================
// AVX2 Vectorized Operations (optional)
// ============================================================================

#ifdef __AVX2__

/**
 * @brief AVX2 vectorized modular addition (4 x uint64)
 * @param a First operands (4 values)
 * @param b Second operands (4 values)
 * @param modulus Broadcast modulus value
 * @return (a + b) mod modulus for each lane
 */
inline __m256i add_uint_mod_avx2(__m256i a, __m256i b, __m256i modulus) {
    // sum = a + b
    __m256i sum = _mm256_add_epi64(a, b);
    
    // Create mask: if sum >= modulus, mask = 0xFFFFFFFFFFFFFFFF
    // Note: AVX2 doesn't have unsigned 64-bit comparison, use subtraction trick
    __m256i diff = _mm256_sub_epi64(sum, modulus);
    
    // If diff >= 0 (i.e., sum >= modulus), sign bit is 0
    // We want to select diff if sum >= modulus, else sum
    // Use arithmetic right shift to broadcast sign bit
    __m256i mask = _mm256_cmpgt_epi64(modulus, sum);  // mask = modulus > sum ? -1 : 0
    
    // result = mask ? sum : diff
    return _mm256_blendv_epi8(diff, sum, mask);
}

/**
 * @brief AVX2 vectorized modular subtraction (4 x uint64)
 */
inline __m256i sub_uint_mod_avx2(__m256i a, __m256i b, __m256i modulus) {
    // diff = a - b
    __m256i diff = _mm256_sub_epi64(a, b);
    
    // If a < b, we need to add modulus
    __m256i mask = _mm256_cmpgt_epi64(b, a);  // mask = b > a ? -1 : 0
    __m256i correction = _mm256_and_si256(modulus, mask);
    
    return _mm256_add_epi64(diff, correction);
}

#endif // __AVX2__

} // namespace fhe
} // namespace kctsb

#endif // KCTSB_ADVANCED_FE_COMMON_MODULAR_OPS_HPP
