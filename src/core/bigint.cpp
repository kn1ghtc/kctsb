/**
 * @file bigint.cpp
 * @brief Self-contained Big Integer Implementation for kctsb v5.0
 * 
 * Additional utilities and optimizations for the BigInt template class.
 * 
 * @author knightc
 * @version 5.0.0
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include "kctsb/core/bigint.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>

namespace kctsb {

// ============================================================================
// Explicit Template Instantiations
// ============================================================================

// Ensure common sizes are compiled
template class BigInt<256>;
template class BigInt<384>;
template class BigInt<512>;
template class BigInt<1024>;
template class BigInt<2048>;
template class BigInt<4096>;

template class MontgomeryContext<256>;
template class MontgomeryContext<2048>;
template class MontgomeryContext<4096>;

// ============================================================================
// Stream I/O
// ============================================================================

template<size_t BITS>
std::ostream& operator<<(std::ostream& os, const BigInt<BITS>& n) {
    os << "0x" << n.to_hex();
    return os;
}

template<size_t BITS>
std::istream& operator>>(std::istream& is, BigInt<BITS>& n) {
    std::string hex;
    is >> hex;
    n.from_hex(hex);
    return is;
}

// Explicit instantiations for I/O
template std::ostream& operator<<(std::ostream&, const BigInt<256>&);
template std::ostream& operator<<(std::ostream&, const BigInt<2048>&);
template std::ostream& operator<<(std::ostream&, const BigInt<4096>&);

// ============================================================================
// GCD and Prime Testing Utilities
// ============================================================================

/**
 * @brief Binary GCD algorithm
 */
template<size_t BITS>
BigInt<BITS> gcd(BigInt<BITS> a, BigInt<BITS> b) {
    if (a.is_zero()) return b;
    if (b.is_zero()) return a;
    
    // Remove common factors of 2
    size_t shift = 0;
    while (!a.is_odd() && !b.is_odd()) {
        a >>= 1;
        b >>= 1;
        ++shift;
    }
    
    while (!a.is_odd()) a >>= 1;
    
    while (!b.is_zero()) {
        while (!b.is_odd()) b >>= 1;
        
        if (a > b) {
            BigInt<BITS>::cswap(a, b, true);
        }
        b -= a;
    }
    
    return a << shift;
}

// Explicit instantiation
template BigInt<256> gcd(BigInt<256>, BigInt<256>);
template BigInt<2048> gcd(BigInt<2048>, BigInt<2048>);

/**
 * @brief Miller-Rabin primality test
 * @param n Number to test
 * @param rounds Number of rounds (40 gives ~2^-80 error probability)
 * @return true if probably prime
 */
template<size_t BITS>
bool is_prime_miller_rabin(const BigInt<BITS>& n, int rounds = 40) {
    using Int = BigInt<BITS>;
    
    // Handle small cases
    if (n < Int(2)) return false;
    if (n == Int(2) || n == Int(3)) return true;
    if (!n.is_odd()) return false;
    
    // Write n-1 = 2^r * d
    Int n_minus_1 = n - Int(1);
    Int d = n_minus_1;
    size_t r = 0;
    
    while (!d.is_odd()) {
        d >>= 1;
        ++r;
    }
    
    // Create Montgomery context for modular exponentiation
    MontgomeryContext<BITS> mont(n);
    
    // Witness tests
    std::mt19937_64 rng(std::random_device{}());
    
    for (int i = 0; i < rounds; ++i) {
        // Pick random a in [2, n-2]
        Int a = random_bigint_mod(rng, n_minus_1 - Int(1));
        if (a < Int(2)) a = Int(2);
        
        // Compute x = a^d mod n
        Int x = mont.pow_mod(a, d);
        
        if (x == Int(1) || x == n_minus_1) continue;
        
        bool composite = true;
        for (size_t j = 0; j < r - 1; ++j) {
            x = mont.mul_montgomery(mont.to_montgomery(x), mont.to_montgomery(x));
            x = mont.from_montgomery(x);
            
            if (x == n_minus_1) {
                composite = false;
                break;
            }
        }
        
        if (composite) return false;
    }
    
    return true;
}

// Explicit instantiation
template bool is_prime_miller_rabin(const BigInt<256>&, int);
template bool is_prime_miller_rabin(const BigInt<2048>&, int);
template bool is_prime_miller_rabin(const BigInt<4096>&, int);

/**
 * @brief Generate random prime of specified bit length
 */
template<size_t BITS>
BigInt<BITS> generate_prime(size_t bit_length, int miller_rabin_rounds = 40) {
    using Int = BigInt<BITS>;
    
    if (bit_length > BITS) {
        throw std::invalid_argument("bit_length exceeds BigInt capacity");
    }
    
    std::mt19937_64 rng(std::random_device{}());
    Int candidate;
    
    while (true) {
        // Generate random odd number with correct bit length
        candidate = random_bigint<BITS>(rng);
        
        // Set top bit to ensure correct length
        candidate.set_bit(bit_length - 1, true);
        
        // Set bottom bit to ensure odd
        candidate.set_bit(0, true);
        
        // Clear bits above bit_length
        for (size_t i = bit_length; i < BITS; ++i) {
            candidate.set_bit(i, false);
        }
        
        // Trial division by small primes
        static const uint64_t small_primes[] = {
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
            59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113
        };
        
        bool divisible = false;
        for (uint64_t p : small_primes) {
            // Simple modulo check for small primes
            uint64_t rem = 0;
            for (size_t i = Int::NUM_LIMBS; i > 0; --i) {
                uint128_t tmp = (static_cast<uint128_t>(rem) << 64) | candidate[i-1];
                rem = tmp % p;
            }
            if (rem == 0) {
                divisible = true;
                break;
            }
        }
        
        if (divisible) continue;
        
        // Miller-Rabin test
        if (is_prime_miller_rabin(candidate, miller_rabin_rounds)) {
            return candidate;
        }
    }
}

// Explicit instantiation
template BigInt<2048> generate_prime(size_t, int);
template BigInt<4096> generate_prime(size_t, int);

} // namespace kctsb
