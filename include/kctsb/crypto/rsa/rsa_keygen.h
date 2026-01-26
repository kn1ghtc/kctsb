/**
 * @file rsa_keygen.h
 * @brief RSA Key Generation Module
 * 
 * Implements RSA key pair generation with:
 * - Prime generation (Miller-Rabin primality testing)
 * - CRT parameter computation
 * - Support for 2048/3072/4096-bit keys
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CRYPTO_RSA_KEYGEN_H
#define KCTSB_CRYPTO_RSA_KEYGEN_H

#include "kctsb/crypto/rsa/rsa_types.h"
#include "kctsb/core/bigint.h"
#include <cstdint>

namespace kctsb {
namespace rsa {

// ============================================================================
// Prime Generation Utilities
// ============================================================================

namespace detail {

/**
 * @brief Miller-Rabin primality test
 * @tparam BITS Bit width of candidate
 * @param n Candidate prime
 * @param trials Number of Miller-Rabin rounds (default: 20)
 * @return true if n is probably prime
 */
template<size_t BITS>
bool is_probable_prime(const BigInt<BITS>& n, int trials = 20);

/**
 * @brief Generate random prime of specified bit length
 * @tparam BITS Maximum bit width
 * @param bits Target bit length of prime
 * @return Random prime with exactly 'bits' bits
 */
template<size_t BITS>
BigInt<BITS> generate_prime(size_t bits);

/**
 * @brief Compute GCD using binary GCD algorithm
 * @tparam BITS Bit width
 * @param a First integer
 * @param b Second integer
 * @return Greatest common divisor of a and b
 */
template<size_t BITS>
BigInt<BITS> gcd(BigInt<BITS> a, BigInt<BITS> b);

} // namespace detail

// ============================================================================
// RSA Key Generation
// ============================================================================

/**
 * @brief Generate new RSA key pair
 * @tparam BITS Key size in bits (2048, 3072, or 4096)
 * @param e_val Public exponent (default: 65537 = 0x10001)
 * @return Generated key pair with public and private keys
 * 
 * @details
 * Key generation process:
 * 1. Generate two random primes p and q of BITS/2 bits each
 * 2. Compute n = p * q
 * 3. Compute φ(n) = (p-1)(q-1)
 * 4. Verify gcd(e, φ(n)) = 1
 * 5. Compute d = e^(-1) mod φ(n)
 * 6. Compute CRT parameters: dp, dq, qinv
 * 
 * @warning This function uses system randomness - ensure RNG is seeded
 */
template<size_t BITS = 2048>
RSAKeyPair<BITS> generate_keypair(uint64_t e_val = 65537);

// ============================================================================
// Explicit Template Instantiations (declared here, defined in .cpp)
// ============================================================================

extern template bool detail::is_probable_prime<1088>(const BigInt<1088>&, int);
extern template bool detail::is_probable_prime<1600>(const BigInt<1600>&, int);
extern template bool detail::is_probable_prime<2112>(const BigInt<2112>&, int);

extern template BigInt<1088> detail::generate_prime<1088>(size_t);
extern template BigInt<1600> detail::generate_prime<1600>(size_t);
extern template BigInt<2112> detail::generate_prime<2112>(size_t);

extern template BigInt<2048> detail::gcd<2048>(BigInt<2048>, BigInt<2048>);
extern template BigInt<3072> detail::gcd<3072>(BigInt<3072>, BigInt<3072>);
extern template BigInt<4096> detail::gcd<4096>(BigInt<4096>, BigInt<4096>);

extern template RSAKeyPair<2048> generate_keypair<2048>(uint64_t);
extern template RSAKeyPair<3072> generate_keypair<3072>(uint64_t);
extern template RSAKeyPair<4096> generate_keypair<4096>(uint64_t);

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * @brief Generate 2048-bit RSA key pair
 */
inline RSAKeyPair<2048> rsa2048_generate_keypair() {
    return generate_keypair<2048>();
}

/**
 * @brief Generate 3072-bit RSA key pair
 */
inline RSAKeyPair<3072> rsa3072_generate_keypair() {
    return generate_keypair<3072>();
}

/**
 * @brief Generate 4096-bit RSA key pair
 */
inline RSAKeyPair<4096> rsa4096_generate_keypair() {
    return generate_keypair<4096>();
}

} // namespace rsa
} // namespace kctsb

#endif // KCTSB_CRYPTO_RSA_KEYGEN_H
