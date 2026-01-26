/**
 * @file rsa_keygen.cpp
 * @brief RSA Key Generation Implementation
 * 
 * Implements RSA key generation with Miller-Rabin primality testing.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/crypto/rsa/rsa_keygen.h"
#include <random>
#include <stdexcept>

namespace kctsb {
namespace rsa {
namespace detail {

// ============================================================================
// Miller-Rabin Primality Test
// ============================================================================

template<size_t BITS>
bool is_probable_prime(const BigInt<BITS>& n, int trials) {
    if (n <= BigInt<BITS>(1)) return false;
    if (n == BigInt<BITS>(2)) return true;
    if (!n.is_odd()) return false;
    
    // Write n-1 = 2^r * d
    BigInt<BITS> n_minus_1 = n;
    n_minus_1 -= BigInt<BITS>(1);
    BigInt<BITS> d = n_minus_1;
    size_t r = 0;
    while (!d.is_odd()) {
        d >>= 1;
        r++;
    }
    
    std::random_device rd;
    std::mt19937_64 gen(rd());
    MontgomeryContext<BITS> mont(n);
    
    for (int i = 0; i < trials; i++) {
        // Pick random a in [2, n-2]
        BigInt<BITS> a = random_bigint_mod(gen, n_minus_1);
        if (a < BigInt<BITS>(2)) a = BigInt<BITS>(2);
        
        BigInt<BITS> x = mont.pow_mod(a, d);
        
        if (x == BigInt<BITS>(1) || x == n_minus_1) continue;
        
        bool found = false;
        for (size_t j = 0; j < r - 1; j++) {
            x = mont.pow_mod(x, BigInt<BITS>(2));
            if (x == n_minus_1) {
                found = true;
                break;
            }
        }
        
        if (!found) return false;
    }
    
    return true;
}

// ============================================================================
// Prime Generation
// ============================================================================

template<size_t BITS>
BigInt<BITS> generate_prime(size_t bits) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    while (true) {
        BigInt<BITS> candidate = random_bigint<BITS>(gen);
        
        // Set top two bits (ensures bit length and product length)
        candidate.set_bit(bits - 1, true);
        candidate.set_bit(bits - 2, true);
        
        // Set bottom bit (ensure odd)
        candidate.set_bit(0, true);
        
        // Clear bits above target length
        for (size_t i = bits; i < BITS; i++) {
            candidate.set_bit(i, false);
        }
        
        if (is_probable_prime(candidate)) {
            return candidate;
        }
    }
}

// ============================================================================
// GCD (Binary GCD Algorithm)
// ============================================================================

template<size_t BITS>
BigInt<BITS> gcd(BigInt<BITS> a, BigInt<BITS> b) {
    if (a.is_zero()) return b;
    if (b.is_zero()) return a;
    
    size_t shift = 0;
    while (!a.is_odd() && !b.is_odd()) {
        a >>= 1;
        b >>= 1;
        shift++;
    }
    
    while (!a.is_zero()) {
        while (!a.is_odd()) a >>= 1;
        while (!b.is_odd()) b >>= 1;
        
        if (a >= b) {
            a -= b;
        } else {
            b -= a;
        }
    }
    
    return b << shift;
}

// Explicit instantiations for prime generation (HALF_BITS + 64)
template bool is_probable_prime<1088>(const BigInt<1088>&, int);
template bool is_probable_prime<1600>(const BigInt<1600>&, int);
template bool is_probable_prime<2112>(const BigInt<2112>&, int);

template BigInt<1088> generate_prime<1088>(size_t);
template BigInt<1600> generate_prime<1600>(size_t);
template BigInt<2112> generate_prime<2112>(size_t);

template BigInt<2048> gcd<2048>(BigInt<2048>, BigInt<2048>);
template BigInt<3072> gcd<3072>(BigInt<3072>, BigInt<3072>);
template BigInt<4096> gcd<4096>(BigInt<4096>, BigInt<4096>);

} // namespace detail

// ============================================================================
// RSA Key Generation
// ============================================================================

template<size_t BITS>
RSAKeyPair<BITS> generate_keypair(uint64_t e_val) {
    static_assert(BITS == 2048 || BITS == 3072 || BITS == 4096,
                  "RSA key size must be 2048, 3072, or 4096 bits");
    
    using Int = BigInt<BITS>;
    using HalfInt = BigInt<BITS / 2 + 64>;
    
    RSAKeyPair<BITS> kp;
    RSAPrivateKey<BITS>& priv = kp.private_key;
    
    priv.e = Int(e_val);
    Int e = priv.e;
    
    while (true) {
        // Generate two primes of half the key size
        priv.p = detail::generate_prime<BITS / 2 + 64>(BITS / 2);
        priv.q = detail::generate_prime<BITS / 2 + 64>(BITS / 2);
        
        // Ensure p != q
        if (priv.p == priv.q) continue;
        
        // Ensure p > q
        if (priv.p < priv.q) {
            HalfInt tmp = priv.p;
            priv.p = priv.q;
            priv.q = tmp;
        }
        
        // Compute n = p * q (promote to full width)
        Int p_full, q_full;
        for (size_t i = 0; i < HalfInt::NUM_LIMBS && i < Int::NUM_LIMBS; i++) {
            p_full[i] = priv.p[i];
            q_full[i] = priv.q[i];
        }
        
        // Schoolbook multiplication for n = p * q
        BigInt<BITS * 2> n_wide;
        for (size_t i = 0; i < Int::NUM_LIMBS; i++) {
            limb_t carry = 0;
            for (size_t j = 0; j < Int::NUM_LIMBS; j++) {
                limb_t hi, lo;
                Int::mul64(p_full[i], q_full[j], lo, hi);
                
                limb_t c1, c2;
                c1 = Int::add_with_carry(n_wide[i + j], lo, 0, n_wide[i + j]);
                c2 = Int::add_with_carry(n_wide[i + j], carry, 0, n_wide[i + j]);
                carry = hi + c1 + c2;
            }
            n_wide[i + Int::NUM_LIMBS] += carry;
        }
        
        // Copy lower BITS to n
        for (size_t i = 0; i < Int::NUM_LIMBS; i++) {
            priv.n[i] = n_wide[i];
        }
        
        // Check n has correct bit length
        if (priv.n.num_bits() != BITS) continue;
        
        // Compute phi(n) = (p-1)(q-1)
        HalfInt p_minus_1 = priv.p;
        p_minus_1 -= HalfInt(1);
        HalfInt q_minus_1 = priv.q;
        q_minus_1 -= HalfInt(1);
        
        // Compute phi(n) in full width
        BigInt<BITS * 2> phi_wide;
        for (size_t i = 0; i < HalfInt::NUM_LIMBS; i++) {
            limb_t carry = 0;
            for (size_t j = 0; j < HalfInt::NUM_LIMBS; j++) {
                limb_t hi, lo;
                HalfInt::mul64(p_minus_1[i], q_minus_1[j], lo, hi);
                
                limb_t c1, c2;
                c1 = HalfInt::add_with_carry(phi_wide[i + j], lo, 0, phi_wide[i + j]);
                c2 = HalfInt::add_with_carry(phi_wide[i + j], carry, 0, phi_wide[i + j]);
                carry = hi + c1 + c2;
            }
            phi_wide[i + HalfInt::NUM_LIMBS] += carry;
        }
        
        Int phi;
        for (size_t i = 0; i < Int::NUM_LIMBS; i++) {
            phi[i] = phi_wide[i];
        }
        
        // Check gcd(e, phi) = 1
        Int e_gcd = detail::gcd(e, phi);
        if (e_gcd != Int(1)) continue;
        
        // Compute d = e^(-1) mod phi
        priv.d = mod_inverse(e, phi);
        if (priv.d.is_zero()) continue;
        
        // Compute CRT parameters
        priv.dp = mod_inverse(HalfInt(e_val), p_minus_1);
        priv.dq = mod_inverse(HalfInt(e_val), q_minus_1);
        priv.qinv = mod_inverse(priv.q, priv.p);
        
        break;
    }
    
    kp.public_key = priv.get_public_key();
    return kp;
}

// Explicit instantiations for common key sizes
template RSAKeyPair<2048> generate_keypair<2048>(uint64_t);
template RSAKeyPair<3072> generate_keypair<3072>(uint64_t);
template RSAKeyPair<4096> generate_keypair<4096>(uint64_t);

} // namespace rsa
} // namespace kctsb
