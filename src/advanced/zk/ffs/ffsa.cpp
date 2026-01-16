/**
 * ffsa.cpp - Feige-Fiat-Shamir Authentication using GMP C API
 * 
 * Uses GMP C API (mpz_t) directly instead of C++ wrapper classes.
 * All mpz_t operations use standard GMP C functions.
 */

#include "kctsb/advanced/zk/ffsa.h"
#include "kctsb/core/security.h"
#include <iostream>
#include <cstdlib>
#include <ctime>

/**
 * Check if GMP number is prime using Miller-Rabin primality test
 * @param p Number to test for primality
 * @return true if prime, false otherwise
 */
bool ffsa_check_prime(const mpz_t p)
{
    int8_t reps = 25;
    int prob = mpz_probab_prime_p(p, reps);

    if(prob == 2)
        return true;
    else if(prob == 0)
        return false;
    else if(prob == 1)
    {
        /* REMARK: Instead of increasing the reps, one may run some deterministic
         * prime verification algorithm like AKS. But since Miller-Rabin is likely
         * to return "probably prime", the speedup may not be achieved through
         * double checking. */
        reps = 50;
        prob = mpz_probab_prime_p(p, reps);
        if(prob == 2)
            return true;
        else if(prob == 0)
            return false;
        else if(prob == 1)
            return true;
    }
    return false;
}

/**
 * Generate random prime couple p,q and derive the modulus n=pq
 * @param result Output: modulus n = p * q where p,q are primes ≡ 3 (mod 4)
 */
void ffsa_get_modulus(mpz_t result)
{
    mpz_t p, q, temp;
    mpz_init(p);
    mpz_init(q);
    mpz_init(temp);

    gmp_randstate_t state;
    gmp_randinit_default(state);

    srand(static_cast<unsigned int>(time(NULL)));
    unsigned long int seed = static_cast<unsigned long int>(rand());
    gmp_randseed_ui(state, seed);

    // Generate p: 1024-bit prime ≡ 3 (mod 4)
    mpz_urandomb(p, state, 1024);
    
    // Ensure p is odd and p ≡ 3 (mod 4)
    mpz_setbit(p, 0); // Make odd
    mpz_mod_ui(temp, p, 4);
    while(mpz_cmp_ui(temp, 3) != 0 || !ffsa_check_prime(p))
    {
        mpz_add_ui(p, p, 2);
        mpz_mod_ui(temp, p, 4);
    }

    // Generate q: 1024-bit prime ≡ 3 (mod 4), q != p
    mpz_urandomb(q, state, 1024);
    mpz_setbit(q, 0); // Make odd
    
    mpz_mod_ui(temp, q, 4);
    while(mpz_cmp_ui(temp, 3) != 0 || !ffsa_check_prime(q) || mpz_cmp(p, q) == 0)
    {
        mpz_add_ui(q, q, 2);
        mpz_mod_ui(temp, q, 4);
    }

    // result = p * q
    mpz_mul(result, p, q);

    // Cleanup
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(temp);
    gmp_randclear(state);
}

/**
 * Get random bool vector of length k
 * @param k Length of boolean vector
 * @return Random boolean vector
 */
bool_vec_t ffsa_get_bool_vector(int8_t k)
{
    bool_vec_t a;
    a.reserve(static_cast<size_t>(k));

    srand(static_cast<unsigned int>(time(NULL)));

    for(int8_t i = 0; i < k; i++)
        a.push_back(static_cast<bool>(rand() % 2));

    return a;
}

/**
 * Get random coprime vector of length k derived from n
 * @param s Output vector of k random numbers coprime to n
 * @param k Length of vector
 * @param n Modulus
 */
void ffsa_get_secrets(mpz_vec_t& s, int8_t k, const mpz_t n)
{
    s.clear();
    s.reserve(static_cast<size_t>(k));

    gmp_randstate_t state;
    gmp_randinit_default(state);

    srand(static_cast<unsigned int>(time(NULL)));
    unsigned long int seed = static_cast<unsigned long int>(rand());
    gmp_randseed_ui(state, seed);

    mpz_t intermediate, n_minus_1, gcd_result;
    mpz_init(intermediate);
    mpz_init(n_minus_1);
    mpz_init(gcd_result);

    mpz_sub_ui(n_minus_1, n, 1);

    for(int8_t i = 0; i < k; i++)
    {
        bool duplicate = false;
        
        do
        {
            duplicate = false;
            
            // Generate random number in range [1, n-1]
            mpz_urandomm(intermediate, state, n_minus_1);
            mpz_add_ui(intermediate, intermediate, 1);
            
            // Check if coprime to n
            mpz_gcd(gcd_result, intermediate, n);
            
            if(mpz_cmp_ui(gcd_result, 1) != 0)
                continue;
            
            // Check for duplicates
            for(int8_t j = 0; j < i; j++)
            {
                if(mpz_cmp(intermediate, *s[j]) == 0)
                {
                    duplicate = true;
                    break;
                }
            }
        } while(duplicate || mpz_cmp_ui(gcd_result, 1) != 0);

        // Store new secret
        mpz_t* new_secret = new mpz_t[1];
        mpz_init(*new_secret);
        mpz_set(*new_secret, intermediate);
        s.push_back(new_secret);
    }

    // Cleanup
    mpz_clear(intermediate);
    mpz_clear(n_minus_1);
    mpz_clear(gcd_result);
    gmp_randclear(state);
}

/**
 * Derive verifier vector from secret vector and modulus
 * @param v Output: verifier vector
 * @param s Input: secret vector
 * @param n Modulus
 */
void ffsa_get_verifiers(mpz_vec_t& v, const mpz_vec_t& s, const mpz_t n)
{
    srand(static_cast<unsigned int>(time(NULL)));

    v.clear();
    v.reserve(s.size());

    mpz_t inter;
    mpz_init(inter);

    for(size_t i = 0; i < s.size(); i++)
    {
        int8_t sig = (rand() % 2) ? -1 : 1;

        // inter = s[i]^2 mod n
        mpz_mul(*s[i], *s[i], inter);
        mpz_mod(inter, inter, n);
        
        // Apply sign
        if(sig == -1)
            mpz_neg(inter, inter);

        // Store verifier
        mpz_t* new_verifier = new mpz_t[1];
        mpz_init(*new_verifier);
        mpz_set(*new_verifier, inter);
        v.push_back(new_verifier);
    }

    mpz_clear(inter);
}

/**
 * Compute verifier constant
 * @param x Output: x = ±r^2 mod n
 * @param r Random commitment
 * @param sig Sign (-1 or +1)
 * @param n Modulus
 */
void ffsa_compute_x(mpz_t x, const mpz_t r, int8_t sig, const mpz_t n)
{
    mpz_t temp;
    mpz_init(temp);
    
    // x = r^2 mod n
    mpz_mul(temp, r, r);
    mpz_mod(x, temp, n);
    
    // Apply sign
    if(sig == -1)
        mpz_neg(x, x);
    
    mpz_clear(temp);
}

/**
 * Compute share number
 * @param y Output: y = r * ∏(s[i] for a[i]=true) mod n
 * @param s Secret vector
 * @param a Boolean selector vector
 * @param r Random commitment
 * @param n Modulus
 */
void ffsa_compute_y(mpz_t y, const mpz_vec_t& s, const bool_vec_t& a, const mpz_t r, const mpz_t n)
{
    if(s.size() != a.size())
    {
        mpz_set_ui(y, 0);
        return;
    }

    mpz_set(y, r);

    for(size_t i = 0; i < s.size(); i++)
    {
        if(a[i])
        {
            mpz_mul(y, y, *s[i]);
        }
    }

    mpz_mod(y, y, n);
}

/**
 * Verify share number and verify-vector
 * @param y Share number
 * @param v Verifier vector
 * @param a Boolean selector vector
 * @param n Modulus
 * @param x Verifier constant
 * @return true if verification passes
 */
bool ffsa_verify_values(const mpz_t y, const mpz_vec_t& v, const bool_vec_t& a, const mpz_t n, const mpz_t x)
{
    if(v.size() != a.size() || mpz_cmp_ui(x, 0) == 0)
        return false;

    mpz_t verifier, check, neg_check, temp;
    mpz_init(verifier);
    mpz_init(check);
    mpz_init(neg_check);
    mpz_init(temp);

    // verifier = y^2 mod n
    mpz_mul(temp, y, y);
    mpz_mod(verifier, temp, n);

    // check = x * ∏(v[i] for a[i]=true) mod n
    mpz_set(check, x);

    for(size_t i = 0; i < v.size(); i++)
    {
        if(a[i])
        {
            mpz_mul(check, check, *v[i]);
        }
    }

    mpz_mod(check, check, n);
    
    // Also check negative
    mpz_neg(neg_check, check);
    mpz_mod(neg_check, neg_check, n);

    bool result = (mpz_cmp(verifier, check) == 0) || (mpz_cmp(verifier, neg_check) == 0);

    mpz_clear(verifier);
    mpz_clear(check);
    mpz_clear(neg_check);
    mpz_clear(temp);

    return result;
}
