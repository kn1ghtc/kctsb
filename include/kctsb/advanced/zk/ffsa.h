//
//  ffsa.h
//  kcalg
//
//  Created by knightc on 2019/7/17.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef ffsa_h
#define ffsa_h

/*------------------------------------------------------------------------------
 * ffsa.h -- main header file containing the function prototypes, typedefs, etc.
 * 
 * Note: Uses GMP C API (mpz_t) directly.
 * GMP provides its own C++ compatibility, no extern "C" wrapper needed.
 *------------------------------------------------------------------------------
 */

// TODO: Reimplement ffsa using kctsb::ZZ instead of GMP
#ifdef KCTSB_USE_GMP  // Only compile when GMP is explicitly enabled

#include <vector>
#include <stdint.h>
#include <gmp.h>

/*typedefs for convenience with vectors*/
typedef std::vector<mpz_t*> mpz_vec_t;
typedef std::vector<bool> bool_vec_t;

/*function prototypes for distribution*/
void ffsa_get_modulus(mpz_t result);
bool_vec_t ffsa_get_bool_vector(int8_t k);
void ffsa_get_secrets(mpz_vec_t& s, int8_t k, const mpz_t n);
void ffsa_get_verifiers(mpz_vec_t& v, const mpz_vec_t& s, const mpz_t n);
void ffsa_compute_x(mpz_t x, const mpz_t r, int8_t sig, const mpz_t n);
void ffsa_compute_y(mpz_t y, const mpz_vec_t& s, const bool_vec_t& a, const mpz_t r, const mpz_t n);
bool ffsa_verify_values(const mpz_t y, const mpz_vec_t& v, const bool_vec_t& a, const mpz_t n, const mpz_t x);
bool ffsa_check_prime(const mpz_t p);

#endif  // KCTSB_USE_GMP



#endif /* ffsa_h */
