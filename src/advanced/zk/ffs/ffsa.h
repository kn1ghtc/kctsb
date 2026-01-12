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
 *------------------------------------------------------------------------------
 */

/*include header for system functions*/
#include <vector>
#include <gmpxx.h>
#include <gmp.h>
#include <stdint.h>


/*typedefs for convenience with vectors*/
typedef std::vector<mpz_class> mpz_vec_t;
typedef std::vector<bool> bool_vec_t;

/*function prototypes for distribution*/
mpz_class ffsa_get_modulus(void);
bool_vec_t ffsa_get_bool_vector(int8_t k);
mpz_vec_t ffsa_get_secrets(int8_t k, mpz_class n);
mpz_vec_t ffsa_get_verifiers(mpz_vec_t s, mpz_class n);
mpz_class ffsa_compute_x(mpz_class r, int8_t s, mpz_class n);
mpz_class ffsa_compute_y(mpz_vec_t s, bool_vec_t a, mpz_class r, mpz_class n);
bool ffsa_verify_values(mpz_class y, mpz_vec_t v, bool_vec_t a, mpz_class n, mpz_class x);
bool ffsa_check_prime(mpz_class p);




#endif /* ffsa_h */
