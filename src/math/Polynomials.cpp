//
//  Polynomials.cpp
//  kcalg
//
//  Created by knightc on 2019/7/15.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>
#include <fstream>

#include "kctsb/math/math.h"

#include <kctsb/math/bignum/ZZXFactoring.h>  // Polynomial factorization over integers
#include <kctsb/math/bignum/ZZX.h>           // Univariate polynomial over integers
#include <kctsb/math/bignum/ZZ_pX.h>         // Univariate polynomial over Z/pZ
#include <kctsb/math/bignum/ZZ_pXFactoring.h>
#include <kctsb/math/bignum/GF2X.h>
#include <kctsb/math/bignum/GF2XFactoring.h>
#include <kctsb/math/bignum/GF2EX.h>
#include <kctsb/math/bignum/GF2EXFactoring.h>

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;
using namespace std;


ZZ y_polynomials(const ZZX &f,const ZZ xPoint) {

    ZZ m;
    m= f.rep[0];

    for (long i=1 ; i < f.rep.length(); i++) {
        if (!IsZero(f.rep[i])){
        m+=power(xPoint, i) * f.rep[i];
        }
    }


    return m;
}

// TODO: Reimplement with v5.0 self-contained types
// This function requires NTL-specific types that need v5 reimplementation:
// - Vec< Pair<ZZX,long> >
// - vec_ZZX
// - vec_pair_ZZ_pX_long
// - vec_pair_GF2EX_long
// - CanZass
// - factor(c, factors, f)
// - INIT_SIZE, INIT_MONO

/*
void test_polynomials_main() {
    // ... commented out pending v5 type implementation
}
*/

void test_polynomial_v5() {
    // Simple v5 polynomial test
    ZZX t1;
    SetCoeff(t1, 4, 1);
    t1.rep[2] = ZZ(2);
    SetCoeff(t1, 0, -1);
    
    ZZ x = ZZ::from_decimal("12345678901234567890");
    ZZ result = y_polynomials(t1, x);
    (void)result;  // TODO: Add proper test validation
}





