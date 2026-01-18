//
//  kc_latt.cpp
//  kcalg
//
//  Created by knightc on 2019/7/10.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>

#include <kctsb/math/bignum/LLL.h>
#include <kctsb/math/bignum/mat_ZZ.h>
#include <kctsb/math/bignum/ZZ.h>

#include <vector>
#include <iostream>

#include "kctsb/math/math.h"
#include "kctsb/core/security.h"

// Bignum namespace is now kctsb (was bignum)
using namespace kctsb;
using namespace std;


void test_lll_main() {
    ZZ det2;
    
    mat_ZZ X,A,B;
    
    ZZ array[]={
        ZZ(1),ZZ(234),ZZ(345),ZZ(345)
    };
    
    vector<vector<ZZ>> array2,arrayA,arrayB;
    array2={
        {ZZ(232),ZZ(345),ZZ(234)},
        {ZZ(434),ZZ(345),ZZ(234)}
    };
    
    arrayA={
        {ZZ(1),ZZ(345),ZZ(234)},
        {ZZ(4),ZZ(345),ZZ(234)}
    };
    
    arrayB={
        {ZZ(1),ZZ(2),ZZ(3),ZZ(1)},
        {ZZ(4),ZZ(4),ZZ(5),ZZ(1)},
        {ZZ(1),ZZ(2),ZZ(3),ZZ(1)}
    };
    
    
    X.SetDims(2, 3);
    A.SetDims(2, 3);
    B.SetDims(3, 4);
    
      array2_to_mat(arrayA, A);
    LLL(det2, A);
    cout << A << endl;
    
}
