//
//  decimal.cpp
//  kcalg
//
//  Created by knightc on 2019/4/24.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>
#include <iostream>


#include "kctsb/math/math.h"

using namespace std;

// Convert and display binary representation
void test_convert(const unsigned int v1, const unsigned int d1, const unsigned int d2) {
    for (int i = 16; i >= 0; i--) {
        if (v1 & (1 << i))
            cout << "1";
        else
            cout << "0";
    }
}


