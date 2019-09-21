//
//  test_struct.cpp
//  kcalg
//
//  Created by knightc on 2019/7/23.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>

#include "opentsb/cplus.h"
#include "testStruct.h"


void test_struct () {
    
    kc_test_data data1,data2;
    
    if (data1.a1==data2.a1) {
        data2.sout= "test success \n";
    } ;
    
    cout << data2.sout;
}


