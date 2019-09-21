//
//  testStruct.h
//  kcalg
//
//  Created by knightc on 2019/7/24.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef testStruct_h
#define testStruct_h
#include <NTL/GF2EX.h>
#include <vector>
#include <string>

using namespace std;
using namespace NTL;

struct kc_test_data {
    
    int array1[3]={1,2,3};
    
    string sout;
    GF2X P;
    //setcoeff需要在 void 里使用，在 struct 里只定义数据成员
    //    SetCoeff(P, 8, 1);
    //    SetCoeff(P, 4, 1);
    //    SetCoeff(P, 3, 1);
    //    SetCoeff(P, 1, 1);
    //    SetCoeff(P, 0, 1);
    
    ZZ p;
    // p= power_ZZ(2, 255)-19;
    
    ZZ vec1[3],vec2[3],vec3[3];//一维数组
    vector<int> vv{1,2};//向量

    //在 struc 里，如果要对成员赋值，必须在声明时赋值,如果未赋值，将被系统自动初始化赋值
    unsigned a1=4;
    unsigned   a2=7;
    unsigned   a3=9;
    unsigned   a4=15;
    vector<vector<unsigned>> array_aa_i{
        {a1,a4,a3,a2},
        {a2,a1,a4,a3},
        {a3,a2,a1,a4},
        {a4,a3,a2,a1}
    };
    vector<vector<int>>   arrayM1_i = {
        {2,3,1,1},
        {1,2,3,1},
        {1,1,2,3},
        {3,1,1,2}
    };
    vector<vector<ZZ>>  arrayM1={
        {ZZ(2),ZZ(3),ZZ(1),ZZ(1)},
        {ZZ(1),ZZ(2),ZZ(3),ZZ(1)},
        {ZZ(1),ZZ(1),ZZ(2),ZZ(3)},
        {ZZ(3),ZZ(1),ZZ(1),ZZ(2)}
    };
    vector<vector<GF2>>    arrayM1_GF2={
        {GF2(2),GF2(3),GF2(1),GF2(1)},
        {GF2(1),GF2(2),GF2(3),GF2(1)},
        {GF2(1),GF2(1),GF2(2),GF2(3)},
        {GF2(3),GF2(1),GF2(1),GF2(2)}
    };
    vector<vector<int>>  arrayM2_i = {
        {14,11,13,9},
        {9,14,11,13},
        {13,9,14,11},
        {11,13,9,14}
    };
    vector<vector<ZZ>>    arrayM2={
        {ZZ(14),ZZ(11),ZZ(13),ZZ(9)},
        {ZZ(9),ZZ(14),ZZ(11),ZZ(13)},
        {ZZ(13),ZZ(9),ZZ(14),ZZ(11)},
        {ZZ(11),ZZ(13),ZZ(9),ZZ(14)}
    };
    vector<vector<GF2>>   arrayM2_GF2={
        {GF2(14),GF2(11),GF2(13),GF2(9)},
        {GF2(9),GF2(14),GF2(11),GF2(13)},
        {GF2(13),GF2(9),GF2(14),GF2(11)},
        {GF2(11),GF2(13),GF2(9),GF2(14)}
    };
    vector<vector<ZZ>>    arrayC={
        {ZZ(2),ZZ(3)},
        {ZZ(1),ZZ(2)}
    };
    
};

struct FinanceData {
    
    unsigned amountZFB = 123459;
    unsigned amountFUND_all;
    unsigned amountFUND_baijiu;
    
    unsigned MonthAdd = 10000 ;
    
    
    
};

static FinanceData datakkk;



#endif /* testStruct_h */
