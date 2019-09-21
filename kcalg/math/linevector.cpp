//
//  linevector.cpp
//  kcalg
//
//  Created by knightc on 2019/4/25.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>
#include "opentsb/math.h"
#include "opentsb/kc_common.h"

#include <vector>
#include <NTL/GF2X.h>

using namespace NTL;
using namespace std;


//(a^e) mod n;
ZZ test_PowerMod(const ZZ& a, const ZZ& e, const ZZ& n) {
    if (e == 0) return ZZ(1);
    
    long k = NumBits(e);
    
    ZZ res;
    res = 1;
    
    //if e=7(0111),the first bit is 1,second 1,third 1,fourth 0;low-to-high
    for (long i = k-1; i >= 0; i--) {
        res = (res*res) % n;//res = SqrMod(res, n);SqrMod（res,res,n)
        if (bit(e, i) == 1) res = (res*a) % n;//res = MulMod(res, a, n);MulMod(res, res, a, n)
    }
    
    if (e < 0)
        return InvMod(res, n);//inv
    else
        return res;
}

//big intergers:zz
//test-zz
ZZ test_zz_and(ZZ a,ZZ b){
    ZZ k;
    lcm(k,a,b);
    return (a+1)*(b+1);
    // return k;
}

//测试主函数
void test_vec_mat_main() {
    mat_ZZ X,A,B,C,M1,M2,M;
    vec_ZZ v,v1,v2,v3,mul_v;
    mat_GF2 X_GF2,M_GF2,M1_GF2,M2_GF2;
    mat_GF2E X_GF2E,M_GF2E,M1_GF2E,M2_GF2E;
    mat_ZZ_p M_zz_p,M1_zz_p,M2_zz_p;
    
    ZZ a,b,c;
    GF2 a_gf2,b_gf2,c_gf2;
    GF2E  a_gf2e,b_gf2e,c_gf2e;
    
    
    a=10;
   //const GF2X P(INIT_MONO,8);
    //aes的 gf（2^8）的不可约多项式为：x^8 + x^4 + x^3 + x + 1
    GF2X P;
      SetCoeff(P, 8, 1);
      SetCoeff(P, 4, 1);
      SetCoeff(P, 3, 1);
      SetCoeff(P, 1, 1);
      SetCoeff(P, 0, 1);
    GF2E::init(P);
    GF2X P1;
    
    GF2EPush push(P);//定义 push 变量，后续可以快速更换模 p，而不用再次初始化
    ZZ p;
    p= power_ZZ(2, 255)-19;
    ZZ_p::init(p);
    
   // cout<< P.xrep.length()<<endl;
   // cout<<P.HexOutput<<endl;
   // GF2EContext context(P);
    
    //a_gf2e= random_GF2E();
   // random(a_gf2e);
    
   // cout<< a_gf2e.modulus()<<endl;

    
    // vector<int> = {1,2,3};
    ZZ vec1[]={ZZ(1),ZZ(2),ZZ(3),ZZ(4),ZZ(4)};
    //cout << getArrayLen(vec1)<< endl;
    ZZ vec2[]={ZZ(1),ZZ(2),ZZ(3),ZZ(4)};
    ZZ vec3[]={ZZ(1),ZZ(2),ZZ(3)};
    ZZ vec[]={ZZ(1),ZZ(234),ZZ(345),ZZ(345)};
    
    vector<vector<ZZ>> array2,arrayA,arrayB,arrayC,arrayM1,arrayM2;
    vector<vector<GF2>> array2_GF2,arrayA_GF2,arrayB_GF2,arrayC_GF2,arrayM1_GF2,arrayM2_GF2;
    vector<vector<int>> arrayM1_i,arrayM2_i, array_aa_i;
    
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
    
    //aes-M
    //快速定义可逆矩阵4*4：定义第一列 4 个数，此后每一列重复这 4 个数（顺序波动即可），此类矩阵基本在有限域内有可逆矩阵
    //每行每列都是 a1a2a3a4的不同顺序组合
    //如果成立，aea 的 m 盒在 gf2 内，破解自定义 m 需要 pow（2，2*4）次，在gf256 内，需要 pow（2，8*4）次
    /*
     【  a1  a4  a3  a2
        a2   a1  a4  a3
        a3   a2  a1  a4
        a4   a3  a2  a1 】
     */
    int a1,a2,a3,a4;
    a1=4;
    a2=7;
    a3=9;
    a4=15;
    array_aa_i = {
        {a1,a4,a3,a2},
        {a2,a1,a4,a3},
        {a3,a2,a1,a4},
        {a4,a3,a2,a1}
    };
    arrayM1_i = {
        {2,3,1,1},
        {1,2,3,1},
        {1,1,2,3},
        {3,1,1,2}
    };
    arrayM1={
        {ZZ(2),ZZ(3),ZZ(1),ZZ(1)},
        {ZZ(1),ZZ(2),ZZ(3),ZZ(1)},
        {ZZ(1),ZZ(1),ZZ(2),ZZ(3)},
        {ZZ(3),ZZ(1),ZZ(1),ZZ(2)}
    };
    arrayM1_GF2={
        {GF2(2),GF2(3),GF2(1),GF2(1)},
        {GF2(1),GF2(2),GF2(3),GF2(1)},
        {GF2(1),GF2(1),GF2(2),GF2(3)},
        {GF2(3),GF2(1),GF2(1),GF2(2)}
    };
    arrayM2_i = {
        {14,11,13,9},
        {9,14,11,13},
        {13,9,14,11},
        {11,13,9,14}
    };
    arrayM2={
        {ZZ(14),ZZ(11),ZZ(13),ZZ(9)},
        {ZZ(9),ZZ(14),ZZ(11),ZZ(13)},
        {ZZ(13),ZZ(9),ZZ(14),ZZ(11)},
        {ZZ(11),ZZ(13),ZZ(9),ZZ(14)}
    };
    arrayM2_GF2={
        {GF2(14),GF2(11),GF2(13),GF2(9)},
        {GF2(9),GF2(14),GF2(11),GF2(13)},
        {GF2(13),GF2(9),GF2(14),GF2(11)},
        {GF2(11),GF2(13),GF2(9),GF2(14)}
    };
    arrayC={
        {ZZ(2),ZZ(3)},
        {ZZ(1),ZZ(2)}
    };
    
//    v1.SetLength(4);
//    v2.SetLength(4);
//    v3.SetLength(3);
    v.SetLength(4);
    mul_v.SetLength(3);
    array_to_vec(vec1, v1,getArrayLen(vec1));
    array_to_vec(vec2, v2,getArrayLen(vec2));
    array_to_vec(vec3, v3,getArrayLen(vec3));
    cout << lcm_gcd_vec(v1,1,3) << endl;
//    //向量运算
//    //向量加法：同长度
//    add(v,v1,v2);
//    cout <<v <<endl;
//    //向量减法：同长度
//    v= v1 - v2;
//    cout << v << endl;
//    //只能计算数乘，外积更复杂
//    v= a * v1;
//    cout << v << endl;
    //计算内积，得到是对应值类型的数;内积的双方长度要相同
    InnerProduct( b, v1, v2);
  //  cout << b << endl;
    
    X.SetDims(4, 4);
    M.SetDims(4, 4);
    M1.SetDims(4, 4);
    M2.SetDims(4, 4);
    A.SetDims(2, 3);
    B.SetDims(3, 4);
    C.SetDims(2, 2);
    M_GF2.SetDims(4, 4);
    X_GF2.SetDims(4, 4);
    M1_GF2.SetDims(4, 4);
    M2_GF2.SetDims(4, 4);
    M1_GF2E.SetDims(4, 4);
    M2_GF2E.SetDims(4, 4);
    X_GF2E.SetDims(4, 4);
      M_GF2E.SetDims(4, 4);
   // M1_zz_p.SetDims(4, 4);//可以在转换函数内部实现动态大小定义
    // array2_to_mat(array2, X);
    array2_to_mat(arrayA, A);
    array2_to_mat(arrayB, B);
    array2_to_mat(arrayC, C);
    array2_to_mat(arrayM1, M1);
    array2_to_mat(arrayM2, M2);
    array2_to_mat(arrayM1_GF2, M1_GF2);
    array2_to_mat(arrayM2_GF2, M2_GF2);
    array2_to_mat(array_aa_i, X_GF2);
    array2_to_mat(array_aa_i, X_GF2E);
    array2_to_mat(arrayM1_i, M1_GF2E);
    array2_to_mat(arrayM2_i, M2_GF2E);
    array2_to_mat(arrayM1_i, M1_zz_p);
    //矩阵运算
   // X = A * B;//矩阵乘积,矩阵m*p才能与矩阵 p*n相乘，得到 m*n 的矩阵
//    mul(X,A,B);
//    cout<<X << endl;
    //矩阵与向量乘法；矩阵的任何乘法几乎都不满足交换率;向量与矩阵无论怎么乘，得到的结果是向量
    //矩阵*向量：向量的长度要与矩阵的列数相等---【m，n】* 【n】 =【m】
//    mul_v = A * v3;
//    cout << mul_v << endl;
    //向量*矩阵：向量的长度要与矩阵的行数相等---【m】*【m，n】=【n】
//    mul_v = v3 * B;
//    cout << mul_v << endl;
    //矩阵加法；只有行列相等的矩阵才能相加
//    add(X,A,A);
//    cout<< X << endl;
    //矩阵逆：可逆矩阵是针对方阵的
    //初等变化求逆等等
//    inv(X, C);
//    cout<< X << endl;
//    M= M1 * M2;
//    cout<< M << endl;
//    M_GF2 = M2_GF2 * M1_GF2;
//    cout << M_GF2 << endl;
  
   // cout << inv(X_GF2) << endl;
    M_GF2E= M1_GF2E * M2_GF2E;
 //  cout<< M_GF2E <<endl;
 // cout<< M1_GF2E<< endl;
//    cout << X_GF2E <<endl;
//     cout << inv(X_GF2E) << endl;
//    array2_to_mat(arrayM1_i, M1_GF2);//test int conv
//     cout << M1_GF2 << endl;
//   cout << M1_GF2 << endl;
//   cout << M2_GF2 << endl;
//   cout << inv(M1_GF2)<< endl;
//   cout << inv(M2_GF2) << endl;
  // cout << M1_zz_p << endl;
   // cout << inv(M1_zz_p) << endl;
    
}

