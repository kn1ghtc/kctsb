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

#include <NTL/ZZXFactoring.h>  // Polynomial factorization over integers
#include <NTL/ZZX.h>           // Univariate polynomial over integers
#include <NTL/ZZ_pX.h>         // Univariate polynomial over Z/pZ
#include <NTL/ZZ_pXFactoring.h>
#include <NTL/GF2X.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/GF2EX.h>
#include <NTL/GF2EXFactoring.h>

using namespace NTL;
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


void test_polynomials_main() {

    ZZX f;

    //f= a0+a1*x +a2*x^2 + a3 * x^3 +... + an * x^n
    ifstream fin("/Users/kc/git/alg-test/kcalg/kcalg/poly.txt");
    fin >> f;
   // cin >> f;//xcode的输入会自动补齐，但是键盘输入需要手动输入"【 "与 " 】"

    Vec< Pair<ZZX,long> > factors;//pair--系数、指数的对；vec_pair_ZZX_long
    ZZ c;

    factor(c, factors, f);//多项式的因式分解

 //   cout << c << "\n" << factors << "\n";


    //特定多项式输出:分圆多项式
    vec_ZZX phi(INIT_SIZE, 5);
    for (long i = 1; i <= 5; i++) {
        ZZX t;
        t = 1;

        for (long j = 1; j <= i-1; j++)
            if (i % j == 0)
                t *= phi(j);

        phi(i) = (ZZX(INIT_MONO, i) - 1)/t;

     //   cout << phi(i) << "\n";
    }


    //多项式赋值示例
    ZZX t1;
    ZZ t11;
    SetCoeff(t1, 4, 1);    //SetCoeff的优点：自动判断长度是否变化，即保证领项系数非0
    //SetCoeff(t1, 2560, 128); //尝试一下，大数
    t1.rep[2] = 2; //ZZX.rep的缺点：改变系数的同时不判断长度是否变化
    SetCoeff(t1, 0, -1);
    SetCoeff(t1, 5, 0); //领项系数设为 0 时，自动去掉
  //  t1[4]=2; //也可以直接定义系数值

    cout << t1 << "\n";
    ZZ t12;
    t12 = conv<ZZ>("12345678901234567890"); // 使用字符串转换避免整数字面量溢出警告
    t11=y_polynomials(t1, t12);
    cout << t11 << endl;//t12=2 时，正确值为 23

    ZZX t2;
    t2.rep.SetLength(6); //如果没有SetCoeff，使用ZZX.rep之前必须先用该句初始化长度
    t2.rep[4] = 1;
    t2.rep[0] = -1;
//    cout << t2 << "\n"; //注：此时领项系数是0，即第 6 项的系数为 0

    t2.normalize(); //作用：重新调整长度，以保证领项系数非0
 //   cout << t2 << "\n";

    //下面两种从多项式中取系数的值的方法等价
    if (t1.rep[4] == 1 and coeff(t1, 4) == 1 ){
      //  cout << "多项式取值正确" << "\n";
    }
  //  cout << GCD(t1, t2) << endl;

    //mod p polynomials
    ZZ p(65537);
    ZZ_p::init(p);

    ZZ_pX f_px;
    //cin >> f_px;
    SetCoeff(f_px, 4, 2);
    f_px.rep[3]=35;
    SetCoeff(f_px,5,1);//领项系数必须为 1：leadcoeff=1


    vec_pair_ZZ_pX_long factors_px;
    CanZass(factors_px, f_px);  // calls "Cantor/Zassenhaus" algorithm
  //  cout << factors_px << "\n" << f_px << "\n";


    // mod gf2e polynomials
    GF2X P;
    SetCoeff(P, 8, 1);
    SetCoeff(P, 4, 1);
    SetCoeff(P, 3, 1);
    SetCoeff(P, 1, 1);
    SetCoeff(P, 0, 1);
    GF2E::init(P);

    GF2EX f_gf2ex;
    SetCoeff(f_gf2ex, 0, 65537);
   // f_gf2ex.rep[2]= 23;

    vec_pair_GF2EX_long factors_gf2ex;
  //  CanZass(factors_gf2ex, f_gf2ex);
   // cout << factors_gf2ex << "\n" << f_gf2ex << "\n";

}




