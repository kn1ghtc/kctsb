//
//  main.cpp
//  kcalg
//
//  Created by knightc on 2019/4/4.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <gmp/gmp.h>

#include "opentsb/test.h"
#include "opentsb/cplus.h"
#include "opentsb/math.h"
#include "opentsb/kc_common.h"
#include "opentsb/kc_sec.h"
#include "opentsb/kc_sm.h"

extern "C" {
    #include "opentsb/chow_aes_wbox.h"
    #include "opentsb/aes.h"
    #include "opentsb/test_c.h"
}


using namespace std;
using namespace NTL;


int main(int argc, const char * argv[]) {
    
  // cout << strout()<< endl;
    strout();
    
    //test-ntl
    ZZ a,b,c,x,y,k;
    ifstream fin("/Users/kc/git/alg-test/kcalg/kcalg/gcd.txt");
    fin >> a >> b;
   // cin>> a >> b;
 //   cin>>b;
   // cin >> c;
    lcm(k,a,b);
    XGCD(c,x,y,a,b);
   // cout << test_zz_and(a,b) << endl;
   // cout <<k<<endl;
    // xy=lcm(x,y)* gcd(x,y)
//    cout << "lcm("<<a << ","<<b<<")"<<"="<<k<<endl;
//    cout << "gcd("<<a << ","<<b<<")"<<"="<<GCD(a,b)<<endl;
//     cout << "xgcd("<<a << ","<<b<<")"<<"="<<a<<"*"<<x<<"+"<<b<<"*"<<y<<endl;
//    x=PowerMod(a, b, c) ;
//  //  y= test_PowerMod(a, b, b);
//    y=InvMod(x, c);//x≠0
//    cout << x << endl;
//    cout << y << endl;

    
  //  test_main_aes_rigndael();
  //  fixed_income(21.0, 0.1, 10.0, 21);
  // cout<< strout(arr)<<endl;
    
    
    //ffs--zk
    //ffs1
    // test_ffs1_main();
   // test_ffsa_main();
    
   // test_vec_mat_main();
   // test_lll_main();
    
    
    
 //   test_polynomials_main();
    
    
   // test_eigamal_main();
   // test_aes_genTables_main();
    //test_aes_table();
    
    
    //test he
  // test_helib_all_main();
   // test_simpleFHE();
   // test_example_helib_main();
   // test_example_main();
    
    
    //test -CRT
    vec_ZZ crt_c,crt_m;
//    cin >> crt_c;
//   // cout << crt_c << endl;
//    cin>> crt_m;
//   // cout << crt_m << endl;
    fstream fin2("/Users/kc/git/alg-test/kcalg/kcalg/crt.txt");
    fin2 >> crt_c >> crt_m;
  //  cout << kc_crt(crt_c, crt_m) << endl;
//    ZZ test_a,test_p;
//    test_a=35;
//    test_p =2779;
//  cout<< CRT(test_a, test_p, ZZ(3), ZZ(5)) << endl;
//    cout << test_a << "\n" << test_p << endl;
    
    
    //test- struct
  //  test_struct();
    
    
    //test mysql
  //  test_mysql_conn();
    
    
    
    //test- miracl
  //  test_pkdemoMiracl_main();
    
    
    //纯 c 实现的 ecc 测试
 //  test_ecc_c_main();
  //  test_Virginia_main();
    
    
    //test GMJ sm
// return   SM2_ENC_SelfTest();
 //   return SM2_KeyEX_SelfTest();
  //  return SM2_SelfCheck();
     // return SM4_SelfCheck();
  //  return ZUC_SelfCheck();
    
    //test endian,x86 is all endian
//    int number = 1;
//    if(*(char *)&number){
//        cout<<"Little-endian!\n";
//        return 1;}
//    else{
//        cout<<"Big-endian!\n";
//        return 0;}
    
    //test -RSA
   // test_rsa();
  
  //  return 0;
    
    
    printf("\n it's over, then return 234 \n");
    return 234;
}
