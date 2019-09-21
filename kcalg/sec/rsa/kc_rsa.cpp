//
//  kc_rsa.cpp
//  kcalg
//
//  Created by knightc on 2019/7/22.
//  Copyright © 2019 knightc. All rights reserved.
//

#include "opentsb/kc_sec.h"
#include "opentsb/kc_common.h"
#include "rsaUtil.hpp"

#include "opentsb/test.h"

#include <cstdio>
#include <vector>

#include <NTL/vec_ZZ.h>


int rsa_getKey(ZZ pubKey[],ZZ privKey[]) {
    
    ZZ p,q,n ,f_n;
    ZZ pubkey_e,privKey_d;
    
   pubkey_e= 65537;
    
       RandomPrime(p, 1024);
       RandomPrime(q, 1024);
    //    NextPrime(q, p );
//    p= 37;
//    q= 23;
//    if (GCD(p , q )==1) {
//        cout << "p and q is prime " << endl;
//    }
    
    
    n= p * q;
    oula(p, q, f_n);
    
    if (GCD(pubkey_e, f_n )== 1) {
        cout << " pubkey_e is true \n" << endl;
    }
    
    privKey_d = InvMod(pubkey_e, f_n);
    
    pubKey[0]=pubkey_e;
    pubKey[1]=n;
    
    
    privKey[0] = privKey_d;
    privKey[1] =p;
    privKey[2] = q ;
  
    cout <<"公钥 e = "<< pubkey_e <<"\n"
    << "共模 n = " << n << "\n"
    << "欧拉 n = " << f_n << "\n"
    <<"私钥 d = " <<privKey_d<< endl;
    
    return 1;
}

ZZ rsa_enc(const ZZ pubKey[],unsigned char *plaintext ,long plain_len) {
    
//    unsigned char *cyperTxt={0};
    ZZ e,n,plaintx_z,cypertx_z;
    
    e= pubKey[0];
    n= pubKey[1];
    
    plaintx_z= ZZFromBytes(plaintext, plain_len);
   cout  <<"明文 M = " <<plaintx_z<< endl;
//    cout <<"公钥 e = "<< e <<"\n"
//        << "共模 n = " << n << "\n"
//        <<"明文 M = " <<plaintx_z<< endl;
    
    cypertx_z = PowerMod(plaintx_z, e, n);
    cout << "密文 C = " << cypertx_z << endl;
    
    
//    BytesFromZZ(cyperTxt, cypertx_z, 256);
//
//    return cyperTxt;
    return cypertx_z;
   
    
}

int rsa_decy(ZZ cyperTxt_z,ZZ privKey[] , unsigned char *plaintext) {
    
    ZZ d,n,plaintx_z;
//    long ctx_len;
    
 //   ctx_len= getArrayLen(cyperTxt);
    
    d= privKey[0];
    n= privKey[1] * privKey[2];
//    cout <<"私钥 d = "<< d <<"\n"
//    << "共模 n = " << n << "\n"
//      <<"密文 C = " <<cyperTxt_z<< endl;
  //  ZZFromBytes(cyperTxt_z, cyperTxt, ctx_len);
    
   plaintx_z= PowerMod(cyperTxt_z, d, n);
    cout << "解密 M = " << plaintx_z << endl;
    
//    BytesFromZZ(plaintext, plaintx_z,1);
//    cout << "明文 M = " << plaintext << endl;
    
    return 0;
}

int test_rsa() {
    
//    unsigned   char std_Message[19]={
//        0x65,0x6E,0x63,0x72,0x79,0x70,0x74,0x69,0x6F,0x6E,0x20,0x73,0x74,0x61,0x6E,
//        0x64,0x61,0x72,0x64};
    unsigned char std_Message[1]={0x65};


    unsigned char *plaintx={0};
   // unsigned char *cypertx= {0};
    ZZ cypertx;
    
    long plain_len;
    ZZ pubKey[2],privKey[3];
    ZZ e,d,n;
    
    plain_len= getArrayLen(std_Message);
    rsa_getKey(pubKey, privKey);
    
    cypertx= rsa_enc(pubKey,std_Message, plain_len);
    
    rsa_decy(cypertx, privKey, plaintx);
    
    
    return 0;
}
