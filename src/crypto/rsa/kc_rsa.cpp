//
//  kc_rsa.cpp
//  kctsb
//
//  Created by knightc on 2019/7/22.
//  Copyright © 2019-2025 knightc. All rights reserved.
//

// This file requires NTL library
#if defined(KCTSB_HAS_NTL) || defined(KCTSB_USE_NTL)

#include "kctsb/core/security.h"
#include "kctsb/core/common.h"
#include "rsaUtil.hpp"

// Test utilities - only for internal testing
#include <iostream>

#include <cstdio>
#include <vector>

#include <NTL/vec_ZZ.h>


int rsa_getKey(ZZ pubKey[],ZZ privKey[]) {
    
    ZZ p,q,n ,f_n;
    ZZ pubkey_e,privKey_d;
    
    pubkey_e= 65537;
    
    RandomPrime(p, 1024);
    RandomPrime(q, 1024);
    
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
    
    return 0;  // Return 0 on success
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
    
    d= privKey[0];
    n= privKey[1] * privKey[2];
    
    // Decrypt: M = C^d mod n
    plaintx_z = PowerMod(cyperTxt_z, d, n);
    cout << "解密 M = " << plaintx_z << endl;
    
    // Convert ZZ to bytes using NTL's BytesFromZZ function
    // BytesFromZZ(unsigned char* buf, const ZZ& a, long n)
    // For single byte: convert ZZ to long then to byte
    if (plaintx_z <= 255) {
        plaintext[0] = (unsigned char)to_long(plaintx_z);
    } else {
        // Multi-byte number - use NTL's conversion
        BytesFromZZ(plaintext, plaintx_z, NumBytes(plaintx_z));
    }
    
    return 0;
}

int test_rsa() {
    
//    unsigned   char std_Message[19]={
//        0x65,0x6E,0x63,0x72,0x79,0x70,0x74,0x69,0x6F,0x6E,0x20,0x73,0x74,0x61,0x6E,
//        0x64,0x61,0x72,0x64};
    unsigned char std_Message[1]={0x65};

    // Allocate proper buffer for decrypted plaintext
    unsigned char plaintx[256] = {0};
    ZZ cypertx;
    
    long plain_len;
    ZZ pubKey[2],privKey[3];
    ZZ e,d,n;
    
    plain_len = sizeof(std_Message);  // Use sizeof instead of getArrayLen
    rsa_getKey(pubKey, privKey);
    
    cypertx= rsa_enc(pubKey,std_Message, plain_len);
    
    rsa_decy(cypertx, privKey, plaintx);
    
    // Verify the decryption result
    if (plaintx[0] != std_Message[0]) {
        return -1;  // Decryption failed
    }
    
    return 0;
}

#else
// Stubs when NTL is not available
int rsa_getKey(void*, void*) { return -1; }
int test_rsa() { return -1; }
#endif // KCTSB_HAS_NTL