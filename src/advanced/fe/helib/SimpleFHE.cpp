//
//  SimpleFHESum.cpp
//  kcalg
//
//  Created by knightc on 2019/7/19.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>

#include "opentsb/test.h"

#include <helib/FHE.h>
#include <iostream>

using namespace std;
using namespace NTL;

void test_simpleFHE() {
    long p = 65537;// Plaintext prime modulus
    long r = 1; //Hensel lifting (default = 1)
    long L = 300; //Number of bits of the modulus chain
    long c = 2; //Number of columns of Key-Switching matix (default = 2 or 3)
    long k = 80;
    long s = 0;
    long d = 0;
    long w = 64;
    
    ZZ randomP;
    RandomPrime(randomP,60);
    p= to_ulong(randomP);
    cout << "p = " << p << endl;
    
    cout << "finding m..." << flush;
    long m = FindM(k,L,c,p,d,s,0);
    cout << "m = "<< m << endl;
    
    cout << "Initializing context..." << flush;
    FHEcontext context(m,p,r);  //initialize context
    buildModChain(context, L, c);  //modify the context
    cout << "OK!" << endl;
    
    cout << "Creating polynomial..." << flush;
    ZZX G = context.alMod.getFactorsOverZZ()[0];  //creates the polynomial used to encrypted the data
    cout << "OK!" << endl;
    
    cout << "Generating keys..." << flush;
    FHESecKey secretKey(context);  //construct a secret key structure
    const FHEPubKey& publicKey = secretKey;  //An "upcast": FHESecKey is a subclass of FHEPubKey
    secretKey.GenSecKey(w);  //actually generate a secret key with Hamming weight w
    cout << "OK!" << endl;
    
    
    Ctxt ctxt1(publicKey);
    Ctxt ctxt2(publicKey);
    
    ZZX m1,m2;
    m1=to_ZZX(523456444567);
    m2=to_ZZX(855554);
    
    publicKey.Encrypt(ctxt1, m1);  //encrypt the value 2
    publicKey.Encrypt(ctxt2, m2);  //encrypt the value 3
    
    
    Ctxt ctSum = ctxt1;  //create a ciphertext to hold the sum and initialize it with Enc(2)
    ctSum += ctxt2;
    
    Ctxt ctMul = ctxt1;
    ctMul *= ctxt2;
    
    
    ZZX ptSum,ptMul;  //create a ciphertext to hold the plaintext of the sum
    secretKey.Decrypt(ptSum, ctSum);
    secretKey.Decrypt(ptMul, ctMul);
    
    cout << m1 << " + " << m2  <<" = " << ptSum[0] <<endl;
    cout << m1[0] << "   +  " << m2[0] <<"  = " << m1[0]+m2[0]   <<endl;
    printf("\n");
    
    cout << m1 << " * " << m2 <<" = " << ptMul[0] <<endl;
    cout << m1[0] << "   *  " << m2[0] <<"  = " << m1[0]*m2[0]    <<endl;
    printf("\n");
    
}
