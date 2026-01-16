//
//  common.cpp
//  kcalg
//
//  Created by knightc on 2019/7/12.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>
#include <cmath>

#include "kctsb/math/math.h"
#include <NTL/GF2X.h>
#include <NTL/ZZX.h>

using namespace NTL;
using namespace std;

 void lcm(ZZ& k, const ZZ& x, const ZZ& y) {
    ZZ gcd;
    mul(k, x, y);
    GCD(gcd, x, y);
    k /= gcd;
}

// Compute vector LCM/GCD in a single pass.
vec_ZZ lcm_gcd_vec(const vec_ZZ& v,int typemode){
    
    vec_ZZ vec_out;
    long m,n,j,i;
    ZZ temp;
    i=0;
    j=0;

    n= v.length();
    m = static_cast<long>(std::ceil(static_cast<double>(n) / 2.0)); // Round up n/2.
      vec_out.SetLength(m);
    switch (typemode) {
        case 1:
            for (i=0; i < n-1; i+=2) {
                
                lcm(temp,v[i],v[i+1]);
                // cout << temp<< endl;
                vec_out[j] = temp;
                //cout << vec_out << endl;
                j++;
                // cout << j << endl;
            }
            // cout << i << endl;
            if (n % 2 == 1 ) {
                lcm( vec_out[j],v[i],ZZ(1));
            }
            break;
         case 2:
            for (i=0; i < n-1; i+=2) {
                GCD(temp,v[i],v[i+1]);
                // cout << temp<< endl;
                vec_out[j] = temp;
                //cout << vec_out << endl;
                j++;
                // cout << j << endl;
            }
            // cout << i << endl;
            if (n % 2 == 1 ) {
                GCD( vec_out[j],v[i],v[i-1]);
            }
            break;
    }
    return vec_out;
}

// Compute GCD/LCM for n numbers.
vec_ZZ lcm_gcd_vec(const vec_ZZ& v,int typemode,long endleng){
    
    vec_ZZ vec_out;
    
    vec_out= lcm_gcd_vec(v, typemode);
    endleng=vec_out.length();
    
    while (endleng != 1) {
       vec_out= lcm_gcd_vec(vec_out, typemode);
         endleng=vec_out.length();
    }
    
    return vec_out;
}



// Arrays can use index assignment; vectors can use push_back when needed.
void array_to_vec(const ZZ arr[],vec_ZZ &v,long len) {
   // long n= v.length();
    
    v.SetLength(len);
    for (int i=0; i<=len-1; i++) {
        v[i]=arr[i];
    }
    //cout<<v<<endl;
}

void array_to_vec(const int arr[],vec_ZZ &v,long len) {
   // long n= v.length();
    
    for (int i=0; i<=len-1; i++) {
        v[i]=to_ZZ(arr[i]);
        
    }
    // cout<<v<<endl;
}

void array2_to_mat(const vector< vector<ZZ> > arr,mat_ZZ &v){
    long m = v.NumRows();
    long n = v.NumCols();
    
    for (long i = 0; i < m; ++i){
        for (long j = 0; j < n; ++j) {
            v[i][j] = arr[static_cast<size_t>(i)][static_cast<size_t>(j)];
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_ZZ &v){
    long m = v.NumRows();
    long n = v.NumCols();
    
    for (long i = 0; i < m; ++i){
        for (long j = 0; j < n; ++j) {
            v[i][j] = to_ZZ(arr[static_cast<size_t>(i)][static_cast<size_t>(j)]);
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_GF2 &v){
    long m = v.NumRows();
    long n = v.NumCols();
    
    for (long i = 0; i < m; ++i){
        for (long j = 0; j < n; ++j) {
            v[i][j] = to_GF2(arr[static_cast<size_t>(i)][static_cast<size_t>(j)]);
        }
    }
    
}

void array2_to_mat(const vector< vector<ZZ> > arr,mat_GF2 &v){
    long m = v.NumRows();
    long n = v.NumCols();
    
    for (long i = 0; i < m; ++i){
        for (long j = 0; j < n; ++j) {
            v[i][j] = to_GF2(arr[static_cast<size_t>(i)][static_cast<size_t>(j)]);
        }
    }
    
}

void array2_to_mat(const vector< vector<GF2> > arr,mat_GF2 &v){
    long m = v.NumRows();
    long n = v.NumCols();
    
    for (long i = 0; i < m; ++i){
        for (long j = 0; j < n; ++j) {
            v[i][j] = arr[static_cast<size_t>(i)][static_cast<size_t>(j)];
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_GF2E &v){
    
    
    long m = v.NumRows();
    long n = v.NumCols();
    
//    const GF2X P(INIT_MONO,8);
//    GF2E::init(P);
    GF2X P;
    SetCoeff(P, 8, 1);
    SetCoeff(P, 4, 1);
    SetCoeff(P, 3, 1);
    SetCoeff(P, 1, 1);
    SetCoeff(P, 0, 1);
    GF2E::init(P);
    
    for (long i = 0; i < m; ++i){
        for (long j = 0; j < n; ++j) {
            v[i][j] = to_GF2E(arr[static_cast<size_t>(i)][static_cast<size_t>(j)]);
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_ZZ_p &v){
  
    v.SetDims(static_cast<long>(arr.size()), static_cast<long>(arr[0].size()));
    
    long m = v.NumRows();
    long n = v.NumCols();
    
    ZZ_p::init(ZZ(256));
    
    for (long i = 0; i < m; ++i){
        for (long j = 0; j < n; ++j) {
            v[i][j] = to_ZZ_p(static_cast<long>(arr[static_cast<size_t>(i)][static_cast<size_t>(j)]));
        }
    }
    
}


//void inv_array2_to_mat(const mat_GF2E &v, vector< vector<int> > &arr) //gf2e --> int  ?????


// to_ZZX(vec) converts a 1D vector into a polynomial (coefficient mapping).
void kc_lagrange(vec_vec_ZZ_p &pointMat,vec_zz_p &coeffVec) {
    
}
