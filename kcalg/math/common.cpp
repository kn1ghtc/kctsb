//
//  common.cpp
//  kcalg
//
//  Created by knightc on 2019/7/12.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>

#include "opentsb/math.h"
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

//一次性运算求 向量的 lcm/gcd
vec_ZZ lcm_gcd_vec(const vec_ZZ& v,int typemode){
    
    vec_ZZ vec_out;
    long m,n,j,i;
    ZZ temp;
    i=0;
    j=0;

     n= v.length();
    m= ceil(n/2.0);//向上取整，必须是非整数，即 2---》2.0
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

//求 n 个数的最大公约数/最小公倍数
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



//array can use "for" to assignment，but vector can't。if must，can use vector.push_back
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
    long m= v.NumRows();
    long n= v.NumCols();
    
    for (int i=0;i<=m-1;i++){
        for (int j=0; j<=n-1; j++) {
            v[i][j]=arr[i][j];
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_ZZ &v){
    long m= v.NumRows();
    long n= v.NumCols();
    
    for (int i=0;i<=m-1;i++){
        for (int j=0; j<=n-1; j++) {
            v[i][j]=to_ZZ(arr[i][j]);
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_GF2 &v){
    long m= v.NumRows();
    long n= v.NumCols();
    
    for (int i=0;i<=m-1;i++){
        for (int j=0; j<=n-1; j++) {
            v[i][j]=to_GF2(arr[i][j]);
        }
    }
    
}

void array2_to_mat(const vector< vector<ZZ> > arr,mat_GF2 &v){
    long m= v.NumRows();
    long n= v.NumCols();
    
    for (int i=0;i<=m-1;i++){
        for (int j=0; j<=n-1; j++) {
            v[i][j]=to_GF2(arr[i][j]);
        }
    }
    
}

void array2_to_mat(const vector< vector<GF2> > arr,mat_GF2 &v){
    long m= v.NumRows();
    long n= v.NumCols();
    
    for (int i=0;i<=m-1;i++){
        for (int j=0; j<=n-1; j++) {
            v[i][j]=arr[i][j];
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_GF2E &v){
    
    
    long m= v.NumRows();
    long n= v.NumCols();
    
//    const GF2X P(INIT_MONO,8);
//    GF2E::init(P);
    GF2X P;
    SetCoeff(P, 8, 1);
    SetCoeff(P, 4, 1);
    SetCoeff(P, 3, 1);
    SetCoeff(P, 1, 1);
    SetCoeff(P, 0, 1);
    GF2E::init(P);
    
    for (int i=0;i<=m-1;i++){
        for (int j=0; j<=n-1; j++) {
            v[i][j]=to_GF2E(arr[i][j]);
        }
    }
    
}

void array2_to_mat(const vector< vector<int> > arr,mat_ZZ_p &v){
  
    v.SetDims(arr.size(),arr[0].size());
    
    long m= v.NumRows();
    long n= v.NumCols();
    
    ZZ_p::init(ZZ(256));
    
    for (int i=0;i<=m-1;i++){
        for (int j=0; j<=n-1; j++) {
            v[i][j]=to_ZZ_p(long(arr[i][j]));
        }
    }
    
}


//void inv_array2_to_mat(const mat_GF2E &v, vector< vector<int> > &arr) //gf2e --> int  ?????


//to_ZZX(vec);可以把一个一维数组/向量 转为多项式（系数更换）
void kc_lagrange(vec_vec_ZZ_p &pointMat,vec_zz_p &coeffVec) {
    
}
