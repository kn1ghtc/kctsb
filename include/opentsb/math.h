//
//  math.h
//  kcalg
//
//  Created by knightc on 2019/4/24.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef math_h
#define math_h

#include <vector>

#include <NTL/vec_ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_ZZ_p.h>
#include <NTL/mat_GF2.h>
#include <NTL/mat_GF2E.h>

using namespace NTL;
using namespace std;



void test_convert(const unsigned int v1,const unsigned int d1,const unsigned int d2);

ZZ test_zz_and(ZZ a,ZZ b);
ZZ test_PowerMod(const ZZ& a, const ZZ& e, const ZZ& n);
void test_vec_mat_main();

void lcm(ZZ& k, const ZZ& x, const ZZ& y);
//vec_ZZ lcm_gcd_vec(const vec_ZZ& v,int typemode);
vec_ZZ lcm_gcd_vec(const vec_ZZ& v,int typemode,long endleng);

void array_to_vec(const ZZ arr[],vec_ZZ &v,long len);
void array_to_vec(const int arr[],vec_ZZ &v,long len);
void array2_to_mat(const vector< vector<int> > arr,mat_ZZ &v);
void array2_to_mat(const vector< vector<ZZ> > arr,mat_ZZ &v);
void array2_to_mat(const vector< vector<int> > arr,mat_GF2 &v);
void array2_to_mat(const vector< vector<ZZ> > arr,mat_GF2 &v);
void array2_to_mat(const vector< vector<GF2> > arr,mat_GF2 &v);
void array2_to_mat(const vector< vector<int> > arr,mat_GF2E &v);
void array2_to_mat(const vector< vector<int> > arr,mat_ZZ_p &v);


void test_polynomials_main();



#endif /* math_h */
