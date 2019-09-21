//
//  crt.cpp
//  kcalg
//
//  Created by knightc on 2019/7/22.
//  Copyright © 2019 knightc. All rights reserved.
//


//中国剩余定理(Chinese Remainder Theorem)--CRT
#include <stdio.h>


#include "opentsb/kc_common.h"

//互质
   // crt_result+= (vec_c * vec_M * vec_N) % M;CRT的公式
//vec_c=[2 3 2] vec_m=[3 5 7] return 23
ZZ kc_crt(const vec_ZZ& vec_c,const vec_ZZ& vec_m){
    
    ZZ crt_result,M,crt_d,temp;
    vec_ZZ vec_M,vec_N,vec_n;
    
    long len;
    len= vec_m.length();
    vec_M.SetLength(len);
    vec_N.SetLength(len);
    vec_n.SetLength(len);
    
    crt_result=0;
    
    M=1;
    for (int i=0; i< len; i++) {
        M *= vec_m[i];
    }
    
    for (int j=0; j < len; j++) {
        temp = M / vec_m[j] ;
        vec_M[j]= temp;
    }

    for (int k =0; k < len; k++) {
        XGCD(crt_d, vec_N[k], vec_n[k], vec_M[k], vec_m[k]);
        
    }
    
    for (int k =0; k < len; k++) {
        crt_result += vec_c[k] * vec_N[k] * vec_M[k];
        
    }
    crt_result = crt_result % M;
    
    return crt_result;
}

