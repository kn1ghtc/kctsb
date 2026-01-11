//
//  ElGamal.cpp
//  kcalg
//
//  Created by knightc on 2019/7/16.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>
#include <string>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <cstdio>

#include <gmp/gmp.h>

#include "opentsb/kc_common.h"

using namespace std;

int test_eigamal_main()
{
    gmp_randstate_t grt;
    gmp_randinit_default(grt);//设置随机数生成算法为默认
    gmp_randseed_ui(grt, time(NULL)); //设置随机化种子为当前时间，这几条语句的作用相当于标准C中的srand(time(NULL));
    
    const char * buf_n = "1000000000000000000000000000000000000000000000000000000";
    
    mpz_t X1,Y1,k,C1,C2,K,M,p,q,v,s;//初始化
    mpz_inits (X1,Y1,k,C1,C2,K,M,p,q,v,s,NULL);
    mpz_init_set_ui (M,65537);//chiper
    mpz_init_set_str(q,buf_n,10);
    mpz_init_set_ui(v,2);
    mpz_init_set_ui(s,1);
    
    
    mpz_t g,b,e,l;//用于中介值
    mpz_inits(g,b,e,l,NULL);
    
    
    while(true)
    {
        mpz_nextprime(q, q);//使用GMP自带的素数生成函数
        
        mpz_mul(p,q,v);//p=q*2
        mpz_add(p,p,s);// p=p+1
        
        if(mpz_probab_prime_p(p,30))//p、q都是素数且满足p=2q+1，则p是安全素数
            break;
}
    
    
    mpz_urandomm(g,grt,p);//生成g
    mpz_powm(b,g,v,p);//b=g^2 mod p
    mpz_powm(e,g,q,p);//e=g^q mod p
    while(mpz_cmp(b,s)==0||mpz_cmp(e,s)==0||mpz_cmp_ui(g,0)==0)
    {
        mpz_urandomm(g,grt,p);//生成g
        mpz_powm(b,g,v,p);//b=g^2 mod p
        mpz_powm(e,g,q,p);//e=g^q mod p
        //计算g^2 mod p 和g^q mod p都不等于1，则g是生成元，否则继续选g,s=1
    }
    
    gmp_printf("%s %ZX \n","g is:",g);
    mpz_urandomm(k,grt,p);//生成任意整数k
    mpz_urandomm(X1,grt,p);//生成任意整数X1
    //加密
    mpz_powm(Y1,g,X1,p);//计算Y1=g^X1 mod p
    mpz_powm(K,Y1,k,p);//计算K=Y1^k mod p
    mpz_powm(C1,g,k,p);//计算C1=g^k mod p
    mpz_mul(l,K,M);//计算l=KM
    mpz_mod(C2,l,p);//计算C2=l mod p
    //解密
    mpz_t a,f,m;
    mpz_inits(a,f,m,NULL);
    
    
    mpz_powm(K,C1,X1,p);//K=C1^X1 mod p
    mpz_invert(a,K,p);//a=K^-1 mod p
    mpz_mul(f,C2,a);//f=C2(K^-1 mod p)
    mpz_mod(m,f,p);//m=f mod p
    gmp_printf("%s %Zd \n","q is:",p);
    gmp_printf("%s %Zd \n","a is:",g);
    gmp_printf("%s (%Zd, %Zd) \n","密文为：",C1,C2);
    gmp_printf("%s %Zd \n","m is:",m);
    mpz_clears(p,q,a,f,m,K,k,X1,Y1,g,l,C1,C2,b,e,v,s,NULL);
    return 0;
}
