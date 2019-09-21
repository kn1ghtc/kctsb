
#include <stdlib.h>


#include "smUtil.h"
#include "smGroup.h"


/****************************************************************
 Function: Test_Point
 Description: test if the given point is on SM2 curve
 Calls:
 Called By: SM2_Decrypt, Test_PubKey
 Input: point
 Output: null
 Return: 0: sucess
 3: not a valid point on curve
 Others:
 ****************************************************************/
int Test_Point(epoint* point,big para_p,big para_a ,big para_b)
{
    big x,y,x_3,tmp;
    x=mirvar(0);
    y=mirvar(0);
    x_3=mirvar(0);
    tmp=mirvar(0);
    //test if y^2=x^3+ax+b
    epoint_get(point,x,y);
    power (x, 3, para_p, x_3); //x_3=x^3 mod p
    multiply (x, para_a,x); //x=a*x
    divide (x, para_p, tmp); //x=a*x mod p , tmp=a*x/p
    add(x_3,x,x); //x=x^3+ax
    add(x,para_b,x); //x=x^3+ax+b
    divide(x,para_p,tmp); //x=x^3+ax+b mod p
    power (y, 2,para_p, y); //y=y^2 mod p
    if(mr_compare(x,y)!=0)
        return ERR_NOT_VALID_POINT;
    else
        return 0;
}


/****************************************************************
 Function: SM2_TestPubKey
 Description: test if the given point is valid
 Calls:
 Called By: SM2_Decrypt
 Input: pubKey //a point
 Output: null
 Return: 0: sucess
 1: a point at infinity
 2: X or Y coordinate is beyond Fq
 3: not a valid point on curve
 4: not a point of order n
 Others:
 ****************************************************************/
int Test_PubKey(epoint *pubKey,big para_p ,big para_a, big para_b,big para_n)
{
    big x,y,x_3,tmp;
    epoint *nP;
    x=mirvar(0);
    y=mirvar(0);
    x_3=mirvar(0);
    tmp=mirvar(0);
    nP=epoint_init();
    //test if the pubKey is the point at infinity
    if (point_at_infinity(pubKey))// if pubKey is point at infinity, return error;
        return ERR_INFINITY_POINT;
    //test if x<p and y<p both hold
    epoint_get(pubKey,x,y);
    if((mr_compare(x,para_p)!=-1) || (mr_compare(y,para_p)!=-1))
        return ERR_NOT_VALID_ELEMENT;
    if(Test_Point(pubKey,para_p,para_a,para_b)!=0)
        return ERR_NOT_VALID_POINT;
    //test if the order of pubKey is equal to n
    ecurve_mult(para_n,pubKey,nP); // nP=[n]P
    if (!point_at_infinity(nP)) // if np is point NOT at infinity, return error;
        return ERR_ORDER;
    return 0;
}


/****************************************************************
 Function: Test_Zero
 Description: test if the big x is zero
 Calls:
 Called By: SM2_Sign
 Input: pubKey //a point
 Output: null
 Return: 0: x!=0
 1: x==0
 Others:
 ****************************************************************/
int Test_Zero(big x)
{
    big zero;
    zero=mirvar(0);
    if(compare(x,zero)==0)
        return 1;
    else return 0;
}


/****************************************************************
 Function: Test_n
 Description: test if the big x is order n
 Calls:
 Called By: SM2_Sign
 Input: big x //a miracl data type
 Output: null
 Return: 0: sucess
 1: x==n,fail
 Others:
 ****************************************************************/
int Test_n(big x)
{
    big n;
    n= mirvar(0);
    bytes_to_big(32,SM2_n,n);
    if(compare(x,n)==0)
        return 1;
    else return 0;
}


/****************************************************************
 Function: Test_Range
 Description: test if the big x belong to the range[1,n-1]
 Calls:
 Called By: SM2_Verify
 Input: big x ///a miracl data type
 Output: null
 Return: 0: sucess
 1: fail
 Others:
 ****************************************************************/
int Test_Range(big x)
{
    big one,decr_n,n;
    one=mirvar(0);
    decr_n=mirvar(0);
    n=mirvar(0);
    
    convert(1,one);
     bytes_to_big(32,SM2_n,n);
    
    decr(n,1,decr_n);
    if( (compare(x,one) < 0)| (compare(x,decr_n)>0) )
        return 1;
    return 0;
}


int sm2_init(epoint *G) {
    
    // SM2_Init();//initiate SM2 curve
   big p,a,b,n,Gx,Gy,h;
    epoint *nG;
    p=mirvar(0);
    a=mirvar(0);
    b=mirvar(0);
    n=mirvar(0);
    Gx=mirvar(0);
    Gy=mirvar(0);
    h=mirvar(0);
    
    
    nG=epoint_init();
    
    bytes_to_big(SM2_NUMWORD,SM2_p,p);
    bytes_to_big(SM2_NUMWORD,SM2_a,a);
    bytes_to_big(SM2_NUMWORD,SM2_b,b);
    bytes_to_big(SM2_NUMWORD,SM2_n,n);
    bytes_to_big(SM2_NUMWORD,SM2_Gx,Gx);
    bytes_to_big(SM2_NUMWORD,SM2_Gy,Gy);
    bytes_to_big(SM2_NUMWORD,SM2_h,h);
//    cinstr(p, test_SM2_p);
//    cinstr(a, test_SM2_a);
//    cinstr(b, test_SM2_b);
//    cinstr(n, test_SM2_n);
//    cinstr(h, test_SM2_h);
//    cinstr(Gx, test_SM2_pbKey_Gx);
//    cinstr(Gy, test_SM2_pbKey_Gy);

    
    //ecurve_init(para_a,para_b,para_p,MR_PROJECTIVE);//Initialises GF(p) elliptic curve.
    ecurve_init(a,b,p,MR_PROJECTIVE);//MR_PROJECTIVE specifying projective coordinates
    if (!epoint_set(Gx,Gy,0,G))//initialise point G
    {
        return ERR_ECURVE_INIT;
    }
    ecurve_mult(n,G,nG);
    if (!point_at_infinity(nG)) //test if the order of the point is n
    {
        return ERR_ORDER;
    }
    
    return 0;
    
}


int SM2_KeyGeneration(big priKey,epoint *pubKey,epoint *G)
{

    big p,a,b,n;
    p=mirvar(0);
    a=mirvar(0);
    b=mirvar(0);
    n=mirvar(0);
    bytes_to_big(SM2_NUMWORD,SM2_p,p);
    bytes_to_big(SM2_NUMWORD,SM2_a,a);
    bytes_to_big(SM2_NUMWORD,SM2_b,b);
    bytes_to_big(SM2_NUMWORD,SM2_n,n);
//    cinstr(p, test_SM2_p);
//    cinstr(a, test_SM2_a);
//    cinstr(b, test_SM2_b);
//    cinstr(n, test_SM2_n);
    
    ecurve_mult(priKey,G,pubKey);//通过大数和基点产生公钥
//    epoint_get(pubKey,x,y);
    if(Test_PubKey(pubKey,p,a,b,n)!=0)
        return 1;
    else
        return 0;
}
