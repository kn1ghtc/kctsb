/*
 *
 *   Example program demonstrates 1024 bit Diffie-Hellman, El Gamal and RSA
 *   and 168 bit Elliptic Curve Diffie-Hellman
 *
 */


/*
 ************************************
 1.椭圆曲线方程初始化
 ecurve_init
 Function:    void ecurve_init(A,B,p,type)
 big A,B,p;
 int type;
 Module:    mrcurve.c
 Description:    Initialises the internal parameters of the current active GF(p) elliptic curve. The curve is assumed to be of the form y2 =x3 + Ax + B mod p, the so-called Weierstrass model. This routine can be called subsequently with the parameters of a different curve.
 Parameters:    Three big numbers A, B and p. The type parameter must be either MR_PROJECTIVE or MR_AFFINE, and specifies whether projective or affine co-ordinates should be used internally. Normally the former is faster. (投影坐标、仿射坐标)
 Return value:    None
 
 2.点乘
 ecurve_mult
 Function:    void ecurve_mult(k,p,pa)
 big k;
 epoint *p,*pa;
 Description:    Multiplies a point on a GP(p) elliptic curve by an integer. Uses the addition/subtraction method.
 Parameters:    A big number k, and two points p and pa. On exit pa=k*p.
 Return value:    None
 Restrictions:    The point p must be on the active curve.
 
 3.点乘加快速运算
 ecurve_mult2
 Function:    void ecurve_mult2(k1,p1,k2,p2,pa)
 big k1,k2;
 epoint *p1,*p2,*pa;
 Description:    Calculates the point k1.p1+k2.p2 on a GF(p) elliptic curve. This is quicker than doing two separate multiplications and an addition. Useful for certain cryptosystems. (See ecsver.c for example)
 Parameters:    Two big integers k1 and k2, and three points p1, p2 and pa.
 On exit pa = k1.p1+k2.p2
 Return value:    None
 
 4.点的加法pa=pa+a
 ecurve_add
 Function:    void ecurve_add(p,pa)
 epoint *p,*pa;
 Description:    Adds two points on a GF(p) elliptic curve using the special rule for addition. Note that if pa=p, then a different duplication rule is used. Addition is quicker if p is normalised.
 Parameters:    Two points on the current active curve, pa and p. On exit pa=pa+p.
 Return value:    None
 Restrictions:    The input points must actually be on the current active curve.
 
 5.点的减法pa=pa-a
 ecurve_sub
 Function:    void ecurve_sub(p,pa)
 epoint *p,*pa;
 Description:    Subtracts two points on a GF(p) elliptic curve. Actually negates p and adds it to pa. Subtraction is quicker if p is normalised.
 Parameters:    Two points on the current active curve, pa and p. On exit pa = pa-p.
 Return value:    None
 Restrictions:    The input points must actually be on the current active curve.
 
 6.比较椭圆曲线上两个点是否相同
 epoint_comp
 Function:    BOOL epoint_comp(p1,p2)
 epoint *p1,*p2;
 Description:    Compares two points on the current active GF(p) elliptic curve.
 Parameters:    Two points p1 and p2.
 Return Value:    TRUE if the points are the same, otherwise FALSE.
 
 7.点的复制
 epoint_copy
 Function:    void epoint_copy(p1,p2)
 epoint *p1,*p2;
 Description:    Copies one point to another on a GF(p) elliptic curve.
 Parameters:    Two points p1 and p2. On exit p2=p1.
 Return value:    None
 
 8.初始化点 返回epoint类型点
 epoint_init
 Function:    epoint* epoint_init()
 Description:    Assigns memory to a point on a GF(p) elliptic curve, and initialises it to the "point at infinity".(并将其初始化为“无穷远点”)
 Parameters:    None.
 Return value:    A point p (in fact a pointer to a structure allocated from the heap).Parameters:    A point p.
 C程序员有责任确保通过调用此函数初始化的所有椭圆曲线点最终通过调用epoint_free释放;如果没有，将导致内存泄漏。
 
 9.释放点内存
 epoint_free
 Function:    void epoint_free(p)
 epoint *p;
 Description:    Frees memory associated with a point on a GF(p) elliptic curve.
 
 10.设置点坐标，若属于当前方程则返回True，不满足当前方程返回False
 值得注意的是：设置后（x!=p->X y!=p->Y）
 epoint_set
 Function:    BOOL epoint_set(x,y,lsb,p)
 big x,y;
 int lsb;
 epoint *p;
 Description:    Sets a point on the current active GF(p) elliptic curve (if possible).
 Parameters:    The integer co-ordinates x and y of the point p. If x and y are not distinct variables then x only is passed to the function, and lsb is taken as the least significant bit of y. In this case the full value of y is reconstructed internally. This is known as “point decompression” (and is a bit time-consuming, requiring the extraction of a modular square root). On exit p=(x,y).
 Return value:    TRUE if the point exists on the current active point, otherwise FALSE.
 Restrictions:    None
 Example:    C=epoint_init();
 epoint_set(x,x,1,C);


11.从epoint结构体中取出点坐标赋给给x、y
值得注意的是：设置后（p->X!=x p->Y!y）
epoint_get
Function:    int epoint_get(p,x,y)
epoint *p;
big x,y;
Description:    Normalises a point and extracts its (x,y) co-ordinates on the active GF(p) elliptic curve.
Parameters:    A point p, and two big integers x and y. If x and y are not distinct variables on entry then only the value of x is returned.
Return value:    The least significant bit of y. Note that it is possible to reconstruct a point from its x co-ordinate and just the least significant bit of y. Often such a “compressed” description of a point is useful.
Restrictions:    The point p must be on the active curve.
Example:    i=epoint_get(p,x,x);

12.检验x坐标是否在椭圆曲线下存在点（合法）
epoint_x
Function:    BOOL epoint_x(x)
big x;
Description:    Tests to see if the parameter x is a valid co-ordinate of a point on the curve. It is faster to test an x co-ordinate first in this way, rather than trying to directly set it on the curve by calling epoint_set, as it avoids an expensive modular square root.
Parameters:    The integer coordinate x.
Return value: TRUE if x is the coordinate of a curve point, otherwise FALSE

13.是否为无穷远点
point_at_infinity
Function:    BOOL point_at_infinity(p)
epoint *p;
Description: Tests if an elliptic curve point is the "point at infinity".
Parameters:    An elliptic curve point p.
Return value:    TRUE if p is the point-at-infinity, otherwise FALSE.
Restrictions:    The point must be initialised.
 
 ************************************
 */
#include <stdio.h>
#include "miracl.h"
#include <time.h>

#include "opentsb/test_c.h"

/* large 1024 bit prime p for which (p-1)/2 is also prime */
char *primetext=
"155315526351482395991155996351231807220169644828378937433223838972232518351958838087073321845624756550146945246003790108045940383194773439496051917019892370102341378990113959561895891019716873290512815434724157588460613638202017020672756091067223336194394910765309830876066246480156617492164140095427773547319";

/* Use elliptic curve of the form y^2=x^3-3x+B */

/* NIST p192 bit elliptic curve prime 2#192-2#64-1 */

char *ecp="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";

/* elliptic curve parameter B */

char *ecb="64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";

/* elliptic curve - point of prime order (x,y) */

char *ecx="188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012";
char *ecy="07192B95FFC8DA78631011ED6B24CDD573F977A11E794811";


char *text="MIRACL - Best multi-precision library in the World!\n";

int test_pkdemoMiracl_main()
{
    int ia,ib;
    time_t seed;
    epoint *g,*ea,*eb;
    big a,b,p,q,n,p1,q1,phi,pa,pb,key,e,d,dp,dq,t,m,c,x,y,k,inv;
    big pm[2];
  //  big primes[2];
 //   big_chinese ch;
    miracl *mip;
#ifndef MR_NOFULLWIDTH
    mip=mirsys(10000,0);
#else
    mip=mirsys(10000,64);
#endif
    a=mirvar(0);
    b=mirvar(0);
    p=mirvar(0);
    q=mirvar(0);
    n=mirvar(0);
    p1=mirvar(0);
    q1=mirvar(0);
    phi=mirvar(0);
    pa=mirvar(0);
    pb=mirvar(0);
    key=mirvar(0);
    e=mirvar(0);
    d=mirvar(0);
    dp=mirvar(0);
    dq=mirvar(0);
    t=mirvar(0);
    m=mirvar(0);
    c=mirvar(0);
    pm[0]=mirvar(0);
    pm[1]=mirvar(0);
    x=mirvar(0);
    y=mirvar(0);
    k=mirvar(0);
    inv=mirvar(0);
    
    time(&seed);
    irand((unsigned long)seed);   /* change parameter for different values */
    
    printf("First Diffie-Hellman Key exchange .... \n");
    
    cinstr(p,primetext);
    
    /* offline calculations could be done quicker using Comb method
     - See brick.c. Note use of "truncated exponent" of 160 bits -
     could be output of hash function SHA (see mrshs.c)               */
    
    printf("\nAlice's offline calculation\n");
    bigbits(160,a);
    
    /* 3 generates the sub-group of prime order (p-1)/2 */
    powltr(3,a,p,pa);
    
    printf("Bob's offline calculation\n");
    bigbits(160,b);
    powltr(3,b,p,pb);
    
    printf("Alice calculates Key=\n");
    powmod(pb,a,p,key);
    cotnum(key,stdout);
    
    printf("Bob calculates Key=\n");
    powmod(pa,b,p,key);
    cotnum(key,stdout);
    
    printf("Alice and Bob's keys should be the same!\n");
    
    /*
     Now Elliptic Curve version of the above.
     Curve is y^2=x^3+Ax+B mod p, where A=-3, B and p as above
     "Primitive root" is the point (x,y) above, which is of large prime order q.
     In this case actually
     q=FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
     
     */
    
    printf("\nLets try that again using elliptic curves .... \n");
    convert(-3,a);//convert bigtype
    mip->IOBASE=16;
    cinstr(b,ecb);
    cinstr(p,ecp);
    ecurve_init(a,b,p,MR_BEST);  /* Use PROJECTIVE if possible, else AFFINE coordinates */
    
    g=epoint_init();
    cinstr(x,ecx);
    cinstr(y,ecy);
    mip->IOBASE=10;
    epoint_set(x,y,0,g);
    ea=epoint_init();
    eb=epoint_init();
    epoint_copy(g,ea);
    epoint_copy(g,eb);
    
    printf("Alice's offline calculation\n");
    bigbits(160,a);
    ecurve_mult(a,ea,ea);
    ia=epoint_get(ea,pa,pa); /* <ia,pa> is compressed form of public key */
    
    printf("Bob's offline calculation\n");
    bigbits(160,b);
    ecurve_mult(b,eb,eb);
    ib=epoint_get(eb,pb,pb); /* <ib,pb> is compressed form of public key */
    
    printf("Alice calculates Key=\n");
    epoint_set(pb,pb,ib,eb); /* decompress eb */
    ecurve_mult(a,eb,eb);
    epoint_get(eb,key,key);
    cotnum(key,stdout);
    
    printf("Bob calculates Key=\n");
    epoint_set(pa,pa,ia,ea); /* decompress ea */
    ecurve_mult(b,ea,ea);
    epoint_get(ea,key,key);
    cotnum(key,stdout);
    
    printf("Alice and Bob's keys should be the same! (but much smaller)\n");
    
    epoint_free(g);
    epoint_free(ea);
    epoint_free(eb);
    
    /* El Gamal's Method */
    
    printf("\nTesting El Gamal's public key method\n");
    cinstr(p,primetext);
    bigbits(160,x);    /* x<p */
    powltr(3,x,p,y);    /* y=3^x mod p*/
    decr(p,1,p1);
    
    mip->IOBASE=128;
    cinstr(m,text);
    
    mip->IOBASE=10;
    do
    {
        bigbits(160,k);
    } while (egcd(k,p1,t)!=1);
    powltr(3,k,p,a);   /* a=3^k mod p */
    powmod(y,k,p,b);
    mad(b,m,m,p,p,b);  /* b=m*y^k mod p */
    printf("Ciphertext= \n");
    cotnum(a,stdout);
    cotnum(b,stdout);
    
    zero(m);           /* proof of pudding... */
    
    subtract(p1,x,t);
    powmod(a,t,p,m);
    mad(m,b,b,p,p,m);  /* m=b/a^x mod p */
    
    printf("Plaintext= \n");
    mip->IOBASE=128;
    cotnum(m,stdout);
    mip->IOBASE=10;
    
    /* RSA. Generate primes p & q. Use e=65537, and find d=1/e mod (p-1)(q-1) */
    
    printf("\nNow generating 512-bit random primes p and q\n");
    do
    {
        bigbits(512,p);
        if (subdivisible(p,2)) incr(p,1,p);
        while (!isprime(p)) incr(p,2,p);
        
        bigbits(512,q);
        if (subdivisible(q,2)) incr(q,1,q);
        while (!isprime(q)) incr(q,2,q);
        
        multiply(p,q,n);      /* n=p.q */
        
        lgconv(65537L,e);
        decr(p,1,p1);
        decr(q,1,q1);
        multiply(p1,q1,phi);  /* phi =(p-1)*(q-1) */
    } while (xgcd(e,phi,d,d,t)!=1);
    
    cotnum(p,stdout);
    cotnum(q,stdout);
    printf("n = p.q = \n");
    cotnum(n,stdout);
    
    /* set up for chinese remainder thereom */
    /*    primes[0]=p;
     primes[1]=q;
     crt_init(&ch,2,primes);
     */
    
    /* use simple CRT as only two primes */
    
    xgcd(p,q,inv,inv,inv);   /* 1/p mod q */
    
    copy(d,dp);
    copy(d,dq);
    divide(dp,p1,p1);   /* dp=d mod p-1 */
    divide(dq,q1,q1);   /* dq=d mod q-1 */
    mip->IOBASE=128;
    cinstr(m,text);
    mip->IOBASE=10;
    printf("Encrypting test string\n");
    powmod(m,e,n,c);
    printf("Ciphertext= \n");
    cotnum(c,stdout);
    
    zero(m);
    
    printf("Decrypting test string\n");
    
    powmod(c,dp,p,pm[0]);    /* get result mod p */
    powmod(c,dq,q,pm[1]);    /* get result mod q */
    
    subtract(pm[1],pm[0],pm[1]);  /* poor man's CRT */
    mad(inv,pm[1],inv,q,q,m);
    multiply(m,p,m);
    add(m,pm[0],m);
    
    /*    crt(&ch,pm,m);            combine them using CRT */
    
    printf("Plaintext= \n");
    mip->IOBASE=128;
    cotnum(m,stdout);
    /*    crt_end(&ch);  */
    
    return 0;

}

