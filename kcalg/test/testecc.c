/*
 (1)编程计算该椭圆曲线上所有在有限域GF(89)上的点；
 (2)编程实现椭圆曲线上任意一个点P(例如P=(12,5))的倍点运算的递归算法，即计算k*P( k=2,3,…)；（重点！）
 (3)利用此递归算法找出椭圆曲线上的所有生成元G以及它们的阶n，即满足n*G_testECC=O；
 (4)设计实现某一用户B的公钥、私钥算法，即得到public key=(n, G_testECC, PB, Ep(a, b))
 secure key=nB(小于n)
 (5)假如用户A发送明文消息“yes”并加密传输给用户B，用户B接收消息后要能解密为明文。试用ECC密码体制实现此功能。
 */

//速度极其之慢，可用 ntl 改写其模运算、逆运算


#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<time.h>

#include "opentsb/test_c.h"
#define MAX 100

typedef struct point{
    int point_x;
    int point_y;
}Point;
typedef struct ecc{
    struct point p[MAX];
    int len;
}ECCPoint;
typedef struct generator{
    Point p;
    int p_class;
}GENE_SET;

void get_all_points();
int int_sqrt(int s);
Point timesPiont(int k,Point p);
Point add_two_points(Point p1,Point p2);
int inverse(int n,int b);
void get_generetor_class();
void encrypt_ecc();
void decrypt_ecc();
int mod_p(int s);
void print();
int isPrime(int n);

/*
 ** set ecc
 **set  y^2 = x^3 + ax + b
 ** set mod p
 ** get all point{include (0,0) },m= length[all point]
 ** choose G_testECC(x,y)
 **calculate n or h,nG=(0,0),h= m /n
 */
char alphabet[26]="abcdefghijklmnopqrstuvwxyz";
//必须全部小写字母；不同的模，可能出错
int a=-1,b=0,p=89;//椭圆曲线为E89(-1,0)： y2=x3-x (mod 89)

ECCPoint eccPoint;
GENE_SET geneSet[MAX];
int geneLen;
char plain[]="helloecc";
int m[MAX];
int cipher[MAX];
int nB;//私钥
Point P1,P2,Pt,G_testECC,PB;
Point Pm;
int C[MAX];

int test_ecc_c_main()
{
    get_generetor_class();
    encrypt_ecc();
    decrypt_ecc();
    return 0;
}
//task4:加密
void encrypt_ecc()
{
    int num,i,j;
    int gene_class;
    int num_t;
    int k;
    srand(time(NULL));
    //明文转换过程
    for(i=0;i<strlen(plain);i++)
    {
        for(j=0;j<26;j++) //for(j=0;j<26;j++)
        {
            if(plain[i]==alphabet[j])
            {
                m[i]=j;//将字符串明文换成数字，并存到整型数组m里面
            }
        }
    }
    //选择生成元1    num=rand()%geneLen;
    gene_class=geneSet[num].p_class;
    while(isPrime(gene_class)==-1)//不是素数
    {
        num=rand()%(geneLen-3)+3;
        gene_class=geneSet[num].p_class;
    }
    //printf("gene_class=%d\n",gene_class);
    G_testECC=geneSet[num].p;
    //printf("G_testECC:(%d,%d)\n",geneSet[num].p.point_x,geneSet[num].p.point_y);
    nB=rand()%(gene_class-1)+1;//选择私钥
    PB=timesPiont(nB,G_testECC);
    printf("\n公钥：\n");
    printf("{y^2=x^3%d*x+%d,%d,(%d,%d),(%d,%d)}\n",a,b,gene_class,G_testECC.point_x,G_testECC.point_y,PB.point_x,PB.point_y);
    printf("私钥：\n");
    printf("nB=%d\n",nB);
    //加密
    //
    k=rand()%(gene_class-2)+1;
    P1=timesPiont(k,G_testECC);
    //
    num_t=rand()%eccPoint.len; //选择映射点
    Pt=eccPoint.p[num_t];
    //printf("Pt:(%d,%d)\n",Pt.point_x,Pt.point_y);
    P2=timesPiont(k,PB);
    Pm=add_two_points(Pt,P2);
    printf("加密数据：\n");
    printf("kG=(%d,%d),Pt+kPB=(%d,%d),C={",P1.point_x,P1.point_y,Pm.point_x,Pm.point_y);
    for(i=0;i<strlen(plain);i++)
    {
        //        num_t=rand()%eccPoint.len; //选择映射点
        //        Pt=eccPoint.p[num_t];
        C[i]=m[i]*Pt.point_x+Pt.point_y;
        printf("{%d}",C[i]);
    }
    printf("}\n");
}
//task5:解密
void decrypt_ecc()
{
    Point temp,temp1;
    int m,i;
    temp=timesPiont(nB,P1);
    temp.point_y=0-temp.point_y;
    temp1=add_two_points(Pm,temp);//求解Pt
    //    printf("(%d,%d)\n",temp.point_x,temp.point_y);
    //    printf("(%d,%d)\n",temp1.point_x,temp1.point_y);
    printf("\n解密结果：\n");
    for(i=0;i<strlen(plain);i++)
    {
        m=(C[i]-temp1.point_y)/temp1.point_x;
        printf("%c",alphabet[m]);//输出密文
    }
    printf("\n");
}
//判断是否为素数
int isPrime(int n)
{
    int i,k;
    k = sqrt(n);
    for (i = 2; i <= k;i++)
    {
        if (n%i == 0)
            break;
    }
    if (i <=k){
        return -1;
    }
    else {
        return 0;
    }
}
//task3:求生成元以及阶
void get_generetor_class()
{
    int i,j=0;
    int count=1;
    Point p1,p2;
    get_all_points();
    //    p1.point_x=p2.point_x=3;
    //    p1.point_y=p2.point_y=2;
    //    while(1)
    //    {
    //        printf("(%d,%d)+(%d,%d)---%d\n",p1.point_x,p1.point_y,p2.point_x,p2.point_y,count);
    //        p2=add_two_points(p1,p2);
    //        count++;
    //        if(p2.point_x==-1 && p2.point_y==-1)
    //        {
    //            break;
    //        }
    //    }
    //    printf("\n\n(%d,%d)---%d\n",p1.point_x,p1.point_y,count);
    //
    //    do{
    //            printf("(%d,%d)+(%d,%d)---%d\n",p1.point_x,p1.point_y,p2.point_x,p2.point_y,count);
    //            p2=add_two_points(p1,p2);
    //            count++;
    //
    //    } while(!((p2.point_x==p1.point_x)&&(p2.point_y==p1.point_y)));
    //    printf("(%d,%d)+(%d,%d)---%d\n",p1.point_x,p1.point_y,p2.point_x,p2.point_y,count);
    //    count ++ ;
    //    printf("\n\n(%d,%d)---%d\n",p1.point_x,p1.point_y,count);
    printf("\n**********************************输出生成元以及阶：*************************************\n");
    for(i=0;i<eccPoint.len;i++)
    {
        count=1;
        p1.point_x=p2.point_x=eccPoint.p[i].point_x;
        p1.point_y=p2.point_y=eccPoint.p[i].point_y;
        while(1)
        {
            p2=add_two_points(p1,p2);
            if(p2.point_x==-1 && p2.point_y==-1)
            {
                break;
            }
            count++;
            if(p2.point_x==p1.point_x)
            {
                break;
            }
        }
        count++;
        if(count<=eccPoint.len+1)
        {
            geneSet[j].p.point_x=p1.point_x;
            geneSet[j].p.point_y=p1.point_y;
            geneSet[j].p_class=count;
            printf("(%d,%d)--->>%d\t",geneSet[j].p.point_x,geneSet[j].p.point_y,geneSet[j].p_class);
            j++;
            if(j % 6 ==0){
                printf("\n");
            }
        }
        geneLen=j;
    }
}

//task2:倍点运算的递归算法
Point timesPiont(int k,Point p0)
{
    if(k==1){
        return p0;
    }
    else if(k==2){
        return add_two_points(p0,p0);
    }else{
        return add_two_points(p0,timesPiont(k-1,p0));
    }
}

//两点的加法运算
Point add_two_points(Point p1,Point p2)
{
    long t;
    int x1=p1.point_x;
    int y1=p1.point_y;
    int x2=p2.point_x;
    int y2=p2.point_y;
    int tx,ty;
    int x3,y3;
    int flag=0;
    //求
    if((x2==x1)&& (y2==y1) )
    {
        //相同点相加
        if(y1==0)
        {
            flag=1;
        }else{
            t=(3*x1*x1+a)*inverse(p,2*y1) % p;
        }
        //printf("inverse(p,2*y1)=%d\n",inverse(p,2*y1));
    }else{
        //不同点相加
        ty=y2-y1;
        tx=x2-x1;
        while(ty<0)
        {
            ty+=p;
        }
        while(tx<0)
        {
            tx+=p;
        }
        if(tx==0 && ty !=0)
        {
            flag=1;
        }else{
            t=ty*inverse(p,tx) % p;
        }
    }
    if(flag==1)
    {
        p2.point_x=-1;
        p2.point_y=-1;
    }else{
        x3=(t*t-x1-x2) % p;
        y3=(t*(x1-x3)-y1) % p;
        //使结果在有限域GF(P)上
        while(x3<0)
        {
            x3+=p;
        }
        while(y3<0)
        {
            y3+=p;
        }
        p2.point_x=x3;
        p2.point_y=y3;
    }
    return p2;
}
//求b关于n的逆元
int inverse(int n,int b)
{
    int q,r,r1=n,r2=b,t,t1=0,t2=1,i=1;
    while(r2>0)
    {
        q=r1/r2;
        r=r1%r2;
        r1=r2;
        r2=r;
        t=t1-q*t2;
        t1=t2;
        t2=t;
    }
    if(t1>=0)
        return t1%n;
    else{
        while((t1+i*n)<0)
            i++;
        return t1+i*n;
    }
}
//task1:求出椭圆曲线上所有点
void get_all_points()
{
    int i=0;
    int j=0;
    int s,y=0;
    int n=0,q=0;
    int modsqrt=0;
    int flag=0;
    if (4 * a * a * a + 27 * b * b != 0)
    {
        for(i=0;i<=p-1;i++)
        {
            flag=0;
            n=1;
            y=0;
            s= i * i * i + a * i + b;
            while(s<0)
            {
                s+=p;
            }
            s=mod_p(s);
            modsqrt=int_sqrt(s);
            if(modsqrt!=-1)
            {
                flag=1;
                y=modsqrt;
            }else{
                while(n<=p-1)
                {
                    q=s+n*p;
                    modsqrt=int_sqrt(q);
                    if(modsqrt!=-1)
                    {
                        y=modsqrt;
                        flag=1;
                        break;
                    }
                    flag=0;
                    n++;
                }
            }
            if(flag==1)
            {
                eccPoint.p[j].point_x=i;
                eccPoint.p[j].point_y=y;
                j++;
                if(y!=0)
                {
                    eccPoint.p[j].point_x=i;
                    eccPoint.p[j].point_y=(p-y) % p;
                    j++;
                }
            }
        }
        eccPoint.len=j;//点集个数
        print(); //打印点集
    }
}

//取模函数
int mod_p(int s)
{
    int i;    //保存s/p的倍数
    int result;    //模运算的结果
    i = s / p;
    result = s - i * p;
    if (result >= 0)
    {
        return result;
    }
    else
    {
        return result + p;
    }
}

//判断平方根是否为整数
int int_sqrt(int s)
{
    int temp;
    temp=(int)sqrt(s);//转为整型
    if(temp*temp==s)
    {
        return temp;
    }else{
        return -1;
    }
}
//打印点集
void print()
{
    int i;
    int len=eccPoint.len;
    printf("\n该椭圆曲线上共有%d个点(包含无穷远点)\n",len+1);
    for(i=0;i<len;i++)
    {
        if(i % 8==0)
        {
            printf("\n");
        }
        printf("(%2d,%2d)\t",eccPoint.p[i].point_x,eccPoint.p[i].point_y);
    }
    printf("\n");
}
