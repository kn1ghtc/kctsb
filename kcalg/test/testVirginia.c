#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#define MAX 10000
#define LEN 150

#include "opentsb/test_c.h"

/*Virginia加密算法*/
void virginiaEnc()
{
    FILE *fin,*fout;
    char ch,cc;
    char filename1[LEN]="/Users/kc/git/alg-test/kcalg/kcalg/vinginiaPlain.txt";
    char filename2[LEN]="/Users/kc/git/alg-test/kcalg/kcalg/vinginiaCipher.txt";
    char key[MAX];
    int i=0;
    long keylen;
    printf("请输入加密密钥:\n") ;
    scanf("%s",key);
    keylen=strlen(key);
    fin=fopen(filename1,"r");
    if(fin==NULL)
    {
        printf("Fail to open the file1!\n");
    }
    fout=fopen(filename2,"w");
    if(fout==NULL)
    {
        printf("Fail to open the file2!\n");
    }
    printf("加密后的密文：\n");
    while((ch=fgetc(fin))!=EOF)
    {
        cc=(ch+(key[i%keylen]-'a'))<='z'?(ch+(key[i%keylen]-'a')):(ch+(key[i%keylen]-'a'))-26;
        fprintf(fout,"%c",cc);
        i++;
        printf("%c",cc);
    }
    printf("\n");
    fclose(fin);//关闭输入流
    fclose(fout);
}

/*唯密文破解密钥*/
//结果不对，且只能一次，且必须为字母
void getKey(char filename1[],char key[])
{
    FILE *fin,*fout;
    char sub[100]="";
    char try[100]="";
    int alphabat[26]={0};//用于统计字母出现的频率
    double assese[100]={0}; //统计每个字串的IC'值
    int Count=1;//密钥长度
    int i,j;
    double avg=0;
    double p[30]={0.0805,0.0162,0.0320,0.0365,0.1231,0.0228,0.0161,0.0514,0.0718,0.0010,
        0.0520,0.0403,0.0225,0.0719,0.0794,0.0229,0.0020,0.0603,0.0659,0.0959,
        0.0310,0.0093,0.0203,0.0020,0.0188,0.0009};//字母出现的统计频率
    
    int keyIndex[MAX];//密钥的位置
    // step1：估算Virginia多表代换加密的秘钥长度
    while((int)(fabs(avg-0.065)*1000)>1)
    {
        char ch;
        Count++;
        avg=0.0;
        //将密文分成Count个子串，然后计算其IC’的平均值
        memset(assese,0,sizeof(assese));
        printf("分成%d个子串\n",Count);
        for(i=0;i<Count;i++)
        {
            fin=fopen(filename1,"r");
            if(fin==NULL)
            {
                printf("Fail to open the cipertextfile!\n");
                exit(0);
            }else{
                sprintf(sub,"/Users/kc/git/alg-test/kcalg/kcalg/testdataVinginia/sub%d.txt",i+1);//创建Count个文本文件
                fout=fopen(sub,"w");
                if(fout== NULL )
                {
                    printf("Fail to open subFile.");
                    break ;
                }else
                {
                    int len=0;
                    memset(alphabat,0,sizeof(alphabat));//初始化字母出现的频率
                    for(j=0;j<i;j++)//第i个字串的开始点
                    {
                        if((ch=fgetc(fin))!=EOF) continue;
                    }
                    while((ch=fgetc(fin))!=EOF)
                    {
                        fprintf(fout,"%c",ch);
                        alphabat[ch-'a']++;
                        len++;
                        printf("%c",ch);
                        for(j=0;j<Count-1;j++)//同一个字串内的字母相距 Count-1
                        {
                            if((ch=fgetc(fin))!=EOF)
                            {
                                continue;
                            }
                        }
                    }
                    printf("\n");
                    //计算IC'
                    for(j=0;j<26;j++)
                    {
                        if(alphabat[j]>1)
                        {
                            assese[i+1]+=((double)alphabat[j]/len)*((double)(alphabat[j]-1)/(len-1));
                        }
                        
                    }
                    avg+=assese[i+1];
                }
                fclose(fout);
                fclose(fin);//关闭输入流
            }
        }
        avg=avg/Count;//求IC'的平均值
        if((int)(fabs(avg-0.065)*1000)<=1)//IC'的平均值接近于0.065
        {
            printf("第%d次的IC'=%f\n",Count,avg);
            break;
        }
        printf("第%d次的IC'=%f\n",Count,avg);
    }
    //step2：再计算秘钥中的每个字符
    for(i=0;i<Count;i++)
    {
        double index[27]={0.0};//字串每一次移位的拟重合指数
        int fre[26]={0};
        double max=0.0;
        sprintf(sub,"/Users/kc/git/alg-test/kcalg/kcalg/testdataVinginia/sub%d.txt",i+1);//打开字串文件
        sprintf(try,"/Users/kc/git/alg-test/kcalg/kcalg/testdataVinginia/try%d.txt",i+1);
        for(j=0;j<26;j++)
        {
            char ch,cc;
            int k;
            int n=0;//字串的长度
            memset(fre,0,sizeof(fre));
            fin=fopen(sub,"r");
            fout=fopen(try,"w");
            while((ch=fgetc(fin))!=EOF)
            {
                cc=(ch-j)>='a'?(ch-j):(ch-j)+26;//左移j位
                fprintf(fout,"%c",cc);
                fre[cc-'a']++;//统计移位后每个 字母出现的频率
                n++;
            }
            //计算拟重合指数
            for(k=0;k<26;k++)
            {
                index[j-1]+=(p[k]*fre[k])/n;
            }
        }
        //求最大的拟重合指数
        max=index[0];
        for(j=1;j<26;j++)
        {
            if(index[j]>max)
            {
                max=index[j];
                keyIndex[i]=j;//保存当前字串的密钥
            }
        }
        fclose(fin);
        fclose(fout);
    }
    printf("所求密钥为：\n");
    for(i=0;i<Count;i++)//输出密钥
    {
        printf("%c",keyIndex[i]+'a'+1);
        key[i]= keyIndex[i]+'a'+1;//保存密钥
    }
    printf("\n");
}
/*Virginia已知密钥解密算法*/
void decrypt()
{
    FILE *fin,*fout;
    char ch,cc;
    char key[MAX];
    char filename1[LEN]="/Users/kc/git/alg-test/kcalg/kcalg/vinginiaCipher.txt";
    char filename2[LEN]="/Users/kc/git/alg-test/kcalg/kcalg/vinginiaCipherToPlain.txt";
    int keylen,i=0;
    getKey(filename1,key);
    keylen=strlen(key);
    fin=fopen(filename1,"r");
    fout=fopen(filename2,"w");
    if(fout==NULL)
    {
        printf("fail\n");
    }
    printf("解密得到的明文:\n");
    while((ch=fgetc(fin))!=EOF)
    {
        cc=(ch-(key[i%keylen]-'a'))>='a'?(ch-(key[i%keylen]-'a')):(ch-(key[i%keylen]-'a'))+26;
        fprintf(fout,"%c",cc);
        i++;
        printf("%c",cc);
    }
    printf("\n");
    fclose(fin);//关闭输入流
    fclose(fout);
}
int test_Virginia_main()
{
    int choice;
    while(1)
    {
        printf("----------------------------------------\n");
        printf("\t\t1.加密\n");
        printf("\t\t2.解密\n");
        printf("\t\t3.退出\n");
        printf("----------------------------------------\n");
        printf("请输入你的选择：\n") ;
        scanf("%d",&choice);
        switch(choice)
        {
            case 1:
               virginiaEnc();
            
                break;
            case 2:
                decrypt();
                break;
            case 3:
                exit(0);
                break;
        }
    }
    return 0;
}
