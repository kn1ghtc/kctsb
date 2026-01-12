#ifndef SM4_hpp
#define SM4_hpp


#include<stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

//rotate n bits to the left in a 32bit buffer
#define SM4_Rotl32(buf, n) (((buf)<<n)|((buf)>>(32-n)))

// External declarations (defined in sm4.cpp)
extern unsigned int SM4_CK[32];
extern unsigned char SM4_Sbox[256];
extern unsigned int SM4_FK[4];



void SM4_KeySchedule(unsigned char MK[], unsigned int rk[]);
void SM4_Encrypt(unsigned char MK[],unsigned char PlainText[],unsigned char CipherText[]);
void SM4_Decrypt(unsigned char MK[],unsigned char CipherText[], unsigned char PlainText[]);

#ifdef __cplusplus
}
#endif

#endif /* SM4_hpp */
