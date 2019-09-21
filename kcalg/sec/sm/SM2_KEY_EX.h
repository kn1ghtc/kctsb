#ifndef SM2_KEY_EX_h
#define SM2_KEY_EX_h


#include "miracl.h"
#include "mirdef.h"


static int SM2_W(big para_n);
static void SM3_Z(unsigned char ID[], unsigned short int ELAN, epoint* pubKey, unsigned char hash[]);


static int SM2_KeyEx_Init_I(big ra, epoint* RA,epoint *G_point_gm);

static int SM2_KeyEx_Re_I(big rb, big dB, epoint* RA, epoint* PA, unsigned char ZA[],unsigned char
                   ZB[],unsigned char K[],int klen,epoint* RB, epoint* V,unsigned char hash[],
                   epoint *G_point_gm,big para_p,big para_a,big para_b,big para_n,big para_h);


static int SM2_KeyEx_Init_II(big ra, big dA, epoint* RA,epoint* RB, epoint* PB, unsigned char ZA[],unsigned char ZB[],unsigned char SB[],unsigned char K[],int klen,unsigned char SA[],big para_p,big para_a,big para_b,big para_n,big para_h);

static int SM2_KeyEx_Re_II(epoint *V,epoint *RA,epoint *RB,unsigned char ZA[],unsigned char ZB[],unsigned char SA[]);





#endif /* SM2_KEY_EX_h */
