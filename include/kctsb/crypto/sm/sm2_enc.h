#ifndef SM2_ENC_h
#define SM2_ENC_h


#include "miracl.h"
#include "mirdef.h"




static int Test_Null(unsigned char array[],int len);

static int SM2_Encrypt(unsigned char* randK,epoint *pubKey,unsigned char M[],int klen,unsigned char C[],epoint *G_point_gm,big para_h);
static int SM2_Decrypt(big dB,unsigned char C[],int Clen,unsigned char M[],big para_p,big para_a,big para_b,big para_h);




#endif /* SM2_ENC_h */
