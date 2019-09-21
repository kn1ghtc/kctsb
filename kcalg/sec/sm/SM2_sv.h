#ifndef SM2_sv_h
#define SM2_sv_h



#include "miracl.h"




int SM2_Sign(const char *message,long len, char ZA[], char rand[], char d[], char R[], char S[],epoint *G);

int SM2_Verify(const char *message,long len, char ZA[], char Px[],char Py[], char R[], char S[],epoint *G);



#endif /* SM2_sv_h */
