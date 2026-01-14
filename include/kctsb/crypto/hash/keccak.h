#ifndef __ALG_KECCAK_H_
#define __ALG_KECCAK_H_

#include <iostream>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

void KeccakRand(const unsigned char *input, unsigned long long int inputByteLen,
	unsigned char *output, unsigned long long int outLen);

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char delimitedSuffix,
	unsigned char *output, unsigned long long int outputByteLen);

void FIPS202_SHA3_256(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);
void FIPS202_SHA3_512(const unsigned char *input, unsigned int inputByteLen, unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif
