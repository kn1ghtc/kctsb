//
//  smGroup.h
//  kcalg
//
//  Created by knightc on 2019/7/26.
//  Copyright © 2019 knightc. All rights reserved.
//

#ifndef smGroup_h
#define smGroup_h

#include "miracl.h"
#include "mirdef.h"

#define SM2_NUMBITS 256
#define SM2_NUMWORD (SM2_NUMBITS/ECC_WORDSIZE) //32
#define ECC_WORDSIZE 8

#define ERR_INFINITY_POINT 0x00000001
#define ERR_NOT_VALID_ELEMENT 0x00000002
#define ERR_NOT_VALID_POINT 0x00000003
#define ERR_ORDER 0x00000004
#define ERR_ARRAY_NULL 0x00000005
#define ERR_C3_MATCH 0x00000006
#define ERR_ECURVE_INIT 0x00000007
#define ERR_SELFTEST_KG 0x00000008
#define ERR_SELFTEST_ENC 0x00000009
#define ERR_SELFTEST_DEC 0x0000000A

#define SM2_WORDSIZE 8
#define SM2_NUMBITS 256


#define ERR_GENERATE_R 0x00000026
#define ERR_GENERATE_S 0x00000027
#define ERR_OUTRANGE_R 0x00000028
#define ERR_OUTRANGE_S 0x00000029
#define ERR_GENERATE_T 0x0000002A
#define ERR_PUBKEY_INIT 0x0000002B
#define ERR_DATA_MEMCMP 0x0000002C

#define ERR_KEYEX_RA 0x00000016
#define ERR_KEYEX_RB 0x00000017
#define ERR_EQUAL_S1SB 0x00000018
#define ERR_EQUAL_S2SA 0x00000019
#define ERR_SELFTEST_Z 0x0000001A
#define ERR_SELFTEST_INI_I 0x0000000B
#define ERR_SELFTEST_RES_I 0x0000000C
#define ERR_SELFTEST_INI_II 0x0000000D


//sm2 char*
static  char* sSM2_p="FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";

static  char* test_SM2_p="8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
static  char* test_SM2_a="787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
static  char* test_SM2_b="63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
static  char* test_SM2_n="8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
static  char* test_SM2_h="0000000000000000000000000000000000000000000000000000000000000001";
static  char* test_SM2_Gx="421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
static  char* test_SM2Gy="0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
static  char*  test_SM2_dbKey="1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
static  char* test_SM2_pbKey_Gx="435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A";
static  char* test_SM2_pbKey_Gy="75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";
static  char* test_SM2_rand_k= "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";
static  char* test_SM2_rand_kG_Gx= "245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E7";
static  char* test_SM2_rand_kG_Gy= "76CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8";
static  char* test_SM2_C3="76CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8";
static  char* test_SM2_C2="9C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D";

//sm2 []
static unsigned  char SM2_p[32] = {
        0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
static unsigned  char SM2_a[32] ={
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC
};
static unsigned   char SM2_b[32] ={
    0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
    0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93
};
static unsigned   char SM2_n[32] ={
    0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23
};
static unsigned  char SM2_Gx[32]={
    0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
    0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7
};
static unsigned  char SM2_Gy[32]={
    0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
    0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0
};
//h=1,set m=n
static unsigned  char SM2_h[32]={
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};


#endif /* smGroup_h */
