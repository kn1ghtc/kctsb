//
//  aes_table.c
//  kcalg
//
//  Created by knightc on 2019/7/16.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <stdio.h>
#include "opentsb/aes.h"
//#include "genTables.cpp"
//#include "chow_aes_wbox.h"
#include "/Users/kc/git/alg-test/kcalg/kcalg/aesTable.h"


#define GETU32(pt) (\
((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^\
((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]) )

#define PUTU32(ct, st) {\
(ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16);\
(ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }


void printstate(unsigned char * in){
    for(int i = 0; i < 16; i++) {
        printf("%.2X", in[i]);
        
    }
    printf("\n");
    
    return;
}

char ascii2hex(char in){
    char out;
    
    if (('0' <= in) && (in <= '9'))
        out = in - '0';
    
    if (('A' <= in) && (in <= 'F'))
        out = in - 'A' + 10;
    
    if (('a' <= in) && (in <= 'f'))
        out = in - 'a' + 10;
    
    return out;
}

void asciiStr2hex (char * in, char * out, int len){
    int j = 0;
    for (int i = 0; i < len; i += 2)
        out[j++]  = (ascii2hex(in[i ]) << 4) +  ascii2hex(in[i+1]);
}


void mixColumns_table(u8 state[16]) {
    u8 out[16];
    u32 tmp;
    for (int j = 0; j < 4; j++)
    {
        tmp = TyiTables[0][state[4*j]] ^ TyiTables[1][state[4*j + 1]]
        ^ TyiTables[2][state[4*j + 2]] ^ TyiTables[3][state[4*j + 3]];
        out[4*j + 0] = (u8) (tmp >> 24);
        out[4*j + 1] = (u8) (tmp >> 16);
        out[4*j + 2] = (u8) (tmp >> 8);
        out[4*j + 3] = (u8) (tmp >> 0);
    }
    
    memcpy(state, out, sizeof(out));
}

void aes_128_table_encrypt (u8 input[16], u8 output[16]) {
    u32 a, b, c, d, aa, bb, cc, dd;
    for (int i = 0; i < 9; i++) {
        shiftRows (input);
        
        for (int j = 0; j < 4; j++)
        {
            a = TyiBoxes[i][4*j + 0][input[4*j + 0]];
            b = TyiBoxes[i][4*j + 1][input[4*j + 1]];
            c = TyiBoxes[i][4*j + 2][input[4*j + 2]];
            d = TyiBoxes[i][4*j + 3][input[4*j + 3]];
            
            aa = xorTable[i][24*j + 0][(a >> 28) & 0xf][(b >> 28) & 0xf];
            bb = xorTable[i][24*j + 1][(c >> 28) & 0xf][(d >> 28) & 0xf];
            cc = xorTable[i][24*j + 2][(a >> 24) & 0xf][(b >> 24) & 0xf];
            dd = xorTable[i][24*j + 3][(c >> 24) & 0xf][(d >> 24) & 0xf];
            input[4*j + 0] = (xorTable[i][24*j + 4][aa][bb] << 4) | xorTable[i][24*j + 5][cc][dd];
            
            aa = xorTable[i][24*j + 6][(a >> 20) & 0xf][(b >> 20) & 0xf];
            bb = xorTable[i][24*j + 7][(c >> 20) & 0xf][(d >> 20) & 0xf];
            cc = xorTable[i][24*j + 8][(a >> 16) & 0xf][(b >> 16) & 0xf];
            dd = xorTable[i][24*j + 9][(c >> 16) & 0xf][(d >> 16) & 0xf];
            input[4*j + 1] = (xorTable[i][24*j + 10][aa][bb] << 4) | xorTable[i][24*j + 11][cc][dd];
            
            aa = xorTable[i][24*j + 12][(a >> 12) & 0xf][(b >> 12) & 0xf];
            bb = xorTable[i][24*j + 13][(c >> 12) & 0xf][(d >> 12) & 0xf];
            cc = xorTable[i][24*j + 14][(a >>  8) & 0xf][(b >>  8) & 0xf];
            dd = xorTable[i][24*j + 15][(c >>  8) & 0xf][(d >>  8) & 0xf];
            input[4*j + 2] = (xorTable[i][24*j + 16][aa][bb] << 4) | xorTable[i][24*j + 17][cc][dd];
            
            aa = xorTable[i][24*j + 18][(a >>  4) & 0xf][(b >>  4) & 0xf];
            bb = xorTable[i][24*j + 19][(c >>  4) & 0xf][(d >>  4) & 0xf];
            cc = xorTable[i][24*j + 20][(a >>  0) & 0xf][(b >>  0) & 0xf];
            dd = xorTable[i][24*j + 21][(c >>  0) & 0xf][(d >>  0) & 0xf];
            input[4*j + 3] = (xorTable[i][24*j + 22][aa][bb] << 4) | xorTable[i][24*j + 23][cc][dd];
            
            
            a = mixBijOut[i][4*j + 0][input[4*j + 0]];
            b = mixBijOut[i][4*j + 1][input[4*j + 1]];
            c = mixBijOut[i][4*j + 2][input[4*j + 2]];
            d = mixBijOut[i][4*j + 3][input[4*j + 3]];
            
            aa = xorTable[i][24*j + 0][(a >> 28) & 0xf][(b >> 28) & 0xf];
            bb = xorTable[i][24*j + 1][(c >> 28) & 0xf][(d >> 28) & 0xf];
            cc = xorTable[i][24*j + 2][(a >> 24) & 0xf][(b >> 24) & 0xf];
            dd = xorTable[i][24*j + 3][(c >> 24) & 0xf][(d >> 24) & 0xf];
            input[4*j + 0] = (xorTable[i][24*j + 4][aa][bb] << 4) | xorTable[i][24*j + 5][cc][dd];
            
            aa = xorTable[i][24*j + 6][(a >> 20) & 0xf][(b >> 20) & 0xf];
            bb = xorTable[i][24*j + 7][(c >> 20) & 0xf][(d >> 20) & 0xf];
            cc = xorTable[i][24*j + 8][(a >> 16) & 0xf][(b >> 16) & 0xf];
            dd = xorTable[i][24*j + 9][(c >> 16) & 0xf][(d >> 16) & 0xf];
            input[4*j + 1] = (xorTable[i][24*j + 10][aa][bb] << 4) | xorTable[i][24*j + 11][cc][dd];
            
            aa = xorTable[i][24*j + 12][(a >> 12) & 0xf][(b >> 12) & 0xf];
            bb = xorTable[i][24*j + 13][(c >> 12) & 0xf][(d >> 12) & 0xf];
            cc = xorTable[i][24*j + 14][(a >>  8) & 0xf][(b >>  8) & 0xf];
            dd = xorTable[i][24*j + 15][(c >>  8) & 0xf][(d >>  8) & 0xf];
            input[4*j + 2] = (xorTable[i][24*j + 16][aa][bb] << 4) | xorTable[i][24*j + 17][cc][dd];
            
            aa = xorTable[i][24*j + 18][(a >>  4) & 0xf][(b >>  4) & 0xf];
            bb = xorTable[i][24*j + 19][(c >>  4) & 0xf][(d >>  4) & 0xf];
            cc = xorTable[i][24*j + 20][(a >>  0) & 0xf][(b >>  0) & 0xf];
            dd = xorTable[i][24*j + 21][(c >>  0) & 0xf][(d >>  0) & 0xf];
            input[4*j + 3] = (xorTable[i][24*j + 22][aa][bb] << 4) | xorTable[i][24*j + 23][cc][dd];
        }
    }
    shiftRows(input);
    for (int j = 0; j < 16; j++) {
        input[j] = TBoxes[9][j][input[j]];
    }
    
    for (int i = 0; i < 16; i++)
        output[i] = input[i];
    
}


/*int main(void) {
 u8 out[16];
 //u8 in2[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
 u8 in[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
 
 printState(in);
 aes_128_encrypt(in, out);
 printState(out);
 
 return 0;
 }*/

void test_aes_table_main(int argc, char * argv[]){
    unsigned char OUT[32];
   unsigned char IN[32];
   asciiStr2hex(argv[1], (char *)IN, 32);
  // unsigned char IN[32] = "00112233445566778899aabbccddeeff";
    printstate(IN);
    
    aes_128_table_encrypt(IN, OUT);
    
    printstate(OUT);
    
}

void test_aes_table(){
    unsigned char OUT[32];
    //unsigned char IN[32];
    // asciiStr2hex(argv[1], (char *)IN, 32);
    unsigned char IN[32] = "00112233445566778899aabbccddeeff";
    printstate(IN);
    
    aes_128_table_encrypt(IN, OUT);
    
    printstate(OUT);
    
}
