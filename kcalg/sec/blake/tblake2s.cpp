/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Derived from the BLAKE2 reference implementation written by Samuel Neves.
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>
 * More information about the BLAKE2 hash function and its implementations
 * can be found at https://blake2.net.
 */

#include <assert.h>
#include <string.h>
#include <openssl/crypto.h>

#include "tblake2_locl.h"
#include "tblake2_impl.h"


namespace ALG {
    static const uint32_t tblake2s_IV[8] = {
        0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
        0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
    };
    
    static const uint8_t tblake2s_sigma[10][16] = {
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
        { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
        {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
        {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
        {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
        { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
        { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
        {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
        { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
    };
    
    /* Set that it's the last block we'll compress */
    static inline void tblake2s_set_lastblock(TBLAKE2S_CTX *S) {
        S->f[0] = -1;
    }
    
    /* Initialize the hashing state. */
    static inline void tblake2s_init0(TBLAKE2S_CTX *S) {
        int i;
        
        memset(S, 0, sizeof(TBLAKE2S_CTX));
        for (i = 0; i < 8; ++i) {
            S->h[i] = tblake2s_IV[i];
        }
    }
    
    /* init2 xors IV with input parameter block */
    void tblake2s_init_param(TBLAKE2S_CTX *S, const TBLAKE2S_PARAM *P) {
        const uint8_t *p = (const uint8_t *)(P);
        size_t i;
        
        /* The param struct is carefully hand packed, and should be 32 bytes on
         * every platform. */
        assert(sizeof(TBLAKE2S_PARAM) == 32);
        tblake2s_init0(S);
        /* IV XOR ParamBlock */
        for (i = 0; i < 8; ++i) {
            S->h[i] ^= tload32(&p[i*4]);
        }
    }
    
    /* Initialize the hashing context.  Always returns 1. */
    int TBLAKE2s_Init(TBLAKE2S_CTX *c, size_t outLen) {
        TBLAKE2S_PARAM P[1];

        P->digest_length = TBLAKE2S_DIGEST_LENGTH;
        P->key_length    = 0;
        P->fanout        = 1;
        P->depth         = 1;
        tstore32((uint8_t *)&P->leaf_length, 0);
        tstore32((uint8_t *)&P->node_offset, 0);
        tstore16((uint8_t *)&P->xof_length, 0);
        P->node_depth    = 0;
        P->inner_length  = 0;
        memset(P->salt,     0, sizeof(P->salt));
        memset(P->personal, 0, sizeof(P->personal));
        tblake2s_init_param(c, P);
        return 1;
    }
    
    /* Permute the state while xoring in the block of data. */
    static void tblake2s_compress(TBLAKE2S_CTX *S,
                                  const uint8_t *blocks,
                                  size_t len) {
        uint32_t m[16];
        uint32_t v[16];
        size_t i;
        size_t increment;
        
        /*
         * There are two distinct usage vectors for this function:
         *
         * a) BLAKE2s_Update uses it to process complete blocks,
         *    possibly more than one at a time;
         *
         * b) BLAK2s_Final uses it to process last block, always
         *    single but possibly incomplete, in which case caller
         *    pads input with zeros.
         */
        assert(len < TBLAKE2S_BLOCKBYTES || len % TBLAKE2S_BLOCKBYTES == 0);
        
        /*
         * Since last block is always processed with separate call,
         * |len| not being multiple of complete blocks can be observed
         * only with |len| being less than TBLAKE2S_BLOCKBYTES ("less"
         * including even zero), which is why following assignment doesn't
         * have to reside inside the main loop below.
         */
        increment = len < TBLAKE2S_BLOCKBYTES ? len : TBLAKE2S_BLOCKBYTES;
        
        for (i = 0; i < 8; ++i) {
            v[i] = S->h[i];
        }
        
        do {
            for (i = 0; i < 16; ++i) {
                m[i] = tload32(blocks + i * sizeof(m[i]));
            }
            
            /* blake2s_increment_counter */
            S->t[0] += increment;
            S->t[1] += (S->t[0] < increment);
            
            v[ 8] = tblake2s_IV[0];
            v[ 9] = tblake2s_IV[1];
            v[10] = tblake2s_IV[2];
            v[11] = tblake2s_IV[3];
            v[12] = S->t[0] ^ tblake2s_IV[4];
            v[13] = S->t[1] ^ tblake2s_IV[5];
            v[14] = S->f[0] ^ tblake2s_IV[6];
            v[15] = S->f[1] ^ tblake2s_IV[7];
#define G(r,i,a,b,c,d) \
    do { \
        a = a + b + m[tblake2s_sigma[r][2*i+0]]; \
        d = trotr32(d ^ a, 16); \
        c = c + d; \
        b = trotr32(b ^ c, 12); \
        a = a + b + m[tblake2s_sigma[r][2*i+1]]; \
        d = trotr32(d ^ a, 8); \
        c = c + d; \
        b = trotr32(b ^ c, 7); \
    } while (0)
#define ROUND(r)  \
    do { \
        G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
        G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
        G(r,2,v[ 2],v[ 6],v[10],v[14]); \
        G(r,3,v[ 3],v[ 7],v[11],v[15]); \
        G(r,4,v[ 0],v[ 5],v[10],v[15]); \
        G(r,5,v[ 1],v[ 6],v[11],v[12]); \
        G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
        G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
    } while (0)
#if defined(OPENSSL_SMALL_FOOTPRINT)
            /* almost 3x reduction on x86_64, 4.5x on ARMv8, 4x on ARMv4 */
            for (i = 0; i < 10; i++) {
                ROUND(i);
            }
#else
            ROUND(0);
            ROUND(1);
            ROUND(2);
            ROUND(3);
            ROUND(4);
            ROUND(5);
            ROUND(6);
            ROUND(7);
            ROUND(8);
            ROUND(9);
#endif
            
            for (i = 0; i < 8; ++i) {
                S->h[i] = v[i] ^= v[i + 8] ^ S->h[i];
            }
#undef G
#undef ROUND
            blocks += increment;
            len -= increment;
        } while (len);
    }
    
    /* Absorb the input data into the hash state.  Always returns 1. */
    int TBLAKE2s_Update(TBLAKE2S_CTX *c, const void *data, size_t datalen) {
        const uint8_t *in = (uint8_t *)data;
        size_t fill;
        
        /*
         * Intuitively one would expect intermediate buffer, c->buf, to
         * store incomplete blocks. But in this case we are interested to
         * temporarily stash even complete blocks, because last one in the
         * stream has to be treated in special way, and at this point we
         * don't know if last block in *this* call is last one "ever". This
         * is the reason for why |datalen| is compared as >, and not >=.
         */
        fill = sizeof(c->buf) - c->buflen;
        if (datalen > fill) {
            if (c->buflen) {
                memcpy(c->buf + c->buflen, in, fill); /* Fill buffer */
                tblake2s_compress(c, c->buf, TBLAKE2S_BLOCKBYTES);
                c->buflen = 0;
                in += fill;
                datalen -= fill;
            }
            if (datalen > TBLAKE2S_BLOCKBYTES) {
                size_t stashlen = datalen % TBLAKE2S_BLOCKBYTES;
                /*
                 * If |datalen| is a multiple of the blocksize, stash
                 * last complete block, it can be final one...
                 */
                stashlen = stashlen ? stashlen : TBLAKE2S_BLOCKBYTES;
                datalen -= stashlen;
                tblake2s_compress(c, in, datalen);
                in += datalen;
                datalen = stashlen;
            }
        }
        
        assert(datalen <= TBLAKE2S_BLOCKBYTES);
        
        memcpy(c->buf + c->buflen, in, datalen);
        c->buflen += datalen; /* Be lazy, do not compress */
        
        return 1;
    }
    
    /*
     * Calculate the final hash and save it in md.
     * Always returns 1.
     */
    int TBLAKE2s_Final(unsigned char *md, TBLAKE2S_CTX *c, size_t outLen) {
        int i;
        
        tblake2s_set_lastblock(c);
        /* Padding */
        memset(c->buf + c->buflen, 0, sizeof(c->buf) - c->buflen);
        tblake2s_compress(c, c->buf, c->buflen);
        
        /* Output full hash to temp buffer */
        for (i = 0; i < 8; ++i) {
            tstore32(md + sizeof(c->h[i]) * i, c->h[i]);
        }
        
        OPENSSL_cleanse(c, sizeof(TBLAKE2S_CTX));
        return 1;
    }
    
    
//    uint8_t buffer[BLAKE2S_OUTBYTES] = {0};
//    size_t i;
//    
//    if( out == NULL || outlen < S->outlen )
//        return -1;
//    
//    if( blake2s_is_lastblock( S ) )
//        return -1;
//    
//    blake2s_increment_counter( S, (uint32_t)S->buflen );
//    blake2s_set_lastblock( S );
//    memset( S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen ); /* Padding */
//    blake2s_compress( S, S->buf );
//    
//    for( i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
//        store32( buffer + sizeof( S->h[i] ) * i, S->h[i] );
//        
//        memcpy( out, buffer, S->outlen );
//        secure_zero_memory( buffer, sizeof(buffer) );
}

