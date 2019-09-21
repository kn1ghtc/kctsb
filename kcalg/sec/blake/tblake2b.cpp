
#include <assert.h>
#include <string.h>
#include <openssl/crypto.h>

#include "tblake2_locl.h"
#include "tblake2_impl.h"

namespace ALG {
    static const uint64_t tblake2b_IV[8] = {
        0x6a09e667f3bcc908U, 0xbb67ae8584caa73bU,
        0x3c6ef372fe94f82bU, 0xa54ff53a5f1d36f1U,
        0x510e527fade682d1U, 0x9b05688c2b3e6c1fU,
        0x1f83d9abfb41bd6bU, 0x5be0cd19137e2179U
    };
    
    static const uint8_t tblake2b_sigma[12][16] = {
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
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
    };
    
    /* Set that it's the last block we'll compress */
    static inline void tblake2b_set_lastblock(TBLAKE2B_CTX *S) {
        S->f[0] = -1;
    }
    
    /* Initialize the hashing state. */
    static inline void tblake2b_init0(TBLAKE2B_CTX *S) {
        int i;
        
        memset(S, 0, sizeof(TBLAKE2B_CTX));
        for (i = 0; i < 8; ++i) {
            S->h[i] = tblake2b_IV[i];
        }
    }
    
    static int tblake2b_is_lastblock(const tblake2b_ctx_st *S) {
        return S->f[0] != 0;
    }
    
    static void tblake2b_increment_counter(tblake2b_ctx_st *S, const uint64_t inc) {
        S->t[0] += inc;
        S->t[1] += ( S->t[0] < inc );
    }
    
    /* init xors IV with input parameter block */
    void tblake2b_init_param(TBLAKE2B_CTX *S, const TBLAKE2B_PARAM *P) {
        size_t i;
        const uint8_t *p = (const uint8_t *)(P);
        tblake2b_init0(S);
        
        /* The param struct is carefully hand packed, and should be 64 bytes on
         * every platform. */
        assert(sizeof(TBLAKE2B_PARAM) == 64);
        /* IV XOR ParamBlock */
        for (i = 0; i < 8; ++i) {
            S->h[i] ^= tload64(p + sizeof(S->h[i]) * i);
        }
        S->outlen = P->digest_length;
    }
    
    /* Initialize the hashing context.  Always returns 1. */
    int TBLAKE2b_Init(TBLAKE2B_CTX *c, size_t outLen) {
        TBLAKE2B_PARAM P[1];
        P->digest_length = outLen;
        P->key_length    = 0;
        P->fanout        = 1;
        P->depth         = 1;
        tstore32((uint8_t *)&P->leaf_length, 0);
        tstore32((uint8_t *)&P->node_offset, 0);
        tstore32((uint8_t *)&P->xof_length, 0);
        P->node_depth    = 0;
        P->inner_length  = 0;
        memset(P->reserved, 0, sizeof(P->reserved));
        memset(P->salt,     0, sizeof(P->salt));
        memset(P->personal, 0, sizeof(P->personal));
        tblake2b_init_param(c, P);
        return 1;
    }
    
    /* Permute the state while xoring in the block of data. */
    static void tblake2b_compress(TBLAKE2B_CTX *S,
                                  const uint8_t *blocks,
                                  size_t len) {
        uint64_t m[16];
        uint64_t v[16];
        int i;
        size_t increment;

        assert(len < TBLAKE2B_BLOCKBYTES || len % TBLAKE2B_BLOCKBYTES == 0);
        
        increment = len < TBLAKE2B_BLOCKBYTES ? len : TBLAKE2B_BLOCKBYTES;
        
        for (i = 0; i < 8; ++i) {
            v[i] = S->h[i];
        }
        
        do {
            for (i = 0; i < 16; ++i) {
                m[i] = tload64(blocks + i * sizeof(m[i]));
            }
            
            /* blake2b_increment_counter */
            S->t[0] += increment;
            S->t[1] += (S->t[0] < increment);
            
            v[8]  = tblake2b_IV[0];
            v[9]  = tblake2b_IV[1];
            v[10] = tblake2b_IV[2];
            v[11] = tblake2b_IV[3];
            v[12] = S->t[0] ^ tblake2b_IV[4];
            v[13] = S->t[1] ^ tblake2b_IV[5];
            v[14] = S->f[0] ^ tblake2b_IV[6];
            v[15] = S->f[1] ^ tblake2b_IV[7];
#define G(r,i,a,b,c,d) \
    do { \
        a = a + b + m[tblake2b_sigma[r][2*i+0]]; \
        d = trotr64(d ^ a, 32); \
        c = c + d; \
        b = trotr64(b ^ c, 24); \
        a = a + b + m[tblake2b_sigma[r][2*i+1]]; \
        d = trotr64(d ^ a, 16); \
        c = c + d; \
        b = trotr64(b ^ c, 63); \
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
            /* 3x size reduction on x86_64, almost 7x on ARMv8, 9x on ARMv4 */
            for (i = 0; i < 12; i++) {
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
            ROUND(10);
            ROUND(11);
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
    int TBLAKE2b_Update(TBLAKE2B_CTX *c, const void *data, size_t datalen) {
//        const unsigned char * in = (const unsigned char *)data;
//        if (datalen > 0) {
//            size_t left = c->buflen;
//            size_t fill = TBLAKE2B_BLOCKBYTES - left;
//            if (datalen > fill) {
//                c->buflen = 0;
//                memcpy(c->buf + left, in, fill); /* Fill buffer */
//                tblake2b_increment_counter(c, TBLAKE2B_BLOCKBYTES);
//                tblake2b_compress(c, c->buf); /* Compress */
//                in += fill; datalen -= fill;
//                while(datalen > TBLAKE2B_BLOCKBYTES) {
//                    blake2b_increment_counter(c, TBLAKE2B_BLOCKBYTES);
//                    blake2b_compress(c, in);
//                    in += TBLAKE2B_BLOCKBYTES;
//                    inlen -= TBLAKE2B_BLOCKBYTES;
//                }
//            }
//            memcpy( S->buf + S->buflen, in, inlen );
//            S->buflen += inlen;
//        }
//        return 0;
        
        const uint8_t *in = (uint8_t *)data;
        size_t fill;
        fill = sizeof(c->buf) - c->buflen;
        if (datalen > fill) {
            if (c->buflen) {
                memcpy(c->buf + c->buflen, in, fill); /* Fill buffer */
                tblake2b_compress(c, c->buf, TBLAKE2B_BLOCKBYTES);
                c->buflen = 0;
                in += fill;
                datalen -= fill;
            }
            if (datalen > TBLAKE2B_BLOCKBYTES) {
                size_t stashlen = datalen % TBLAKE2B_BLOCKBYTES;
                stashlen = stashlen ? stashlen : TBLAKE2B_BLOCKBYTES;
                datalen -= stashlen;
                tblake2b_compress(c, in, datalen);
                in += datalen;
                datalen = stashlen;
            }
        }
        assert(datalen <= TBLAKE2B_BLOCKBYTES);
        memcpy(c->buf + c->buflen, in, datalen);
        c->buflen += datalen; /* Be lazy, do not compress */

        return 1;
    }

    /*
     * Calculate the final hash and save it in md.
     * Always returns 1.
     */
    int TBLAKE2b_Final(unsigned char *md, TBLAKE2B_CTX *c, size_t outLen) {
        if (md == NULL || outLen < c->outlen) {
            return -1;
        }
        
        if (tblake2b_is_lastblock(c)) {
            return -1;
        }
        
        
        tblake2b_increment_counter(c, c->buflen);
        tblake2b_set_lastblock(c);
        memset(c->buf + c->buflen, 0, TBLAKE2B_BLOCKBYTES - c->buflen);
        
        
        tblake2b_set_lastblock(c);
        /* Padding */
        memset(c->buf + c->buflen, 0, sizeof(c->buf) - c->buflen);
        tblake2b_compress(c, c->buf, c->buflen);
        
        /* Output full hash to message digest */
//        outLen = outLen / 8 + (outLen % 8 == 0 ? 0 : 1);
        for (int i = 0; i < 8; ++i) {
            tstore64(md + sizeof(c->h[i]) * i, c->h[i]);
        }
        
        OPENSSL_cleanse(c, sizeof(TBLAKE2B_CTX));
        return 1;
    }

}
