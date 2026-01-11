
#include "tblake2x.hpp"

#include "tblake2_impl.h"
#include "tblake2_locl.h"

namespace ALG {
    typedef struct tblake2xb_ctx_st {
        TBLAKE2B_CTX S[1];
        TBLAKE2B_PARAM P[1];
    } tblake2xb_ctx_st;
    
    typedef struct tblake2xs_ctx_st {
        TBLAKE2S_CTX S[1];
        TBLAKE2S_PARAM P[1];
    } tblake2xs_ctx_st;
    
    int tblake2xs_init(tblake2xs_ctx_st *S, const size_t outLen);
    int tblake2xs_init_key(tblake2xs_ctx_st *S, const size_t outLen, const void *key, size_t keyLen);
    int tblake2xs_update(tblake2xs_ctx_st *S, const void *in, size_t inLen);
    int tblake2xs_final(tblake2xs_ctx_st *S, void *out, size_t outLen);
    
    int tblake2xb_init(tblake2xb_ctx_st *S, const size_t outLen);
    int tblake2xb_init_key(tblake2xb_ctx_st *S, const size_t outLen, const void *key, size_t keyLen);
    int tblake2xb_update(tblake2xb_ctx_st *S, const void *in, size_t inLen);
    int tblake2xb_final(tblake2xb_ctx_st *S, void *out, size_t outLen);
    
    int tblake2xs_init(tblake2xs_ctx_st *S, const size_t outLen) {
        return tblake2xs_init_key(S, outLen, NULL, 0);
    }
    
    int tblake2xs_init_key(tblake2xs_ctx_st *S, const size_t outLen, const void *key, size_t keyLen) {
        if (outLen == 0 || outLen > 0xFFFFUL) {
            return -1;
        }
        
        if (key != NULL && keyLen > TBLAKE2B_KEYBYTES) {
            return -1;
        }
        
        if (key == NULL && keyLen > 0) {
            return -1;
        }
        
        S->P->depth = 1;
        S->P->fanout = 1;
        S->P->key_length = keyLen;
        S->P->digest_length = TBLAKE2S_OUTBYTES;
        
        tstore32((uint8_t *)&S->P->leaf_length, 0);
        tstore32((uint8_t *)&S->P->node_offset, 0);
        tstore16((uint8_t *)&S->P->xof_length, outLen);
        
        S->P->node_depth = 0;
        S->P->inner_length = 0;
        memset( S->P->salt, 0, sizeof(S->P->salt));
        memset( S->P->personal, 0, sizeof(S->P->personal));

        tblake2s_init_param(S->S, S->P);

        if (keyLen > 0) {
            uint8_t block[TBLAKE2S_BLOCKBYTES] = {0};
            memcpy(block, key, keyLen);
            TBLAKE2s_Update(S->S, block, TBLAKE2S_BLOCKBYTES);
            memset(block, 0, TBLAKE2S_BLOCKBYTES);
        }
        
        return 1;
    }
    
    int tblake2xs_update(tblake2xs_ctx_st *S, const void *in, size_t inLen) {
        return TBLAKE2s_Update(S->S, in, inLen);
    }
    
    int tblake2xs_final(tblake2xs_ctx_st *S, void *out, size_t outLen) {
        TBLAKE2S_CTX C[1];
        TBLAKE2S_PARAM P[1];
        
        uint16_t xof_length = tload16(&S->P->xof_length);
        uint8_t root[TBLAKE2S_BLOCKBYTES];
        size_t i;
        
        if (NULL == out) {
            return -1;
        }
        
        /* outlen must match the output size defined in xof_length, */
        /* unless it was -1, in which case anything goes except 0. */
        if (xof_length == 0xFFFFUL) {
            if (outLen == 0) {
                return -1;
            }
        } else {
            if (outLen != xof_length) {
                return -1;
            }
        }
        
        /* Finalize the root hash */
        if (TBLAKE2s_Final(root, S->S, TBLAKE2S_OUTBYTES) < 0) {
            return -1;
        }
        
        /* Set common block structure values */
        /* Copy values from parent instance, and only change the ones below */
        memcpy(P, S->P, sizeof(TBLAKE2S_PARAM));
        P->key_length = 0;
        P->fanout = 0;
        P->depth = 0;
        tstore32((uint8_t *)&P->leaf_length, TBLAKE2S_OUTBYTES);
        P->inner_length = TBLAKE2S_OUTBYTES;
        P->node_depth = 0;
        
        for (i = 0; outLen > 0; ++i) {
            const size_t block_size = (outLen < TBLAKE2S_OUTBYTES) ? outLen : TBLAKE2S_OUTBYTES;
            /* Initialize state */
            P->digest_length = block_size;
            tstore32((uint8_t *)&P->node_offset, (uint32_t)i);
            tblake2s_init_param(C, P);
            /* Process key if needed */
            TBLAKE2s_Update(C, root, TBLAKE2S_OUTBYTES);
            if (TBLAKE2s_Final((uint8_t *)out + i * TBLAKE2S_OUTBYTES, C, block_size) < 0) {
                return -1;
            }
            
            outLen -= block_size;
        }
        
        memset(root, 0, sizeof(root));
        memset(P, 0, sizeof(P));
        memset(C, 0, sizeof(C));
        
        return 1;
    }
    
    
    
    int tblake2xb_init(tblake2xb_ctx_st *S, const size_t outLen) {
        return tblake2xb_init_key(S, outLen, NULL, 0);
    }
    
    int tblake2xb_init_key(tblake2xb_ctx_st *S, const size_t outLen, const void *key, size_t keyLen) {
        if (outLen == 0 || outLen > 0xFFFFFFFFUL) {
            return -1;
        }
        
        if (key != NULL && keyLen > TBLAKE2B_KEYBYTES) {
            return -1;
        }
        
        if (key == NULL && keyLen > 0) {
            return -1;
        }
        
        S->P->digest_length = TBLAKE2B_OUTBYTES;
        S->P->key_length    = keyLen;
        S->P->fanout        = 1;
        S->P->depth         = 1;
        tstore32((uint8_t *)&S->P->leaf_length, 0);
        tstore32((uint8_t *)&S->P->node_offset, 0);
        tstore32((uint8_t *)&S->P->xof_length, (uint32_t)outLen);
        
        S->P->node_depth    = 0;
        S->P->inner_length  = 0;
        memset(S->P->reserved, 0, sizeof(S->P->reserved));
        memset(S->P->salt,     0, sizeof(S->P->salt));
        memset(S->P->personal, 0, sizeof(S->P->personal));
        
        tblake2b_init_param(S->S, S->P);
        
        if (keyLen > 0) {
            uint8_t block[TBLAKE2B_BLOCKBYTES] = {0};
            memcpy(block, key, keyLen);
            TBLAKE2b_Update(S->S, block, TBLAKE2B_BLOCKBYTES);
            memset(block, 0, TBLAKE2B_BLOCKBYTES);
        }
        
        return 1;
    }
    
    int tblake2xb_update(tblake2xb_ctx_st *S, const void *in, size_t inLen) {
        return TBLAKE2b_Update(S->S, in, inLen);
    }
    
    int tblake2xb_final(tblake2xb_ctx_st *S, void *out, size_t outLen) {
        TBLAKE2B_CTX C[1];
        TBLAKE2B_PARAM P[1];
        uint32_t xof_length = tload32((uint8_t *)&S->P->xof_length);
        uint8_t root[TBLAKE2B_BLOCKBYTES];
        size_t i;
        
        if (out == NULL) {
            return -1;
        }
        
        if (xof_length == 0xFFFFFFFFUL) {
            if(outLen == 0) {
                return -1;
            }
        } else {
            if (outLen != xof_length) {
                return -1;
            }
        }
        
        if (TBLAKE2b_Final(root, S->S, TBLAKE2B_OUTBYTES) < 0) {
            return -1;
        }
        
        memcpy(P, S->P, sizeof(tblake2b_param_st));
        P->key_length = 0;
        P->fanout = 0;
        P->depth = 0;
        tstore32((uint8_t *)&P->leaf_length, TBLAKE2B_OUTBYTES);
        P->inner_length = TBLAKE2B_OUTBYTES;
        P->node_depth = 0;
        
        for (i = 0; outLen > 0; ++i) {
            const size_t block_size = (outLen < TBLAKE2B_OUTBYTES) ? outLen : TBLAKE2B_OUTBYTES;
            P->digest_length = block_size;
            tstore32((uint8_t *)&P->node_offset, (uint32_t)i);
            tblake2b_init_param(C, P);
            TBLAKE2b_Update(C, root, TBLAKE2B_OUTBYTES);
            if (TBLAKE2b_Final((uint8_t *)out + i * TBLAKE2B_OUTBYTES, C, block_size) != 1) {
                return -1;
            }

            outLen -= block_size;
        }
        
        memset(root, 0, sizeof(root));
        memset(P, 0, sizeof(P));
        memset(C, 0, sizeof(C));
        
        return 1;
    }
    
    int tblake2xs_data_md(const string &data, unsigned char *md, unsigned int outLen) {
        tblake2xs_ctx_st ctx;
        if (tblake2xs_init(&ctx, (size_t)outLen) != 1) {
            return -1;
        }
        
        if (tblake2xs_update(&ctx, data.c_str(), data.length()) != 1) {
            return -1;
        }
        
        if (tblake2xs_final(&ctx, md, outLen) != 1) {
            return -1;
        }
        
        return 1;
    }
    
    int tblake2xb_data_md(const string &data, unsigned char *md, unsigned int outLen) {
        tblake2xb_ctx_st ctx;
        if (tblake2xb_init(&ctx, (size_t)outLen) != 1) {
            return -1;
        }
        
        if (tblake2xb_update(&ctx, data.c_str(), data.length()) != 1) {
            return -1;
        }
        
        if (tblake2xb_final(&ctx, md, outLen) != 1) {
            return -1;
        }
        
        return 1;
    }
    
}
