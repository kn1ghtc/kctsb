
#include <stdio.h>

#include <openssl/evp.h>

#include "algApi.h"
#include "tsbBase64.h"
#include "tsbUtility.h"
//#include "tblake2x.hpp"


namespace ALG {
    int64_t blake(const string &data, const TBlakeMode mode, string &md, unsigned int mdLen) {
        int64_t res = ERR_SUCCESS;
        unsigned int digest_len = EVP_MAX_MD_SIZE;
        unsigned char *digest = NULL;
        EVP_MD_CTX *md_ctx = NULL;
        
        if (data.length() == 0 || mode >= Blake_count) {
            std::cout << "alg blake param err" << endl;
            res = ERR_PARAM_INVALID;
            goto blakEnd;
        }
        
#if defined(tsb_blake_2x_switch) && tsb_blake_2x_switch > 0
        if (mode == Blake_2x_b || mode == Blake_2x_s) {
            digest_len = mdLen;
            digest = (unsigned char *)calloc(1, digest_len + 1);
            if (digest == NULL) {
                std::cout << "alg blake calloc failed!!!" << endl;
                res = ERR_EVP_INVALID;
                goto blakEnd;
            }
            
            if ((mode == Blake_2x_b && tblake2xb_data_md(data, digest, digest_len) != 1) || (mode == Blake_2x_s && tblake2xs_data_md(data, digest, digest_len) != 1)) {
                std::cout << "alg blake 2x failed!!!" << endl;
                res = ERR_EVP_INVALID;
                goto blakEnd;
            }
            
            md.assign(digest, digest + digest_len);
//            md = base64_encode(digest, digest_len);
//            md = utility::base64_safe_encode(md);
            goto blakEnd;
        }
#endif
        
        md_ctx = EVP_MD_CTX_new();
        if (md_ctx == NULL) {
            std::cout << "alg blake init evp failed!!!" << endl;
            res = ERR_EVP_INVALID;
            goto blakEnd;
        }
        
        if (mode == Blake_2b) {
            if (EVP_DigestInit(md_ctx, EVP_blake2b512()) != 1) {
                std::cout << "alg blake init 2b failed!!!" << endl;
                res = ERR_EVP_INVALID;
                goto blakEnd;
            }
        } else if (mode == Blake_2s) {
            if (EVP_DigestInit(md_ctx, EVP_blake2s256()) != 1) {
                std::cout << "alg blake init 2s failed!!!" << endl;
                res = ERR_EVP_INVALID;
                goto blakEnd;
            }
        } else {
            std::cout << "alg blake mode err" << endl;
            res = ERR_EVP_INVALID;
            goto blakEnd;
        }
        
        if (EVP_DigestUpdate(md_ctx, data.c_str(), data.length()) != 1) {
            std::cout << "alg blake digestUpdate failed!!!" << endl;
            res = ERR_EVP_INVALID;
            goto blakEnd;
        }
        
        digest = (unsigned char *)calloc(1, digest_len + 1);
        if (digest == NULL) {
            std::cout << "alg blake calloc failed!!!" << endl;
            res = ERR_EVP_INVALID;
            goto blakEnd;
        }
        
        if (EVP_DigestFinal(md_ctx, digest, &digest_len) != 1) {
            std::cout << "alg blake digestFinal failed!!!" << endl;
            res = ERR_EVP_INVALID;
            goto blakEnd;
        }
        
        md = base64_encode(digest, digest_len);
        md = utility::base64_safe_encode(md);
    blakEnd:
        if (md_ctx != NULL) {
            EVP_MD_CTX_free(md_ctx);
            md_ctx = NULL;
        }
        
        if (digest != NULL) {
            free(digest);
            digest = NULL;
        }
        
        return res;
    }
}

