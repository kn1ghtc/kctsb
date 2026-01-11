
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "algApi.h"
#include "tsbBase64.h"
#include "tsbUtility.h"


#include "opentsb/kc_sec.h"

namespace ALG {
//#define CHACHA_KEY_SIZE        32
//#define CHACHA_CTR_SIZE        16
//#define CHACHA_BLK_SIZE        64
    
//#define POLY1305_BLOCK_SIZE  16
//#define POLY1305_DIGEST_SIZE 16
//#define POLY1305_KEY_SIZE    32
    static const int64_t kChacha20_key_len = 32;
    static const int64_t kChacha20_iv_max_len = 16;
    static const int64_t kChacha20_block_len = 64;
    static const int64_t kChacha20_poly1305_md_len = 16;
    
    int64_t chacha20_poly1305_encryptData(const string &data, const string &key, const string &iv, const string &aad, string &cipherText) {
        int64_t res = ERR_SUCCESS;
        unsigned char *oMemBuffer = NULL;
        unsigned char mac[17] = {0};
        int block_num = (int)data.size() / kChacha20_block_len + 1;
        int oMemLen = 0;
        int tmpMemLen = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100001L
        EVP_CIPHER_CTX ctxbase;
        EVP_CIPHER_CTX * md_ctx = &ctxbase;
#else
        EVP_CIPHER_CTX *md_ctx = NULL;
#endif
        
        if (data.length() == 0 || iv.length() > kChacha20_iv_max_len || aad.length() != EVP_AEAD_TLS1_AAD_LEN) {
            res = ERR_PARAM_INVALID;
            goto end;
        }
        
#if OPENSSL_VERSION_NUMBER < 0x10100001L
        EVP_CIPHER_CTX_init(md_ctx);
#else
        md_ctx = EVP_CIPHER_CTX_new();
        if (md_ctx == NULL) {
            res = ERR_EVP_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_CIPHER_CTX_new failure" << endl;
            goto end;
        }
#endif
        
        if (EVP_EncryptInit_ex(md_ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_EncryptInit_ex failure" << endl;
            goto end;
        }
        
        if (EVP_CIPHER_CTX_ctrl(md_ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv.length(), NULL) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_CIPHER_CTX_ctrl set iv len failure" << endl;
            goto end;
        }
        
        if (EVP_CIPHER_CTX_ctrl(md_ctx, EVP_CTRL_AEAD_SET_TAG, kChacha20_poly1305_md_len, NULL) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_CIPHER_CTX_ctrl set tag len failure" << endl;
            goto end;
        }
        
        if (EVP_EncryptInit_ex(md_ctx, NULL, NULL, (unsigned char *)key.c_str(), (unsigned char *)iv.c_str()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_CIPHER_CTX_ctrl update key and iv failure" << endl;
            goto end;
        }
        
        //EVP_AEAD_TLS1_AAD_LEN
        if (EVP_EncryptUpdate(md_ctx, NULL, &tmpMemLen, (unsigned char *)aad.c_str(), (int)aad.length()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_CIPHER_CTX_ctrl set aad failure" << endl;
            goto end;
        }
        
//        if (EVP_CIPHER_CTX_ctrl(md_ctx, EVP_CTRL_AEAD_TLS1_AAD, (int)aad.length(), (unsigned char *)aad.c_str()) != 16) {
//            res = ERR_PARAM_INVALID;
//            cout << "tsb chacha20_poly1305_encrypt EVP_CIPHER_CTX_ctrl set aad failure" << endl;
//            goto end;
//        }
        
        oMemBuffer = (unsigned char *)calloc(1, block_num * kChacha20_block_len + 1);
        if (oMemBuffer == NULL) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt calloc failure" << endl;
            goto end;
        }
        
        if (EVP_EncryptUpdate(md_ctx, oMemBuffer, &tmpMemLen, (unsigned char *)data.c_str(), (int)data.length()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_CipherUpdate failure" << endl;
            goto end;
        }
        
        oMemLen = tmpMemLen;
        if (EVP_EncryptFinal(md_ctx, oMemBuffer, &tmpMemLen) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_EncryptFinal failure" << endl;
            goto end;
        }
        
        oMemLen += tmpMemLen;
        
        if (1 != EVP_CIPHER_CTX_ctrl(md_ctx, EVP_CTRL_AEAD_GET_TAG, 16, mac)) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_encrypt EVP_CIPHER_CTX_ctrl failure" << endl;
            goto end;
        }
        cipherText.assign(mac, mac + 16);
        cipherText.append(string(oMemBuffer, oMemBuffer + oMemLen));
        cipherText = utility::base64_safe_encode(base64_encode((unsigned char *)cipherText.c_str(), (int)cipherText.length()));
    end:
        if (oMemBuffer != NULL) {
            free(oMemBuffer);
            oMemBuffer = NULL;
        }
        
#if OPENSSL_VERSION_NUMBER < 0x10100001L
        EVP_CIPHER_CTX_cleanup(md_ctx);
#else
        if (md_ctx) {
            EVP_CIPHER_CTX_free(md_ctx);
            md_ctx = NULL;
        }
#endif
        return res;
    }
    
    int64_t chacha20_poly1305_decryptData(const string &cipherText, const string &key, const string &iv, const string &aad, string &plain) {
        int64_t res = ERR_SUCCESS;
        unsigned char *oMemBuffer = NULL;//(unsigned char *)calloc(1, 1024);
        int oMemLen = 0;
        int tmpMemLen = 0;
        string cipher = base64_decode(utility::base64_safe_decode(cipherText));
        string poly_md = "";
#if OPENSSL_VERSION_NUMBER < 0x10100001L
        EVP_CIPHER_CTX ctxbase;
        EVP_CIPHER_CTX * md_ctx = &ctxbase;
#else
        EVP_CIPHER_CTX *md_ctx = NULL;
#endif
        
        if (cipherText.length() == 0 || iv.length() > kChacha20_iv_max_len || aad.length() != EVP_AEAD_TLS1_AAD_LEN) {
            res = ERR_PARAM_INVALID;
            goto end;
        }
        
        poly_md = cipher.substr(0, kChacha20_poly1305_md_len);
        cipher = cipher.substr(kChacha20_poly1305_md_len, cipher.size() - kChacha20_poly1305_md_len);
#if OPENSSL_VERSION_NUMBER < 0x10100001L
        EVP_CIPHER_CTX_init(md_ctx);
#else
        md_ctx = EVP_CIPHER_CTX_new();
        if (md_ctx == NULL) {
            res = ERR_EVP_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_CIPHER_CTX_new failure" << endl;
            goto end;
        }
#endif
        
        if (EVP_DecryptInit_ex(md_ctx, EVP_chacha20_poly1305(), NULL, (unsigned char *)key.c_str(), (unsigned char *)iv.c_str()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_DecryptInit_ex failure" << endl;
            goto end;
        }
        
        if (EVP_CIPHER_CTX_ctrl(md_ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv.length(), NULL) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_CIPHER_CTX_ctrl set iv len failure" << endl;
            goto end;
        }
        
        if (EVP_CIPHER_CTX_ctrl(md_ctx, EVP_CTRL_AEAD_SET_TAG, kChacha20_poly1305_md_len, (void *)poly_md.c_str()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_CIPHER_CTX_ctrl set tag len failure" << endl;
            goto end;
        }
        
        if (EVP_DecryptInit_ex(md_ctx, NULL, NULL, (unsigned char *)key.c_str(), (unsigned char *)iv.c_str()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_CIPHER_CTX_ctrl update key and iv failure" << endl;
            goto end;
        }
        
        if (EVP_DecryptUpdate(md_ctx, NULL, &tmpMemLen, (unsigned char *)aad.c_str(), (int)aad.length()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_CIPHER_CTX_ctrl set aad failure" << endl;
            goto end;
        }
        
        oMemBuffer = (unsigned char *)calloc(1, 1024 + cipher.size());
        if (oMemBuffer == NULL) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt calloc failure" << endl;
            goto end;
        }
        
        if (EVP_DecryptUpdate(md_ctx, oMemBuffer, &tmpMemLen, (unsigned char *)cipher.c_str(), (int)cipher.length()) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_DecryptUpdate failure" << endl;
            goto end;
        }
        
        oMemLen = tmpMemLen;
        if (EVP_DecryptFinal(md_ctx, oMemBuffer, &tmpMemLen) != 1) {
            res = ERR_PARAM_INVALID;
            cout << "tsb chacha20_poly1305_decrypt EVP_DecryptFinal failure" << endl;
            goto end;
        }
        
        oMemLen += tmpMemLen;
        plain.assign(oMemBuffer, oMemBuffer + oMemLen);
    end:
        if (oMemBuffer != NULL) {
            free(oMemBuffer);
            oMemBuffer = NULL;
        }
        
#if OPENSSL_VERSION_NUMBER < 0x10100001L
        EVP_CIPHER_CTX_cleanup(md_ctx);
#else
        if (md_ctx) {
            EVP_CIPHER_CTX_free(md_ctx);
            md_ctx = NULL;
        }
#endif
        return res;
    }
}
