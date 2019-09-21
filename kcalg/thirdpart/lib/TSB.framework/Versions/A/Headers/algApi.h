#ifndef __TSB_ALGAPI_H_
#define __TSB_ALGAPI_H_

#include <vector>
#include <chrono>
#include <functional>
#include <string>
#include "tsbCommonApi.h"

using namespace std;
using namespace std::chrono;

typedef enum
{
	ECB = 0, 
    CBC,
    CTR,
    XTS //support 128 and 256 bit
    
	/*
    CFB = 2 //temporary not support
	*/
}_AESMode;

typedef enum {
    TECB = 0,
    TCBC,
    TCFB,
    TCTR,
    TOFB,
    TCount,
} TSymEncryptMode;

namespace ALG
{
	/*ECC notice the key is safe base64 format*/
	int64_t ecc_generateKey(std::string &pubKey,std::string &priKey);
	int64_t ecc_sign(const char * priKey, const BufferArray &context, BufferArray & sigBuffer);
	int64_t ecc_verify(const char * pubKey, const BufferArray &context, const BufferArray &sigBuffer);
	int64_t ecc_encryptData(const char * pubKey, const BufferArray &context, BufferArray &sec_buf);
	int64_t ecc_decryptData(const char * priKey, const BufferArray &context, BufferArray &text_buf);

	void *ecc_getkeybyPrikey(const std::string &priKey);
	void *ecc_getkeybyPubkey(const std::string &pubKey);
	/*AES*/
	int64_t aes_encryptData(const BufferArray &src, BufferArray &des, const char *key, int32_t keyLen, const char * IV, int32_t iMode);
	int64_t aes_decryptData(const BufferArray &src, BufferArray &des, const char *key, int32_t keyLen, const char * IV, int32_t iMode);
	int64_t aes_encryptCCM(unsigned char *plaintext, int32_t plaintext_len, unsigned char *aad,
		int32_t aad_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int32_t *cipherLen, unsigned char *tag, int32_t *tagLen);
	int64_t aes_decryptCCM(unsigned char const *ciphertext, int32_t ciphertext_len, unsigned char *aad,
		int32_t aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, unsigned char *plaintext,int32_t *plainLen);

	/*MD5*/
	int64_t md5_encrypt_file(char *path, int32_t md5_len,BufferArray &output);
	int64_t md5_encrypt_str(unsigned char *str, int32_t len, int32_t md5_len, BufferArray &output);

	/*SHA*/
	int64_t sha256(const unsigned char *str,int32_t len,std::vector<unsigned char> &output);
	int64_t sha512(const unsigned char *str, int32_t len,std::vector<unsigned char> &output);
	int64_t sha3_512(const unsigned char *str,int32_t len,std::vector<unsigned char> &output);
	int64_t sha3_256(const unsigned char *str, int32_t len,std::vector<unsigned char> &output);
	int64_t shaRand(const unsigned char *str, int32_t inputLen,int32_t outLen,std::vector<unsigned char> &output);
	bool PKCS5_PBKDF2_HMAC(const char *pass, int32_t passlen,unsigned char *salt, int32_t saltlen, int32_t iter,
		int32_t keylen, unsigned char *out, int32_t EVP_SHA);
    
    /*******************************************************************************************************************************/
    /* because of algorithm of choosing elliptic curve to encrypt the whole process is similar, so code merging can be done later  */
    /*******************************************************************************************************************************/
    
    /* sm2 api */
    int64_t sm2_generateKey(string &pubKey, string &priKey);
    int64_t sm2_signData(const string &priKey, const string &data, string &signature);
    int64_t sm2_verifyData(const string &pubKey, const string &data, const string &signature);
    int64_t sm2_encryptData(const string &pubKey, const string &data, string &cipherText);
    int64_t sm2_decryptData(const string &priKey, const string &cipherText, string &data);
    
    /* sm3 api */
    int64_t sm3(const string &data, string &md);
    
    /* sm4 api */
    int64_t sm4_encryptData(const string &data, const string &key, const string &iv, const TSymEncryptMode mode, string &cipherText);
    int64_t sm4_decryptData(const string cipherText, const string &key, const string &iv, const TSymEncryptMode mode, string &plain);
    
    /* sm9 api */
//    int64_t sm9_generateKey(const string &identifier, string &pubKey, string &priKey);
//    int64_t sm9_signData(const string &priKey, const string &data, string &signature);
//    int64_t sm9_verifyData(const string &identifier, const string &data, const string &signature);
//    int64_t sm9_encryptData(const string &identifier, const string &data, string &cipherText);
//    int64_t sm9_decryptData(const string &priKey, const string &cipherText, string &plainText);
    
    
    /* chacha20-poly1305 api */
    int64_t chacha20_poly1305_encryptData(const string &data, const string &key, const string &iv, const string &aad, string &cipherText);
    int64_t chacha20_poly1305_decryptData(const string &cipherText, const string &key, const string &iv, const string &aad, string &plain);
    
    /* blake api */
    /* note: bake 2x can not use currently */
    typedef enum {
        Blake_2b = 0,
        Blake_2s,
#if defined(tsb_blake_2x_switch) && tsb_blake_2x_switch > 0
//        Blake_2x_b,
//        Blake_2x_s,
#endif
        Blake_count,
    }TBlakeMode;
    
    int64_t blake(const string &data, const TBlakeMode mode, string &md, unsigned int mdLen = 0/* only use for 2x */);
    
    /* rsa api */
    int64_t rsa_generateKey(const unsigned int nBit, string &pubkey, string &prikey);
    int64_t rsa_signData(const string &priKey, const string &data, string &signature);
    int64_t rsa_verifyData(const string &pubKey, const string &data, const string &signature);
    int64_t rsa_encrypData(const string &pubKey, const string &data, string &cipherText);
    int64_t rsa_decrypData(const string &priKey, const string &cipherText, string &plain);
    
    /* eddsa api */
    typedef enum {
        ED_448 = 0, //not support at currently
        ED_25519,
        ED_count,
    } TEDMode;
    
//    int64_t eddsa_generateKey(const TEDMode mode, string &pubKey, string &priKey);
//    int64_t eddsa_signData(const TEDMode mode, const string &priKey, const string &data, string &signature);
//    int64_t eddsa_verifyData(const TEDMode mode, const string &pubKey, const string &data, string &signature);
    
    /* base58 api*/
    int64_t base58_encode(const string &data, string &cipher);
    int64_t base58_decode(const string &cipher, string &plain);
    
    int64_t secp256k1GenerateKey(string &priKey, string &pubKey);
    int64_t secp256k1VerifyData(const string &pubKey, const string &signature, const string &plain);
    int64_t secp256k1SignData(const string &priKey, const string &data, string &signature);
//    int64_t secp256k1EncryptData(const string &pubKey, const string &data, string &cipher);
//    int64_t secp256k1DecryptData(const string priKey, const string &cipher, string &plain);
}

#endif

