
#include <stdio.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <string>

using namespace std;

namespace ALG {
    static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    int64_t base58_encode(const string &data, string &cipher) {
      //  int64_t res = ERR_SUCCESS;

        const unsigned char *bytes = NULL;
        unsigned char *digBuf = NULL;
        char *cipBuf = NULL;

        int cipBufLen = 0;
        int digBufLen = 1;
        bool zmark = true;

        size_t dataLen = data.length();
        if (dataLen == 0) {
            cout << "base58_encode data is empty" << endl;
            goto end;
        }

        digBuf = (unsigned char *)calloc(1, dataLen * 137 / 100 + 1);
        if (digBuf == NULL) {
            cout << "base58_encode calloc failure" << endl;
       //     res = ERR_BASE58_ENCODE_FAILED;
            goto end;
        }

        bytes = (const unsigned char *)data.c_str();
        for (int i = 0; i < dataLen; i++) {
            unsigned int carry = (unsigned int)bytes[i];
            if (zmark && carry == 0) {
                cipBufLen++;
            } else {
                zmark = false;
            }

            for (int j = 0; j < digBufLen; j++) {
                carry += (unsigned int) (digBuf[j]) << 8;
                digBuf[j] = (unsigned char)(carry % 58);
                carry /= 58;
            }

            while (carry > 0) {
                digBuf[digBufLen++] = (unsigned char) (carry % 58);
                carry /= 58;
            }
        }

        cipBuf = (char *)calloc(1, cipBufLen + digBufLen);
        if (cipBuf == NULL) {
            cout << "base58_encode calloc failure" << endl;
         //   res = ERR_BASE58_ENCODE_FAILED;
            goto end;
        }

        if (cipBufLen > 0) {
            memset(cipBuf, (int)'1', cipBufLen);
        }

        for (int i = 0; i < digBufLen; i++) {
            cipBuf[cipBufLen++] = b58digits_ordered[digBuf[digBufLen - 1 - i]];
        }

        cipher.assign(cipBuf, cipBuf + cipBufLen);
    end:
        if (digBuf != NULL) {
            free(digBuf);
            digBuf = NULL;
        }

        if (cipBuf != NULL) {
            free(cipBuf);
            cipBuf = NULL;
        }

       // return res;
        return 0;
    }
    
    static const int8_t b58digits_map[] = {
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
        -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
        22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
        -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
        47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
    };
    
    int64_t base58_decode(const string &cipher, string &plain) {
       // int64_t res = ERR_SUCCESS;
        const unsigned char *str = (const unsigned char*)cipher.c_str();
        unsigned char *plainBuf = NULL;
        
        size_t len = cipher.length();
        int plainLen = 1;
        
        if (len == 0) {
        //    res = ERR_BASE58_DECODE_FAILED;
            cout << "base58_decode cipher is empty" << endl;
            goto end;
        }
        
        plainBuf = (unsigned char *)calloc(1, len);
        if (plainBuf == NULL) {
         //   res = ERR_BASE58_DECODE_FAILED;
            cout << "base58_decode calloc failure" << endl;
            goto end;
        }
        
        plainBuf[0] = 0;
        for (int i = 0; i < len; i++) {
            unsigned int carry = (unsigned int) b58digits_map[str[i]];
            for (int j = 0; j < plainLen; j++) {
                carry += (unsigned int) (plainBuf[j]) * 58;
                plainBuf[j] = (unsigned char) (carry & 0xff);
                carry >>= 8;
            }
            
            while (carry > 0) {
                plainBuf[plainLen++] = (unsigned int) (carry & 0xff);
                carry >>= 8;
            }
        }
        
        for (int i = 0; i < len && str[i] == '1'; i++) {
            plainBuf[plainLen++] = 0;
        }
        
        for (int i = plainLen - 1, z = (plainLen >> 1) + (plainLen & 1); i >= z; i--) {
            int k = plainBuf[i];
            plainBuf[i] = plainBuf[plainLen - i - 1];
            plainBuf[plainLen - i - 1] = k;
        }
        
        plain.assign(plainBuf, plainBuf + plainLen);
    end:
        if (plainBuf != NULL) {
            free(plainBuf);
            plainBuf = NULL;
        }
        
      //  return res;
        return 0;
    }
}
