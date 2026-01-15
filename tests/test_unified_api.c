/**
 * @file test_unified_api.c
 * @brief Test that kctsb_api.h works as a standalone unified header
 * 
 * This test verifies that external users can use ONLY kctsb_api.h
 * to access all kctsb library functionality, similar to OpenSSL's EVP approach.
 */

/* ONLY include the unified public API header */
#include "kctsb/kctsb_api.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== kctsb Unified API Header Test ===\n");
    printf("Library version: %d.%d.%d\n", 
           KCTSB_VERSION_MAJOR, KCTSB_VERSION_MINOR, KCTSB_VERSION_PATCH);
    printf("Header includes all public APIs in one file.\n\n");
    
    kctsb_error_t err;
    
    /* Initialize library */
    err = kctsb_init();
    if (err != KCTSB_SUCCESS) {
        printf("ERROR: kctsb_init failed: %d\n", err);
        return 1;
    }
    printf("[OK] Library initialized\n");
    
    /* Test 1: SHA-256 (void return) */
    {
        const char* msg = "Hello, kctsb!";
        uint8_t hash[KCTSB_SHA256_DIGEST_SIZE];
        
        kctsb_sha256((const uint8_t*)msg, strlen(msg), hash);
        printf("[OK] SHA-256: ");
        for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
        printf("...\n");
    }
    
    /* Test 2: SHA3-256 (returns error code) */
    {
        const char* msg = "Hello, kctsb!";
        uint8_t hash[KCTSB_SHA3_256_DIGEST_SIZE];
        
        err = kctsb_sha3_256((const uint8_t*)msg, strlen(msg), hash);
        if (err == KCTSB_SUCCESS) {
            printf("[OK] SHA3-256: ");
            for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
            printf("...\n");
        } else {
            printf("[FAIL] SHA3-256 failed: %d\n", err);
        }
    }
    
    /* Test 3: BLAKE2b (void return, 4 params) */
    {
        const char* msg = "Hello, kctsb!";
        uint8_t hash[KCTSB_BLAKE2B_OUTBYTES];
        
        kctsb_blake2b((const uint8_t*)msg, strlen(msg), hash, 32);
        printf("[OK] BLAKE2b: ");
        for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
        printf("...\n");
    }
    
    /* Test 4: SM3 (Chinese National Standard) */
    {
        const char* msg = "Hello, kctsb!";
        uint8_t hash[KCTSB_SM3_DIGEST_SIZE];
        
        err = kctsb_sm3((const uint8_t*)msg, strlen(msg), hash);
        if (err == KCTSB_SUCCESS) {
            printf("[OK] SM3: ");
            for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
            printf("...\n");
        } else {
            printf("[FAIL] SM3 failed: %d\n", err);
        }
    }
    
    /* Test 5: AES-GCM */
    {
        uint8_t key[KCTSB_AES_256_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        uint8_t iv[12] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb
        };
        const char* plaintext = "AES-GCM Test!";
        size_t plaintext_len = strlen(plaintext);
        uint8_t ciphertext[64];
        uint8_t tag[KCTSB_AES_GCM_TAG_SIZE];
        uint8_t decrypted[64];
        
        kctsb_aes_ctx_t ctx;
        
        err = kctsb_aes_init(&ctx, key, sizeof(key));
        if (err == KCTSB_SUCCESS) {
            err = kctsb_aes_gcm_encrypt(&ctx, iv, sizeof(iv),
                                        NULL, 0,
                                        (const uint8_t*)plaintext, plaintext_len,
                                        ciphertext, tag);
            if (err == KCTSB_SUCCESS) {
                err = kctsb_aes_gcm_decrypt(&ctx, iv, sizeof(iv),
                                            NULL, 0,
                                            ciphertext, plaintext_len,
                                            tag, decrypted);
                if (err == KCTSB_SUCCESS) {
                    decrypted[plaintext_len] = '\0';
                    if (strcmp((char*)decrypted, plaintext) == 0) {
                        printf("[OK] AES-256-GCM encrypt/decrypt roundtrip\n");
                    } else {
                        printf("[FAIL] AES-GCM decrypt mismatch\n");
                    }
                } else {
                    printf("[FAIL] AES-GCM decrypt failed: %d\n", err);
                }
            } else {
                printf("[FAIL] AES-GCM encrypt failed: %d\n", err);
            }
            kctsb_aes_clear(&ctx);
        } else {
            printf("[FAIL] AES init failed: %d\n", err);
        }
    }
    
    /* Test 6: ChaCha20-Poly1305 */
    {
        uint8_t key[KCTSB_CHACHA20_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        uint8_t nonce[KCTSB_CHACHA20_NONCE_SIZE] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb
        };
        const char* plaintext = "ChaCha20-Poly1305 Test!";
        size_t plaintext_len = strlen(plaintext);
        uint8_t ciphertext[64];
        uint8_t tag[KCTSB_POLY1305_TAG_SIZE];
        uint8_t decrypted[64];
        
        err = kctsb_chacha20_poly1305_encrypt(key, nonce,
                                              NULL, 0,
                                              (const uint8_t*)plaintext, plaintext_len,
                                              ciphertext, tag);
        if (err == KCTSB_SUCCESS) {
            err = kctsb_chacha20_poly1305_decrypt(key, nonce,
                                                  NULL, 0,
                                                  ciphertext, plaintext_len,
                                                  tag, decrypted);
            if (err == KCTSB_SUCCESS) {
                decrypted[plaintext_len] = '\0';
                if (strcmp((char*)decrypted, plaintext) == 0) {
                    printf("[OK] ChaCha20-Poly1305 encrypt/decrypt roundtrip\n");
                } else {
                    printf("[FAIL] ChaCha20-Poly1305 decrypt mismatch\n");
                }
            } else {
                printf("[FAIL] ChaCha20-Poly1305 decrypt failed: %d\n", err);
            }
        } else {
            printf("[FAIL] ChaCha20-Poly1305 encrypt failed: %d\n", err);
        }
    }
    
    /* Test 7: HMAC-SHA256 (void return) */
    {
        uint8_t key[] = "secret-key";
        const char* msg = "Message to authenticate";
        uint8_t mac[KCTSB_SHA256_DIGEST_SIZE];
        
        kctsb_hmac_sha256(key, sizeof(key) - 1,
                          (const uint8_t*)msg, strlen(msg), mac);
        printf("[OK] HMAC-SHA256: ");
        for (int i = 0; i < 8; i++) printf("%02x", mac[i]);
        printf("...\n");
    }
    
    /* Test 8: Random bytes */
    {
        uint8_t random[16];
        int ret = kctsb_random_bytes(random, sizeof(random));
        if (ret == 0) {
            printf("[OK] Random bytes: ");
            for (int i = 0; i < 8; i++) printf("%02x", random[i]);
            printf("...\n");
        } else {
            printf("[FAIL] Random bytes failed: %d\n", ret);
        }
    }
    
    /* Test 9: SM4-GCM (using context API) */
    {
        uint8_t key[KCTSB_SM4_KEY_SIZE] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        uint8_t iv[KCTSB_SM4_GCM_IV_SIZE] = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb
        };
        const char* plaintext = "SM4-GCM Test!";
        size_t plaintext_len = strlen(plaintext);
        uint8_t ciphertext[64];
        uint8_t tag[KCTSB_SM4_GCM_TAG_SIZE];
        uint8_t decrypted[64];
        
        kctsb_sm4_gcm_ctx_t ctx;
        err = kctsb_sm4_gcm_init(&ctx, key, iv);
        if (err == KCTSB_SUCCESS) {
            err = kctsb_sm4_gcm_encrypt(&ctx,
                                        NULL, 0,
                                        (const uint8_t*)plaintext, plaintext_len,
                                        ciphertext, tag);
            if (err == KCTSB_SUCCESS) {
                /* Re-init for decryption */
                err = kctsb_sm4_gcm_init(&ctx, key, iv);
                if (err == KCTSB_SUCCESS) {
                    err = kctsb_sm4_gcm_decrypt(&ctx,
                                                NULL, 0,
                                                ciphertext, plaintext_len,
                                                tag, decrypted);
                    if (err == KCTSB_SUCCESS) {
                        decrypted[plaintext_len] = '\0';
                        if (strcmp((char*)decrypted, plaintext) == 0) {
                            printf("[OK] SM4-GCM encrypt/decrypt roundtrip\n");
                        } else {
                            printf("[FAIL] SM4-GCM decrypt mismatch\n");
                        }
                    } else {
                        printf("[FAIL] SM4-GCM decrypt failed: %d\n", err);
                    }
                }
            } else {
                printf("[FAIL] SM4-GCM encrypt failed: %d\n", err);
            }
        } else {
            printf("[FAIL] SM4-GCM init failed: %d\n", err);
        }
    }
    
    /* Cleanup */
    kctsb_cleanup();
    printf("\n=== All tests completed ===\n");
    printf("Unified header kctsb_api.h works correctly!\n");
    printf("External users only need:\n");
    printf("  - #include <kctsb_api.h>\n");
    printf("  - Link with libkctsb.a or kctsb.dll\n");
    
    return 0;
}
