/**
 * @file sm2.h
 * @brief SM2 elliptic curve public key cryptography (Chinese National Standard)
 * 
 * Implements GB/T 32918-2016 specification for:
 * - Key generation
 * - Digital signature
 * - Key exchange
 * - Public key encryption
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CRYPTO_SM2_H
#define KCTSB_CRYPTO_SM2_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// SM2 key sizes
#define KCTSB_SM2_PRIVATE_KEY_SIZE  32
#define KCTSB_SM2_PUBLIC_KEY_SIZE   64  // X and Y coordinates
#define KCTSB_SM2_SIGNATURE_SIZE    64  // r and s values

// SM2 key pair structure
typedef struct {
    uint8_t private_key[KCTSB_SM2_PRIVATE_KEY_SIZE];
    uint8_t public_key[KCTSB_SM2_PUBLIC_KEY_SIZE];
} kctsb_sm2_keypair_t;

// SM2 signature structure
typedef struct {
    uint8_t r[32];
    uint8_t s[32];
} kctsb_sm2_signature_t;

/**
 * @brief Generate SM2 key pair
 * @param keypair Output key pair
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm2_generate_keypair(kctsb_sm2_keypair_t* keypair);

/**
 * @brief SM2 digital signature
 * @param private_key 32-byte private key
 * @param public_key 64-byte public key (for Z value computation)
 * @param user_id User ID string (default: "1234567812345678")
 * @param user_id_len User ID length
 * @param message Message to sign
 * @param message_len Message length
 * @param signature Output signature
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm2_sign(
    const uint8_t private_key[32],
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    kctsb_sm2_signature_t* signature
);

/**
 * @brief SM2 signature verification
 * @param public_key 64-byte public key
 * @param user_id User ID string
 * @param user_id_len User ID length
 * @param message Original message
 * @param message_len Message length
 * @param signature Signature to verify
 * @return KCTSB_SUCCESS if valid, KCTSB_ERROR_VERIFICATION_FAILED otherwise
 */
KCTSB_API kctsb_error_t kctsb_sm2_verify(
    const uint8_t public_key[64],
    const uint8_t* user_id,
    size_t user_id_len,
    const uint8_t* message,
    size_t message_len,
    const kctsb_sm2_signature_t* signature
);

/**
 * @brief SM2 public key encryption
 * @param public_key 64-byte public key
 * @param plaintext Plaintext to encrypt
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext buffer
 * @param ciphertext_len Output length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm2_encrypt(
    const uint8_t public_key[64],
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext,
    size_t* ciphertext_len
);

/**
 * @brief SM2 private key decryption
 * @param private_key 32-byte private key
 * @param ciphertext Ciphertext to decrypt
 * @param ciphertext_len Ciphertext length
 * @param plaintext Output plaintext buffer
 * @param plaintext_len Output length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sm2_decrypt(
    const uint8_t private_key[32],
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    uint8_t* plaintext,
    size_t* plaintext_len
);

/**
 * @brief SM2 self test
 * @return KCTSB_SUCCESS if all tests pass
 */
KCTSB_API kctsb_error_t kctsb_sm2_self_test(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace kctsb {

/**
 * @brief SM2 key pair
 */
class SM2KeyPair {
public:
    SM2KeyPair();
    explicit SM2KeyPair(const ByteVec& privateKey);
    
    static SM2KeyPair generate();
    
    ByteVec getPrivateKey() const;
    ByteVec getPublicKey() const;
    
private:
    kctsb_sm2_keypair_t keypair_;
};

/**
 * @brief SM2 cryptography class
 */
class SM2 {
public:
    // Signature operations
    static ByteVec sign(
        const SM2KeyPair& keypair,
        const ByteVec& message,
        const std::string& userId = "1234567812345678"
    );
    
    static bool verify(
        const ByteVec& publicKey,
        const ByteVec& message,
        const ByteVec& signature,
        const std::string& userId = "1234567812345678"
    );
    
    // Encryption operations
    static ByteVec encrypt(const ByteVec& publicKey, const ByteVec& plaintext);
    static ByteVec decrypt(const ByteVec& privateKey, const ByteVec& ciphertext);
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CRYPTO_SM2_H
