/**
 * @file test_rsa.cpp
 * @brief RSA cryptosystem unit tests with NTL integration
 * 
 * Tests RSA key generation, encryption, decryption using NTL big integers.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>

// Check if NTL is available
#if defined(KCTSB_HAS_NTL) || defined(KCTSB_USE_NTL)

#include <NTL/ZZ.h>
#include <NTL/vec_ZZ.h>
using namespace NTL;

// RSA functions from kc_rsa.cpp
extern int rsa_getKey(ZZ pubKey[], ZZ privKey[]);
extern ZZ rsa_enc(const ZZ pubKey[], unsigned char *plaintext, long plain_len);
extern int rsa_decy(ZZ cyperTxt_z, ZZ privKey[], unsigned char *plaintext);

// ============================================================================
// RSA Key Generation Tests
// ============================================================================

TEST(RSATest, KeyGeneration) {
    ZZ pubKey[2], privKey[3];
    
    // Generate RSA-2048 keys (1024-bit primes)
    int result = rsa_getKey(pubKey, privKey);
    
    EXPECT_EQ(result, 0) << "Key generation should succeed";
    
    // pubKey[0] = e (public exponent), pubKey[1] = n (modulus)
    // privKey[0] = d (private exponent), privKey[1] = p, privKey[2] = q
    
    // Check public exponent is standard value
    EXPECT_EQ(pubKey[0], ZZ(65537)) << "Public exponent should be 65537";
    
    // Check modulus n = p * q
    ZZ n = privKey[1] * privKey[2];
    EXPECT_EQ(pubKey[1], n) << "Modulus should equal p * q";
    
    // Check key sizes (approximate, due to random generation)
    int n_bits = NumBits(pubKey[1]);
    EXPECT_GE(n_bits, 2040) << "Modulus should be ~2048 bits";
    EXPECT_LE(n_bits, 2056) << "Modulus should be ~2048 bits";
}

TEST(RSATest, PrimeFactorization) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    ZZ p = privKey[1];
    ZZ q = privKey[2];
    ZZ n = pubKey[1];
    
    // Verify p and q are primes
    EXPECT_TRUE(ProbPrime(p, 20)) << "p should be prime";
    EXPECT_TRUE(ProbPrime(q, 20)) << "q should be prime";
    
    // Verify n = p * q
    EXPECT_EQ(n, p * q) << "n must equal p * q";
    
    // Verify p != q (distinct primes)
    EXPECT_NE(p, q) << "p and q must be distinct";
}

TEST(RSATest, EulerTotient) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    ZZ e = pubKey[0];
    ZZ d = privKey[0];
    ZZ p = privKey[1];
    ZZ q = privKey[2];
    
    // Compute Euler's totient: φ(n) = (p-1)(q-1)
    ZZ phi_n = (p - 1) * (q - 1);
    
    // Verify GCD(e, φ(n)) = 1
    EXPECT_EQ(GCD(e, phi_n), ZZ(1)) << "e and φ(n) must be coprime";
    
    // Verify e * d ≡ 1 (mod φ(n))
    ZZ ed_mod_phi = MulMod(e, d, phi_n);
    EXPECT_EQ(ed_mod_phi, ZZ(1)) << "e * d must be ≡ 1 (mod φ(n))";
}

// ============================================================================
// RSA Encryption/Decryption Tests
// ============================================================================

TEST(RSATest, EncryptDecryptSingleByte) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    // Test message: single byte 'A'
    unsigned char plaintext[1] = {0x41};  // 'A'
    unsigned char decrypted[16] = {0};
    
    // Encrypt
    ZZ ciphertext = rsa_enc(pubKey, plaintext, 1);
    
    // Verify ciphertext is within modulus
    EXPECT_LT(ciphertext, pubKey[1]) << "Ciphertext must be < n";
    EXPECT_GE(ciphertext, ZZ(0)) << "Ciphertext must be >= 0";
    
    // Decrypt
    int result = rsa_decy(ciphertext, privKey, decrypted);
    
    // Verify decryption succeeded
    EXPECT_EQ(result, 0) << "Decryption should succeed";
    EXPECT_EQ(decrypted[0], plaintext[0]) << "Decrypted text should match original";
}

TEST(RSATest, EncryptDecryptMessage) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    // Test message: "Hello"
    unsigned char plaintext[] = "Hello";
    unsigned char decrypted[16] = {0};
    
    // RSA can only encrypt data smaller than modulus
    // For multi-byte messages, need hybrid encryption (RSA + symmetric)
    // Here we test each byte separately (textbook RSA)
    
    for (size_t i = 0; i < sizeof(plaintext) - 1; i++) {
        unsigned char single_byte[1] = {plaintext[i]};
        
        ZZ ciphertext = rsa_enc(pubKey, single_byte, 1);
        rsa_decy(ciphertext, privKey, &decrypted[i]);
        
        EXPECT_EQ(decrypted[i], plaintext[i]) 
            << "Byte " << i << " should match after encrypt/decrypt";
    }
}

TEST(RSATest, DifferentPlaintextsProduceDifferentCiphertexts) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    unsigned char plaintext1[1] = {0x41};  // 'A'
    unsigned char plaintext2[1] = {0x42};  // 'B'
    
    ZZ ciphertext1 = rsa_enc(pubKey, plaintext1, 1);
    ZZ ciphertext2 = rsa_enc(pubKey, plaintext2, 1);
    
    EXPECT_NE(ciphertext1, ciphertext2) 
        << "Different plaintexts should produce different ciphertexts";
}

TEST(RSATest, SamePlaintextProducesSameCiphertext) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    unsigned char plaintext[1] = {0x65};  // 0x65 from original test
    
    ZZ ciphertext1 = rsa_enc(pubKey, plaintext, 1);
    ZZ ciphertext2 = rsa_enc(pubKey, plaintext, 1);
    
    EXPECT_EQ(ciphertext1, ciphertext2) 
        << "Same plaintext should produce same ciphertext (deterministic RSA)";
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST(RSATest, EncryptZeroByte) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    unsigned char plaintext[1] = {0x00};
    unsigned char decrypted[16] = {0};
    
    ZZ ciphertext = rsa_enc(pubKey, plaintext, 1);
    
    // 0^e mod n should be 0 for standard RSA
    EXPECT_EQ(ciphertext, ZZ(0)) << "Encrypting 0 should produce 0";
    
    rsa_decy(ciphertext, privKey, decrypted);
    EXPECT_EQ(decrypted[0], 0x00) << "Decrypting 0 should produce 0";
}

TEST(RSATest, EncryptMaxByte) {
    ZZ pubKey[2], privKey[3];
    rsa_getKey(pubKey, privKey);
    
    unsigned char plaintext[1] = {0xFF};
    unsigned char decrypted[16] = {0};
    
    ZZ ciphertext = rsa_enc(pubKey, plaintext, 1);
    rsa_decy(ciphertext, privKey, decrypted);
    
    EXPECT_EQ(decrypted[0], 0xFF) << "Max byte value should round-trip correctly";
}

// ============================================================================
// Original Test Function (Integration Test)
// ============================================================================

extern int test_rsa();  // Original test from kc_rsa.cpp

TEST(RSATest, OriginalTestFunction) {
    int result = test_rsa();
    EXPECT_EQ(result, 0) << "Original test_rsa() should return 0 on success";
}

#else
// NTL not available - skip tests
TEST(RSATest, DISABLED_NTL_NotAvailable) {
    GTEST_SKIP() << "NTL library not available, RSA tests skipped";
}
#endif // KCTSB_HAS_NTL

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
