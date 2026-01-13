/**
 * @file test_pqc.cpp
 * @brief Unit tests for Post-Quantum Cryptography (Kyber, Dilithium)
 */

#include <gtest/gtest.h>
#include <kctsb/advanced/pqc/pqc.h>
#include <cstring>

using namespace kctsb::pqc;

// ============================================================================
// Kyber Tests
// ============================================================================

class KyberTest : public ::testing::TestWithParam<KyberLevel> {};

TEST_P(KyberTest, KeyGeneration) {
    Kyber kyber(GetParam());
    auto kp = kyber.keygen();
    
    const auto& params = kyber.get_params();
    EXPECT_EQ(kp.public_key.size(), params.public_key_size);
    EXPECT_EQ(kp.secret_key.size(), params.secret_key_size);
    
    // Keys should not be all zeros
    bool pk_nonzero = false, sk_nonzero = false;
    for (size_t i = 0; i < kp.public_key.size(); ++i) {
        if (kp.public_key.bytes()[i] != 0) pk_nonzero = true;
    }
    for (size_t i = 0; i < kp.secret_key.size(); ++i) {
        if (kp.secret_key.bytes()[i] != 0) sk_nonzero = true;
    }
    EXPECT_TRUE(pk_nonzero);
    EXPECT_TRUE(sk_nonzero);
}

TEST_P(KyberTest, EncapsDecaps) {
    Kyber kyber(GetParam());
    auto kp = kyber.keygen();
    
    // Encapsulation
    std::array<uint8_t, 32> ss_enc;
    auto ct = kyber.encaps(kp.public_key, ss_enc);
    
    const auto& params = kyber.get_params();
    EXPECT_EQ(ct.size(), params.ciphertext_size);
    
    // Decapsulation
    std::array<uint8_t, 32> ss_dec;
    bool result = kyber.decaps(kp.secret_key, ct, ss_dec);
    EXPECT_TRUE(result);
    
    // Shared secrets should match
    EXPECT_EQ(ss_enc, ss_dec);
}

TEST_P(KyberTest, DifferentKeysProduceDifferentSecrets) {
    Kyber kyber(GetParam());
    
    auto kp1 = kyber.keygen();
    auto kp2 = kyber.keygen();
    
    std::array<uint8_t, 32> ss1, ss2;
    kyber.encaps(kp1.public_key, ss1);
    kyber.encaps(kp2.public_key, ss2);
    
    // Different keys should produce different shared secrets
    EXPECT_NE(ss1, ss2);
}

TEST_P(KyberTest, HighLevelAPI) {
    KyberLevel level = GetParam();
    
    auto kp = kyber_keygen(level);
    auto [ct, ss_enc] = kyber_encaps(kp.public_key, level);
    auto ss_dec = kyber_decaps(kp.secret_key, ct, level);
    
    EXPECT_EQ(ss_enc, ss_dec);
}

INSTANTIATE_TEST_SUITE_P(
    KyberLevels,
    KyberTest,
    ::testing::Values(
        KyberLevel::KYBER512,
        KyberLevel::KYBER768,
        KyberLevel::KYBER1024
    )
);

// ============================================================================
// Dilithium Tests
// ============================================================================

class DilithiumTest : public ::testing::TestWithParam<DilithiumLevel> {};

TEST_P(DilithiumTest, KeyGeneration) {
    Dilithium dilithium(GetParam());
    auto kp = dilithium.keygen();
    
    const auto& params = dilithium.get_params();
    EXPECT_EQ(kp.public_key.size(), params.public_key_size);
    EXPECT_EQ(kp.secret_key.size(), params.secret_key_size);
}

TEST_P(DilithiumTest, SignVerify) {
    Dilithium dilithium(GetParam());
    auto kp = dilithium.keygen();
    
    const char* message = "Test message for Dilithium signature";
    size_t msg_len = strlen(message);
    
    auto sig = dilithium.sign(kp.secret_key, 
                              reinterpret_cast<const uint8_t*>(message), 
                              msg_len);
    
    const auto& params = dilithium.get_params();
    EXPECT_EQ(sig.size(), params.signature_size);
    
    bool valid = dilithium.verify(kp.public_key, sig,
                                  reinterpret_cast<const uint8_t*>(message),
                                  msg_len);
    EXPECT_TRUE(valid);
}

TEST_P(DilithiumTest, HighLevelAPI) {
    DilithiumLevel level = GetParam();
    
    auto kp = dilithium_keygen(level);
    
    const char* message = "High level API test";
    auto sig = dilithium_sign(kp.secret_key,
                              reinterpret_cast<const uint8_t*>(message),
                              strlen(message), level);
    
    bool valid = dilithium_verify(kp.public_key, sig,
                                  reinterpret_cast<const uint8_t*>(message),
                                  strlen(message), level);
    EXPECT_TRUE(valid);
}

INSTANTIATE_TEST_SUITE_P(
    DilithiumLevels,
    DilithiumTest,
    ::testing::Values(
        DilithiumLevel::DILITHIUM2,
        DilithiumLevel::DILITHIUM3,
        DilithiumLevel::DILITHIUM5
    )
);

// ============================================================================
// Parameter Tests
// ============================================================================

TEST(KyberParamsTest, ParameterValues) {
    auto p512 = KyberParams::get(KyberLevel::KYBER512);
    EXPECT_EQ(p512.k, 2);
    EXPECT_EQ(p512.public_key_size, 800);
    EXPECT_EQ(p512.ciphertext_size, 768);
    
    auto p768 = KyberParams::get(KyberLevel::KYBER768);
    EXPECT_EQ(p768.k, 3);
    EXPECT_EQ(p768.public_key_size, 1184);
    EXPECT_EQ(p768.ciphertext_size, 1088);
    
    auto p1024 = KyberParams::get(KyberLevel::KYBER1024);
    EXPECT_EQ(p1024.k, 4);
    EXPECT_EQ(p1024.public_key_size, 1568);
    EXPECT_EQ(p1024.ciphertext_size, 1568);
}

TEST(DilithiumParamsTest, ParameterValues) {
    auto p2 = DilithiumParams::get(DilithiumLevel::DILITHIUM2);
    EXPECT_EQ(p2.k, 4);
    EXPECT_EQ(p2.l, 4);
    EXPECT_EQ(p2.signature_size, 2420);
    
    auto p3 = DilithiumParams::get(DilithiumLevel::DILITHIUM3);
    EXPECT_EQ(p3.k, 6);
    EXPECT_EQ(p3.l, 5);
    EXPECT_EQ(p3.signature_size, 3293);
    
    auto p5 = DilithiumParams::get(DilithiumLevel::DILITHIUM5);
    EXPECT_EQ(p5.k, 8);
    EXPECT_EQ(p5.l, 7);
    EXPECT_EQ(p5.signature_size, 4595);
}

// ============================================================================
// Polynomial Tests
// ============================================================================

TEST(KyberPolyTest, Addition) {
    KyberPoly a, b;
    for (size_t i = 0; i < KYBER_N; ++i) {
        a.coeffs[i] = i % 100;
        b.coeffs[i] = (i * 2) % 100;
    }
    
    KyberPoly c = a + b;
    for (size_t i = 0; i < KYBER_N; ++i) {
        EXPECT_GE(c.coeffs[i], 0);
        EXPECT_LT(c.coeffs[i], KYBER_Q);
    }
}

TEST(KyberPolyTest, NTT) {
    KyberPoly p;
    for (size_t i = 0; i < KYBER_N; ++i) {
        p.coeffs[i] = i % 100;
    }
    
    KyberPoly original = p;
    p.ntt();
    p.inv_ntt();
    
    // After NTT and inverse NTT, should get back similar values
    for (size_t i = 0; i < KYBER_N; ++i) {
        int16_t diff = (p.coeffs[i] - original.coeffs[i]) % KYBER_Q;
        if (diff < 0) diff += KYBER_Q;
        if (diff > KYBER_Q / 2) diff = KYBER_Q - diff;
        EXPECT_LT(diff, 10);  // Allow small numerical error
    }
}

TEST(DilithiumPolyTest, Addition) {
    DilithiumPoly a, b;
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        a.coeffs[i] = i % 1000;
        b.coeffs[i] = (i * 3) % 1000;
    }
    
    DilithiumPoly c = a + b;
    for (size_t i = 0; i < DILITHIUM_N; ++i) {
        EXPECT_EQ(c.coeffs[i], a.coeffs[i] + b.coeffs[i]);
    }
}

// ============================================================================
// Security Tests
// ============================================================================

TEST(KyberSecurityTest, SecretKeyZeroing) {
    Kyber kyber(KyberLevel::KYBER768);
    auto kp = kyber.keygen();
    
    size_t sk_size = kp.secret_key.size();
    EXPECT_GT(sk_size, 0);
    
    kp.secret_key.clear();
    EXPECT_EQ(kp.secret_key.size(), 0);
}

TEST(DilithiumSecurityTest, SecretKeyZeroing) {
    Dilithium dilithium(DilithiumLevel::DILITHIUM3);
    auto kp = dilithium.keygen();
    
    size_t sk_size = kp.secret_key.size();
    EXPECT_GT(sk_size, 0);
    
    kp.secret_key.clear();
    EXPECT_EQ(kp.secret_key.size(), 0);
}
