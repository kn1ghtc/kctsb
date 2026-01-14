/**
 * @file test_simd.cpp
 * @brief Unit tests for SIMD acceleration module
 */

#include <gtest/gtest.h>
#include <kctsb/simd/simd.h>
#include <cstring>
#include <vector>

using namespace kctsb::simd;

// ============================================================================
// Feature Detection Tests
// ============================================================================

TEST(SIMDFeatureTest, DetectFeatures) {
    // Should not throw
    bool has_sse2 = has_feature(SIMDFeature::SSE2);
    bool has_avx2 = has_feature(SIMDFeature::AVX2);
    
    // SSE2 should be available on all x86-64
    #if defined(__x86_64__) || defined(_M_X64)
    EXPECT_TRUE(has_sse2);
    #endif
    
    // If AVX2 available, SSE2 must also be available
    if (has_avx2) {
        EXPECT_TRUE(has_sse2);
    }
}

TEST(SIMDFeatureTest, GetBestFeature) {
    SIMDFeature best = get_best_feature();
    
    // Should return a valid feature
    EXPECT_GE(static_cast<int>(best), 0);
}

// ============================================================================
// XOR Operation Tests
// ============================================================================

TEST(SIMDXORTest, BasicXOR) {
    constexpr size_t size = 256;
    AlignedBuffer<uint8_t> a(size), b(size), result(size);
    
    // Initialize with test data
    for (size_t i = 0; i < size; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(i * 2);
    }
    
    xor_blocks(result.data(), a.data(), b.data(), size);
    
    // Verify result
    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(result[i], static_cast<uint8_t>(a[i] ^ b[i]));
    }
}

TEST(SIMDXORTest, LargeBuffer) {
    constexpr size_t size = 4096;
    AlignedBuffer<uint8_t> a(size), b(size), result(size);
    
    for (size_t i = 0; i < size; ++i) {
        a[i] = static_cast<uint8_t>(i % 256);
        b[i] = static_cast<uint8_t>((i * 17) % 256);
    }
    
    xor_blocks(result.data(), a.data(), b.data(), size);
    
    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(result[i], static_cast<uint8_t>(a[i] ^ b[i]));
    }
}

TEST(SIMDXORTest, UnalignedSize) {
    // Test with non-multiple-of-64 size
    constexpr size_t size = 137;
    std::vector<uint8_t> a(size), b(size), result(size);
    
    for (size_t i = 0; i < size; ++i) {
        a[i] = static_cast<uint8_t>(i);
        b[i] = static_cast<uint8_t>(255 - i);
    }
    
    xor_blocks(result.data(), a.data(), b.data(), size);
    
    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(result[i], static_cast<uint8_t>(a[i] ^ b[i]));
    }
}

// ============================================================================
// ChaCha20 SIMD Tests
// ============================================================================

TEST(ChaChaTest, BlockFunction) {
    ChaChaState state;
    
    // Initialize with test key and nonce
    const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    
    chacha20_init(&state, key, nonce, 1);
    
    uint8_t block[64];
    chacha20_block_simd(&state, block);
    
    // Output should not be all zeros
    bool nonzero = false;
    for (int i = 0; i < 64; ++i) {
        if (block[i] != 0) nonzero = true;
    }
    EXPECT_TRUE(nonzero);
}

TEST(ChaChaTest, DifferentCountersProduceDifferentBlocks) {
    ChaChaState state1, state2;
    
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    
    chacha20_init(&state1, key, nonce, 0);
    chacha20_init(&state2, key, nonce, 1);
    
    uint8_t block1[64], block2[64];
    chacha20_block_simd(&state1, block1);
    chacha20_block_simd(&state2, block2);
    
    EXPECT_NE(memcmp(block1, block2, 64), 0);
}

// ============================================================================
// AES-NI Tests
// ============================================================================

#if defined(__AES__) || defined(_M_X64)

TEST(AESNITest, KeyExpansion) {
    if (!has_feature(SIMDFeature::SSE2)) {
        GTEST_SKIP() << "AES-NI not available";
    }
    
    alignas(16) uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    alignas(16) uint8_t round_keys[176];
    
    aes128_expand_key_ni(key, round_keys);
    
    // Round keys should not be all zeros
    bool nonzero = false;
    for (int i = 0; i < 176; ++i) {
        if (round_keys[i] != 0) nonzero = true;
    }
    EXPECT_TRUE(nonzero);
}

TEST(AESNITest, SingleBlockEncryption) {
    if (!has_feature(SIMDFeature::SSE2)) {
        GTEST_SKIP() << "AES-NI not available";
    }
    
    alignas(16) uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    alignas(16) uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    alignas(16) uint8_t ciphertext[16];
    alignas(16) uint8_t round_keys[176];
    
    aes128_expand_key_ni(key, round_keys);
    aes128_encrypt_block_ni(plaintext, ciphertext, round_keys);
    
    // Known test vector result
    const uint8_t expected[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    EXPECT_EQ(memcmp(ciphertext, expected, 16), 0);
}

TEST(AESNITest, ECBMode) {
    if (!has_feature(SIMDFeature::SSE2)) {
        GTEST_SKIP() << "AES-NI not available";
    }
    
    alignas(16) uint8_t key[16] = {0};
    alignas(16) uint8_t plaintext[64] = {0};
    alignas(16) uint8_t ciphertext[64];
    alignas(16) uint8_t round_keys[176];
    
    // Initialize with pattern
    for (int i = 0; i < 64; ++i) {
        plaintext[i] = i;
    }
    
    aes128_expand_key_ni(key, round_keys);
    aes128_ecb_encrypt_ni(plaintext, ciphertext, 64, round_keys);
    
    // Each 16-byte block should be encrypted
    EXPECT_NE(memcmp(plaintext, ciphertext, 64), 0);
    
    // Same plaintext blocks should produce same ciphertext
    // (first block is all zeros if key is zeros)
}

TEST(AESNITest, CTRMode) {
    if (!has_feature(SIMDFeature::SSE2)) {
        GTEST_SKIP() << "AES-NI not available";
    }
    
    alignas(16) uint8_t key[16] = {0};
    alignas(16) uint8_t nonce[12] = {0};
    alignas(16) uint8_t plaintext[64];
    alignas(16) uint8_t ciphertext[64];
    alignas(16) uint8_t decrypted[64];
    alignas(16) uint8_t round_keys[176];
    
    for (int i = 0; i < 64; ++i) {
        plaintext[i] = i;
    }
    
    aes128_expand_key_ni(key, round_keys);
    
    // Encrypt
    aes128_ctr_ni(plaintext, ciphertext, 64, round_keys, nonce, 0);
    
    // CTR is self-inverse
    aes128_ctr_ni(ciphertext, decrypted, 64, round_keys, nonce, 0);
    
    EXPECT_EQ(memcmp(plaintext, decrypted, 64), 0);
}

#endif

// ============================================================================
// Constant-Time Operation Tests
// ============================================================================

TEST(ConstantTimeTest, Select) {
    uint64_t a = 0xDEADBEEFCAFEBABE;
    uint64_t b = 0x1234567890ABCDEF;
    
    EXPECT_EQ(ct_select(a, b, true), a);
    EXPECT_EQ(ct_select(a, b, false), b);
}

TEST(ConstantTimeTest, Compare) {
    uint8_t a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t b[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t c[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16};
    
    EXPECT_TRUE(ct_compare(a, b, 16));
    EXPECT_FALSE(ct_compare(a, c, 16));
}

TEST(ConstantTimeTest, ConditionalMove) {
    uint64_t dest = 0xAAAAAAAAAAAAAAAA;
    uint64_t src = 0xBBBBBBBBBBBBBBBB;
    
    ct_cmov(&dest, src, false);
    EXPECT_EQ(dest, 0xAAAAAAAAAAAAAAAA);
    
    ct_cmov(&dest, src, true);
    EXPECT_EQ(dest, 0xBBBBBBBBBBBBBBBB);
}

// ============================================================================
// Secure Memory Tests
// ============================================================================

TEST(SecureMemoryTest, SecureZero) {
    uint8_t buffer[64];
    memset(buffer, 0xFF, sizeof(buffer));
    
    secure_zero(buffer, sizeof(buffer));
    
    for (int i = 0; i < 64; ++i) {
        EXPECT_EQ(buffer[i], 0);
    }
}

// ============================================================================
// AlignedBuffer Tests
// ============================================================================

TEST(AlignedBufferTest, Allocation) {
    AlignedBuffer<uint8_t> buf(1024);
    
    EXPECT_EQ(buf.size(), 1024);
    EXPECT_NE(buf.data(), nullptr);
    
    // Check alignment (32-byte aligned for AVX)
    EXPECT_EQ(reinterpret_cast<uintptr_t>(buf.data()) % 32, 0);
}

TEST(AlignedBufferTest, Access) {
    AlignedBuffer<uint32_t> buf(256);
    
    for (size_t i = 0; i < 256; ++i) {
        buf[i] = static_cast<uint32_t>(i * i);
    }
    
    for (size_t i = 0; i < 256; ++i) {
        EXPECT_EQ(buf[i], static_cast<uint32_t>(i * i));
    }
}

TEST(AlignedBufferTest, MoveSemantics) {
    AlignedBuffer<uint8_t> buf1(512);
    for (size_t i = 0; i < 512; ++i) {
        buf1[i] = static_cast<uint8_t>(i);
    }
    
    AlignedBuffer<uint8_t> buf2 = std::move(buf1);
    
    EXPECT_EQ(buf2.size(), 512);
    for (size_t i = 0; i < 512; ++i) {
        EXPECT_EQ(buf2[i], static_cast<uint8_t>(i));
    }
}
