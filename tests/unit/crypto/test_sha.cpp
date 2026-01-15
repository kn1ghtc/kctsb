/**
 * @file test_sha.cpp
 * @brief SHA family unit tests with NIST test vectors
 *
 * Test vectors from FIPS 180-4 and NIST CAVP
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#include <gtest/gtest.h>
#include "kctsb/crypto/sha256.h"
#include "kctsb/crypto/sha512.h"
#include <cstring>
#include <iomanip>
#include <sstream>

// Helper: Convert bytes to hex string
static std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

// ============================================================================
// SHA-256 Tests
// ============================================================================

TEST(SHA256Test, EmptyString) {
    // SHA-256("") = e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
    uint8_t digest[32];
    kctsb_sha256((const uint8_t*)"", 0, digest);

    EXPECT_EQ(to_hex(digest, 32),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(SHA256Test, ABC) {
    // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    uint8_t digest[32];
    kctsb_sha256((const uint8_t*)"abc", 3, digest);

    EXPECT_EQ(to_hex(digest, 32),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(SHA256Test, LongMessage) {
    // SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    const char* msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t digest[32];
    kctsb_sha256((const uint8_t*)msg, strlen(msg), digest);

    EXPECT_EQ(to_hex(digest, 32),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(SHA256Test, IncrementalUpdate) {
    // Test incremental hashing
    kctsb_sha256_ctx_t ctx;
    uint8_t digest[32];

    kctsb_sha256_init(&ctx);
    kctsb_sha256_update(&ctx, (const uint8_t*)"ab", 2);
    kctsb_sha256_update(&ctx, (const uint8_t*)"c", 1);
    kctsb_sha256_final(&ctx, digest);

    EXPECT_EQ(to_hex(digest, 32),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(SHA256Test, MillionAs) {
    // SHA-256 of 1 million 'a' characters
    kctsb_sha256_ctx_t ctx;
    uint8_t digest[32];
    uint8_t block[1000];

    memset(block, 'a', sizeof(block));
    kctsb_sha256_init(&ctx);
    for (int i = 0; i < 1000; i++) {
        kctsb_sha256_update(&ctx, block, sizeof(block));
    }
    kctsb_sha256_final(&ctx, digest);

    EXPECT_EQ(to_hex(digest, 32),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// ============================================================================
// SHA-512 Tests
// ============================================================================

TEST(SHA512Test, EmptyString) {
    // SHA-512("")
    uint8_t digest[64];
    kctsb_sha512((const uint8_t*)"", 0, digest);

    EXPECT_EQ(to_hex(digest, 64),
              "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
              "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

TEST(SHA512Test, ABC) {
    // SHA-512("abc")
    uint8_t digest[64];
    kctsb_sha512((const uint8_t*)"abc", 3, digest);

    EXPECT_EQ(to_hex(digest, 64),
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

TEST(SHA512Test, LongMessage) {
    // SHA-512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    const char* msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t digest[64];
    kctsb_sha512((const uint8_t*)msg, strlen(msg), digest);

    EXPECT_EQ(to_hex(digest, 64),
              "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
              "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

TEST(SHA512Test, IncrementalUpdate) {
    // Test incremental hashing
    kctsb_sha512_ctx_t ctx;
    uint8_t digest[64];

    kctsb_sha512_init(&ctx);
    kctsb_sha512_update(&ctx, (const uint8_t*)"ab", 2);
    kctsb_sha512_update(&ctx, (const uint8_t*)"c", 1);
    kctsb_sha512_final(&ctx, digest);

    EXPECT_EQ(to_hex(digest, 64),
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

// ============================================================================
// SHA-384 Tests
// ============================================================================

TEST(SHA384Test, EmptyString) {
    // SHA-384("")
    uint8_t digest[48];
    kctsb_sha384((const uint8_t*)"", 0, digest);

    EXPECT_EQ(to_hex(digest, 48),
              "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
              "274edebfe76f65fbd51ad2f14898b95b");
}

TEST(SHA384Test, ABC) {
    // SHA-384("abc")
    uint8_t digest[48];
    kctsb_sha384((const uint8_t*)"abc", 3, digest);

    EXPECT_EQ(to_hex(digest, 48),
              "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
              "8086072ba1e7cc2358baeca134c825a7");
}

TEST(SHA384Test, LongMessage) {
    // SHA-384 of long message
    const char* msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t digest[48];
    kctsb_sha384((const uint8_t*)msg, strlen(msg), digest);

    EXPECT_EQ(to_hex(digest, 48),
              "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
              "fcc7c71a557e2db966c3e9fa91746039");
}

TEST(SHA384Test, IncrementalUpdate) {
    // Test incremental hashing
    kctsb_sha384_ctx_t ctx;
    uint8_t digest[48];

    kctsb_sha384_init(&ctx);
    kctsb_sha384_update(&ctx, (const uint8_t*)"ab", 2);
    kctsb_sha384_update(&ctx, (const uint8_t*)"c", 1);
    kctsb_sha384_final(&ctx, digest);

    EXPECT_EQ(to_hex(digest, 48),
              "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
              "8086072ba1e7cc2358baeca134c825a7");
}

// ============================================================================
// Cross-Family Compatibility Tests
// ============================================================================

TEST(SHATest, DifferentOutputSizes) {
    // Verify different hash sizes
    const char* msg = "The quick brown fox jumps over the lazy dog";

    uint8_t sha256[32];
    uint8_t sha384[48];
    uint8_t sha512[64];

    kctsb_sha256((const uint8_t*)msg, strlen(msg), sha256);
    kctsb_sha384((const uint8_t*)msg, strlen(msg), sha384);
    kctsb_sha512((const uint8_t*)msg, strlen(msg), sha512);

    // SHA-256 produces 32 bytes
    EXPECT_EQ(to_hex(sha256, 32),
              "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

    // SHA-384 produces 48 bytes
    EXPECT_EQ(to_hex(sha384, 48),
              "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");

    // SHA-512 produces 64 bytes
    EXPECT_EQ(to_hex(sha512, 64),
              "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
