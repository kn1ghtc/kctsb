/**
 * @file test_benchmark.cpp
 * @brief Performance benchmark tests
 */

#include <gtest/gtest.h>
#include "kctsb/crypto/aes.h"
#include <chrono>
#include <iostream>

TEST(BenchmarkTest, AES128_Performance) {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    kctsb_aes_ctx_t ctx;
    ASSERT_EQ(kctsb_aes_init(&ctx, key, 16), KCTSB_SUCCESS);
    
    uint8_t ciphertext[16];
    
    constexpr int iterations = 100000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        kctsb_aes_encrypt_block(&ctx, plaintext, ciphertext);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double seconds = static_cast<double>(duration.count()) / 1000000.0;
    double blocks_per_second = static_cast<double>(iterations) / seconds;
    double mb_per_second = (blocks_per_second * 16) / (1024 * 1024);
    
    std::cout << "AES-128 Encryption Performance:" << std::endl;
    std::cout << "  Iterations: " << iterations << std::endl;
    std::cout << "  Total time: " << duration.count() << " microseconds" << std::endl;
    std::cout << "  Blocks/second: " << blocks_per_second << std::endl;
    std::cout << "  Throughput: " << mb_per_second << " MB/s" << std::endl;
    
    EXPECT_GT(mb_per_second, 10.0);  // Expect at least 10 MB/s
    
    kctsb_aes_clear(&ctx);
}
