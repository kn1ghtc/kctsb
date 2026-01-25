/**
 * @file test_random.cpp
 * @brief Secure random number generation unit tests
 *
 * Tests for CSPRNG functionality:
 * - kctsb_random_bytes: Cryptographically secure random byte generation
 * - kctsb_random_u32/u64: Random integer generation
 * - kctsb_random_range: Uniform random in range
 * - Distribution uniformity tests
 *
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <set>
#include <unordered_map>
#include <cmath>
#include <algorithm>

#include "kctsb/kctsb.h"
#include "kctsb/utils/random.h"

class RandomTest : public ::testing::Test {
protected:
    void SetUp() override {
        kctsb_init();
    }
};

// ============================================================================
// Basic Random Bytes Tests
// ============================================================================

TEST_F(RandomTest, RandomBytes_Basic) {
    uint8_t buf1[32] = {0};
    uint8_t buf2[32] = {0};

    // kctsb_random_bytes returns int: 0 = success
    int ret1 = kctsb_random_bytes(buf1, sizeof(buf1));
    int ret2 = kctsb_random_bytes(buf2, sizeof(buf2));

    EXPECT_EQ(ret1, 0);
    EXPECT_EQ(ret2, 0);

    // Two calls should produce different output
    EXPECT_NE(memcmp(buf1, buf2, sizeof(buf1)), 0);
}

TEST_F(RandomTest, RandomBytes_NotAllZero) {
    uint8_t buf[128] = {0};
    kctsb_random_bytes(buf, sizeof(buf));

    bool all_zero = true;
    for (size_t i = 0; i < sizeof(buf); ++i) {
        if (buf[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "Random bytes should not be all zeros";
}

TEST_F(RandomTest, RandomBytes_NotAllOnes) {
    uint8_t buf[128];
    memset(buf, 0xFF, sizeof(buf));
    kctsb_random_bytes(buf, sizeof(buf));

    bool all_ones = true;
    for (size_t i = 0; i < sizeof(buf); ++i) {
        if (buf[i] != 0xFF) {
            all_ones = false;
            break;
        }
    }
    EXPECT_FALSE(all_ones) << "Random bytes should not be all 0xFF";
}

TEST_F(RandomTest, RandomBytes_VariousSizes) {
    std::vector<size_t> sizes = {1, 8, 16, 32, 64, 128, 256, 1024, 4096};

    for (size_t size : sizes) {
        std::vector<uint8_t> buf(size, 0);
        int ret = kctsb_random_bytes(buf.data(), size);
        EXPECT_EQ(ret, 0) << "Failed for size " << size;

        // Check not all zeros (statistically unlikely for size >= 8)
        if (size >= 8) {
            bool all_zero = true;
            for (size_t i = 0; i < size; ++i) {
                if (buf[i] != 0) {
                    all_zero = false;
                    break;
                }
            }
            EXPECT_FALSE(all_zero) << "Random bytes should not be all zeros for size " << size;
        }
    }
}

TEST_F(RandomTest, RandomBytes_ZeroLength) {
    uint8_t buf[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    int ret = kctsb_random_bytes(buf, 0);

    // Should succeed and not modify buffer
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(buf[0], 0xAA);
    EXPECT_EQ(buf[1], 0xBB);
}

TEST_F(RandomTest, RandomBytes_NullPointer) {
    int ret = kctsb_random_bytes(nullptr, 32);
    EXPECT_NE(ret, 0);
}

// ============================================================================
// Random Integer Tests
// ============================================================================

TEST_F(RandomTest, RandomU32_Uniqueness) {
    std::set<uint32_t> values;
    constexpr size_t NUM_SAMPLES = 1000;

    for (size_t i = 0; i < NUM_SAMPLES; ++i) {
        values.insert(kctsb_random_u32());
    }

    // With good randomness, most values should be unique
    EXPECT_GT(values.size(), NUM_SAMPLES * 0.99)
        << "Random u32 should produce mostly unique values";
}

TEST_F(RandomTest, RandomU64_Uniqueness) {
    std::set<uint64_t> values;
    constexpr size_t NUM_SAMPLES = 1000;

    for (size_t i = 0; i < NUM_SAMPLES; ++i) {
        values.insert(kctsb_random_u64());
    }

    // All values should be unique (birthday paradox: P(collision) < 0.01 for 1000 samples in 2^64)
    EXPECT_EQ(values.size(), NUM_SAMPLES)
        << "Random u64 should produce unique values";
}

TEST_F(RandomTest, RandomU32_Distribution) {
    constexpr size_t NUM_SAMPLES = 10000;
    constexpr size_t NUM_BUCKETS = 16;
    std::vector<size_t> buckets(NUM_BUCKETS, 0);

    for (size_t i = 0; i < NUM_SAMPLES; ++i) {
        uint32_t val = kctsb_random_u32();
        size_t bucket = (val >> 28) & 0xF;  // Top 4 bits
        buckets[bucket]++;
    }

    // Chi-squared test for uniformity
    double expected = static_cast<double>(NUM_SAMPLES) / static_cast<double>(NUM_BUCKETS);
    double chi_squared = 0.0;
    for (size_t count : buckets) {
        double diff = static_cast<double>(count) - expected;
        chi_squared += (diff * diff) / expected;
    }

    // Critical value for chi-squared with df=15, alpha=0.01 is ~30.58
    EXPECT_LT(chi_squared, 30.58)
        << "Random u32 distribution should be approximately uniform";
}

// ============================================================================
// Random Range Tests
// ============================================================================

TEST_F(RandomTest, RandomRange_Bounds) {
    constexpr uint32_t MAX = 100;
    constexpr size_t NUM_SAMPLES = 10000;

    for (size_t i = 0; i < NUM_SAMPLES; ++i) {
        uint32_t val = kctsb_random_range(MAX);
        EXPECT_LT(val, MAX) << "Random range should be in [0, max)";
    }
}

TEST_F(RandomTest, RandomRange_Distribution) {
    constexpr uint32_t MAX = 10;
    constexpr size_t NUM_SAMPLES = 10000;
    const size_t max_size = static_cast<size_t>(MAX);
    std::vector<size_t> counts(max_size, 0);

    for (size_t i = 0; i < NUM_SAMPLES; ++i) {
        uint32_t val = kctsb_random_range(MAX);
        counts[val]++;
    }

    // Check rough uniformity: each bucket should have ~1000 samples
    double expected = static_cast<double>(NUM_SAMPLES) / static_cast<double>(MAX);
    for (size_t i = 0; i < max_size; ++i) {
        EXPECT_GT(counts[i], expected * 0.8)
            << "Bucket " << i << " has too few samples";
        EXPECT_LT(counts[i], expected * 1.2)
            << "Bucket " << i << " has too many samples";
    }
}

TEST_F(RandomTest, RandomRange_SmallMax) {
    // Edge case: max = 1 should always return 0
    for (size_t i = 0; i < 100; ++i) {
        EXPECT_EQ(kctsb_random_range(1), 0u);
    }
}

TEST_F(RandomTest, RandomRange_PowerOfTwo) {
    constexpr uint32_t MAX = 256;
    constexpr size_t NUM_SAMPLES = 5000;

    for (size_t i = 0; i < NUM_SAMPLES; ++i) {
        uint32_t val = kctsb_random_range(MAX);
        EXPECT_LT(val, MAX);
    }
}

TEST_F(RandomTest, RandomRange_NonPowerOfTwo) {
    constexpr uint32_t MAX = 137;  // Non-power-of-two
    constexpr size_t NUM_SAMPLES = 5000;
    const size_t max_size = static_cast<size_t>(MAX);
    std::vector<size_t> counts(max_size, 0);

    for (size_t i = 0; i < NUM_SAMPLES; ++i) {
        uint32_t val = kctsb_random_range(MAX);
        EXPECT_LT(val, MAX);
        counts[val]++;
    }

    // All values should be hit at least once
    for (size_t i = 0; i < max_size; ++i) {
        EXPECT_GT(counts[i], 0u) << "Value " << i << " was never generated";
    }
}

// ============================================================================
// Statistical Quality Tests
// ============================================================================

TEST_F(RandomTest, MonobitTest) {
    // NIST Statistical Test Suite - Monobit test
    constexpr size_t NUM_BITS = 8000;
    constexpr size_t NUM_BYTES = NUM_BITS / 8;
    std::vector<uint8_t> buf(NUM_BYTES);
    kctsb_random_bytes(buf.data(), NUM_BYTES);

    size_t ones = 0;
    for (uint8_t byte : buf) {
        ones += static_cast<size_t>(__builtin_popcount(byte));
    }

    // The sum should be approximately half of total bits
    // P-value threshold: |ones - 4000| / sqrt(2000) < 2.58 (99% confidence)
    double ones_diff = std::abs(static_cast<double>(ones) - (static_cast<double>(NUM_BITS) / 2.0));
    double s_obs = ones_diff / std::sqrt(static_cast<double>(NUM_BITS) / 4.0);
    EXPECT_LT(s_obs, 2.58) << "Monobit test failed: too many or too few ones";
}

TEST_F(RandomTest, RunsTest) {
    // Simple runs test: count transitions between 0 and 1
    constexpr size_t NUM_BYTES = 1000;
    std::vector<uint8_t> buf(NUM_BYTES);
    kctsb_random_bytes(buf.data(), NUM_BYTES);

    size_t runs = 1;  // Start with 1 run
    uint8_t prev_bit = buf[0] & 1;

    for (size_t i = 0; i < NUM_BYTES; ++i) {
        for (size_t j = (i == 0 ? 1 : 0); j < 8; ++j) {
            uint8_t curr_bit = (buf[i] >> j) & 1;
            if (curr_bit != prev_bit) {
                runs++;
                prev_bit = curr_bit;
            }
        }
    }

    // Expected runs ≈ (n-1)/2 + 1 for random bits
    // Allow 20% deviation
    size_t expected_runs = (NUM_BYTES * 8 - 1) / 2 + 1;
    double expected_runs_double = static_cast<double>(expected_runs);
    EXPECT_GT(static_cast<double>(runs), expected_runs_double * 0.8);
    EXPECT_LT(static_cast<double>(runs), expected_runs_double * 1.2);
}

// ============================================================================
// C++ Wrapper Tests
// ============================================================================

#ifdef __cplusplus
TEST_F(RandomTest, CppWrapper_ByteVec) {
    auto bytes = kctsb::randomBytes(32);
    EXPECT_EQ(bytes.size(), 32u);

    // Check not all zeros
    bool all_zero = true;
    for (uint8_t b : bytes) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero);
}

TEST_F(RandomTest, CppWrapper_U32) {
    uint32_t val1 = kctsb::randomU32();
    uint32_t val2 = kctsb::randomU32();
    // Very unlikely to be equal
    EXPECT_NE(val1, val2);
}

TEST_F(RandomTest, CppWrapper_U64) {
    uint64_t val1 = kctsb::randomU64();
    uint64_t val2 = kctsb::randomU64();
    EXPECT_NE(val1, val2);
}

TEST_F(RandomTest, CppWrapper_Range) {
    for (size_t i = 0; i < 1000; ++i) {
        uint32_t val = kctsb::randomRange(100);
        EXPECT_LT(val, 100u);
    }
}
#endif

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

TEST_F(RandomTest, LargeBuffer) {
    // 1 MB buffer
    std::vector<uint8_t> buf(1024 * 1024, 0);
    int ret = kctsb_random_bytes(buf.data(), buf.size());
    EXPECT_EQ(ret, 0);

    // Check entropy: simple byte frequency test
    std::vector<size_t> freq(256, 0);
    for (uint8_t b : buf) {
        freq[b]++;
    }

    // Each byte value should appear ~4096 times
    for (size_t i = 0; i < freq.size(); ++i) {
        EXPECT_GT(freq[i], 3000u) << "Byte " << i << " appears too infrequently";
        EXPECT_LT(freq[i], 5500u) << "Byte " << i << " appears too frequently";
    }
}
