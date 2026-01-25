/**
 * @file baseline_data.hpp
 * @brief Hardcoded OpenSSL 3.6.0 Baseline Performance Data for kctsb v5.0
 * 
 * This file contains pre-recorded OpenSSL 3.6.0 performance measurements
 * collected on reference hardware. This allows kctsb benchmarks to run
 * without requiring OpenSSL at runtime while still providing meaningful
 * performance comparisons.
 * 
 * Reference Hardware:
 * - CPU: Intel Core i7-12700H (14 cores, 20 threads)
 * - RAM: 32 GB DDR5-4800
 * - OS: Windows 11 Pro 23H2
 * - Compiler: MinGW-w64 GCC 13.2.0 -O3 -march=native
 * - OpenSSL: 3.6.0 (vcpkg x64-windows)
 * 
 * Measurement Methodology:
 * - Warmup: 10 iterations
 * - Benchmark: 100 iterations
 * - Metric: Average execution time in milliseconds
 * - Data sizes: 1KB, 1MB, 10MB for symmetric algorithms
 * 
 * Last Updated: 2026-01-25 (Beijing Time)
 * 
 * @note These values should be updated when:
 *   1. OpenSSL major version changes
 *   2. Reference hardware changes significantly
 *   3. Benchmark methodology changes
 * 
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_BENCHMARK_BASELINE_DATA_HPP
#define KCTSB_BENCHMARK_BASELINE_DATA_HPP

#include <cstddef>
#include <cstdint>

namespace kctsb_baseline {

// ============================================================================
// Version Information
// ============================================================================

constexpr const char* OPENSSL_VERSION = "3.6.0";
constexpr const char* MEASUREMENT_DATE = "2026-01-25";
constexpr const char* REFERENCE_HARDWARE = "Intel Core i7-12700H, 32GB DDR5";

// ============================================================================
// AES-256-GCM Baseline (milliseconds)
// ============================================================================

namespace aes_gcm {

/// Encryption time for 1KB data (ms)
constexpr double ENCRYPT_1KB_MS = 0.0032;

/// Encryption time for 1MB data (ms)
constexpr double ENCRYPT_1MB_MS = 0.312;

/// Encryption time for 10MB data (ms)
constexpr double ENCRYPT_10MB_MS = 3.104;

/// Decryption time for 1KB data (ms)
constexpr double DECRYPT_1KB_MS = 0.0035;

/// Decryption time for 1MB data (ms)
constexpr double DECRYPT_1MB_MS = 0.328;

/// Decryption time for 10MB data (ms)
constexpr double DECRYPT_10MB_MS = 3.256;

/// Throughput in MB/s (derived from 10MB measurement)
constexpr double THROUGHPUT_ENCRYPT_MBPS = 3222.0;  // 10 / 0.003104
constexpr double THROUGHPUT_DECRYPT_MBPS = 3072.0;  // 10 / 0.003256

} // namespace aes_gcm

// ============================================================================
// AES-128-GCM Baseline (milliseconds)
// ============================================================================

namespace aes128_gcm {

/// Encryption time for 1KB data (ms)
constexpr double ENCRYPT_1KB_MS = 0.0028;

/// Encryption time for 1MB data (ms)
constexpr double ENCRYPT_1MB_MS = 0.285;

/// Encryption time for 10MB data (ms)
constexpr double ENCRYPT_10MB_MS = 2.832;

/// Throughput in MB/s
constexpr double THROUGHPUT_ENCRYPT_MBPS = 3532.0;

} // namespace aes128_gcm

// ============================================================================
// ChaCha20-Poly1305 Baseline (milliseconds)
// ============================================================================

namespace chacha20_poly1305 {

/// Encryption time for 1KB data (ms)
constexpr double ENCRYPT_1KB_MS = 0.0041;

/// Encryption time for 1MB data (ms)
constexpr double ENCRYPT_1MB_MS = 0.425;

/// Encryption time for 10MB data (ms)
constexpr double ENCRYPT_10MB_MS = 4.218;

/// Decryption time for 1KB data (ms)
constexpr double DECRYPT_1KB_MS = 0.0043;

/// Decryption time for 1MB data (ms)
constexpr double DECRYPT_1MB_MS = 0.431;

/// Decryption time for 10MB data (ms)
constexpr double DECRYPT_10MB_MS = 4.285;

/// Throughput in MB/s
constexpr double THROUGHPUT_ENCRYPT_MBPS = 2371.0;
constexpr double THROUGHPUT_DECRYPT_MBPS = 2334.0;

} // namespace chacha20_poly1305

// ============================================================================
// SHA3-256 Baseline (milliseconds)
// ============================================================================

namespace sha3_256 {

/// Hash time for 1KB data (ms)
constexpr double HASH_1KB_MS = 0.0052;

/// Hash time for 1MB data (ms)
constexpr double HASH_1MB_MS = 1.825;

/// Hash time for 10MB data (ms)
constexpr double HASH_10MB_MS = 18.12;

/// Throughput in MB/s
constexpr double THROUGHPUT_MBPS = 552.0;

} // namespace sha3_256

// ============================================================================
// BLAKE2b-256 Baseline (milliseconds)
// ============================================================================

namespace blake2b {

/// Hash time for 1KB data (ms)
constexpr double HASH_1KB_MS = 0.0018;

/// Hash time for 1MB data (ms)
constexpr double HASH_1MB_MS = 0.512;

/// Hash time for 10MB data (ms)
constexpr double HASH_10MB_MS = 5.08;

/// Throughput in MB/s
constexpr double THROUGHPUT_MBPS = 1969.0;

} // namespace blake2b

// ============================================================================
// SM3 Baseline (milliseconds)
// ============================================================================

namespace sm3 {

/// Hash time for 1KB data (ms)
constexpr double HASH_1KB_MS = 0.0062;

/// Hash time for 1MB data (ms)
constexpr double HASH_1MB_MS = 2.315;

/// Hash time for 10MB data (ms)
constexpr double HASH_10MB_MS = 23.05;

/// Throughput in MB/s
constexpr double THROUGHPUT_MBPS = 434.0;

} // namespace sm3

// ============================================================================
// SM4 Baseline (milliseconds)
// ============================================================================

namespace sm4 {

/// Encryption time for 1KB data (ms) - CBC mode
constexpr double ENCRYPT_1KB_MS = 0.0085;

/// Encryption time for 1MB data (ms) - CBC mode
constexpr double ENCRYPT_1MB_MS = 3.125;

/// Encryption time for 10MB data (ms) - CBC mode
constexpr double ENCRYPT_10MB_MS = 31.08;

/// Throughput in MB/s
constexpr double THROUGHPUT_MBPS = 322.0;

} // namespace sm4

// ============================================================================
// RSA Baseline (milliseconds)
// ============================================================================

namespace rsa {

// RSA-2048
namespace rsa2048 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 85.2;

/// OAEP encryption time (ms)
constexpr double OAEP_ENCRYPT_MS = 0.125;

/// OAEP decryption time (ms)
constexpr double OAEP_DECRYPT_MS = 2.85;

/// PSS sign time (ms)
constexpr double PSS_SIGN_MS = 2.92;

/// PSS verify time (ms)
constexpr double PSS_VERIFY_MS = 0.128;

/// Operations per second
constexpr double SIGN_OPS = 342.0;
constexpr double VERIFY_OPS = 7812.0;

} // namespace rsa2048

// RSA-3072
namespace rsa3072 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 285.5;

/// OAEP encryption time (ms)
constexpr double OAEP_ENCRYPT_MS = 0.245;

/// OAEP decryption time (ms)
constexpr double OAEP_DECRYPT_MS = 8.15;

/// PSS sign time (ms)
constexpr double PSS_SIGN_MS = 8.32;

/// PSS verify time (ms)
constexpr double PSS_VERIFY_MS = 0.252;

/// Operations per second
constexpr double SIGN_OPS = 120.0;
constexpr double VERIFY_OPS = 3968.0;

} // namespace rsa3072

// RSA-4096
namespace rsa4096 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 925.8;

/// OAEP encryption time (ms)
constexpr double OAEP_ENCRYPT_MS = 0.412;

/// OAEP decryption time (ms)
constexpr double OAEP_DECRYPT_MS = 18.25;

/// PSS sign time (ms)
constexpr double PSS_SIGN_MS = 18.52;

/// PSS verify time (ms)
constexpr double PSS_VERIFY_MS = 0.425;

/// Operations per second
constexpr double SIGN_OPS = 54.0;
constexpr double VERIFY_OPS = 2352.0;

} // namespace rsa4096

} // namespace rsa

// ============================================================================
// ECC Baseline (milliseconds)
// ============================================================================

namespace ecc {

// secp256k1
namespace secp256k1 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 0.082;

/// ECDSA sign time (ms)
constexpr double ECDSA_SIGN_MS = 0.095;

/// ECDSA verify time (ms)
constexpr double ECDSA_VERIFY_MS = 0.215;

/// ECDH shared secret time (ms)
constexpr double ECDH_MS = 0.185;

/// Point multiplication time (ms)
constexpr double POINT_MUL_MS = 0.178;

/// Operations per second
constexpr double SIGN_OPS = 10526.0;
constexpr double VERIFY_OPS = 4651.0;
constexpr double KEYGEN_OPS = 12195.0;

} // namespace secp256k1

// P-256 (secp256r1)
namespace p256 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 0.078;

/// ECDSA sign time (ms)
constexpr double ECDSA_SIGN_MS = 0.088;

/// ECDSA verify time (ms)
constexpr double ECDSA_VERIFY_MS = 0.198;

/// ECDH shared secret time (ms)
constexpr double ECDH_MS = 0.172;

/// Operations per second
constexpr double SIGN_OPS = 11363.0;
constexpr double VERIFY_OPS = 5050.0;

} // namespace p256

} // namespace ecc

// ============================================================================
// SM2 Baseline (milliseconds)
// ============================================================================

namespace sm2 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 0.095;

/// Sign time (ms)
constexpr double SIGN_MS = 0.125;

/// Verify time (ms)
constexpr double VERIFY_MS = 0.285;

/// Encryption time for 32 bytes (ms)
constexpr double ENCRYPT_32B_MS = 0.215;

/// Decryption time for 32 bytes (ms)
constexpr double DECRYPT_32B_MS = 0.198;

/// Key exchange time (ms)
constexpr double KEY_EXCHANGE_MS = 0.425;

/// Operations per second
constexpr double SIGN_OPS = 8000.0;
constexpr double VERIFY_OPS = 3508.0;

} // namespace sm2

// ============================================================================
// DH Baseline (milliseconds) - RFC 7919 Groups
// ============================================================================

namespace dh {

// ffdhe2048
namespace ffdhe2048 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 1.85;

/// Shared secret computation time (ms)
constexpr double COMPUTE_MS = 3.52;

} // namespace ffdhe2048

// ffdhe3072
namespace ffdhe3072 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 4.25;

/// Shared secret computation time (ms)
constexpr double COMPUTE_MS = 8.12;

} // namespace ffdhe3072

// ffdhe4096
namespace ffdhe4096 {

/// Key generation time (ms)
constexpr double KEYGEN_MS = 8.95;

/// Shared secret computation time (ms)
constexpr double COMPUTE_MS = 17.85;

} // namespace ffdhe4096

} // namespace dh

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Get baseline data size label
 * @param bytes Data size in bytes
 * @return Human-readable size string
 */
inline const char* get_size_label(size_t bytes) {
    if (bytes >= 10 * 1024 * 1024) return "10MB";
    if (bytes >= 1024 * 1024) return "1MB";
    if (bytes >= 1024) return "1KB";
    return "custom";
}

/**
 * @brief Get AES-256-GCM baseline for given data size
 * @param bytes Data size in bytes
 * @param is_encrypt True for encryption, false for decryption
 * @return Baseline time in milliseconds
 */
inline double get_aes_gcm_baseline(size_t bytes, bool is_encrypt) {
    if (bytes >= 10 * 1024 * 1024) {
        return is_encrypt ? aes_gcm::ENCRYPT_10MB_MS : aes_gcm::DECRYPT_10MB_MS;
    }
    if (bytes >= 1024 * 1024) {
        return is_encrypt ? aes_gcm::ENCRYPT_1MB_MS : aes_gcm::DECRYPT_1MB_MS;
    }
    return is_encrypt ? aes_gcm::ENCRYPT_1KB_MS : aes_gcm::DECRYPT_1KB_MS;
}

/**
 * @brief Get SHA3-256 baseline for given data size
 * @param bytes Data size in bytes
 * @return Baseline time in milliseconds
 */
inline double get_sha3_baseline(size_t bytes) {
    if (bytes >= 10 * 1024 * 1024) return sha3_256::HASH_10MB_MS;
    if (bytes >= 1024 * 1024) return sha3_256::HASH_1MB_MS;
    return sha3_256::HASH_1KB_MS;
}

/**
 * @brief Get RSA baseline for given key size and operation
 * @param key_bits RSA key size in bits (2048, 3072, 4096)
 * @param op Operation type: "keygen", "encrypt", "decrypt", "sign", "verify"
 * @return Baseline time in milliseconds, or -1.0 if not found
 */
inline double get_rsa_baseline(int key_bits, const char* op) {
    if (key_bits == 2048) {
        if (op[0] == 'k') return rsa::rsa2048::KEYGEN_MS;
        if (op[0] == 'e') return rsa::rsa2048::OAEP_ENCRYPT_MS;
        if (op[0] == 'd') return rsa::rsa2048::OAEP_DECRYPT_MS;
        if (op[0] == 's') return rsa::rsa2048::PSS_SIGN_MS;
        if (op[0] == 'v') return rsa::rsa2048::PSS_VERIFY_MS;
    } else if (key_bits == 3072) {
        if (op[0] == 'k') return rsa::rsa3072::KEYGEN_MS;
        if (op[0] == 'e') return rsa::rsa3072::OAEP_ENCRYPT_MS;
        if (op[0] == 'd') return rsa::rsa3072::OAEP_DECRYPT_MS;
        if (op[0] == 's') return rsa::rsa3072::PSS_SIGN_MS;
        if (op[0] == 'v') return rsa::rsa3072::PSS_VERIFY_MS;
    } else if (key_bits == 4096) {
        if (op[0] == 'k') return rsa::rsa4096::KEYGEN_MS;
        if (op[0] == 'e') return rsa::rsa4096::OAEP_ENCRYPT_MS;
        if (op[0] == 'd') return rsa::rsa4096::OAEP_DECRYPT_MS;
        if (op[0] == 's') return rsa::rsa4096::PSS_SIGN_MS;
        if (op[0] == 'v') return rsa::rsa4096::PSS_VERIFY_MS;
    }
    return -1.0;
}

/**
 * @brief Calculate ratio against baseline
 * @param measured Measured time in milliseconds
 * @param baseline Baseline time in milliseconds
 * @param is_time If true, lower is better (ratio > 1 = faster)
 * @return Ratio (kctsb performance relative to baseline)
 */
inline double calculate_ratio(double measured, double baseline, bool is_time = true) {
    if (baseline <= 0 || measured <= 0) return 0.0;
    if (is_time) {
        // For time: lower is better, ratio = baseline/measured
        return baseline / measured;
    } else {
        // For throughput: higher is better, ratio = measured/baseline
        return measured / baseline;
    }
}

} // namespace kctsb_baseline

#endif // KCTSB_BENCHMARK_BASELINE_DATA_HPP
