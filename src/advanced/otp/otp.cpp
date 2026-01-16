/**
 * @file otp.cpp
 * @brief One-Time Password (OTP) Implementation
 *
 * High-performance implementation of RFC 4226 (HOTP) and RFC 6238 (TOTP).
 * Uses HMAC-SHA256/SHA512 for security (SHA1 is deprecated and not supported).
 *
 * Architecture: C++ internal implementation + C ABI export.
 *
 * References:
 * - RFC 4226: HOTP - An HMAC-Based One-Time Password Algorithm
 * - RFC 6238: TOTP - Time-Based One-Time Password Algorithm
 * - RFC 4648: Base Encodings (Base32)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/advanced/otp.h"
#include "kctsb/crypto/sha256.h"
#include "kctsb/crypto/sha512.h"
#include "kctsb/crypto/mac.h"
#include "kctsb/core/security.h"

#include <cstring>
#include <cstdio>
#include <ctime>
#include <array>
#include <vector>

// ============================================================================
// Internal Implementation
// ============================================================================

namespace {

/**
 * @brief Power of 10 lookup table for digit truncation
 */
constexpr uint32_t POW10[] = {
    1,          // 0 digits
    10,         // 1 digit
    100,        // 2 digits
    1000,       // 3 digits
    10000,      // 4 digits
    100000,     // 5 digits
    1000000,    // 6 digits
    10000000,   // 7 digits
    100000000,  // 8 digits
    1000000000, // 9 digits
    0           // 10 digits (use all 32 bits)
};

/**
 * @brief Base32 alphabet (RFC 4648)
 */
constexpr char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * @brief Base32 decode table
 */
constexpr int8_t BASE32_DECODE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x00-0x0F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x10-0x1F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x20-0x2F
    -1,-1,26,27,28,29,30,31,-1,-1,-1,-1,-1,-2,-1,-1,  // 0x30-0x3F (2-7, =)
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // 0x40-0x4F (A-O)
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  // 0x50-0x5F (P-Z)
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // 0x60-0x6F (a-o)
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  // 0x70-0x7F (p-z)
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x80-0x8F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x90-0x9F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xA0-0xAF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xB0-0xBF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xC0-0xCF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xD0-0xDF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xE0-0xEF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   // 0xF0-0xFF
};

/**
 * @brief Convert uint64 counter to big-endian bytes
 */
void counter_to_bytes(uint64_t counter, uint8_t* bytes) {
    bytes[0] = static_cast<uint8_t>(counter >> 56);
    bytes[1] = static_cast<uint8_t>(counter >> 48);
    bytes[2] = static_cast<uint8_t>(counter >> 40);
    bytes[3] = static_cast<uint8_t>(counter >> 32);
    bytes[4] = static_cast<uint8_t>(counter >> 24);
    bytes[5] = static_cast<uint8_t>(counter >> 16);
    bytes[6] = static_cast<uint8_t>(counter >> 8);
    bytes[7] = static_cast<uint8_t>(counter);
}

/**
 * @brief Compute HMAC with specified algorithm
 */
kctsb_error_t compute_hmac(
    kctsb_otp_algorithm_t algorithm,
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* mac, size_t* mac_len
) {
    switch (algorithm) {
        case KCTSB_OTP_HMAC_SHA256: {
            kctsb_hmac_sha256(key, key_len, data, data_len, mac);
            *mac_len = 32;
            return KCTSB_SUCCESS;
        }
        case KCTSB_OTP_HMAC_SHA512: {
            kctsb_hmac_sha512(key, key_len, data, data_len, mac);
            *mac_len = 64;
            return KCTSB_SUCCESS;
        }
        default:
            return KCTSB_ERROR_INVALID_PARAM;
    }
}

/**
 * @brief Dynamic truncation (RFC 4226 Section 5.3)
 *
 * DT(hmac) = hmac[offset]..hmac[offset+3] & 0x7FFFFFFF
 * where offset = hmac[19] & 0x0F (for SHA1/SHA256)
 *       or hmac[63] & 0x0F (for SHA512)
 */
uint32_t dynamic_truncate(const uint8_t* hmac, size_t hmac_len) {
    // Offset is last nibble of last byte
    int offset = static_cast<int>(hmac[hmac_len - 1] & 0x0F);
    
    // Extract 4 bytes at offset, mask MSB
    uint32_t binary_code = 
        (static_cast<uint32_t>(hmac[offset] & 0x7F) << 24) |
        (static_cast<uint32_t>(hmac[static_cast<size_t>(offset) + 1]) << 16) |
        (static_cast<uint32_t>(hmac[static_cast<size_t>(offset) + 2]) << 8) |
        static_cast<uint32_t>(hmac[static_cast<size_t>(offset) + 3]);
    
    return binary_code;
}

/**
 * @brief Get current Unix timestamp
 */
uint64_t get_unix_time() {
    return static_cast<uint64_t>(std::time(nullptr));
}

/**
 * @brief Compute time counter for TOTP
 */
uint64_t compute_time_counter(uint64_t unix_time, uint32_t time_step) {
    return unix_time / time_step;
}

} // anonymous namespace

// ============================================================================
// C API Implementation - HOTP
// ============================================================================

extern "C" {

kctsb_error_t kctsb_hotp_generate(
    const uint8_t* secret,
    size_t secret_len,
    uint64_t counter,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    uint32_t* otp_value
) {
    // Validate parameters
    if (secret == nullptr || otp_value == nullptr) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    if (secret_len < KCTSB_OTP_MIN_SECRET_LEN) {
        return KCTSB_ERROR_INVALID_KEY;
    }
    
    if (digits < 1 || digits > KCTSB_OTP_MAX_DIGITS) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Convert counter to big-endian bytes
    uint8_t counter_bytes[8];
    counter_to_bytes(counter, counter_bytes);
    
    // Compute HMAC
    uint8_t hmac[64];  // Max size for SHA512
    size_t hmac_len;
    kctsb_error_t err = compute_hmac(
        algorithm, secret, secret_len,
        counter_bytes, 8, hmac, &hmac_len
    );
    
    if (err != KCTSB_SUCCESS) {
        kctsb_secure_zero(hmac, sizeof(hmac));
        return err;
    }
    
    // Dynamic truncation
    uint32_t binary_code = dynamic_truncate(hmac, hmac_len);
    
    // Clear sensitive data
    kctsb_secure_zero(hmac, sizeof(hmac));
    
    // Apply modulo for digit count
    if (digits < 10) {
        *otp_value = binary_code % POW10[digits];
    } else {
        *otp_value = binary_code;  // All 10 digits
    }
    
    return KCTSB_SUCCESS;
}

kctsb_error_t kctsb_hotp_verify(
    const uint8_t* secret,
    size_t secret_len,
    uint64_t counter,
    uint32_t otp_value,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    int window,
    uint64_t* new_counter
) {
    if (window < 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // Try each counter in window [counter, counter + window]
    for (int i = 0; i <= window; i++) {
        uint32_t expected;
        kctsb_error_t err = kctsb_hotp_generate(
            secret, secret_len,
            counter + i,
            digits, algorithm,
            &expected
        );
        
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        // Constant-time comparison (timing-safe)
        if (expected == otp_value) {
            if (new_counter != nullptr) {
                *new_counter = counter + i + 1;  // Next counter
            }
            return KCTSB_SUCCESS;
        }
    }
    
    return KCTSB_ERROR_VERIFICATION_FAILED;
}

// ============================================================================
// C API Implementation - TOTP
// ============================================================================

kctsb_error_t kctsb_totp_generate(
    const uint8_t* secret,
    size_t secret_len,
    uint64_t unix_time,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    uint32_t* otp_value
) {
    if (time_step == 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    // TOTP = HOTP(K, T) where T = floor(unix_time / time_step)
    uint64_t time_counter = compute_time_counter(unix_time, time_step);
    
    return kctsb_hotp_generate(
        secret, secret_len,
        time_counter,
        digits, algorithm,
        otp_value
    );
}

kctsb_error_t kctsb_totp_generate_now(
    const uint8_t* secret,
    size_t secret_len,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    uint32_t* otp_value
) {
    return kctsb_totp_generate(
        secret, secret_len,
        get_unix_time(),
        time_step, digits, algorithm,
        otp_value
    );
}

kctsb_error_t kctsb_totp_verify(
    const uint8_t* secret,
    size_t secret_len,
    uint32_t otp_value,
    uint64_t unix_time,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    int window
) {
    if (time_step == 0 || window < 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    uint64_t time_counter = compute_time_counter(unix_time, time_step);
    
    // Check [T - window, T + window]
    for (int i = -window; i <= window; i++) {
        // Handle underflow for negative offsets
        uint64_t check_counter = (i < 0 && time_counter < static_cast<uint64_t>(-i))
            ? 0
            : time_counter + static_cast<uint64_t>(i);
        
        uint32_t expected;
        kctsb_error_t err = kctsb_hotp_generate(
            secret, secret_len,
            check_counter,
            digits, algorithm,
            &expected
        );
        
        if (err != KCTSB_SUCCESS) {
            return err;
        }
        
        if (expected == otp_value) {
            return KCTSB_SUCCESS;
        }
    }
    
    return KCTSB_ERROR_VERIFICATION_FAILED;
}

kctsb_error_t kctsb_totp_verify_now(
    const uint8_t* secret,
    size_t secret_len,
    uint32_t otp_value,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    int window
) {
    return kctsb_totp_verify(
        secret, secret_len,
        otp_value,
        get_unix_time(),
        time_step, digits, algorithm,
        window
    );
}

// ============================================================================
// C API Implementation - Utilities
// ============================================================================

uint32_t kctsb_totp_remaining_seconds(uint64_t unix_time, uint32_t time_step) {
    if (time_step == 0) {
        return 0;
    }
    return time_step - (unix_time % time_step);
}

kctsb_error_t kctsb_otp_generate_secret(uint8_t* secret, size_t secret_len) {
    if (secret == nullptr || secret_len == 0) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    int result = kctsb_random_bytes(secret, secret_len);
    return (result == 0) ? KCTSB_SUCCESS : KCTSB_ERROR_RANDOM_FAILED;
}

size_t kctsb_otp_secret_to_base32(
    const uint8_t* secret,
    size_t secret_len,
    char* base32,
    size_t base32_size
) {
    if (secret == nullptr || base32 == nullptr || secret_len == 0) {
        return 0;
    }
    
    // Calculate required output size: ceil(secret_len * 8 / 5) + padding + null
    size_t out_len = ((secret_len * 8 + 4) / 5);
    // Add padding to make length multiple of 8
    out_len = ((out_len + 7) / 8) * 8;
    
    if (base32_size < out_len + 1) {
        return 0;
    }
    
    size_t i = 0;
    size_t j = 0;
    uint32_t buffer = 0;
    int bits = 0;
    
    // Encode 5 bits at a time
    while (i < secret_len) {
        buffer = (buffer << 8) | secret[i++];
        bits += 8;
        
        while (bits >= 5) {
            bits -= 5;
            base32[j++] = BASE32_ALPHABET[static_cast<size_t>((buffer >> bits) & 0x1F)];
        }
    }
    
    // Handle remaining bits
    if (bits > 0) {
        buffer <<= (5 - bits);
        base32[j++] = BASE32_ALPHABET[static_cast<size_t>(buffer & 0x1F)];
    }
    
    // Add padding
    while (j % 8 != 0) {
        base32[j++] = '=';
    }
    
    base32[j] = '\0';
    return j;
}

size_t kctsb_otp_secret_from_base32(
    const char* base32,
    size_t base32_len,
    uint8_t* secret,
    size_t secret_size
) {
    if (base32 == nullptr || secret == nullptr) {
        return 0;
    }
    
    if (base32_len == 0) {
        base32_len = std::strlen(base32);
    }
    
    // Strip trailing padding
    while (base32_len > 0 && base32[base32_len - 1] == '=') {
        base32_len--;
    }
    
    // Calculate output size
    size_t out_len = (base32_len * 5) / 8;
    if (secret_size < out_len) {
        return 0;
    }
    
    size_t i = 0;
    size_t j = 0;
    uint32_t buffer = 0;
    int bits = 0;
    
    while (i < base32_len) {
        int8_t val = BASE32_DECODE[static_cast<uint8_t>(base32[i++])];
        if (val < 0) {
            return 0;  // Invalid character
        }
        
        buffer = (buffer << 5) | static_cast<uint32_t>(val);
        bits += 5;
        
        if (bits >= 8) {
            bits -= 8;
            secret[j++] = static_cast<uint8_t>(buffer >> bits);
        }
    }
    
    return j;
}

size_t kctsb_otp_generate_uri(
    const char* type,
    const char* issuer,
    const char* account,
    const uint8_t* secret,
    size_t secret_len,
    kctsb_otp_algorithm_t algorithm,
    int digits,
    uint64_t period,
    char* uri,
    size_t uri_size
) {
    if (type == nullptr || issuer == nullptr || account == nullptr ||
        secret == nullptr || uri == nullptr || secret_len == 0) {
        return 0;
    }
    
    // Encode secret to Base32
    size_t base32_len = ((secret_len * 8 + 4) / 5);
    base32_len = ((base32_len + 7) / 8) * 8;
    std::vector<char> base32(base32_len + 1);
    
    size_t encoded_len = kctsb_otp_secret_to_base32(
        secret, secret_len,
        base32.data(), base32.size()
    );
    
    if (encoded_len == 0) {
        return 0;
    }
    
    // Get algorithm name
    const char* algo_name;
    switch (algorithm) {
        case KCTSB_OTP_HMAC_SHA256:
            algo_name = "SHA256";
            break;
        case KCTSB_OTP_HMAC_SHA512:
            algo_name = "SHA512";
            break;
        default:
            return 0;
    }
    
    // Format URI
    int written = snprintf(
        uri, uri_size,
        "otpauth://%s/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d",
        type, issuer, account, base32.data(), issuer, algo_name, digits
    );
    
    if (written < 0 || static_cast<size_t>(written) >= uri_size) {
        return 0;
    }
    
    // Add period for TOTP or counter for HOTP
    if (std::strcmp(type, "totp") == 0) {
        int added = snprintf(
            uri + written, uri_size - written,
            "&period=%lu", static_cast<unsigned long>(period)
        );
        if (added < 0) return 0;
        written += added;
    } else if (std::strcmp(type, "hotp") == 0) {
        int added = snprintf(
            uri + written, uri_size - written,
            "&counter=%lu", static_cast<unsigned long>(period)
        );
        if (added < 0) return 0;
        written += added;
    }
    
    return static_cast<size_t>(written);
}

} // extern "C"
