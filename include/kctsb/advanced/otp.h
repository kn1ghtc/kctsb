/**
 * @file otp.h
 * @brief One-Time Password (OTP) Implementation - HOTP/TOTP
 *
 * Complete implementation of OTP algorithms:
 * - RFC 4226: HOTP (HMAC-Based One-Time Password)
 * - RFC 6238: TOTP (Time-Based One-Time Password)
 *
 * Supports multiple hash algorithms:
 * - HMAC-SHA256 (default, recommended)
 * - HMAC-SHA512 (for higher security)
 *
 * Note: SHA1 is not supported as it is deprecated for security applications.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_ADVANCED_OTP_H
#define KCTSB_ADVANCED_OTP_H

#include "kctsb/core/common.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

/**
 * @brief Hash algorithm for OTP
 */
typedef enum {
    KCTSB_OTP_HMAC_SHA256 = 0,  /**< HMAC-SHA256 (default, recommended) */
    KCTSB_OTP_HMAC_SHA512 = 1   /**< HMAC-SHA512 (higher security) */
} kctsb_otp_algorithm_t;

/**
 * @brief Default TOTP time step in seconds (RFC 6238)
 */
#define KCTSB_TOTP_DEFAULT_PERIOD 30

/**
 * @brief Default OTP digit count
 */
#define KCTSB_OTP_DEFAULT_DIGITS 6

/**
 * @brief Maximum supported OTP digits
 */
#define KCTSB_OTP_MAX_DIGITS 10

/**
 * @brief Minimum secret key length (RFC 4226 recommends at least 128 bits)
 */
#define KCTSB_OTP_MIN_SECRET_LEN 16

/**
 * @brief Recommended secret key length for SHA256 (256 bits)
 */
#define KCTSB_OTP_SECRET_LEN_SHA256 32

/**
 * @brief Recommended secret key length for SHA512 (512 bits)
 */
#define KCTSB_OTP_SECRET_LEN_SHA512 64

// ============================================================================
// HOTP Functions (RFC 4226)
// ============================================================================

/**
 * @brief Generate HOTP value
 *
 * Computes HOTP(K, C) = Truncate(HMAC(K, C)) mod 10^d
 *
 * @param secret Secret key (shared between client and server)
 * @param secret_len Length of secret key in bytes (min 16 bytes recommended)
 * @param counter Counter value (8-byte moving factor)
 * @param digits Number of digits in OTP (6-10, default 6)
 * @param algorithm Hash algorithm to use
 * @param otp_value Output OTP value (as uint32_t)
 * @return KCTSB_SUCCESS on success, error code otherwise
 */
KCTSB_API kctsb_error_t kctsb_hotp_generate(
    const uint8_t* secret,
    size_t secret_len,
    uint64_t counter,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    uint32_t* otp_value
);

/**
 * @brief Verify HOTP value
 *
 * Verifies an HOTP value against expected counter.
 * Supports look-ahead window for resynchronization.
 *
 * @param secret Secret key
 * @param secret_len Length of secret key
 * @param counter Current counter value
 * @param otp_value OTP value to verify
 * @param digits Number of digits
 * @param algorithm Hash algorithm
 * @param window Look-ahead window size (0 = exact match only)
 * @param new_counter Output: new counter value if verification succeeds
 * @return KCTSB_SUCCESS if OTP is valid, KCTSB_ERROR_VERIFY_FAILED otherwise
 */
KCTSB_API kctsb_error_t kctsb_hotp_verify(
    const uint8_t* secret,
    size_t secret_len,
    uint64_t counter,
    uint32_t otp_value,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    int window,
    uint64_t* new_counter
);

// ============================================================================
// TOTP Functions (RFC 6238)
// ============================================================================

/**
 * @brief Generate TOTP value
 *
 * Computes TOTP using current Unix time.
 * TOTP(K, T) = HOTP(K, floor((T - T0) / X))
 * where T0 = 0 (Unix epoch) and X = time_step (default 30 seconds)
 *
 * @param secret Secret key
 * @param secret_len Length of secret key
 * @param unix_time Current Unix timestamp (seconds since epoch)
 * @param time_step Time step in seconds (default 30)
 * @param digits Number of digits (6-10)
 * @param algorithm Hash algorithm
 * @param otp_value Output OTP value
 * @return KCTSB_SUCCESS on success, error code otherwise
 */
KCTSB_API kctsb_error_t kctsb_totp_generate(
    const uint8_t* secret,
    size_t secret_len,
    uint64_t unix_time,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    uint32_t* otp_value
);

/**
 * @brief Generate TOTP value using current system time
 *
 * Convenience function that uses current system time.
 *
 * @param secret Secret key
 * @param secret_len Length of secret key
 * @param time_step Time step in seconds
 * @param digits Number of digits
 * @param algorithm Hash algorithm
 * @param otp_value Output OTP value
 * @return KCTSB_SUCCESS on success, error code otherwise
 */
KCTSB_API kctsb_error_t kctsb_totp_generate_now(
    const uint8_t* secret,
    size_t secret_len,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    uint32_t* otp_value
);

/**
 * @brief Verify TOTP value
 *
 * Verifies TOTP with time window to account for clock drift.
 *
 * @param secret Secret key
 * @param secret_len Length of secret key
 * @param otp_value OTP value to verify
 * @param unix_time Current Unix timestamp
 * @param time_step Time step in seconds
 * @param digits Number of digits
 * @param algorithm Hash algorithm
 * @param window Number of time steps to check before/after current
 * @return KCTSB_SUCCESS if valid, KCTSB_ERROR_VERIFY_FAILED otherwise
 */
KCTSB_API kctsb_error_t kctsb_totp_verify(
    const uint8_t* secret,
    size_t secret_len,
    uint32_t otp_value,
    uint64_t unix_time,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    int window
);

/**
 * @brief Verify TOTP using current system time
 *
 * @param secret Secret key
 * @param secret_len Length of secret key
 * @param otp_value OTP value to verify
 * @param time_step Time step in seconds
 * @param digits Number of digits
 * @param algorithm Hash algorithm
 * @param window Time window
 * @return KCTSB_SUCCESS if valid, error code otherwise
 */
KCTSB_API kctsb_error_t kctsb_totp_verify_now(
    const uint8_t* secret,
    size_t secret_len,
    uint32_t otp_value,
    uint32_t time_step,
    int digits,
    kctsb_otp_algorithm_t algorithm,
    int window
);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get time remaining until next TOTP period
 *
 * @param unix_time Current Unix timestamp
 * @param time_step Time step in seconds
 * @return Seconds remaining until next period
 */
KCTSB_API uint32_t kctsb_totp_remaining_seconds(
    uint64_t unix_time,
    uint32_t time_step
);

/**
 * @brief Generate random secret key
 *
 * Generates a cryptographically secure random secret key
 * suitable for OTP.
 *
 * @param secret Output buffer for secret
 * @param secret_len Length of secret to generate
 * @return KCTSB_SUCCESS on success, error code otherwise
 */
KCTSB_API kctsb_error_t kctsb_otp_generate_secret(
    uint8_t* secret,
    size_t secret_len
);

/**
 * @brief Encode secret to Base32 for QR code generation
 *
 * Base32 encoding is standard for Google Authenticator compatibility.
 *
 * @param secret Input secret key
 * @param secret_len Length of secret
 * @param base32 Output Base32 string (must be pre-allocated)
 * @param base32_size Size of output buffer
 * @return Length of encoded string, 0 on error
 */
KCTSB_API size_t kctsb_otp_secret_to_base32(
    const uint8_t* secret,
    size_t secret_len,
    char* base32,
    size_t base32_size
);

/**
 * @brief Decode Base32 secret
 *
 * @param base32 Input Base32 string
 * @param base32_len Length of Base32 string
 * @param secret Output secret buffer
 * @param secret_size Size of output buffer
 * @return Length of decoded secret, 0 on error
 */
KCTSB_API size_t kctsb_otp_secret_from_base32(
    const char* base32,
    size_t base32_len,
    uint8_t* secret,
    size_t secret_size
);

/**
 * @brief Generate otpauth:// URI for QR code
 *
 * Generates a URI in the format:
 * otpauth://totp/ISSUER:ACCOUNT?secret=BASE32SECRET&issuer=ISSUER&algorithm=SHA256&digits=6&period=30
 *
 * @param type "totp" or "hotp"
 * @param issuer Service/application name
 * @param account User account name
 * @param secret Secret key
 * @param secret_len Length of secret
 * @param algorithm Hash algorithm
 * @param digits Number of digits
 * @param period Time step (for TOTP) or initial counter (for HOTP)
 * @param uri Output URI buffer
 * @param uri_size Size of output buffer
 * @return Length of URI string, 0 on error
 */
KCTSB_API size_t kctsb_otp_generate_uri(
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
);

#ifdef __cplusplus
}
#endif

#endif // KCTSB_ADVANCED_OTP_H
