/**
 * @file encoding.h
 * @brief Comprehensive encoding utilities for cryptographic data conversion
 *
 * Provides complete encoding/decoding utilities for:
 * - Hexadecimal (uppercase/lowercase)
 * - Base64 (standard and URL-safe variants)
 * - Bytes/String conversions
 * - Big integer conversions (for cryptographic operations)
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_UTILS_ENCODING_H
#define KCTSB_UTILS_ENCODING_H

#include "kctsb/core/common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Hexadecimal Encoding/Decoding (C API)
// ============================================================================

/**
 * @brief Encode binary data to hexadecimal string (lowercase)
 *
 * @param data Input binary data
 * @param len Length of input data
 * @param hex Output buffer (must be at least len*2+1 bytes)
 * @param hex_size Size of output buffer
 * @return Number of characters written (excluding null terminator), 0 on error
 */
KCTSB_API size_t kctsb_hex_encode(const uint8_t* data, size_t len, char* hex, size_t hex_size);

/**
 * @brief Encode binary data to hexadecimal string (uppercase)
 *
 * @param data Input binary data
 * @param len Length of input data
 * @param hex Output buffer (must be at least len*2+1 bytes)
 * @param hex_size Size of output buffer
 * @return Number of characters written (excluding null terminator), 0 on error
 */
KCTSB_API size_t kctsb_hex_encode_upper(const uint8_t* data, size_t len, char* hex, size_t hex_size);

/**
 * @brief Decode hexadecimal string to binary data
 *
 * @param hex Input hex string (may contain 0x prefix)
 * @param hex_len Length of hex string (0 for null-terminated)
 * @param data Output buffer
 * @param data_size Size of output buffer
 * @return Number of bytes written, 0 on error
 */
KCTSB_API size_t kctsb_hex_decode(const char* hex, size_t hex_len, uint8_t* data, size_t data_size);

/**
 * @brief Check if a character is valid hexadecimal
 */
KCTSB_API int kctsb_is_hex_char(char c);

/**
 * @brief Get hex character value (0-15), returns -1 for invalid
 */
KCTSB_API int kctsb_hex_char_value(char c);

// ============================================================================
// Base64 Encoding/Decoding (C API)
// ============================================================================

/**
 * @brief Encode binary data to Base64 string (standard alphabet)
 *
 * @param data Input binary data
 * @param len Length of input data
 * @param b64 Output buffer (must be at least ((len+2)/3)*4+1 bytes)
 * @param b64_size Size of output buffer
 * @return Number of characters written (excluding null terminator), 0 on error
 */
KCTSB_API size_t kctsb_base64_encode(const uint8_t* data, size_t len, char* b64, size_t b64_size);

/**
 * @brief Encode binary data to URL-safe Base64 (RFC 4648 section 5)
 *
 * Uses '-' and '_' instead of '+' and '/', no padding
 *
 * @param data Input binary data
 * @param len Length of input data
 * @param b64 Output buffer
 * @param b64_size Size of output buffer
 * @return Number of characters written, 0 on error
 */
KCTSB_API size_t kctsb_base64url_encode(const uint8_t* data, size_t len, char* b64, size_t b64_size);

/**
 * @brief Decode Base64 string to binary data
 *
 * Handles both standard and URL-safe Base64
 *
 * @param b64 Input Base64 string
 * @param b64_len Length of Base64 string (0 for null-terminated)
 * @param data Output buffer
 * @param data_size Size of output buffer
 * @return Number of bytes written, 0 on error
 */
KCTSB_API size_t kctsb_base64_decode(const char* b64, size_t b64_len, uint8_t* data, size_t data_size);

/**
 * @brief Calculate Base64 encoded length
 */
KCTSB_API size_t kctsb_base64_encoded_len(size_t input_len);

/**
 * @brief Calculate maximum decoded length from Base64
 */
KCTSB_API size_t kctsb_base64_decoded_len(const char* b64, size_t b64_len);

// ============================================================================
// String/Bytes Conversions (C API)
// ============================================================================

/**
 * @brief Convert UTF-8 string to byte array (no transformation)
 *
 * @param str Input string
 * @param str_len Length of string (0 for null-terminated)
 * @param bytes Output buffer
 * @param bytes_size Size of output buffer
 * @return Number of bytes written
 */
KCTSB_API size_t kctsb_string_to_bytes(const char* str, size_t str_len, uint8_t* bytes, size_t bytes_size);

/**
 * @brief Convert byte array to UTF-8 string (validates UTF-8)
 *
 * @param bytes Input bytes
 * @param bytes_len Length of bytes
 * @param str Output string buffer
 * @param str_size Size of string buffer (includes null terminator)
 * @return Number of characters written (excluding null), 0 on invalid UTF-8
 */
KCTSB_API size_t kctsb_bytes_to_string(const uint8_t* bytes, size_t bytes_len, char* str, size_t str_size);

// ============================================================================
// Big Integer Conversions (C API)
// ============================================================================

/**
 * @brief Convert unsigned 64-bit integer to big-endian bytes
 *
 * @param value Input value
 * @param bytes Output buffer (must be at least 8 bytes)
 * @param bytes_size Size of output buffer
 * @return Number of bytes written (always 8 or 0 on error)
 */
KCTSB_API size_t kctsb_uint64_to_bytes_be(uint64_t value, uint8_t* bytes, size_t bytes_size);

/**
 * @brief Convert unsigned 64-bit integer to little-endian bytes
 */
KCTSB_API size_t kctsb_uint64_to_bytes_le(uint64_t value, uint8_t* bytes, size_t bytes_size);

/**
 * @brief Convert big-endian bytes to unsigned 64-bit integer
 *
 * @param bytes Input bytes (must be exactly 8 bytes)
 * @param bytes_len Length of input bytes
 * @param value Output value
 * @return 1 on success, 0 on error
 */
KCTSB_API int kctsb_bytes_to_uint64_be(const uint8_t* bytes, size_t bytes_len, uint64_t* value);

/**
 * @brief Convert little-endian bytes to unsigned 64-bit integer
 */
KCTSB_API int kctsb_bytes_to_uint64_le(const uint8_t* bytes, size_t bytes_len, uint64_t* value);

/**
 * @brief Convert variable-length big-endian bytes to uint64
 *
 * Handles inputs from 1-8 bytes, zero-pads on the left
 *
 * @param bytes Input bytes
 * @param bytes_len Length of input (1-8)
 * @param value Output value
 * @return 1 on success, 0 on error
 */
KCTSB_API int kctsb_bytes_to_uint64_be_var(const uint8_t* bytes, size_t bytes_len, uint64_t* value);

#ifdef __cplusplus
}
#endif

// ============================================================================
// C++ API
// ============================================================================
#ifdef __cplusplus

#include "kctsb/core/types.h"  // For ByteVec
#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace kctsb {
namespace encoding {

/**
 * @brief Encoding exception for invalid input
 */
class EncodingError : public std::runtime_error {
public:
    explicit EncodingError(const std::string& msg) : std::runtime_error(msg) {}
};

// ============================================================================
// Hex Encoding (C++ API)
// ============================================================================

/**
 * @brief Encode bytes to lowercase hex string
 */
std::string hexEncode(const ByteVec& data);
std::string hexEncode(const uint8_t* data, size_t len);

/**
 * @brief Encode bytes to uppercase hex string
 */
std::string hexEncodeUpper(const ByteVec& data);
std::string hexEncodeUpper(const uint8_t* data, size_t len);

/**
 * @brief Decode hex string to bytes
 * @throws EncodingError on invalid input
 */
ByteVec hexDecode(const std::string& hex);

/**
 * @brief Try to decode hex string, returns empty on error
 */
ByteVec hexDecodeSafe(const std::string& hex) noexcept;

/**
 * @brief Check if string is valid hex
 */
bool isValidHex(const std::string& str) noexcept;

// ============================================================================
// Base64 Encoding (C++ API)
// ============================================================================

/**
 * @brief Encode bytes to standard Base64 string
 */
std::string base64Encode(const ByteVec& data);
std::string base64Encode(const uint8_t* data, size_t len);

/**
 * @brief Encode bytes to URL-safe Base64 (no padding)
 */
std::string base64UrlEncode(const ByteVec& data);
std::string base64UrlEncode(const uint8_t* data, size_t len);

/**
 * @brief Decode Base64 string to bytes
 * @throws EncodingError on invalid input
 */
ByteVec base64Decode(const std::string& b64);

/**
 * @brief Try to decode Base64 string, returns empty on error
 */
ByteVec base64DecodeSafe(const std::string& b64) noexcept;

/**
 * @brief Check if string is valid Base64
 */
bool isValidBase64(const std::string& str) noexcept;

// ============================================================================
// String/Bytes Conversions (C++ API)
// ============================================================================

/**
 * @brief Convert string to bytes (UTF-8 encoding)
 */
ByteVec stringToBytes(const std::string& str);

/**
 * @brief Convert bytes to string (validates UTF-8)
 * @throws EncodingError if bytes are not valid UTF-8
 */
std::string bytesToString(const ByteVec& bytes);

/**
 * @brief Convert bytes to string, replacing invalid sequences
 */
std::string bytesToStringSafe(const ByteVec& bytes) noexcept;

// ============================================================================
// Big Integer Conversions (C++ API)
// ============================================================================

/**
 * @brief Convert uint64 to big-endian bytes
 */
ByteVec uint64ToBytesBE(uint64_t value);

/**
 * @brief Convert uint64 to little-endian bytes
 */
ByteVec uint64ToBytesLE(uint64_t value);

/**
 * @brief Convert big-endian bytes to uint64
 * @throws EncodingError if bytes length is not 8
 */
uint64_t bytesToUint64BE(const ByteVec& bytes);

/**
 * @brief Convert little-endian bytes to uint64
 * @throws EncodingError if bytes length is not 8
 */
uint64_t bytesToUint64LE(const ByteVec& bytes);

/**
 * @brief Convert variable-length big-endian bytes to uint64
 *
 * @param bytes Input bytes (1-8)
 * @return uint64 value
 * @throws EncodingError if bytes length > 8
 */
uint64_t bytesToUint64BEVar(const ByteVec& bytes);

/**
 * @brief Convert uint64 to minimum-length big-endian bytes
 *
 * Returns 1-8 bytes depending on value magnitude
 */
ByteVec uint64ToMinBytesBE(uint64_t value);

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * @brief XOR two byte vectors
 * @throws EncodingError if sizes don't match
 */
ByteVec xorBytes(const ByteVec& a, const ByteVec& b);

/**
 * @brief Pad bytes to specified length (PKCS#7)
 */
ByteVec padPKCS7(const ByteVec& data, size_t block_size);

/**
 * @brief Remove PKCS#7 padding
 * @throws EncodingError on invalid padding
 */
ByteVec unpadPKCS7(const ByteVec& data);

/**
 * @brief Constant-time comparison of byte vectors
 */
bool secureCompare(const ByteVec& a, const ByteVec& b) noexcept;

} // namespace encoding

// Convenience aliases at kctsb namespace level (backward compatibility)
using encoding::hexEncode;
using encoding::hexDecode;
using encoding::base64Encode;
using encoding::base64Decode;
using encoding::stringToBytes;
using encoding::bytesToString;

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_UTILS_ENCODING_H
