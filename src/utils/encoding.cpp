/**
 * @file encoding.cpp
 * @brief Comprehensive encoding utilities implementation
 *
 * Implements all encoding/decoding functions for:
 * - Hexadecimal (uppercase/lowercase)
 * - Base64 (standard and URL-safe)
 * - Bytes/String conversions
 * - Big integer conversions
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#include "kctsb/utils/encoding.h"
#include "kctsb/core/security.h"
#include <cstring>
#include <algorithm>

// ============================================================================
// Internal Constants
// ============================================================================

static const char HEX_LOWER[] = "0123456789abcdef";
static const char HEX_UPPER[] = "0123456789ABCDEF";

static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char BASE64_URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Lookup table for Base64 decoding (-1 = invalid, -2 = padding '=')
static const int8_t BASE64_DECODE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x00-0x0F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x10-0x1F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,  // 0x20-0x2F (+,-)
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,  // 0x30-0x3F (0-9,=)
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // 0x40-0x4F (A-O)
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,  // 0x50-0x5F (P-Z,_)
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  // 0x60-0x6F (a-o)
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  // 0x70-0x7F (p-z)
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x80-0x8F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0x90-0x9F
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xA0-0xAF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xB0-0xBF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xC0-0xCF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xD0-0xDF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0xE0-0xEF
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   // 0xF0-0xFF
};

// ============================================================================
// C API: Hex Encoding/Decoding
// ============================================================================

extern "C" {

size_t kctsb_hex_encode(const uint8_t* data, size_t len, char* hex, size_t hex_size) {
    if (data == nullptr || hex == nullptr || hex_size < len * 2 + 1) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = HEX_LOWER[data[i] >> 4];
        hex[i * 2 + 1] = HEX_LOWER[data[i] & 0x0F];
    }
    hex[len * 2] = '\0';

    return len * 2;
}

size_t kctsb_hex_encode_upper(const uint8_t* data, size_t len, char* hex, size_t hex_size) {
    if (data == nullptr || hex == nullptr || hex_size < len * 2 + 1) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = HEX_UPPER[data[i] >> 4];
        hex[i * 2 + 1] = HEX_UPPER[data[i] & 0x0F];
    }
    hex[len * 2] = '\0';

    return len * 2;
}

int kctsb_is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

int kctsb_hex_char_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t kctsb_hex_decode(const char* hex, size_t hex_len, uint8_t* data, size_t data_size) {
    if (hex == nullptr || data == nullptr) {
        return 0;
    }

    // Calculate actual length if 0 passed
    if (hex_len == 0) {
        hex_len = strlen(hex);
    }

    // Skip 0x prefix if present
    if (hex_len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
        hex_len -= 2;
    }

    // Must be even length
    if (hex_len % 2 != 0) {
        return 0;
    }

    size_t out_len = hex_len / 2;
    if (data_size < out_len) {
        return 0;
    }

    for (size_t i = 0; i < out_len; i++) {
        int hi = kctsb_hex_char_value(hex[i * 2]);
        int lo = kctsb_hex_char_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        data[i] = (uint8_t)((hi << 4) | lo);
    }

    return out_len;
}

// ============================================================================
// C API: Base64 Encoding/Decoding
// ============================================================================

size_t kctsb_base64_encoded_len(size_t input_len) {
    return ((input_len + 2) / 3) * 4;
}

size_t kctsb_base64_decoded_len(const char* b64, size_t b64_len) {
    if (b64 == nullptr || b64_len == 0) {
        return 0;
    }
    if (b64_len == 0) {
        b64_len = strlen(b64);
    }

    size_t len = (b64_len / 4) * 3;

    // Account for padding
    if (b64_len >= 1 && b64[b64_len - 1] == '=') len--;
    if (b64_len >= 2 && b64[b64_len - 2] == '=') len--;

    return len;
}

size_t kctsb_base64_encode(const uint8_t* data, size_t len, char* b64, size_t b64_size) {
    if (data == nullptr || b64 == nullptr) {
        return 0;
    }

    size_t out_len = kctsb_base64_encoded_len(len);
    if (b64_size < out_len + 1) {
        return 0;
    }

    size_t i = 0, j = 0;
    uint8_t buf[3];
    size_t buf_len = 0;

    while (i < len) {
        buf[buf_len++] = data[i++];

        if (buf_len == 3) {
            b64[j++] = BASE64_CHARS[(buf[0] >> 2) & 0x3F];
            b64[j++] = BASE64_CHARS[((buf[0] << 4) | (buf[1] >> 4)) & 0x3F];
            b64[j++] = BASE64_CHARS[((buf[1] << 2) | (buf[2] >> 6)) & 0x3F];
            b64[j++] = BASE64_CHARS[buf[2] & 0x3F];
            buf_len = 0;
        }
    }

    // Handle remaining bytes
    if (buf_len > 0) {
        if (buf_len == 1) {
            b64[j++] = BASE64_CHARS[(buf[0] >> 2) & 0x3F];
            b64[j++] = BASE64_CHARS[(buf[0] << 4) & 0x3F];
            b64[j++] = '=';
            b64[j++] = '=';
        } else { // buf_len == 2
            b64[j++] = BASE64_CHARS[(buf[0] >> 2) & 0x3F];
            b64[j++] = BASE64_CHARS[((buf[0] << 4) | (buf[1] >> 4)) & 0x3F];
            b64[j++] = BASE64_CHARS[(buf[1] << 2) & 0x3F];
            b64[j++] = '=';
        }
    }

    b64[j] = '\0';
    return j;
}

size_t kctsb_base64url_encode(const uint8_t* data, size_t len, char* b64, size_t b64_size) {
    if (data == nullptr || b64 == nullptr) {
        return 0;
    }

    // Calculate size without padding
    size_t out_len = ((len * 4) + 2) / 3;
    if (b64_size < out_len + 1) {
        return 0;
    }

    size_t i = 0, j = 0;
    uint8_t buf[3];
    size_t buf_len = 0;

    while (i < len) {
        buf[buf_len++] = data[i++];

        if (buf_len == 3) {
            b64[j++] = BASE64_URL_CHARS[(buf[0] >> 2) & 0x3F];
            b64[j++] = BASE64_URL_CHARS[((buf[0] << 4) | (buf[1] >> 4)) & 0x3F];
            b64[j++] = BASE64_URL_CHARS[((buf[1] << 2) | (buf[2] >> 6)) & 0x3F];
            b64[j++] = BASE64_URL_CHARS[buf[2] & 0x3F];
            buf_len = 0;
        }
    }

    // Handle remaining bytes (no padding for URL-safe)
    if (buf_len > 0) {
        if (buf_len == 1) {
            b64[j++] = BASE64_URL_CHARS[(buf[0] >> 2) & 0x3F];
            b64[j++] = BASE64_URL_CHARS[(buf[0] << 4) & 0x3F];
        } else { // buf_len == 2
            b64[j++] = BASE64_URL_CHARS[(buf[0] >> 2) & 0x3F];
            b64[j++] = BASE64_URL_CHARS[((buf[0] << 4) | (buf[1] >> 4)) & 0x3F];
            b64[j++] = BASE64_URL_CHARS[(buf[1] << 2) & 0x3F];
        }
    }

    b64[j] = '\0';
    return j;
}

size_t kctsb_base64_decode(const char* b64, size_t b64_len, uint8_t* data, size_t data_size) {
    if (b64 == nullptr || data == nullptr) {
        return 0;
    }

    if (b64_len == 0) {
        b64_len = strlen(b64);
    }

    if (b64_len == 0) {
        return 0;
    }

    // Skip whitespace at end
    while (b64_len > 0 && (b64[b64_len - 1] == '\n' || b64[b64_len - 1] == '\r' ||
                           b64[b64_len - 1] == ' ' || b64[b64_len - 1] == '\t')) {
        b64_len--;
    }

    size_t out_len = kctsb_base64_decoded_len(b64, b64_len);
    if (data_size < out_len) {
        return 0;
    }

    size_t i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;

    while (i < b64_len) {
        char c = b64[i++];

        // Skip whitespace
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            continue;
        }

        int8_t val = BASE64_DECODE[(uint8_t)c];

        if (val == -2) { // Padding '='
            break;
        }
        if (val == -1) { // Invalid character
            return 0;
        }

        buf = (buf << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            data[j++] = (uint8_t)(buf >> bits);
        }
    }

    return j;
}

// ============================================================================
// C API: String/Bytes Conversions
// ============================================================================

size_t kctsb_string_to_bytes(const char* str, size_t str_len, uint8_t* bytes, size_t bytes_size) {
    if (str == nullptr || bytes == nullptr) {
        return 0;
    }

    if (str_len == 0) {
        str_len = strlen(str);
    }

    if (bytes_size < str_len) {
        return 0;
    }

    memcpy(bytes, str, str_len);
    return str_len;
}

// Simple UTF-8 validation
static bool is_valid_utf8(const uint8_t* bytes, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (bytes[i] < 0x80) {
            i++;
        } else if ((bytes[i] & 0xE0) == 0xC0) {
            if (i + 1 >= len || (bytes[i+1] & 0xC0) != 0x80) return false;
            i += 2;
        } else if ((bytes[i] & 0xF0) == 0xE0) {
            if (i + 2 >= len || (bytes[i+1] & 0xC0) != 0x80 || (bytes[i+2] & 0xC0) != 0x80) return false;
            i += 3;
        } else if ((bytes[i] & 0xF8) == 0xF0) {
            if (i + 3 >= len || (bytes[i+1] & 0xC0) != 0x80 ||
                (bytes[i+2] & 0xC0) != 0x80 || (bytes[i+3] & 0xC0) != 0x80) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

size_t kctsb_bytes_to_string(const uint8_t* bytes, size_t bytes_len, char* str, size_t str_size) {
    if (bytes == nullptr || str == nullptr) {
        return 0;
    }

    if (str_size < bytes_len + 1) {
        return 0;
    }

    // Validate UTF-8
    if (!is_valid_utf8(bytes, bytes_len)) {
        return 0;
    }

    memcpy(str, bytes, bytes_len);
    str[bytes_len] = '\0';
    return bytes_len;
}

// ============================================================================
// C API: Big Integer Conversions
// ============================================================================

size_t kctsb_uint64_to_bytes_be(uint64_t value, uint8_t* bytes, size_t bytes_size) {
    if (bytes == nullptr || bytes_size < 8) {
        return 0;
    }

    bytes[0] = (uint8_t)(value >> 56);
    bytes[1] = (uint8_t)(value >> 48);
    bytes[2] = (uint8_t)(value >> 40);
    bytes[3] = (uint8_t)(value >> 32);
    bytes[4] = (uint8_t)(value >> 24);
    bytes[5] = (uint8_t)(value >> 16);
    bytes[6] = (uint8_t)(value >> 8);
    bytes[7] = (uint8_t)value;

    return 8;
}

size_t kctsb_uint64_to_bytes_le(uint64_t value, uint8_t* bytes, size_t bytes_size) {
    if (bytes == nullptr || bytes_size < 8) {
        return 0;
    }

    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
    bytes[4] = (uint8_t)(value >> 32);
    bytes[5] = (uint8_t)(value >> 40);
    bytes[6] = (uint8_t)(value >> 48);
    bytes[7] = (uint8_t)(value >> 56);

    return 8;
}

int kctsb_bytes_to_uint64_be(const uint8_t* bytes, size_t bytes_len, uint64_t* value) {
    if (bytes == nullptr || value == nullptr || bytes_len != 8) {
        return 0;
    }

    *value = ((uint64_t)bytes[0] << 56) |
             ((uint64_t)bytes[1] << 48) |
             ((uint64_t)bytes[2] << 40) |
             ((uint64_t)bytes[3] << 32) |
             ((uint64_t)bytes[4] << 24) |
             ((uint64_t)bytes[5] << 16) |
             ((uint64_t)bytes[6] << 8) |
             ((uint64_t)bytes[7]);

    return 1;
}

int kctsb_bytes_to_uint64_le(const uint8_t* bytes, size_t bytes_len, uint64_t* value) {
    if (bytes == nullptr || value == nullptr || bytes_len != 8) {
        return 0;
    }

    *value = ((uint64_t)bytes[7] << 56) |
             ((uint64_t)bytes[6] << 48) |
             ((uint64_t)bytes[5] << 40) |
             ((uint64_t)bytes[4] << 32) |
             ((uint64_t)bytes[3] << 24) |
             ((uint64_t)bytes[2] << 16) |
             ((uint64_t)bytes[1] << 8) |
             ((uint64_t)bytes[0]);

    return 1;
}

int kctsb_bytes_to_uint64_be_var(const uint8_t* bytes, size_t bytes_len, uint64_t* value) {
    if (bytes == nullptr || value == nullptr || bytes_len == 0 || bytes_len > 8) {
        return 0;
    }

    *value = 0;
    for (size_t i = 0; i < bytes_len; i++) {
        *value = (*value << 8) | bytes[i];
    }

    return 1;
}

} // extern "C"

// ============================================================================
// C++ API Implementation
// ============================================================================

namespace kctsb {
namespace encoding {

// ============================================================================
// Hex Encoding (C++ API)
// ============================================================================

std::string hexEncode(const ByteVec& data) {
    return hexEncode(data.data(), data.size());
}

std::string hexEncode(const uint8_t* data, size_t len) {
    std::string result(len * 2, '\0');
    kctsb_hex_encode(data, len, result.data(), result.size() + 1);
    return result;
}

std::string hexEncodeUpper(const ByteVec& data) {
    return hexEncodeUpper(data.data(), data.size());
}

std::string hexEncodeUpper(const uint8_t* data, size_t len) {
    std::string result(len * 2, '\0');
    kctsb_hex_encode_upper(data, len, result.data(), result.size() + 1);
    return result;
}

ByteVec hexDecode(const std::string& hex) {
    ByteVec result(hex.size() / 2);
    size_t decoded = kctsb_hex_decode(hex.c_str(), hex.size(), result.data(), result.size());
    if (decoded == 0 && !hex.empty()) {
        throw EncodingError("Invalid hex string: " + hex.substr(0, 20));
    }
    result.resize(decoded);
    return result;
}

ByteVec hexDecodeSafe(const std::string& hex) noexcept {
    ByteVec result(hex.size() / 2);
    size_t decoded = kctsb_hex_decode(hex.c_str(), hex.size(), result.data(), result.size());
    result.resize(decoded);
    return result;
}

bool isValidHex(const std::string& str) noexcept {
    size_t start = 0;
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        start = 2;
    }

    if ((str.size() - start) % 2 != 0) {
        return false;
    }

    for (size_t i = start; i < str.size(); i++) {
        if (!kctsb_is_hex_char(str[i])) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Base64 Encoding (C++ API)
// ============================================================================

std::string base64Encode(const ByteVec& data) {
    return base64Encode(data.data(), data.size());
}

std::string base64Encode(const uint8_t* data, size_t len) {
    size_t out_len = kctsb_base64_encoded_len(len);
    std::string result(out_len, '\0');
    kctsb_base64_encode(data, len, result.data(), result.size() + 1);
    return result;
}

std::string base64UrlEncode(const ByteVec& data) {
    return base64UrlEncode(data.data(), data.size());
}

std::string base64UrlEncode(const uint8_t* data, size_t len) {
    size_t out_len = ((len * 4) + 2) / 3;
    std::string result(out_len, '\0');
    kctsb_base64url_encode(data, len, result.data(), result.size() + 1);
    return result;
}

ByteVec base64Decode(const std::string& b64) {
    size_t max_len = kctsb_base64_decoded_len(b64.c_str(), b64.size());
    ByteVec result(max_len);
    size_t decoded = kctsb_base64_decode(b64.c_str(), b64.size(), result.data(), result.size());
    if (decoded == 0 && !b64.empty()) {
        throw EncodingError("Invalid Base64 string");
    }
    result.resize(decoded);
    return result;
}

ByteVec base64DecodeSafe(const std::string& b64) noexcept {
    size_t max_len = kctsb_base64_decoded_len(b64.c_str(), b64.size());
    ByteVec result(max_len);
    size_t decoded = kctsb_base64_decode(b64.c_str(), b64.size(), result.data(), result.size());
    result.resize(decoded);
    return result;
}

bool isValidBase64(const std::string& str) noexcept {
    for (char c : str) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int8_t val = BASE64_DECODE[(uint8_t)c];
        if (val == -1) return false;
    }
    return true;
}

// ============================================================================
// String/Bytes Conversions (C++ API)
// ============================================================================

ByteVec stringToBytes(const std::string& str) {
    return ByteVec(str.begin(), str.end());
}

std::string bytesToString(const ByteVec& bytes) {
    if (!is_valid_utf8(bytes.data(), bytes.size())) {
        throw EncodingError("Invalid UTF-8 sequence");
    }
    return std::string(bytes.begin(), bytes.end());
}

std::string bytesToStringSafe(const ByteVec& bytes) noexcept {
    std::string result;
    result.reserve(bytes.size());

    size_t i = 0;
    while (i < bytes.size()) {
        if (bytes[i] < 0x80) {
            result += static_cast<char>(bytes[i]);
            i++;
        } else if ((bytes[i] & 0xE0) == 0xC0 && i + 1 < bytes.size() &&
                   (bytes[i+1] & 0xC0) == 0x80) {
            result += static_cast<char>(bytes[i]);
            result += static_cast<char>(bytes[i+1]);
            i += 2;
        } else if ((bytes[i] & 0xF0) == 0xE0 && i + 2 < bytes.size() &&
                   (bytes[i+1] & 0xC0) == 0x80 && (bytes[i+2] & 0xC0) == 0x80) {
            result += static_cast<char>(bytes[i]);
            result += static_cast<char>(bytes[i+1]);
            result += static_cast<char>(bytes[i+2]);
            i += 3;
        } else if ((bytes[i] & 0xF8) == 0xF0 && i + 3 < bytes.size() &&
                   (bytes[i+1] & 0xC0) == 0x80 && (bytes[i+2] & 0xC0) == 0x80 &&
                   (bytes[i+3] & 0xC0) == 0x80) {
            result += static_cast<char>(bytes[i]);
            result += static_cast<char>(bytes[i+1]);
            result += static_cast<char>(bytes[i+2]);
            result += static_cast<char>(bytes[i+3]);
            i += 4;
        } else {
            // Replace invalid byte with replacement character
            result += "\xEF\xBF\xBD"; // U+FFFD
            i++;
        }
    }

    return result;
}

// ============================================================================
// Big Integer Conversions (C++ API)
// ============================================================================

ByteVec uint64ToBytesBE(uint64_t value) {
    ByteVec result(8);
    kctsb_uint64_to_bytes_be(value, result.data(), 8);
    return result;
}

ByteVec uint64ToBytesLE(uint64_t value) {
    ByteVec result(8);
    kctsb_uint64_to_bytes_le(value, result.data(), 8);
    return result;
}

uint64_t bytesToUint64BE(const ByteVec& bytes) {
    if (bytes.size() != 8) {
        throw EncodingError("Expected 8 bytes for uint64, got " + std::to_string(bytes.size()));
    }
    uint64_t value = 0;
    if (kctsb_bytes_to_uint64_be(bytes.data(), bytes.size(), &value) != 1) {
        throw EncodingError("Failed to parse big-endian uint64");
    }
    return value;
}

uint64_t bytesToUint64LE(const ByteVec& bytes) {
    if (bytes.size() != 8) {
        throw EncodingError("Expected 8 bytes for uint64, got " + std::to_string(bytes.size()));
    }
    uint64_t value = 0;
    if (kctsb_bytes_to_uint64_le(bytes.data(), bytes.size(), &value) != 1) {
        throw EncodingError("Failed to parse little-endian uint64");
    }
    return value;
}

uint64_t bytesToUint64BEVar(const ByteVec& bytes) {
    if (bytes.size() == 0 || bytes.size() > 8) {
        throw EncodingError("Expected 1-8 bytes for uint64, got " + std::to_string(bytes.size()));
    }
    uint64_t value = 0;
    if (kctsb_bytes_to_uint64_be_var(bytes.data(), bytes.size(), &value) != 1) {
        throw EncodingError("Failed to parse variable-length big-endian uint64");
    }
    return value;
}

ByteVec uint64ToMinBytesBE(uint64_t value) {
    if (value == 0) {
        return ByteVec{0};
    }

    ByteVec result;
    while (value > 0) {
        result.insert(result.begin(), static_cast<uint8_t>(value & 0xFF));
        value >>= 8;
    }
    return result;
}

// ============================================================================
// Convenience Functions
// ============================================================================

ByteVec xorBytes(const ByteVec& a, const ByteVec& b) {
    if (a.size() != b.size()) {
        throw EncodingError("XOR: size mismatch (" + std::to_string(a.size()) +
                           " vs " + std::to_string(b.size()) + ")");
    }

    ByteVec result(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

ByteVec padPKCS7(const ByteVec& data, size_t block_size) {
    if (block_size == 0 || block_size > 255) {
        throw EncodingError("Invalid block size for PKCS#7: " + std::to_string(block_size));
    }

    size_t pad_len = block_size - (data.size() % block_size);
    ByteVec result = data;
    result.resize(data.size() + pad_len, static_cast<uint8_t>(pad_len));
    return result;
}

ByteVec unpadPKCS7(const ByteVec& data) {
    if (data.empty()) {
        throw EncodingError("Cannot unpad empty data");
    }

    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > data.size()) {
        throw EncodingError("Invalid PKCS#7 padding");
    }

    // Verify all padding bytes
    for (size_t i = data.size() - pad_len; i < data.size(); i++) {
        if (data[i] != pad_len) {
            throw EncodingError("Invalid PKCS#7 padding");
        }
    }

    return ByteVec(data.begin(), data.end() - pad_len);
}

bool secureCompare(const ByteVec& a, const ByteVec& b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }

    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

} // namespace encoding
} // namespace kctsb
