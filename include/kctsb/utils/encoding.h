/**
 * @file encoding.h
 * @brief Data encoding utilities
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_UTILS_ENCODING_H
#define KCTSB_UTILS_ENCODING_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

// Hex encoding
KCTSB_API size_t kctsb_hex_encode(const uint8_t* data, size_t len, char* hex, size_t hex_size);
KCTSB_API size_t kctsb_hex_decode(const char* hex, size_t hex_len, uint8_t* data, size_t data_size);

// Base64 encoding
KCTSB_API size_t kctsb_base64_encode(const uint8_t* data, size_t len, char* b64, size_t b64_size);
KCTSB_API size_t kctsb_base64_decode(const char* b64, size_t b64_len, uint8_t* data, size_t data_size);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
namespace kctsb {

std::string hexEncode(const ByteVec& data);
ByteVec hexDecode(const std::string& hex);
std::string base64Encode(const ByteVec& data);
ByteVec base64Decode(const std::string& b64);

} // namespace kctsb
#endif

#endif // KCTSB_UTILS_ENCODING_H
