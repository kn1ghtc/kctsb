/**
 * @file byte_order.cpp
 * @brief Byte Order Conversion Utilities Implementation
 *
 * Provides byte order detection and conversion functions for
 * cross-platform compatibility.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#include "kctsb/utils/byte_order.h"
#include <cstring>
#include <algorithm>

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

int kctsb_is_little_endian(void) {
    uint32_t test = 1;
    return *reinterpret_cast<uint8_t*>(&test) == 1;
}

int kctsb_is_big_endian(void) {
    return !kctsb_is_little_endian();
}

uint16_t kctsb_bswap16(uint16_t value) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(value);
#elif defined(_MSC_VER)
    return _byteswap_ushort(value);
#else
    return (value >> 8) | (value << 8);
#endif
}

uint32_t kctsb_bswap32(uint32_t value) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(value);
#elif defined(_MSC_VER)
    return _byteswap_ulong(value);
#else
    return ((value >> 24) & 0x000000FF) |
           ((value >> 8)  & 0x0000FF00) |
           ((value << 8)  & 0x00FF0000) |
           ((value << 24) & 0xFF000000);
#endif
}

uint64_t kctsb_bswap64(uint64_t value) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(value);
#elif defined(_MSC_VER)
    return _byteswap_uint64(value);
#else
    return ((value >> 56) & 0x00000000000000FFULL) |
           ((value >> 40) & 0x000000000000FF00ULL) |
           ((value >> 24) & 0x0000000000FF0000ULL) |
           ((value >> 8)  & 0x00000000FF000000ULL) |
           ((value << 8)  & 0x000000FF00000000ULL) |
           ((value << 24) & 0x0000FF0000000000ULL) |
           ((value << 40) & 0x00FF000000000000ULL) |
           ((value << 56) & 0xFF00000000000000ULL);
#endif
}

void kctsb_reverse_bytes(uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return;
    }
    
    size_t half = len / 2;
    for (size_t i = 0; i < half; i++) {
        uint8_t tmp = data[i];
        data[i] = data[len - 1 - i];
        data[len - 1 - i] = tmp;
    }
}

void kctsb_reverse_bytes_to(const uint8_t* input, uint8_t* output, size_t len) {
    if (input == nullptr || output == nullptr || len == 0) {
        return;
    }
    
    // Handle in-place reversal
    if (input == output) {
        kctsb_reverse_bytes(output, len);
        return;
    }
    
    for (size_t i = 0; i < len; i++) {
        output[i] = input[len - 1 - i];
    }
}

void kctsb_le_to_be(const uint8_t* le_bytes, uint8_t* be_bytes, size_t len) {
    kctsb_reverse_bytes_to(le_bytes, be_bytes, len);
}

void kctsb_be_to_le(const uint8_t* be_bytes, uint8_t* le_bytes, size_t len) {
    kctsb_reverse_bytes_to(be_bytes, le_bytes, len);
}

} // extern "C"
