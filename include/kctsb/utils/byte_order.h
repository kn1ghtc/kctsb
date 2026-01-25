/**
 * @file byte_order.h
 * @brief Byte Order Conversion Utilities for bignum Integration
 *
 * This header provides standardized byte order conversion functions for
 * integrating bignum's big integer library with cryptographic standards.
 *
 * Architecture Decision:
 * - Internal storage: Little-endian (bignum native format)
 * - External interface: Big-endian (cryptographic standards: RSA, ECC, SM2)
 * - All external byte arrays (input/output) use big-endian format
 *
 * bignum's BytesFromZZ/ZZFromBytes use LITTLE-ENDIAN format.
 * Cryptographic standards (PKCS#1, SEC 1, GB/T 32918) use BIG-ENDIAN format.
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache License 2.0
 */

#ifndef KCTSB_UTILS_BYTE_ORDER_H
#define KCTSB_UTILS_BYTE_ORDER_H

#include "kctsb/core/common.h"
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Byte Order Detection
// ============================================================================

/**
 * @brief Check if the system is little-endian
 * @return 1 if little-endian, 0 if big-endian
 */
KCTSB_API int kctsb_is_little_endian(void);

/**
 * @brief Check if the system is big-endian
 * @return 1 if big-endian, 0 if little-endian
 */
KCTSB_API int kctsb_is_big_endian(void);

// ============================================================================
// Byte Swap Functions
// ============================================================================

/**
 * @brief Swap bytes of a 16-bit value
 * @param value Input value
 * @return Byte-swapped value
 */
KCTSB_API uint16_t kctsb_bswap16(uint16_t value);

/**
 * @brief Swap bytes of a 32-bit value
 * @param value Input value
 * @return Byte-swapped value
 */
KCTSB_API uint32_t kctsb_bswap32(uint32_t value);

/**
 * @brief Swap bytes of a 64-bit value
 * @param value Input value
 * @return Byte-swapped value
 */
KCTSB_API uint64_t kctsb_bswap64(uint64_t value);

// ============================================================================
// Array Byte Order Conversion
// ============================================================================

/**
 * @brief Reverse byte array in-place
 *
 * Used to convert between little-endian and big-endian byte arrays.
 *
 * @param data Byte array to reverse
 * @param len Length of array
 */
KCTSB_API void kctsb_reverse_bytes(uint8_t* data, size_t len);

/**
 * @brief Reverse byte array to output buffer
 *
 * @param input Source byte array
 * @param output Destination byte array (can be same as input)
 * @param len Length of arrays
 */
KCTSB_API void kctsb_reverse_bytes_to(const uint8_t* input, uint8_t* output, size_t len);

/**
 * @brief Convert little-endian bytes to big-endian bytes
 *
 * This is equivalent to kctsb_reverse_bytes but with clearer semantics.
 *
 * @param le_bytes Little-endian input
 * @param be_bytes Big-endian output
 * @param len Length of arrays
 */
KCTSB_API void kctsb_le_to_be(const uint8_t* le_bytes, uint8_t* be_bytes, size_t len);

/**
 * @brief Convert big-endian bytes to little-endian bytes
 *
 * @param be_bytes Big-endian input
 * @param le_bytes Little-endian output
 * @param len Length of arrays
 */
KCTSB_API void kctsb_be_to_le(const uint8_t* be_bytes, uint8_t* le_bytes, size_t len);

#ifdef __cplusplus
}

// ============================================================================
// C++ bignum Integration Utilities
// ============================================================================

#ifdef KCTSB_USE_NTL
#include <kctsb/math/bignum/ZZ.h>
#include <kctsb/math/bignum/ZZ_p.h>
#include <vector>
#include <array>
#include <cstring>

namespace kctsb {
namespace byte_order {

/**
 * @brief Convert big-endian byte array to bignum ZZ
 *
 * Input is big-endian (cryptographic standard format).
 * Internally converts to little-endian for bignum.
 *
 * @param data Input bytes (big-endian)
 * @param len Length of input
 * @return bignum ZZ value
 */
inline kctsb::ZZ be_bytes_to_zz(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) {
        return kctsb::ZZ(0);
    }
    
    // Convert big-endian input to little-endian for bignum
    std::vector<uint8_t> le_bytes(len);
    for (size_t i = 0; i < len; i++) {
        le_bytes[i] = data[len - 1 - i];
    }
    
    kctsb::ZZ result;
    kctsb::ZZFromBytes(result, le_bytes.data(), static_cast<long>(len));
    return result;
}

/**
 * @brief Convert bignum ZZ to big-endian byte array
 *
 * Output is big-endian (cryptographic standard format).
 * Internally uses bignum's little-endian format and converts.
 *
 * @param z bignum ZZ value
 * @param out Output buffer (big-endian)
 * @param len Output length (zero-padded to this length)
 */
inline void zz_to_be_bytes(const kctsb::ZZ& z, uint8_t* out, size_t len) {
    if (out == nullptr || len == 0) {
        return;
    }
    
    std::memset(out, 0, len);
    
    // Get little-endian bytes from bignum
    std::vector<uint8_t> le_bytes(len);
    kctsb::BytesFromZZ(le_bytes.data(), z, static_cast<long>(len));
    
    // Convert to big-endian for output
    for (size_t i = 0; i < len; i++) {
        out[i] = le_bytes[len - 1 - i];
    }
}

/**
 * @brief Convert big-endian byte array to ZZ with automatic size detection
 *
 * Strips leading zeros and converts to ZZ.
 *
 * @param data Input bytes (big-endian)
 * @param len Length of input
 * @return bignum ZZ value
 */
inline kctsb::ZZ be_bytes_to_zz_auto(const uint8_t* data, size_t len) {
    return be_bytes_to_zz(data, len);
}

/**
 * @brief Convert ZZ to big-endian byte vector
 *
 * Output size is automatically determined based on ZZ bit length.
 *
 * @param z bignum ZZ value
 * @return Vector of bytes (big-endian)
 */
inline std::vector<uint8_t> zz_to_be_bytes_auto(const kctsb::ZZ& z) {
    if (z == 0) {
        return {0};
    }
    
    size_t byte_len = static_cast<size_t>((kctsb::NumBits(z) + 7) / 8);
    std::vector<uint8_t> result(byte_len);
    zz_to_be_bytes(z, result.data(), byte_len);
    return result;
}

/**
 * @brief Template for fixed-size big-endian to ZZ conversion
 *
 * @tparam N Fixed size in bytes
 * @param data Input array (big-endian)
 * @return bignum ZZ value
 */
template<size_t N>
inline kctsb::ZZ be_array_to_zz(const std::array<uint8_t, N>& data) {
    return be_bytes_to_zz(data.data(), N);
}

/**
 * @brief Template for fixed-size ZZ to big-endian conversion
 *
 * @tparam N Fixed size in bytes
 * @param z bignum ZZ value
 * @return Array of bytes (big-endian)
 */
template<size_t N>
inline std::array<uint8_t, N> zz_to_be_array(const kctsb::ZZ& z) {
    std::array<uint8_t, N> result;
    zz_to_be_bytes(z, result.data(), N);
    return result;
}

/**
 * @brief Extract ZZ value from ZZ_p safely
 *
 * @param val ZZ_p value
 * @param modulus The modulus p (to ensure correct initialization)
 * @return ZZ representation
 */
inline kctsb::ZZ extract_zz_from_zzp(const kctsb::ZZ_p& val, const kctsb::ZZ& modulus) {
    kctsb::ZZ_p::init(modulus);
    return kctsb::rep(val);
}

/**
 * @brief I2OSP - Integer to Octet String Primitive (PKCS#1)
 *
 * Converts a non-negative integer to an octet string of specified length.
 * Output is big-endian.
 *
 * @param x Non-negative integer
 * @param x_len Intended length of output
 * @param out Output buffer (big-endian)
 * @return 0 on success, -1 if integer is too large
 */
inline int i2osp(const kctsb::ZZ& x, size_t x_len, uint8_t* out) {
    // Check if x can be represented in x_len bytes
    if (kctsb::NumBits(x) > static_cast<long>(x_len * 8)) {
        return -1;  // Integer too large
    }
    
    zz_to_be_bytes(x, out, x_len);
    return 0;
}

/**
 * @brief OS2IP - Octet String to Integer Primitive (PKCS#1)
 *
 * Converts a big-endian octet string to a non-negative integer.
 *
 * @param data Input bytes (big-endian)
 * @param len Length of input
 * @return bignum ZZ value
 */
inline kctsb::ZZ os2ip(const uint8_t* data, size_t len) {
    return be_bytes_to_zz(data, len);
}

} // namespace byte_order
} // namespace kctsb

#endif // KCTSB_USE_NTL

#endif // __cplusplus

#endif // KCTSB_UTILS_BYTE_ORDER_H
