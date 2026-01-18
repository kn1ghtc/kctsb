/**
 * @file types.h
 * @brief Type definitions for kctsb library
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_CORE_TYPES_H
#define KCTSB_CORE_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Basic unsigned types
typedef uint8_t  kctsb_u8;
typedef uint16_t kctsb_u16;
typedef uint32_t kctsb_u32;
typedef uint64_t kctsb_u64;

// Basic signed types
typedef int8_t   kctsb_i8;
typedef int16_t  kctsb_i16;
typedef int32_t  kctsb_i32;
typedef int64_t  kctsb_i64;

// Byte type
typedef uint8_t kctsb_byte;

// Word types for different architectures
#if defined(__LP64__) || defined(_WIN64)
    typedef uint64_t kctsb_word;
    typedef int64_t  kctsb_sword;
    #define KCTSB_WORD_BITS 64
#else
    typedef uint32_t kctsb_word;
    typedef int32_t  kctsb_sword;
    #define KCTSB_WORD_BITS 32
#endif

// Buffer type for binary data
typedef struct {
    kctsb_byte* data;
    size_t length;
    size_t capacity;
} kctsb_buffer_t;

// Key material structure
typedef struct {
    kctsb_byte* key;
    size_t key_len;
} kctsb_key_t;

// IV/Nonce structure
typedef struct {
    kctsb_byte* iv;
    size_t iv_len;
} kctsb_iv_t;

// Generic context structure base
typedef struct {
    void* internal;
    int initialized;
} kctsb_context_t;

#ifdef __cplusplus
}
#endif

// C++ types
#ifdef __cplusplus

#include <vector>
#include <string>
#include <array>
#include <memory>

namespace kctsb {

// Byte vector
using ByteVec = std::vector<uint8_t>;

// Byte array templates
template<size_t N>
using ByteArray = std::array<uint8_t, N>;

// Common key sizes
using AES128Key = ByteArray<16>;
using AES192Key = ByteArray<24>;
using AES256Key = ByteArray<32>;
using SM4Key = ByteArray<16>;
using ChaCha20Key = ByteArray<32>;

// Common block sizes
using AESBlock = ByteArray<16>;
using SM4Block = ByteArray<16>;

// Hash digests
using SHA256Digest = ByteArray<32>;
using SHA384Digest = ByteArray<48>;
using SHA512Digest = ByteArray<64>;
using SM3Digest = ByteArray<32>;

// Smart pointer aliases (avoid conflict with bignum's SmartPtr.h)
// Use KcUniquePtr/KcSharedPtr to distinguish from bignum's UniquePtr
template<typename T>
using KcUniquePtr = std::unique_ptr<T>;

template<typename T>
using KcSharedPtr = std::shared_ptr<T>;

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CORE_TYPES_H
