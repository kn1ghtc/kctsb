/**
 * @file simd.h
 * @brief SIMD Acceleration Interface - AVX2/AVX-512 Vectorization
 *
 * Provides hardware-accelerated cryptographic operations using:
 * - AVX2 (256-bit vectors)
 * - AVX-512 (512-bit vectors)
 * - Runtime detection and fallback
 *
 * Accelerated Operations:
 * - XOR operations for stream ciphers
 * - Polynomial multiplication for hash functions
 * - Matrix operations for lattice cryptography
 * - Parallel block cipher processing
 *
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_SIMD_H
#define KCTSB_SIMD_H

#include <cstdint>
#include <cstddef>
#include <vector>

// Detect SIMD support
#if defined(__AVX512F__)
    #define KCTSB_HAS_AVX512 1
    #include <immintrin.h>
#endif

#if defined(__AVX2__)
    #define KCTSB_HAS_AVX2 1
    #include <immintrin.h>
#endif

#if defined(__SSE4_1__)
    #define KCTSB_HAS_SSE41 1
    #include <smmintrin.h>
#endif

#if defined(__SSE2__)
    #define KCTSB_HAS_SSE2 1
    #include <emmintrin.h>
#endif

// ARM NEON support
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    #define KCTSB_HAS_NEON 1
    #include <arm_neon.h>
#endif

namespace kctsb {
namespace simd {

// ============================================================================
// SIMD Feature Detection
// ============================================================================

/**
 * @brief SIMD feature flags
 */
enum class SIMDFeature : uint32_t {
    NONE    = 0x00,
    SSE2    = 0x01,
    SSE41   = 0x02,
    AVX     = 0x04,
    AVX2    = 0x08,
    AVX512F = 0x10,
    AVX512VL = 0x20,
    AVX512BW = 0x40,
    NEON    = 0x80
};

/**
 * @brief Get available SIMD features at runtime
 * @return Bitmask of available features
 */
uint32_t detect_features();

/**
 * @brief Check if specific feature is available
 * @param feature Feature to check
 * @return true if feature is available
 */
bool has_feature(SIMDFeature feature);

/**
 * @brief Get human-readable SIMD info string
 */
const char* get_simd_info();

// ============================================================================
// Memory Operations
// ============================================================================

/**
 * @brief Aligned memory allocation
 * @param size Size in bytes
 * @param alignment Alignment (default 64 for AVX-512)
 * @return Aligned pointer (free with aligned_free)
 */
void* aligned_alloc(size_t size, size_t alignment = 64);

/**
 * @brief Free aligned memory
 */
void aligned_free(void* ptr);

/**
 * @brief RAII wrapper for aligned memory
 */
template<typename T>
class AlignedBuffer {
public:
    explicit AlignedBuffer(size_t count, size_t alignment = 64)
        : size_(count), alignment_(alignment) {
        data_ = static_cast<T*>(aligned_alloc(count * sizeof(T), alignment));
    }

    ~AlignedBuffer() {
        if (data_) aligned_free(data_);
    }

    // Move semantics
    AlignedBuffer(AlignedBuffer&& other) noexcept
        : data_(other.data_), size_(other.size_), alignment_(other.alignment_) {
        other.data_ = nullptr;
    }

    AlignedBuffer& operator=(AlignedBuffer&& other) noexcept {
        if (this != &other) {
            if (data_) aligned_free(data_);
            data_ = other.data_;
            size_ = other.size_;
            alignment_ = other.alignment_;
            other.data_ = nullptr;
        }
        return *this;
    }

    // No copy
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;

    T* data() { return data_; }
    const T* data() const { return data_; }
    size_t size() const { return size_; }

    T& operator[](size_t i) { return data_[i]; }
    const T& operator[](size_t i) const { return data_[i]; }

private:
    T* data_ = nullptr;
    size_t size_;
    size_t alignment_;
};

// ============================================================================
// XOR Operations (for stream ciphers)
// ============================================================================

/**
 * @brief XOR two buffers using SIMD
 * @param dst Destination (also first source)
 * @param src Second source
 * @param len Length in bytes
 *
 * Uses AVX-512 > AVX2 > SSE2 > scalar fallback
 */
void xor_blocks(uint8_t* dst, const uint8_t* src, size_t len);

/**
 * @brief XOR three buffers: dst = a XOR b
 */
void xor_blocks_3way(uint8_t* dst, const uint8_t* a, const uint8_t* b, size_t len);

// ============================================================================
// ChaCha20 Quarter Round (AVX2/AVX-512)
// ============================================================================

/**
 * @brief ChaCha20 state (16 x 32-bit words)
 */
struct ChaChaState {
    uint32_t state[16];
};

/**
 * @brief ChaCha20 quarter round using SIMD
 * @param state ChaCha state
 * @param a, b, c, d Quarter round indices
 */
void chacha_quarter_round_simd(ChaChaState& state, int a, int b, int c, int d);

/**
 * @brief Full ChaCha20 block function using SIMD
 * @param output Output block (64 bytes)
 * @param input Input state
 */
void chacha20_block_simd(uint8_t output[64], const ChaChaState& input);

/**
 * @brief Parallel ChaCha20 blocks (4 blocks with AVX2, 8 with AVX-512)
 */
void chacha20_blocks_parallel(uint8_t* output, const ChaChaState& input, size_t num_blocks);

// ============================================================================
// AES Operations (AES-NI)
// ============================================================================

// AES-NI detection - check both compiler intrinsic and CMake-defined macro
#if defined(__AES__) || defined(_MSC_VER) || defined(KCTSB_HAS_AESNI)
    #ifndef KCTSB_HAS_AESNI
        #define KCTSB_HAS_AESNI 1
    #endif
    #include <wmmintrin.h>  // AES-NI intrinsics
#endif

/**
 * @brief Check if AES-NI is available
 */
bool has_aesni();

/**
 * @brief AES-128 key expansion using AES-NI
 * @param key 16-byte key
 * @param round_keys Output: 11 round keys (176 bytes)
 */
void aes128_expand_key_ni(const uint8_t key[16], uint8_t round_keys[176]);

/**
 * @brief AES-256 key expansion using AES-NI
 * @param key 32-byte key
 * @param round_keys Output: 15 round keys (240 bytes)
 */
void aes256_expand_key_ni(const uint8_t key[32], uint8_t round_keys[240]);

/**
 * @brief AES-128 single block encryption using AES-NI
 */
void aes128_encrypt_block_ni(const uint8_t in[16], uint8_t out[16],
                              const uint8_t round_keys[176]);

/**
 * @brief AES-256 single block encryption using AES-NI
 */
void aes256_encrypt_block_ni(const uint8_t in[16], uint8_t out[16],
                              const uint8_t round_keys[240]);

/**
 * @brief AES-128 ECB encryption of multiple blocks (parallel)
 * @param in Input blocks
 * @param out Output blocks
 * @param num_blocks Number of 16-byte blocks
 * @param round_keys Expanded key
 */
void aes128_ecb_encrypt_ni(const uint8_t* in, uint8_t* out,
                            size_t num_blocks, const uint8_t round_keys[176]);

/**
 * @brief AES-256 ECB encryption of multiple blocks (parallel)
 */
void aes256_ecb_encrypt_ni(const uint8_t* in, uint8_t* out,
                            size_t num_blocks, const uint8_t round_keys[240]);

/**
 * @brief AES-128 CTR mode using AES-NI with parallel processing
 */
void aes128_ctr_ni(const uint8_t* in, uint8_t* out, size_t len,
                   const uint8_t round_keys[176], uint8_t nonce[16]);

/**
 * @brief GHASH using PCLMUL instruction for GCM mode
 * @param tag Running GHASH tag (16 bytes, in/out)
 * @param h GHASH subkey (16 bytes)
 * @param data Input data
 * @param len Data length
 */
#if defined(KCTSB_HAS_PCLMUL) || defined(__PCLMUL__)
void ghash_pclmul(uint8_t tag[16], const uint8_t h[16], const uint8_t* data, size_t len);
#endif

// ============================================================================
// Polynomial Operations (for NTT/FFT)
// ============================================================================

/**
 * @brief Modular addition of polynomial coefficients
 * @param result Output polynomial
 * @param a First polynomial
 * @param b Second polynomial
 * @param n Number of coefficients
 * @param q Modulus
 */
void poly_add_simd(uint32_t* result, const uint32_t* a, const uint32_t* b,
                   size_t n, uint32_t q);

/**
 * @brief Modular subtraction of polynomial coefficients
 */
void poly_sub_simd(uint32_t* result, const uint32_t* a, const uint32_t* b,
                   size_t n, uint32_t q);

/**
 * @brief Coefficient-wise multiplication (Hadamard product)
 */
void poly_mul_coeffwise_simd(uint32_t* result, const uint32_t* a, const uint32_t* b,
                              size_t n, uint32_t q);

/**
 * @brief Barrett reduction for polynomial coefficients
 */
void poly_reduce_simd(uint32_t* coeffs, size_t n, uint32_t q);

// ============================================================================
// Matrix Operations (for lattice crypto)
// ============================================================================

/**
 * @brief Matrix-vector multiplication mod q
 * @param result Output vector (rows)
 * @param matrix Input matrix (rows x cols)
 * @param vector Input vector (cols)
 * @param rows Matrix rows
 * @param cols Matrix cols
 * @param q Modulus
 */
void matrix_vector_mul_simd(uint32_t* result, const uint32_t* matrix,
                             const uint32_t* vector, size_t rows, size_t cols,
                             uint32_t q);

/**
 * @brief Matrix-matrix multiplication mod q
 */
void matrix_mul_simd(uint32_t* result, const uint32_t* a, const uint32_t* b,
                      size_t m, size_t n, size_t k, uint32_t q);

// ============================================================================
// Hash Function Acceleration
// ============================================================================

/**
 * @brief SHA-256 message schedule using SIMD
 * @param W Output: 64 x 32-bit words
 * @param block Input: 16 x 32-bit words
 */
void sha256_schedule_simd(uint32_t W[64], const uint32_t block[16]);

/**
 * @brief Keccak-f[1600] permutation using SIMD
 * @param state 25 x 64-bit state words
 */
void keccak_f1600_simd(uint64_t state[25]);

// ============================================================================
// Constant-Time Operations
// ============================================================================

/**
 * @brief Constant-time conditional select
 * @param a First value
 * @param b Second value
 * @param selector 0 selects a, non-zero selects b
 * @return Selected value
 */
uint64_t ct_select(uint64_t a, uint64_t b, uint64_t selector);

/**
 * @brief Constant-time buffer comparison
 * @return 0 if equal, non-zero otherwise
 */
int ct_compare(const uint8_t* a, const uint8_t* b, size_t len);

/**
 * @brief Constant-time conditional copy
 * @param dst Destination
 * @param src Source
 * @param len Length
 * @param condition If non-zero, copy src to dst
 */
void ct_cmov(uint8_t* dst, const uint8_t* src, size_t len, int condition);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Secure memory zeroing (not optimized away)
 */
void secure_zero(void* ptr, size_t len);

/**
 * @brief Load 32-bit value in little-endian
 */
inline uint32_t load32_le(const uint8_t* p) {
#if defined(__GNUC__) || defined(__clang__)
    uint32_t v;
    __builtin_memcpy(&v, p, 4);
    return v;
#else
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
#endif
}

/**
 * @brief Store 32-bit value in little-endian
 */
inline void store32_le(uint8_t* p, uint32_t v) {
#if defined(__GNUC__) || defined(__clang__)
    __builtin_memcpy(p, &v, 4);
#else
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
#endif
}

/**
 * @brief Load 64-bit value in little-endian
 */
inline uint64_t load64_le(const uint8_t* p) {
#if defined(__GNUC__) || defined(__clang__)
    uint64_t v;
    __builtin_memcpy(&v, p, 8);
    return v;
#else
    return static_cast<uint64_t>(load32_le(p)) |
           (static_cast<uint64_t>(load32_le(p + 4)) << 32);
#endif
}

/**
 * @brief Store 64-bit value in little-endian
 */
inline void store64_le(uint8_t* p, uint64_t v) {
    store32_le(p, static_cast<uint32_t>(v));
    store32_le(p + 4, static_cast<uint32_t>(v >> 32));
}

/**
 * @brief Rotate left 32-bit
 */
inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/**
 * @brief Rotate left 64-bit
 */
inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

} // namespace simd
} // namespace kctsb

#endif // KCTSB_SIMD_H
