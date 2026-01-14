/**
 * @file security.h
 * @brief Security primitives for kctsb - Side-channel resistant operations
 * 
 * This header provides security-critical functions including:
 * - Constant-time comparison to prevent timing attacks
 * - Secure memory operations
 * - Cryptographically secure random number generation
 * 
 * All functions are designed for production use with side-channel resistance.
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 * @license Apache-2.0
 */

#ifndef KCTSB_CORE_SECURITY_H
#define KCTSB_CORE_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Constant-time memory comparison
 * 
 * Compares two memory regions in constant time to prevent timing attacks.
 * The execution time does not depend on the content of the memory regions.
 * 
 * @param a First memory region
 * @param b Second memory region
 * @param len Number of bytes to compare
 * @return 0 if equal, non-zero if different (but NOT the position of difference)
 */
int kctsb_secure_compare(const void* a, const void* b, size_t len);

/**
 * @brief Constant-time conditional select
 * 
 * Returns a if condition is 0, b if condition is non-zero.
 * Executes in constant time regardless of condition value.
 * 
 * @param condition Selection condition (0 selects a, non-zero selects b)
 * @param a Value returned if condition is 0
 * @param b Value returned if condition is non-zero
 * @return Selected value
 */
uint64_t kctsb_ct_select(uint64_t condition, uint64_t a, uint64_t b);

/**
 * @brief Constant-time conditional swap
 * 
 * Swaps *a and *b if condition is non-zero, in constant time.
 * 
 * @param condition Swap condition
 * @param a Pointer to first value
 * @param b Pointer to second value
 */
void kctsb_ct_swap(uint64_t condition, uint64_t* a, uint64_t* b);

/**
 * @brief Secure memory zeroing
 * 
 * Securely zeros memory, guaranteed not to be optimized away by compiler.
 * Uses platform-specific secure zeroing when available.
 * 
 * @param ptr Pointer to memory to zero
 * @param len Number of bytes to zero
 */
void kctsb_secure_zero(void* ptr, size_t len);

/**
 * @brief Secure memory copy
 * 
 * Copies memory with bounds checking and zeroing of source after copy.
 * 
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param src Source buffer
 * @param count Number of bytes to copy
 * @return 0 on success, non-zero on error (buffer overflow would occur)
 */
int kctsb_secure_copy(void* dest, size_t dest_size, const void* src, size_t count);

/**
 * @brief Cryptographically secure random bytes
 * 
 * Generates cryptographically secure random bytes using platform CSPRNG:
 * - Windows: BCryptGenRandom
 * - Linux: getrandom() syscall or /dev/urandom
 * - macOS: SecRandomCopyBytes or arc4random_buf
 * 
 * @param buf Buffer to fill with random bytes
 * @param len Number of random bytes to generate
 * @return KCTSB_SUCCESS on success, KCTSB_ERROR_RANDOM_FAILED on error
 */
#ifndef KCTSB_RANDOM_BYTES_DECLARED
#define KCTSB_RANDOM_BYTES_DECLARED
/* Forward declare return type for C linkage compatibility */
int kctsb_random_bytes(void* buf, size_t len);
#endif

/**
 * @brief Generate random uint32_t
 * 
 * @return Cryptographically secure random 32-bit value
 */
uint32_t kctsb_random_uint32(void);

/**
 * @brief Generate random uint64_t
 * 
 * @return Cryptographically secure random 64-bit value
 */
uint64_t kctsb_random_uint64(void);

/**
 * @brief Generate random bytes in range [0, max)
 * 
 * Generates unbiased random value in the specified range.
 * Uses rejection sampling to avoid modulo bias.
 * 
 * @param max Upper bound (exclusive)
 * @return Random value in [0, max)
 */
uint64_t kctsb_random_uniform(uint64_t max);

/**
 * @brief Check if running in secure execution environment
 * 
 * Performs runtime checks for security features:
 * - Memory protection
 * - ASLR status
 * - Debug detection
 * 
 * @return Bitmask of security features detected
 */
uint32_t kctsb_security_check(void);

// Security check flags
#define KCTSB_SEC_ASLR_ENABLED       (1U << 0)
#define KCTSB_SEC_DEP_ENABLED        (1U << 1)
#define KCTSB_SEC_DEBUGGER_ABSENT    (1U << 2)
#define KCTSB_SEC_STACK_CANARY       (1U << 3)
#define KCTSB_SEC_RANDOM_AVAILABLE   (1U << 4)
#define KCTSB_SEC_SECURE_MEMORY      (1U << 5)

/**
 * @brief Memory barrier to prevent compiler/CPU reordering
 */
void kctsb_memory_barrier(void);

/**
 * @brief Acquire memory fence
 */
void kctsb_fence_acquire(void);

/**
 * @brief Release memory fence
 */
void kctsb_fence_release(void);

#ifdef __cplusplus
} // extern "C"

namespace kctsb {

/**
 * @brief RAII wrapper for secure memory allocation
 * 
 * Memory is:
 * - Allocated with alignment for SIMD operations
 * - Locked in memory (mlock) when possible
 * - Securely zeroed on destruction
 */
template<typename T>
class SecureBuffer {
public:
    explicit SecureBuffer(size_t count);
    ~SecureBuffer();
    
    // Non-copyable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    // Movable
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    
    T* data() noexcept { return data_; }
    const T* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    
    T& operator[](size_t i) { return data_[i]; }
    const T& operator[](size_t i) const { return data_[i]; }

private:
    T* data_;
    size_t size_;
};

/**
 * @brief Constant-time comparison for C++ containers
 */
template<typename Container>
bool secure_compare(const Container& a, const Container& b) {
    if (a.size() != b.size()) return false;
    return kctsb_secure_compare(a.data(), b.data(), a.size() * sizeof(typename Container::value_type)) == 0;
}

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_CORE_SECURITY_H
