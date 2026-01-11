/**
 * @file random.h
 * @brief Secure random number generation
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_UTILS_RANDOM_H
#define KCTSB_UTILS_RANDOM_H

#include "kctsb/core/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate cryptographically secure random bytes
 * @param buffer Output buffer
 * @param len Number of bytes to generate
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_random_bytes(uint8_t* buffer, size_t len);

/**
 * @brief Generate random 32-bit integer
 * @return Random uint32_t value
 */
KCTSB_API uint32_t kctsb_random_u32(void);

/**
 * @brief Generate random 64-bit integer
 * @return Random uint64_t value
 */
KCTSB_API uint64_t kctsb_random_u64(void);

/**
 * @brief Generate random integer in range [0, max)
 * @param max Upper bound (exclusive)
 * @return Random value in range
 */
KCTSB_API uint32_t kctsb_random_range(uint32_t max);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
namespace kctsb {

ByteVec randomBytes(size_t len);
uint32_t randomU32();
uint64_t randomU64();
uint32_t randomRange(uint32_t max);

} // namespace kctsb
#endif

#endif // KCTSB_UTILS_RANDOM_H
