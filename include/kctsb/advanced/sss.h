/**
 * @file sss.h
 * @brief Secret Sharing Schemes (Shamir's Secret Sharing and variants)
 * 
 * Implements threshold secret sharing:
 * - Shamir's (t,n) threshold scheme
 * - Verifiable secret sharing
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_ADVANCED_SSS_H
#define KCTSB_ADVANCED_SSS_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"
#include "kctsb/core/security.h"

#ifdef __cplusplus
extern "C" {
#endif

// Maximum share size
#define KCTSB_SSS_MAX_SECRET_SIZE 256
#define KCTSB_SSS_MAX_SHARES 255

// Share structure
typedef struct {
    uint8_t index;          // Share index (1-255)
    uint8_t data[KCTSB_SSS_MAX_SECRET_SIZE];
    size_t data_len;
} kctsb_sss_share_t;

/**
 * @brief Split secret into shares using Shamir's scheme
 * @param secret Secret to split
 * @param secret_len Secret length
 * @param threshold Minimum shares needed for reconstruction (t)
 * @param num_shares Total number of shares to generate (n)
 * @param shares Output array of shares
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sss_split(
    const uint8_t* secret,
    size_t secret_len,
    int threshold,
    int num_shares,
    kctsb_sss_share_t* shares
);

/**
 * @brief Reconstruct secret from shares
 * @param shares Array of shares
 * @param num_shares Number of shares provided
 * @param secret Output buffer for reconstructed secret
 * @param secret_len Expected secret length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_sss_reconstruct(
    const kctsb_sss_share_t* shares,
    int num_shares,
    uint8_t* secret,
    size_t secret_len
);

// kctsb_random_bytes is declared in security.h, included via common.h

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <vector>

namespace kctsb {

/**
 * @brief Secret share
 */
struct Share {
    uint8_t index;
    ByteVec data;
};

/**
 * @brief Shamir's Secret Sharing
 */
class ShamirSSS {
public:
    /**
     * @brief Split secret into shares
     * @param secret Secret data
     * @param threshold Minimum shares needed (t)
     * @param numShares Total shares to generate (n)
     * @return Vector of shares
     */
    static std::vector<Share> split(
        const ByteVec& secret,
        int threshold,
        int numShares
    );
    
    /**
     * @brief Reconstruct secret from shares
     * @param shares Vector of shares (must have at least threshold shares)
     * @param secretLen Expected secret length
     * @return Reconstructed secret
     */
    static ByteVec reconstruct(
        const std::vector<Share>& shares,
        size_t secretLen
    );
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_SSS_H
