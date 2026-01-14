/**
 * @file zk.h
 * @brief Zero-Knowledge Proof systems
 * 
 * Implements various ZK proof protocols:
 * - Fiat-Shamir identification scheme (FFS)
 * - zk-SNARKs basics
 * 
 * @author knightc
 * @copyright Copyright (c) 2019-2026 knightc. All rights reserved.
 */

#ifndef KCTSB_ADVANCED_ZK_H
#define KCTSB_ADVANCED_ZK_H

#include "kctsb/core/common.h"
#include "kctsb/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Fiat-Shamir identification scheme
typedef struct {
    void* internal;
} kctsb_ffs_ctx_t;

/**
 * @brief Initialize FFS prover
 * @param ctx Context to initialize
 * @param secret Prover's secret
 * @param secret_len Secret length
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_ffs_prover_init(
    kctsb_ffs_ctx_t* ctx,
    const uint8_t* secret,
    size_t secret_len
);

/**
 * @brief Generate FFS commitment
 * @param ctx Prover context
 * @param commitment Output commitment
 * @param commitment_len Commitment buffer size
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_ffs_commit(
    kctsb_ffs_ctx_t* ctx,
    uint8_t* commitment,
    size_t* commitment_len
);

/**
 * @brief Generate FFS response
 * @param ctx Prover context
 * @param challenge Challenge from verifier
 * @param response Output response
 * @param response_len Response buffer size
 * @return KCTSB_SUCCESS or error code
 */
KCTSB_API kctsb_error_t kctsb_ffs_respond(
    kctsb_ffs_ctx_t* ctx,
    int challenge,
    uint8_t* response,
    size_t* response_len
);

/**
 * @brief Verify FFS proof
 * @param public_info Public verification information
 * @param commitment Prover's commitment
 * @param challenge Challenge sent
 * @param response Prover's response
 * @return KCTSB_SUCCESS if valid
 */
KCTSB_API kctsb_error_t kctsb_ffs_verify(
    const uint8_t* public_info,
    const uint8_t* commitment,
    int challenge,
    const uint8_t* response
);

/**
 * @brief Free FFS context
 * @param ctx Context to free
 */
KCTSB_API void kctsb_ffs_free(kctsb_ffs_ctx_t* ctx);

/**
 * @brief FFS self test
 * @return KCTSB_SUCCESS if test passes
 */
KCTSB_API kctsb_error_t kctsb_ffs_self_test(void);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

namespace kctsb {

/**
 * @brief Fiat-Shamir Zero-Knowledge Proof
 */
class FiatShamir {
public:
    // Prover side
    static ByteVec generateCommitment(const ByteVec& secret);
    static ByteVec respond(const ByteVec& secret, int challenge);
    
    // Verifier side
    static bool verify(
        const ByteVec& publicInfo,
        const ByteVec& commitment,
        int challenge,
        const ByteVec& response
    );
};

} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_ZK_H
