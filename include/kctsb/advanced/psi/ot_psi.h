/**
 * @file ot_psi.h
 * @brief OT-based PSI Implementation Header
 * @details Private Set Intersection using Oblivious Transfer
 * 
 * Protocol Overview:
 * 1. Client has set X, Server has set Y
 * 2. Server encodes Y using polynomial or hash-based structure
 * 3. Client uses OT to obliviously query encoded Y
 * 4. Client locally computes intersection X ∩ Y
 * 
 * Features:
 * - OT Extension (IKNP protocol)
 * - Balanced PSI (both parties learn intersection)
 * - Unbalanced PSI optimization
 * - Communication: O(|X| + |Y|)
 * 
 * @author kn1ghtc
 * @version 4.13.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_OT_PSI_H
#define KCTSB_ADVANCED_OT_PSI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <vector>
#include <memory>
#include <string>
extern "C" {
#endif

/* ============================================================================
 * OT-PSI Configuration
 * ============================================================================ */

/**
 * @brief OT variant selection
 */
typedef enum {
    KCTSB_OT_NAIVE,      /**< Naive 1-out-of-2 OT */
    KCTSB_OT_EXTENSION,  /**< IKNP OT Extension */
    KCTSB_OT_KKRT        /**< KKRT PSI protocol */
} kctsb_ot_variant_t;

/**
 * @brief OT-PSI configuration
 */
typedef struct {
    kctsb_ot_variant_t variant;      /**< OT protocol variant */
    size_t security_parameter;       /**< Security parameter (128/192/256) */
    size_t hash_table_size;          /**< Cuckoo hash table size */
    size_t num_hash_functions;       /**< Number of hash functions */
    size_t ot_batch_size;            /**< OT batch size */
    bool enable_malicious_security;  /**< Enable malicious security */
    bool enable_balanced_psi;        /**< Both parties learn result */
} kctsb_ot_psi_config_t;

/**
 * @brief OT-PSI result
 */
typedef struct {
    size_t intersection_size;        /**< Intersection cardinality */
    int64_t *intersection_elements;  /**< Intersection elements */
    double execution_time_ms;        /**< Total time */
    double ot_setup_time_ms;         /**< OT setup time */
    double ot_execution_time_ms;     /**< OT execution time */
    double psi_compute_time_ms;      /**< PSI computation time */
    size_t communication_bytes;      /**< Total communication */
    size_t ot_count;                 /**< Number of OTs executed */
    bool is_correct;                 /**< Verification flag */
    char error_message[256];         /**< Error description */
} kctsb_ot_psi_result_t;

/**
 * @brief Opaque OT-PSI context
 */
typedef struct kctsb_ot_psi_ctx kctsb_ot_psi_ctx_t;

/* ============================================================================
 * C API Functions
 * ============================================================================ */

/**
 * @brief Initialize OT-PSI configuration
 * @param config Configuration to initialize
 * @param variant OT variant (NAIVE/EXTENSION/KKRT)
 */
void kctsb_ot_psi_config_init(
    kctsb_ot_psi_config_t *config,
    kctsb_ot_variant_t variant
);

/**
 * @brief Create OT-PSI context
 * @param config OT-PSI configuration (NULL for defaults)
 * @return OT-PSI context or NULL on failure
 */
kctsb_ot_psi_ctx_t *kctsb_ot_psi_create(const kctsb_ot_psi_config_t *config);

/**
 * @brief Destroy OT-PSI context
 * @param ctx OT-PSI context
 */
void kctsb_ot_psi_destroy(kctsb_ot_psi_ctx_t *ctx);

/**
 * @brief Compute OT-based PSI
 * @param ctx OT-PSI context
 * @param client_set Client's set
 * @param client_size Client set size
 * @param server_set Server's set
 * @param server_size Server set size
 * @param result Output result
 * @return 0 on success, negative error code on failure
 */
int kctsb_ot_psi_compute(
    kctsb_ot_psi_ctx_t *ctx,
    const int64_t *client_set, size_t client_size,
    const int64_t *server_set, size_t server_size,
    kctsb_ot_psi_result_t *result
);

/**
 * @brief Free OT-PSI result
 * @param result Result to free
 */
void kctsb_ot_psi_result_free(kctsb_ot_psi_result_t *result);

#ifdef __cplusplus
}

/* ============================================================================
 * C++ Wrapper Class
 * ============================================================================ */

namespace kctsb {
namespace psi {

/**
 * @brief OT-based PSI C++ wrapper
 */
class OTPSI {
public:
    /**
     * @brief Configuration
     */
    struct Config {
        kctsb_ot_variant_t variant = KCTSB_OT_EXTENSION;
        size_t security_parameter = 128;
        size_t hash_table_size = 0;  // Auto
        size_t num_hash_functions = 3;
        size_t ot_batch_size = 1024;
        bool enable_malicious_security = false;
        bool enable_balanced_psi = false;
    };

    /**
     * @brief PSI result
     */
    struct Result {
        size_t intersection_size;
        std::vector<int64_t> intersection_elements;
        double execution_time_ms;
        double ot_setup_time_ms;
        double ot_execution_time_ms;
        double psi_compute_time_ms;
        size_t communication_bytes;
        size_t ot_count;
        bool is_correct;
        std::string error_message;
    };

    explicit OTPSI(const Config& config);
    OTPSI();  // Default constructor
    ~OTPSI();

    // Non-copyable, movable
    OTPSI(const OTPSI&) = delete;
    OTPSI& operator=(const OTPSI&) = delete;
    OTPSI(OTPSI&&) noexcept;
    OTPSI& operator=(OTPSI&&) noexcept;

    /**
     * @brief Compute PSI
     * @param client_set Client's input set
     * @param server_set Server's input set
     * @return PSI result
     */
    Result compute(const std::vector<int64_t>& client_set,
                  const std::vector<int64_t>& server_set);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace psi
} // namespace kctsb

#endif /* __cplusplus */

#endif /* KCTSB_ADVANCED_OT_PSI_H */
