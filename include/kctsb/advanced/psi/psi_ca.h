/**
 * @file psi_ca.h
 * @brief PSI with Cardinality and Attributes (PSI-CA)
 * 
 * @details Extended PSI that returns intersection cardinality and attributes
 * 
 * Features:
 * - PSI-Cardinality: Only reveals |X ∩ Y| (size)
 * - PSI-Payload: Returns associated attributes for intersection elements
 * - PSI-Sum: Computes sum of attributes for intersection elements
 * - Threshold PSI: Reveals result only if |X ∩ Y| >= threshold
 * 
 * Use Cases:
 * - Contact matching with profile attributes
 * - Fraud detection with risk scores
 * - Advertising conversion tracking
 * 
 * Security:
 * - Semi-honest security (default)
 * - No element leakage beyond cardinality/attributes
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_PSI_CA_H
#define KCTSB_ADVANCED_PSI_CA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
extern "C" {
#endif

/* ============================================================================
 * PSI-CA Configuration
 * ============================================================================ */

/**
 * @brief PSI-CA mode
 */
typedef enum {
    KCTSB_PSI_CARDINALITY_ONLY,  /**< Only reveal intersection size */
    KCTSB_PSI_WITH_PAYLOAD,      /**< Reveal intersection with payloads */
    KCTSB_PSI_SUM,               /**< Reveal sum of payload values */
    KCTSB_PSI_THRESHOLD          /**< Reveal only if above threshold */
} kctsb_psi_ca_mode_t;

/**
 * @brief Payload aggregation function
 */
typedef enum {
    KCTSB_PSI_AGG_NONE,          /**< No aggregation (return all) */
    KCTSB_PSI_AGG_SUM,           /**< Sum of payloads */
    KCTSB_PSI_AGG_COUNT,         /**< Count (same as cardinality) */
    KCTSB_PSI_AGG_AVG,           /**< Average of payloads */
    KCTSB_PSI_AGG_MIN,           /**< Minimum payload value */
    KCTSB_PSI_AGG_MAX            /**< Maximum payload value */
} kctsb_psi_aggregation_t;

/**
 * @brief PSI-CA configuration
 */
typedef struct {
    kctsb_psi_ca_mode_t mode;        /**< PSI-CA mode */
    kctsb_psi_aggregation_t aggregation; /**< Payload aggregation */
    size_t threshold;                /**< Threshold for threshold mode */
    size_t security_parameter;       /**< Security parameter (bits) */
    bool client_learns_result;       /**< Client learns intersection */
    bool server_learns_result;       /**< Server learns intersection */
    size_t payload_byte_size;        /**< Max payload size per element */
} kctsb_psi_ca_config_t;

/**
 * @brief Element with payload
 */
typedef struct {
    int64_t element;                 /**< Set element */
    uint8_t* payload;                /**< Associated payload data */
    size_t payload_size;             /**< Payload size in bytes */
} kctsb_psi_element_t;

/**
 * @brief PSI-CA result
 */
typedef struct {
    size_t intersection_size;        /**< Intersection cardinality */
    int64_t* intersection_elements;  /**< Intersection elements (if revealed) */
    uint8_t** payloads;              /**< Payloads for intersection elements */
    size_t* payload_sizes;           /**< Size of each payload */
    double aggregated_value;         /**< Aggregated result (sum/avg/etc.) */
    bool threshold_met;              /**< Did cardinality meet threshold? */
    double execution_time_ms;        /**< Total execution time */
    size_t communication_bytes;      /**< Communication cost */
    bool success;                    /**< Operation success */
    char error_message[256];         /**< Error description */
} kctsb_psi_ca_result_t;

/**
 * @brief Opaque PSI-CA context
 */
typedef struct kctsb_psi_ca_ctx kctsb_psi_ca_ctx_t;

/* ============================================================================
 * C API Functions
 * ============================================================================ */

/**
 * @brief Initialize PSI-CA configuration
 * @param config Configuration to initialize
 * @param mode PSI-CA mode
 */
void kctsb_psi_ca_config_init(
    kctsb_psi_ca_config_t* config,
    kctsb_psi_ca_mode_t mode
);

/**
 * @brief Create PSI-CA context
 * @param config Configuration
 * @return Context or NULL on failure
 */
kctsb_psi_ca_ctx_t* kctsb_psi_ca_create(const kctsb_psi_ca_config_t* config);

/**
 * @brief Compute PSI-CA (simple sets without payloads)
 * @param ctx PSI-CA context
 * @param client_set Client's elements
 * @param client_size Client set size
 * @param server_set Server's elements
 * @param server_size Server set size
 * @param result Output result
 * @return 0 on success
 */
int kctsb_psi_ca_compute_simple(
    kctsb_psi_ca_ctx_t* ctx,
    const int64_t* client_set, size_t client_size,
    const int64_t* server_set, size_t server_size,
    kctsb_psi_ca_result_t* result
);

/**
 * @brief Compute PSI-CA with payloads
 * @param ctx PSI-CA context
 * @param client_elements Client's elements with payloads
 * @param client_size Client set size
 * @param server_elements Server's elements with payloads
 * @param server_size Server set size
 * @param result Output result
 * @return 0 on success
 */
int kctsb_psi_ca_compute_with_payload(
    kctsb_psi_ca_ctx_t* ctx,
    const kctsb_psi_element_t* client_elements, size_t client_size,
    const kctsb_psi_element_t* server_elements, size_t server_size,
    kctsb_psi_ca_result_t* result
);

/**
 * @brief Destroy PSI-CA context
 * @param ctx Context to destroy
 */
void kctsb_psi_ca_destroy(kctsb_psi_ca_ctx_t* ctx);

/**
 * @brief Free PSI-CA result
 * @param result Result to free
 */
void kctsb_psi_ca_result_free(kctsb_psi_ca_result_t* result);

#ifdef __cplusplus
}

/* ============================================================================
 * C++ Wrapper Classes
 * ============================================================================ */

namespace kctsb {
namespace psi {

/**
 * @brief PSI-CA configuration
 */
struct PSICAConfig {
    kctsb_psi_ca_mode_t mode = KCTSB_PSI_CARDINALITY_ONLY;
    kctsb_psi_aggregation_t aggregation = KCTSB_PSI_AGG_NONE;
    size_t threshold = 0;
    size_t security_parameter = 128;
    bool client_learns_result = true;
    bool server_learns_result = false;
    size_t payload_byte_size = 256;
};

/**
 * @brief Element with payload
 */
template<typename T = std::vector<uint8_t>>
struct ElementWithPayload {
    int64_t element;
    T payload;
};

/**
 * @brief PSI-CA result
 */
struct PSICAResult {
    size_t intersection_size = 0;
    std::vector<int64_t> intersection_elements;
    std::vector<std::vector<uint8_t>> payloads;
    double aggregated_value = 0.0;
    bool threshold_met = false;
    double execution_time_ms = 0.0;
    size_t communication_bytes = 0;
    bool success = false;
    std::string error_message;
};

/**
 * @brief PSI with Cardinality and Attributes
 */
class PSICA {
public:
    explicit PSICA(const PSICAConfig& config);
    ~PSICA();

    PSICA(const PSICA&) = delete;
    PSICA& operator=(const PSICA&) = delete;
    PSICA(PSICA&&) noexcept;
    PSICA& operator=(PSICA&&) noexcept;

    /**
     * @brief Compute PSI cardinality only
     * @return Result with cardinality (no elements revealed)
     */
    PSICAResult compute_cardinality(
        const std::vector<int64_t>& client_set,
        const std::vector<int64_t>& server_set
    );

    /**
     * @brief Compute PSI with payloads
     * @return Result with payloads for intersection elements
     */
    PSICAResult compute_with_payloads(
        const std::vector<ElementWithPayload<>>& client_elements,
        const std::vector<ElementWithPayload<>>& server_elements
    );

    /**
     * @brief Compute PSI-Sum (sum of payloads as integers)
     * @return Result with aggregated sum
     */
    PSICAResult compute_sum(
        const std::vector<std::pair<int64_t, int64_t>>& client_with_values,
        const std::vector<std::pair<int64_t, int64_t>>& server_with_values
    );

    /**
     * @brief Compute threshold PSI
     * @return Result only if cardinality >= threshold
     */
    PSICAResult compute_threshold(
        const std::vector<int64_t>& client_set,
        const std::vector<int64_t>& server_set,
        size_t threshold
    );

    /**
     * @brief Get configuration
     */
    const PSICAConfig& config() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace psi
} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_PSI_CA_H
