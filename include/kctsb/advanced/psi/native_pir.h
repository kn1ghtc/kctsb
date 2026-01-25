/**
 * @file native_pir.h
 * @brief Native PIR Implementation using kctsb FHE (BGV/BFV/CKKS)
 * @details Private Information Retrieval without external dependencies
 * 
 * Supported Schemes:
 * - BGV-PIR: Integer-based PIR with exact arithmetic
 * - BFV-PIR: Scale-invariant PIR
 * - CKKS-PIR: Approximate PIR for floating-point databases
 * 
 * Features:
 * - No SEAL dependency - uses kctsb native FHE
 * - Batched query processing (SIMD packing)
 * - Sublinear communication: O(√n) with square-root decomposition
 * - Client preprocessing for amortized queries
 * 
 * @author kn1ghtc
 * @version 4.13.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_NATIVE_PIR_H
#define KCTSB_ADVANCED_NATIVE_PIR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <vector>
#include <memory>
#include <string>
#include <cmath>
extern "C" {
#endif

/* ============================================================================
 * PIR Configuration
 * ============================================================================ */

/**
 * @brief PIR scheme selection
 */
typedef enum {
    KCTSB_PIR_BGV,   /**< BGV scheme (exact integers) */
    KCTSB_PIR_BFV,   /**< BFV scheme (scale-invariant) */
    KCTSB_PIR_CKKS   /**< CKKS scheme (approximate floats) */
} kctsb_pir_scheme_t;

/**
 * @brief Native PIR configuration
 */
typedef struct {
    kctsb_pir_scheme_t scheme;       /**< FHE scheme */
    size_t poly_modulus_degree;      /**< n (4096, 8192, 16384) */
    size_t plaintext_modulus;        /**< t (BGV/BFV only) */
    size_t num_moduli;               /**< RNS chain length L */
    size_t modulus_bits;             /**< Bits per modulus (30-60) */
    size_t database_size;            /**< Number of database elements */
    size_t element_size_bytes;       /**< Bytes per element */
    double ckks_scale;               /**< CKKS scale (2^40 default) */
    bool enable_batching;            /**< Enable SIMD batching */
    bool enable_sqrt_decomposition;  /**< Enable O(√n) optimization */
    size_t batch_size;               /**< Elements per batch (0=auto) */
} kctsb_native_pir_config_t;

/**
 * @brief Native PIR query result
 */
typedef struct {
    size_t query_index;              /**< Queried index */
    uint8_t *retrieved_data;         /**< Retrieved data */
    size_t data_size;                /**< Data size in bytes */
    double retrieved_double;         /**< Retrieved value (CKKS) */
    bool is_correct;                 /**< Verification flag */
    double query_time_ms;            /**< Query generation time */
    double server_time_ms;           /**< Server processing time */
    double client_time_ms;           /**< Decryption time */
    size_t communication_bytes;      /**< Total communication */
    int noise_budget_bits;           /**< Remaining noise budget */
    char error_message[256];         /**< Error description */
} kctsb_native_pir_result_t;

/**
 * @brief Opaque PIR context
 */
typedef struct kctsb_native_pir_ctx kctsb_native_pir_ctx_t;

/* ============================================================================
 * C API Functions
 * ============================================================================ */

/**
 * @brief Initialize PIR configuration with defaults
 * @param config Configuration to initialize
 * @param scheme FHE scheme (BGV/BFV/CKKS)
 * @param database_size Number of database elements
 */
void kctsb_native_pir_config_init(
    kctsb_native_pir_config_t *config,
    kctsb_pir_scheme_t scheme,
    size_t database_size
);

/**
 * @brief Create Native PIR context for integer database
 * @param config PIR configuration
 * @param database Integer database
 * @param db_size Database size
 * @return PIR context or NULL on failure
 */
kctsb_native_pir_ctx_t *kctsb_native_pir_create_int(
    const kctsb_native_pir_config_t *config,
    const int64_t *database,
    size_t db_size
);

/**
 * @brief Create Native PIR context for double database (CKKS)
 * @param config PIR configuration (must use CKKS scheme)
 * @param database Double database
 * @param db_size Database size
 * @return PIR context or NULL on failure
 */
kctsb_native_pir_ctx_t *kctsb_native_pir_create_double(
    const kctsb_native_pir_config_t *config,
    const double *database,
    size_t db_size
);

/**
 * @brief Create Native PIR context for binary database
 * @param config PIR configuration
 * @param database Binary database
 * @param db_size Database size
 * @param element_size Size of each element in bytes
 * @return PIR context or NULL on failure
 */
kctsb_native_pir_ctx_t *kctsb_native_pir_create_binary(
    const kctsb_native_pir_config_t *config,
    const uint8_t *database,
    size_t db_size,
    size_t element_size
);

/**
 * @brief Destroy PIR context
 * @param ctx PIR context
 */
void kctsb_native_pir_destroy(kctsb_native_pir_ctx_t *ctx);

/**
 * @brief Execute PIR query
 * @param ctx PIR context
 * @param target_index Index to retrieve
 * @param result Output result
 * @return 0 on success, negative error code on failure
 */
int kctsb_native_pir_query(
    kctsb_native_pir_ctx_t *ctx,
    size_t target_index,
    kctsb_native_pir_result_t *result
);

/**
 * @brief Batch query (amortized cost)
 * @param ctx PIR context
 * @param indices Array of indices
 * @param num_queries Number of queries
 * @param results Output results array
 * @return 0 on success, negative error code on failure
 */
int kctsb_native_pir_batch_query(
    kctsb_native_pir_ctx_t *ctx,
    const size_t *indices,
    size_t num_queries,
    kctsb_native_pir_result_t *results
);

/**
 * @brief Free PIR result memory
 * @param result Result to free
 */
void kctsb_native_pir_result_free(kctsb_native_pir_result_t *result);

#ifdef __cplusplus
}

/* ============================================================================
 * C++ Wrapper Classes
 * ============================================================================ */

namespace kctsb {
namespace pir {

/**
 * @brief Native PIR C++ wrapper
 */
class NativePIR {
public:
    /**
     * @brief PIR configuration
     */
    struct Config {
        kctsb_pir_scheme_t scheme = KCTSB_PIR_BGV;
        size_t poly_modulus_degree = 8192;
        size_t plaintext_modulus = 65537;
        size_t num_moduli = 3;
        size_t modulus_bits = 50;
        size_t database_size = 0;
        size_t element_size_bytes = 8;
        double ckks_scale = std::pow(2.0, 40);
        bool enable_batching = true;
        bool enable_sqrt_decomposition = true;
        size_t batch_size = 0;  // Auto
    };

    /**
     * @brief Query result
     */
    struct Result {
        size_t query_index;
        std::vector<uint8_t> retrieved_data;
        double retrieved_double;
        bool is_correct;
        double query_time_ms;
        double server_time_ms;
        double client_time_ms;
        size_t communication_bytes;
        int noise_budget_bits;
        std::string error_message;
    };

    /**
     * @brief Constructor for integer database
     */
    explicit NativePIR(const Config& config, const std::vector<int64_t>& database);

    /**
     * @brief Constructor for double database (CKKS)
     */
    explicit NativePIR(const Config& config, const std::vector<double>& database);

    /**
     * @brief Constructor for binary database
     */
    explicit NativePIR(const Config& config, 
                      const std::vector<uint8_t>& database, 
                      size_t element_size);

    ~NativePIR();

    // Non-copyable, movable
    NativePIR(const NativePIR&) = delete;
    NativePIR& operator=(const NativePIR&) = delete;
    NativePIR(NativePIR&&) noexcept;
    NativePIR& operator=(NativePIR&&) noexcept;

    /**
     * @brief Execute single query
     * @param target_index Index to retrieve
     * @return Query result
     */
    Result query(size_t target_index);

    /**
     * @brief Execute batch queries
     * @param indices Indices to retrieve
     * @return Query results
     */
    std::vector<Result> batch_query(const std::vector<size_t>& indices);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace pir
} // namespace kctsb

#endif /* __cplusplus */

#endif /* KCTSB_ADVANCED_NATIVE_PIR_H */
