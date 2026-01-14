/**
 * @file psi.h
 * @brief Private Set Intersection (PSI) and Private Information Retrieval (PIR)
 * @details Native C/C++ implementations for secure computation protocols
 * 
 * Supported Protocols:
 * - Piano-PSI: Sublinear communication complexity O(√n)
 * - Simple-PSI: Basic hash-based PSI
 * - SEAL-PIR: Homomorphic encryption based PIR (requires SEAL)
 * 
 * @note All implementations are native C/C++ without external PSI libraries.
 *       For production APSI integration, see separate build scripts.
 * 
 * @author kn1ghtc
 * @version 3.2.0
 * @date 2026-01-14
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_PSI_H
#define KCTSB_ADVANCED_PSI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

/** Default number of hash functions for Cuckoo hashing */
#define KCTSB_PSI_DEFAULT_HASH_FUNCTIONS    4

/** Default Cuckoo hashing iterations */
#define KCTSB_PSI_DEFAULT_CUCKOO_ITERS      20

/** Default load factor threshold for hash tables */
#define KCTSB_PSI_DEFAULT_LOAD_FACTOR       0.75

/** Statistical security parameter (bits) */
#define KCTSB_PSI_SECURITY_BITS             128

/** Minimum query batch size for efficiency */
#define KCTSB_PSI_MIN_BATCH_SIZE            32

/* ============================================================================
 * Error Codes
 * ============================================================================ */

#define KCTSB_PSI_SUCCESS                   0
#define KCTSB_PSI_ERROR_INVALID_PARAM       -1
#define KCTSB_PSI_ERROR_MEMORY              -2
#define KCTSB_PSI_ERROR_HASH_FAILED         -3
#define KCTSB_PSI_ERROR_CUCKOO_FAILED       -4
#define KCTSB_PSI_ERROR_SEAL_NOT_AVAILABLE  -5
#define KCTSB_PSI_ERROR_FILE_IO             -6

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * @brief Piano-PSI configuration parameters
 */
typedef struct {
    size_t hash_table_size;          /**< Hash table size (0 = auto-calculate) */
    size_t num_hash_functions;       /**< Number of Cuckoo hash functions */
    size_t bucket_size;              /**< Bucket size for overflow */
    size_t sublinear_factor;         /**< √n factor for sublinear communication */
    double statistical_security;     /**< Statistical security parameter (bits) */
    size_t max_cuckoo_iterations;    /**< Max iterations for Cuckoo insertion */
    double load_factor_threshold;    /**< Target load factor */
    size_t min_query_batch_size;     /**< Minimum batch size for queries */
    bool enable_batch_optimization;  /**< Enable batched query processing */
    bool malicious_security;         /**< Enable malicious security mode */
} kctsb_psi_config_t;

/**
 * @brief PSI computation result
 */
typedef struct {
    size_t intersection_size;        /**< Number of common elements */
    int64_t *intersection_elements;  /**< Array of intersection elements */
    double execution_time_ms;        /**< Total execution time */
    double client_time_ms;           /**< Client-side processing time */
    double server_time_ms;           /**< Server-side processing time */
    double communication_bytes;      /**< Communication overhead */
    double hash_table_load_factor;   /**< Actual hash table load factor */
    bool is_correct;                 /**< Verification result */
    char error_message[256];         /**< Error description if any */
} kctsb_psi_result_t;

/**
 * @brief PIR query result
 */
typedef struct {
    size_t query_index;              /**< Queried database index */
    double retrieved_value;          /**< Retrieved value (for numeric DB) */
    uint8_t *retrieved_data;         /**< Retrieved data (for binary DB) */
    size_t data_size;                /**< Size of retrieved data */
    bool is_correct;                 /**< Verification result */
    double query_time_ms;            /**< Query generation time */
    double server_time_ms;           /**< Server processing time */
    double client_time_ms;           /**< Client decryption time */
    size_t communication_bytes;      /**< Communication overhead */
    int noise_budget_remaining;      /**< Remaining noise budget (HE) */
    char error_message[256];         /**< Error description if any */
} kctsb_pir_result_t;

/**
 * @brief Opaque PSI context handle
 */
typedef struct kctsb_psi_ctx kctsb_psi_ctx_t;

/**
 * @brief Opaque PIR context handle
 */
typedef struct kctsb_pir_ctx kctsb_pir_ctx_t;

/* ============================================================================
 * Configuration Functions
 * ============================================================================ */

/**
 * @brief Initialize PSI configuration with default values
 * @param config Configuration structure to initialize
 */
void kctsb_psi_config_init(kctsb_psi_config_t *config);

/* ============================================================================
 * Piano-PSI Functions (Native Implementation)
 * ============================================================================ */

/**
 * @brief Create a new Piano-PSI context
 * @param config PSI configuration (NULL for defaults)
 * @return Pointer to PSI context, or NULL on failure
 */
kctsb_psi_ctx_t *kctsb_piano_psi_create(const kctsb_psi_config_t *config);

/**
 * @brief Destroy Piano-PSI context and free resources
 * @param ctx PSI context to destroy
 */
void kctsb_piano_psi_destroy(kctsb_psi_ctx_t *ctx);

/**
 * @brief Compute private set intersection using Piano protocol
 * @param ctx PSI context
 * @param client_set Client's input set
 * @param client_size Number of elements in client set
 * @param server_set Server's input set
 * @param server_size Number of elements in server set
 * @param result Output result structure
 * @return 0 on success, negative error code on failure
 */
int kctsb_piano_psi_compute(
    kctsb_psi_ctx_t *ctx,
    const int64_t *client_set, size_t client_size,
    const int64_t *server_set, size_t server_size,
    kctsb_psi_result_t *result
);

/* ============================================================================
 * Simple PSI Functions (Hash-based)
 * ============================================================================ */

/**
 * @brief Compute simple hash-based PSI (non-private, for testing)
 * @param client_set Client's input set
 * @param client_size Number of elements in client set
 * @param server_set Server's input set
 * @param server_size Number of elements in server set
 * @param result Output result structure
 * @return 0 on success, negative error code on failure
 */
int kctsb_simple_psi_compute(
    const int64_t *client_set, size_t client_size,
    const int64_t *server_set, size_t server_size,
    kctsb_psi_result_t *result
);

/* ============================================================================
 * PIR Functions (Requires SEAL)
 * ============================================================================ */

#ifdef KCTSB_HAS_SEAL

/**
 * @brief Create a new SEAL-based PIR context
 * @param database Database values
 * @param db_size Number of elements in database
 * @return Pointer to PIR context, or NULL on failure
 */
kctsb_pir_ctx_t *kctsb_seal_pir_create(
    const double *database, size_t db_size
);

/**
 * @brief Destroy PIR context and free resources
 * @param ctx PIR context to destroy
 */
void kctsb_seal_pir_destroy(kctsb_pir_ctx_t *ctx);

/**
 * @brief Execute a PIR query
 * @param ctx PIR context
 * @param target_index Index to query
 * @param result Output result structure
 * @return 0 on success, negative error code on failure
 */
int kctsb_seal_pir_query(
    kctsb_pir_ctx_t *ctx,
    size_t target_index,
    kctsb_pir_result_t *result
);

#endif /* KCTSB_HAS_SEAL */

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * @brief Free PSI result memory
 * @param result Result structure to free
 */
void kctsb_psi_result_free(kctsb_psi_result_t *result);

/**
 * @brief Free PIR result memory
 * @param result Result structure to free
 */
void kctsb_pir_result_free(kctsb_pir_result_t *result);

/**
 * @brief Get error message for error code
 * @param error_code Error code
 * @return Error message string
 */
const char *kctsb_psi_error_string(int error_code);

#ifdef __cplusplus
}
#endif

/* ============================================================================
 * C++ API (Optional)
 * ============================================================================ */

#ifdef __cplusplus

#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace kctsb {
namespace psi {

/**
 * @brief Piano-PSI C++ wrapper class
 */
class PianoPSI {
public:
    /**
     * @brief Configuration for Piano-PSI
     */
    struct Config {
        size_t hash_table_size;
        size_t num_hash_functions;
        size_t bucket_size;
        size_t sublinear_factor;
        double statistical_security;
        size_t max_cuckoo_iterations;
        double load_factor_threshold;
        size_t min_query_batch_size;
        bool enable_batch_optimization;
        bool malicious_security;

        Config()
            : hash_table_size(0)
            , num_hash_functions(KCTSB_PSI_DEFAULT_HASH_FUNCTIONS)
            , bucket_size(8)
            , sublinear_factor(3)
            , statistical_security(KCTSB_PSI_SECURITY_BITS)
            , max_cuckoo_iterations(KCTSB_PSI_DEFAULT_CUCKOO_ITERS)
            , load_factor_threshold(KCTSB_PSI_DEFAULT_LOAD_FACTOR)
            , min_query_batch_size(KCTSB_PSI_MIN_BATCH_SIZE)
            , enable_batch_optimization(true)
            , malicious_security(false)
        {}
    };

    /**
     * @brief PSI computation result
     */
    struct Result {
        std::vector<int64_t> intersection;
        double execution_time_ms;
        double client_time_ms;
        double server_time_ms;
        double communication_bytes;
        double hash_table_load_factor;
        bool is_correct;
        std::string error_message;
    };

    explicit PianoPSI(const Config& config = Config());
    ~PianoPSI();

    PianoPSI(const PianoPSI&) = delete;
    PianoPSI& operator=(const PianoPSI&) = delete;
    PianoPSI(PianoPSI&&) noexcept;
    PianoPSI& operator=(PianoPSI&&) noexcept;

    /**
     * @brief Compute PSI between client and server sets
     * @param client_set Client's input set
     * @param server_set Server's input set
     * @return PSI computation result
     */
    Result compute(
        const std::vector<int64_t>& client_set,
        const std::vector<int64_t>& server_set
    );

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

/**
 * @brief Simple PSI computation (non-private)
 */
std::vector<int64_t> simple_intersection(
    const std::vector<int64_t>& set1,
    const std::vector<int64_t>& set2
);

#ifdef KCTSB_HAS_SEAL

/**
 * @brief SEAL-based PIR C++ wrapper class
 */
class SEALPIR {
public:
    struct Result {
        size_t query_index;
        double retrieved_value;
        bool is_correct;
        double query_time_ms;
        double server_time_ms;
        double client_time_ms;
        size_t communication_bytes;
        int noise_budget_remaining;
        std::string error_message;
    };

    explicit SEALPIR(const std::vector<double>& database);
    ~SEALPIR();

    SEALPIR(const SEALPIR&) = delete;
    SEALPIR& operator=(const SEALPIR&) = delete;

    Result query(size_t target_index);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

#endif /* KCTSB_HAS_SEAL */

} // namespace psi
} // namespace kctsb

#endif /* __cplusplus */

#endif /* KCTSB_ADVANCED_PSI_H */
