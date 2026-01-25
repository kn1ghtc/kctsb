/**
 * @file pir_preprocessing.h
 * @brief PIR with Offline/Online Preprocessing
 * 
 * @details Two-phase PIR for faster online queries
 * 
 * Protocol:
 * - Offline Phase: Precompute database-specific hints
 * - Online Phase: Fast query using precomputed data
 * 
 * Schemes:
 * 1. Hint-based PIR: Client stores O(√N) hints
 * 2. Keyword PIR: Index-based retrieval without knowing position
 * 3. Batch PIR: Amortize cost over multiple queries
 * 
 * Performance:
 * - Offline: O(N) server work (one-time per database update)
 * - Online: O(√N) server work per query
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_PIR_PREPROCESSING_H
#define KCTSB_ADVANCED_PIR_PREPROCESSING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <memory>
#include <string>
#include <vector>
extern "C" {
#endif

/* ============================================================================
 * PIR Preprocessing Configuration
 * ============================================================================ */

/**
 * @brief Preprocessing scheme
 */
typedef enum {
    KCTSB_PIR_HINT_BASED,    /**< Client hints (√N storage) */
    KCTSB_PIR_KEYWORD,       /**< Keyword-based retrieval */
    KCTSB_PIR_BATCH          /**< Batch query optimization */
} kctsb_pir_preproc_scheme_t;

/**
 * @brief PIR preprocessing configuration
 */
typedef struct {
    kctsb_pir_preproc_scheme_t scheme;   /**< Preprocessing scheme */
    size_t database_size;                /**< Number of database entries */
    size_t entry_byte_size;              /**< Size of each entry */
    size_t hint_count;                   /**< Number of hints (√N if 0) */
    size_t batch_size;                   /**< Batch size for batch PIR */
    size_t poly_modulus_degree;          /**< HE polynomial degree */
    size_t security_parameter;           /**< Security bits */
} kctsb_pir_preproc_config_t;

/**
 * @brief Preprocessing hints (client-side storage)
 */
typedef struct {
    uint8_t* hint_data;                  /**< Hint bytes */
    size_t hint_size;                    /**< Total hint size */
    size_t num_hints;                    /**< Number of hints */
    size_t database_version;             /**< Database version hash */
} kctsb_pir_hints_t;

/**
 * @brief PIR preprocessing result
 */
typedef struct {
    size_t query_index;                  /**< Queried index */
    uint8_t* retrieved_entry;            /**< Retrieved entry */
    size_t entry_size;                   /**< Entry size */
    double offline_time_ms;              /**< Offline preprocessing time */
    double online_time_ms;               /**< Online query time */
    double total_time_ms;                /**< Total time */
    size_t offline_communication;        /**< Offline communication bytes */
    size_t online_communication;         /**< Online communication bytes */
    bool success;                        /**< Operation success */
    char error_message[256];             /**< Error description */
} kctsb_pir_preproc_result_t;

/**
 * @brief Opaque PIR preprocessing context
 */
typedef struct kctsb_pir_preproc_ctx kctsb_pir_preproc_ctx_t;

/* ============================================================================
 * C API Functions
 * ============================================================================ */

/**
 * @brief Initialize configuration
 */
void kctsb_pir_preproc_config_init(
    kctsb_pir_preproc_config_t* config,
    size_t database_size,
    size_t entry_size,
    kctsb_pir_preproc_scheme_t scheme
);

/**
 * @brief Create server context
 */
kctsb_pir_preproc_ctx_t* kctsb_pir_preproc_server_create(
    const kctsb_pir_preproc_config_t* config
);

/**
 * @brief Create client context
 */
kctsb_pir_preproc_ctx_t* kctsb_pir_preproc_client_create(
    const kctsb_pir_preproc_config_t* config
);

/**
 * @brief Server: Set database
 */
int kctsb_pir_preproc_server_set_database(
    kctsb_pir_preproc_ctx_t* ctx,
    const uint8_t* database,
    size_t database_bytes
);

/**
 * @brief Server: Offline preprocessing
 * @param ctx Server context
 * @param hints Output hints for client
 * @return 0 on success
 */
int kctsb_pir_preproc_server_preprocess(
    kctsb_pir_preproc_ctx_t* ctx,
    kctsb_pir_hints_t* hints
);

/**
 * @brief Client: Store hints
 */
int kctsb_pir_preproc_client_set_hints(
    kctsb_pir_preproc_ctx_t* ctx,
    const kctsb_pir_hints_t* hints
);

/**
 * @brief Client: Create online query
 */
int kctsb_pir_preproc_client_query(
    kctsb_pir_preproc_ctx_t* ctx,
    size_t index,
    uint8_t* query,
    size_t* query_size
);

/**
 * @brief Server: Process online query
 */
int kctsb_pir_preproc_server_answer(
    kctsb_pir_preproc_ctx_t* ctx,
    const uint8_t* query,
    size_t query_size,
    uint8_t* response,
    size_t* response_size,
    kctsb_pir_preproc_result_t* result
);

/**
 * @brief Client: Decode response
 */
int kctsb_pir_preproc_client_decode(
    kctsb_pir_preproc_ctx_t* ctx,
    const uint8_t* response,
    size_t response_size,
    kctsb_pir_preproc_result_t* result
);

/**
 * @brief Destroy context
 */
void kctsb_pir_preproc_destroy(kctsb_pir_preproc_ctx_t* ctx);

/**
 * @brief Free hints
 */
void kctsb_pir_preproc_hints_free(kctsb_pir_hints_t* hints);

/**
 * @brief Free result
 */
void kctsb_pir_preproc_result_free(kctsb_pir_preproc_result_t* result);

#ifdef __cplusplus
}

/* ============================================================================
 * C++ Wrapper Classes
 * ============================================================================ */

namespace kctsb {
namespace pir {

/**
 * @brief Preprocessing configuration
 */
struct PreprocConfig {
    kctsb_pir_preproc_scheme_t scheme = KCTSB_PIR_HINT_BASED;
    size_t database_size = 0;
    size_t entry_byte_size = 256;
    size_t hint_count = 0;  // Auto: √N
    size_t batch_size = 32;
    size_t poly_modulus_degree = 4096;
    size_t security_parameter = 128;
};

/**
 * @brief Client hints
 */
struct PreprocHints {
    std::vector<uint8_t> data;
    size_t num_hints = 0;
    size_t database_version = 0;
};

/**
 * @brief Preprocessing result
 */
struct PreprocResult {
    size_t query_index = 0;
    std::vector<uint8_t> entry;
    double offline_time_ms = 0;
    double online_time_ms = 0;
    double total_time_ms = 0;
    size_t offline_communication = 0;
    size_t online_communication = 0;
    bool success = false;
    std::string error_message;
};

/**
 * @brief PIR Server with Preprocessing
 */
class PreprocPIRServer {
public:
    explicit PreprocPIRServer(const PreprocConfig& config);
    ~PreprocPIRServer();

    PreprocPIRServer(const PreprocPIRServer&) = delete;
    PreprocPIRServer& operator=(const PreprocPIRServer&) = delete;
    PreprocPIRServer(PreprocPIRServer&&) noexcept;
    PreprocPIRServer& operator=(PreprocPIRServer&&) noexcept;

    /**
     * @brief Set database
     */
    void set_database(const std::vector<std::vector<uint8_t>>& database);
    void set_database(const uint8_t* data, size_t total_bytes);

    /**
     * @brief Offline: Generate hints for client
     */
    PreprocHints preprocess();

    /**
     * @brief Online: Answer query
     */
    std::vector<uint8_t> answer(const std::vector<uint8_t>& query);

    /**
     * @brief Get last result
     */
    const PreprocResult& get_result() const { return result_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    PreprocResult result_;
};

/**
 * @brief PIR Client with Preprocessing
 */
class PreprocPIRClient {
public:
    explicit PreprocPIRClient(const PreprocConfig& config);
    ~PreprocPIRClient();

    PreprocPIRClient(const PreprocPIRClient&) = delete;
    PreprocPIRClient& operator=(const PreprocPIRClient&) = delete;
    PreprocPIRClient(PreprocPIRClient&&) noexcept;
    PreprocPIRClient& operator=(PreprocPIRClient&&) noexcept;

    /**
     * @brief Store hints from server
     */
    void set_hints(const PreprocHints& hints);

    /**
     * @brief Create online query
     */
    std::vector<uint8_t> create_query(size_t index);

    /**
     * @brief Decode response
     */
    std::vector<uint8_t> decode_response(const std::vector<uint8_t>& response);

    /**
     * @brief Get last result
     */
    const PreprocResult& get_result() const { return result_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    PreprocResult result_;
};

} // namespace pir
} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_PIR_PREPROCESSING_H
