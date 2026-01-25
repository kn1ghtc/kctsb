/**
 * @file pir_cuda.h
 * @brief CUDA GPU-accelerated Private Information Retrieval
 * 
 * @details Self-contained CUDA implementation of PIR with GPU acceleration
 * 
 * Features:
 * - GPU-accelerated homomorphic operations (BFV/BGV)
 * - CUDA tensor core utilization for matrix-vector operations
 * - Asynchronous query processing with CUDA streams
 * - CPU fallback when CUDA not available
 * 
 * Performance:
 * - 10-100x speedup over CPU for large databases (>1M entries)
 * - Optimized for RTX 3000/4000 series and A100/H100
 * - Memory-efficient chunked processing for limited VRAM
 * 
 * Protocol:
 * 1. Client encrypts query index
 * 2. Server performs GPU-accelerated homomorphic evaluation
 * 3. Client decrypts single database entry
 * 
 * Communication: O(polylog(N)) for database of N entries
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#ifndef KCTSB_ADVANCED_PIR_CUDA_H
#define KCTSB_ADVANCED_PIR_CUDA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <memory>
#include <vector>
#include <string>
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

/** Maximum supported database size (entries) */
#define KCTSB_PIR_CUDA_MAX_DB_SIZE (1ULL << 30)  // 1 billion

/** Default chunk size for memory-limited processing */
#define KCTSB_PIR_CUDA_DEFAULT_CHUNK (1ULL << 20)  // 1 million

/* ============================================================================
 * CUDA PIR Configuration
 * ============================================================================ */

/**
 * @brief CUDA device selection
 */
typedef enum {
    KCTSB_CUDA_AUTO,       /**< Auto-select best GPU */
    KCTSB_CUDA_DEVICE_0,   /**< Use GPU 0 */
    KCTSB_CUDA_DEVICE_1,   /**< Use GPU 1 */
    KCTSB_CUDA_CPU_ONLY    /**< CPU fallback (no GPU) */
} kctsb_cuda_device_t;

/**
 * @brief CUDA PIR scheme selection (separate from native_pir)
 */
typedef enum {
    KCTSB_CUDA_PIR_BFV,    /**< BFV scheme (integer) */
    KCTSB_CUDA_PIR_BGV,    /**< BGV scheme (integer, faster) */
    KCTSB_CUDA_PIR_CKKS    /**< CKKS scheme (approximate) */
} kctsb_cuda_pir_scheme_t;

/**
 * @brief CUDA PIR configuration
 */
typedef struct {
    kctsb_cuda_device_t device;      /**< CUDA device selection */
    kctsb_cuda_pir_scheme_t scheme;  /**< HE scheme for PIR */
    size_t poly_modulus_degree;      /**< Polynomial degree (4096/8192/16384) */
    size_t plain_modulus_bits;       /**< Plaintext modulus bit-width */
    size_t database_size;            /**< Database entry count */
    size_t entry_byte_size;          /**< Size of each database entry */
    size_t chunk_size;               /**< Entries per GPU chunk */
    bool enable_preprocessing;       /**< Enable offline preprocessing */
    bool enable_batch_queries;       /**< Enable batched query processing */
    size_t num_cuda_streams;         /**< CUDA streams for parallelism */
} kctsb_pir_cuda_config_t;

/**
 * @brief CUDA PIR result/statistics
 */
typedef struct {
    size_t query_index;              /**< Queried index */
    uint8_t* retrieved_entry;        /**< Retrieved database entry */
    size_t entry_size;               /**< Entry size in bytes */
    double preprocess_time_ms;       /**< Preprocessing time */
    double query_encrypt_time_ms;    /**< Query encryption time */
    double gpu_eval_time_ms;         /**< GPU evaluation time */
    double response_decrypt_time_ms; /**< Response decryption time */
    double total_time_ms;            /**< Total query time */
    size_t communication_bytes;      /**< Total communication */
    size_t gpu_memory_used_mb;       /**< GPU memory used */
    bool success;                    /**< Operation success */
    char error_message[256];         /**< Error description */
} kctsb_pir_cuda_result_t;

/**
 * @brief CUDA device information
 */
typedef struct {
    int device_id;                   /**< CUDA device ID */
    char device_name[256];           /**< Device name */
    size_t total_memory_mb;          /**< Total GPU memory */
    size_t free_memory_mb;           /**< Free GPU memory */
    int compute_capability_major;    /**< Compute capability major */
    int compute_capability_minor;    /**< Compute capability minor */
    int multiprocessor_count;        /**< SM count */
    bool tensor_cores_available;     /**< Tensor core support */
} kctsb_cuda_device_info_t;

/**
 * @brief Opaque CUDA PIR context
 */
typedef struct kctsb_pir_cuda_ctx kctsb_pir_cuda_ctx_t;

/* ============================================================================
 * Initialization and Device Management
 * ============================================================================ */

/**
 * @brief Check if CUDA is available
 * @return true if CUDA runtime is available and GPU detected
 */
bool kctsb_pir_cuda_available(void);

/**
 * @brief Get CUDA device count
 * @return Number of CUDA-capable GPUs (0 if none)
 */
int kctsb_pir_cuda_device_count(void);

/**
 * @brief Get CUDA device information
 * @param device_id Device ID (0, 1, ...)
 * @param info Output device info
 * @return 0 on success
 */
int kctsb_pir_cuda_device_info(int device_id, kctsb_cuda_device_info_t* info);

/**
 * @brief Initialize default configuration
 * @param config Configuration to initialize
 * @param database_size Database entry count
 * @param entry_size Entry size in bytes
 */
void kctsb_pir_cuda_config_init(
    kctsb_pir_cuda_config_t* config,
    size_t database_size,
    size_t entry_size
);

/* ============================================================================
 * Server API (Database Holder)
 * ============================================================================ */

/**
 * @brief Create CUDA PIR server context
 * @param config Configuration
 * @return Server context or NULL on failure
 */
kctsb_pir_cuda_ctx_t* kctsb_pir_cuda_server_create(
    const kctsb_pir_cuda_config_t* config
);

/**
 * @brief Load database into GPU memory
 * @param ctx Server context
 * @param database Raw database (database_size × entry_size bytes)
 * @param database_bytes Total database size in bytes
 * @return 0 on success
 */
int kctsb_pir_cuda_server_set_database(
    kctsb_pir_cuda_ctx_t* ctx,
    const uint8_t* database,
    size_t database_bytes
);

/**
 * @brief Server: Preprocess database for faster online queries
 * @param ctx Server context
 * @return 0 on success
 */
int kctsb_pir_cuda_server_preprocess(kctsb_pir_cuda_ctx_t* ctx);

/**
 * @brief Server: Process encrypted query and generate response
 * @param ctx Server context
 * @param encrypted_query Client's encrypted query
 * @param query_size Query size in bytes
 * @param encrypted_response Output encrypted response buffer
 * @param response_size In: buffer size, Out: actual response size
 * @param result Output statistics
 * @return 0 on success
 */
int kctsb_pir_cuda_server_answer(
    kctsb_pir_cuda_ctx_t* ctx,
    const uint8_t* encrypted_query,
    size_t query_size,
    uint8_t* encrypted_response,
    size_t* response_size,
    kctsb_pir_cuda_result_t* result
);

/* ============================================================================
 * Client API (Query Issuer)
 * ============================================================================ */

/**
 * @brief Create CUDA PIR client context
 * @param config Configuration (must match server)
 * @return Client context or NULL on failure
 */
kctsb_pir_cuda_ctx_t* kctsb_pir_cuda_client_create(
    const kctsb_pir_cuda_config_t* config
);

/**
 * @brief Client: Generate encrypted query for index
 * @param ctx Client context
 * @param index Database index to retrieve (0 to database_size-1)
 * @param encrypted_query Output encrypted query buffer
 * @param query_size In: buffer size, Out: actual query size
 * @param result Output statistics
 * @return 0 on success
 */
int kctsb_pir_cuda_client_query(
    kctsb_pir_cuda_ctx_t* ctx,
    size_t index,
    uint8_t* encrypted_query,
    size_t* query_size,
    kctsb_pir_cuda_result_t* result
);

/**
 * @brief Client: Decrypt server response to retrieve entry
 * @param ctx Client context
 * @param encrypted_response Server's encrypted response
 * @param response_size Response size in bytes
 * @param result Output: contains retrieved_entry and statistics
 * @return 0 on success
 */
int kctsb_pir_cuda_client_decrypt(
    kctsb_pir_cuda_ctx_t* ctx,
    const uint8_t* encrypted_response,
    size_t response_size,
    kctsb_pir_cuda_result_t* result
);

/**
 * @brief Get required query buffer size
 * @param ctx Client context
 * @return Required buffer size in bytes
 */
size_t kctsb_pir_cuda_query_size(kctsb_pir_cuda_ctx_t* ctx);

/**
 * @brief Get expected response buffer size
 * @param ctx Server context
 * @return Required buffer size in bytes
 */
size_t kctsb_pir_cuda_response_size(kctsb_pir_cuda_ctx_t* ctx);

/* ============================================================================
 * Cleanup
 * ============================================================================ */

/**
 * @brief Destroy PIR context and free GPU memory
 * @param ctx Context to destroy
 */
void kctsb_pir_cuda_destroy(kctsb_pir_cuda_ctx_t* ctx);

/**
 * @brief Free result resources
 * @param result Result to free
 */
void kctsb_pir_cuda_result_free(kctsb_pir_cuda_result_t* result);

#ifdef __cplusplus
}

/* ============================================================================
 * C++ Wrapper Classes
 * ============================================================================ */

namespace kctsb {
namespace pir {

/**
 * @brief CUDA device information
 */
struct CudaDeviceInfo {
    int device_id;
    std::string device_name;
    size_t total_memory_mb;
    size_t free_memory_mb;
    int compute_capability_major;
    int compute_capability_minor;
    int multiprocessor_count;
    bool tensor_cores_available;
};

/**
 * @brief CUDA PIR configuration
 */
struct CudaPIRConfig {
    kctsb_cuda_device_t device = KCTSB_CUDA_AUTO;
    kctsb_cuda_pir_scheme_t cuda_scheme = KCTSB_CUDA_PIR_BFV;
    size_t poly_modulus_degree = 8192;
    size_t plain_modulus_bits = 20;
    size_t database_size = 0;
    size_t entry_byte_size = 256;
    size_t chunk_size = KCTSB_PIR_CUDA_DEFAULT_CHUNK;
    bool enable_preprocessing = true;
    bool enable_batch_queries = false;
    size_t num_cuda_streams = 4;
};

/**
 * @brief CUDA PIR result
 */
struct CudaPIRResult {
    size_t query_index = 0;
    std::vector<uint8_t> retrieved_entry;
    double preprocess_time_ms = 0;
    double query_encrypt_time_ms = 0;
    double gpu_eval_time_ms = 0;
    double response_decrypt_time_ms = 0;
    double total_time_ms = 0;
    size_t communication_bytes = 0;
    size_t gpu_memory_used_mb = 0;
    bool success = false;
    std::string error_message;
};

/**
 * @brief Check CUDA availability
 */
bool cuda_available();

/**
 * @brief Get CUDA device information
 */
std::vector<CudaDeviceInfo> get_cuda_devices();

/**
 * @brief CUDA PIR Server
 */
class CudaPIRServer {
public:
    explicit CudaPIRServer(const CudaPIRConfig& config);
    ~CudaPIRServer();

    CudaPIRServer(const CudaPIRServer&) = delete;
    CudaPIRServer& operator=(const CudaPIRServer&) = delete;
    CudaPIRServer(CudaPIRServer&&) noexcept;
    CudaPIRServer& operator=(CudaPIRServer&&) noexcept;

    /**
     * @brief Load database into GPU memory
     */
    void set_database(const std::vector<std::vector<uint8_t>>& database);
    void set_database(const uint8_t* data, size_t total_bytes);

    /**
     * @brief Preprocess database (optional, improves online performance)
     */
    void preprocess();

    /**
     * @brief Process encrypted query
     * @param encrypted_query Client's query
     * @return Encrypted response
     */
    std::vector<uint8_t> answer(const std::vector<uint8_t>& encrypted_query);

    /**
     * @brief Get last operation result
     */
    const CudaPIRResult& get_result() const { return result_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    CudaPIRResult result_;
};

/**
 * @brief CUDA PIR Client
 */
class CudaPIRClient {
public:
    explicit CudaPIRClient(const CudaPIRConfig& config);
    ~CudaPIRClient();

    CudaPIRClient(const CudaPIRClient&) = delete;
    CudaPIRClient& operator=(const CudaPIRClient&) = delete;
    CudaPIRClient(CudaPIRClient&&) noexcept;
    CudaPIRClient& operator=(CudaPIRClient&&) noexcept;

    /**
     * @brief Generate encrypted query for index
     * @param index Database index (0 to N-1)
     * @return Encrypted query
     */
    std::vector<uint8_t> create_query(size_t index);

    /**
     * @brief Decrypt server response
     * @param encrypted_response Server's response
     * @return Retrieved database entry
     */
    std::vector<uint8_t> decrypt_response(const std::vector<uint8_t>& encrypted_response);

    /**
     * @brief Get last operation result
     */
    const CudaPIRResult& get_result() const { return result_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    CudaPIRResult result_;
};

} // namespace pir
} // namespace kctsb

#endif // __cplusplus

#endif // KCTSB_ADVANCED_PIR_CUDA_H
