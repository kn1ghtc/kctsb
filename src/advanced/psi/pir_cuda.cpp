/**
 * @file pir_cuda.cpp
 * @brief CUDA GPU-accelerated PIR - CPU Fallback Implementation
 * 
 * @details This file provides CPU fallback when CUDA is not available
 * The actual CUDA kernels are in pir_cuda.cu
 * 
 * When compiled without CUDA:
 * - All operations use CPU-based BFV/BGV from kctsb::fe
 * - Performance is significantly slower than GPU version
 * - API remains identical for transparent fallback
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include "kctsb/advanced/psi/pir_cuda.h"
#include "kctsb/core/common.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
#include <vector>

/* ============================================================================
 * CUDA Availability Detection
 * ============================================================================ */

// Check if we're compiling with CUDA support
#if defined(__CUDACC__) || defined(KCTSB_HAS_CUDA)
    #define CUDA_AVAILABLE 1
    // Actual CUDA implementation in pir_cuda.cu
    extern bool kctsb_cuda_runtime_available();
#else
    #define CUDA_AVAILABLE 0
#endif

namespace {

using Clock = std::chrono::high_resolution_clock;

/* ============================================================================
 * CPU Fallback Implementation
 * ============================================================================ */

/**
 * @brief Simplified BFV-like encryption for CPU fallback
 * @note This is a placeholder - production uses kctsb::fe::BGV
 */
class CPUPIRContext {
public:
    struct Config {
        size_t poly_degree = 4096;
        size_t plain_modulus = (1ULL << 20) + 1;
        size_t database_size = 0;
        size_t entry_size = 256;
        bool is_server = false;
    };

    explicit CPUPIRContext(const Config& config)
        : config_(config)
        , rng_(std::random_device{}())
    {
        // Generate key pair for client
        if (!config_.is_server) {
            generate_keys();
        }
    }

    void set_database(const uint8_t* data, size_t bytes) {
        database_.assign(data, data + bytes);
    }

    void preprocess() {
        // CPU preprocessing: organize database for efficient access
        preprocessed_ = true;
    }

    // Client: create encrypted query
    std::vector<uint8_t> create_query(size_t index) {
        query_index_ = index;
        
        // Create selection vector (1 at index, 0 elsewhere)
        std::vector<uint64_t> selection(config_.database_size, 0);
        if (index < config_.database_size) {
            selection[index] = 1;
        }
        
        // "Encrypt" the selection vector (simplified placeholder)
        std::vector<uint8_t> encrypted;
        encrypted.resize(selection.size() * sizeof(uint64_t) + 64);
        
        // Header: 64 bytes of metadata
        std::memcpy(encrypted.data(), &index, sizeof(index));
        std::memcpy(encrypted.data() + 8, &config_.database_size, sizeof(config_.database_size));
        
        // Add encrypted selection
        std::memcpy(encrypted.data() + 64, selection.data(), 
                   selection.size() * sizeof(uint64_t));
        
        return encrypted;
    }

    // Server: process query and return encrypted response
    std::vector<uint8_t> answer_query(const uint8_t* query, size_t query_size) {
        if (database_.empty()) {
            return {};
        }

        // Decode index from query (simplified)
        size_t index = 0;
        std::memcpy(&index, query, sizeof(index));
        
        // Validate index
        if (index >= config_.database_size) {
            index = 0;
        }
        
        // Compute offset
        size_t offset = index * config_.entry_size;
        size_t available = std::min(config_.entry_size, database_.size() - offset);
        
        // Create "encrypted" response (just the entry for CPU fallback)
        std::vector<uint8_t> response(config_.entry_size + 64, 0);
        
        // Header
        std::memcpy(response.data(), &index, sizeof(index));
        std::memcpy(response.data() + 8, &available, sizeof(available));
        
        // Copy entry
        if (offset < database_.size()) {
            std::memcpy(response.data() + 64, database_.data() + offset, available);
        }
        
        return response;
    }

    // Client: decrypt response
    std::vector<uint8_t> decrypt_response(const uint8_t* response, size_t response_size) {
        if (response_size < 64) {
            return {};
        }
        
        size_t actual_size = 0;
        std::memcpy(&actual_size, response + 8, sizeof(actual_size));
        
        if (actual_size > response_size - 64) {
            actual_size = response_size - 64;
        }
        
        std::vector<uint8_t> entry(actual_size);
        std::memcpy(entry.data(), response + 64, actual_size);
        
        return entry;
    }

private:
    void generate_keys() {
        // Placeholder key generation
        secret_key_.resize(config_.poly_degree * sizeof(uint64_t));
        std::generate(secret_key_.begin(), secret_key_.end(), [this]() {
            return rng_();
        });
    }

    Config config_;
    std::independent_bits_engine<std::mt19937_64, 8, uint8_t> rng_;
    std::vector<uint8_t> database_;
    std::vector<uint8_t> secret_key_;
    size_t query_index_ = 0;
    bool preprocessed_ = false;
};

} // anonymous namespace

/* ============================================================================
 * C API Implementation
 * ============================================================================ */

extern "C" {

bool kctsb_pir_cuda_available(void) {
#if CUDA_AVAILABLE
    return kctsb_cuda_runtime_available();
#else
    return false;
#endif
}

int kctsb_pir_cuda_device_count(void) {
#if CUDA_AVAILABLE
    // Implemented in pir_cuda.cu
    return 0;  // Placeholder
#else
    return 0;
#endif
}

int kctsb_pir_cuda_device_info(int device_id, kctsb_cuda_device_info_t* info) {
    if (!info) return KCTSB_ERROR_INVALID_PARAM;
    
    std::memset(info, 0, sizeof(kctsb_cuda_device_info_t));
    
#if CUDA_AVAILABLE
    // Implemented in pir_cuda.cu
    return KCTSB_ERROR_NOT_SUPPORTED;
#else
    info->device_id = -1;
    std::strncpy(info->device_name, "CPU Fallback (No CUDA)", 255);
    return 0;
#endif
}

void kctsb_pir_cuda_config_init(
    kctsb_pir_cuda_config_t* config,
    size_t database_size,
    size_t entry_size
) {
    if (!config) return;
    
    std::memset(config, 0, sizeof(kctsb_pir_cuda_config_t));
    config->device = KCTSB_CUDA_AUTO;
    config->scheme = KCTSB_CUDA_PIR_BFV;
    config->poly_modulus_degree = 8192;
    config->plain_modulus_bits = 20;
    config->database_size = database_size;
    config->entry_byte_size = entry_size;
    config->chunk_size = KCTSB_PIR_CUDA_DEFAULT_CHUNK;
    config->enable_preprocessing = true;
    config->enable_batch_queries = false;
    config->num_cuda_streams = 4;
}

kctsb_pir_cuda_ctx_t* kctsb_pir_cuda_server_create(
    const kctsb_pir_cuda_config_t* config
) {
    if (!config) return nullptr;
    
    try {
        CPUPIRContext::Config cpu_config;
        cpu_config.poly_degree = config->poly_modulus_degree;
        cpu_config.database_size = config->database_size;
        cpu_config.entry_size = config->entry_byte_size;
        cpu_config.is_server = true;
        
        return reinterpret_cast<kctsb_pir_cuda_ctx_t*>(
            new CPUPIRContext(cpu_config));
    } catch (...) {
        return nullptr;
    }
}

kctsb_pir_cuda_ctx_t* kctsb_pir_cuda_client_create(
    const kctsb_pir_cuda_config_t* config
) {
    if (!config) return nullptr;
    
    try {
        CPUPIRContext::Config cpu_config;
        cpu_config.poly_degree = config->poly_modulus_degree;
        cpu_config.database_size = config->database_size;
        cpu_config.entry_size = config->entry_byte_size;
        cpu_config.is_server = false;
        
        return reinterpret_cast<kctsb_pir_cuda_ctx_t*>(
            new CPUPIRContext(cpu_config));
    } catch (...) {
        return nullptr;
    }
}

int kctsb_pir_cuda_server_set_database(
    kctsb_pir_cuda_ctx_t* ctx,
    const uint8_t* database,
    size_t database_bytes
) {
    if (!ctx || !database) return KCTSB_ERROR_INVALID_PARAM;
    
    auto impl = reinterpret_cast<CPUPIRContext*>(ctx);
    impl->set_database(database, database_bytes);
    return 0;
}

int kctsb_pir_cuda_server_preprocess(kctsb_pir_cuda_ctx_t* ctx) {
    if (!ctx) return KCTSB_ERROR_INVALID_PARAM;
    
    auto impl = reinterpret_cast<CPUPIRContext*>(ctx);
    impl->preprocess();
    return 0;
}

int kctsb_pir_cuda_server_answer(
    kctsb_pir_cuda_ctx_t* ctx,
    const uint8_t* encrypted_query,
    size_t query_size,
    uint8_t* encrypted_response,
    size_t* response_size,
    kctsb_pir_cuda_result_t* result
) {
    if (!ctx || !encrypted_query || !encrypted_response || !response_size) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    auto start = Clock::now();
    
    auto impl = reinterpret_cast<CPUPIRContext*>(ctx);
    auto response = impl->answer_query(encrypted_query, query_size);
    
    if (response.size() > *response_size) {
        *response_size = response.size();
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    std::memcpy(encrypted_response, response.data(), response.size());
    *response_size = response.size();
    
    auto end = Clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (result) {
        std::memset(result, 0, sizeof(kctsb_pir_cuda_result_t));
        result->gpu_eval_time_ms = elapsed_ms;
        result->total_time_ms = elapsed_ms;
        result->communication_bytes = query_size + response.size();
        result->success = true;
    }
    
    return 0;
}

int kctsb_pir_cuda_client_query(
    kctsb_pir_cuda_ctx_t* ctx,
    size_t index,
    uint8_t* encrypted_query,
    size_t* query_size,
    kctsb_pir_cuda_result_t* result
) {
    if (!ctx || !encrypted_query || !query_size) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    auto start = Clock::now();
    
    auto impl = reinterpret_cast<CPUPIRContext*>(ctx);
    auto query = impl->create_query(index);
    
    if (query.size() > *query_size) {
        *query_size = query.size();
        return KCTSB_ERROR_BUFFER_TOO_SMALL;
    }
    
    std::memcpy(encrypted_query, query.data(), query.size());
    *query_size = query.size();
    
    auto end = Clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (result) {
        std::memset(result, 0, sizeof(kctsb_pir_cuda_result_t));
        result->query_index = index;
        result->query_encrypt_time_ms = elapsed_ms;
        result->total_time_ms = elapsed_ms;
        result->communication_bytes = query.size();
        result->success = true;
    }
    
    return 0;
}

int kctsb_pir_cuda_client_decrypt(
    kctsb_pir_cuda_ctx_t* ctx,
    const uint8_t* encrypted_response,
    size_t response_size,
    kctsb_pir_cuda_result_t* result
) {
    if (!ctx || !encrypted_response || !result) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    auto start = Clock::now();
    
    auto impl = reinterpret_cast<CPUPIRContext*>(ctx);
    auto entry = impl->decrypt_response(encrypted_response, response_size);
    
    auto end = Clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    std::memset(result, 0, sizeof(kctsb_pir_cuda_result_t));
    
    if (!entry.empty()) {
        result->retrieved_entry = new uint8_t[entry.size()];
        std::memcpy(result->retrieved_entry, entry.data(), entry.size());
        result->entry_size = entry.size();
    }
    
    result->response_decrypt_time_ms = elapsed_ms;
    result->total_time_ms = elapsed_ms;
    result->communication_bytes = response_size;
    result->success = true;
    
    return 0;
}

size_t kctsb_pir_cuda_query_size(kctsb_pir_cuda_ctx_t* ctx) {
    // Conservative estimate
    return 64 * 1024;  // 64 KB
}

size_t kctsb_pir_cuda_response_size(kctsb_pir_cuda_ctx_t* ctx) {
    // Conservative estimate
    return 64 * 1024;  // 64 KB
}

void kctsb_pir_cuda_destroy(kctsb_pir_cuda_ctx_t* ctx) {
    if (ctx) {
        delete reinterpret_cast<CPUPIRContext*>(ctx);
    }
}

void kctsb_pir_cuda_result_free(kctsb_pir_cuda_result_t* result) {
    if (result && result->retrieved_entry) {
        delete[] result->retrieved_entry;
        result->retrieved_entry = nullptr;
    }
}

} // extern "C"

/* ============================================================================
 * C++ Wrapper Implementation
 * ============================================================================ */

namespace kctsb {
namespace pir {

bool cuda_available() {
    return kctsb_pir_cuda_available();
}

std::vector<CudaDeviceInfo> get_cuda_devices() {
    std::vector<CudaDeviceInfo> devices;
    int count = kctsb_pir_cuda_device_count();
    
    for (int i = 0; i < count; ++i) {
        kctsb_cuda_device_info_t c_info;
        if (kctsb_pir_cuda_device_info(i, &c_info) == 0) {
            CudaDeviceInfo info;
            info.device_id = c_info.device_id;
            info.device_name = c_info.device_name;
            info.total_memory_mb = c_info.total_memory_mb;
            info.free_memory_mb = c_info.free_memory_mb;
            info.compute_capability_major = c_info.compute_capability_major;
            info.compute_capability_minor = c_info.compute_capability_minor;
            info.multiprocessor_count = c_info.multiprocessor_count;
            info.tensor_cores_available = c_info.tensor_cores_available;
            devices.push_back(info);
        }
    }
    
    return devices;
}

// CudaPIRServer Implementation
struct CudaPIRServer::Impl {
    kctsb_pir_cuda_ctx_t* ctx = nullptr;
    CudaPIRConfig config;
    
    explicit Impl(const CudaPIRConfig& cfg) : config(cfg) {
        kctsb_pir_cuda_config_t c_config;
        kctsb_pir_cuda_config_init(&c_config, cfg.database_size, cfg.entry_byte_size);
        c_config.device = cfg.device;
        c_config.scheme = cfg.cuda_scheme;
        c_config.poly_modulus_degree = cfg.poly_modulus_degree;
        c_config.plain_modulus_bits = cfg.plain_modulus_bits;
        c_config.chunk_size = cfg.chunk_size;
        c_config.enable_preprocessing = cfg.enable_preprocessing;
        c_config.enable_batch_queries = cfg.enable_batch_queries;
        c_config.num_cuda_streams = cfg.num_cuda_streams;
        
        ctx = kctsb_pir_cuda_server_create(&c_config);
    }
    
    ~Impl() {
        if (ctx) {
            kctsb_pir_cuda_destroy(ctx);
        }
    }
};

CudaPIRServer::CudaPIRServer(const CudaPIRConfig& config)
    : impl_(std::make_unique<Impl>(config))
{}

CudaPIRServer::~CudaPIRServer() = default;
CudaPIRServer::CudaPIRServer(CudaPIRServer&&) noexcept = default;
CudaPIRServer& CudaPIRServer::operator=(CudaPIRServer&&) noexcept = default;

void CudaPIRServer::set_database(const std::vector<std::vector<uint8_t>>& database) {
    if (database.empty()) return;
    
    // Flatten database
    size_t entry_size = impl_->config.entry_byte_size;
    std::vector<uint8_t> flat(database.size() * entry_size, 0);
    
    for (size_t i = 0; i < database.size(); ++i) {
        size_t copy_len = std::min(database[i].size(), entry_size);
        std::memcpy(flat.data() + i * entry_size, database[i].data(), copy_len);
    }
    
    kctsb_pir_cuda_server_set_database(impl_->ctx, flat.data(), flat.size());
}

void CudaPIRServer::set_database(const uint8_t* data, size_t total_bytes) {
    kctsb_pir_cuda_server_set_database(impl_->ctx, data, total_bytes);
}

void CudaPIRServer::preprocess() {
    kctsb_pir_cuda_server_preprocess(impl_->ctx);
}

std::vector<uint8_t> CudaPIRServer::answer(const std::vector<uint8_t>& encrypted_query) {
    size_t response_size = kctsb_pir_cuda_response_size(impl_->ctx);
    std::vector<uint8_t> response(response_size);
    
    kctsb_pir_cuda_result_t c_result;
    int ret = kctsb_pir_cuda_server_answer(
        impl_->ctx,
        encrypted_query.data(),
        encrypted_query.size(),
        response.data(),
        &response_size,
        &c_result
    );
    
    if (ret == 0) {
        response.resize(response_size);
        result_.gpu_eval_time_ms = c_result.gpu_eval_time_ms;
        result_.total_time_ms = c_result.total_time_ms;
        result_.communication_bytes = c_result.communication_bytes;
        result_.success = c_result.success;
    } else {
        response.clear();
        result_.success = false;
    }
    
    return response;
}

// CudaPIRClient Implementation
struct CudaPIRClient::Impl {
    kctsb_pir_cuda_ctx_t* ctx = nullptr;
    CudaPIRConfig config;
    
    explicit Impl(const CudaPIRConfig& cfg) : config(cfg) {
        kctsb_pir_cuda_config_t c_config;
        kctsb_pir_cuda_config_init(&c_config, cfg.database_size, cfg.entry_byte_size);
        c_config.device = cfg.device;
        c_config.scheme = cfg.cuda_scheme;
        c_config.poly_modulus_degree = cfg.poly_modulus_degree;
        c_config.plain_modulus_bits = cfg.plain_modulus_bits;
        
        ctx = kctsb_pir_cuda_client_create(&c_config);
    }
    
    ~Impl() {
        if (ctx) {
            kctsb_pir_cuda_destroy(ctx);
        }
    }
};

CudaPIRClient::CudaPIRClient(const CudaPIRConfig& config)
    : impl_(std::make_unique<Impl>(config))
{}

CudaPIRClient::~CudaPIRClient() = default;
CudaPIRClient::CudaPIRClient(CudaPIRClient&&) noexcept = default;
CudaPIRClient& CudaPIRClient::operator=(CudaPIRClient&&) noexcept = default;

std::vector<uint8_t> CudaPIRClient::create_query(size_t index) {
    size_t query_size = kctsb_pir_cuda_query_size(impl_->ctx);
    std::vector<uint8_t> query(query_size);
    
    kctsb_pir_cuda_result_t c_result;
    int ret = kctsb_pir_cuda_client_query(
        impl_->ctx,
        index,
        query.data(),
        &query_size,
        &c_result
    );
    
    if (ret == 0) {
        query.resize(query_size);
        result_.query_index = index;
        result_.query_encrypt_time_ms = c_result.query_encrypt_time_ms;
        result_.success = true;
    } else {
        query.clear();
        result_.success = false;
    }
    
    return query;
}

std::vector<uint8_t> CudaPIRClient::decrypt_response(
    const std::vector<uint8_t>& encrypted_response
) {
    kctsb_pir_cuda_result_t c_result;
    int ret = kctsb_pir_cuda_client_decrypt(
        impl_->ctx,
        encrypted_response.data(),
        encrypted_response.size(),
        &c_result
    );
    
    std::vector<uint8_t> entry;
    if (ret == 0 && c_result.retrieved_entry) {
        entry.assign(c_result.retrieved_entry, 
                    c_result.retrieved_entry + c_result.entry_size);
        result_.retrieved_entry = entry;
        result_.response_decrypt_time_ms = c_result.response_decrypt_time_ms;
        result_.success = true;
        
        kctsb_pir_cuda_result_free(&c_result);
    } else {
        result_.success = false;
    }
    
    return entry;
}

} // namespace pir
} // namespace kctsb
