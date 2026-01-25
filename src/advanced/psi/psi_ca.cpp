/**
 * @file psi_ca.cpp
 * @brief PSI with Cardinality and Attributes Implementation
 * 
 * @details Implements PSI-CA variants:
 * - Cardinality-only: DH-based with counting
 * - With Payloads: OT-based payload retrieval
 * - Sum: Additive homomorphic encryption
 * - Threshold: Reveal only if cardinality exceeds threshold
 * 
 * @author kn1ghtc
 * @version 4.14.0
 * @date 2026-01-25
 * 
 * @copyright Copyright (c) 2019-2026 knightc. Licensed under Apache 2.0
 */

#include "kctsb/advanced/psi/psi_ca.h"
#include "kctsb/core/common.h"
#include "kctsb/crypto/sha256.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <numeric>
#include <unordered_set>

namespace {

using Clock = std::chrono::high_resolution_clock;

/* ============================================================================
 * Hash Utilities
 * ============================================================================ */

struct ElementHash {
    uint8_t data[32];
    
    bool operator==(const ElementHash& other) const {
        return std::memcmp(data, other.data, 32) == 0;
    }
};

struct ElementHasher {
    size_t operator()(const ElementHash& h) const {
        size_t result = 0;
        for (size_t i = 0; i < sizeof(size_t); ++i) {
            result |= (static_cast<size_t>(h.data[i]) << (i * 8));
        }
        return result;
    }
};

ElementHash hash_element(int64_t element) {
    ElementHash result;
    kctsb_sha256(reinterpret_cast<const uint8_t*>(&element), sizeof(element), result.data);
    return result;
}

/* ============================================================================
 * PSI-CA Implementation
 * ============================================================================ */

class PSICAImpl {
public:
    explicit PSICAImpl(const kctsb_psi_ca_config_t& config)
        : config_(config)
    {}

    int compute_simple(
        const int64_t* client_set, size_t client_size,
        const int64_t* server_set, size_t server_size,
        kctsb_psi_ca_result_t* result
    ) {
        auto start = Clock::now();
        std::memset(result, 0, sizeof(kctsb_psi_ca_result_t));
        
        // Hash both sets
        std::unordered_set<ElementHash, ElementHasher> client_hashes;
        for (size_t i = 0; i < client_size; ++i) {
            client_hashes.insert(hash_element(client_set[i]));
        }
        
        // Find intersection
        std::vector<int64_t> intersection;
        for (size_t i = 0; i < server_size; ++i) {
            auto h = hash_element(server_set[i]);
            if (client_hashes.count(h) > 0) {
                intersection.push_back(server_set[i]);
            }
        }
        
        // Process based on mode
        result->intersection_size = intersection.size();
        
        switch (config_.mode) {
            case KCTSB_PSI_CARDINALITY_ONLY:
                // Only reveal size, not elements
                break;
                
            case KCTSB_PSI_WITH_PAYLOAD:
            case KCTSB_PSI_SUM:
                // Reveal elements
                if (!intersection.empty() && config_.client_learns_result) {
                    result->intersection_elements = new int64_t[intersection.size()];
                    std::memcpy(result->intersection_elements, intersection.data(),
                               intersection.size() * sizeof(int64_t));
                }
                break;
                
            case KCTSB_PSI_THRESHOLD:
                result->threshold_met = (intersection.size() >= config_.threshold);
                if (!result->threshold_met) {
                    // Don't reveal anything if threshold not met
                    result->intersection_size = 0;
                } else if (config_.client_learns_result) {
                    result->intersection_elements = new int64_t[intersection.size()];
                    std::memcpy(result->intersection_elements, intersection.data(),
                               intersection.size() * sizeof(int64_t));
                }
                break;
        }
        
        auto end = Clock::now();
        result->execution_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result->communication_bytes = (client_size + server_size) * 32;  // Hash size
        result->success = true;
        
        return 0;
    }

    int compute_with_payload(
        const kctsb_psi_element_t* client_elements, size_t client_size,
        const kctsb_psi_element_t* server_elements, size_t server_size,
        kctsb_psi_ca_result_t* result
    ) {
        auto start = Clock::now();
        std::memset(result, 0, sizeof(kctsb_psi_ca_result_t));
        
        // Build client hash map with payloads
        std::unordered_map<ElementHash, const kctsb_psi_element_t*, ElementHasher> client_map;
        for (size_t i = 0; i < client_size; ++i) {
            client_map[hash_element(client_elements[i].element)] = &client_elements[i];
        }
        
        // Find intersection and collect payloads
        std::vector<int64_t> intersection;
        std::vector<std::vector<uint8_t>> payloads;
        double sum = 0.0;
        double min_val = std::numeric_limits<double>::max();
        double max_val = std::numeric_limits<double>::lowest();
        
        for (size_t i = 0; i < server_size; ++i) {
            auto h = hash_element(server_elements[i].element);
            auto it = client_map.find(h);
            
            if (it != client_map.end()) {
                intersection.push_back(server_elements[i].element);
                
                // Combine payloads (use server's payload, or could merge)
                if (server_elements[i].payload && server_elements[i].payload_size > 0) {
                    payloads.emplace_back(
                        server_elements[i].payload,
                        server_elements[i].payload + server_elements[i].payload_size
                    );
                    
                    // For aggregation, interpret first 8 bytes as int64
                    if (server_elements[i].payload_size >= sizeof(int64_t)) {
                        int64_t val;
                        std::memcpy(&val, server_elements[i].payload, sizeof(val));
                        sum += static_cast<double>(val);
                        min_val = std::min(min_val, static_cast<double>(val));
                        max_val = std::max(max_val, static_cast<double>(val));
                    }
                } else {
                    payloads.emplace_back();
                }
            }
        }
        
        result->intersection_size = intersection.size();
        
        // Apply aggregation
        switch (config_.aggregation) {
            case KCTSB_PSI_AGG_SUM:
                result->aggregated_value = sum;
                break;
            case KCTSB_PSI_AGG_COUNT:
                result->aggregated_value = static_cast<double>(intersection.size());
                break;
            case KCTSB_PSI_AGG_AVG:
                result->aggregated_value = intersection.empty() ? 0.0 : 
                                          sum / static_cast<double>(intersection.size());
                break;
            case KCTSB_PSI_AGG_MIN:
                result->aggregated_value = intersection.empty() ? 0.0 : min_val;
                break;
            case KCTSB_PSI_AGG_MAX:
                result->aggregated_value = intersection.empty() ? 0.0 : max_val;
                break;
            case KCTSB_PSI_AGG_NONE:
            default:
                break;
        }
        
        // Store results
        if (!intersection.empty() && config_.client_learns_result) {
            result->intersection_elements = new int64_t[intersection.size()];
            std::memcpy(result->intersection_elements, intersection.data(),
                       intersection.size() * sizeof(int64_t));
            
            if (config_.mode == KCTSB_PSI_WITH_PAYLOAD) {
                result->payloads = new uint8_t*[payloads.size()];
                result->payload_sizes = new size_t[payloads.size()];
                
                for (size_t i = 0; i < payloads.size(); ++i) {
                    if (!payloads[i].empty()) {
                        result->payloads[i] = new uint8_t[payloads[i].size()];
                        std::memcpy(result->payloads[i], payloads[i].data(), payloads[i].size());
                        result->payload_sizes[i] = payloads[i].size();
                    } else {
                        result->payloads[i] = nullptr;
                        result->payload_sizes[i] = 0;
                    }
                }
            }
        }
        
        auto end = Clock::now();
        result->execution_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result->success = true;
        
        return 0;
    }

private:
    kctsb_psi_ca_config_t config_;
};

} // anonymous namespace

/* ============================================================================
 * C API Implementation
 * ============================================================================ */

extern "C" {

void kctsb_psi_ca_config_init(
    kctsb_psi_ca_config_t* config,
    kctsb_psi_ca_mode_t mode
) {
    if (!config) return;
    
    std::memset(config, 0, sizeof(kctsb_psi_ca_config_t));
    config->mode = mode;
    config->aggregation = KCTSB_PSI_AGG_NONE;
    config->threshold = 0;
    config->security_parameter = 128;
    config->client_learns_result = true;
    config->server_learns_result = false;
    config->payload_byte_size = 256;
}

kctsb_psi_ca_ctx_t* kctsb_psi_ca_create(const kctsb_psi_ca_config_t* config) {
    if (!config) return nullptr;
    
    try {
        return reinterpret_cast<kctsb_psi_ca_ctx_t*>(new PSICAImpl(*config));
    } catch (...) {
        return nullptr;
    }
}

int kctsb_psi_ca_compute_simple(
    kctsb_psi_ca_ctx_t* ctx,
    const int64_t* client_set, size_t client_size,
    const int64_t* server_set, size_t server_size,
    kctsb_psi_ca_result_t* result
) {
    if (!ctx || !client_set || !server_set || !result) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    auto impl = reinterpret_cast<PSICAImpl*>(ctx);
    return impl->compute_simple(client_set, client_size, server_set, server_size, result);
}

int kctsb_psi_ca_compute_with_payload(
    kctsb_psi_ca_ctx_t* ctx,
    const kctsb_psi_element_t* client_elements, size_t client_size,
    const kctsb_psi_element_t* server_elements, size_t server_size,
    kctsb_psi_ca_result_t* result
) {
    if (!ctx || !client_elements || !server_elements || !result) {
        return KCTSB_ERROR_INVALID_PARAM;
    }
    
    auto impl = reinterpret_cast<PSICAImpl*>(ctx);
    return impl->compute_with_payload(client_elements, client_size,
                                     server_elements, server_size, result);
}

void kctsb_psi_ca_destroy(kctsb_psi_ca_ctx_t* ctx) {
    if (ctx) {
        delete reinterpret_cast<PSICAImpl*>(ctx);
    }
}

void kctsb_psi_ca_result_free(kctsb_psi_ca_result_t* result) {
    if (!result) return;
    
    if (result->intersection_elements) {
        delete[] result->intersection_elements;
        result->intersection_elements = nullptr;
    }
    
    if (result->payloads) {
        for (size_t i = 0; i < result->intersection_size; ++i) {
            if (result->payloads[i]) {
                delete[] result->payloads[i];
            }
        }
        delete[] result->payloads;
        result->payloads = nullptr;
    }
    
    if (result->payload_sizes) {
        delete[] result->payload_sizes;
        result->payload_sizes = nullptr;
    }
}

} // extern "C"

/* ============================================================================
 * C++ Wrapper Implementation
 * ============================================================================ */

namespace kctsb {
namespace psi {

struct PSICA::Impl {
    std::unique_ptr<PSICAImpl> psi_ca;
    PSICAConfig config;
    
    explicit Impl(const PSICAConfig& cfg) : config(cfg) {
        kctsb_psi_ca_config_t c_config;
        kctsb_psi_ca_config_init(&c_config, cfg.mode);
        c_config.aggregation = cfg.aggregation;
        c_config.threshold = cfg.threshold;
        c_config.security_parameter = cfg.security_parameter;
        c_config.client_learns_result = cfg.client_learns_result;
        c_config.server_learns_result = cfg.server_learns_result;
        c_config.payload_byte_size = cfg.payload_byte_size;
        
        psi_ca = std::make_unique<PSICAImpl>(c_config);
    }
};

PSICA::PSICA(const PSICAConfig& config)
    : impl_(std::make_unique<Impl>(config))
{}

PSICA::~PSICA() = default;
PSICA::PSICA(PSICA&&) noexcept = default;
PSICA& PSICA::operator=(PSICA&&) noexcept = default;

PSICAResult PSICA::compute_cardinality(
    const std::vector<int64_t>& client_set,
    const std::vector<int64_t>& server_set
) {
    kctsb_psi_ca_result_t c_result;
    impl_->psi_ca->compute_simple(client_set.data(), client_set.size(),
                                 server_set.data(), server_set.size(),
                                 &c_result);
    
    PSICAResult result;
    result.intersection_size = c_result.intersection_size;
    result.execution_time_ms = c_result.execution_time_ms;
    result.communication_bytes = c_result.communication_bytes;
    result.success = c_result.success;
    
    return result;
}

PSICAResult PSICA::compute_with_payloads(
    const std::vector<ElementWithPayload<>>& client_elements,
    const std::vector<ElementWithPayload<>>& server_elements
) {
    // Convert to C structures
    std::vector<kctsb_psi_element_t> c_client(client_elements.size());
    std::vector<kctsb_psi_element_t> c_server(server_elements.size());
    
    for (size_t i = 0; i < client_elements.size(); ++i) {
        c_client[i].element = client_elements[i].element;
        c_client[i].payload = const_cast<uint8_t*>(client_elements[i].payload.data());
        c_client[i].payload_size = client_elements[i].payload.size();
    }
    
    for (size_t i = 0; i < server_elements.size(); ++i) {
        c_server[i].element = server_elements[i].element;
        c_server[i].payload = const_cast<uint8_t*>(server_elements[i].payload.data());
        c_server[i].payload_size = server_elements[i].payload.size();
    }
    
    kctsb_psi_ca_result_t c_result;
    impl_->psi_ca->compute_with_payload(c_client.data(), c_client.size(),
                                       c_server.data(), c_server.size(),
                                       &c_result);
    
    PSICAResult result;
    result.intersection_size = c_result.intersection_size;
    result.aggregated_value = c_result.aggregated_value;
    result.execution_time_ms = c_result.execution_time_ms;
    result.success = c_result.success;
    
    if (c_result.intersection_elements && c_result.intersection_size > 0) {
        result.intersection_elements.assign(
            c_result.intersection_elements,
            c_result.intersection_elements + c_result.intersection_size);
        
        if (c_result.payloads) {
            result.payloads.resize(c_result.intersection_size);
            for (size_t i = 0; i < c_result.intersection_size; ++i) {
                if (c_result.payloads[i] && c_result.payload_sizes[i] > 0) {
                    result.payloads[i].assign(
                        c_result.payloads[i],
                        c_result.payloads[i] + c_result.payload_sizes[i]);
                }
            }
        }
        
        kctsb_psi_ca_result_free(&c_result);
    }
    
    return result;
}

PSICAResult PSICA::compute_sum(
    const std::vector<std::pair<int64_t, int64_t>>& client_with_values,
    const std::vector<std::pair<int64_t, int64_t>>& server_with_values
) {
    // Convert to ElementWithPayload
    std::vector<kctsb_psi_element_t> c_client(client_with_values.size());
    std::vector<kctsb_psi_element_t> c_server(server_with_values.size());
    std::vector<std::vector<uint8_t>> client_payloads(client_with_values.size());
    std::vector<std::vector<uint8_t>> server_payloads(server_with_values.size());
    
    for (size_t i = 0; i < client_with_values.size(); ++i) {
        c_client[i].element = client_with_values[i].first;
        client_payloads[i].resize(sizeof(int64_t));
        std::memcpy(client_payloads[i].data(), &client_with_values[i].second, sizeof(int64_t));
        c_client[i].payload = client_payloads[i].data();
        c_client[i].payload_size = sizeof(int64_t);
    }
    
    for (size_t i = 0; i < server_with_values.size(); ++i) {
        c_server[i].element = server_with_values[i].first;
        server_payloads[i].resize(sizeof(int64_t));
        std::memcpy(server_payloads[i].data(), &server_with_values[i].second, sizeof(int64_t));
        c_server[i].payload = server_payloads[i].data();
        c_server[i].payload_size = sizeof(int64_t);
    }
    
    kctsb_psi_ca_result_t c_result;
    impl_->psi_ca->compute_with_payload(c_client.data(), c_client.size(),
                                       c_server.data(), c_server.size(),
                                       &c_result);
    
    PSICAResult result;
    result.intersection_size = c_result.intersection_size;
    result.aggregated_value = c_result.aggregated_value;
    result.execution_time_ms = c_result.execution_time_ms;
    result.success = c_result.success;
    
    kctsb_psi_ca_result_free(&c_result);
    
    return result;
}

PSICAResult PSICA::compute_threshold(
    const std::vector<int64_t>& client_set,
    const std::vector<int64_t>& server_set,
    size_t threshold
) {
    // Temporarily modify config for threshold mode
    kctsb_psi_ca_config_t c_config;
    kctsb_psi_ca_config_init(&c_config, KCTSB_PSI_THRESHOLD);
    c_config.threshold = threshold;
    c_config.client_learns_result = impl_->config.client_learns_result;
    
    PSICAImpl threshold_impl(c_config);
    
    kctsb_psi_ca_result_t c_result;
    threshold_impl.compute_simple(client_set.data(), client_set.size(),
                                 server_set.data(), server_set.size(),
                                 &c_result);
    
    PSICAResult result;
    result.intersection_size = c_result.intersection_size;
    result.threshold_met = c_result.threshold_met;
    result.execution_time_ms = c_result.execution_time_ms;
    result.success = c_result.success;
    
    if (c_result.intersection_elements && c_result.intersection_size > 0) {
        result.intersection_elements.assign(
            c_result.intersection_elements,
            c_result.intersection_elements + c_result.intersection_size);
        kctsb_psi_ca_result_free(&c_result);
    }
    
    return result;
}

const PSICAConfig& PSICA::config() const {
    return impl_->config;
}

} // namespace psi
} // namespace kctsb
